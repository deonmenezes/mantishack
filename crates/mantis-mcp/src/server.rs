//! `MantisMcpServer` and its tool router.
//!
//! Each tool method is a thin wrapper around a daemon gRPC call.
//! Inputs deserialize from MCP tool arguments via `serde` +
//! `schemars` (the JSON schema is what the host LLM sees when it
//! decides whether and how to call the tool). Outputs are returned
//! as JSON-serialized text content so the LLM can parse structured
//! data back into its planning loop.
//!
//! Errors travel as `rmcp::ErrorData`. We surface daemon-side
//! failures with `invalid_request` for client-fixable issues
//! (unknown engagement id, malformed url) and `internal_error` for
//! infrastructure problems (daemon down, signing-key missing).

use std::str::FromStr;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::{schemars, tool, tool_router, ErrorData as McpError};
use serde::{Deserialize, Serialize};
use serde_json::json;

use mantis_proto::v1::{
    AuthorizeRequest, CreateRequest, EngagementState as ProtoState, ExportRequest, ListRequest,
    ScanRequest, StatusRequest,
};

use crate::daemon;
use crate::scope::build_signed_scope_json;

#[derive(Debug, Clone)]
pub struct MantisMcpServer {
    daemon_endpoint: String,
}

impl MantisMcpServer {
    pub fn new(daemon_endpoint: String) -> Self {
        Self { daemon_endpoint }
    }
}

// ---------- input schemas ----------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateEngagementArgs {
    /// Human-readable engagement name. If empty, a `mantis-<ulid>`
    /// name is generated.
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuthorizeScopeArgs {
    /// Engagement id returned by `mantis_create_engagement`.
    pub engagement_id: String,
    /// URL targets the engagement is authorized to test. Host and
    /// port matchers are derived from this list.
    pub targets: Vec<String>,
    /// Wall-clock budget the daemon will enforce on this engagement.
    /// Defaults to 1800s (30 minutes).
    #[serde(default = "default_budget")]
    pub budget_seconds: u32,
}

fn default_budget() -> u32 {
    1800
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EngagementIdArgs {
    /// Engagement id (ULID).
    pub engagement_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunReconArgs {
    /// Engagement id.
    pub engagement_id: String,
    /// URL targets to probe. Each must be in the engagement's
    /// authorized scope or the daemon will reject the request at the
    /// egress proxy.
    pub targets: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RenderReportArgs {
    /// Engagement id to render.
    pub engagement_id: String,
    /// Output directory. Defaults to
    /// `./mantishack-<engagement-id>/` relative to the daemon's
    /// working directory.
    #[serde(default)]
    pub output_dir: Option<String>,
}

// ---------- response shapes (for LLM-friendly JSON) ----------

#[derive(Debug, Serialize)]
struct EngagementSummary {
    id: String,
    name: String,
    state: &'static str,
    created_at_unix: u64,
    event_count: u64,
    scope_hash: Option<String>,
}

impl From<mantis_proto::v1::EngagementInfo> for EngagementSummary {
    fn from(info: mantis_proto::v1::EngagementInfo) -> Self {
        Self {
            id: info.id,
            name: info.name,
            state: state_name(info.state),
            created_at_unix: info.created_at_unix,
            event_count: info.event_count,
            scope_hash: info.scope_hash,
        }
    }
}

fn state_name(s: i32) -> &'static str {
    match ProtoState::try_from(s).unwrap_or(ProtoState::Unspecified) {
        ProtoState::Unspecified => "unspecified",
        ProtoState::Draft => "draft",
        ProtoState::Authorized => "authorized",
        ProtoState::Active => "active",
        ProtoState::Paused => "paused",
        ProtoState::Completed => "completed",
        ProtoState::Archived => "archived",
    }
}

#[derive(Debug, Serialize)]
struct Surface {
    seq: u64,
    host: String,
    port: u32,
    scheme: String,
    path: String,
    status: u32,
    server: Option<String>,
    tech_hints: Vec<String>,
}

// ---------- helpers ----------

fn to_internal<E: std::fmt::Display>(label: &str, e: E) -> McpError {
    McpError::internal_error(format!("{label}: {e}"), None)
}

fn to_invalid<E: std::fmt::Display>(label: &str, e: E) -> McpError {
    McpError::invalid_request(format!("{label}: {e}"), None)
}

fn json_ok<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| to_internal("serialize response", e))?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

// ---------- tool router ----------

#[tool_router(server_handler)]
impl MantisMcpServer {
    #[tool(
        description = "Create a new Mantis engagement. Returns the engagement id (ULID). \
                       Always call this first; every other tool requires an engagement id."
    )]
    async fn mantis_create_engagement(
        &self,
        Parameters(args): Parameters<CreateEngagementArgs>,
    ) -> Result<CallToolResult, McpError> {
        let name = if args.name.trim().is_empty() {
            format!("mantis-{}", ulid::Ulid::new())
        } else {
            args.name
        };
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let info = client
            .create(CreateRequest { name: name.clone() })
            .await
            .map_err(|e| to_internal("create rpc", e))?
            .into_inner();
        json_ok(&EngagementSummary::from(info))
    }

    #[tool(
        description = "Authorize an engagement's scope. Builds a signed scope manifest from \
                       the URL targets (host + port matchers derived automatically) and submits \
                       it to the daemon. Required before any scan/recon. The daemon enforces \
                       this scope cryptographically at the egress proxy."
    )]
    async fn mantis_authorize_scope(
        &self,
        Parameters(args): Parameters<AuthorizeScopeArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.targets.is_empty() {
            return Err(McpError::invalid_request(
                "targets must contain at least one URL".to_string(),
                None,
            ));
        }
        let scope_json =
            build_signed_scope_json(&args.engagement_id, &args.targets, args.budget_seconds)
                .map_err(|e| to_internal("build signed scope", e))?;
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let info = client
            .authorize(AuthorizeRequest {
                id: args.engagement_id,
                signed_scope_json: scope_json.into_bytes(),
            })
            .await
            .map_err(|e| to_invalid("authorize rpc", e))?
            .into_inner();
        json_ok(&EngagementSummary::from(info))
    }

    #[tool(
        description = "Look up an engagement by id. Returns its current state \
                       (draft / authorized / active / paused / completed / archived), \
                       event count, scope hash, and creation timestamp."
    )]
    async fn mantis_engagement_status(
        &self,
        Parameters(args): Parameters<EngagementIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let info = client
            .status(StatusRequest {
                id: args.engagement_id,
            })
            .await
            .map_err(|e| to_invalid("status rpc", e))?
            .into_inner();
        json_ok(&EngagementSummary::from(info))
    }

    #[tool(description = "List every engagement known to the daemon.")]
    async fn mantis_engagement_list(&self) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .list(ListRequest {})
            .await
            .map_err(|e| to_internal("list rpc", e))?
            .into_inner();
        let summaries: Vec<EngagementSummary> =
            resp.engagements.into_iter().map(Into::into).collect();
        json_ok(&summaries)
    }

    #[tool(
        description = "Run recon against URL targets within an authorized engagement. \
                       The daemon probes each URL, records every discovered surface as an \
                       event, and returns a count of new surfaces / hypotheses. On a 3xx \
                       redirect, the daemon records the surface but does NOT auto-follow \
                       the redirect; the orchestrator should call `mantis_run_recon` again \
                       on the redirect target after authorizing it into scope."
    )]
    async fn mantis_run_recon(
        &self,
        Parameters(args): Parameters<RunReconArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.targets.is_empty() {
            return Err(McpError::invalid_request(
                "targets must contain at least one URL".to_string(),
                None,
            ));
        }
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .scan(ScanRequest {
                id: args.engagement_id,
                targets: args.targets,
            })
            .await
            .map_err(|e| to_invalid("scan rpc", e))?
            .into_inner();
        json_ok(&json!({
            "engagement_id": resp.id,
            "surfaces_recorded": resp.surfaces_recorded,
            "hypotheses_recorded": resp.hypotheses_recorded,
        }))
    }

    #[tool(
        description = "List every SurfaceDiscovered event the daemon has recorded for an \
                       engagement, decoded into structured records (host, port, scheme, \
                       path, HTTP status, server header, tech hints). Use this after \
                       `mantis_run_recon` to see what to probe next; in particular, any \
                       surface with status 3xx is a redirect that warrants its own recon \
                       pass on the Location target."
    )]
    async fn mantis_list_surfaces(
        &self,
        Parameters(args): Parameters<EngagementIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let surfaces = export_surfaces(&self.daemon_endpoint, &args.engagement_id).await?;
        json_ok(&surfaces)
    }

    #[tool(
        description = "Export the entire append-only event log for an engagement as JSONL. \
                       Every entry is BLAKE3-hashed into the engagement's tree head and \
                       signed by the workspace key. Useful for ad-hoc inspection beyond \
                       what `mantis_list_surfaces` returns."
    )]
    async fn mantis_export_events(
        &self,
        Parameters(args): Parameters<EngagementIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let jsonl = export_events(&self.daemon_endpoint, &args.engagement_id).await?;
        Ok(CallToolResult::success(vec![Content::text(jsonl)]))
    }

    #[tool(
        description = "Render a markdown summary report for an engagement (surfaces, \
                       hypotheses, claims, event count) and write it under \
                       `./mantishack-<engagement-id>/report.md` along with the events.jsonl \
                       evidence log. Returns the directory path."
    )]
    async fn mantis_render_report(
        &self,
        Parameters(args): Parameters<RenderReportArgs>,
    ) -> Result<CallToolResult, McpError> {
        let jsonl = export_events(&self.daemon_endpoint, &args.engagement_id).await?;
        let info = engagement_status(&self.daemon_endpoint, &args.engagement_id).await?;
        let dir_path = args
            .output_dir
            .clone()
            .unwrap_or_else(|| format!("./mantishack-{}", info.id));
        let dir = std::path::PathBuf::from_str(&dir_path)
            .map_err(|e| to_invalid("output_dir path", e))?;
        std::fs::create_dir_all(&dir).map_err(|e| to_internal("create output dir", e))?;
        std::fs::write(dir.join("events.jsonl"), &jsonl)
            .map_err(|e| to_internal("write events.jsonl", e))?;
        let surfaces = parse_surfaces(&jsonl);
        let report = render_markdown(&info, &surfaces);
        std::fs::write(dir.join("report.md"), &report)
            .map_err(|e| to_internal("write report.md", e))?;
        json_ok(&json!({
            "directory": dir,
            "surfaces": surfaces.len(),
            "events": jsonl.lines().count(),
        }))
    }
}

// ---------- module-private helpers (used by multiple tools) ----------

async fn export_events(endpoint: &str, engagement_id: &str) -> Result<String, McpError> {
    let mut client = daemon::connect(endpoint)
        .await
        .map_err(|e| to_internal("daemon connect", e))?;
    let resp = client
        .export(ExportRequest {
            id: engagement_id.to_string(),
        })
        .await
        .map_err(|e| to_invalid("export rpc", e))?
        .into_inner();
    String::from_utf8(resp.jsonl).map_err(|e| to_internal("decode jsonl utf-8", e))
}

async fn export_surfaces(endpoint: &str, engagement_id: &str) -> Result<Vec<Surface>, McpError> {
    let jsonl = export_events(endpoint, engagement_id).await?;
    Ok(parse_surfaces(&jsonl))
}

async fn engagement_status(
    endpoint: &str,
    engagement_id: &str,
) -> Result<EngagementSummary, McpError> {
    let mut client = daemon::connect(endpoint)
        .await
        .map_err(|e| to_internal("daemon connect", e))?;
    let info = client
        .status(StatusRequest {
            id: engagement_id.to_string(),
        })
        .await
        .map_err(|e| to_invalid("status rpc", e))?
        .into_inner();
    Ok(EngagementSummary::from(info))
}

fn parse_surfaces(jsonl: &str) -> Vec<Surface> {
    let mut out = Vec::new();
    for line in jsonl.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let kind = value.get("kind").and_then(|k| k.get("kind")).and_then(|k| k.as_str());
        if kind != Some("SurfaceDiscovered") {
            continue;
        }
        let seq = value.get("seq").and_then(|s| s.as_u64()).unwrap_or(0);
        let k = match value.get("kind") {
            Some(k) => k,
            None => continue,
        };
        out.push(Surface {
            seq,
            host: k.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            port: k.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            scheme: k.get("scheme").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            path: k.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            status: k.get("status").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            server: k.get("server").and_then(|v| v.as_str()).map(str::to_string),
            tech_hints: k
                .get("tech_hints")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|h| h.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    out
}

fn render_markdown(info: &EngagementSummary, surfaces: &[Surface]) -> String {
    let mut s = String::new();
    s.push_str("# Mantis Engagement Report\n\n");
    s.push_str(&format!("- **Engagement:** `{}`\n", info.id));
    s.push_str(&format!("- **Name:** `{}`\n", info.name));
    s.push_str(&format!("- **State:** `{}`\n", info.state));
    s.push_str(&format!("- **Events recorded:** {}\n", info.event_count));
    if let Some(h) = &info.scope_hash {
        s.push_str(&format!("- **Scope hash:** `{}`\n", h));
    }
    s.push_str("\n## Pipeline summary\n\n");
    s.push_str("| Stage | Count |\n|---|---|\n");
    s.push_str(&format!("| Surfaces discovered | {} |\n", surfaces.len()));
    s.push_str("\n## Surfaces\n\n");
    if surfaces.is_empty() {
        s.push_str("_No surfaces recorded for this engagement._\n");
    } else {
        s.push_str("| seq | URL | status | server | tech |\n|---|---|---|---|---|\n");
        for surf in surfaces {
            s.push_str(&format!(
                "| {} | `{}://{}:{}{}` | {} | {} | {} |\n",
                surf.seq,
                surf.scheme,
                surf.host,
                surf.port,
                surf.path,
                surf.status,
                surf.server.as_deref().unwrap_or(""),
                surf.tech_hints.join(", "),
            ));
        }
    }
    s.push_str("\n_Rendered by `mantis_render_report` via the Mantis MCP server._\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_surface_event() {
        let jsonl = r#"{"schema_version":1,"seq":4,"wall_clock_unix":0,"kind":{"kind":"SurfaceDiscovered","host":"app.tenkara.ai","port":443,"scheme":"https","path":"/","status":307,"server":"Vercel","content_length":null,"tech_hints":["next.js"]}}"#;
        let surfaces = parse_surfaces(jsonl);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].host, "app.tenkara.ai");
        assert_eq!(surfaces[0].status, 307);
        assert_eq!(surfaces[0].tech_hints, vec!["next.js".to_string()]);
    }

    #[test]
    fn ignores_non_surface_events() {
        let jsonl = "{\"seq\":0,\"kind\":{\"kind\":\"EngagementCreated\",\"name\":\"x\"}}\n{\"seq\":1,\"kind\":{\"kind\":\"EngagementStarted\"}}\n";
        let surfaces = parse_surfaces(jsonl);
        assert!(surfaces.is_empty());
    }

    #[test]
    fn renders_minimal_report() {
        let info = EngagementSummary {
            id: "01HXXX".into(),
            name: "test".into(),
            state: "active",
            created_at_unix: 0,
            event_count: 5,
            scope_hash: None,
        };
        let surfaces = vec![Surface {
            seq: 4,
            host: "x.example".into(),
            port: 443,
            scheme: "https".into(),
            path: "/".into(),
            status: 200,
            server: Some("nginx".into()),
            tech_hints: vec![],
        }];
        let md = render_markdown(&info, &surfaces);
        assert!(md.contains("x.example"));
        assert!(md.contains("Mantis Engagement Report"));
    }
}
