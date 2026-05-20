//! `find_auth_bugs` — the end-to-end pipeline.

use mantis_auth::AuthProfile;
use mantis_auth_differential::{
    run_differential, DiffFinding, ProfileBinding, ProfileRole, RunnerConfig,
};
use mantis_scanner_http::{generate_candidates, EnumerationConfig};
use mantis_signup::{signup_supabase, SupabaseSignupConfig};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Clone, Error)]
pub enum OrchestratorError {
    #[error("signup failed for `{profile_name}`: {source}")]
    Signup {
        profile_name: String,
        source: mantis_signup::SignupError,
    },
    #[error("no endpoints to probe — enumeration returned 0 candidates")]
    NoCandidates,
    #[error("authorization not granted (`--i-have-authorization` not set)")]
    NotAuthorized,
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthBugConfig {
    /// Target — the seed URL the enumerator expands from. e.g.
    /// `https://app.tenkara.ai/`.
    pub target_url: String,
    /// Supabase signup endpoint (full URL). When set, drives the
    /// Supabase JSON signup path. The `apikey` MUST also be set.
    pub supabase_signup_url: Option<String>,
    /// Public anon key for Supabase. Required when
    /// `supabase_signup_url` is set.
    pub supabase_apikey: Option<String>,
    /// Max candidates probed by the enumerator.
    pub max_candidates: usize,
    /// Hard cap on auth-diff probes total. Stops once reached.
    /// Protects against runaway enumerations.
    pub max_endpoints_probed: usize,
    /// Skip subdomain expansion in the enumerator.
    pub no_subdomain_expansion: bool,
    /// Extra candidate paths to probe on top of the built-in
    /// wordlist. Operator-supplied target-specific paths.
    pub extra_paths: Vec<String>,
}

impl Default for AuthBugConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            supabase_signup_url: None,
            supabase_apikey: None,
            max_candidates: 60,
            max_endpoints_probed: 60,
            no_subdomain_expansion: true,
            extra_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointResult {
    pub url: String,
    pub findings: Vec<DiffFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthBugReport {
    pub target_url: String,
    pub attacker_email: Option<String>,
    pub victim_email: Option<String>,
    pub endpoints_probed: usize,
    pub endpoints_with_findings: usize,
    pub findings_total: usize,
    pub findings_by_severity: std::collections::BTreeMap<String, u32>,
    pub findings_by_class: std::collections::BTreeMap<String, u32>,
    pub per_endpoint: Vec<EndpointResult>,
}

/// Drive the full chain with BYO profiles (skip the signup phase).
/// Useful when the target isn't Supabase-backed and the operator
/// has captured `AuthProfile` JSON via DevTools or manual paste.
pub async fn find_auth_bugs_with_profiles(
    config: &AuthBugConfig,
    attacker: Option<AuthProfile>,
    victim: Option<AuthProfile>,
) -> Result<AuthBugReport, OrchestratorError> {
    let attacker_email = attacker.as_ref().map(|p| format!("BYO[{}]", p.name));
    let victim_email = victim.as_ref().map(|p| format!("BYO[{}]", p.name));
    drive_pipeline(config, attacker, victim, attacker_email, victim_email).await
}

/// Drive the full chain. Returns once enumeration is exhausted or
/// `max_endpoints_probed` is reached.
///
/// The function is async + does network I/O — call from a Tokio
/// runtime. It does NOT touch the daemon's egress proxy directly;
/// downstream callers (the CLI / MCP tool) can wrap with the proxy
/// URL via `RunnerConfig::proxy`.
pub async fn find_auth_bugs(config: &AuthBugConfig) -> Result<AuthBugReport, OrchestratorError> {
    // --- 1. Sign up attacker + victim if Supabase config is supplied ---
    let (attacker, victim, attacker_email, victim_email) =
        match (&config.supabase_signup_url, &config.supabase_apikey) {
            (Some(url), Some(key)) if !key.is_empty() => {
                let sb = SupabaseSignupConfig {
                    apikey: key.clone(),
                    timeout_secs: 10,
                };
                info!("[orchestrator] signing up attacker");
                let (att_out, att_profile) = signup_supabase(url, &sb, None, None, "attacker")
                    .await
                    .map_err(|e| OrchestratorError::Signup {
                        profile_name: "attacker".into(),
                        source: e,
                    })?;
                info!("[orchestrator] signing up victim");
                let (vic_out, vic_profile) = signup_supabase(url, &sb, None, None, "victim")
                    .await
                    .map_err(|e| OrchestratorError::Signup {
                        profile_name: "victim".into(),
                        source: e,
                    })?;
                (
                    Some(att_profile),
                    Some(vic_profile),
                    Some(att_out.email),
                    Some(vic_out.email),
                )
            }
            _ => {
                info!(
                    "[orchestrator] no Supabase signup config — running unauth-only differential"
                );
                (None, None, None, None)
            }
        };

    drive_pipeline(config, attacker, victim, attacker_email, victim_email).await
}

async fn drive_pipeline(
    config: &AuthBugConfig,
    attacker: Option<AuthProfile>,
    victim: Option<AuthProfile>,
    attacker_email: Option<String>,
    victim_email: Option<String>,
) -> Result<AuthBugReport, OrchestratorError> {
    // --- 2. Enumerate candidate endpoints ---
    // Always enumerate against the seed target.
    let mut cands = generate_candidates(
        &config.target_url,
        &EnumerationConfig {
            max_candidates: config.max_candidates,
            expand_subdomains: !config.no_subdomain_expansion,
            extra_paths: config.extra_paths.clone(),
            ..Default::default()
        },
    );
    // ALSO enumerate against the Supabase project URL when it's
    // configured — that's where the *real* RLS / PostgREST attack
    // surface lives. Without this, `mantis hack app.tenkara.ai`
    // would never probe `lciwjbtbadjpkooufsvx.supabase.co/rest/v1/*`.
    // The Supabase REST API doesn't use a wordlist — known table
    // names + a few RPC paths are the canonical surface.
    if let Some(supabase_signup_url) = &config.supabase_signup_url {
        if let Some(supabase_base) = supabase_base_from_signup(supabase_signup_url) {
            let supabase_paths = supabase_default_paths();
            for path in supabase_paths {
                cands.push(format!("{supabase_base}{path}"));
            }
            // Operator-supplied paths are tried on BOTH hosts so the
            // operator only specifies them once.
            for path in &config.extra_paths {
                let normalized = if path.starts_with('/') {
                    path.clone()
                } else {
                    format!("/{path}")
                };
                cands.push(format!("{supabase_base}{normalized}"));
            }
            tracing::info!(
                "[orchestrator] expanded with Supabase host: {} ({} known paths + {} extra)",
                supabase_base,
                supabase_default_paths().len(),
                config.extra_paths.len()
            );
        }
    }
    if cands.is_empty() {
        return Err(OrchestratorError::NoCandidates);
    }
    info!("[orchestrator] {} candidate URL(s)", cands.len());

    // --- 3. Auth-diff each candidate ---
    let mut per_endpoint: Vec<EndpointResult> = Vec::new();
    let runner_config = RunnerConfig::default();
    let mut probed = 0usize;
    for url in &cands {
        if probed >= config.max_endpoints_probed {
            break;
        }
        probed += 1;
        let mut bindings: Vec<ProfileBinding<'_>> = vec![ProfileBinding {
            role: ProfileRole::Unauthenticated,
            profile: None,
        }];
        if let Some(att) = &attacker {
            bindings.push(ProfileBinding {
                role: ProfileRole::Attacker,
                profile: Some(att),
            });
        }
        if let Some(vic) = &victim {
            bindings.push(ProfileBinding {
                role: ProfileRole::Victim,
                profile: Some(vic),
            });
        }
        match run_differential(url, &bindings, &runner_config).await {
            Ok(findings) => {
                if !findings.is_empty() {
                    info!("[orchestrator] {} → {} finding(s)", url, findings.len());
                }
                per_endpoint.push(EndpointResult {
                    url: url.clone(),
                    findings,
                });
            }
            Err(e) => {
                warn!("[orchestrator] {} → runner error: {e}", url);
                per_endpoint.push(EndpointResult {
                    url: url.clone(),
                    findings: Vec::new(),
                });
            }
        }
    }

    // --- 4. Aggregate ---
    let mut findings_by_severity: std::collections::BTreeMap<String, u32> =
        std::collections::BTreeMap::new();
    let mut findings_by_class: std::collections::BTreeMap<String, u32> =
        std::collections::BTreeMap::new();
    let mut total = 0usize;
    let mut endpoints_with_findings = 0usize;
    for ep in &per_endpoint {
        if !ep.findings.is_empty() {
            endpoints_with_findings += 1;
        }
        total += ep.findings.len();
        for f in &ep.findings {
            *findings_by_severity
                .entry(f.class.default_severity().to_string())
                .or_default() += 1;
            *findings_by_class
                .entry(f.class.vuln_class().to_string())
                .or_default() += 1;
        }
    }

    Ok(AuthBugReport {
        target_url: config.target_url.clone(),
        attacker_email,
        victim_email,
        endpoints_probed: probed,
        endpoints_with_findings,
        findings_total: total,
        findings_by_severity,
        findings_by_class,
        per_endpoint,
    })
}

/// Strip `/auth/v1/signup` from a Supabase signup URL to get the
/// project base. `https://x.supabase.co/auth/v1/signup` → `https://x.supabase.co`.
fn supabase_base_from_signup(signup_url: &str) -> Option<String> {
    let stripped = signup_url.trim_end_matches('/');
    let suffixes = ["/auth/v1/signup", "/auth/v1", "/auth"];
    for s in &suffixes {
        if let Some(base) = stripped.strip_suffix(s) {
            return Some(base.to_string());
        }
    }
    Some(stripped.to_string())
}

/// The PostgREST + auth-API surface that ships with every Supabase
/// project. We probe every table-shaped path that previously-reported
/// Supabase bug-bounties found vulnerable, plus the auth-API.
/// Operators add target-specific tables via `--extra-path`.
fn supabase_default_paths() -> Vec<&'static str> {
    vec![
        // PostgREST tables that public bounty reports have repeatedly
        // found missing-or-permissive RLS on.
        "/rest/v1/users?select=*&limit=5",
        "/rest/v1/organizations?select=*&limit=5",
        "/rest/v1/orders?select=*&limit=5",
        "/rest/v1/suppliers?select=*&limit=5",
        "/rest/v1/formulas?select=*&limit=5",
        "/rest/v1/notifications?select=*&limit=5",
        "/rest/v1/materials?select=*&limit=5",
        "/rest/v1/vendor_packets?select=*&limit=5",
        "/rest/v1/system_settings?select=*&limit=5",
        "/rest/v1/operators_view?select=*&limit=5",
        "/rest/v1/profiles?select=*&limit=5",
        "/rest/v1/teams?select=*&limit=5",
        "/rest/v1/team_members?select=*&limit=5",
        "/rest/v1/invitations?select=*&limit=5",
        "/rest/v1/sessions?select=*&limit=5",
        "/rest/v1/products?select=*&limit=5",
        "/rest/v1/customers?select=*&limit=5",
        "/rest/v1/invoices?select=*&limit=5",
        "/rest/v1/payments?select=*&limit=5",
        "/rest/v1/projects?select=*&limit=5",
        // Auth-API surface.
        "/auth/v1/health",
        "/auth/v1/user",
        "/auth/v1/admin/users",
    ]
}

/// Build the [`AuthProfile`] payload pair from a previously-captured
/// attacker + victim outcome. Useful when the operator captured
/// profiles out-of-band (manual paste) and wants to drive the
/// differential without re-running signup.
pub fn pair_from_profiles(
    attacker: AuthProfile,
    victim: AuthProfile,
) -> (AuthProfile, AuthProfile) {
    (attacker, victim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Synthetic target: combines a fake Supabase signup endpoint
    /// (returns a stable JWT per email) AND a cross-tenant-vulnerable
    /// `/rest/v1/orders` endpoint.
    async fn spawn_tenkara_like_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let req_lower = req.to_ascii_lowercase();

                    let (status, body): (&str, String) =
                        if req_lower.contains("post /auth/v1/signup") {
                            // Pull email from JSON body roughly. Whichever
                            // email we get, mint a stable per-email JWT.
                            let token = if req.contains("\"email\":\"") {
                                let idx = req.find("\"email\":\"").unwrap() + 9;
                                let rest = &req[idx..];
                                let end = rest.find('"').unwrap_or(rest.len());
                                format!("JWT-{}", &rest[..end])
                            } else {
                                "JWT-anon".into()
                            };
                            (
                                "HTTP/1.1 200 OK",
                                serde_json::json!({
                                    "access_token": token,
                                    "token_type": "bearer",
                                    "expires_in": 3600,
                                    "refresh_token": "R",
                                    "user": {"id":"u-1"}
                                })
                                .to_string(),
                            )
                        } else if req_lower.contains("get /rest/v1/orders") {
                            // Vulnerable endpoint: any Bearer wins. The
                            // body shape is identical regardless of which
                            // account asked.
                            if req_lower.contains("authorization: bearer") {
                                (
                                    "HTTP/1.1 200 OK",
                                    serde_json::json!([
                                        {"id":"o-1","organization_id":"victim-org","total":500},
                                        {"id":"o-2","organization_id":"victim-org","total":750}
                                    ])
                                    .to_string(),
                                )
                            } else {
                                (
                                    "HTTP/1.1 401 Unauthorized",
                                    r#"{"message":"JWT expired"}"#.to_string(),
                                )
                            }
                        } else if req_lower.contains("get /") {
                            // Index / unknown paths → 404 quickly.
                            ("HTTP/1.1 404 Not Found", "{}".into())
                        } else {
                            ("HTTP/1.1 400 Bad Request", "{}".into())
                        };

                    let response = format!(
                        "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    #[test]
    fn supabase_base_strips_signup_path() {
        assert_eq!(
            supabase_base_from_signup("https://x.supabase.co/auth/v1/signup"),
            Some("https://x.supabase.co".into())
        );
        assert_eq!(
            supabase_base_from_signup("https://x.supabase.co/auth/v1/signup/"),
            Some("https://x.supabase.co".into())
        );
        assert_eq!(
            supabase_base_from_signup("https://x.supabase.co"),
            Some("https://x.supabase.co".into())
        );
    }

    #[test]
    fn supabase_default_paths_covers_common_tables() {
        let paths = supabase_default_paths();
        // Smoke-test: the known-vulnerable tables from public Supabase
        // bounty reports are all included.
        for table in [
            "/rest/v1/users",
            "/rest/v1/orders",
            "/rest/v1/suppliers",
            "/rest/v1/system_settings",
            "/rest/v1/operators_view",
        ] {
            assert!(
                paths.iter().any(|p| p.starts_with(table)),
                "default path list missing {table}: {paths:?}"
            );
        }
    }

    #[tokio::test]
    async fn end_to_end_signup_then_diff_finds_cross_tenant_read() {
        let addr = spawn_tenkara_like_server().await;
        let port = addr.port();
        // Seed the enumerator at the root; extra path adds the vuln endpoint.
        let cfg = AuthBugConfig {
            target_url: format!("http://127.0.0.1:{port}/"),
            supabase_signup_url: Some(format!("http://127.0.0.1:{port}/auth/v1/signup")),
            supabase_apikey: Some("PUBLIC-ANON".into()),
            max_candidates: 80,
            max_endpoints_probed: 80,
            no_subdomain_expansion: true,
            extra_paths: vec!["/rest/v1/orders".into()],
        };
        let report = find_auth_bugs(&cfg).await.unwrap();
        assert!(
            report.attacker_email.is_some(),
            "expected attacker email — signup should have run"
        );
        assert!(report.victim_email.is_some());
        assert_ne!(report.attacker_email, report.victim_email);
        // Attacker + victim both reading the same /rest/v1/orders →
        // CrossTenantRead and ForeignOwnerIdentifier should fire.
        assert!(
            report.findings_total >= 2,
            "expected at least 2 findings, got {report:?}"
        );
        let any_cross_tenant = report.per_endpoint.iter().any(|e| {
            e.findings
                .iter()
                .any(|f| f.class == mantis_auth_differential::DivergenceClass::CrossTenantRead)
        });
        assert!(any_cross_tenant, "expected CrossTenantRead in: {report:?}");
        // The aggregate severity counts include `critical`.
        assert!(
            report
                .findings_by_severity
                .get("critical")
                .copied()
                .unwrap_or(0)
                >= 1
        );
    }

    #[tokio::test]
    async fn missing_supabase_config_runs_unauth_only() {
        let addr = spawn_tenkara_like_server().await;
        let cfg = AuthBugConfig {
            target_url: format!("http://127.0.0.1:{}/", addr.port()),
            supabase_signup_url: None,
            supabase_apikey: None,
            max_candidates: 8,
            max_endpoints_probed: 8,
            no_subdomain_expansion: true,
            extra_paths: vec![],
        };
        let report = find_auth_bugs(&cfg).await.unwrap();
        assert!(report.attacker_email.is_none());
        assert!(report.endpoints_probed > 0);
    }

    #[tokio::test]
    async fn signup_failure_propagates_with_profile_name() {
        let cfg = AuthBugConfig {
            target_url: "http://127.0.0.1:0/".into(),
            supabase_signup_url: Some("http://127.0.0.1:0/auth/v1/signup".into()),
            supabase_apikey: Some("KEY".into()),
            max_candidates: 1,
            max_endpoints_probed: 1,
            no_subdomain_expansion: true,
            extra_paths: vec![],
        };
        let err = find_auth_bugs(&cfg).await.unwrap_err();
        match err {
            OrchestratorError::Signup { profile_name, .. } => {
                assert_eq!(profile_name, "attacker");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn max_endpoints_probed_caps_work() {
        let addr = spawn_tenkara_like_server().await;
        let cfg = AuthBugConfig {
            target_url: format!("http://127.0.0.1:{}/", addr.port()),
            supabase_signup_url: None,
            supabase_apikey: None,
            max_candidates: 50,
            max_endpoints_probed: 3,
            no_subdomain_expansion: true,
            extra_paths: vec![],
        };
        let report = find_auth_bugs(&cfg).await.unwrap();
        assert!(report.endpoints_probed <= 3);
    }
}
