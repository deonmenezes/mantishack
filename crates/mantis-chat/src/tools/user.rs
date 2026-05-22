//! User-defined HTTP tools loaded from TOML files.
//!
//! **SECURITY NOTE**: User tools bypass the scope manifest. They
//! trust the operator. URL templates can be abused to SSRF arbitrary
//! internal services. For v1 this is intentional — we'll wire
//! `mantis-egress` enforcement in a follow-up. Don't enable a user-
//! tools directory in production environments where untrusted
//! operators can drop TOML files.
//!
//! TOML schema:
//! ```toml
//! [tool]
//! name = "shodan_lookup"
//! description = "Look up an IP on Shodan and return the host JSON."
//!
//! [tool.http]
//! method = "GET"
//! url = "https://api.shodan.io/shodan/host/{ip}?key=${SHODAN_API_KEY}"
//!
//! [tool.http.headers]
//! "User-Agent" = "mantis-chat/0.1"
//!
//! [[tool.params]]
//! name = "ip"
//! type = "string"
//! description = "IP address to look up, e.g. 1.1.1.1"
//! required = true
//! ```
//!
//! Templating:
//! - `{<param>}` in `url` / `headers` values is replaced with the
//!   URL-encoded model-supplied argument.
//! - `${ENV_VAR}` in `url` / `headers` values is replaced with the
//!   value of the process environment variable. Missing env vars
//!   cause the tool call to fail with a clear error.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use mantis_synthesizer::{Tool, ToolCall};

use crate::tools::ChatToolRegistry;

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const TIMEOUT_ENV: &str = "MANTIS_USER_TOOL_TIMEOUT";
const MAX_BODY_BYTES: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// TOML schema types.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ToolFile {
    tool: ToolDef,
}

#[derive(Debug, Deserialize, Clone)]
struct ToolDef {
    name: String,
    description: String,
    http: HttpDef,
    #[serde(default)]
    params: Vec<ParamDef>,
}

#[derive(Debug, Deserialize, Clone)]
struct HttpDef {
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ParamDef {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_required")]
    required: bool,
}

fn default_required() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Public registry.
// ---------------------------------------------------------------------------

/// Registry of HTTP-backed tools loaded from a flat directory of
/// TOML files. See module docs for the schema and security caveats.
#[derive(Debug, Default, Clone)]
pub struct UserToolRegistry {
    tools: Vec<ToolDef>,
    client: reqwest::Client,
}

impl UserToolRegistry {
    /// Build an empty registry (no tools, behaves like `NoTools`).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load every `*.toml` file directly inside `path` (non-recursive).
    /// Files that fail to parse emit a warning to stderr and are
    /// skipped — the registry loads as much as it can. If `path`
    /// does not exist, returns an empty registry (not an error):
    /// most operators won't have user tools configured and that's
    /// fine.
    pub fn from_dir(path: &Path) -> Result<Self, anyhow::Error> {
        let client = build_client()?;
        if !path.exists() {
            return Ok(Self {
                tools: Vec::new(),
                client,
            });
        }
        let entries = std::fs::read_dir(path)
            .with_context(|| format!("read user tool dir {}", path.display()))?;
        let mut tools = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("mantis-chat: skipping bad dir entry in {}: {e}", path.display());
                    continue;
                }
            };
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            match load_tool_file(&p) {
                Ok(def) => tools.push(def),
                Err(e) => {
                    eprintln!(
                        "mantis-chat: failed to load user tool {}: {e:#}",
                        p.display()
                    );
                }
            }
        }
        Ok(Self { tools, client })
    }

    fn find(&self, name: &str) -> Option<&ToolDef> {
        self.tools.iter().find(|t| t.name == name)
    }

    fn timeout(&self) -> Duration {
        if let Ok(v) = std::env::var(TIMEOUT_ENV) {
            if let Ok(secs) = v.parse::<u64>() {
                return Duration::from_secs(secs);
            }
        }
        Duration::from_secs(DEFAULT_TIMEOUT_SECS)
    }
}

fn build_client() -> Result<reqwest::Client, anyhow::Error> {
    // Default timeout is applied per-request via RequestBuilder so
    // that MANTIS_USER_TOOL_TIMEOUT can be honored dynamically.
    reqwest::Client::builder()
        .build()
        .context("build reqwest client for user tools")
}

fn load_tool_file(path: &Path) -> Result<ToolDef, anyhow::Error> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let file: ToolFile = toml::from_str(&raw)
        .with_context(|| format!("parse TOML {}", path.display()))?;
    validate_tool_def(&file.tool)
        .with_context(|| format!("invalid tool definition in {}", path.display()))?;
    Ok(file.tool)
}

fn validate_tool_def(def: &ToolDef) -> Result<(), anyhow::Error> {
    if def.name.is_empty() {
        return Err(anyhow!("tool.name must be non-empty"));
    }
    let method = def.http.method.to_ascii_uppercase();
    match method.as_str() {
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" => {}
        other => return Err(anyhow!("unsupported HTTP method: {other}")),
    }
    for p in &def.params {
        match p.ty.as_str() {
            "string" | "integer" | "number" | "boolean" => {}
            other => {
                return Err(anyhow!(
                    "param `{}` has unsupported type `{}` (expected string/integer/number/boolean)",
                    p.name,
                    other
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON Schema synthesis.
// ---------------------------------------------------------------------------

fn synthesize_schema(def: &ToolDef) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required: Vec<Value> = Vec::new();
    for p in &def.params {
        let mut prop = serde_json::Map::new();
        prop.insert("type".to_string(), Value::String(p.ty.clone()));
        if let Some(desc) = &p.description {
            prop.insert("description".to_string(), Value::String(desc.clone()));
        }
        properties.insert(p.name.clone(), Value::Object(prop));
        if p.required {
            required.push(Value::String(p.name.clone()));
        }
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn to_tool(def: &ToolDef) -> Tool {
    Tool {
        name: def.name.clone(),
        description: def.description.clone(),
        input_schema: synthesize_schema(def),
    }
}

// ---------------------------------------------------------------------------
// Templating: argument and env var substitution.
// ---------------------------------------------------------------------------

/// Simple URL-component encoder. Encodes everything outside the
/// "unreserved" set per RFC 3986 (ALPHA / DIGIT / `-` / `_` / `.` / `~`).
/// We intentionally encode `/`, `?`, `&`, `=`, `#`, `:` so a malicious
/// argument can't smuggle a different host or path into the template.
fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        let unreserved = b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'_'
            || b == b'.'
            || b == b'~';
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Coerce a JSON argument value to a string suitable for URL
/// templating. Strings pass through; numbers/booleans stringify;
/// arrays/objects/null are an error.
fn arg_to_string(name: &str, v: &Value) -> Result<String, anyhow::Error> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Err(anyhow!("argument `{name}` is null")),
        Value::Array(_) | Value::Object(_) => Err(anyhow!(
            "argument `{name}` is not a scalar; only string/number/boolean parameters can appear in URL or header templates"
        )),
    }
}

/// Render `{name}` and `${ENV}` references in `template`. Argument
/// substitutions are URL-encoded; env var substitutions are
/// inserted verbatim (the operator picked the value).
///
/// Env vars are expanded *before* argument placeholders so that
/// `${FOO}` is not mistakenly parsed as a `{FOO}` argument reference.
fn render_template(
    template: &str,
    args: &serde_json::Map<String, Value>,
) -> Result<String, anyhow::Error> {
    let with_env = render_env_placeholders(template)?;
    render_arg_placeholders(&with_env, args)
}

fn render_arg_placeholders(
    template: &str,
    args: &serde_json::Map<String, Value>,
) -> Result<String, anyhow::Error> {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'{' {
            // Find the matching '}'.
            if let Some(end_rel) = template[i + 1..].find('}') {
                let end = i + 1 + end_rel;
                let name = &template[i + 1..end];
                // Empty {} is not a placeholder — emit literally.
                if name.is_empty() {
                    out.push('{');
                    out.push('}');
                    i = end + 1;
                    continue;
                }
                let v = args
                    .get(name)
                    .ok_or_else(|| anyhow!("template references unknown argument `{name}`"))?;
                let s = arg_to_string(name, v)?;
                out.push_str(&url_encode(&s));
                i = end + 1;
                continue;
            } else {
                // Unmatched `{` — emit literally.
                out.push('{');
                i += 1;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    Ok(out)
}

fn render_env_placeholders(template: &str) -> Result<String, anyhow::Error> {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end_rel) = template[i + 2..].find('}') {
                let end = i + 2 + end_rel;
                let name = &template[i + 2..end];
                if name.is_empty() {
                    return Err(anyhow!("empty `${{}}` placeholder in template"));
                }
                let val = std::env::var(name).map_err(|_| {
                    anyhow!("environment variable `${{{name}}}` is not set")
                })?;
                out.push_str(&val);
                i = end + 1;
                continue;
            } else {
                return Err(anyhow!("unterminated `${{` placeholder in template"));
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Argument validation.
// ---------------------------------------------------------------------------

fn validate_args(
    def: &ToolDef,
    args: &serde_json::Map<String, Value>,
) -> Result<(), anyhow::Error> {
    for p in &def.params {
        let present = args.get(&p.name).is_some_and(|v| !v.is_null());
        if p.required && !present {
            return Err(anyhow!(
                "missing required argument `{}` for tool `{}`",
                p.name,
                def.name
            ));
        }
        if let Some(v) = args.get(&p.name) {
            // Best-effort type compatibility. JSON's number type is
            // flexible, so integer/number both accept any number;
            // boolean/string are strict.
            let ok = match p.ty.as_str() {
                "string" => v.is_string() || v.is_null(),
                "integer" | "number" => v.is_number() || v.is_null(),
                "boolean" => v.is_boolean() || v.is_null(),
                _ => true,
            };
            if !ok {
                return Err(anyhow!(
                    "argument `{}` for tool `{}` has wrong type (expected {})",
                    p.name,
                    def.name,
                    p.ty
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP execution.
// ---------------------------------------------------------------------------

async fn run_http(
    client: &reqwest::Client,
    def: &ToolDef,
    args: &serde_json::Map<String, Value>,
    timeout: Duration,
) -> Result<String, anyhow::Error> {
    let url = render_template(&def.http.url, args)
        .with_context(|| format!("render url for tool `{}`", def.name))?;
    let method = reqwest::Method::from_bytes(def.http.method.to_ascii_uppercase().as_bytes())
        .with_context(|| format!("invalid HTTP method for tool `{}`", def.name))?;
    let mut req = client.request(method, &url).timeout(timeout);
    for (k, v_template) in &def.http.headers {
        let v = render_template(v_template, args)
            .with_context(|| format!("render header `{k}` for tool `{}`", def.name))?;
        req = req.header(k, v);
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("HTTP request for tool `{}` to {url}", def.name))?;
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase());
    let bytes = resp
        .bytes()
        .await
        .with_context(|| format!("read response body for tool `{}`", def.name))?;
    if !status.is_success() {
        let preview = String::from_utf8_lossy(&bytes);
        let preview = truncate(&preview);
        return Err(anyhow!(
            "tool `{}` HTTP {} from {url}: {}",
            def.name,
            status.as_u16(),
            preview
        ));
    }
    let is_json = content_type
        .as_deref()
        .map(|c| c.contains("application/json") || c.contains("+json"))
        .unwrap_or(false);
    if is_json {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            return Ok(serde_json::to_string_pretty(&v).unwrap_or_else(|_| {
                String::from_utf8_lossy(&bytes).to_string()
            }));
        }
        // Fall through to text handling on parse failure.
    }
    let text = String::from_utf8_lossy(&bytes).to_string();
    Ok(truncate(&text))
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_BODY_BYTES {
        return s.to_string();
    }
    // Slice on a char boundary so we don't split a multi-byte char.
    let mut cut = MAX_BODY_BYTES;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(cut + 16);
    out.push_str(&s[..cut]);
    out.push_str("[...truncated]");
    out
}

// ---------------------------------------------------------------------------
// Trait impl.
// ---------------------------------------------------------------------------

#[async_trait]
impl ChatToolRegistry for UserToolRegistry {
    fn tools(&self) -> Vec<Tool> {
        self.tools.iter().map(to_tool).collect()
    }

    async fn execute(&self, call: &ToolCall) -> Result<String, anyhow::Error> {
        let def = self
            .find(&call.name)
            .ok_or_else(|| anyhow!("unknown user tool `{}`", call.name))?;
        let empty = serde_json::Map::new();
        let args = match &call.arguments {
            Value::Object(m) => m,
            Value::Null => &empty,
            _ => {
                return Err(anyhow!(
                    "tool `{}` expected an object of arguments",
                    call.name
                ))
            }
        };
        validate_args(def, args)?;
        run_http(&self.client, def, args, self.timeout()).await
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    struct CapturedRequest {
        request_line: String,
        headers: String,
        #[allow(dead_code)]
        body: String,
    }

    /// One-shot HTTP server: captures the first request, then
    /// replies with `response_body` (JSON or text per `content_type`).
    async fn mock_server(
        response_body: String,
        content_type: &'static str,
        captured: Arc<Mutex<Option<CapturedRequest>>>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let (headers_blob, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
            let request_line = headers_blob.lines().next().unwrap_or("").to_string();
            *captured.lock().await = Some(CapturedRequest {
                request_line,
                headers: headers_blob.to_string(),
                body: body.to_string(),
            });
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\n\r\n{}",
                response_body.len(),
                content_type,
                response_body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        });
        format!("http://{addr}")
    }

    fn write_tool_toml(dir: &Path, name: &str, body: &str) {
        let mut f = std::fs::File::create(dir.join(name)).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    // -----------------------------------------------------------------
    // Loader tests.
    // -----------------------------------------------------------------

    #[test]
    fn loads_tool_from_toml() {
        let dir = tempdir().unwrap();
        write_tool_toml(
            dir.path(),
            "shodan.toml",
            r#"
[tool]
name = "shodan_lookup"
description = "Look up an IP on Shodan."

[tool.http]
method = "GET"
url = "https://api.shodan.io/shodan/host/{ip}"

[[tool.params]]
name = "ip"
type = "string"
description = "IP address to look up"
required = true
"#,
        );
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let tools = reg.tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "shodan_lookup");
        assert_eq!(tools[0].description, "Look up an IP on Shodan.");
        // Schema sanity: required ip property.
        let schema = &tools[0].input_schema;
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["ip"]["type"], "string");
        assert_eq!(schema["required"], json!(["ip"]));
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    fn missing_dir_returns_empty_registry() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let reg = UserToolRegistry::from_dir(&missing).unwrap();
        assert!(reg.tools().is_empty());
    }

    #[test]
    fn malformed_toml_files_are_skipped_with_warning() {
        let dir = tempdir().unwrap();
        write_tool_toml(dir.path(), "broken.toml", "this is not valid toml = =");
        write_tool_toml(
            dir.path(),
            "good.toml",
            r#"
[tool]
name = "ping"
description = "Ping a host."

[tool.http]
method = "GET"
url = "https://example.com/"
"#,
        );
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let tools = reg.tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "ping");
    }

    #[test]
    fn parses_input_schema_correctly() {
        let dir = tempdir().unwrap();
        write_tool_toml(
            dir.path(),
            "lookup.toml",
            r#"
[tool]
name = "lookup"
description = "Lookup."

[tool.http]
method = "GET"
url = "https://example.com/{ip}"

[[tool.params]]
name = "ip"
type = "string"
required = true

[[tool.params]]
name = "history"
type = "boolean"
required = false
"#,
        );
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let tools = reg.tools();
        let schema = &tools[0].input_schema;
        assert_eq!(
            schema,
            &json!({
                "type": "object",
                "properties": {
                    "ip":      { "type": "string" },
                    "history": { "type": "boolean" }
                },
                "required": ["ip"],
                "additionalProperties": false
            })
        );
    }

    // -----------------------------------------------------------------
    // Execution tests.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn executes_get_request_with_url_template() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"ok":true}"#.into(),
            "application/json",
            captured.clone(),
        )
        .await;
        let dir = tempdir().unwrap();
        let toml_body = format!(
            r#"
[tool]
name = "lookup"
description = "Lookup an IP."

[tool.http]
method = "GET"
url = "{base}/host/{{ip}}"

[[tool.params]]
name = "ip"
type = "string"
required = true
"#,
            base = base
        );
        write_tool_toml(dir.path(), "lookup.toml", &toml_body);
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let call = ToolCall {
            id: "c1".into(),
            name: "lookup".into(),
            arguments: json!({ "ip": "1.1.1.1" }),
        };
        let out = reg.execute(&call).await.unwrap();
        // Response was JSON and got pretty-printed.
        assert!(out.contains("\"ok\""));
        let req = captured.lock().await.take().unwrap();
        // The IP path-segment characters are URL-encoded (dots are
        // unreserved, so they pass through). Verify the rendered
        // path contains the IP literally.
        assert!(
            req.request_line.contains("GET /host/1.1.1.1"),
            "got request line: {}",
            req.request_line
        );
    }

    #[tokio::test]
    async fn url_template_encodes_unsafe_argument_chars() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            "ok".into(),
            "text/plain",
            captured.clone(),
        )
        .await;
        let dir = tempdir().unwrap();
        let toml_body = format!(
            r#"
[tool]
name = "lookup"
description = "Lookup something."

[tool.http]
method = "GET"
url = "{base}/q/{{query}}"

[[tool.params]]
name = "query"
type = "string"
required = true
"#,
            base = base
        );
        write_tool_toml(dir.path(), "lookup.toml", &toml_body);
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let call = ToolCall {
            id: "c1".into(),
            name: "lookup".into(),
            arguments: json!({ "query": "a b/c?d" }),
        };
        let _ = reg.execute(&call).await.unwrap();
        let req = captured.lock().await.take().unwrap();
        // Space -> %20, slash -> %2F, question mark -> %3F.
        assert!(
            req.request_line.contains("a%20b%2Fc%3Fd"),
            "got: {}",
            req.request_line
        );
    }

    #[tokio::test]
    async fn expands_env_vars_in_url() {
        // Use a unique env var name per test so we don't race other tests.
        let var = "MANTIS_TEST_EXPAND_ENV_VAR_TOKEN";
        std::env::set_var(var, "secret-token-123");
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            "ok".into(),
            "text/plain",
            captured.clone(),
        )
        .await;
        let dir = tempdir().unwrap();
        let toml_body = format!(
            r#"
[tool]
name = "env_tool"
description = "Tool that uses an env var."

[tool.http]
method = "GET"
url = "{base}/path?key=${{{var}}}"
"#,
            base = base,
            var = var
        );
        write_tool_toml(dir.path(), "env.toml", &toml_body);
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let call = ToolCall {
            id: "c1".into(),
            name: "env_tool".into(),
            arguments: json!({}),
        };
        let _ = reg.execute(&call).await.unwrap();
        let req = captured.lock().await.take().unwrap();
        assert!(
            req.request_line.contains("key=secret-token-123"),
            "got: {}",
            req.request_line
        );
        std::env::remove_var(var);
    }

    #[tokio::test]
    async fn missing_env_var_errors() {
        let var = "MANTIS_TEST_MISSING_ENV_VAR_XYZ";
        std::env::remove_var(var);
        let dir = tempdir().unwrap();
        let toml_body = format!(
            r#"
[tool]
name = "needs_env"
description = "Needs env."

[tool.http]
method = "GET"
url = "https://example.com/?key=${{{var}}}"
"#,
            var = var
        );
        write_tool_toml(dir.path(), "needs.toml", &toml_body);
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let call = ToolCall {
            id: "c1".into(),
            name: "needs_env".into(),
            arguments: json!({}),
        };
        let err = reg.execute(&call).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(var) && msg.to_lowercase().contains("not set"),
            "expected env-var-not-set error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn missing_required_arg_errors() {
        let dir = tempdir().unwrap();
        write_tool_toml(
            dir.path(),
            "needs_ip.toml",
            r#"
[tool]
name = "needs_ip"
description = "Needs ip."

[tool.http]
method = "GET"
url = "https://example.com/{ip}"

[[tool.params]]
name = "ip"
type = "string"
required = true
"#,
        );
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let call = ToolCall {
            id: "c1".into(),
            name: "needs_ip".into(),
            arguments: json!({}),
        };
        let err = reg.execute(&call).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing required argument") && msg.contains("ip"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn renders_template_in_headers() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            "ok".into(),
            "text/plain",
            captured.clone(),
        )
        .await;
        let dir = tempdir().unwrap();
        let toml_body = format!(
            r#"
[tool]
name = "with_header"
description = "Tool with templated header."

[tool.http]
method = "GET"
url = "{base}/x"

[tool.http.headers]
"X-Trace-Id" = "{{trace_id}}"

[[tool.params]]
name = "trace_id"
type = "string"
required = true
"#,
            base = base
        );
        write_tool_toml(dir.path(), "h.toml", &toml_body);
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let call = ToolCall {
            id: "c1".into(),
            name: "with_header".into(),
            arguments: json!({ "trace_id": "abc-123" }),
        };
        let _ = reg.execute(&call).await.unwrap();
        let req = captured.lock().await.take().unwrap();
        assert!(
            req.headers
                .lines()
                .any(|l| l.eq_ignore_ascii_case("x-trace-id: abc-123")),
            "headers blob:\n{}",
            req.headers
        );
    }

    #[tokio::test]
    async fn non_2xx_response_returns_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"error":"nope"}"#;
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        let base = format!("http://{addr}");
        let dir = tempdir().unwrap();
        let toml_body = format!(
            r#"
[tool]
name = "explodes"
description = "Always 500s."

[tool.http]
method = "GET"
url = "{base}/x"
"#,
            base = base
        );
        write_tool_toml(dir.path(), "explodes.toml", &toml_body);
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let call = ToolCall {
            id: "c1".into(),
            name: "explodes".into(),
            arguments: json!({}),
        };
        let err = reg.execute(&call).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("500"), "got: {msg}");
    }

    #[tokio::test]
    async fn truncates_large_text_body() {
        // Build a server that streams a body > 16 KiB.
        let big = "A".repeat(20_000);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let big_for_server = big.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                big_for_server.len(),
                big_for_server
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        let base = format!("http://{addr}");
        let dir = tempdir().unwrap();
        let toml_body = format!(
            r#"
[tool]
name = "big"
description = "Returns a big body."

[tool.http]
method = "GET"
url = "{base}/big"
"#,
            base = base
        );
        write_tool_toml(dir.path(), "big.toml", &toml_body);
        let reg = UserToolRegistry::from_dir(dir.path()).unwrap();
        let call = ToolCall {
            id: "c1".into(),
            name: "big".into(),
            arguments: json!({}),
        };
        let out = reg.execute(&call).await.unwrap();
        assert!(out.ends_with("[...truncated]"), "tail: ...{}", &out[out.len().saturating_sub(40)..]);
        assert!(out.len() < big.len(), "expected truncation");
    }

    // -----------------------------------------------------------------
    // Unit-ish helpers.
    // -----------------------------------------------------------------

    #[test]
    fn url_encode_keeps_unreserved_and_escapes_others() {
        assert_eq!(url_encode("abc-_.~"), "abc-_.~");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("/?&="), "%2F%3F%26%3D");
    }

    #[test]
    fn unknown_argument_in_template_errors() {
        let mut args = serde_json::Map::new();
        args.insert("ip".into(), json!("1.1.1.1"));
        let err = render_arg_placeholders("https://x/{not_there}", &args).unwrap_err();
        assert!(format!("{err:#}").contains("unknown argument"));
    }
}
