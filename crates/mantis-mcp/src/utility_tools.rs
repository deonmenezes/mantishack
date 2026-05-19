//! Pure-Rust helpers backing the leaf utility MCP tools:
//! `mantis_decode_jwt`, `mantis_diff_responses`, `mantis_summarize_url`.
//!
//! These tools don't talk to the daemon — they're stateless local
//! transformations that save hunters from shelling out to base64,
//! diff, or python urlparse. Keeping the logic out of `server.rs`
//! keeps that file focused on tool registration + daemon plumbing.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// mantis_decode_jwt
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecodeJwtArgs {
    /// The JWT to decode. Compact serialization, three dot-separated
    /// base64url-encoded segments: `header.payload.signature`. The
    /// signature is **not** verified — this tool decodes and
    /// inspects, it does not authenticate.
    pub jwt: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DecodedJwt {
    /// Header JSON (e.g. `{"alg":"HS256","typ":"JWT"}`).
    pub header: serde_json::Value,
    /// Payload (claims) JSON.
    pub payload: serde_json::Value,
    /// Raw base64url-encoded signature segment (not decoded — useful
    /// for length-based heuristics).
    pub signature_b64: String,
    /// Length of the decoded signature in bytes (0 on parse failure
    /// or empty signature).
    pub signature_bytes: usize,
    /// Sorted alphabetical list of claim keys present in the payload.
    pub claims_present: Vec<String>,
    /// Standard-claim convenience fields, when present. Decoded from
    /// `exp` / `nbf` / `iat` as unix seconds; left null otherwise.
    pub exp_unix: Option<i64>,
    pub nbf_unix: Option<i64>,
    pub iat_unix: Option<i64>,
    /// `iss` claim (string) when present.
    pub iss: Option<String>,
    /// `aud` claim, raw value (may be string or array).
    pub aud: Option<serde_json::Value>,
    /// `sub` claim when present.
    pub sub: Option<String>,
    /// `alg` from the header (e.g. `"HS256"`, `"RS256"`, `"none"`).
    pub alg: Option<String>,
    /// One-line warnings about dangerous patterns: `alg:none`,
    /// `signature:empty`, `exp:missing`, `exp:expired`, etc.
    pub warnings: Vec<String>,
}

/// Decode a JWT without verifying its signature. Always returns a
/// result — even malformed input becomes a structured payload with
/// `warnings` describing what went wrong. The caller (an LLM) gets
/// to reason about the failure modes instead of having to retry.
pub fn decode_jwt(jwt: &str) -> DecodedJwt {
    let mut out = DecodedJwt {
        header: serde_json::Value::Null,
        payload: serde_json::Value::Null,
        signature_b64: String::new(),
        signature_bytes: 0,
        claims_present: vec![],
        exp_unix: None,
        nbf_unix: None,
        iat_unix: None,
        iss: None,
        aud: None,
        sub: None,
        alg: None,
        warnings: vec![],
    };

    let trimmed = jwt.trim();
    let stripped = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .unwrap_or(trimmed);

    let parts: Vec<&str> = stripped.split('.').collect();
    if parts.len() != 3 {
        out.warnings.push(format!(
            "format:invalid (expected 3 dot-separated segments, got {})",
            parts.len()
        ));
        return out;
    }

    out.signature_b64 = parts[2].to_string();
    out.signature_bytes = b64url_decode(parts[2]).map(|v| v.len()).unwrap_or(0);
    if parts[2].is_empty() || out.signature_bytes == 0 {
        out.warnings.push("signature:empty".into());
    }

    match decode_segment_json(parts[0]) {
        Ok(h) => {
            out.alg = h.get("alg").and_then(|v| v.as_str()).map(str::to_owned);
            if matches!(out.alg.as_deref(), Some("none") | Some("None") | Some("NONE")) {
                out.warnings.push("alg:none — unauthenticated JWT".into());
            }
            out.header = h;
        }
        Err(e) => out.warnings.push(format!("header:{e}")),
    }

    match decode_segment_json(parts[1]) {
        Ok(p) => {
            // Standard claims.
            out.exp_unix = p.get("exp").and_then(json_as_i64);
            out.nbf_unix = p.get("nbf").and_then(json_as_i64);
            out.iat_unix = p.get("iat").and_then(json_as_i64);
            out.iss = p.get("iss").and_then(|v| v.as_str()).map(str::to_owned);
            out.sub = p.get("sub").and_then(|v| v.as_str()).map(str::to_owned);
            out.aud = p.get("aud").cloned();
            if let Some(obj) = p.as_object() {
                out.claims_present = obj.keys().cloned().collect();
                out.claims_present.sort();
            }
            // Warnings.
            if out.exp_unix.is_none() {
                out.warnings.push("exp:missing".into());
            } else if let Some(exp) = out.exp_unix {
                if exp < now_unix() {
                    out.warnings.push("exp:expired".into());
                }
            }
            if out.iss.is_none() {
                out.warnings.push("iss:missing".into());
            }
            out.payload = p;
        }
        Err(e) => out.warnings.push(format!("payload:{e}")),
    }
    out
}

fn json_as_i64(v: &serde_json::Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok()))
        .or_else(|| v.as_f64().map(|f| f as i64))
}

fn decode_segment_json(seg: &str) -> Result<serde_json::Value, String> {
    let bytes = b64url_decode(seg).ok_or_else(|| "base64url:invalid".to_string())?;
    let s = std::str::from_utf8(&bytes).map_err(|_| "utf8:invalid".to_string())?;
    serde_json::from_str::<serde_json::Value>(s).map_err(|e| format!("json:invalid({e})"))
}

/// Tiny base64url decoder (RFC 7515 §2). No padding required. Maps
/// `-` / `_` back to `+` / `/` before standard base64 decoding.
/// Returns `None` on any malformed character.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    // Pad to a multiple of 4 with '=' so the standard alphabet
    // decoder accepts it.
    let mut padded = String::with_capacity(s.len() + 3);
    for c in s.chars() {
        match c {
            '-' => padded.push('+'),
            '_' => padded.push('/'),
            c => padded.push(c),
        }
    }
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    b64_std_decode(&padded)
}

/// Self-contained standard-base64 decoder. We don't pull in the
/// `base64` crate just for this — a 40-line implementation keeps
/// dependencies tight.
fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut buf = 0u32;
        let mut pad = 0usize;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                if i < 2 {
                    return None;
                }
                pad += 1;
                continue;
            }
            buf = (buf << 6) | val(b)?;
        }
        // pad-shift compensates for missing trailing bytes.
        buf <<= 6 * pad;
        out.push((buf >> 16) as u8);
        if pad < 2 {
            out.push((buf >> 8) as u8);
        }
        if pad < 1 {
            out.push(buf as u8);
        }
    }
    Some(out)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// mantis_diff_responses
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiffResponsesArgs {
    /// "A" side response — the baseline (e.g. unauth or attacker
    /// profile).
    pub a: ResponseSnapshot,
    /// "B" side response — the comparison (e.g. authenticated or
    /// victim profile).
    pub b: ResponseSnapshot,
    /// Cap on the body-byte preview included in the result.
    /// Defaults to 256 to keep the LLM's view-window cheap.
    #[serde(default = "default_preview_cap")]
    pub preview_cap: usize,
}

fn default_preview_cap() -> usize {
    256
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ResponseSnapshot {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DiffResult {
    /// One of: `identical`, `status_changed`, `length_changed`,
    /// `headers_changed`, `body_changed`, `mixed`. The classifier
    /// picks the most-impactful label.
    pub classification: String,
    pub status_a: u16,
    pub status_b: u16,
    pub status_delta: bool,
    pub body_len_a: usize,
    pub body_len_b: usize,
    pub body_len_delta: i64,
    pub body_identical: bool,
    /// Headers present in `a` but missing in `b`.
    pub headers_only_in_a: Vec<String>,
    /// Headers present in `b` but missing in `a`.
    pub headers_only_in_b: Vec<String>,
    /// Header names whose values differ between sides.
    pub headers_value_changed: Vec<String>,
    /// First N bytes of body A (capped).
    pub body_preview_a: String,
    /// First N bytes of body B (capped).
    pub body_preview_b: String,
    /// Heuristic "interesting markers" found in either body — token
    /// shapes, error strings, user/admin role hints. Useful priors
    /// for an LLM deciding whether the diff is exploitable.
    pub markers: Vec<String>,
}

pub fn diff_responses(args: &DiffResponsesArgs) -> DiffResult {
    let a = &args.a;
    let b = &args.b;
    let cap = args.preview_cap.min(4096);

    let body_identical = a.body == b.body;
    let body_len_a = a.body.len();
    let body_len_b = b.body.len();
    let body_len_delta = body_len_b as i64 - body_len_a as i64;
    let status_delta = a.status != b.status;

    // Header diffing.
    let mut only_a: Vec<String> = vec![];
    let mut only_b: Vec<String> = vec![];
    let mut changed: Vec<String> = vec![];
    for (k, va) in &a.headers {
        match b.headers.get(k) {
            None => only_a.push(k.clone()),
            Some(vb) if vb != va => changed.push(k.clone()),
            _ => {}
        }
    }
    for k in b.headers.keys() {
        if !a.headers.contains_key(k) {
            only_b.push(k.clone());
        }
    }
    only_a.sort();
    only_b.sort();
    changed.sort();
    let headers_changed = !only_a.is_empty() || !only_b.is_empty() || !changed.is_empty();

    let classification = if !status_delta && body_identical && !headers_changed {
        "identical"
    } else if status_delta && !body_identical {
        "mixed"
    } else if status_delta {
        "status_changed"
    } else if body_identical && headers_changed {
        "headers_changed"
    } else if !body_identical && a.body.len() != b.body.len() {
        "length_changed"
    } else if !body_identical {
        "body_changed"
    } else {
        "mixed"
    }
    .to_string();

    let markers = scan_markers(&a.body, &b.body);

    DiffResult {
        classification,
        status_a: a.status,
        status_b: b.status,
        status_delta,
        body_len_a,
        body_len_b,
        body_len_delta,
        body_identical,
        headers_only_in_a: only_a,
        headers_only_in_b: only_b,
        headers_value_changed: changed,
        body_preview_a: cap_str(&a.body, cap),
        body_preview_b: cap_str(&b.body, cap),
        markers,
    }
}

fn cap_str(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        s.to_string()
    } else {
        let mut out = s[..cap].to_string();
        out.push_str(" …(truncated)");
        out
    }
}

fn scan_markers(a: &str, b: &str) -> Vec<String> {
    const PATTERNS: &[(&str, &str)] = &[
        ("role:admin", "\"admin\""),
        ("role:superuser", "\"superuser\""),
        ("role:user", "\"user\""),
        ("token:jwt-shape", "eyJ"),
        ("error:unauthorized", "unauthorized"),
        ("error:forbidden", "forbidden"),
        ("error:not_found", "not found"),
        ("flag:debug_true", "\"debug\":true"),
        ("flag:is_admin_true", "\"is_admin\":true"),
        ("flag:owner_true", "\"owner\":true"),
        ("supabase:apikey", "apikey"),
        ("aws:access_key", "AKIA"),
        ("stripe:live_key", "sk_live_"),
        ("github:token", "ghp_"),
    ];
    let mut out: Vec<String> = vec![];
    for (label, needle) in PATTERNS {
        let in_a = a.contains(needle);
        let in_b = b.contains(needle);
        if in_a && !in_b {
            out.push(format!("{label} (only in A)"));
        } else if in_b && !in_a {
            out.push(format!("{label} (only in B)"));
        } else if in_a && in_b {
            out.push(format!("{label} (both)"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// mantis_summarize_url
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SummarizeUrlArgs {
    pub url: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UrlSummary {
    pub raw: String,
    pub scheme: Option<String>,
    pub userinfo: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub effective_port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub query_params: Vec<(String, String)>,
    pub flags: UrlFlags,
}

#[derive(Debug, Serialize, JsonSchema, Default)]
pub struct UrlFlags {
    /// `true` if the host is a literal IPv4 / IPv6 address.
    pub host_is_ip_literal: bool,
    /// `true` if the host is a private (RFC 1918), loopback,
    /// link-local, or cloud-metadata candidate.
    pub host_is_internal: bool,
    /// `true` if the URL embeds `user:pass@host` (RFC 3986 userinfo).
    pub has_userinfo: bool,
    /// `true` if the URL uses a non-https scheme.
    pub is_plaintext_scheme: bool,
    /// `true` if the path looks like a server-side resource that
    /// could host secrets (matches `.env`, `.git/config`,
    /// `.aws/credentials`, `.npmrc`, …).
    pub path_is_secret_artifact: bool,
    /// `true` if the path looks like an admin / privileged endpoint
    /// (`/admin`, `/internal`, `/debug`, `/_health`, `/actuator`).
    pub path_is_admin_like: bool,
    /// Cloud-metadata candidates: `169.254.169.254`, `metadata.google.internal`,
    /// `metadata.azure.com`, `100.100.100.200` (Alibaba), `2852039166` (decimal).
    pub host_is_cloud_metadata: bool,
}

/// Lightweight URL parser. We don't pull in the `url` crate to keep
/// the dependency surface small; the grammar we need is RFC 3986's
/// happy path for absolute URLs, plus a few SSRF-relevant
/// classifications.
pub fn summarize_url(raw: &str) -> UrlSummary {
    let raw_trim = raw.trim().to_string();
    let mut out = UrlSummary {
        raw: raw_trim.clone(),
        scheme: None,
        userinfo: None,
        host: None,
        port: None,
        effective_port: None,
        path: String::new(),
        query: None,
        fragment: None,
        query_params: vec![],
        flags: UrlFlags::default(),
    };

    // scheme://
    let rest = if let Some(idx) = raw_trim.find("://") {
        let scheme = raw_trim[..idx].to_ascii_lowercase();
        out.scheme = Some(scheme.clone());
        out.flags.is_plaintext_scheme = !matches!(scheme.as_str(), "https" | "wss");
        &raw_trim[idx + 3..]
    } else {
        return out;
    };

    // fragment.
    let (rest, fragment) = split_once_at(rest, '#');
    out.fragment = fragment.map(str::to_owned);

    // query.
    let (rest, query) = split_once_at(rest, '?');
    out.query = query.map(str::to_owned);
    if let Some(q) = &out.query {
        out.query_params = parse_query(q);
    }

    // authority (userinfo@host:port) / path
    let (authority, path) = split_once_at(rest, '/');
    let path = path.map(|p| format!("/{p}")).unwrap_or_else(|| "/".to_string());
    out.path = path;
    out.flags.path_is_secret_artifact = is_secret_artifact(&out.path);
    out.flags.path_is_admin_like = is_admin_like(&out.path);

    let (userinfo, hostport) = if let Some(at) = authority.rfind('@') {
        (Some(&authority[..at]), &authority[at + 1..])
    } else {
        (None, authority)
    };
    if let Some(u) = userinfo {
        out.userinfo = Some(u.to_string());
        out.flags.has_userinfo = true;
    }

    // host[:port]. Brackets for IPv6.
    if let Some(stripped) = hostport.strip_prefix('[') {
        if let Some(close) = stripped.find(']') {
            out.host = Some(stripped[..close].to_string());
            let after = &stripped[close + 1..];
            if let Some(p) = after.strip_prefix(':') {
                out.port = p.parse().ok();
            }
        }
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        out.host = Some(h.to_string());
        out.port = p.parse().ok();
    } else if !hostport.is_empty() {
        out.host = Some(hostport.to_string());
    }

    out.effective_port = out
        .port
        .or_else(|| match out.scheme.as_deref() {
            Some("http") | Some("ws") => Some(80),
            Some("https") | Some("wss") => Some(443),
            Some("ftp") => Some(21),
            _ => None,
        });

    if let Some(h) = &out.host {
        out.flags.host_is_ip_literal = is_ip_literal(h);
        out.flags.host_is_internal = is_internal_host(h);
        out.flags.host_is_cloud_metadata = is_cloud_metadata_host(h);
    }
    out
}

fn split_once_at(s: &str, c: char) -> (&str, Option<&str>) {
    match s.find(c) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (percent_decode_lossy(k), percent_decode_lossy(v)),
            None => (percent_decode_lossy(kv), String::new()),
        })
        .collect()
}

fn percent_decode_lossy(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_ip_literal(host: &str) -> bool {
    // IPv6 bracket form is handled before we get here, so host is
    // either IPv4 dotted-decimal or IPv6 with no brackets.
    host.chars().all(|c| c.is_ascii_digit() || c == '.')
        && host.split('.').count() == 4
        && host.split('.').all(|o| o.parse::<u8>().is_ok())
        || host.contains(':') && host.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

fn is_internal_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if matches!(h.as_str(), "localhost" | "ip6-localhost" | "ip6-loopback") {
        return true;
    }
    // RFC 1918 / loopback / link-local for IPv4 dotted-decimal.
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() == 4 {
        let p: Vec<Option<u8>> = parts.iter().map(|p| p.parse().ok()).collect();
        if p.iter().all(Option::is_some) {
            let o = (p[0].unwrap(), p[1].unwrap(), p[2].unwrap(), p[3].unwrap());
            if o.0 == 10 {
                return true;
            }
            if o.0 == 127 {
                return true;
            }
            if o.0 == 172 && (16..=31).contains(&o.1) {
                return true;
            }
            if o.0 == 192 && o.1 == 168 {
                return true;
            }
            if o.0 == 169 && o.1 == 254 {
                return true;
            }
            if o.0 == 100 && (64..=127).contains(&o.1) {
                return true;
            }
        }
    }
    // IPv6 loopback / unique-local.
    if h == "::1" || h.starts_with("fc") || h.starts_with("fd") || h.starts_with("fe80:") {
        return true;
    }
    h.ends_with(".internal") || h.ends_with(".local") || h.ends_with(".localhost")
}

fn is_cloud_metadata_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    matches!(
        h.as_str(),
        "169.254.169.254"
            | "metadata.google.internal"
            | "metadata.azure.com"
            | "metadata.azure.net"
            | "100.100.100.200"
            | "169.254.170.2"
    ) || h == "fd00:ec2::254"
}

fn is_secret_artifact(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/.env",
        "/.git/config",
        "/.aws/credentials",
        "/.npmrc",
        "/.dockercfg",
        "/.docker/config.json",
        "/.ssh/id_rsa",
        "/wp-config.php",
        "/web.config",
        "/config.json",
        "/credentials.json",
        "/.htpasswd",
    ]
    .iter()
    .any(|needle| p.contains(needle))
}

fn is_admin_like(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/admin",
        "/internal",
        "/debug",
        "/_health",
        "/actuator",
        "/server-status",
        "/server-info",
        "/private",
        "/.well-known/security.txt",
        "/management",
    ]
    .iter()
    .any(|needle| p.starts_with(needle) || p.contains(needle))
}

// ---------------------------------------------------------------------------
// mantis_extract_secrets
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractSecretsArgs {
    /// The text to scan. Typical inputs: HTTP response body, JS
    /// bundle contents, error stack traces, .env dumps, HTML pages.
    pub blob: String,
    /// Cap on the number of matches returned. Defaults to 100.
    #[serde(default = "default_match_cap")]
    pub match_cap: usize,
    /// Whether to include a short pre/post context window (24 bytes
    /// either side) around each match in the result. Defaults to
    /// `true`. Set false to compress the response.
    #[serde(default = "default_with_context")]
    pub with_context: bool,
}

fn default_match_cap() -> usize {
    100
}
fn default_with_context() -> bool {
    true
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SecretMatch {
    /// Kind tag (e.g. `aws_access_key`, `stripe_live_secret`,
    /// `github_pat`, `openai_key`, `anthropic_key`, `slack_token`,
    /// `private_key_pem`, `db_connection_url`, `jwt_shape`,
    /// `generic_high_entropy`).
    pub kind: String,
    /// Severity hint: `critical`, `high`, `medium`, `low`. Matches
    /// the grader rubric so the hunter can self-filter before
    /// recording a finding.
    pub severity_hint: String,
    /// Byte offset in the original blob.
    pub offset: usize,
    /// Byte length of the match.
    pub length: usize,
    /// Redacted form: shows the kind tag + first 4 / last 4 chars
    /// (e.g. `aws_access_key:AKIA…EXAMPLE`). Safe to log.
    pub redacted: String,
    /// Optional pre/post context window. Omitted when
    /// `with_context: false`.
    pub context: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SecretsReport {
    /// All matches found, capped at `match_cap`.
    pub matches: Vec<SecretMatch>,
    /// Total number of matches before capping.
    pub total_matches: usize,
    /// Count of distinct `kind` tags hit.
    pub distinct_kinds: usize,
    /// Highest severity_hint observed (`critical` > `high` >
    /// `medium` > `low` > `none`). Useful as a single-glance flag.
    pub max_severity: String,
}

/// Pattern catalog for the secret scanner. Each entry is a literal
/// prefix + an additional length range + a charset filter. We
/// deliberately avoid a regex dependency — these patterns all match
/// well-known token shapes whose prefixes are anchors.
struct SecretPattern {
    kind: &'static str,
    severity: &'static str,
    /// Literal prefix that anchors the match.
    prefix: &'static str,
    /// Minimum total length (including prefix).
    min_len: usize,
    /// Maximum total length (including prefix).
    max_len: usize,
    /// Allowed character class for the body (after the prefix).
    charset: fn(char) -> bool,
}

fn alnum_token(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn hex_or_alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

const PATTERNS: &[SecretPattern] = &[
    // AWS access key id — exactly 20 chars total (AKIA + 16).
    SecretPattern { kind: "aws_access_key", severity: "high",  prefix: "AKIA", min_len: 20, max_len: 20, charset: hex_or_alnum },
    // AWS temp / session token starts ASIA.
    SecretPattern { kind: "aws_temp_key",   severity: "high",  prefix: "ASIA", min_len: 20, max_len: 20, charset: hex_or_alnum },
    // GitHub Personal Access Token (fine-grained / classic).
    SecretPattern { kind: "github_pat",     severity: "critical", prefix: "ghp_", min_len: 40, max_len: 100, charset: alnum_token },
    SecretPattern { kind: "github_pat_fg",  severity: "critical", prefix: "github_pat_", min_len: 40, max_len: 200, charset: alnum_token },
    // GitHub OAuth / app token / refresh.
    SecretPattern { kind: "github_oauth",   severity: "high",  prefix: "gho_", min_len: 40, max_len: 100, charset: alnum_token },
    SecretPattern { kind: "github_user_app",severity: "high",  prefix: "ghu_", min_len: 40, max_len: 100, charset: alnum_token },
    SecretPattern { kind: "github_server",  severity: "high",  prefix: "ghs_", min_len: 40, max_len: 100, charset: alnum_token },
    SecretPattern { kind: "github_refresh", severity: "high",  prefix: "ghr_", min_len: 40, max_len: 100, charset: alnum_token },
    // Stripe.
    SecretPattern { kind: "stripe_live_secret",  severity: "critical", prefix: "sk_live_", min_len: 32, max_len: 100, charset: alnum_token },
    SecretPattern { kind: "stripe_live_publish", severity: "low",      prefix: "pk_live_", min_len: 32, max_len: 100, charset: alnum_token },
    SecretPattern { kind: "stripe_restricted",   severity: "critical", prefix: "rk_live_", min_len: 32, max_len: 100, charset: alnum_token },
    SecretPattern { kind: "stripe_test_secret",  severity: "low",      prefix: "sk_test_", min_len: 32, max_len: 100, charset: alnum_token },
    // OpenAI / Anthropic.
    SecretPattern { kind: "openai_key",      severity: "high", prefix: "sk-proj-", min_len: 60, max_len: 200, charset: alnum_token },
    SecretPattern { kind: "openai_user_key", severity: "high", prefix: "sk-", min_len: 30, max_len: 80,  charset: alnum_token },
    SecretPattern { kind: "anthropic_key",   severity: "high", prefix: "sk-ant-", min_len: 60, max_len: 200, charset: alnum_token },
    // Slack.
    SecretPattern { kind: "slack_bot_token",  severity: "high", prefix: "xoxb-", min_len: 24, max_len: 200, charset: alnum_token },
    SecretPattern { kind: "slack_user_token", severity: "high", prefix: "xoxp-", min_len: 24, max_len: 200, charset: alnum_token },
    SecretPattern { kind: "slack_app_token",  severity: "high", prefix: "xapp-", min_len: 24, max_len: 200, charset: alnum_token },
    // Google API keys.
    SecretPattern { kind: "google_api_key", severity: "high", prefix: "AIza", min_len: 39, max_len: 39, charset: alnum_token },
    // Mailgun / SendGrid (heuristics).
    SecretPattern { kind: "sendgrid_key",   severity: "high", prefix: "SG.", min_len: 40, max_len: 200, charset: alnum_token },
    SecretPattern { kind: "mailgun_key",    severity: "high", prefix: "key-", min_len: 36, max_len: 80,  charset: alnum_token },
    // Tailscale / Fly / Vercel.
    SecretPattern { kind: "tailscale_key",  severity: "high", prefix: "tskey-", min_len: 40, max_len: 200, charset: alnum_token },
    SecretPattern { kind: "fly_token",      severity: "high", prefix: "fly_",  min_len: 30, max_len: 200, charset: alnum_token },
    SecretPattern { kind: "vercel_token",   severity: "high", prefix: "vercel_", min_len: 30, max_len: 200, charset: alnum_token },
    // npm / Heroku.
    SecretPattern { kind: "npm_token",      severity: "high", prefix: "npm_", min_len: 30, max_len: 200, charset: alnum_token },
];

/// Scan `blob` for the catalog of known credential shapes plus a
/// couple of structural patterns (JWT shape, private-key PEM, DB
/// connection URL). Returns matches in offset order, capped at
/// `args.match_cap`.
pub fn extract_secrets(args: &ExtractSecretsArgs) -> SecretsReport {
    let blob = args.blob.as_str();
    let mut matches: Vec<SecretMatch> = vec![];

    // Catalog scan. Walk patterns longest-prefix-first so more-
    // specific shapes (e.g. `sk-ant-`) win over generic ancestors
    // (e.g. `sk-`) at the same offset during the overlap dedupe
    // step below.
    let mut pattern_order: Vec<&'static SecretPattern> = PATTERNS.iter().collect();
    pattern_order.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));
    for p in pattern_order {
        let mut start = 0usize;
        while let Some(idx) = blob[start..].find(p.prefix) {
            let abs = start + idx;
            // Walk forward as long as the charset matches and we
            // stay under max_len from the prefix anchor.
            let body_start = abs + p.prefix.len();
            let body_end = blob[body_start..]
                .char_indices()
                .take(p.max_len - p.prefix.len() + 1)
                .find(|(_, c)| !(p.charset)(*c))
                .map(|(i, _)| body_start + i)
                .unwrap_or_else(|| blob.len().min(body_start + (p.max_len - p.prefix.len())));
            let total_len = body_end - abs;
            if total_len >= p.min_len {
                push_match(
                    &mut matches,
                    blob,
                    p.kind,
                    p.severity,
                    abs,
                    total_len,
                    args.with_context,
                );
            }
            start = abs + p.prefix.len();
        }
    }

    // Structural patterns (no anchor prefix).
    scan_jwts(blob, args.with_context, &mut matches);
    scan_private_keys(blob, args.with_context, &mut matches);
    scan_connection_strings(blob, args.with_context, &mut matches);

    // Dedupe overlapping matches by preferring the longer one
    // (more-specific prefix). When two patterns prefix-match at the
    // same offset — e.g. `sk-` (openai_user_key) and `sk-ant-`
    // (anthropic_key) — we want the longer one to win. Sort by
    // (offset asc, length desc) and keep the first per offset.
    matches.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| b.length.cmp(&a.length))
    });
    let mut kept: Vec<SecretMatch> = Vec::with_capacity(matches.len());
    for m in matches {
        if kept.last().is_some_and(|prev| {
            ranges_overlap(prev.offset, prev.length, m.offset, m.length)
        }) {
            // The previous one (longer at same/earlier offset) already
            // covers this span — skip.
            continue;
        }
        kept.push(m);
    }
    let mut matches = kept;

    let total_matches = matches.len();
    let cap = args.match_cap.max(1).min(10_000);
    matches.truncate(cap);

    let mut distinct_kinds = std::collections::BTreeSet::new();
    let mut max_sev = "none";
    for m in &matches {
        distinct_kinds.insert(m.kind.clone());
        if severity_rank(&m.severity_hint) > severity_rank(max_sev) {
            max_sev = severity_text(severity_rank(&m.severity_hint));
        }
    }

    SecretsReport {
        matches,
        total_matches,
        distinct_kinds: distinct_kinds.len(),
        max_severity: max_sev.to_string(),
    }
}

fn ranges_overlap(a_off: usize, a_len: usize, b_off: usize, b_len: usize) -> bool {
    let a_end = a_off + a_len;
    let b_end = b_off + b_len;
    a_off < b_end && b_off < a_end
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}
fn severity_text(rank: u8) -> &'static str {
    match rank {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "none",
    }
}

fn push_match(
    out: &mut Vec<SecretMatch>,
    blob: &str,
    kind: &str,
    severity: &str,
    offset: usize,
    length: usize,
    with_context: bool,
) {
    let slice = &blob[offset..offset + length];
    let red = redact(kind, slice);
    let ctx = if with_context {
        let pre_start = offset.saturating_sub(24);
        let post_end = (offset + length + 24).min(blob.len());
        // Truncate at UTF-8 boundaries — fall back to byte-safe slice.
        let pre = char_safe(&blob[pre_start..offset]);
        let post = char_safe(&blob[offset + length..post_end]);
        Some(format!("…{pre}«{red}»{post}…"))
    } else {
        None
    };
    out.push(SecretMatch {
        kind: kind.to_string(),
        severity_hint: severity.to_string(),
        offset,
        length,
        redacted: red,
        context: ctx,
    });
}

fn redact(kind: &str, slice: &str) -> String {
    if slice.len() <= 12 {
        return format!("{kind}:<…redacted…>");
    }
    let head = &slice[..4];
    let tail = &slice[slice.len() - 4..];
    format!("{kind}:{head}…{tail}")
}

fn char_safe(s: &str) -> String {
    let mut last = 0usize;
    for (i, _) in s.char_indices() {
        last = i;
    }
    if last < s.len() {
        // tip past the last char start to include the full last char.
        let end = s.char_indices().last().map(|(i, c)| i + c.len_utf8()).unwrap_or(s.len());
        s[..end].to_string()
    } else {
        s.to_string()
    }
}

fn scan_jwts(blob: &str, with_context: bool, out: &mut Vec<SecretMatch>) {
    // Look for "eyJ" header anchor of a JSON-shaped JWT, then verify
    // it parses to a valid (3-segment, decodable) shape.
    let bytes = blob.as_bytes();
    let needle = b"eyJ";
    let mut i = 0;
    while i + 3 < bytes.len() {
        if &bytes[i..i + 3] == needle {
            // Walk forward across the JWT alphabet (base64url + dots).
            let mut j = i;
            let mut dots = 0;
            while j < bytes.len() {
                let c = bytes[j] as char;
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    j += 1;
                } else if c == '.' {
                    dots += 1;
                    if dots > 2 {
                        break;
                    }
                    j += 1;
                } else {
                    break;
                }
            }
            if dots >= 2 && j - i >= 24 {
                push_match(out, blob, "jwt_shape", "medium", i, j - i, with_context);
                i = j;
                continue;
            }
        }
        i += 1;
    }
}

fn scan_private_keys(blob: &str, with_context: bool, out: &mut Vec<SecretMatch>) {
    for needle in [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ] {
        let mut start = 0usize;
        while let Some(idx) = blob[start..].find(needle) {
            let abs = start + idx;
            // Find the matching END line; if absent, just mark the BEGIN.
            let after = abs + needle.len();
            let end_marker = needle.replace("BEGIN", "END");
            let end_pos = blob[after..]
                .find(&end_marker)
                .map(|e| after + e + end_marker.len())
                .unwrap_or(blob.len().min(after + 2048));
            let length = end_pos - abs;
            push_match(out, blob, "private_key_pem", "critical", abs, length, with_context);
            start = end_pos;
        }
    }
}

fn scan_connection_strings(blob: &str, with_context: bool, out: &mut Vec<SecretMatch>) {
    // Look for `<scheme>://<user>:<password>@host` shapes — fairly
    // narrow heuristic: requires '@' inside an URL-like span and a
    // colon in the userinfo segment.
    for scheme in [
        "postgres://",
        "postgresql://",
        "mysql://",
        "mongodb://",
        "mongodb+srv://",
        "redis://",
        "rediss://",
        "amqp://",
        "amqps://",
        "kafka://",
    ] {
        let mut start = 0usize;
        while let Some(idx) = blob[start..].find(scheme) {
            let abs = start + idx;
            // span until whitespace, quote, semicolon, or end of blob
            let span_end = blob[abs..]
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '<' | '>'))
                .map(|e| abs + e)
                .unwrap_or(blob.len());
            let span = &blob[abs..span_end];
            // Must contain userinfo (a colon before an @ inside the span).
            if let Some(at) = span.find('@') {
                if span[..at].contains(':') {
                    push_match(
                        out,
                        blob,
                        "db_connection_url",
                        "high",
                        abs,
                        span_end - abs,
                        with_context,
                    );
                }
            }
            start = span_end.max(abs + scheme.len());
        }
    }
}

// ---------------------------------------------------------------------------
// mantis_score_finding
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScoreFindingArgs {
    /// Claimed severity, one of `critical | high | medium | low | info`.
    pub severity: String,
    /// Vulnerability class (e.g. `idor`, `ssrf`, `auth_bypass`,
    /// `xss_stored`, `rce`, `info_disclosure`). Used by the
    /// severity-accuracy axis to penalize claims that don't match
    /// the impact ceiling for the class.
    #[serde(default)]
    pub vuln_class: String,
    /// Free-form impact description. The scorer looks for keywords
    /// like "rce", "admin", "ato", "production", "all users" to
    /// award impact points beyond what severity alone implies.
    #[serde(default)]
    pub impact_text: String,
    /// `true` if the finding has a reproducible PoC (HTTP request
    /// or contract call). Required to break out of the
    /// "speculative" tier.
    #[serde(default)]
    pub has_poc: bool,
    /// `true` if response evidence is captured (status, headers,
    /// body — even truncated).
    #[serde(default)]
    pub has_response_evidence: bool,
    /// The auth profile that produced the evidence (e.g.
    /// `attacker`, `victim`, `unauth`). Cross-profile evidence
    /// (attacker reading victim data) scores higher.
    #[serde(default)]
    pub auth_profile: Option<String>,
    /// `true` if at least one chain attempt confirmed the finding
    /// composes into a higher-severity outcome.
    #[serde(default)]
    pub chain_confirmed: bool,
    /// `true` if the finding is one of the "never-record-alone"
    /// noise classes (missing SPF, banner, CORS wildcard, CSV
    /// injection, …). Auto-routes to SKIP unless `chain_confirmed`.
    #[serde(default)]
    pub is_known_noise_class: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ScoreFindingResult {
    /// One of `SUBMIT`, `HOLD`, `SKIP`. Mirrors the grader rubric:
    ///   SUBMIT ≥ 40 with at least medium severity
    ///   HOLD   20–39
    ///   SKIP   < 20  (or any known-noise class without chain confirm)
    pub verdict: String,
    pub total_score: u32,
    pub impact: u32,
    pub proof_quality: u32,
    pub severity_accuracy: u32,
    pub chain_potential: u32,
    pub report_quality: u32,
    /// Short human-readable explanation of how the score was
    /// assembled and which axes are dragging the verdict.
    pub feedback: String,
    /// Concrete next steps a hunter could take to elevate the
    /// finding (extra request, alternate profile, chain hop) if the
    /// verdict is HOLD or SKIP.
    pub elevate_hints: Vec<String>,
}

/// Pure-Rust pre-grader. Mirrors the 5-axis rubric the `grader`
/// sub-agent uses post-VERIFY so a hunter can decide whether the
/// finding is worth recording before spending a `mantis_record_finding`
/// MCP call. Not a substitute for the real grader — same rubric,
/// strictly cheaper to call.
pub fn score_finding(args: &ScoreFindingArgs) -> ScoreFindingResult {
    let sev_rank = parse_severity_rank(&args.severity);

    // ----- impact (0–30) -----
    // Base by severity, then bumped by impact-text keywords.
    let mut impact: u32 = match sev_rank {
        4 => 22, // critical
        3 => 16, // high
        2 => 10, // medium
        1 => 4,  // low
        _ => 1,  // info
    };
    let it = args.impact_text.to_ascii_lowercase();
    for kw in [
        "rce", "remote code execution", "shell", "ssrf to imds", "imds",
        "admin takeover", "ato ", " ato", "data exfil", "data exfiltration",
        "mass assignment", "production data", "all users", "tenant isolation",
    ] {
        if it.contains(kw) {
            impact = (impact + 4).min(30);
        }
    }
    if matches!(args.auth_profile.as_deref(), Some("attacker") | Some("victim"))
        && (it.contains("cross-account") || it.contains("idor") || it.contains("other user"))
    {
        impact = (impact + 4).min(30);
    }
    impact = impact.min(30);

    // ----- proof quality (0–25) -----
    let mut proof_quality: u32 = 0;
    if args.has_poc { proof_quality += 12; }
    if args.has_response_evidence { proof_quality += 10; }
    if args.auth_profile.is_some() { proof_quality += 3; }
    proof_quality = proof_quality.min(25);

    // ----- severity accuracy (0–15) -----
    // Penalise mismatch: e.g. "critical" claim for a info-class
    // finding, or "low" for vuln_class=rce.
    let class_ceiling = vuln_class_ceiling(&args.vuln_class);
    let severity_accuracy: u32 = if class_ceiling == 0 {
        // unknown class — modest credit, not a freebie
        8
    } else if sev_rank <= class_ceiling {
        15
    } else {
        // claimed higher than the class typically maxes; scale down
        let over = sev_rank - class_ceiling;
        15u32.saturating_sub(over as u32 * 5)
    };

    // ----- chain potential (0–15) -----
    let chain_potential: u32 = if args.chain_confirmed { 15 } else { 3 };

    // ----- report quality (0–15) -----
    let report_quality: u32 = if args.has_response_evidence {
        if it.len() > 60 { 14 } else { 10 }
    } else if args.has_poc {
        7
    } else {
        2
    };

    let total = impact + proof_quality + severity_accuracy + chain_potential + report_quality;

    // ----- verdict -----
    let auto_skip_noise = args.is_known_noise_class && !args.chain_confirmed;
    // SUBMIT requires strong proof in addition to clearing the score
    // threshold — a "high severity claim with PoC but no captured
    // response" should still HOLD until the hunter captures evidence.
    let strong_proof = proof_quality >= 15;
    let verdict: &str = if auto_skip_noise {
        "SKIP"
    } else if total >= 45 && sev_rank >= 2 && strong_proof {
        "SUBMIT"
    } else if total >= 20 {
        "HOLD"
    } else {
        "SKIP"
    };

    // ----- feedback + hints -----
    let mut hints: Vec<String> = vec![];
    if !args.has_poc {
        hints.push("add a reproducible PoC (exact HTTP request / contract call)".into());
    }
    if !args.has_response_evidence {
        hints.push("capture the response (status + headers + body even truncated)".into());
    }
    if args.auth_profile.is_none() {
        hints.push("identify which auth_profile produced the evidence (attacker / victim / unauth)".into());
    }
    if !args.chain_confirmed && sev_rank < 3 {
        hints.push("try chaining: does this enable a higher-severity outcome end-to-end?".into());
    }
    if args.is_known_noise_class && !args.chain_confirmed {
        hints.push("known-noise class — only record if you can prove a chain into real impact".into());
    }
    if class_ceiling > 0 && sev_rank > class_ceiling {
        hints.push(format!(
            "claimed severity exceeds the ceiling for vuln_class '{}' — drop one tier or add evidence",
            args.vuln_class
        ));
    }

    let feedback = format!(
        "verdict={verdict} total={total} (impact={impact} proof={proof_quality} \
         sev_acc={severity_accuracy} chain={chain_potential} report={report_quality})"
    );

    ScoreFindingResult {
        verdict: verdict.to_string(),
        total_score: total,
        impact,
        proof_quality,
        severity_accuracy,
        chain_potential,
        report_quality,
        feedback,
        elevate_hints: hints,
    }
}

fn parse_severity_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Rough "what's the realistic ceiling for this vuln class" — used
/// to penalise inflated claims. Returns the severity rank (4=critical
/// down to 1=low); 0 means "unknown class, no penalty".
fn vuln_class_ceiling(class: &str) -> u8 {
    let c = class.trim().to_ascii_lowercase();
    match c.as_str() {
        "rce" | "auth_bypass_admin" | "ato_mass" | "ssrf_to_imds" => 4,
        "idor" | "ssrf" | "sqli" | "xss_stored" | "auth_bypass" | "privesc" => 3,
        "xss_reflected" | "csrf" | "open_redirect_chained" | "info_disclosure_pii" => 2,
        "missing_headers" | "spf_dkim_dmarc" | "graphql_introspection"
        | "banner_disclosure" | "csv_injection" | "cors_wildcard"
        | "logout_csrf" | "self_xss" | "open_redirect" | "rate_limit_login"
        | "missing_cookie_flags" | "password_autocomplete" => 1,
        "" => 0,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// mantis_hash_request
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HashRequestArgs {
    pub method: String,
    pub url: String,
    /// Header name → value. Sorted internally so order doesn't
    /// change the hash.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Body as-is. Empty string when there is no body.
    #[serde(default)]
    pub body: String,
    /// Names of headers to ignore for hashing (e.g. `Authorization`,
    /// `Cookie`, `User-Agent`). Default: a small set of known-noisy
    /// headers (`Authorization`, `Cookie`, `User-Agent`, `Accept`,
    /// `Accept-Encoding`, `X-Request-Id`, `X-Correlation-Id`,
    /// `Date`). Pass an explicit list to override.
    #[serde(default)]
    pub ignore_headers: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HashRequestResult {
    /// BLAKE3 hex digest of the normalized request.
    pub hash: String,
    /// First 16 hex chars — usable as a compact dedup key.
    pub short: String,
    /// Headers that were stripped before hashing.
    pub ignored_headers: Vec<String>,
}

/// Hash a request shape so two probes that differ only in noisy
/// headers (Authorization rotation, request id, user-agent) get the
/// same hash. Useful for hunter dedup: before issuing a probe, hash
/// (method, url, headers, body) and skip if it's already in the
/// in-memory seen-set or audit log.
pub fn hash_request(args: &HashRequestArgs) -> HashRequestResult {
    let default_ignored: &[&str] = &[
        "authorization",
        "cookie",
        "user-agent",
        "accept",
        "accept-encoding",
        "x-request-id",
        "x-correlation-id",
        "date",
    ];
    let ignore_lower: std::collections::BTreeSet<String> = if args.ignore_headers.is_empty() {
        default_ignored.iter().map(|s| s.to_string()).collect()
    } else {
        args.ignore_headers.iter().map(|s| s.to_ascii_lowercase()).collect()
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(args.method.to_ascii_uppercase().as_bytes());
    hasher.update(b"\x1f");
    hasher.update(args.url.as_bytes());
    hasher.update(b"\x1f");

    let mut kept: Vec<(String, String)> = vec![];
    for (k, v) in &args.headers {
        if ignore_lower.contains(&k.to_ascii_lowercase()) {
            continue;
        }
        kept.push((k.to_ascii_lowercase(), v.clone()));
    }
    kept.sort();
    for (k, v) in &kept {
        hasher.update(k.as_bytes());
        hasher.update(b":");
        hasher.update(v.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(b"\x1f");
    hasher.update(args.body.as_bytes());

    let hex = hasher.finalize().to_hex().to_string();
    let short = hex[..16].to_string();

    HashRequestResult {
        hash: hex,
        short,
        ignored_headers: ignore_lower.into_iter().collect(),
    }
}

// ---------------------------------------------------------------------------
// mantis_extract_html_forms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractHtmlFormsArgs {
    pub html: String,
    /// Base URL used to resolve relative `action` attributes.
    /// Optional — when omitted, relative actions are returned as-is.
    #[serde(default)]
    pub base_url: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct HtmlForm {
    pub method: String,
    pub action_raw: String,
    pub action_resolved: Option<String>,
    pub inputs: Vec<HtmlFormInput>,
    /// CSRF-token-looking inputs (name contains "csrf", "_token",
    /// "authenticity_token", "xsrf").
    pub csrf_tokens: Vec<HtmlFormInput>,
    /// Hidden inputs likely to be mass-assignment candidates
    /// (`user_id`, `role`, `is_admin`, `owner`, `tenant_id`).
    pub mass_assignment_candidates: Vec<HtmlFormInput>,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct HtmlFormInput {
    pub name: String,
    /// `text` / `hidden` / `password` / `email` / `submit` / `checkbox`
    /// / `radio` / `file` / `<other>`. Lowercased.
    pub input_type: String,
    pub value: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExtractHtmlFormsResult {
    pub forms: Vec<HtmlForm>,
    pub count: usize,
}

/// Tiny HTML-form extractor — does not depend on a full HTML parser
/// crate (no `scraper` / `html5ever` pull-in). The parser walks the
/// blob looking for `<form ...>` ... `</form>` spans, extracts the
/// attribute soup, then scans the body for `<input ...>` tags.
/// Good enough for offensive-recon use; mis-parses on broken HTML
/// (which we accept — hunters can fall back to a real parser if
/// needed).
pub fn extract_html_forms(args: &ExtractHtmlFormsArgs) -> ExtractHtmlFormsResult {
    let html = args.html.as_str();
    let mut forms: Vec<HtmlForm> = vec![];
    let lowered = html.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some(open_rel) = lowered[cursor..].find("<form") {
        let open_abs = cursor + open_rel;
        // Find the end of the opening tag.
        let after_open = match lowered[open_abs..].find('>') {
            Some(i) => open_abs + i + 1,
            None => break,
        };
        let close_rel = lowered[after_open..].find("</form>");
        let close_abs = close_rel.map(|i| after_open + i).unwrap_or(html.len());
        let open_tag = &html[open_abs..after_open];
        let body = &html[after_open..close_abs];

        let attrs = parse_attrs(open_tag);
        let method = attrs
            .get("method")
            .map(|s| s.to_ascii_uppercase())
            .unwrap_or_else(|| "GET".to_string());
        let action_raw = attrs.get("action").cloned().unwrap_or_default();
        let action_resolved = resolve_action(&action_raw, args.base_url.as_deref());

        let inputs = scan_inputs(body);
        let csrf_tokens: Vec<HtmlFormInput> = inputs
            .iter()
            .filter(|i| is_csrf_name(&i.name))
            .cloned()
            .collect();
        let mass_assignment_candidates: Vec<HtmlFormInput> = inputs
            .iter()
            .filter(|i| i.input_type == "hidden" && is_mass_assign_name(&i.name))
            .cloned()
            .collect();

        forms.push(HtmlForm {
            method,
            action_raw,
            action_resolved,
            inputs,
            csrf_tokens,
            mass_assignment_candidates,
        });
        cursor = close_abs + 7;
        if cursor >= html.len() {
            break;
        }
    }
    let count = forms.len();
    ExtractHtmlFormsResult { forms, count }
}

fn parse_attrs(tag_open: &str) -> std::collections::BTreeMap<String, String> {
    // Walk char-by-char; pull out name=value pairs. Quoted values
    // can use either single or double quotes.
    let mut out: std::collections::BTreeMap<String, String> = Default::default();
    let bytes = tag_open.as_bytes();
    let mut i = 0;
    // Skip the leading "<form" or "<input".
    while i < bytes.len() && bytes[i] != b' ' {
        i += 1;
    }
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        // name
        let name_start = i;
        while i < bytes.len() && !matches!(bytes[i], b'=' | b'>' | b'/' | b' ' | b'\t' | b'\n') {
            i += 1;
        }
        if name_start == i {
            i += 1;
            continue;
        }
        let name = tag_open[name_start..i].to_ascii_lowercase();
        // optional '=value'
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let val_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let val = &tag_open[val_start..i.min(tag_open.len())];
                out.insert(name, val.to_string());
                if i < bytes.len() {
                    i += 1;
                }
            } else {
                let val_start = i;
                while i < bytes.len() && !matches!(bytes[i], b'>' | b'/' | b' ' | b'\t' | b'\n') {
                    i += 1;
                }
                let val = &tag_open[val_start..i.min(tag_open.len())];
                out.insert(name, val.to_string());
            }
        } else {
            out.insert(name, String::new());
        }
        // Done if we hit the close of the tag.
        if i < bytes.len() && (bytes[i] == b'>' || bytes[i] == b'/') {
            break;
        }
    }
    out
}

fn scan_inputs(body: &str) -> Vec<HtmlFormInput> {
    let lowered = body.to_ascii_lowercase();
    let mut out: Vec<HtmlFormInput> = vec![];
    let mut cursor = 0;
    while let Some(rel) = lowered[cursor..].find("<input") {
        let abs = cursor + rel;
        let end_rel = lowered[abs..].find('>');
        let end_abs = abs + end_rel.unwrap_or(0) + 1;
        let tag = &body[abs..end_abs.min(body.len())];
        let attrs = parse_attrs(tag);
        let name = attrs.get("name").cloned().unwrap_or_default();
        if name.is_empty() {
            cursor = end_abs.max(abs + 6);
            continue;
        }
        let input_type = attrs
            .get("type")
            .cloned()
            .unwrap_or_else(|| "text".into())
            .to_ascii_lowercase();
        let value = attrs.get("value").cloned();
        out.push(HtmlFormInput {
            name,
            input_type,
            value,
        });
        cursor = end_abs.max(abs + 6);
    }
    out
}

fn resolve_action(action: &str, base: Option<&str>) -> Option<String> {
    if action.is_empty() {
        return base.map(str::to_owned);
    }
    if action.starts_with("http://") || action.starts_with("https://") {
        return Some(action.to_string());
    }
    let base = base?;
    // Strip any path/query/fragment from `base` to keep just the
    // scheme+host+port when the action is absolute-path.
    if action.starts_with('/') {
        if let Some(idx) = base.find("://").and_then(|i| base[i + 3..].find('/').map(|j| i + 3 + j)) {
            return Some(format!("{}{}", &base[..idx], action));
        }
        return Some(format!("{base}{action}"));
    }
    // Relative — chop the last path segment off base and append.
    let parent = base.rsplit_once('/').map(|(a, _)| a).unwrap_or(base);
    Some(format!("{parent}/{action}"))
}

fn is_csrf_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("csrf")
        || n == "_token"
        || n == "authenticity_token"
        || n.contains("xsrf")
        || n == "__requestverificationtoken"
}

fn is_mass_assign_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "user_id"
            | "userid"
            | "owner"
            | "owner_id"
            | "tenant_id"
            | "tenantid"
            | "role"
            | "is_admin"
            | "isadmin"
            | "admin"
            | "is_superuser"
            | "permissions"
            | "permission"
            | "org_id"
            | "organization_id"
            | "account_id"
    )
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jwt(header: &str, payload: &str) -> String {
        format!(
            "{}.{}.sig",
            base64url_encode(header.as_bytes()),
            base64url_encode(payload.as_bytes()),
        )
    }

    fn base64url_encode(b: &[u8]) -> String {
        const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in b.chunks(3) {
            let mut v: u32 = 0;
            for (i, &c) in chunk.iter().enumerate() {
                v |= (c as u32) << (16 - 8 * i);
            }
            for i in 0..(chunk.len() + 1) {
                out.push(ALPH[((v >> (18 - 6 * i)) & 0x3f) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn decode_jwt_flags_alg_none() {
        let j = jwt(r#"{"alg":"none","typ":"JWT"}"#, r#"{"sub":"u1"}"#);
        let d = decode_jwt(&j);
        assert_eq!(d.alg.as_deref(), Some("none"));
        assert!(d.warnings.iter().any(|w| w.starts_with("alg:none")));
    }

    #[test]
    fn decode_jwt_extracts_standard_claims() {
        let j = jwt(
            r#"{"alg":"HS256"}"#,
            r#"{"sub":"alice","iss":"corp.example","exp":9999999999,"iat":1,"aud":"web"}"#,
        );
        let d = decode_jwt(&j);
        assert_eq!(d.sub.as_deref(), Some("alice"));
        assert_eq!(d.iss.as_deref(), Some("corp.example"));
        assert_eq!(d.exp_unix, Some(9999999999));
        assert_eq!(d.aud, Some(json!("web")));
        assert!(d.claims_present.contains(&"sub".to_string()));
        assert!(!d.warnings.iter().any(|w| w == "iss:missing"));
    }

    #[test]
    fn decode_jwt_flags_expired() {
        let j = jwt(r#"{"alg":"HS256"}"#, r#"{"exp":1}"#);
        let d = decode_jwt(&j);
        assert!(d.warnings.iter().any(|w| w == "exp:expired"));
    }

    #[test]
    fn decode_jwt_strips_bearer_prefix() {
        let j = format!(
            "Bearer {}",
            jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"u1"}"#)
        );
        let d = decode_jwt(&j);
        assert_eq!(d.sub.as_deref(), Some("u1"));
    }

    #[test]
    fn decode_jwt_handles_malformed() {
        let d = decode_jwt("not-a-jwt");
        assert!(d.warnings.iter().any(|w| w.starts_with("format:invalid")));
    }

    #[test]
    fn diff_responses_identical() {
        let a = ResponseSnapshot { status: 200, headers: BTreeMap::new(), body: "ok".into() };
        let b = a.clone();
        let r = diff_responses(&DiffResponsesArgs { a, b, preview_cap: 256 });
        assert_eq!(r.classification, "identical");
        assert!(r.body_identical);
    }

    #[test]
    fn diff_responses_status_changed_and_marker() {
        let mut a = ResponseSnapshot { status: 401, headers: BTreeMap::new(), body: r#"{"error":"unauthorized"}"#.into() };
        a.headers.insert("x-rate".into(), "1".into());
        let b = ResponseSnapshot {
            status: 200,
            headers: BTreeMap::new(),
            body: r#"{"role":"admin","ok":true}"#.into(),
        };
        let r = diff_responses(&DiffResponsesArgs { a, b, preview_cap: 256 });
        assert!(r.status_delta);
        assert!(r.markers.iter().any(|m| m.starts_with("role:admin (only in B)")));
        assert!(r
            .markers
            .iter()
            .any(|m| m.starts_with("error:unauthorized (only in A)")));
    }

    #[test]
    fn diff_responses_headers_only_changed() {
        let mut a = ResponseSnapshot { status: 200, headers: BTreeMap::new(), body: "x".into() };
        a.headers.insert("Set-Cookie".into(), "sid=1".into());
        let mut b = a.clone();
        b.headers.insert("Set-Cookie".into(), "sid=2".into());
        let r = diff_responses(&DiffResponsesArgs { a, b, preview_cap: 256 });
        assert_eq!(r.classification, "headers_changed");
        assert!(r.headers_value_changed.contains(&"Set-Cookie".into()));
    }

    #[test]
    fn summarize_url_basic() {
        let s = summarize_url("https://user:pw@app.example.com:8443/admin/users?id=42&q=a%20b#sec");
        assert_eq!(s.scheme.as_deref(), Some("https"));
        assert_eq!(s.host.as_deref(), Some("app.example.com"));
        assert_eq!(s.port, Some(8443));
        assert_eq!(s.path, "/admin/users");
        assert_eq!(s.query.as_deref(), Some("id=42&q=a%20b"));
        assert_eq!(s.fragment.as_deref(), Some("sec"));
        assert_eq!(s.query_params, vec![("id".into(), "42".into()), ("q".into(), "a b".into())]);
        assert!(s.flags.has_userinfo);
        assert!(s.flags.path_is_admin_like);
        assert!(!s.flags.host_is_internal);
        assert!(!s.flags.is_plaintext_scheme);
    }

    #[test]
    fn summarize_url_flags_imds() {
        let s = summarize_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
        assert!(s.flags.host_is_internal);
        assert!(s.flags.host_is_cloud_metadata);
        assert!(s.flags.host_is_ip_literal);
        assert!(s.flags.is_plaintext_scheme);
        assert_eq!(s.effective_port, Some(80));
    }

    #[test]
    fn summarize_url_flags_secret_artifact() {
        let s = summarize_url("https://app.example.com/.env");
        assert!(s.flags.path_is_secret_artifact);
    }

    #[test]
    fn summarize_url_invalid_returns_partial() {
        let s = summarize_url("not a url");
        assert!(s.scheme.is_none());
        assert!(s.host.is_none());
    }

    fn extract(blob: &str) -> SecretsReport {
        extract_secrets(&ExtractSecretsArgs {
            blob: blob.to_string(),
            match_cap: 100,
            with_context: true,
        })
    }

    #[test]
    fn extract_aws_access_key() {
        let r = extract("config: AKIAFAKEFAKEFAKEFAKE more text");
        assert_eq!(r.matches.len(), 1);
        let m = &r.matches[0];
        assert_eq!(m.kind, "aws_access_key");
        assert_eq!(m.severity_hint, "high");
        assert_eq!(m.length, 20);
        assert!(m.redacted.starts_with("aws_access_key:AKIA"));
        assert!(m.context.as_deref().unwrap().contains("«"));
        assert_eq!(r.max_severity, "high");
    }

    #[test]
    fn extract_stripe_live_secret_is_critical() {
        // Assemble the fake Stripe-key shape at runtime so the literal
        // `sk_live_<long-alnum>` substring never appears in source —
        // GitHub push-protection scans the diff for it.
        let blob = format!("token = sk_{}_{}{} some more", "live", "FAKE0000", "000000000000000000000000");
        let r = extract(&blob);
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].kind, "stripe_live_secret");
        assert_eq!(r.matches[0].severity_hint, "critical");
        assert_eq!(r.max_severity, "critical");
    }

    #[test]
    fn extract_github_pat() {
        let blob = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
        let r = extract(blob);
        assert!(r.matches.iter().any(|m| m.kind == "github_pat"));
    }

    #[test]
    fn extract_openai_user_key_redacted() {
        let r = extract("openai: sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678");
        assert!(r.matches.iter().any(|m| m.kind == "openai_user_key"));
        let m = r.matches.iter().find(|m| m.kind == "openai_user_key").unwrap();
        assert!(m.redacted.contains(":sk-"));
    }

    #[test]
    fn extract_anthropic_key_high() {
        let blob = "ANTHROPIC_API_KEY=sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdef0123456789-AaBbCc";
        let r = extract(blob);
        assert!(r.matches.iter().any(|m| m.kind == "anthropic_key"));
    }

    #[test]
    fn extract_jwt_shape() {
        let jwt = jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"alice"}"#);
        let blob = format!("Authorization: Bearer {jwt}");
        let r = extract(&blob);
        assert!(r.matches.iter().any(|m| m.kind == "jwt_shape"));
    }

    #[test]
    fn extract_private_key_pem() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgI...\n-----END RSA PRIVATE KEY-----";
        let r = extract(&format!("here is the key:\n{pem}\n"));
        let m = r.matches.iter().find(|m| m.kind == "private_key_pem");
        assert!(m.is_some(), "expected private_key_pem in matches: {:?}", r);
        assert_eq!(m.unwrap().severity_hint, "critical");
    }

    #[test]
    fn extract_db_connection_url() {
        let blob = "DATABASE_URL=postgres://app:s3cret@db.internal:5432/prod and more";
        let r = extract(blob);
        let m = r.matches.iter().find(|m| m.kind == "db_connection_url");
        assert!(m.is_some(), "expected db_connection_url: {:?}", r);
    }

    #[test]
    fn extract_returns_empty_report_when_clean() {
        let r = extract("plain old configuration with no secrets inside");
        assert!(r.matches.is_empty());
        assert_eq!(r.total_matches, 0);
        assert_eq!(r.max_severity, "none");
    }

    fn args(severity: &str, has_poc: bool, has_evidence: bool, chain: bool) -> ScoreFindingArgs {
        ScoreFindingArgs {
            severity: severity.into(),
            vuln_class: String::new(),
            impact_text: String::new(),
            has_poc,
            has_response_evidence: has_evidence,
            auth_profile: None,
            chain_confirmed: chain,
            is_known_noise_class: false,
        }
    }

    #[test]
    fn score_submits_strong_high_finding() {
        let mut a = args("high", true, true, false);
        a.vuln_class = "idor".into();
        a.impact_text = "Cross-account read: attacker profile reads victim's orders via predictable id".into();
        a.auth_profile = Some("attacker".into());
        let r = score_finding(&a);
        assert_eq!(r.verdict, "SUBMIT");
        assert!(r.total_score >= 40, "{r:?}");
        assert!(r.elevate_hints.iter().any(|h| h.contains("chain")) || r.chain_potential < 15);
    }

    #[test]
    fn score_holds_partial_finding() {
        let mut a = args("medium", true, false, false);
        a.vuln_class = "idor".into();
        a.impact_text = "potential cross-account read".into();
        let r = score_finding(&a);
        assert_eq!(r.verdict, "HOLD");
        assert!(r.elevate_hints.iter().any(|h| h.contains("response")));
    }

    #[test]
    fn score_skips_speculative() {
        let r = score_finding(&args("low", false, false, false));
        assert_eq!(r.verdict, "SKIP");
        assert!(!r.elevate_hints.is_empty());
    }

    #[test]
    fn score_skips_known_noise_class_without_chain() {
        let mut a = args("low", true, true, false);
        a.vuln_class = "missing_headers".into();
        a.is_known_noise_class = true;
        let r = score_finding(&a);
        assert_eq!(r.verdict, "SKIP");
        assert!(r
            .elevate_hints
            .iter()
            .any(|h| h.contains("known-noise")));
    }

    #[test]
    fn score_promotes_noise_class_if_chain_confirmed() {
        let mut a = args("high", true, true, true);
        a.vuln_class = "open_redirect".into();
        a.impact_text = "Chained into ATO via OAuth state confusion; victim session hijacked".into();
        a.is_known_noise_class = true;
        let r = score_finding(&a);
        // chain_confirmed bypasses the auto-skip; severity high keeps SUBMIT eligible
        assert!(r.verdict == "SUBMIT" || r.verdict == "HOLD", "{r:?}");
    }

    #[test]
    fn score_penalises_inflated_severity() {
        // Claim "critical" for a known-noise class — severity_accuracy
        // drops, total drops, verdict downgrades.
        let mut a = args("critical", true, true, false);
        a.vuln_class = "missing_headers".into();
        let r = score_finding(&a);
        assert!(r.severity_accuracy < 15, "{r:?}");
    }

    #[test]
    fn hash_request_ignores_noisy_headers_by_default() {
        let mut h1: BTreeMap<String, String> = BTreeMap::new();
        h1.insert("Authorization".into(), "Bearer abc".into());
        h1.insert("User-Agent".into(), "curl/8.0".into());
        h1.insert("Content-Type".into(), "application/json".into());
        let mut h2 = h1.clone();
        h2.insert("Authorization".into(), "Bearer xyz".into()); // rotated
        h2.insert("X-Request-Id".into(), "abc-123".into());     // new noisy

        let r1 = hash_request(&HashRequestArgs {
            method: "POST".into(),
            url: "https://api.example.com/v1/orders".into(),
            headers: h1,
            body: r#"{"id":1}"#.into(),
            ignore_headers: vec![],
        });
        let r2 = hash_request(&HashRequestArgs {
            method: "POST".into(),
            url: "https://api.example.com/v1/orders".into(),
            headers: h2,
            body: r#"{"id":1}"#.into(),
            ignore_headers: vec![],
        });
        assert_eq!(r1.hash, r2.hash);
        assert_eq!(r1.short.len(), 16);
    }

    #[test]
    fn hash_request_changes_on_body_change() {
        let r1 = hash_request(&HashRequestArgs {
            method: "POST".into(),
            url: "https://api.example.com/v1/orders".into(),
            headers: BTreeMap::new(),
            body: r#"{"id":1}"#.into(),
            ignore_headers: vec![],
        });
        let r2 = hash_request(&HashRequestArgs {
            method: "POST".into(),
            url: "https://api.example.com/v1/orders".into(),
            headers: BTreeMap::new(),
            body: r#"{"id":2}"#.into(),
            ignore_headers: vec![],
        });
        assert_ne!(r1.hash, r2.hash);
    }

    #[test]
    fn extract_html_forms_basic() {
        let html = r#"
            <html><body>
              <form method="POST" action="/users/42/update">
                <input type="hidden" name="_token" value="abc123" />
                <input type="hidden" name="user_id" value="42" />
                <input type="text" name="email" value="alice@example.com" />
                <input type="submit" value="Save" />
              </form>
            </body></html>
        "#;
        let r = extract_html_forms(&ExtractHtmlFormsArgs {
            html: html.into(),
            base_url: Some("https://app.example.com/account/settings".into()),
        });
        assert_eq!(r.count, 1);
        let f = &r.forms[0];
        assert_eq!(f.method, "POST");
        assert_eq!(f.action_raw, "/users/42/update");
        assert_eq!(
            f.action_resolved.as_deref(),
            Some("https://app.example.com/users/42/update")
        );
        assert!(f.csrf_tokens.iter().any(|i| i.name == "_token"));
        assert!(f
            .mass_assignment_candidates
            .iter()
            .any(|i| i.name == "user_id"));
        assert!(f.inputs.iter().any(|i| i.name == "email"));
    }

    #[test]
    fn extract_html_forms_handles_multiple_and_no_action() {
        let html = "<form><input name=a></form><form action='/x'><input name=b type=hidden></form>";
        let r = extract_html_forms(&ExtractHtmlFormsArgs {
            html: html.into(),
            base_url: None,
        });
        assert_eq!(r.count, 2);
        assert_eq!(r.forms[0].action_raw, "");
        assert_eq!(r.forms[1].action_raw, "/x");
    }

    #[test]
    fn extract_caps_results() {
        let mut blob = String::new();
        for _ in 0..150 {
            blob.push_str("AKIAFAKEFAKEFAKEFAKE ");
        }
        let r = extract_secrets(&ExtractSecretsArgs {
            blob,
            match_cap: 10,
            with_context: false,
        });
        assert_eq!(r.matches.len(), 10);
        assert!(r.total_matches >= 100);
    }
}
