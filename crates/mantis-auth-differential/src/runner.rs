//! Live runner — fetches the same URL under N auth profiles and
//! returns the classified findings.
//!
//! Designed to be invoked from the CLI (`mantis auth-diff`) and
//! the MCP `mantis_run_auth_differential` tool. Decoupled from the
//! daemon's scope-enforcing egress proxy here so the crate stays
//! lean — production callers route requests through the daemon's
//! egress instead of reqwest directly.

use crate::classify::{classify, DiffFinding, ProfileResponse, ProfileRole};
use crate::AuthDiffError;
use mantis_auth::AuthProfile;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum RunnerError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("classifier: {0}")]
    Classifier(#[from] AuthDiffError),
    #[error("response was not valid JSON: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerConfig {
    pub timeout: Duration,
    /// User-Agent banner. Defaults to `mantis-auth-diff/0.0.1`.
    pub user_agent: String,
    /// Optional proxy URL (typically the daemon's egress proxy).
    pub proxy: Option<String>,
    /// Treat non-JSON bodies as `Value::Null`. The classifier
    /// reads JSON shape; HTML / plaintext responses still yield a
    /// useful divergence signal via the status code.
    pub tolerate_non_json: bool,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            user_agent: format!("mantis-auth-diff/{}", env!("CARGO_PKG_VERSION")),
            proxy: None,
            tolerate_non_json: true,
        }
    }
}

/// One (role, profile) input. `None` profile = unauthenticated probe.
pub struct ProfileBinding<'a> {
    pub role: ProfileRole,
    pub profile: Option<&'a AuthProfile>,
}

/// Run the differential. For each profile, issue one GET against
/// `url` with the profile's cookies / headers / query params, then
/// classify the divergence.
pub async fn run_differential(
    url: &str,
    bindings: &[ProfileBinding<'_>],
    config: &RunnerConfig,
) -> Result<Vec<DiffFinding>, RunnerError> {
    let mut responses: Vec<ProfileResponse> = Vec::with_capacity(bindings.len());

    let mut builder = reqwest::Client::builder()
        .timeout(config.timeout)
        .user_agent(&config.user_agent)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(p) = &config.proxy {
        builder = builder.proxy(
            reqwest::Proxy::all(p).map_err(|e| RunnerError::Http(e.to_string()))?,
        );
    }
    let client = builder
        .build()
        .map_err(|e| RunnerError::Http(e.to_string()))?;

    for b in bindings {
        let resp = fetch_one(&client, url, b.profile, config.tolerate_non_json).await?;
        responses.push(ProfileResponse::new(b.role, resp.0, resp.1));
    }

    classify(url, &responses).map_err(RunnerError::Classifier)
}

async fn fetch_one(
    client: &reqwest::Client,
    url: &str,
    profile: Option<&AuthProfile>,
    tolerate_non_json: bool,
) -> Result<(u16, serde_json::Value), RunnerError> {
    let mut full_url = url.to_string();
    if let Some(p) = profile {
        if !p.query.is_empty() {
            let sep = if full_url.contains('?') { '&' } else { '?' };
            let pairs: Vec<String> = p
                .query
                .iter()
                .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
                .collect();
            full_url = format!("{full_url}{sep}{}", pairs.join("&"));
        }
    }
    let mut req = client.get(&full_url);
    if let Some(p) = profile {
        for h in &p.headers {
            req = req.header(h.name.as_str(), h.value.as_str());
        }
        if !p.cookies.is_empty() {
            let cookie = p
                .cookies
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; ");
            req = req.header(reqwest::header::COOKIE, cookie);
        }
    }
    let response = req
        .send()
        .await
        .map_err(|e| RunnerError::Http(e.to_string()))?;
    let status = response.status().as_u16();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| RunnerError::Http(e.to_string()))?;
    let body: serde_json::Value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) if tolerate_non_json => {
                // Surface non-JSON bodies as a tagged string so the
                // shape analysis still sees something.
                serde_json::Value::String(format!(
                    "[non-json body, {} bytes, parse error: {}]",
                    bytes.len(),
                    e
                ))
            }
            Err(e) => return Err(RunnerError::Decode(e.to_string())),
        }
    };
    Ok((status, body))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::DivergenceClass;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Minimal HTTP test server. Routes by `Cookie` header to
    /// mimic a Supabase-style endpoint that leaks cross-tenant data.
    async fn spawn_vulnerable_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let req_lower = req.to_ascii_lowercase();
                    let body = if req_lower.contains("cookie: session=attacker")
                        || req_lower.contains("cookie: session=victim")
                    {
                        // Both auth'd roles see the SAME rows — the vuln.
                        r#"[{"id":"o-1","organization_id":"victim-org","total":500}]"#
                    } else if req_lower.contains("authorization:") {
                        r#"[{"id":"o-1","organization_id":"victim-org","total":500}]"#
                    } else {
                        r#"{"message":"JWT expired"}"#
                    };
                    let status = if body.starts_with("[") { "200 OK" } else { "401 Unauthorized" };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    fn attacker_profile() -> AuthProfile {
        AuthProfile {
            name: "attacker".into(),
            headers: vec![],
            cookies: vec![mantis_auth::AuthCookie {
                name: "session".into(),
                value: "attacker".into(),
                domain: None,
                path: None,
                secure: false,
                http_only: false,
            }],
            query: vec![],
            expires_at_unix: None,
            created_at_unix: 0,
            origin: "test".into(),
        }
    }

    fn victim_profile() -> AuthProfile {
        AuthProfile {
            name: "victim".into(),
            headers: vec![],
            cookies: vec![mantis_auth::AuthCookie {
                name: "session".into(),
                value: "victim".into(),
                domain: None,
                path: None,
                secure: false,
                http_only: false,
            }],
            query: vec![],
            expires_at_unix: None,
            created_at_unix: 0,
            origin: "test".into(),
        }
    }

    #[tokio::test]
    async fn runner_detects_cross_tenant_read_against_synthetic_server() {
        let addr = spawn_vulnerable_server().await;
        let url = format!("http://127.0.0.1:{}/rest/v1/orders", addr.port());
        let attacker = attacker_profile();
        let victim = victim_profile();
        let bindings = vec![
            ProfileBinding {
                role: ProfileRole::Unauthenticated,
                profile: None,
            },
            ProfileBinding {
                role: ProfileRole::Attacker,
                profile: Some(&attacker),
            },
            ProfileBinding {
                role: ProfileRole::Victim,
                profile: Some(&victim),
            },
        ];
        let findings = run_differential(&url, &bindings, &RunnerConfig::default())
            .await
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.class, DivergenceClass::CrossTenantRead)),
            "expected CrossTenantRead, got {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.class, DivergenceClass::ForeignOwnerIdentifier)),
            "expected ForeignOwnerIdentifier, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn runner_no_finding_when_endpoint_properly_gated() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let body = r#"{"message":"nope"}"#;
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        let url = format!("http://127.0.0.1:{}/admin", addr.port());
        let attacker = attacker_profile();
        let findings = run_differential(
            &url,
            &[
                ProfileBinding {
                    role: ProfileRole::Unauthenticated,
                    profile: None,
                },
                ProfileBinding {
                    role: ProfileRole::Attacker,
                    profile: Some(&attacker),
                },
            ],
            &RunnerConfig::default(),
        )
        .await
        .unwrap();
        // Both blocked → no auth-diff finding to report.
        // Avoid unused-variable warning on Arc/Mutex import.
        let _ = (Arc::new(()), Mutex::new(()));
        assert!(findings.is_empty(), "expected empty, got {findings:?}");
    }
}
