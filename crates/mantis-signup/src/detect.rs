//! Signup endpoint detection.
//!
//! Probes a target host for known signup URL patterns and infers
//! the auth provider:
//!
//! - `<host>/auth/v1/signup` (Supabase) — JSON POST with `apikey` header
//! - `<host>/api/auth/register` (NextAuth-ish) — JSON POST
//! - `<host>/api/auth/signup` — JSON POST
//! - `<host>/api/v1/users` — sometimes the API itself is the registration endpoint
//!
//! Detection is a HEAD/OPTIONS probe followed by a small POST with
//! syntactically-valid garbage. A 4xx with a structured error
//! envelope is treated as "endpoint exists, payload is wrong" and
//! reports the kind. A 404 or connection error skips that pattern.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupKind {
    /// `POST /auth/v1/signup` with `apikey` header. The response
    /// is `{access_token, refresh_token, user, …}`.
    SupabaseAuthV1,
    /// `POST /api/auth/register` or `/api/auth/signup`. NextAuth /
    /// Next.js variant. Response shape varies.
    NextAuthRegister,
    /// `POST /api/v1/users` — REST-style "create user".
    RestUsers,
    /// Operator-supplied URL with explicit kind.
    Custom { url: String },
}

impl SignupKind {
    pub fn as_str(&self) -> &str {
        match self {
            SignupKind::SupabaseAuthV1 => "supabase_auth_v1",
            SignupKind::NextAuthRegister => "next_auth_register",
            SignupKind::RestUsers => "rest_users",
            SignupKind::Custom { .. } => "custom",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSignup {
    pub kind: SignupKind,
    pub url: String,
    /// Optional public API key required by the endpoint (Supabase
    /// requires `apikey` header). Caller supplies this; detection
    /// only flags whether the endpoint needs one.
    pub requires_apikey: bool,
    /// Observed HTTP status from the probe.
    pub probe_status: u16,
}

/// Probe candidate signup paths on `base_url` (e.g.
/// `https://api.example.com`) and return the first one that
/// responds with a recognizable signature.
///
/// The probe sends `{"email":"_probe@_.invalid","password":"_"}`
/// — syntactically valid for parsers, semantically garbage. A
/// real signup will reject this with 400/422, which is precisely
/// the signal we want.
pub async fn detect_signup(
    base_url: &str,
    apikey: Option<&str>,
) -> Result<Option<DetectedSignup>, crate::SignupError> {
    let base = base_url.trim_end_matches('/');
    let candidates: Vec<(SignupKind, String, bool)> = vec![
        (
            SignupKind::SupabaseAuthV1,
            format!("{base}/auth/v1/signup"),
            true,
        ),
        (
            SignupKind::NextAuthRegister,
            format!("{base}/api/auth/register"),
            false,
        ),
        (
            SignupKind::NextAuthRegister,
            format!("{base}/api/auth/signup"),
            false,
        ),
        (SignupKind::RestUsers, format!("{base}/api/v1/users"), false),
        (SignupKind::RestUsers, format!("{base}/api/users"), false),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| crate::SignupError::Http(e.to_string()))?;

    for (kind, url, requires_apikey) in candidates {
        let mut req = client
            .post(&url)
            .json(&serde_json::json!({"email": "_probe@_.invalid", "password": "_"}));
        if requires_apikey {
            if let Some(k) = apikey {
                req = req.header("apikey", k);
            }
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                // 404 = no such endpoint. 5xx = unknown / WAF. Both skip.
                if status == 404 || status >= 500 {
                    continue;
                }
                // Anything else (400 / 401 / 422 / 200) means there's
                // SOMETHING at this URL — return the first hit.
                return Ok(Some(DetectedSignup {
                    kind,
                    url,
                    requires_apikey,
                    probe_status: status,
                }));
            }
            Err(_) => continue,
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_server(behavior: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let beh = behavior;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, body): (&str, &[u8]) = match beh {
                        "supabase-rejects" => {
                            if req.contains("POST /auth/v1/signup") {
                                ("HTTP/1.1 400 Bad Request", b"{\"error\":\"invalid email\"}")
                            } else {
                                ("HTTP/1.1 404 Not Found", b"")
                            }
                        }
                        "nothing-here" => ("HTTP/1.1 404 Not Found", b""),
                        _ => ("HTTP/1.1 500 Internal Server Error", b""),
                    };
                    let response = format!(
                        "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_supabase_when_endpoint_rejects() {
        let addr = spawn_server("supabase-rejects").await;
        let base = format!("http://127.0.0.1:{}", addr.port());
        let d = detect_signup(&base, None).await.unwrap();
        assert!(d.is_some(), "expected detection");
        let d = d.unwrap();
        assert_eq!(d.kind, SignupKind::SupabaseAuthV1);
        assert_eq!(d.probe_status, 400);
        assert!(d.requires_apikey);
    }

    #[tokio::test]
    async fn returns_none_when_no_signup_endpoint() {
        let addr = spawn_server("nothing-here").await;
        let base = format!("http://127.0.0.1:{}", addr.port());
        let d = detect_signup(&base, None).await.unwrap();
        assert!(d.is_none());
    }
}
