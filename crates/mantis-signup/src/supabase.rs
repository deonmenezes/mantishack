//! Supabase auth/v1/signup driver.
//!
//! Single POST against `<host>/auth/v1/signup` with:
//! - `apikey: <public anon key>` header
//! - `Content-Type: application/json`
//! - `{"email": ..., "password": ...}` body
//!
//! Successful response shape:
//! ```json
//! {
//!   "access_token": "...JWT...",
//!   "token_type": "bearer",
//!   "expires_in": 3600,
//!   "refresh_token": "...",
//!   "user": { ... }
//! }
//! ```
//! Some Supabase configs return the token under `session.access_token`
//! when email-confirmation is enabled. We try both.

use crate::email::EmailSpec;
use crate::{SignupError, SignupOutcome};
use mantis_auth::{AuthHeader, AuthProfile};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupabaseSignupConfig {
    /// Public anon key — visible to the browser. Required by
    /// Supabase as the `apikey` header.
    pub apikey: String,
    /// Per-request timeout.
    pub timeout_secs: u64,
}

impl Default for SupabaseSignupConfig {
    fn default() -> Self {
        Self {
            apikey: String::new(),
            timeout_secs: 10,
        }
    }
}

/// Drive a Supabase signup against `signup_url`. Returns:
/// - the [`SignupOutcome`] (raw token data)
/// - an [`AuthProfile`] ready to drop into `mantis-auth::AuthStore`
///
/// `email` and `password` default to random values when omitted.
pub async fn signup_supabase(
    signup_url: &str,
    config: &SupabaseSignupConfig,
    email: Option<&str>,
    password: Option<&str>,
    profile_name: &str,
) -> Result<(SignupOutcome, AuthProfile), SignupError> {
    if config.apikey.trim().is_empty() {
        return Err(SignupError::Http(
            "Supabase signup requires a non-empty apikey".into(),
        ));
    }

    let email_addr = email
        .map(|s| s.to_string())
        .unwrap_or_else(|| EmailSpec::random().as_address());
    let password = password
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("Mantis-{}!", ulid::Ulid::new()));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| SignupError::Http(e.to_string()))?;

    let resp = client
        .post(signup_url)
        .header("apikey", &config.apikey)
        .json(&serde_json::json!({
            "email": email_addr,
            "password": password,
        }))
        .send()
        .await
        .map_err(|e| SignupError::Http(e.to_string()))?;

    let status = resp.status().as_u16();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| SignupError::Http(e.to_string()))?;
    if !(200..300).contains(&status) {
        return Err(SignupError::Rejected {
            status,
            body: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
        });
    }

    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| SignupError::Decode(e.to_string()))?;

    // Supabase shape varies — sometimes the token is at the root,
    // sometimes under `session`. Try root first, then `session`.
    let token_node = parsed
        .get("access_token")
        .or_else(|| parsed.get("session").and_then(|s| s.get("access_token")));
    let access_token = match token_node.and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return Err(SignupError::NoToken {
                field: "access_token".into(),
                body: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
            })
        }
    };
    let token_type = parsed
        .get("token_type")
        .or_else(|| parsed.get("session").and_then(|s| s.get("token_type")))
        .and_then(|v| v.as_str())
        .unwrap_or("bearer")
        .to_string();
    let refresh_token = parsed
        .get("refresh_token")
        .or_else(|| parsed.get("session").and_then(|s| s.get("refresh_token")))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let expires_in = parsed
        .get("expires_in")
        .or_else(|| parsed.get("session").and_then(|s| s.get("expires_in")))
        .and_then(|v| v.as_u64());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let outcome = SignupOutcome {
        email: email_addr.clone(),
        access_token: access_token.clone(),
        refresh_token,
        token_type: token_type.clone(),
        expires_in,
    };
    let profile = AuthProfile {
        name: profile_name.to_string(),
        headers: vec![
            AuthHeader {
                name: "apikey".into(),
                value: config.apikey.clone(),
            },
            AuthHeader {
                name: "Authorization".into(),
                value: format!("Bearer {access_token}"),
            },
        ],
        cookies: Vec::new(),
        query: Vec::new(),
        expires_at_unix: outcome.expires_in.map(|s| now + s),
        created_at_unix: now,
        origin: "supabase_auth_v1".into(),
    };
    Ok((outcome, profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_supabase_like(behavior: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let beh = behavior;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, body): (&str, String) = match beh {
                        "ok-root" => (
                            "HTTP/1.1 200 OK",
                            serde_json::json!({
                                "access_token": "JWT-ATTACKER-1",
                                "token_type": "bearer",
                                "expires_in": 3600,
                                "refresh_token": "REFRESH-1",
                                "user": {"id": "u-1"}
                            })
                            .to_string(),
                        ),
                        "ok-session" => (
                            "HTTP/1.1 200 OK",
                            serde_json::json!({
                                "session": {
                                    "access_token": "JWT-SESSION-1",
                                    "token_type": "bearer",
                                    "expires_in": 7200,
                                    "refresh_token": "R2"
                                },
                                "user": {"id": "u-1"}
                            })
                            .to_string(),
                        ),
                        "no-token" => ("HTTP/1.1 200 OK", r#"{"user":{"id":"u-1"}}"#.to_string()),
                        "rejected" => (
                            "HTTP/1.1 400 Bad Request",
                            r#"{"error":"weak password"}"#.to_string(),
                        ),
                        "no-apikey" => {
                            if !req.to_ascii_lowercase().contains("apikey:") {
                                (
                                    "HTTP/1.1 401 Unauthorized",
                                    r#"{"error":"missing apikey"}"#.to_string(),
                                )
                            } else {
                                (
                                    "HTTP/1.1 200 OK",
                                    serde_json::json!({
                                        "access_token": "OK", "token_type": "bearer"
                                    })
                                    .to_string(),
                                )
                            }
                        }
                        _ => ("HTTP/1.1 500 Internal Server Error", "".to_string()),
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

    fn cfg() -> SupabaseSignupConfig {
        SupabaseSignupConfig {
            apikey: "PUBLIC-ANON-KEY".into(),
            timeout_secs: 5,
        }
    }

    #[tokio::test]
    async fn happy_path_root_token() {
        let addr = spawn_supabase_like("ok-root").await;
        let url = format!("http://127.0.0.1:{}/auth/v1/signup", addr.port());
        let (outcome, profile) = signup_supabase(&url, &cfg(), None, None, "attacker")
            .await
            .unwrap();
        assert_eq!(outcome.access_token, "JWT-ATTACKER-1");
        assert_eq!(outcome.token_type, "bearer");
        assert_eq!(outcome.refresh_token.as_deref(), Some("REFRESH-1"));
        assert_eq!(outcome.expires_in, Some(3600));
        // Profile carries the apikey + Bearer header.
        let header_names: Vec<&str> = profile.headers.iter().map(|h| h.name.as_str()).collect();
        assert!(header_names.contains(&"apikey"));
        assert!(header_names.contains(&"Authorization"));
        // Bearer value carries the token.
        let auth_header = profile
            .headers
            .iter()
            .find(|h| h.name == "Authorization")
            .unwrap();
        assert_eq!(auth_header.value, "Bearer JWT-ATTACKER-1");
    }

    #[tokio::test]
    async fn happy_path_session_nested_token() {
        let addr = spawn_supabase_like("ok-session").await;
        let url = format!("http://127.0.0.1:{}/auth/v1/signup", addr.port());
        let (outcome, _profile) = signup_supabase(&url, &cfg(), None, None, "victim")
            .await
            .unwrap();
        assert_eq!(outcome.access_token, "JWT-SESSION-1");
        assert_eq!(outcome.expires_in, Some(7200));
    }

    #[tokio::test]
    async fn rejected_signup_surfaces_status_and_body() {
        let addr = spawn_supabase_like("rejected").await;
        let url = format!("http://127.0.0.1:{}/auth/v1/signup", addr.port());
        let err = signup_supabase(&url, &cfg(), None, None, "attacker")
            .await
            .unwrap_err();
        match err {
            SignupError::Rejected { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("weak password"));
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_token_in_body_is_an_error() {
        let addr = spawn_supabase_like("no-token").await;
        let url = format!("http://127.0.0.1:{}/auth/v1/signup", addr.port());
        let err = signup_supabase(&url, &cfg(), None, None, "attacker")
            .await
            .unwrap_err();
        assert!(matches!(err, SignupError::NoToken { .. }));
    }

    #[tokio::test]
    async fn missing_apikey_fails_fast() {
        let bad_cfg = SupabaseSignupConfig {
            apikey: "".into(),
            timeout_secs: 5,
        };
        let err = signup_supabase("http://127.0.0.1:0/x", &bad_cfg, None, None, "x")
            .await
            .unwrap_err();
        assert!(matches!(err, SignupError::Http(_)));
    }

    #[tokio::test]
    async fn user_supplied_email_passes_through() {
        let addr = spawn_supabase_like("ok-root").await;
        let url = format!("http://127.0.0.1:{}/auth/v1/signup", addr.port());
        let (outcome, _) = signup_supabase(
            &url,
            &cfg(),
            Some("victim+1@example.com"),
            Some("HunterPW1!"),
            "victim",
        )
        .await
        .unwrap();
        assert_eq!(outcome.email, "victim+1@example.com");
    }
}
