//! Email adapter via Resend HTTP API (PRD §9.4).
//!
//! Resend was chosen over SMTP because:
//! - HTTPS POST is uniformly testable against the same
//!   TcpListener mock pattern the other adapters use.
//! - SMTP support would mean another heavy dep (`lettre` pulls
//!   `native-tls`, `mio`, etc.) for a feature most production
//!   deployments now route through HTTP transactional-email APIs.
//!
//! Operators who require SMTP can wrap an HTTP-to-SMTP gateway
//! (e.g. `aiosmtpd`-based bridge); the contract here is "POST a
//! JSON envelope to a configurable endpoint with bearer auth".
//! That contract matches Resend, Mailgun, Postmark, Sendgrid, and
//! AWS SES (with minor field rename) — pick any.

use async_trait::async_trait;
use serde::Serialize;

use crate::identity::IdentityBinding;
use crate::platform::{MessagingPlatform, Notification, NotificationKind, PlatformId, Severity};
use crate::GatewayError;

const DEFAULT_BASE_URL: &str = "https://api.resend.com";
const DEFAULT_FROM: &str = "mantis@no-reply.example";

#[derive(Debug, Clone)]
pub struct EmailHttpPlatform {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    from: String,
}

impl EmailHttpPlatform {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.into(),
            from: DEFAULT_FROM.into(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_from(mut self, from: impl Into<String>) -> Self {
        self.from = from.into();
        self
    }
}

#[async_trait]
impl MessagingPlatform for EmailHttpPlatform {
    fn platform_id(&self) -> PlatformId {
        PlatformId::Email
    }

    async fn send(
        &self,
        binding: &IdentityBinding,
        notification: &Notification,
    ) -> Result<(), GatewayError> {
        if !binding.remote_id.contains('@') {
            return Err(GatewayError::Backend(format!(
                "email remote_id must be a recipient address, got `{}`",
                binding.remote_id
            )));
        }
        let (subject, body_text) = render_notification(notification);
        let payload = EmailPayload {
            from: &self.from,
            to: vec![&binding.remote_id],
            subject,
            text: body_text,
        };
        let url = format!("{}/emails", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| GatewayError::Backend(format!("email send: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Backend(format!(
                "email {}: {text}",
                status.as_u16()
            )));
        }
        Ok(())
    }
}

fn render_notification(n: &Notification) -> (String, String) {
    match &n.kind {
        NotificationKind::NewClaim {
            primitive_id,
            severity,
            surface_url,
        } => (
            format!(
                "[Mantis] {} new claim: {primitive_id}",
                severity_text(*severity)
            ),
            format!(
                "Mantis detected a new claim.\n\nPrimitive: {primitive_id}\nSeverity: {severity:?}\nSurface: {surface_url}\n"
            ),
        ),
        NotificationKind::BudgetWarning {
            engagement_id,
            remaining_pct,
        } => (
            format!("[Mantis] budget warning: {engagement_id}"),
            format!(
                "Engagement {engagement_id} is at {remaining_pct}% remaining budget. Top it up or let the engagement complete.\n"
            ),
        ),
        NotificationKind::ScheduledRunComplete {
            engagement_id,
            verified,
        } => (
            format!("[Mantis] scheduled run complete: {engagement_id}"),
            format!(
                "Engagement {engagement_id} completed its scheduled run with {verified} verified finding(s).\n"
            ),
        ),
        NotificationKind::LiveVerificationApprovalRequest {
            engagement_id,
            primitive_id,
        } => (
            "[Mantis] live-verification approval required".to_string(),
            format!(
                "Engagement {engagement_id} is requesting approval to run primitive {primitive_id} against the live target.\n\nReply `approve {engagement_id} {primitive_id}` to authorize.\n"
            ),
        ),
    }
}

fn severity_text(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Informational => "INFO",
    }
}

#[derive(Serialize)]
struct EmailPayload<'a> {
    from: &'a str,
    to: Vec<&'a str>,
    subject: String,
    text: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_core::OperatorId;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use ulid::Ulid;

    async fn mock_email_server(
        captured: Arc<Mutex<Option<(String, String)>>>,
        status: u16,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
            *captured.lock().await = Some((head.into(), body.into()));
            let resp_body = r#"{"id":"em_test"}"#;
            let reason = if (200..300).contains(&status) {
                "OK"
            } else {
                "ERR"
            };
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
                resp_body.len()
            );
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(resp_body.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        });
        format!("http://{addr}")
    }

    fn binding(addr: &str) -> IdentityBinding {
        IdentityBinding {
            operator: OperatorId(Ulid::new()),
            platform: PlatformId::Email,
            remote_id: addr.into(),
            created_at_unix: 0,
        }
    }

    fn notif() -> Notification {
        Notification {
            kind: NotificationKind::BudgetWarning {
                engagement_id: "01HEM".into(),
                remaining_pct: 12,
            },
            generated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn posts_to_resend_emails_endpoint() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_email_server(captured.clone(), 200).await;
        let platform = EmailHttpPlatform::new("re_key")
            .with_base_url(base)
            .with_from("ops@example.com");
        platform
            .send(&binding("alice@example.com"), &notif())
            .await
            .unwrap();
        let (head, body) = captured.lock().await.take().unwrap();
        assert!(head.contains("POST /emails"));
        assert!(head.to_lowercase().contains("authorization: bearer re_key"));
        assert!(body.contains("alice@example.com"));
        assert!(body.contains("ops@example.com"));
        assert!(body.contains("01HEM"));
    }

    #[tokio::test]
    async fn rejects_non_email_remote_id() {
        let p = EmailHttpPlatform::new("x").with_base_url("http://127.0.0.1:1");
        let err = p
            .send(&binding("not-an-email"), &notif())
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("recipient address"));
    }

    #[tokio::test]
    async fn http_error_surfaces() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_email_server(captured, 422).await;
        let p = EmailHttpPlatform::new("x").with_base_url(base);
        let err = p.send(&binding("a@b.com"), &notif()).await.unwrap_err();
        assert!(format!("{err}").contains("422"));
    }

    #[test]
    fn render_uses_severity_word() {
        let n = Notification {
            kind: NotificationKind::NewClaim {
                primitive_id: "xss".into(),
                severity: Severity::Critical,
                surface_url: "https://x".into(),
            },
            generated_at_unix: 0,
        };
        let (subject, body) = render_notification(&n);
        assert!(subject.contains("CRITICAL"));
        assert!(body.contains("xss"));
    }
}
