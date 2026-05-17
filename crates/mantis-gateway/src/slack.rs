//! Slack incoming-webhook adapter (PRD §9.4).
//!
//! Posts JSON to a Slack Incoming Webhook URL. The binding's
//! `remote_id` is the full webhook URL. Slack accepts both
//! plain-text (`text`) and Block Kit (`blocks`) payloads — we use
//! the simpler `text` form with Slack mrkdwn formatting.

use async_trait::async_trait;
use serde::Serialize;

use crate::identity::IdentityBinding;
use crate::platform::{MessagingPlatform, Notification, NotificationKind, PlatformId, Severity};
use crate::GatewayError;

#[derive(Debug, Clone)]
pub struct SlackWebhookPlatform {
    client: reqwest::Client,
}

impl Default for SlackWebhookPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl SlackWebhookPlatform {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl MessagingPlatform for SlackWebhookPlatform {
    fn platform_id(&self) -> PlatformId {
        PlatformId::Slack
    }

    async fn send(
        &self,
        binding: &IdentityBinding,
        notification: &Notification,
    ) -> Result<(), GatewayError> {
        if !binding.remote_id.starts_with("http") {
            return Err(GatewayError::Backend(format!(
                "slack remote_id must be a webhook URL, got `{}`",
                binding.remote_id
            )));
        }
        let payload = SlackPayload {
            text: render_notification(notification),
            username: "Mantis",
            icon_emoji: ":lock:",
        };
        let resp = self
            .client
            .post(&binding.remote_id)
            .json(&payload)
            .send()
            .await
            .map_err(|e| GatewayError::Backend(format!("slack webhook: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Backend(format!(
                "slack {}: {text}",
                status.as_u16()
            )));
        }
        Ok(())
    }
}

fn render_notification(n: &Notification) -> String {
    match &n.kind {
        NotificationKind::NewClaim {
            primitive_id,
            severity,
            surface_url,
        } => format!(
            "{} *Mantis — new claim* `{primitive_id}` on <{surface_url}>",
            severity_text(*severity)
        ),
        NotificationKind::BudgetWarning {
            engagement_id,
            remaining_pct,
        } => format!(
            ":warning: *Mantis — budget warning* engagement `{engagement_id}` at {remaining_pct}% remaining"
        ),
        NotificationKind::ScheduledRunComplete {
            engagement_id,
            verified,
        } => format!(
            ":white_check_mark: *Mantis — scheduled run done* `{engagement_id}` produced {verified} verified finding(s)"
        ),
        NotificationKind::LiveVerificationApprovalRequest {
            engagement_id,
            primitive_id,
        } => format!(
            ":closed_lock_with_key: *Mantis — approval requested* `{engagement_id}` wants to run `{primitive_id}` live"
        ),
    }
}

fn severity_text(s: Severity) -> &'static str {
    match s {
        Severity::Critical => ":red_circle: *Critical*",
        Severity::High => ":large_orange_circle: *High*",
        Severity::Medium => ":large_yellow_circle: *Medium*",
        Severity::Low => ":large_green_circle: Low",
        Severity::Informational => ":white_circle: Info",
    }
}

#[derive(Serialize)]
struct SlackPayload {
    text: String,
    username: &'static str,
    icon_emoji: &'static str,
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

    async fn mock_webhook(captured: Arc<Mutex<Option<String>>>, status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let body = raw
                .split_once("\r\n\r\n")
                .map(|(_, b)| b)
                .unwrap_or("")
                .to_string();
            *captured.lock().await = Some(body);
            let resp_body = "ok";
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
        format!("http://{addr}/services/T/B/X")
    }

    fn binding(url: &str) -> IdentityBinding {
        IdentityBinding {
            operator: OperatorId(Ulid::new()),
            platform: PlatformId::Slack,
            remote_id: url.into(),
            created_at_unix: 0,
        }
    }

    fn notif() -> Notification {
        Notification {
            kind: NotificationKind::BudgetWarning {
                engagement_id: "01HSL".into(),
                remaining_pct: 8,
            },
            generated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn posts_text_payload_to_webhook() {
        let captured = Arc::new(Mutex::new(None));
        let url = mock_webhook(captured.clone(), 200).await;
        let platform = SlackWebhookPlatform::new();
        platform.send(&binding(&url), &notif()).await.unwrap();
        let body = captured.lock().await.take().unwrap();
        assert!(body.contains("\"text\""));
        assert!(body.contains("01HSL"));
        assert!(body.contains("\"username\":\"Mantis\""));
    }

    #[tokio::test]
    async fn rejects_non_url_remote_id() {
        let p = SlackWebhookPlatform::new();
        let err = p.send(&binding("workspace"), &notif()).await.unwrap_err();
        assert!(format!("{err}").contains("webhook URL"));
    }

    #[tokio::test]
    async fn http_error_surfaces() {
        let captured = Arc::new(Mutex::new(None));
        let url = mock_webhook(captured, 500).await;
        let p = SlackWebhookPlatform::new();
        let err = p.send(&binding(&url), &notif()).await.unwrap_err();
        assert!(format!("{err}").contains("500"));
    }
}
