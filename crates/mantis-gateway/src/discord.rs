//! Discord webhook adapter (PRD §9.4).
//!
//! Posts JSON to a Discord webhook URL. The webhook URL itself is
//! the per-channel secret — the binding's `remote_id` carries the
//! full URL (Discord's webhook URLs already embed the channel id
//! and a per-channel token, so no separate auth header is needed).

use async_trait::async_trait;
use serde::Serialize;

use crate::identity::IdentityBinding;
use crate::platform::{MessagingPlatform, Notification, NotificationKind, PlatformId, Severity};
use crate::GatewayError;

#[derive(Debug, Clone)]
pub struct DiscordWebhookPlatform {
    client: reqwest::Client,
}

impl Default for DiscordWebhookPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscordWebhookPlatform {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl MessagingPlatform for DiscordWebhookPlatform {
    fn platform_id(&self) -> PlatformId {
        PlatformId::Discord
    }

    async fn send(
        &self,
        binding: &IdentityBinding,
        notification: &Notification,
    ) -> Result<(), GatewayError> {
        if !binding.remote_id.starts_with("http") {
            return Err(GatewayError::Backend(format!(
                "discord remote_id must be a webhook URL, got `{}`",
                binding.remote_id
            )));
        }
        let payload = DiscordPayload {
            username: "Mantis",
            content: render_notification(notification),
            embeds: vec![],
        };
        let resp = self
            .client
            .post(&binding.remote_id)
            .json(&payload)
            .send()
            .await
            .map_err(|e| GatewayError::Backend(format!("discord webhook: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Backend(format!(
                "discord {}: {text}",
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
            "{} **Mantis — new claim** `{primitive_id}` on `{surface_url}`",
            sev_emoji(*severity)
        ),
        NotificationKind::BudgetWarning {
            engagement_id,
            remaining_pct,
        } => format!(
            "⚠️ **Mantis — budget warning** engagement `{engagement_id}` at {remaining_pct}% remaining"
        ),
        NotificationKind::ScheduledRunComplete {
            engagement_id,
            verified,
        } => format!(
            "✅ **Mantis — scheduled run done** `{engagement_id}` produced {verified} verified finding(s)"
        ),
        NotificationKind::LiveVerificationApprovalRequest {
            engagement_id,
            primitive_id,
        } => format!(
            "🔐 **Mantis — approval requested** `{engagement_id}` wants to run `{primitive_id}` live"
        ),
    }
}

fn sev_emoji(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🟢",
        Severity::Informational => "⚪",
    }
}

#[derive(Serialize)]
struct DiscordPayload {
    username: &'static str,
    content: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    embeds: Vec<()>,
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
            let resp_body = if status == 204 { "" } else { "{}" };
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
        format!("http://{addr}/webhooks/123/abc")
    }

    fn binding(url: &str) -> IdentityBinding {
        IdentityBinding {
            operator: OperatorId(Ulid::new()),
            platform: PlatformId::Discord,
            remote_id: url.into(),
            created_at_unix: 0,
        }
    }

    fn notif() -> Notification {
        Notification {
            kind: NotificationKind::NewClaim {
                primitive_id: "sqli.error".into(),
                severity: Severity::High,
                surface_url: "https://api.example/v1/q".into(),
            },
            generated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn posts_payload_to_webhook_url() {
        let captured = Arc::new(Mutex::new(None));
        let url = mock_webhook(captured.clone(), 204).await;
        let platform = DiscordWebhookPlatform::new();
        platform.send(&binding(&url), &notif()).await.unwrap();
        let body = captured.lock().await.take().unwrap();
        assert!(body.contains("\"username\":\"Mantis\""));
        assert!(body.contains("sqli.error"));
        assert!(body.contains("api.example"));
    }

    #[tokio::test]
    async fn rejects_non_url_remote_id() {
        let platform = DiscordWebhookPlatform::new();
        let err = platform
            .send(&binding("not-a-url"), &notif())
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("webhook URL"));
    }

    #[tokio::test]
    async fn http_error_surfaces() {
        let captured = Arc::new(Mutex::new(None));
        let url = mock_webhook(captured, 500).await;
        let platform = DiscordWebhookPlatform::new();
        let err = platform.send(&binding(&url), &notif()).await.unwrap_err();
        assert!(format!("{err}").contains("500"));
    }

    #[tokio::test]
    async fn platform_id_is_discord() {
        let p = DiscordWebhookPlatform::new();
        assert_eq!(p.platform_id(), PlatformId::Discord);
    }
}
