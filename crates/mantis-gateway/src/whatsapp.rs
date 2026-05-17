//! WhatsApp Cloud API adapter (PRD §9.4).
//!
//! Posts to `https://graph.facebook.com/v17.0/<PHONE_NUMBER_ID>/messages`
//! with the configured Cloud-API access token. The binding's
//! `remote_id` is the recipient's E.164 phone number (no leading
//! `+`, e.g. `15551234567`).

use async_trait::async_trait;
use serde::Serialize;

use crate::identity::IdentityBinding;
use crate::platform::{MessagingPlatform, Notification, NotificationKind, PlatformId, Severity};
use crate::GatewayError;

const DEFAULT_BASE_URL: &str = "https://graph.facebook.com";
const DEFAULT_API_VERSION: &str = "v17.0";

#[derive(Debug, Clone)]
pub struct WhatsAppCloudPlatform {
    client: reqwest::Client,
    access_token: String,
    phone_number_id: String,
    base_url: String,
    api_version: String,
}

impl WhatsAppCloudPlatform {
    pub fn new(access_token: impl Into<String>, phone_number_id: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            access_token: access_token.into(),
            phone_number_id: phone_number_id.into(),
            base_url: DEFAULT_BASE_URL.into(),
            api_version: DEFAULT_API_VERSION.into(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_api_version(mut self, v: impl Into<String>) -> Self {
        self.api_version = v.into();
        self
    }
}

#[async_trait]
impl MessagingPlatform for WhatsAppCloudPlatform {
    fn platform_id(&self) -> PlatformId {
        PlatformId::WhatsApp
    }

    async fn send(
        &self,
        binding: &IdentityBinding,
        notification: &Notification,
    ) -> Result<(), GatewayError> {
        if !binding.remote_id.chars().all(|c| c.is_ascii_digit()) {
            return Err(GatewayError::Backend(format!(
                "whatsapp remote_id must be E.164 digits (no +), got `{}`",
                binding.remote_id
            )));
        }
        let payload = WhatsAppPayload {
            messaging_product: "whatsapp",
            to: &binding.remote_id,
            r#type: "text",
            text: WhatsAppText {
                body: render_notification(notification),
            },
        };
        let url = format!(
            "{}/{}/{}/messages",
            self.base_url.trim_end_matches('/'),
            self.api_version,
            self.phone_number_id
        );
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| GatewayError::Backend(format!("whatsapp send: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Backend(format!(
                "whatsapp {}: {text}",
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
            "Mantis [{}] {primitive_id} on {surface_url}",
            sev_short(*severity)
        ),
        NotificationKind::BudgetWarning {
            engagement_id,
            remaining_pct,
        } => format!("Mantis budget warning: {engagement_id} at {remaining_pct}%"),
        NotificationKind::ScheduledRunComplete {
            engagement_id,
            verified,
        } => format!("Mantis: {engagement_id} done — {verified} verified finding(s)"),
        NotificationKind::LiveVerificationApprovalRequest {
            engagement_id,
            primitive_id,
        } => format!("Mantis: approve `{primitive_id}` on `{engagement_id}` to run live"),
    }
}

fn sev_short(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Informational => "INFO",
    }
}

#[derive(Serialize)]
struct WhatsAppPayload<'a> {
    messaging_product: &'a str,
    to: &'a str,
    r#type: &'a str,
    text: WhatsAppText,
}

#[derive(Serialize)]
struct WhatsAppText {
    body: String,
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

    async fn mock_server(captured: Arc<Mutex<Option<String>>>, status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            *captured.lock().await = Some(raw);
            let body = r#"{"messages":[{"id":"wamid.test"}]}"#;
            let reason = if (200..300).contains(&status) {
                "OK"
            } else {
                "ERR"
            };
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(body.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        });
        format!("http://{addr}")
    }

    fn binding(phone: &str) -> IdentityBinding {
        IdentityBinding {
            operator: OperatorId(Ulid::new()),
            platform: PlatformId::WhatsApp,
            remote_id: phone.into(),
            created_at_unix: 0,
        }
    }

    fn notif() -> Notification {
        Notification {
            kind: NotificationKind::BudgetWarning {
                engagement_id: "01HWA".into(),
                remaining_pct: 9,
            },
            generated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn posts_to_cloud_api_messages_endpoint() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(captured.clone(), 200).await;
        let p = WhatsAppCloudPlatform::new("EAA", "12345").with_base_url(base);
        p.send(&binding("15551234567"), &notif()).await.unwrap();
        let raw = captured.lock().await.take().unwrap();
        assert!(raw.contains("POST /v17.0/12345/messages"));
        assert!(raw.to_lowercase().contains("authorization: bearer eaa"));
        assert!(raw.contains("\"messaging_product\":\"whatsapp\""));
        assert!(raw.contains("\"to\":\"15551234567\""));
        assert!(raw.contains("01HWA"));
    }

    #[tokio::test]
    async fn rejects_non_digit_phone() {
        let p = WhatsAppCloudPlatform::new("x", "1").with_base_url("http://127.0.0.1:1");
        let err = p
            .send(&binding("+15551234567"), &notif())
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("E.164"));
    }

    #[tokio::test]
    async fn http_error_surfaces() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(captured, 400).await;
        let p = WhatsAppCloudPlatform::new("x", "1").with_base_url(base);
        let err = p.send(&binding("15551234567"), &notif()).await.unwrap_err();
        assert!(format!("{err}").contains("400"));
    }
}
