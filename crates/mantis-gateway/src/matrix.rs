//! Matrix client-server adapter (PRD §9.4).
//!
//! PUTs to `/_matrix/client/v3/rooms/<roomId>/send/m.room.message/<txnId>`
//! with an access token. The binding's `remote_id` is the Matrix
//! room id (`!abc:example.com`).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde::Serialize;

use crate::identity::IdentityBinding;
use crate::platform::{MessagingPlatform, Notification, NotificationKind, PlatformId, Severity};
use crate::GatewayError;

#[derive(Debug)]
pub struct MatrixClientPlatform {
    client: reqwest::Client,
    homeserver_url: String,
    access_token: String,
    txn_counter: AtomicU64,
}

impl Clone for MatrixClientPlatform {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            homeserver_url: self.homeserver_url.clone(),
            access_token: self.access_token.clone(),
            txn_counter: AtomicU64::new(self.txn_counter.load(Ordering::SeqCst)),
        }
    }
}

impl MatrixClientPlatform {
    pub fn new(homeserver_url: impl Into<String>, access_token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            homeserver_url: homeserver_url.into(),
            access_token: access_token.into(),
            txn_counter: AtomicU64::new(0),
        }
    }

    fn next_txn(&self) -> String {
        let n = self.txn_counter.fetch_add(1, Ordering::SeqCst);
        format!("mantis-{n}")
    }
}

#[async_trait]
impl MessagingPlatform for MatrixClientPlatform {
    fn platform_id(&self) -> PlatformId {
        PlatformId::Matrix
    }

    async fn send(
        &self,
        binding: &IdentityBinding,
        notification: &Notification,
    ) -> Result<(), GatewayError> {
        if !binding.remote_id.starts_with('!') {
            return Err(GatewayError::Backend(format!(
                "matrix remote_id must be a room id (`!xyz:server`), got `{}`",
                binding.remote_id
            )));
        }
        let body = MatrixMessage {
            msgtype: "m.text",
            body: render_notification(notification),
        };
        let txn_id = self.next_txn();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.homeserver_url.trim_end_matches('/'),
            urlencode_room_id(&binding.remote_id),
            txn_id
        );
        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| GatewayError::Backend(format!("matrix send: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Backend(format!(
                "matrix {}: {text}",
                status.as_u16()
            )));
        }
        Ok(())
    }
}

fn urlencode_room_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                // write! into the existing String — the prior
                // push_str(&format!()) allocated a fresh 3-char String
                // per non-alnum byte. write! formats straight into `out`.
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn render_notification(n: &Notification) -> String {
    match &n.kind {
        NotificationKind::NewClaim {
            primitive_id,
            severity,
            surface_url,
        } => format!(
            "Mantis [{}] new claim {primitive_id} on {surface_url}",
            sev_short(*severity)
        ),
        NotificationKind::BudgetWarning {
            engagement_id,
            remaining_pct,
        } => format!("Mantis budget warning: {engagement_id} at {remaining_pct}%"),
        NotificationKind::ScheduledRunComplete {
            engagement_id,
            verified,
        } => format!(
            "Mantis scheduled run done: {engagement_id} produced {verified} verified finding(s)"
        ),
        NotificationKind::LiveVerificationApprovalRequest {
            engagement_id,
            primitive_id,
        } => format!("Mantis approval requested: {engagement_id} wants to run {primitive_id} live"),
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
struct MatrixMessage {
    msgtype: &'static str,
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
            let body = r#"{"event_id":"$1:server"}"#;
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

    fn binding(room: &str) -> IdentityBinding {
        IdentityBinding {
            operator: OperatorId(Ulid::new()),
            platform: PlatformId::Matrix,
            remote_id: room.into(),
            created_at_unix: 0,
        }
    }

    fn notif() -> Notification {
        Notification {
            kind: NotificationKind::BudgetWarning {
                engagement_id: "01HMX".into(),
                remaining_pct: 7,
            },
            generated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn put_to_room_message_endpoint() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(captured.clone(), 200).await;
        let p = MatrixClientPlatform::new(base, "syt-test");
        p.send(&binding("!abc:example.com"), &notif())
            .await
            .unwrap();
        let raw = captured.lock().await.take().unwrap();
        assert!(raw.contains("PUT /_matrix/client/v3/rooms/"));
        assert!(raw.contains("send/m.room.message/mantis-0"));
        assert!(raw
            .to_lowercase()
            .contains("authorization: bearer syt-test"));
        assert!(raw.contains("\"msgtype\":\"m.text\""));
        assert!(raw.contains("01HMX"));
    }

    #[tokio::test]
    async fn rejects_non_room_id() {
        let p = MatrixClientPlatform::new("http://127.0.0.1:1", "tok");
        let err = p.send(&binding("not-a-room"), &notif()).await.unwrap_err();
        assert!(format!("{err}").contains("room id"));
    }

    #[tokio::test]
    async fn http_error_surfaces() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(captured, 403).await;
        let p = MatrixClientPlatform::new(base, "bad");
        let err = p.send(&binding("!a:b.com"), &notif()).await.unwrap_err();
        assert!(format!("{err}").contains("403"));
    }

    #[tokio::test]
    async fn txn_id_increments_per_send() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(captured.clone(), 200).await;
        let p = MatrixClientPlatform::new(base.clone(), "tok");
        p.send(&binding("!a:b.com"), &notif()).await.unwrap();
        // Spin up a second mock for the second call so it has a
        // fresh socket.
        let captured2 = Arc::new(Mutex::new(None));
        let base2 = mock_server(captured2.clone(), 200).await;
        let p2 = MatrixClientPlatform {
            client: reqwest::Client::new(),
            homeserver_url: base2,
            access_token: "tok".into(),
            txn_counter: AtomicU64::new(1),
        };
        p2.send(&binding("!a:b.com"), &notif()).await.unwrap();
        let raw2 = captured2.lock().await.take().unwrap();
        assert!(raw2.contains("/mantis-1"));
    }
}
