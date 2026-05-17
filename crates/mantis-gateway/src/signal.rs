//! Signal CLI bridge adapter (PRD §9.4).
//!
//! Signal does not publish an official server-side API; the
//! pragmatic deployment is to run `signal-cli` as a JSON-RPC daemon
//! on the same host as Mantis. This adapter exec's the `signal-cli`
//! binary with `send` parameters per message. Operators who run
//! `signal-cli daemon` can swap in a JSON-RPC client; both pathways
//! use the same `SignalCliPlatform` configuration surface.
//!
//! The exec path is preferred because it survives signal-cli
//! restarts and matches what most operators script anyway.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::identity::IdentityBinding;
use crate::platform::{MessagingPlatform, Notification, NotificationKind, PlatformId, Severity};
use crate::GatewayError;

const DEFAULT_BINARY: &str = "signal-cli";

#[derive(Debug, Clone)]
pub struct SignalCliPlatform {
    binary: PathBuf,
    sender_account: String,
}

impl SignalCliPlatform {
    pub fn new(sender_account: impl Into<String>) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_BINARY),
            sender_account: sender_account.into(),
        }
    }

    pub fn with_binary(mut self, path: impl AsRef<Path>) -> Self {
        self.binary = path.as_ref().to_path_buf();
        self
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary
    }

    pub fn sender_account(&self) -> &str {
        &self.sender_account
    }

    /// Compose the command-line arguments for `signal-cli`. Exposed
    /// for tests so callers can verify the arg list without
    /// actually exec'ing the binary.
    pub fn build_args(&self, recipient: &str, message: &str) -> Vec<String> {
        vec![
            "-u".into(),
            self.sender_account.clone(),
            "send".into(),
            "-m".into(),
            message.into(),
            recipient.into(),
        ]
    }
}

#[async_trait]
impl MessagingPlatform for SignalCliPlatform {
    fn platform_id(&self) -> PlatformId {
        PlatformId::Signal
    }

    async fn send(
        &self,
        binding: &IdentityBinding,
        notification: &Notification,
    ) -> Result<(), GatewayError> {
        if !binding.remote_id.starts_with('+') {
            return Err(GatewayError::Backend(format!(
                "signal remote_id must be E.164 with +, got `{}`",
                binding.remote_id
            )));
        }
        let message = render_notification(notification);
        let args = self.build_args(&binding.remote_id, &message);

        let output = tokio::process::Command::new(&self.binary)
            .args(&args)
            .output()
            .await
            .map_err(|e| GatewayError::Backend(format!("signal-cli spawn: {e}")))?;
        if !output.status.success() {
            return Err(GatewayError::Backend(format!(
                "signal-cli exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
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

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_core::OperatorId;
    use ulid::Ulid;

    fn binding(phone: &str) -> IdentityBinding {
        IdentityBinding {
            operator: OperatorId(Ulid::new()),
            platform: PlatformId::Signal,
            remote_id: phone.into(),
            created_at_unix: 0,
        }
    }

    fn notif() -> Notification {
        Notification {
            kind: NotificationKind::BudgetWarning {
                engagement_id: "01HSG".into(),
                remaining_pct: 4,
            },
            generated_at_unix: 0,
        }
    }

    #[test]
    fn default_binary_is_signal_cli() {
        let p = SignalCliPlatform::new("+15550000000");
        assert_eq!(p.binary_path(), Path::new(DEFAULT_BINARY));
    }

    #[test]
    fn build_args_contains_sender_recipient_and_message() {
        let p = SignalCliPlatform::new("+15550000000");
        let args = p.build_args("+15551111111", "hello");
        assert_eq!(args[0], "-u");
        assert_eq!(args[1], "+15550000000");
        assert_eq!(args[2], "send");
        assert_eq!(args[3], "-m");
        assert_eq!(args[4], "hello");
        assert_eq!(args[5], "+15551111111");
    }

    #[tokio::test]
    async fn rejects_phone_without_plus() {
        let p = SignalCliPlatform::new("+1").with_binary("/nonexistent-binary");
        let err = p.send(&binding("15551234567"), &notif()).await.unwrap_err();
        assert!(format!("{err}").contains("E.164"));
    }

    #[tokio::test]
    async fn missing_binary_surfaces_as_backend_error() {
        let p = SignalCliPlatform::new("+1").with_binary("/definitely/not/here");
        let err = p
            .send(&binding("+15551234567"), &notif())
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("signal-cli") || msg.contains("spawn"));
    }

    #[test]
    fn platform_id_is_signal() {
        assert_eq!(
            SignalCliPlatform::new("+1").platform_id(),
            PlatformId::Signal
        );
    }
}
