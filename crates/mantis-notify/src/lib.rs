//! Notification payload formatters.
//!
//! Mantis produces findings that operators want surfaced in chat tools and
//! ticket systems as they're confirmed. This crate handles the *formatting*
//! half of that flow:
//!
//! - Chat providers (Slack, Discord, Teams) are unified behind [`Provider`].
//! - Ticket providers (Jira, Linear) are exposed as standalone modules
//!   ([`jira`], [`linear`]) because they need provider-specific config
//!   (project key, team id, label uuids).
//!
//! HTTP delivery is intentionally **not** in this crate. The daemon's
//! notification dispatcher owns transport so it can route through
//! `mantis-egress` for scope enforcement and retry policy. That separation
//! keeps this crate pure, deterministic, and unit-testable.
//!
//! ```rust
//! use mantis_notify::{Notification, Severity, Provider};
//! let n = Notification::new("SSRF confirmed at /api/fetch", Severity::High)
//!     .with_target("https://example.com/api/fetch")
//!     .with_detail("Reproducer attached.");
//! let payload = Provider::Slack.format(&n);
//! assert!(payload.to_string().contains("SSRF"));
//! ```

#![deny(missing_docs)]

pub mod bugcrowd;
mod discord;
pub mod github_sarif;
pub mod hackerone;
pub mod jira;
pub mod linear;
mod notification;
mod slack;
mod teams;

pub use notification::{Notification, Severity};

use serde_json::Value;

/// Supported chat-tool destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    /// Slack incoming webhook (Block Kit message payload).
    Slack,
    /// Discord webhook (embed-based payload).
    Discord,
    /// Microsoft Teams (incoming webhook MessageCard payload).
    Teams,
}

impl Provider {
    /// Render a [`Notification`] into the JSON payload this provider's
    /// incoming-webhook endpoint expects.
    pub fn format(self, notification: &Notification) -> Value {
        match self {
            Self::Slack => slack::format(notification),
            Self::Discord => discord::format(notification),
            Self::Teams => teams::format(notification),
        }
    }

    /// All supported providers, in stable order.
    pub const fn all() -> [Provider; 3] {
        [Self::Slack, Self::Discord, Self::Teams]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_providers_format_without_panic() {
        let n = Notification::new("test finding", Severity::Medium);
        for p in Provider::all() {
            let payload = p.format(&n);
            assert!(payload.is_object(), "provider {p:?} did not produce object");
        }
    }
}
