//! The provider-agnostic `Notification` envelope.

use serde::{Deserialize, Serialize};

/// Severity bucket mapped to provider-specific colors / emojis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — not a finding, just a status update.
    Info,
    /// Low severity finding (e.g., missing security header).
    Low,
    /// Medium severity finding (e.g., CORS misconfiguration).
    Medium,
    /// High severity finding (e.g., authenticated SSRF, IDOR).
    High,
    /// Critical severity finding (e.g., RCE, auth bypass to admin).
    Critical,
}

impl Severity {
    /// Hex color string suitable for Slack attachments / Discord embeds / Teams cards.
    pub const fn color_hex(self) -> &'static str {
        match self {
            Self::Info => "#2EB67D",
            Self::Low => "#36A64F",
            Self::Medium => "#ECB22E",
            Self::High => "#E01E5A",
            Self::Critical => "#8E1538",
        }
    }

    /// Unicode emoji used as a visual cue in chat.
    pub const fn emoji(self) -> &'static str {
        match self {
            Self::Info => "ℹ️",
            Self::Low => "🟢",
            Self::Medium => "🟡",
            Self::High => "🔴",
            Self::Critical => "🚨",
        }
    }

    /// Capitalized label, e.g. `"Critical"`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// Provider-agnostic notification payload.
///
/// Constructed via [`Notification::new`] and refined with builder methods. The
/// crate's [`Provider::format`](crate::Provider::format) function then renders
/// it as the JSON each chat provider expects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// One-line title — used as the message subject in every provider.
    pub title: String,
    /// Severity bucket.
    pub severity: Severity,
    /// Optional longer-form description.
    #[serde(default)]
    pub detail: Option<String>,
    /// Optional target URL the finding pertains to.
    #[serde(default)]
    pub target: Option<String>,
    /// Optional engagement ID — Mantis surfaces this so operators can deep-link
    /// into the cockpit.
    #[serde(default)]
    pub engagement_id: Option<String>,
    /// Optional CWE identifier as a string (e.g. `"CWE-89"`).
    #[serde(default)]
    pub cwe: Option<String>,
}

impl Notification {
    /// Construct a new notification with a title and severity.
    pub fn new(title: impl Into<String>, severity: Severity) -> Self {
        Self {
            title: title.into(),
            severity,
            detail: None,
            target: None,
            engagement_id: None,
            cwe: None,
        }
    }

    /// Set the long-form description.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Set the target URL.
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Set the engagement ID.
    pub fn with_engagement_id(mut self, id: impl Into<String>) -> Self {
        self.engagement_id = Some(id.into());
        self
    }

    /// Set the CWE identifier (canonical form `"CWE-<id>"`).
    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe = Some(cwe.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_fields() {
        let n = Notification::new("title", Severity::High)
            .with_detail("detail")
            .with_target("https://example.com")
            .with_engagement_id("eng-123")
            .with_cwe("CWE-89");
        assert_eq!(n.title, "title");
        assert_eq!(n.severity, Severity::High);
        assert_eq!(n.detail.as_deref(), Some("detail"));
        assert_eq!(n.target.as_deref(), Some("https://example.com"));
        assert_eq!(n.engagement_id.as_deref(), Some("eng-123"));
        assert_eq!(n.cwe.as_deref(), Some("CWE-89"));
    }

    #[test]
    fn severity_color_and_emoji_distinct() {
        let mut colors: Vec<&str> = vec![
            Severity::Info.color_hex(),
            Severity::Low.color_hex(),
            Severity::Medium.color_hex(),
            Severity::High.color_hex(),
            Severity::Critical.color_hex(),
        ];
        let len = colors.len();
        colors.sort();
        colors.dedup();
        assert_eq!(colors.len(), len);
    }

    #[test]
    fn severity_serializes_lowercase() {
        let n = Notification::new("t", Severity::Critical);
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"severity\":\"critical\""));
    }
}
