//! Multi-harness adapter layer.
//!
//! Mantis ships slash commands and MCP tools into several AI coding hosts —
//! Claude Code, Codex CLI, OpenCode — and also runs as a standalone CLI. The
//! [`HarnessAdapter`] trait gives each host a single shape so callers
//! (installer, `mantis doctor`, future install/uninstall flows) can iterate
//! every supported harness without duplicating per-host logic.
//!
//! Phase 1 scope (PRD §F1):
//! - One trait, one health shape.
//! - Read-only detection (no install/uninstall side effects yet).
//! - `mantis doctor` consumes the registry to report install state for each
//!   harness.
//!
//! Future phases extend this with install/uninstall, command registration,
//! and MCP server lifecycle. Keeping the trait small in v1 makes those
//! extensions additive.

mod env;

pub mod claude;
pub mod codex;
pub mod opencode;
pub mod standalone;

pub use claude::ClaudeCodeAdapter;
pub use codex::CodexCliAdapter;
pub use opencode::OpenCodeAdapter;
pub use standalone::StandaloneAdapter;

use serde::{Deserialize, Serialize};

/// Canonical identifier for a supported harness. The string form is stable
/// and shows up in CLI output, JSON reports, and config files — do not
/// rename without a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterId {
    #[serde(rename = "claude-code")]
    ClaudeCode,
    #[serde(rename = "codex-cli")]
    CodexCli,
    // Explicit rename rather than kebab-case derive — the installer uses
    // "opencode" (one word) for the host name and plugin directory; the
    // default kebab-case rule would turn `OpenCode` into "open-code".
    #[serde(rename = "opencode")]
    OpenCode,
    #[serde(rename = "standalone")]
    Standalone,
}

impl AdapterId {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::CodexCli => "codex-cli",
            Self::OpenCode => "opencode",
            Self::Standalone => "standalone",
        }
    }
}

impl std::fmt::Display for AdapterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Roadmap priority for a harness. P0 hosts must be supported in v1 (PRD
/// §F1); P1/P2 hosts are tracked but optional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterPriority {
    P0,
    P1,
    P2,
}

/// Install state for a harness on the current host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum AdapterState {
    /// The host CLI (e.g. `claude`) is not installed and no config dir was
    /// found.
    HostAbsent,
    /// The host CLI is present (binary on PATH or a config directory exists)
    /// but the Mantis plugin has not been installed into it.
    HostPresentPluginMissing,
    /// The host CLI is present and the Mantis plugin is installed.
    Installed,
    /// Adapter is intrinsic to Mantis (e.g. the standalone CLI) and is
    /// always available.
    Intrinsic,
}

impl AdapterState {
    /// True when the adapter is in a usable state.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Installed | Self::Intrinsic)
    }
}

/// Static metadata for a harness adapter. Cheap to obtain; safe to clone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterInfo {
    pub id: AdapterId,
    pub display_name: String,
    pub priority: AdapterPriority,
}

/// Runtime health report for a single harness adapter. Produced by
/// [`HarnessAdapter::health`] and surfaced through `mantis doctor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterHealth {
    pub id: AdapterId,
    pub display_name: String,
    pub priority: AdapterPriority,
    pub state: AdapterState,
    /// Path to the host CLI binary on PATH, if discovered.
    pub host_path: Option<String>,
    /// Path to the installed Mantis plugin directory, if discovered.
    pub plugin_path: Option<String>,
    /// One-line human-readable detail describing the current state.
    pub detail: String,
}

impl AdapterHealth {
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.state.is_healthy()
    }
}

/// Read-only health probe for a single harness.
///
/// Implementations must be cheap, side-effect-free, and tolerant of missing
/// hosts — a failing adapter must never crash `mantis doctor` or block the
/// standalone CLI (PRD §F1 acceptance: "a failing adapter does not break
/// standalone CLI").
pub trait HarnessAdapter: Send + Sync {
    fn info(&self) -> AdapterInfo;
    fn health(&self) -> AdapterHealth;
}

/// Default registry of harness adapters in declaration order. Standalone
/// comes first so its always-healthy entry anchors the report even when no
/// AI CLIs are installed.
#[must_use]
pub fn default_registry() -> Vec<Box<dyn HarnessAdapter>> {
    vec![
        Box::new(StandaloneAdapter),
        Box::new(ClaudeCodeAdapter),
        Box::new(CodexCliAdapter),
        Box::new(OpenCodeAdapter),
    ]
}

/// Collect health reports for every adapter in [`default_registry`]. Each
/// adapter's `health()` is called independently; an adapter that wants to
/// signal a failure does so by returning [`AdapterState::HostAbsent`] with a
/// descriptive `detail`.
#[must_use]
pub fn health_report() -> Vec<AdapterHealth> {
    default_registry().iter().map(|a| a.health()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_id_string_form_is_stable() {
        assert_eq!(AdapterId::ClaudeCode.as_str(), "claude-code");
        assert_eq!(AdapterId::CodexCli.as_str(), "codex-cli");
        assert_eq!(AdapterId::OpenCode.as_str(), "opencode");
        assert_eq!(AdapterId::Standalone.as_str(), "standalone");
    }

    #[test]
    fn adapter_id_json_form_matches_str_form() {
        // The serde rename and `as_str` must agree — they're both stable
        // surfaces (CLI output, JSON, config). Drift here means a future
        // config file is unreadable by `mantis doctor --output-format json`.
        for id in [
            AdapterId::ClaudeCode,
            AdapterId::CodexCli,
            AdapterId::OpenCode,
            AdapterId::Standalone,
        ] {
            let json = serde_json::to_string(&id).expect("serialize");
            let unquoted = json.trim_matches('"');
            assert_eq!(
                unquoted,
                id.as_str(),
                "AdapterId::{id:?} drift between serde rename and as_str()",
            );
        }
    }

    #[test]
    fn adapter_state_health_only_true_when_usable() {
        assert!(AdapterState::Installed.is_healthy());
        assert!(AdapterState::Intrinsic.is_healthy());
        assert!(!AdapterState::HostAbsent.is_healthy());
        assert!(!AdapterState::HostPresentPluginMissing.is_healthy());
    }

    #[test]
    fn default_registry_includes_all_p0_harnesses() {
        let ids: Vec<_> = default_registry().iter().map(|a| a.info().id).collect();
        assert!(ids.contains(&AdapterId::Standalone));
        assert!(ids.contains(&AdapterId::ClaudeCode));
        assert!(ids.contains(&AdapterId::CodexCli));
        assert!(ids.contains(&AdapterId::OpenCode));
    }

    #[test]
    fn standalone_is_first_so_anchor_is_always_present() {
        let registry = default_registry();
        assert_eq!(registry[0].info().id, AdapterId::Standalone);
    }

    #[test]
    fn health_report_returns_one_entry_per_adapter() {
        let report = health_report();
        assert_eq!(report.len(), default_registry().len());
    }

    #[test]
    fn standalone_health_is_always_healthy() {
        let h = StandaloneAdapter.health();
        assert!(h.is_healthy());
    }
}
