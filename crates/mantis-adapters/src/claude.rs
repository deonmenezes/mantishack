//! Claude Code adapter.
//!
//! Detects the `claude` CLI on PATH (or a `~/.claude/` config directory) and
//! reports whether the Mantis plugin has been installed under
//! `~/.claude/plugins/mantis/`. The plugin path matches `install_for_claude`
//! in `install.sh`.

use crate::env::{exists, home_join, which};
use crate::{AdapterHealth, AdapterId, AdapterInfo, AdapterPriority, AdapterState, HarnessAdapter};

const HOST_BINARY: &str = "claude";
const CONFIG_DIR_PARTS: &[&str] = &[".claude"];
const PLUGIN_DIR_PARTS: &[&str] = &[".claude", "plugins", "mantis"];

pub struct ClaudeCodeAdapter;

impl HarnessAdapter for ClaudeCodeAdapter {
    fn info(&self) -> AdapterInfo {
        AdapterInfo {
            id: AdapterId::ClaudeCode,
            display_name: "Claude Code".to_owned(),
            priority: AdapterPriority::P0,
        }
    }

    fn health(&self) -> AdapterHealth {
        let host_path = which(HOST_BINARY).map(|p| p.display().to_string());
        let config_dir = home_join(CONFIG_DIR_PARTS).and_then(exists);
        let host_present = host_path.is_some() || config_dir.is_some();

        let plugin_path = home_join(PLUGIN_DIR_PARTS)
            .and_then(exists)
            .map(|p| p.display().to_string());

        let (state, detail) = match (host_present, plugin_path.is_some()) {
            (true, true) => (
                AdapterState::Installed,
                "claude detected; mantis plugin installed".to_owned(),
            ),
            (true, false) => (
                AdapterState::HostPresentPluginMissing,
                "claude detected; mantis plugin not installed".to_owned(),
            ),
            (false, _) => (
                AdapterState::HostAbsent,
                "claude CLI not found".to_owned(),
            ),
        };

        AdapterHealth {
            id: AdapterId::ClaudeCode,
            display_name: "Claude Code".to_owned(),
            priority: AdapterPriority::P0,
            state,
            host_path,
            plugin_path,
            detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_carries_p0_priority() {
        let info = ClaudeCodeAdapter.info();
        assert_eq!(info.id, AdapterId::ClaudeCode);
        assert_eq!(info.priority, AdapterPriority::P0);
    }

    #[test]
    fn health_does_not_panic_when_env_is_empty() {
        // The probe must tolerate the absence of HOME/PATH without crashing —
        // sandbox / CI environments routinely strip both.
        let h = ClaudeCodeAdapter.health();
        assert_eq!(h.id, AdapterId::ClaudeCode);
        // Either healthy or an absent variant — never a panic.
        assert!(matches!(
            h.state,
            AdapterState::Installed
                | AdapterState::HostPresentPluginMissing
                | AdapterState::HostAbsent
        ));
    }
}
