//! Codex CLI adapter.
//!
//! Detects the `codex` CLI on PATH (or a `~/.codex/` config directory) and
//! reports whether the Mantis plugin has been installed under
//! `~/.codex/plugins/mantis/`. The plugin path matches `install_for_codex`
//! in `install.sh`.

use crate::env::{exists, home_join, which};
use crate::{AdapterHealth, AdapterId, AdapterInfo, AdapterPriority, AdapterState, HarnessAdapter};

const HOST_BINARY: &str = "codex";
const CONFIG_DIR_PARTS: &[&str] = &[".codex"];
const PLUGIN_DIR_PARTS: &[&str] = &[".codex", "plugins", "mantis"];

pub struct CodexCliAdapter;

impl HarnessAdapter for CodexCliAdapter {
    fn info(&self) -> AdapterInfo {
        AdapterInfo {
            id: AdapterId::CodexCli,
            display_name: "Codex CLI".to_owned(),
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
                "codex detected; mantis plugin installed".to_owned(),
            ),
            (true, false) => (
                AdapterState::HostPresentPluginMissing,
                "codex detected; mantis plugin not installed".to_owned(),
            ),
            (false, _) => (
                AdapterState::HostAbsent,
                "codex CLI not found".to_owned(),
            ),
        };

        AdapterHealth {
            id: AdapterId::CodexCli,
            display_name: "Codex CLI".to_owned(),
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
        let info = CodexCliAdapter.info();
        assert_eq!(info.id, AdapterId::CodexCli);
        assert_eq!(info.priority, AdapterPriority::P0);
    }

    #[test]
    fn health_tolerates_empty_env() {
        let h = CodexCliAdapter.health();
        assert_eq!(h.id, AdapterId::CodexCli);
        assert!(matches!(
            h.state,
            AdapterState::Installed
                | AdapterState::HostPresentPluginMissing
                | AdapterState::HostAbsent
        ));
    }
}
