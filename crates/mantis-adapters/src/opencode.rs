//! OpenCode adapter.
//!
//! Detects the `opencode` CLI on PATH (or a `~/.config/opencode/` config
//! directory) and reports whether the Mantis plugin has been installed
//! under `~/.config/opencode/plugins/mantis/`. The plugin path matches
//! `install_for_opencode` in `install.sh`.

use crate::env::{exists, home_join, which};
use crate::{AdapterHealth, AdapterId, AdapterInfo, AdapterPriority, AdapterState, HarnessAdapter};

const HOST_BINARY: &str = "opencode";
const CONFIG_DIR_PARTS: &[&str] = &[".config", "opencode"];
const PLUGIN_DIR_PARTS: &[&str] = &[".config", "opencode", "plugins", "mantis"];

pub struct OpenCodeAdapter;

impl HarnessAdapter for OpenCodeAdapter {
    fn info(&self) -> AdapterInfo {
        AdapterInfo {
            id: AdapterId::OpenCode,
            display_name: "OpenCode".to_owned(),
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
                "opencode detected; mantis plugin installed".to_owned(),
            ),
            (true, false) => (
                AdapterState::HostPresentPluginMissing,
                "opencode detected; mantis plugin not installed".to_owned(),
            ),
            (false, _) => (
                AdapterState::HostAbsent,
                "opencode CLI not found".to_owned(),
            ),
        };

        AdapterHealth {
            id: AdapterId::OpenCode,
            display_name: "OpenCode".to_owned(),
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
        let info = OpenCodeAdapter.info();
        assert_eq!(info.id, AdapterId::OpenCode);
        assert_eq!(info.priority, AdapterPriority::P0);
    }

    #[test]
    fn health_tolerates_empty_env() {
        let h = OpenCodeAdapter.health();
        assert_eq!(h.id, AdapterId::OpenCode);
        assert!(matches!(
            h.state,
            AdapterState::Installed
                | AdapterState::HostPresentPluginMissing
                | AdapterState::HostAbsent
        ));
    }
}
