//! Standalone CLI adapter — always available because Mantis ships the
//! `mantis` binary itself. Anchors the registry so reports are never
//! empty.

use crate::{AdapterHealth, AdapterId, AdapterInfo, AdapterPriority, AdapterState, HarnessAdapter};

pub struct StandaloneAdapter;

impl HarnessAdapter for StandaloneAdapter {
    fn info(&self) -> AdapterInfo {
        AdapterInfo {
            id: AdapterId::Standalone,
            display_name: "Standalone CLI".to_owned(),
            priority: AdapterPriority::P0,
        }
    }

    fn health(&self) -> AdapterHealth {
        AdapterHealth {
            id: AdapterId::Standalone,
            display_name: "Standalone CLI".to_owned(),
            priority: AdapterPriority::P0,
            state: AdapterState::Intrinsic,
            host_path: None,
            plugin_path: None,
            detail: "built-in mantis CLI".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_reports_intrinsic_and_healthy() {
        let h = StandaloneAdapter.health();
        assert_eq!(h.state, AdapterState::Intrinsic);
        assert!(h.is_healthy());
        assert!(h.host_path.is_none());
        assert!(h.plugin_path.is_none());
    }
}
