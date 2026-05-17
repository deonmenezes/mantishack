//! Tier trait + the three concrete implementations.

use crate::{Probe, TieredFinding};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierKind {
    Light,
    Medium,
    Hard,
}

impl TierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TierKind::Light => "light",
            TierKind::Medium => "medium",
            TierKind::Hard => "hard",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierResult {
    /// The tier found a vulnerability — done, no escalation.
    Found(TieredFinding),
    /// The tier ran cleanly but didn't find anything. Escalate to
    /// the next tier.
    Miss,
    /// The tier hit an internal error (sandbox failed, LLM
    /// unavailable, etc.). The runner records the error in notes
    /// but still escalates to the next tier — a failed light tier
    /// shouldn't block medium.
    Error(String),
}

/// Object-safe trait every tier implements.
pub trait Tier: Send + Sync {
    fn kind(&self) -> TierKind;
    /// Run the tier against the probe. Async via boxed future to
    /// keep the trait object-safe.
    fn run<'a>(
        &'a self,
        probe: &'a Probe,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = TierResult> + Send + 'a>>;
}
