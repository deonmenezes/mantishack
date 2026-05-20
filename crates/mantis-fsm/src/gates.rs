//! Phase-gate primitives.
//!
//! A gate inspects engagement state and returns zero or more
//! [`Blocker`]s. A transition can only fire when the gate is empty,
//! or when the operator supplies an `override_reason` for an edge
//! that permits override.

use serde::{Deserialize, Serialize};

/// Stable identifiers for the conditions that block transitions.
/// Codes are operator-facing — they appear verbatim in CLI output
/// and analytics dashboards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerCode {
    /// Wave merge has not been reconciled yet.
    PendingWave,
    /// HIGH or CRITICAL surfaces are still unexplored.
    UnexploredHighSurfaces,
    /// HIGH or CRITICAL surfaces are terminally blocked by missing prereqs.
    BlockedHighSurfaces,
    /// Latest coverage rows are in `promising` / `needs_auth` / `requeue`.
    OpenRequeueCoverage,
    /// CHAIN was required by findings count or handoff notes but no
    /// terminal chain attempt has been recorded.
    ChainAttemptsMissing,
    /// Verification cascade is incomplete (a required round is missing).
    VerificationIncomplete,
    /// Evidence packs are missing or do not cover every reportable finding.
    EvidencePacksInvalid,
    /// Grade verdict not yet written.
    GradeMissing,
    /// Report has not been written yet.
    ReportMissing,
    /// Generic catch-all when the engagement is in an unexpected shape.
    Inconsistent,
}

impl BlockerCode {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockerCode::PendingWave => "pending_wave",
            BlockerCode::UnexploredHighSurfaces => "unexplored_high_surfaces",
            BlockerCode::BlockedHighSurfaces => "blocked_high_surfaces",
            BlockerCode::OpenRequeueCoverage => "open_requeue_coverage",
            BlockerCode::ChainAttemptsMissing => "chain_attempts_missing",
            BlockerCode::VerificationIncomplete => "verification_incomplete",
            BlockerCode::EvidencePacksInvalid => "evidence_packs_invalid",
            BlockerCode::GradeMissing => "grade_missing",
            BlockerCode::ReportMissing => "report_missing",
            BlockerCode::Inconsistent => "inconsistent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocker {
    pub code: BlockerCode,
    pub message: String,
    /// Optional structured detail: surface ids, finding ids, etc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<String>,
}

impl Blocker {
    pub fn new(code: BlockerCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            identifiers: Vec::new(),
        }
    }

    pub fn with_identifiers<I: IntoIterator<Item = String>>(mut self, ids: I) -> Self {
        self.identifiers = ids.into_iter().collect();
        self
    }
}

/// The result of running a phase gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateOutcome {
    pub blockers: Vec<Blocker>,
}

impl GateOutcome {
    pub fn clean() -> Self {
        Self {
            blockers: Vec::new(),
        }
    }

    pub fn with_blockers(blockers: Vec<Blocker>) -> Self {
        Self { blockers }
    }

    pub fn is_open(&self) -> bool {
        self.blockers.is_empty()
    }

    pub fn pretty(&self) -> String {
        if self.is_open() {
            return "open".to_string();
        }
        self.blockers
            .iter()
            .map(|b| {
                if b.identifiers.is_empty() {
                    format!("{}: {}", b.code.as_str(), b.message)
                } else {
                    format!(
                        "{}: {} [{}]",
                        b.code.as_str(),
                        b.message,
                        b.identifiers.join(", ")
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_gate_is_open() {
        assert!(GateOutcome::clean().is_open());
    }

    #[test]
    fn pretty_renders_blockers() {
        let g = GateOutcome::with_blockers(vec![Blocker::new(
            BlockerCode::PendingWave,
            "wave 1 still pending",
        )]);
        assert!(!g.is_open());
        assert_eq!(g.pretty(), "pending_wave: wave 1 still pending");
    }

    #[test]
    fn identifiers_are_rendered_in_brackets() {
        let g = GateOutcome::with_blockers(vec![Blocker::new(
            BlockerCode::UnexploredHighSurfaces,
            "HIGH surfaces remain",
        )
        .with_identifiers(["s-1".into(), "s-2".into()])]);
        assert_eq!(
            g.pretty(),
            "unexplored_high_surfaces: HIGH surfaces remain [s-1, s-2]"
        );
    }

    #[test]
    fn json_round_trip() {
        let b = Blocker::new(BlockerCode::BlockedHighSurfaces, "blocked")
            .with_identifiers(["s-1".into()]);
        let j = serde_json::to_string(&b).unwrap();
        let back: Blocker = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
