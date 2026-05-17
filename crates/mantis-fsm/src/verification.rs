//! 3-round verification cascade.
//!
//! Mirrors hacker-bob's brutalist / balanced / final pipeline. Each
//! round emits one [`VerificationRoundResult`] per finding; downstream
//! gates require the cascade to be complete and self-consistent
//! before allowing the [`crate::Phase::Verify`] → [`crate::Phase::Grade`]
//! transition.

use crate::Severity;
use serde::{Deserialize, Serialize};

/// The three rounds, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationRound {
    /// Round 1: aggressive skepticism, severity-inflation challenge,
    /// fresh PoC re-run.
    Brutalist,
    /// Round 2: balanced review of brutalist decisions, reinstates
    /// false negatives, re-judges severity over-corrections.
    Balanced,
    /// Round 3: fresh re-run of reportable findings only — the
    /// authoritative severity for the report.
    Final,
}

impl VerificationRound {
    pub fn as_str(self) -> &'static str {
        match self {
            VerificationRound::Brutalist => "brutalist",
            VerificationRound::Balanced => "balanced",
            VerificationRound::Final => "final",
        }
    }

    /// Returns the next round in the cascade, or `None` for `Final`.
    pub fn next(self) -> Option<VerificationRound> {
        match self {
            VerificationRound::Brutalist => Some(VerificationRound::Balanced),
            VerificationRound::Balanced => Some(VerificationRound::Final),
            VerificationRound::Final => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationDisposition {
    /// Bug reproduced on fresh state.
    Confirmed,
    /// Bug did not reproduce; rejected.
    Denied,
    /// Bug reproduced but severity is lower than originally claimed.
    Downgraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Why the verifier landed on a particular confidence level. Multiple
/// reasons may apply per finding; allow-list matches hacker-bob's
/// `VERIFICATION_CONFIDENCE_REASON_VALUES` so cross-tool analytics line
/// up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceReason {
    FreshReplayPassed,
    AuthExpired,
    ToolingBlocked,
    StateChanged,
    ManualInference,
    RoastDisagreement,
    DisambiguationFailed,
    AgreementNotReplayed,
}

/// One verifier verdict per finding per round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingVerdict {
    pub finding_id: String,
    pub disposition: VerificationDisposition,
    /// Severity authored by the verifier. `None` when the finding was
    /// denied or downgraded out of the report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    pub reportable: bool,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confidence_reasons: Vec<ConfidenceReason>,
    /// Set when target state, auth state, or fresh-replay timing
    /// could change the outcome. Monotonic across rounds: once true,
    /// later rounds must preserve it.
    pub state_sensitive: bool,
    pub reasoning: String,
}

impl FindingVerdict {
    pub fn confirmed(
        finding_id: impl Into<String>,
        severity: Severity,
        reasoning: impl Into<String>,
    ) -> Self {
        Self {
            finding_id: finding_id.into(),
            disposition: VerificationDisposition::Confirmed,
            severity: Some(severity),
            reportable: true,
            confidence: Confidence::High,
            confidence_reasons: vec![ConfidenceReason::FreshReplayPassed],
            state_sensitive: false,
            reasoning: reasoning.into(),
        }
    }

    pub fn denied(finding_id: impl Into<String>, reasoning: impl Into<String>) -> Self {
        Self {
            finding_id: finding_id.into(),
            disposition: VerificationDisposition::Denied,
            severity: None,
            reportable: false,
            confidence: Confidence::High,
            confidence_reasons: Vec::new(),
            state_sensitive: false,
            reasoning: reasoning.into(),
        }
    }

    pub fn downgraded(
        finding_id: impl Into<String>,
        severity: Severity,
        reasoning: impl Into<String>,
    ) -> Self {
        Self {
            finding_id: finding_id.into(),
            disposition: VerificationDisposition::Downgraded,
            severity: Some(severity),
            reportable: false,
            confidence: Confidence::Medium,
            confidence_reasons: Vec::new(),
            state_sensitive: false,
            reasoning: reasoning.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRoundResult {
    pub round: VerificationRound,
    pub results: Vec<FindingVerdict>,
    /// Concise summary notes (optional). Operator-facing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Set on the **final** round only: the
    /// `Adjudication::plan_hash` this round was bound to. The
    /// VERIFY→GRADE gate refuses to open if this does not match the
    /// session's current adjudication plan hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references_plan_hash: Option<String>,
}

impl VerificationRoundResult {
    pub fn new(round: VerificationRound, results: Vec<FindingVerdict>) -> Self {
        Self {
            round,
            results,
            notes: None,
            references_plan_hash: None,
        }
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Bind the **final** round to the adjudication plan hash it was
    /// computed against. Required for the cascade gate to open.
    pub fn with_plan_hash(mut self, plan_hash: impl Into<String>) -> Self {
        self.references_plan_hash = Some(plan_hash.into());
        self
    }

    /// Iterate the finding IDs flagged `reportable: true`.
    pub fn reportable_ids(&self) -> impl Iterator<Item = &str> {
        self.results
            .iter()
            .filter(|r| r.reportable)
            .map(|r| r.finding_id.as_str())
    }
}

/// Validates that round results cover the same finding-id set across
/// rounds and that monotonic invariants (state_sensitive, snapshot
/// coverage) hold.
pub fn validate_cascade(
    brutalist: &VerificationRoundResult,
    balanced: &VerificationRoundResult,
    final_round: &VerificationRoundResult,
) -> Result<(), String> {
    if brutalist.round != VerificationRound::Brutalist {
        return Err("first arg must be the brutalist round".into());
    }
    if balanced.round != VerificationRound::Balanced {
        return Err("second arg must be the balanced round".into());
    }
    if final_round.round != VerificationRound::Final {
        return Err("third arg must be the final round".into());
    }

    let brutalist_ids: std::collections::BTreeSet<&str> =
        brutalist.results.iter().map(|r| r.finding_id.as_str()).collect();
    let balanced_ids: std::collections::BTreeSet<&str> =
        balanced.results.iter().map(|r| r.finding_id.as_str()).collect();
    let final_ids: std::collections::BTreeSet<&str> =
        final_round.results.iter().map(|r| r.finding_id.as_str()).collect();

    if brutalist_ids != balanced_ids {
        return Err("balanced round must cover exactly the brutalist finding IDs".into());
    }
    if balanced_ids != final_ids {
        return Err("final round must cover exactly the balanced finding IDs".into());
    }

    // Monotonic state_sensitive: once set in any earlier round it
    // must remain set in later rounds.
    for f in &final_round.results {
        let earlier_sensitive = brutalist
            .results
            .iter()
            .chain(balanced.results.iter())
            .any(|r| r.finding_id == f.finding_id && r.state_sensitive);
        if earlier_sensitive && !f.state_sensitive {
            return Err(format!(
                "{}: state_sensitive must remain true in final round",
                f.finding_id
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_serializes_lowercase() {
        let j = serde_json::to_string(&VerificationRound::Brutalist).unwrap();
        assert_eq!(j, "\"brutalist\"");
    }

    #[test]
    fn round_next_chains() {
        assert_eq!(
            VerificationRound::Brutalist.next(),
            Some(VerificationRound::Balanced)
        );
        assert_eq!(
            VerificationRound::Balanced.next(),
            Some(VerificationRound::Final)
        );
        assert_eq!(VerificationRound::Final.next(), None);
    }

    #[test]
    fn confirmed_helpers_are_reportable() {
        let v = FindingVerdict::confirmed("F-1", Severity::High, "fresh replay passed");
        assert!(v.reportable);
        assert_eq!(v.severity, Some(Severity::High));
    }

    #[test]
    fn denied_helpers_are_not_reportable() {
        let v = FindingVerdict::denied("F-2", "not reproducible");
        assert!(!v.reportable);
        assert_eq!(v.severity, None);
    }

    #[test]
    fn downgraded_helpers_keep_severity_but_drop_reportability() {
        let v = FindingVerdict::downgraded("F-3", Severity::Low, "non-sensitive");
        assert!(!v.reportable);
        assert_eq!(v.severity, Some(Severity::Low));
    }

    #[test]
    fn cascade_passes_when_ids_match() {
        let b = VerificationRoundResult::new(
            VerificationRound::Brutalist,
            vec![FindingVerdict::confirmed(
                "F-1",
                Severity::High,
                "replay passed",
            )],
        );
        let bal = VerificationRoundResult::new(
            VerificationRound::Balanced,
            vec![FindingVerdict::confirmed("F-1", Severity::High, "pass-through")],
        );
        let fin = VerificationRoundResult::new(
            VerificationRound::Final,
            vec![FindingVerdict::confirmed("F-1", Severity::High, "fresh replay")],
        );
        validate_cascade(&b, &bal, &fin).unwrap();
    }

    #[test]
    fn cascade_rejects_id_mismatch() {
        let b = VerificationRoundResult::new(
            VerificationRound::Brutalist,
            vec![FindingVerdict::confirmed("F-1", Severity::High, "x")],
        );
        let bal = VerificationRoundResult::new(
            VerificationRound::Balanced,
            vec![FindingVerdict::confirmed("F-2", Severity::High, "x")],
        );
        let fin = VerificationRoundResult::new(
            VerificationRound::Final,
            vec![FindingVerdict::confirmed("F-2", Severity::High, "x")],
        );
        let err = validate_cascade(&b, &bal, &fin).unwrap_err();
        assert!(err.contains("balanced round must cover"));
    }

    #[test]
    fn cascade_rejects_state_sensitive_demotion() {
        let mut b = FindingVerdict::confirmed("F-1", Severity::High, "x");
        b.state_sensitive = true;
        let brutalist =
            VerificationRoundResult::new(VerificationRound::Brutalist, vec![b.clone()]);
        let balanced =
            VerificationRoundResult::new(VerificationRound::Balanced, vec![b.clone()]);
        let mut f = FindingVerdict::confirmed("F-1", Severity::High, "x");
        f.state_sensitive = false; // demoted — invalid
        let final_round = VerificationRoundResult::new(VerificationRound::Final, vec![f]);
        let err = validate_cascade(&brutalist, &balanced, &final_round).unwrap_err();
        assert!(err.contains("state_sensitive must remain true"));
    }

    #[test]
    fn round_results_iterate_reportable() {
        let r = VerificationRoundResult::new(
            VerificationRound::Final,
            vec![
                FindingVerdict::confirmed("F-1", Severity::High, "x"),
                FindingVerdict::denied("F-2", "x"),
                FindingVerdict::downgraded("F-3", Severity::Low, "x"),
            ],
        );
        let r_ids: Vec<&str> = r.reportable_ids().collect();
        assert_eq!(r_ids, vec!["F-1"]);
    }
}
