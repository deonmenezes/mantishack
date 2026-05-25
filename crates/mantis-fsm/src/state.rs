//! # Apache-2.0 §4(b) notice — derivative work
//!
//! Portions of this file are derived from or mirror algorithm
//! shape, named constants, threshold values, or workflow logic from
//! Hacker Bob (<https://github.com/vmihalis/hacker-bob>),
//! Copyright 2026 Michail Vasileiadis, licensed under the Apache
//! License, Version 2.0. The surrounding Rust implementation is
//! independent and was written from scratch.
//!
//! See the project NOTICE for the upstream attribution and the
//! compliance-history apology. This notice is provided per
//! Apache-2.0 §4(b) ("You must cause any modified files to carry
//! prominent notices stating that You changed the files").
//!
//! `SessionState`: durable per-engagement FSM state.
//!
//! Each engagement holds exactly one [`SessionState`]. The state is
//! serializable; the daemon persists it through `mantis-event-store`.
//! Transitions go through [`SessionState::transition_to`], which calls
//! the relevant gate, refuses the move if the gate is non-empty, and
//! records the override reason when one is supplied.

use crate::adjudication::{build_adjudication, snapshot_hash, Adjudication};
use crate::coverage::{open_requeue_surface_ids, CoverageRow};
use crate::evidence::{validate_pack_coverage, EvidencePack};
use crate::gates::{Blocker, BlockerCode, GateOutcome};
use crate::goal::Goal;
use crate::grade::{GradeVerdict, Verdict};
use crate::severity::{Severity, SeverityFloor};
use crate::verification::{validate_cascade, VerificationRound, VerificationRoundResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

/// The seven linear phases. `RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Phase {
    Recon,
    Auth,
    Hunt,
    Chain,
    Verify,
    Grade,
    Report,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Recon => "RECON",
            Phase::Auth => "AUTH",
            Phase::Hunt => "HUNT",
            Phase::Chain => "CHAIN",
            Phase::Verify => "VERIFY",
            Phase::Grade => "GRADE",
            Phase::Report => "REPORT",
        }
    }

    /// Next phase in the canonical forward direction, if any.
    pub fn next(self) -> Option<Phase> {
        match self {
            Phase::Recon => Some(Phase::Auth),
            Phase::Auth => Some(Phase::Hunt),
            Phase::Hunt => Some(Phase::Chain),
            Phase::Chain => Some(Phase::Verify),
            Phase::Verify => Some(Phase::Grade),
            Phase::Grade => Some(Phase::Report),
            Phase::Report => None,
        }
    }

    /// True iff this is a valid forward transition. `HUNT → HUNT`
    /// (re-wave) and `GRADE → HUNT` (HOLD retry) are also permitted.
    pub fn is_valid_transition(from: Phase, to: Phase) -> bool {
        if from.next() == Some(to) {
            return true;
        }
        matches!(
            (from, to),
            (Phase::Hunt, Phase::Hunt) | (Phase::Grade, Phase::Hunt)
        )
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthStatus {
    Pending,
    Authenticated,
    Unauthenticated,
}

impl Default for AuthStatus {
    fn default() -> Self {
        AuthStatus::Pending
    }
}

/// Operator-supplied rationale for overriding a phase gate. Required
/// to be ≥ 20 characters and only accepted for the specific edges
/// that explicitly permit overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideReason(String);

impl OverrideReason {
    pub fn new(reason: impl Into<String>) -> Result<Self, TransitionError> {
        let reason = reason.into();
        if reason.trim().len() < 20 {
            return Err(TransitionError::OverrideReasonTooShort);
        }
        Ok(Self(reason))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("invalid transition: {from} -> {to}")]
    InvalidEdge { from: Phase, to: Phase },
    #[error("override_reason must be at least 20 characters")]
    OverrideReasonTooShort,
    #[error("override_reason not permitted for {from} -> {to}")]
    OverrideNotPermitted { from: Phase, to: Phase },
    #[error("gate refused: {0}")]
    GateRefused(String),
}

/// Compact reportability filter — applied at render time.
#[derive(Debug, Clone, Copy)]
pub struct ReportabilityFilter {
    pub floor: SeverityFloor,
}

impl Default for ReportabilityFilter {
    fn default() -> Self {
        Self {
            floor: SeverityFloor::default(),
        }
    }
}

impl ReportabilityFilter {
    pub fn new(floor: SeverityFloor) -> Self {
        Self { floor }
    }

    /// Keep iff the finding is `reportable: true` (set by the final
    /// verifier) and its severity meets the floor.
    pub fn keep(&self, reportable: bool, severity: Option<Severity>) -> bool {
        if !reportable {
            return false;
        }
        match severity {
            Some(s) => self.floor.admits(s),
            None => false,
        }
    }
}

/// Durable per-engagement state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub engagement_id: String,
    pub target: String,
    pub phase: Phase,
    pub auth_status: AuthStatus,

    pub hunt_wave: u32,
    /// `Some(wave_number)` while a wave's handoffs are unmerged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_wave: Option<u32>,

    /// Surface IDs the hunter declared `explored` (covered).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub explored: Vec<String>,
    /// Surface IDs terminally blocked by missing prereqs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terminally_blocked: Vec<String>,
    /// HIGH/CRITICAL surface IDs the operator considers in-scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub high_priority_surfaces: Vec<String>,
    /// Surface IDs whose latest coverage row is
    /// `promising/needs_auth/requeue`. Kept in sync with
    /// `coverage_rows` whenever rows are appended via
    /// [`SessionState::record_coverage`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_requeue: Vec<String>,
    /// Append-only coverage log. Latest-by-key semantics applied by
    /// [`crate::coverage::latest_by_key`] when computing
    /// `open_requeue`. Rows persist across the session so re-renders
    /// can audit which probes the hunters actually ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_rows: Vec<CoverageRow>,

    /// Evidence packs keyed by `finding_id`. One pack per reportable
    /// finding is required by the VERIFY→GRADE gate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_packs: Vec<EvidencePack>,

    /// Optional engagement goal. When present, the orchestrator
    /// keeps iterating waves / cascades until the goal is met or
    /// abandoned. See [`crate::goal`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal: Option<Goal>,

    /// IDs of findings that survived hunt+chain and need verification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,
    /// IDs of findings touched by a recorded chain attempt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_attempt_finding_ids: Vec<String>,

    /// Verification rounds completed so far.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_rounds: Vec<VerificationRoundResult>,

    /// Current verification attempt (opens on VERIFY enter; the
    /// final round must reference its adjudication plan hash).
    /// `None` until the cascade starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_attempt: Option<VerificationAttempt>,

    /// Grade verdict written by the grader.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<GradeVerdict>,

    /// True when the renderer has emitted `report.md` for this state.
    #[serde(default)]
    pub report_written: bool,

    /// Per-engagement reportability gate. Persisted so resumed
    /// sessions render identically to the initial run.
    #[serde(default)]
    pub severity_floor: SeverityFloor,

    /// Audit log of every gate override applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_log: Vec<OverrideEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideEntry {
    pub from: Phase,
    pub to: Phase,
    pub reason: OverrideReason,
    pub blockers: Vec<Blocker>,
}

/// Single verification attempt. Opens at the start of VERIFY phase
/// (or on a restart after stale-state). Holds the snapshot of finding
/// IDs that the cascade is bound to plus, once both early rounds
/// land, the deterministic adjudication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationAttempt {
    pub attempt_id: String,
    /// Hash of the finding-id set captured when this attempt opened.
    pub snapshot_hash: String,
    /// Adjudication, built from brutalist+balanced once both are
    /// recorded. Required before the final round can land.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adjudication: Option<Adjudication>,
}

impl VerificationAttempt {
    pub fn open(attempt_id: impl Into<String>, finding_ids: &[String]) -> Self {
        Self {
            attempt_id: attempt_id.into(),
            snapshot_hash: snapshot_hash(finding_ids),
            adjudication: None,
        }
    }

    pub fn plan_hash(&self) -> Option<&str> {
        self.adjudication.as_ref().map(|a| a.plan_hash.as_str())
    }
}

impl SessionState {
    pub fn new(engagement_id: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            engagement_id: engagement_id.into(),
            target: target.into(),
            phase: Phase::Recon,
            auth_status: AuthStatus::Pending,
            hunt_wave: 0,
            pending_wave: None,
            explored: Vec::new(),
            terminally_blocked: Vec::new(),
            high_priority_surfaces: Vec::new(),
            open_requeue: Vec::new(),
            findings: Vec::new(),
            chain_attempt_finding_ids: Vec::new(),
            verification_rounds: Vec::new(),
            verification_attempt: None,
            grade: None,
            report_written: false,
            severity_floor: SeverityFloor::default(),
            override_log: Vec::new(),
            coverage_rows: Vec::new(),
            evidence_packs: Vec::new(),
            goal: None,
        }
    }

    /// Attach a goal to the session. Replaces any previous goal.
    pub fn set_goal(&mut self, goal: Goal) {
        self.goal = Some(goal);
    }

    /// Clear the attached goal (operator abandon).
    pub fn clear_goal(&mut self) {
        self.goal = None;
    }

    /// Record an evidence pack for a finding. Replaces any existing
    /// pack for the same finding_id; the daemon validates each pack
    /// against the bounds when it's written.
    pub fn record_evidence_pack(
        &mut self,
        pack: EvidencePack,
    ) -> Result<(), crate::evidence::EvidenceError> {
        pack.validate()?;
        if let Some(existing) = self
            .evidence_packs
            .iter_mut()
            .find(|p| p.finding_id == pack.finding_id)
        {
            *existing = pack;
        } else {
            self.evidence_packs.push(pack);
        }
        Ok(())
    }

    /// Append a coverage row and refresh the open-requeue set.
    /// Latest-by-key semantics: writing a row with the same key as
    /// a previous row overwrites it for gate purposes (the prior
    /// row stays in `coverage_rows` for audit but is no longer the
    /// latest).
    pub fn record_coverage(&mut self, row: CoverageRow) {
        self.coverage_rows.push(row);
        self.open_requeue = open_requeue_surface_ids(&self.coverage_rows);
    }

    /// Open a fresh verification attempt for the current finding
    /// set. Replaces any in-flight attempt — the daemon should only
    /// call this when VERIFY is (re)entered or stale-state is
    /// detected. Returns the new attempt.
    pub fn open_verification_attempt(
        &mut self,
        attempt_id: impl Into<String>,
    ) -> &VerificationAttempt {
        // Wipe previously-recorded rounds — they were against an
        // older snapshot and are not valid for this attempt.
        self.verification_rounds.clear();
        self.verification_attempt = Some(VerificationAttempt::open(attempt_id, &self.findings));
        self.verification_attempt.as_ref().unwrap()
    }

    /// Build adjudication from the recorded brutalist + balanced
    /// rounds and persist it on the attempt. Returns the plan hash.
    pub fn build_and_record_adjudication(&mut self) -> Result<String, String> {
        let brutalist = self
            .verification_rounds
            .iter()
            .find(|r| r.round == VerificationRound::Brutalist)
            .cloned()
            .ok_or_else(|| "brutalist round not recorded".to_string())?;
        let balanced = self
            .verification_rounds
            .iter()
            .find(|r| r.round == VerificationRound::Balanced)
            .cloned()
            .ok_or_else(|| "balanced round not recorded".to_string())?;
        let attempt = self
            .verification_attempt
            .as_mut()
            .ok_or_else(|| "no open verification attempt".to_string())?;
        let adj = build_adjudication(
            &attempt.attempt_id,
            &attempt.snapshot_hash,
            &brutalist,
            &balanced,
        )?;
        let hash = adj.plan_hash.clone();
        attempt.adjudication = Some(adj);
        Ok(hash)
    }

    /// Returns the gate outcome for the proposed transition without
    /// applying it. Read-only.
    pub fn evaluate_gate(&self, to: Phase) -> Result<GateOutcome, TransitionError> {
        if !Phase::is_valid_transition(self.phase, to) {
            return Err(TransitionError::InvalidEdge {
                from: self.phase,
                to,
            });
        }
        Ok(self.gate_for(to))
    }

    /// Applies the proposed transition. Returns the gate outcome on
    /// success (the outcome is empty unless `override_reason` carried it).
    pub fn transition_to(
        &mut self,
        to: Phase,
        override_reason: Option<OverrideReason>,
    ) -> Result<GateOutcome, TransitionError> {
        if !Phase::is_valid_transition(self.phase, to) {
            return Err(TransitionError::InvalidEdge {
                from: self.phase,
                to,
            });
        }
        let outcome = self.gate_for(to);
        if !outcome.is_open() {
            let reason = match override_reason {
                Some(r) => r,
                None => return Err(TransitionError::GateRefused(outcome.pretty())),
            };
            if !permits_override(self.phase, to) {
                return Err(TransitionError::OverrideNotPermitted {
                    from: self.phase,
                    to,
                });
            }
            self.override_log.push(OverrideEntry {
                from: self.phase,
                to,
                reason,
                blockers: outcome.blockers.clone(),
            });
        }
        self.phase = to;
        Ok(outcome)
    }

    fn gate_for(&self, to: Phase) -> GateOutcome {
        match (self.phase, to) {
            (Phase::Recon, Phase::Auth) => self.gate_recon_to_auth(),
            (Phase::Auth, Phase::Hunt) => self.gate_auth_to_hunt(),
            (Phase::Hunt, Phase::Hunt) => GateOutcome::clean(),
            (Phase::Hunt, Phase::Chain) => self.gate_hunt_to_chain(),
            (Phase::Chain, Phase::Verify) => self.gate_chain_to_verify(),
            (Phase::Verify, Phase::Grade) => self.gate_verify_to_grade(),
            (Phase::Grade, Phase::Report) => self.gate_grade_to_report(),
            (Phase::Grade, Phase::Hunt) => GateOutcome::clean(), // HOLD re-hunt
            _ => GateOutcome::with_blockers(vec![Blocker::new(
                BlockerCode::Inconsistent,
                format!("no gate defined for {} -> {}", self.phase, to),
            )]),
        }
    }

    // --- gates ---

    fn gate_recon_to_auth(&self) -> GateOutcome {
        // Recon completion is signalled by at least one explored
        // surface OR an explicit "no auth required" path. Conservative
        // default: require ≥1 known surface (explored OR open_requeue).
        if self.explored.is_empty() && self.open_requeue.is_empty() {
            return GateOutcome::with_blockers(vec![Blocker::new(
                BlockerCode::Inconsistent,
                "no surfaces discovered during RECON",
            )]);
        }
        GateOutcome::clean()
    }

    fn gate_auth_to_hunt(&self) -> GateOutcome {
        if matches!(self.auth_status, AuthStatus::Pending) {
            return GateOutcome::with_blockers(vec![Blocker::new(
                BlockerCode::Inconsistent,
                "auth_status is still pending; either authenticate or set unauthenticated",
            )]);
        }
        GateOutcome::clean()
    }

    fn gate_hunt_to_chain(&self) -> GateOutcome {
        let mut blockers = Vec::new();
        if let Some(w) = self.pending_wave {
            blockers.push(
                Blocker::new(BlockerCode::PendingWave, format!("wave {w} pending merge"))
                    .with_identifiers([w.to_string()]),
            );
        }

        let explored: BTreeSet<&str> = self.explored.iter().map(|s| s.as_str()).collect();
        let blocked: BTreeSet<&str> = self.terminally_blocked.iter().map(|s| s.as_str()).collect();

        let unexplored_high: Vec<String> = self
            .high_priority_surfaces
            .iter()
            .filter(|s| !explored.contains(s.as_str()) && !blocked.contains(s.as_str()))
            .cloned()
            .collect();
        if !unexplored_high.is_empty() {
            blockers.push(
                Blocker::new(
                    BlockerCode::UnexploredHighSurfaces,
                    "HIGH/CRITICAL surfaces remain unexplored",
                )
                .with_identifiers(unexplored_high),
            );
        }

        let blocked_high: Vec<String> = self
            .high_priority_surfaces
            .iter()
            .filter(|s| blocked.contains(s.as_str()))
            .cloned()
            .collect();
        if !blocked_high.is_empty() {
            blockers.push(
                Blocker::new(
                    BlockerCode::BlockedHighSurfaces,
                    "HIGH/CRITICAL surfaces terminally blocked",
                )
                .with_identifiers(blocked_high),
            );
        }

        if !self.open_requeue.is_empty() {
            blockers.push(
                Blocker::new(
                    BlockerCode::OpenRequeueCoverage,
                    "coverage shows promising/needs_auth/requeue rows",
                )
                .with_identifiers(self.open_requeue.clone()),
            );
        }

        GateOutcome::with_blockers(blockers)
    }

    fn gate_chain_to_verify(&self) -> GateOutcome {
        // CHAIN attempts are required iff there are 2+ findings OR
        // any explicit chain note. The note channel isn't modeled in
        // this state; mirror hacker-bob's findings-count rule.
        if self.findings.len() >= 2 && self.chain_attempt_finding_ids.is_empty() {
            return GateOutcome::with_blockers(vec![Blocker::new(
                BlockerCode::ChainAttemptsMissing,
                "2+ findings present but no terminal chain attempt recorded",
            )]);
        }
        GateOutcome::clean()
    }

    fn gate_verify_to_grade(&self) -> GateOutcome {
        let have_b = self
            .verification_rounds
            .iter()
            .find(|r| r.round == VerificationRound::Brutalist);
        let have_bal = self
            .verification_rounds
            .iter()
            .find(|r| r.round == VerificationRound::Balanced);
        let have_fin = self
            .verification_rounds
            .iter()
            .find(|r| r.round == VerificationRound::Final);
        match (have_b, have_bal, have_fin) {
            (Some(b), Some(bal), Some(fin)) => {
                if let Err(reason) = validate_cascade(b, bal, fin) {
                    return GateOutcome::with_blockers(vec![Blocker::new(
                        BlockerCode::VerificationIncomplete,
                        reason,
                    )]);
                }
                // Cascade gate: the final round must reference the
                // current adjudication's plan hash. Any drift in
                // earlier rounds or the snapshot invalidates this.
                let attempt = match &self.verification_attempt {
                    Some(a) => a,
                    None => {
                        return GateOutcome::with_blockers(vec![Blocker::new(
                            BlockerCode::VerificationIncomplete,
                            "no open verification attempt",
                        )])
                    }
                };
                let expected_plan = match attempt.plan_hash() {
                    Some(h) => h,
                    None => {
                        return GateOutcome::with_blockers(vec![Blocker::new(
                            BlockerCode::VerificationIncomplete,
                            "adjudication not built — call build_and_record_adjudication after balanced round",
                        )])
                    }
                };
                let supplied_plan = match fin.references_plan_hash.as_deref() {
                    Some(h) => h,
                    None => {
                        return GateOutcome::with_blockers(vec![Blocker::new(
                            BlockerCode::VerificationIncomplete,
                            "final round must reference the adjudication plan hash",
                        )])
                    }
                };
                if expected_plan != supplied_plan {
                    return GateOutcome::with_blockers(vec![Blocker::new(
                        BlockerCode::VerificationIncomplete,
                        format!(
                            "final round plan hash {supplied_plan} does not match current adjudication {expected_plan}"
                        ),
                    )]);
                }
                // Evidence packs must cover every reportable finding.
                let reportable_ids: Vec<String> = fin
                    .results
                    .iter()
                    .filter(|r| r.reportable)
                    .map(|r| r.finding_id.clone())
                    .collect();
                if let Err(err) = validate_pack_coverage(&reportable_ids, &self.evidence_packs) {
                    return GateOutcome::with_blockers(vec![Blocker::new(
                        BlockerCode::EvidencePacksInvalid,
                        format!("{err}"),
                    )]);
                }
                GateOutcome::clean()
            }
            _ => GateOutcome::with_blockers(vec![Blocker::new(
                BlockerCode::VerificationIncomplete,
                "brutalist/balanced/final cascade not complete",
            )]),
        }
    }

    fn gate_grade_to_report(&self) -> GateOutcome {
        match &self.grade {
            Some(g) if matches!(g.verdict, Verdict::Submit | Verdict::Skip) => GateOutcome::clean(),
            Some(_) => GateOutcome::with_blockers(vec![Blocker::new(
                BlockerCode::GradeMissing,
                "grade verdict is HOLD; re-hunt before reporting",
            )]),
            None => GateOutcome::with_blockers(vec![Blocker::new(
                BlockerCode::GradeMissing,
                "no grade verdict recorded",
            )]),
        }
    }

    // --- writers ---

    pub fn record_verification_round(&mut self, r: VerificationRoundResult) {
        if let Some(existing) = self
            .verification_rounds
            .iter_mut()
            .find(|x| x.round == r.round)
        {
            *existing = r;
        } else {
            self.verification_rounds.push(r);
        }
    }

    pub fn write_grade(&mut self, g: GradeVerdict) {
        self.grade = Some(g);
    }

    /// The set of finding IDs that should be rendered. Computed from
    /// the final verifier and the configured floor.
    pub fn reportable_findings(&self, filter: &ReportabilityFilter) -> Vec<&str> {
        let Some(fin) = self
            .verification_rounds
            .iter()
            .find(|r| r.round == VerificationRound::Final)
        else {
            return Vec::new();
        };
        fin.results
            .iter()
            .filter(|v| filter.keep(v.reportable, v.severity))
            .map(|v| v.finding_id.as_str())
            .collect()
    }

    /// Stable JSON serialization used for event-store persistence.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }

    /// blake3 fingerprint for inclusion in event-store leaves.
    pub fn fingerprint_hex(&self) -> String {
        let canon = serde_json::to_vec(self).unwrap_or_default();
        let hash = blake3::hash(&canon);
        hex::encode(hash.as_bytes())
    }
}

fn permits_override(from: Phase, to: Phase) -> bool {
    matches!(
        (from, to),
        (Phase::Hunt, Phase::Chain) | (Phase::Chain, Phase::Verify)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grade::{AxisScores, FindingGrade, GradeVerdict};
    use crate::verification::FindingVerdict;

    fn ready_session() -> SessionState {
        let mut s = SessionState::new("eng-1", "https://example.com/");
        s.explored.push("surface-1".into());
        s
    }

    #[test]
    fn phase_serializes_uppercase() {
        let j = serde_json::to_string(&Phase::Recon).unwrap();
        assert_eq!(j, "\"RECON\"");
    }

    #[test]
    fn valid_forward_path() {
        assert!(Phase::is_valid_transition(Phase::Recon, Phase::Auth));
        assert!(Phase::is_valid_transition(Phase::Auth, Phase::Hunt));
        assert!(Phase::is_valid_transition(Phase::Hunt, Phase::Chain));
        assert!(Phase::is_valid_transition(Phase::Chain, Phase::Verify));
        assert!(Phase::is_valid_transition(Phase::Verify, Phase::Grade));
        assert!(Phase::is_valid_transition(Phase::Grade, Phase::Report));
    }

    #[test]
    fn re_hunt_and_hold_retry_allowed() {
        assert!(Phase::is_valid_transition(Phase::Hunt, Phase::Hunt));
        assert!(Phase::is_valid_transition(Phase::Grade, Phase::Hunt));
    }

    #[test]
    fn backwards_jumps_rejected() {
        assert!(!Phase::is_valid_transition(Phase::Verify, Phase::Recon));
        assert!(!Phase::is_valid_transition(Phase::Report, Phase::Verify));
    }

    #[test]
    fn recon_to_auth_requires_surface() {
        let mut s = SessionState::new("eng-1", "https://example.com/");
        let err = s.transition_to(Phase::Auth, None).unwrap_err();
        assert!(matches!(err, TransitionError::GateRefused(_)));
    }

    #[test]
    fn recon_to_auth_passes_with_surface() {
        let mut s = ready_session();
        let out = s.transition_to(Phase::Auth, None).unwrap();
        assert!(out.is_open());
        assert_eq!(s.phase, Phase::Auth);
    }

    #[test]
    fn auth_to_hunt_requires_resolved_auth() {
        let mut s = ready_session();
        s.transition_to(Phase::Auth, None).unwrap();
        let err = s.transition_to(Phase::Hunt, None).unwrap_err();
        assert!(matches!(err, TransitionError::GateRefused(_)));
        s.auth_status = AuthStatus::Unauthenticated;
        let out = s.transition_to(Phase::Hunt, None).unwrap();
        assert!(out.is_open());
    }

    #[test]
    fn hunt_to_chain_blocks_on_pending_wave() {
        let mut s = ready_session();
        s.phase = Phase::Hunt;
        s.pending_wave = Some(1);
        let err = s.transition_to(Phase::Chain, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("pending_wave"));
    }

    #[test]
    fn hunt_to_chain_blocks_on_unexplored_high() {
        let mut s = ready_session();
        s.phase = Phase::Hunt;
        s.high_priority_surfaces = vec!["high-1".into()];
        let err = s.transition_to(Phase::Chain, None).unwrap_err();
        assert!(format!("{err}").contains("unexplored_high_surfaces"));
    }

    #[test]
    fn override_reason_too_short_rejected() {
        let err = OverrideReason::new("too short").unwrap_err();
        assert_eq!(err, TransitionError::OverrideReasonTooShort);
    }

    #[test]
    fn override_reason_long_enough_accepted() {
        OverrideReason::new("explicit operator accepts gap for documented reason A").unwrap();
    }

    #[test]
    fn hunt_to_chain_override_permitted() {
        let mut s = ready_session();
        s.phase = Phase::Hunt;
        s.high_priority_surfaces = vec!["high-1".into()];
        let reason = OverrideReason::new(
            "operator accepted the unexplored high surface for the next pass; tracked in PR-42",
        )
        .unwrap();
        let out = s.transition_to(Phase::Chain, Some(reason)).unwrap();
        assert!(!out.is_open());
        assert_eq!(s.override_log.len(), 1);
        assert_eq!(s.phase, Phase::Chain);
    }

    #[test]
    fn recon_to_auth_override_rejected_even_with_reason() {
        let mut s = SessionState::new("eng-1", "https://example.com/");
        let reason = OverrideReason::new(
            "operator wants to skip recon for reasons that should not be allowed",
        )
        .unwrap();
        let err = s.transition_to(Phase::Auth, Some(reason)).unwrap_err();
        assert!(matches!(err, TransitionError::OverrideNotPermitted { .. }));
    }

    #[test]
    fn chain_to_verify_requires_attempts_when_findings_exist() {
        let mut s = ready_session();
        s.phase = Phase::Chain;
        s.findings = vec!["F-1".into(), "F-2".into()];
        let err = s.transition_to(Phase::Verify, None).unwrap_err();
        assert!(format!("{err}").contains("chain_attempts_missing"));
        // Recording one attempt is enough.
        s.chain_attempt_finding_ids = vec!["F-1".into()];
        s.transition_to(Phase::Verify, None).unwrap();
    }

    #[test]
    fn verify_to_grade_requires_full_cascade() {
        let mut s = ready_session();
        s.phase = Phase::Verify;
        let err = s.transition_to(Phase::Grade, None).unwrap_err();
        assert!(format!("{err}").contains("verification_incomplete"));
    }

    #[test]
    fn verify_to_grade_passes_with_full_cascade_and_plan_hash() {
        use crate::evidence::{EvidencePack, EvidenceSample};
        let mut s = ready_session();
        s.phase = Phase::Verify;
        s.findings = vec!["F-1".into()];
        s.open_verification_attempt("att-1");
        let findings = ["F-1"]
            .iter()
            .map(|id| FindingVerdict::confirmed(*id, Severity::High, "x"))
            .collect::<Vec<_>>();
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Brutalist,
            findings.clone(),
        ));
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Balanced,
            findings.clone(),
        ));
        let plan_hash = s.build_and_record_adjudication().unwrap();
        s.record_verification_round(
            VerificationRoundResult::new(VerificationRound::Final, findings)
                .with_plan_hash(plan_hash),
        );
        // Reportable finding needs an evidence pack.
        s.record_evidence_pack(EvidencePack {
            finding_id: "F-1".into(),
            sample_count: 1,
            aggregate_counts: Vec::new(),
            representative_samples: vec![EvidenceSample {
                sample_type: "http_replay".into(),
                payload: "PoC".into(),
                label: "req-1".into(),
            }],
            sensitive_clusters: Vec::new(),
            replay_summary: "replayed".into(),
            redaction_notes: "x".into(),
            report_snippet: "snippet".into(),
        })
        .unwrap();
        s.transition_to(Phase::Grade, None).unwrap();
    }

    #[test]
    fn verify_to_grade_refuses_without_evidence_pack() {
        let mut s = ready_session();
        s.phase = Phase::Verify;
        s.findings = vec!["F-1".into()];
        s.open_verification_attempt("att-1");
        let findings = vec![FindingVerdict::confirmed("F-1", Severity::High, "x")];
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Brutalist,
            findings.clone(),
        ));
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Balanced,
            findings.clone(),
        ));
        let plan_hash = s.build_and_record_adjudication().unwrap();
        s.record_verification_round(
            VerificationRoundResult::new(VerificationRound::Final, findings)
                .with_plan_hash(plan_hash),
        );
        // No evidence pack for F-1 → gate must refuse.
        let err = s.transition_to(Phase::Grade, None).unwrap_err();
        assert!(
            format!("{err}").contains("evidence_packs_invalid"),
            "got: {err}"
        );
    }

    #[test]
    fn verify_to_grade_refuses_when_final_missing_plan_hash() {
        let mut s = ready_session();
        s.phase = Phase::Verify;
        s.findings = vec!["F-1".into()];
        s.open_verification_attempt("att-1");
        let findings = vec![FindingVerdict::confirmed("F-1", Severity::High, "x")];
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Brutalist,
            findings.clone(),
        ));
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Balanced,
            findings.clone(),
        ));
        s.build_and_record_adjudication().unwrap();
        // Final lands WITHOUT the plan hash → cascade gate refuses.
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Final,
            findings,
        ));
        let err = s.transition_to(Phase::Grade, None).unwrap_err();
        assert!(
            format!("{err}").contains("must reference the adjudication plan hash"),
            "got: {err}"
        );
    }

    #[test]
    fn verify_to_grade_refuses_on_stale_plan_hash() {
        let mut s = ready_session();
        s.phase = Phase::Verify;
        s.findings = vec!["F-1".into()];
        s.open_verification_attempt("att-1");
        let findings = vec![FindingVerdict::confirmed("F-1", Severity::High, "x")];
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Brutalist,
            findings.clone(),
        ));
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Balanced,
            findings.clone(),
        ));
        s.build_and_record_adjudication().unwrap();
        // Final lands with a fabricated/stale plan hash.
        s.record_verification_round(
            VerificationRoundResult::new(VerificationRound::Final, findings)
                .with_plan_hash("deadbeef".to_string()),
        );
        let err = s.transition_to(Phase::Grade, None).unwrap_err();
        assert!(format!("{err}").contains("does not match"), "got: {err}");
    }

    #[test]
    fn verify_to_grade_refuses_when_adjudication_not_built() {
        let mut s = ready_session();
        s.phase = Phase::Verify;
        s.findings = vec!["F-1".into()];
        s.open_verification_attempt("att-1");
        let findings = vec![FindingVerdict::confirmed("F-1", Severity::High, "x")];
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Brutalist,
            findings.clone(),
        ));
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Balanced,
            findings.clone(),
        ));
        // SKIP build_and_record_adjudication
        s.record_verification_round(
            VerificationRoundResult::new(VerificationRound::Final, findings)
                .with_plan_hash("doesnt-matter"),
        );
        let err = s.transition_to(Phase::Grade, None).unwrap_err();
        assert!(
            format!("{err}").contains("adjudication not built"),
            "got: {err}"
        );
    }

    #[test]
    fn re_opening_attempt_wipes_prior_rounds() {
        let mut s = ready_session();
        s.findings = vec!["F-1".into()];
        s.open_verification_attempt("att-1");
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Brutalist,
            vec![FindingVerdict::confirmed("F-1", Severity::High, "x")],
        ));
        assert_eq!(s.verification_rounds.len(), 1);
        // New attempt — old round must vanish.
        s.findings = vec!["F-2".into()];
        s.open_verification_attempt("att-2");
        assert!(s.verification_rounds.is_empty());
        assert_eq!(s.verification_attempt.as_ref().unwrap().attempt_id, "att-2");
    }

    #[test]
    fn record_coverage_promising_blocks_hunt_to_chain() {
        use crate::coverage::{CoverageKey, CoverageRow};
        let mut s = ready_session();
        s.phase = Phase::Hunt;
        // Promising row → surface goes into open_requeue.
        s.record_coverage(CoverageRow::promising(
            CoverageKey::new("s-1", "GET", "/login", "auth-bypass"),
            10,
        ));
        let err = s.transition_to(Phase::Chain, None).unwrap_err();
        assert!(
            format!("{err}").contains("open_requeue_coverage"),
            "got: {err}"
        );
    }

    #[test]
    fn record_coverage_tested_clears_open_requeue() {
        use crate::coverage::{CoverageKey, CoverageRow};
        let mut s = ready_session();
        s.phase = Phase::Hunt;
        s.record_coverage(CoverageRow::promising(
            CoverageKey::new("s-1", "GET", "/login", "auth-bypass"),
            10,
        ));
        assert_eq!(s.open_requeue, vec!["s-1".to_string()]);
        // Re-test the same key as Tested → open_requeue clears.
        s.record_coverage(CoverageRow::tested(
            CoverageKey::new("s-1", "GET", "/login", "auth-bypass"),
            20,
        ));
        assert!(s.open_requeue.is_empty());
        s.transition_to(Phase::Chain, None).unwrap();
        assert_eq!(s.phase, Phase::Chain);
    }

    #[test]
    fn snapshot_hash_changes_when_findings_change() {
        let mut s = ready_session();
        s.findings = vec!["F-1".into()];
        s.open_verification_attempt("att-1");
        let h1 = s
            .verification_attempt
            .as_ref()
            .unwrap()
            .snapshot_hash
            .clone();

        s.findings = vec!["F-1".into(), "F-2".into()];
        s.open_verification_attempt("att-2");
        let h2 = s
            .verification_attempt
            .as_ref()
            .unwrap()
            .snapshot_hash
            .clone();
        assert_ne!(h1, h2, "different finding sets → different snapshot hashes");
    }

    #[test]
    fn grade_to_report_requires_verdict() {
        let mut s = ready_session();
        s.phase = Phase::Grade;
        let err = s.transition_to(Phase::Report, None).unwrap_err();
        assert!(format!("{err}").contains("grade_missing"));
    }

    #[test]
    fn grade_hold_blocks_report() {
        let mut s = ready_session();
        s.phase = Phase::Grade;
        // Synthesize a HOLD: medium-severity finding with 20-39 score.
        let axes = AxisScores {
            impact: 10,
            proof_quality: 10,
            severity_accuracy: 5,
            chain_potential: 0,
            report_quality: 5,
        };
        let f = FindingGrade::new("F-1", Severity::High, axes).unwrap();
        s.write_grade(GradeVerdict::compute(vec![f], None));
        let err = s.transition_to(Phase::Report, None).unwrap_err();
        assert!(format!("{err}").contains("grade_missing") || format!("{err}").contains("HOLD"));
    }

    #[test]
    fn reportable_findings_apply_floor() {
        let mut s = ready_session();
        s.severity_floor = SeverityFloor::Low;
        s.record_verification_round(VerificationRoundResult::new(
            VerificationRound::Final,
            vec![
                FindingVerdict::confirmed("F-1", Severity::High, "x"),
                FindingVerdict::confirmed("F-2", Severity::Info, "x"),
                FindingVerdict::denied("F-3", "x"),
            ],
        ));
        let filter = ReportabilityFilter::new(s.severity_floor);
        let ids = s.reportable_findings(&filter);
        assert_eq!(ids, vec!["F-1"]);
    }

    #[test]
    fn fingerprint_is_stable_per_state() {
        let s = ready_session();
        let a = s.fingerprint_hex();
        let b = s.clone().fingerprint_hex();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // 32-byte blake3
    }

    #[test]
    fn json_round_trip() {
        let s = ready_session();
        let j = s.to_json().unwrap();
        let back = SessionState::from_json(&j).unwrap();
        assert_eq!(s, back);
    }
}
