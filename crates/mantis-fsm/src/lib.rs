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
//! Linear 7-step engagement FSM with 3-round verification.
//!
//! Pipeline: `RECON -> AUTH -> HUNT -> CHAIN -> VERIFY -> GRADE -> REPORT`.
//! Inspired by hacker-bob's phase model: every transition runs through
//! [`SessionState::transition_to`], which collects [`Blocker`]s from
//! phase-specific gates. A transition succeeds only when the gate
//! returns zero blockers, or the operator supplies an `override_reason`
//! permitted for that specific edge.
//!
//! Verification is a fixed 3-round cascade:
//! [`VerificationRound::Brutalist`] → [`VerificationRound::Balanced`]
//! → [`VerificationRound::Final`]. Only `reportable: true` findings
//! coming out of the final round may be rendered.
//!
//! Reports apply a severity floor (default
//! [`Severity::Low`]) so info-tier noise never reaches the rendered
//! markdown. The renderer's reportability gate is enforced through
//! [`ReportabilityFilter::keep`].

pub mod adjudication;
pub mod coverage;
pub mod evidence;
pub mod gates;
pub mod goal;
pub mod grade;
pub mod severity;
pub mod state;
pub mod verification;

pub use crate::adjudication::{
    build_adjudication, canonical_hash, snapshot_hash, Adjudication, FindingDiff, ReplayReason,
    ReplayRequired, QA_SAMPLE_MAX, SMALL_REPORTABLE_THRESHOLD,
};
pub use crate::coverage::{
    latest_by_key, open_requeue_surface_ids, CoverageKey, CoverageRow, CoverageStatus,
};
pub use crate::evidence::{
    validate_pack_coverage, EvidenceError, EvidencePack, EvidenceSample,
    MAX_REPRESENTATIVE_SAMPLES, MAX_SAMPLE_COUNT, MAX_TEXT_CHARS,
};
pub use crate::gates::{Blocker, BlockerCode, GateOutcome};
pub use crate::goal::{FindingSummary, Goal, GoalKind, GoalStatus};
pub use crate::grade::{
    AxisScores, FindingGrade, GradeVerdict, Verdict, GRADE_HOLD_MIN_SCORE, GRADE_SUBMIT_MIN_SCORE,
};
pub use crate::severity::{Severity, SeverityFloor};
pub use crate::state::{
    AuthStatus, OverrideReason, Phase, ReportabilityFilter, SessionState, TransitionError,
    VerificationAttempt,
};
pub use crate::verification::{
    Confidence, ConfidenceReason, FindingVerdict, VerificationDisposition, VerificationRound,
    VerificationRoundResult,
};
