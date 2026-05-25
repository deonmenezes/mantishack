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
//! Verification cascade adjudication.
//!
//! Ports hacker-bob's `buildVerificationAdjudication` (verification.js
//! around L756) and the surrounding attempt/snapshot infrastructure
//! that makes the cascade gate strong: the final round must reference
//! an `adjudication_plan_hash` computed deterministically from the
//! current brutalist + balanced rounds. Any drift — re-running a round,
//! changing the snapshot, swapping findings — invalidates the hash and
//! the final round is rejected.
//!
//! Output of [`build_adjudication`] feeds the
//! [`crate::SessionState::record_adjudication`] call, which must
//! happen before the final round can land.

use crate::severity::Severity;
use crate::verification::{
    FindingVerdict, VerificationDisposition, VerificationRound, VerificationRoundResult,
};
use serde::{Deserialize, Serialize};

/// Findings small enough for unconditional replay coverage. Mirrors
/// hacker-bob's `VERIFY_SMALL_REPORTABLE_THRESHOLD`.
pub const SMALL_REPORTABLE_THRESHOLD: usize = 5;
/// Cap on deterministic QA sample. Mirrors hacker-bob's
/// `VERIFY_QA_SAMPLE_MAX`.
pub const QA_SAMPLE_MAX: usize = 10;

/// Stable reasons for why a finding was placed on the replay-required
/// list. Operator-facing — surfaces in `adjudication.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayReason {
    /// Brutalist and balanced disagreed on disposition / severity / reportable.
    RoundDisagreement,
    /// Either round marked the finding HIGH/CRITICAL reportable.
    AgreedHighOrCriticalReportable,
    /// Any earlier round marked the finding state_sensitive.
    StateSensitive,
    /// Either round's confidence was low/medium.
    LowConfidence,
    /// Auth expired during one of the earlier rounds.
    Auth,
    /// Tooling / RPC unavailable.
    Tooling,
    /// `unionReportables.size <= SMALL_REPORTABLE_THRESHOLD` — re-run all.
    SmallReportableUnion,
    /// Picked by deterministic QA sampling.
    QaSample,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRequired {
    pub finding_id: String,
    pub reasons: Vec<ReplayReason>,
}

/// Single finding-level diff between brutalist and balanced rounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingDiff {
    pub finding_id: String,
    pub brutalist_disposition: VerificationDisposition,
    pub balanced_disposition: VerificationDisposition,
    pub brutalist_severity: Option<Severity>,
    pub balanced_severity: Option<Severity>,
    pub brutalist_reportable: bool,
    pub balanced_reportable: bool,
    pub state_sensitive_either: bool,
}

/// Output of `build_adjudication`. The `plan_hash` is the value the
/// final-round writer must echo back to land successfully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adjudication {
    pub attempt_id: String,
    pub snapshot_hash: String,
    /// Hash of canonical-JSON of the brutalist round, fixed at the
    /// moment adjudication was built. Drift in the round invalidates.
    pub brutalist_hash: String,
    /// Hash of canonical-JSON of the balanced round.
    pub balanced_hash: String,
    /// Final hash the final round must reference.
    pub plan_hash: String,
    pub agreed: Vec<String>,
    pub disagreements: Vec<FindingDiff>,
    pub replay_required: Vec<ReplayRequired>,
    pub qa_sample: Vec<String>,
}

impl Adjudication {
    /// True iff the finding must be re-run by the final round.
    pub fn requires_replay(&self, finding_id: &str) -> bool {
        self.replay_required
            .iter()
            .any(|r| r.finding_id == finding_id)
    }
}

/// Canonical-JSON blake3 hash of any serializable value.
pub fn canonical_hash<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// Compute the snapshot hash for a finding-id set. Stable iff the
/// (lexicographically sorted) set is the same.
pub fn snapshot_hash(finding_ids: &[String]) -> String {
    let mut sorted: Vec<&str> = finding_ids.iter().map(|s| s.as_str()).collect();
    sorted.sort_unstable();
    let joined = sorted.join("\n");
    hex::encode(blake3::hash(joined.as_bytes()).as_bytes())
}

/// Build the adjudication payload from two completed rounds. Returns
/// the deterministic plan whose hash gates the final round.
///
/// `attempt_id` is supplied by the caller (typically a ULID
/// generated when VERIFY phase opened); `snapshot_hash` is the hash
/// of the finding-id set captured at that moment.
pub fn build_adjudication(
    attempt_id: impl Into<String>,
    snapshot_hash: impl Into<String>,
    brutalist: &VerificationRoundResult,
    balanced: &VerificationRoundResult,
) -> Result<Adjudication, String> {
    if brutalist.round != VerificationRound::Brutalist {
        return Err("first arg must be the brutalist round".into());
    }
    if balanced.round != VerificationRound::Balanced {
        return Err("second arg must be the balanced round".into());
    }

    let attempt_id = attempt_id.into();
    let snapshot_hash = snapshot_hash.into();
    let brutalist_hash = canonical_hash(brutalist);
    let balanced_hash = canonical_hash(balanced);

    // Index by finding_id for fast diffs.
    let by_b: std::collections::BTreeMap<&str, &FindingVerdict> = brutalist
        .results
        .iter()
        .map(|v| (v.finding_id.as_str(), v))
        .collect();
    let by_bal: std::collections::BTreeMap<&str, &FindingVerdict> = balanced
        .results
        .iter()
        .map(|v| (v.finding_id.as_str(), v))
        .collect();

    // The finding-id universe is the union (in practice both rounds
    // should already cover the same set; defensively walk the union
    // so we don't silently drop a stray id).
    let mut ids: std::collections::BTreeSet<&str> = by_b.keys().copied().collect();
    ids.extend(by_bal.keys().copied());

    let mut agreed: Vec<String> = Vec::new();
    let mut disagreements: Vec<FindingDiff> = Vec::new();
    let mut replay_reasons: std::collections::BTreeMap<String, Vec<ReplayReason>> =
        std::collections::BTreeMap::new();

    let mut union_reportable_ids: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();

    for fid in &ids {
        let b = by_b.get(fid);
        let bal = by_bal.get(fid);
        match (b, bal) {
            (Some(b), Some(bal)) => {
                let same_disposition = b.disposition == bal.disposition;
                let same_severity = b.severity == bal.severity;
                let same_reportable = b.reportable == bal.reportable;
                let state_sensitive_either = b.state_sensitive || bal.state_sensitive;

                if same_disposition && same_severity && same_reportable {
                    agreed.push((*fid).to_string());
                } else {
                    disagreements.push(FindingDiff {
                        finding_id: (*fid).to_string(),
                        brutalist_disposition: b.disposition,
                        balanced_disposition: bal.disposition,
                        brutalist_severity: b.severity,
                        balanced_severity: bal.severity,
                        brutalist_reportable: b.reportable,
                        balanced_reportable: bal.reportable,
                        state_sensitive_either,
                    });
                    replay_reasons
                        .entry((*fid).to_string())
                        .or_default()
                        .push(ReplayReason::RoundDisagreement);
                }

                if state_sensitive_either {
                    push_unique(
                        replay_reasons.entry((*fid).to_string()).or_default(),
                        ReplayReason::StateSensitive,
                    );
                }

                let high_or_critical_reportable = (b.reportable && is_high_or_critical(b.severity))
                    || (bal.reportable && is_high_or_critical(bal.severity));
                if high_or_critical_reportable {
                    push_unique(
                        replay_reasons.entry((*fid).to_string()).or_default(),
                        ReplayReason::AgreedHighOrCriticalReportable,
                    );
                }

                if b.confidence != crate::Confidence::High
                    || bal.confidence != crate::Confidence::High
                {
                    push_unique(
                        replay_reasons.entry((*fid).to_string()).or_default(),
                        ReplayReason::LowConfidence,
                    );
                }

                use crate::verification::ConfidenceReason::*;
                if b.confidence_reasons.contains(&AuthExpired)
                    || bal.confidence_reasons.contains(&AuthExpired)
                {
                    push_unique(
                        replay_reasons.entry((*fid).to_string()).or_default(),
                        ReplayReason::Auth,
                    );
                }
                if b.confidence_reasons.contains(&ToolingBlocked)
                    || bal.confidence_reasons.contains(&ToolingBlocked)
                {
                    push_unique(
                        replay_reasons.entry((*fid).to_string()).or_default(),
                        ReplayReason::Tooling,
                    );
                }

                if b.reportable || bal.reportable {
                    union_reportable_ids.insert((*fid).to_string());
                }
            }
            // Missing from one side: treat as disagreement, force replay.
            _ => {
                disagreements.push(FindingDiff {
                    finding_id: (*fid).to_string(),
                    brutalist_disposition: b
                        .map(|v| v.disposition)
                        .unwrap_or(VerificationDisposition::Denied),
                    balanced_disposition: bal
                        .map(|v| v.disposition)
                        .unwrap_or(VerificationDisposition::Denied),
                    brutalist_severity: b.and_then(|v| v.severity),
                    balanced_severity: bal.and_then(|v| v.severity),
                    brutalist_reportable: b.map(|v| v.reportable).unwrap_or(false),
                    balanced_reportable: bal.map(|v| v.reportable).unwrap_or(false),
                    state_sensitive_either: b.map(|v| v.state_sensitive).unwrap_or(false)
                        || bal.map(|v| v.state_sensitive).unwrap_or(false),
                });
                replay_reasons
                    .entry((*fid).to_string())
                    .or_default()
                    .push(ReplayReason::RoundDisagreement);
                if b.map(|v| v.reportable).unwrap_or(false)
                    || bal.map(|v| v.reportable).unwrap_or(false)
                {
                    union_reportable_ids.insert((*fid).to_string());
                }
            }
        }
    }

    // Small-reportable-union rule: if the union of reportable
    // findings is ≤ SMALL_REPORTABLE_THRESHOLD, replay all of them.
    if union_reportable_ids.len() <= SMALL_REPORTABLE_THRESHOLD {
        for fid in &union_reportable_ids {
            push_unique(
                replay_reasons.entry(fid.clone()).or_default(),
                ReplayReason::SmallReportableUnion,
            );
        }
    }

    // Deterministic QA sample. Pick up to QA_SAMPLE_MAX agreed-and-
    // not-already-replay-required findings, sorted by
    // blake3(attempt_id || snapshot_hash || finding_id) to randomise
    // deterministically.
    let agreed_set: std::collections::BTreeSet<&str> = agreed.iter().map(|s| s.as_str()).collect();
    let mut candidates: Vec<&str> = agreed_set
        .iter()
        .copied()
        .filter(|fid| !replay_reasons.contains_key(*fid))
        .collect();
    candidates.sort_by_key(|fid| {
        let mut h = blake3::Hasher::new();
        h.update(attempt_id.as_bytes());
        h.update(b"|");
        h.update(snapshot_hash.as_bytes());
        h.update(b"|");
        h.update(fid.as_bytes());
        *h.finalize().as_bytes()
    });
    let qa_sample: Vec<String> = candidates
        .into_iter()
        .take(QA_SAMPLE_MAX)
        .map(|s| s.to_string())
        .collect();
    for fid in &qa_sample {
        push_unique(
            replay_reasons.entry(fid.clone()).or_default(),
            ReplayReason::QaSample,
        );
    }

    let mut replay_required: Vec<ReplayRequired> = replay_reasons
        .into_iter()
        .map(|(finding_id, mut reasons)| {
            reasons.sort();
            reasons.dedup();
            ReplayRequired {
                finding_id,
                reasons,
            }
        })
        .collect();
    replay_required.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    agreed.sort();
    disagreements.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));

    // The plan hash is computed over every field deterministically.
    let plan_payload = PlanPayload {
        attempt_id: &attempt_id,
        snapshot_hash: &snapshot_hash,
        brutalist_hash: &brutalist_hash,
        balanced_hash: &balanced_hash,
        agreed: &agreed,
        disagreements: &disagreements,
        replay_required: &replay_required,
        qa_sample: &qa_sample,
    };
    let plan_hash = canonical_hash(&plan_payload);

    Ok(Adjudication {
        attempt_id,
        snapshot_hash,
        brutalist_hash,
        balanced_hash,
        plan_hash,
        agreed,
        disagreements,
        replay_required,
        qa_sample,
    })
}

/// Borrowed shadow of [`Adjudication`] used only for hashing — keeps
/// `plan_hash` out of its own input.
#[derive(Serialize)]
struct PlanPayload<'a> {
    attempt_id: &'a str,
    snapshot_hash: &'a str,
    brutalist_hash: &'a str,
    balanced_hash: &'a str,
    agreed: &'a [String],
    disagreements: &'a [FindingDiff],
    replay_required: &'a [ReplayRequired],
    qa_sample: &'a [String],
}

fn push_unique(v: &mut Vec<ReplayReason>, r: ReplayReason) {
    if !v.contains(&r) {
        v.push(r);
    }
}

fn is_high_or_critical(sev: Option<Severity>) -> bool {
    matches!(sev, Some(Severity::High) | Some(Severity::Critical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::{
        Confidence, ConfidenceReason, FindingVerdict, VerificationDisposition,
    };

    fn vfy(id: &str, d: VerificationDisposition, s: Option<Severity>, rep: bool) -> FindingVerdict {
        FindingVerdict {
            finding_id: id.into(),
            disposition: d,
            severity: s,
            reportable: rep,
            confidence: Confidence::High,
            confidence_reasons: vec![ConfidenceReason::FreshReplayPassed],
            state_sensitive: false,
            reasoning: "x".into(),
        }
    }

    #[test]
    fn snapshot_hash_is_stable_under_reordering() {
        let a = snapshot_hash(&["F-2".into(), "F-1".into(), "F-3".into()]);
        let b = snapshot_hash(&["F-1".into(), "F-2".into(), "F-3".into()]);
        assert_eq!(a, b);
    }

    #[test]
    fn snapshot_hash_changes_with_membership() {
        let a = snapshot_hash(&["F-1".into(), "F-2".into()]);
        let b = snapshot_hash(&["F-1".into(), "F-3".into()]);
        assert_ne!(a, b);
    }

    #[test]
    fn agreed_findings_go_to_agreed_or_qa_sample() {
        // Both rounds confirm one Medium-severity finding. Expected:
        // it lands in `agreed` and (since the reportable-union ≤ 5
        // threshold fires AND it's the QA sample fallback) also picks
        // up `SmallReportableUnion` + `QaSample` replay reasons.
        let f = vfy(
            "F-1",
            VerificationDisposition::Confirmed,
            Some(Severity::Medium),
            true,
        );
        let b = VerificationRoundResult::new(VerificationRound::Brutalist, vec![f.clone()]);
        let bal = VerificationRoundResult::new(VerificationRound::Balanced, vec![f]);
        let adj = build_adjudication("att-1", snapshot_hash(&["F-1".into()]), &b, &bal).unwrap();
        assert_eq!(adj.agreed, vec!["F-1".to_string()]);
        // Single agreed finding ≤ 5 reportable threshold → replay required.
        assert!(adj.requires_replay("F-1"));
    }

    #[test]
    fn disagreement_lands_in_replay_required() {
        let b_v = vfy(
            "F-1",
            VerificationDisposition::Confirmed,
            Some(Severity::High),
            true,
        );
        let bal_v = vfy("F-1", VerificationDisposition::Denied, None, false);
        let b = VerificationRoundResult::new(VerificationRound::Brutalist, vec![b_v]);
        let bal = VerificationRoundResult::new(VerificationRound::Balanced, vec![bal_v]);
        let adj = build_adjudication("att-1", snapshot_hash(&["F-1".into()]), &b, &bal).unwrap();
        assert!(adj.agreed.is_empty());
        assert_eq!(adj.disagreements.len(), 1);
        let r = &adj.replay_required[0];
        assert!(r.reasons.contains(&ReplayReason::RoundDisagreement));
    }

    #[test]
    fn high_severity_agreed_replay_required() {
        let f = vfy(
            "F-1",
            VerificationDisposition::Confirmed,
            Some(Severity::Critical),
            true,
        );
        let b = VerificationRoundResult::new(VerificationRound::Brutalist, vec![f.clone()]);
        let bal = VerificationRoundResult::new(VerificationRound::Balanced, vec![f]);
        let adj = build_adjudication("att-1", snapshot_hash(&["F-1".into()]), &b, &bal).unwrap();
        let r = &adj.replay_required[0];
        assert!(r
            .reasons
            .contains(&ReplayReason::AgreedHighOrCriticalReportable));
    }

    #[test]
    fn state_sensitive_propagates_to_replay() {
        let mut f = vfy(
            "F-1",
            VerificationDisposition::Confirmed,
            Some(Severity::High),
            true,
        );
        f.state_sensitive = true;
        let b = VerificationRoundResult::new(VerificationRound::Brutalist, vec![f.clone()]);
        let bal = VerificationRoundResult::new(VerificationRound::Balanced, vec![f]);
        let adj = build_adjudication("att-1", snapshot_hash(&["F-1".into()]), &b, &bal).unwrap();
        let r = &adj.replay_required[0];
        assert!(r.reasons.contains(&ReplayReason::StateSensitive));
    }

    #[test]
    fn plan_hash_is_deterministic() {
        let f = vfy(
            "F-1",
            VerificationDisposition::Confirmed,
            Some(Severity::High),
            true,
        );
        let b = VerificationRoundResult::new(VerificationRound::Brutalist, vec![f.clone()]);
        let bal = VerificationRoundResult::new(VerificationRound::Balanced, vec![f]);
        let a1 = build_adjudication("att-1", "snap-1", &b, &bal).unwrap();
        let a2 = build_adjudication("att-1", "snap-1", &b, &bal).unwrap();
        assert_eq!(a1.plan_hash, a2.plan_hash);
    }

    #[test]
    fn plan_hash_changes_when_inputs_change() {
        let f = vfy(
            "F-1",
            VerificationDisposition::Confirmed,
            Some(Severity::High),
            true,
        );
        let b = VerificationRoundResult::new(VerificationRound::Brutalist, vec![f.clone()]);
        let bal_same = VerificationRoundResult::new(VerificationRound::Balanced, vec![f.clone()]);
        let bal_changed = VerificationRoundResult::new(
            VerificationRound::Balanced,
            vec![vfy("F-1", VerificationDisposition::Denied, None, false)],
        );
        let a1 = build_adjudication("att-1", "snap-1", &b, &bal_same).unwrap();
        let a2 = build_adjudication("att-1", "snap-1", &b, &bal_changed).unwrap();
        assert_ne!(a1.plan_hash, a2.plan_hash);
    }

    #[test]
    fn qa_sample_is_deterministic_and_bounded() {
        // 12 agreed-Medium findings; small-reportable-union does NOT
        // fire (12 > 5); QA sample picks ≤10 deterministically.
        let mut results = Vec::new();
        let mut ids = Vec::new();
        for i in 0..12 {
            let id = format!("F-{i}");
            ids.push(id.clone());
            results.push(vfy(
                &id,
                VerificationDisposition::Confirmed,
                Some(Severity::Medium),
                true,
            ));
        }
        let b = VerificationRoundResult::new(VerificationRound::Brutalist, results.clone());
        let bal = VerificationRoundResult::new(VerificationRound::Balanced, results);
        let snap = snapshot_hash(&ids);
        let a1 = build_adjudication("att-1", snap.clone(), &b, &bal).unwrap();
        let a2 = build_adjudication("att-1", snap, &b, &bal).unwrap();
        assert_eq!(a1.qa_sample, a2.qa_sample);
        // With 12 reportable, union > threshold, so QA picks 10 max.
        // But these are also reportable, so AgreedHighOrCriticalReportable doesn't fire (Medium).
        // The qa_sample list is bounded by QA_SAMPLE_MAX = 10.
        assert!(a1.qa_sample.len() <= QA_SAMPLE_MAX);
    }

    #[test]
    fn missing_from_balanced_forces_replay() {
        let b_v = vfy(
            "F-1",
            VerificationDisposition::Confirmed,
            Some(Severity::High),
            true,
        );
        let b = VerificationRoundResult::new(VerificationRound::Brutalist, vec![b_v]);
        let bal = VerificationRoundResult::new(VerificationRound::Balanced, vec![]);
        let adj = build_adjudication("att-1", snapshot_hash(&["F-1".into()]), &b, &bal).unwrap();
        assert!(adj.requires_replay("F-1"));
    }
}
