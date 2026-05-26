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
//! Evidence packs.
//!
//! Mirrors hacker-bob's `evidence.js`: bounded per-finding artifacts
//! that the grader and report-writer consume. Every reportable
//! finding from the final round must have a corresponding pack
//! before VERIFY→GRADE opens. The bounds prevent hunters from
//! dumping unbounded raw HTTP into the report and force them to
//! summarise.
//!
//! Bounds (hard caps; mirror hacker-bob's constants):
//! - `MAX_SAMPLE_COUNT = 1000` total observations
//! - `MAX_REPRESENTATIVE_SAMPLES = 10` rendered samples
//! - `MAX_SENSITIVE_CLUSTERS = 20`
//! - `MAX_TEXT_CHARS = 4000` per text field
//! - `MAX_REPLAY_SUMMARY_CHARS = 2000`
//! - `MAX_REDACTION_NOTES_CHARS = 1000`

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_SAMPLE_COUNT: u32 = 1000;
pub const MAX_REPRESENTATIVE_SAMPLES: usize = 10;
pub const MAX_SENSITIVE_CLUSTERS: usize = 20;
pub const MAX_TEXT_CHARS: usize = 4000;
pub const MAX_REPLAY_SUMMARY_CHARS: usize = 2000;
pub const MAX_REDACTION_NOTES_CHARS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSample {
    /// Sample-type label tying back to the capability pack
    /// (`http_replay`, `evm_foundry_run`, …).
    pub sample_type: String,
    /// Bounded JSON or text payload (≤ MAX_TEXT_CHARS).
    pub payload: String,
    /// Short identifier (`req-1`, `step-3`) operators can cite.
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePack {
    pub finding_id: String,
    /// Total observations behind the report (e.g. number of distinct
    /// IDs found, number of replay attempts). Must be ≥ the number
    /// of representative_samples.
    pub sample_count: u32,
    /// Compact aggregate breakdown (bucket → count). For "per-status
    /// breakdown across 1000 probes" the map is `{200: 980, 403: 12, 500: 8}`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregate_counts: Vec<(String, u32)>,
    /// At most [`MAX_REPRESENTATIVE_SAMPLES`] redacted samples.
    pub representative_samples: Vec<EvidenceSample>,
    /// Cluster summaries for sensitive material — kept short so
    /// triagers see the shape without exposing raw secrets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_clusters: Vec<String>,
    /// Short replay narrative (≤ MAX_REPLAY_SUMMARY_CHARS).
    pub replay_summary: String,
    /// Redaction methodology (≤ MAX_REDACTION_NOTES_CHARS).
    pub redaction_notes: String,
    /// Inline snippet for the report (≤ MAX_TEXT_CHARS).
    pub report_snippet: String,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("sample_count {actual} exceeds max {MAX_SAMPLE_COUNT}")]
    SampleCountTooHigh { actual: u32 },
    #[error("representative_samples length {actual} exceeds max {MAX_REPRESENTATIVE_SAMPLES}")]
    TooManyRepresentativeSamples { actual: usize },
    #[error("sensitive_clusters length {actual} exceeds max {MAX_SENSITIVE_CLUSTERS}")]
    TooManySensitiveClusters { actual: usize },
    #[error("sample_count {sample_count} < representative_samples length {samples}")]
    SampleCountInconsistent { sample_count: u32, samples: usize },
    #[error("{field} length {actual} exceeds max {max}")]
    TextTooLong {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("finding_id is empty")]
    EmptyFindingId,
    #[error("duplicate evidence pack for finding {0}")]
    Duplicate(String),
    #[error("evidence pack missing for reportable findings: {0:?}")]
    MissingForReportable(Vec<String>),
    #[error("evidence pack present for non-reportable finding {0}")]
    OrphanPack(String),
}

impl EvidencePack {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.finding_id.trim().is_empty() {
            return Err(EvidenceError::EmptyFindingId);
        }
        if self.sample_count > MAX_SAMPLE_COUNT {
            return Err(EvidenceError::SampleCountTooHigh {
                actual: self.sample_count,
            });
        }
        if self.representative_samples.len() > MAX_REPRESENTATIVE_SAMPLES {
            return Err(EvidenceError::TooManyRepresentativeSamples {
                actual: self.representative_samples.len(),
            });
        }
        if self.sensitive_clusters.len() > MAX_SENSITIVE_CLUSTERS {
            return Err(EvidenceError::TooManySensitiveClusters {
                actual: self.sensitive_clusters.len(),
            });
        }
        if (self.sample_count as usize) < self.representative_samples.len() {
            return Err(EvidenceError::SampleCountInconsistent {
                sample_count: self.sample_count,
                samples: self.representative_samples.len(),
            });
        }
        // chars().count() walks the whole string; the prior code walked
        // it once for the comparison + AGAIN for the `actual` field in
        // the error, doubling work on the failing path. Cache the count.
        for sample in &self.representative_samples {
            let count = sample.payload.chars().count();
            if count > MAX_TEXT_CHARS {
                return Err(EvidenceError::TextTooLong {
                    field: "representative_samples[].payload",
                    actual: count,
                    max: MAX_TEXT_CHARS,
                });
            }
        }
        let replay_count = self.replay_summary.chars().count();
        if replay_count > MAX_REPLAY_SUMMARY_CHARS {
            return Err(EvidenceError::TextTooLong {
                field: "replay_summary",
                actual: replay_count,
                max: MAX_REPLAY_SUMMARY_CHARS,
            });
        }
        let redaction_count = self.redaction_notes.chars().count();
        if redaction_count > MAX_REDACTION_NOTES_CHARS {
            return Err(EvidenceError::TextTooLong {
                field: "redaction_notes",
                actual: redaction_count,
                max: MAX_REDACTION_NOTES_CHARS,
            });
        }
        let snippet_count = self.report_snippet.chars().count();
        if snippet_count > MAX_TEXT_CHARS {
            return Err(EvidenceError::TextTooLong {
                field: "report_snippet",
                actual: snippet_count,
                max: MAX_TEXT_CHARS,
            });
        }
        Ok(())
    }
}

/// Validate that every reportable finding has a pack and nothing
/// else. Mirrors hacker-bob's
/// `requireValidEvidencePacksForFinalReportableFindings`.
pub fn validate_pack_coverage(
    reportable_finding_ids: &[String],
    packs: &[EvidencePack],
) -> Result<(), EvidenceError> {
    use std::collections::BTreeSet;
    let reportable_set: BTreeSet<&str> =
        reportable_finding_ids.iter().map(|s| s.as_str()).collect();
    let mut pack_ids: BTreeSet<&str> = BTreeSet::new();
    for pack in packs {
        pack.validate()?;
        if !pack_ids.insert(pack.finding_id.as_str()) {
            return Err(EvidenceError::Duplicate(pack.finding_id.clone()));
        }
        if !reportable_set.contains(pack.finding_id.as_str()) {
            return Err(EvidenceError::OrphanPack(pack.finding_id.clone()));
        }
    }
    let missing: Vec<String> = reportable_set
        .iter()
        .filter(|id| !pack_ids.contains(*id))
        .map(|id| (*id).to_string())
        .collect();
    if !missing.is_empty() {
        return Err(EvidenceError::MissingForReportable(missing));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(label: &str) -> EvidenceSample {
        EvidenceSample {
            sample_type: "http_replay".into(),
            payload: format!("payload-{label}"),
            label: label.into(),
        }
    }

    fn good_pack(fid: &str) -> EvidencePack {
        EvidencePack {
            finding_id: fid.into(),
            sample_count: 5,
            aggregate_counts: vec![("200".into(), 4), ("403".into(), 1)],
            representative_samples: vec![sample("s-1")],
            sensitive_clusters: Vec::new(),
            replay_summary: "ran 5 times; consistent 200 with PII".into(),
            redaction_notes: "names hashed".into(),
            report_snippet: "An attacker reads victim PII via /users?id=...".into(),
        }
    }

    #[test]
    fn good_pack_validates() {
        good_pack("F-1").validate().unwrap();
    }

    #[test]
    fn empty_finding_id_rejected() {
        let mut p = good_pack("F-1");
        p.finding_id = "".into();
        assert!(matches!(p.validate(), Err(EvidenceError::EmptyFindingId)));
    }

    #[test]
    fn sample_count_inconsistent_rejected() {
        let mut p = good_pack("F-1");
        p.sample_count = 0;
        p.representative_samples = vec![sample("s-1")];
        assert!(matches!(
            p.validate(),
            Err(EvidenceError::SampleCountInconsistent { .. })
        ));
    }

    #[test]
    fn too_many_representative_samples_rejected() {
        let mut p = good_pack("F-1");
        p.sample_count = 1000;
        p.representative_samples = (0..11).map(|i| sample(&i.to_string())).collect();
        assert!(matches!(
            p.validate(),
            Err(EvidenceError::TooManyRepresentativeSamples { .. })
        ));
    }

    #[test]
    fn payload_over_max_chars_rejected() {
        let mut p = good_pack("F-1");
        let big = "x".repeat(MAX_TEXT_CHARS + 1);
        p.representative_samples[0].payload = big;
        assert!(matches!(
            p.validate(),
            Err(EvidenceError::TextTooLong {
                field: "representative_samples[].payload",
                ..
            })
        ));
    }

    #[test]
    fn replay_summary_over_max_rejected() {
        let mut p = good_pack("F-1");
        p.replay_summary = "x".repeat(MAX_REPLAY_SUMMARY_CHARS + 1);
        assert!(matches!(
            p.validate(),
            Err(EvidenceError::TextTooLong {
                field: "replay_summary",
                ..
            })
        ));
    }

    #[test]
    fn validate_coverage_empty_passes() {
        validate_pack_coverage(&[], &[]).unwrap();
    }

    #[test]
    fn validate_coverage_missing_pack_for_reportable_fails() {
        let err =
            validate_pack_coverage(&["F-1".into(), "F-2".into()], &[good_pack("F-1")]).unwrap_err();
        if let EvidenceError::MissingForReportable(missing) = err {
            assert_eq!(missing, vec!["F-2".to_string()]);
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    #[test]
    fn validate_coverage_orphan_pack_fails() {
        let err = validate_pack_coverage(&["F-1".into()], &[good_pack("F-2")]).unwrap_err();
        assert!(matches!(err, EvidenceError::OrphanPack(s) if s == "F-2"));
    }

    #[test]
    fn validate_coverage_duplicate_pack_fails() {
        let err = validate_pack_coverage(&["F-1".into()], &[good_pack("F-1"), good_pack("F-1")])
            .unwrap_err();
        assert!(matches!(err, EvidenceError::Duplicate(s) if s == "F-1"));
    }

    #[test]
    fn validate_coverage_happy_path() {
        validate_pack_coverage(
            &["F-1".into(), "F-2".into()],
            &[good_pack("F-1"), good_pack("F-2")],
        )
        .unwrap();
    }

    #[test]
    fn json_round_trip() {
        let p = good_pack("F-1");
        let j = serde_json::to_string(&p).unwrap();
        let back: EvidencePack = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
