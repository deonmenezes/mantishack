//! Reproducibility tests for the evidence chain.
//!
//! Mantis's central product invariant is that every claim is reproducible —
//! the same scope and target produce the same evidence chain on re-execution.
//! This module gives us the structured comparison so CI can detect drift.
//!
//! Given two benchmark runs (typically the same suite executed twice or once
//! against an old binary and once against a candidate binary),
//! [`compare_runs`] returns a [`ReproducibilityReport`] that classifies each
//! benchmark as one of:
//!
//! - [`Match`] — identical status + identical `flag_found` outcome.
//! - [`StatusDrift`] — status changed (e.g. `Solved` → `NoFlag`).
//! - [`FlagDrift`] — same status but the captured flag differs.
//! - [`OnlyInLeft`] / [`OnlyInRight`] — benchmark present in only one run.
//!
//! Run-level metrics ([`ReproducibilityReport::reproducibility_rate`]) make
//! it easy to gate CI on a minimum match rate.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::result::{BenchmarkResult, Status};

/// Per-benchmark verdict comparing two runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Divergence {
    /// Both runs produced the same status and `flag_found` outcome.
    Match,
    /// Status enum differs.
    StatusDrift {
        /// Status from the left/baseline run.
        left: String,
        /// Status from the right/candidate run.
        right: String,
    },
    /// Same status but different captured-flag outcome.
    FlagDrift {
        /// Whether the left run captured a flag.
        left_flag: bool,
        /// Whether the right run captured a flag.
        right_flag: bool,
    },
    /// Benchmark exists only in the left/baseline run.
    OnlyInLeft,
    /// Benchmark exists only in the right/candidate run.
    OnlyInRight,
}

impl Divergence {
    /// Whether this verdict counts as reproducible (only `Match` does).
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }
}

/// Per-benchmark verdict line in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceEntry {
    /// Benchmark identifier (matches `BenchmarkResult::benchmark`).
    pub benchmark: String,
    /// Per-benchmark verdict.
    pub divergence: Divergence,
}

/// Aggregate reproducibility report comparing two runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityReport {
    /// Per-benchmark entries, sorted by benchmark id.
    pub entries: Vec<DivergenceEntry>,
    /// Number of benchmarks that matched exactly.
    pub matched: usize,
    /// Number of benchmarks with any divergence (status, flag, or set-membership).
    pub diverged: usize,
}

impl ReproducibilityReport {
    /// Reproducibility rate in [0.0, 1.0]: matched / (matched + diverged).
    /// Returns 1.0 when both runs are empty (vacuously reproducible).
    pub fn reproducibility_rate(&self) -> f64 {
        let total = self.matched + self.diverged;
        if total == 0 {
            1.0
        } else {
            self.matched as f64 / total as f64
        }
    }

    /// Whether the run is fully reproducible (no divergences at all).
    pub fn is_fully_reproducible(&self) -> bool {
        self.diverged == 0
    }
}

/// Compare two sequences of benchmark results.
///
/// The benchmark identifier (`BenchmarkResult::benchmark`) is the join key.
/// Each benchmark contributes exactly one entry to the report.
pub fn compare_runs(left: &[BenchmarkResult], right: &[BenchmarkResult]) -> ReproducibilityReport {
    let left_by_id: HashMap<&str, &BenchmarkResult> =
        left.iter().map(|r| (r.benchmark.as_str(), r)).collect();
    let right_by_id: HashMap<&str, &BenchmarkResult> =
        right.iter().map(|r| (r.benchmark.as_str(), r)).collect();

    // BTreeMap so report entries are stable-sorted by benchmark id.
    let mut entries: BTreeMap<&str, Divergence> = BTreeMap::new();

    for (id, l) in &left_by_id {
        match right_by_id.get(id) {
            Some(r) => {
                entries.insert(*id, classify(l, r));
            }
            None => {
                entries.insert(*id, Divergence::OnlyInLeft);
            }
        }
    }
    for id in right_by_id.keys() {
        if !left_by_id.contains_key(id) {
            entries.insert(*id, Divergence::OnlyInRight);
        }
    }

    let mut matched = 0;
    let mut diverged = 0;
    let entries: Vec<DivergenceEntry> = entries
        .into_iter()
        .map(|(id, divergence)| {
            if divergence.is_match() {
                matched += 1;
            } else {
                diverged += 1;
            }
            DivergenceEntry {
                benchmark: id.to_string(),
                divergence,
            }
        })
        .collect();

    ReproducibilityReport {
        entries,
        matched,
        diverged,
    }
}

fn classify(left: &BenchmarkResult, right: &BenchmarkResult) -> Divergence {
    let l_status = left.status_enum();
    let r_status = right.status_enum();
    if l_status != r_status {
        return Divergence::StatusDrift {
            left: status_label(l_status, &left.status).to_string(),
            right: status_label(r_status, &right.status).to_string(),
        };
    }
    if left.flag_found != right.flag_found {
        return Divergence::FlagDrift {
            left_flag: left.flag_found,
            right_flag: right.flag_found,
        };
    }
    Divergence::Match
}

fn status_label(parsed: Status, raw: &str) -> &str {
    // Use the parsed enum's canonical label, falling back to the raw string for
    // `Status::Other` so reports preserve the original tag.
    if parsed == Status::Other {
        raw
    } else {
        parsed.label()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(benchmark: &str, status: &str, flag_found: bool) -> BenchmarkResult {
        BenchmarkResult {
            benchmark: benchmark.into(),
            level: String::new(),
            tags: vec![],
            expected_flag: String::new(),
            target_url: String::new(),
            status: status.into(),
            flag_found,
            duration_sec: 0,
            notes: String::new(),
        }
    }

    #[test]
    fn empty_runs_are_vacuously_reproducible() {
        let report = compare_runs(&[], &[]);
        assert_eq!(report.matched, 0);
        assert_eq!(report.diverged, 0);
        assert!(report.is_fully_reproducible());
        assert!((report.reproducibility_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn identical_runs_match_exactly() {
        let r = vec![
            result("XBEN-001", "solved", true),
            result("XBEN-002", "no_flag", false),
        ];
        let report = compare_runs(&r, &r);
        assert_eq!(report.matched, 2);
        assert_eq!(report.diverged, 0);
        assert!(report.is_fully_reproducible());
    }

    #[test]
    fn status_drift_detected() {
        let left = vec![result("XBEN-001", "solved", true)];
        let right = vec![result("XBEN-001", "no_flag", false)];
        let report = compare_runs(&left, &right);
        assert_eq!(report.entries.len(), 1);
        match &report.entries[0].divergence {
            Divergence::StatusDrift { left, right } => {
                assert_eq!(left, "solved");
                assert_eq!(right, "no_flag");
            }
            other => panic!("expected StatusDrift, got {other:?}"),
        }
        assert_eq!(report.diverged, 1);
    }

    #[test]
    fn flag_drift_detected_when_status_unchanged() {
        let left = vec![result("XBEN-001", "solved", true)];
        let right = vec![result("XBEN-001", "solved", false)];
        let report = compare_runs(&left, &right);
        match &report.entries[0].divergence {
            Divergence::FlagDrift {
                left_flag,
                right_flag,
            } => {
                assert!(left_flag);
                assert!(!right_flag);
            }
            other => panic!("expected FlagDrift, got {other:?}"),
        }
    }

    #[test]
    fn only_in_left_when_benchmark_missing_from_right() {
        let left = vec![result("XBEN-001", "solved", true)];
        let report = compare_runs(&left, &[]);
        assert_eq!(report.entries[0].divergence, Divergence::OnlyInLeft);
    }

    #[test]
    fn only_in_right_when_benchmark_missing_from_left() {
        let right = vec![result("XBEN-002", "solved", true)];
        let report = compare_runs(&[], &right);
        assert_eq!(report.entries[0].divergence, Divergence::OnlyInRight);
    }

    #[test]
    fn reproducibility_rate_computed_correctly() {
        let left = vec![
            result("a", "solved", true),
            result("b", "solved", true),
            result("c", "solved", true),
            result("d", "solved", true),
        ];
        let right = vec![
            result("a", "solved", true), // match
            result("b", "no_flag", false), // status drift
            result("c", "solved", true), // match
            result("d", "solved", false), // flag drift
        ];
        let report = compare_runs(&left, &right);
        assert_eq!(report.matched, 2);
        assert_eq!(report.diverged, 2);
        assert!((report.reproducibility_rate() - 0.5).abs() < 1e-9);
        assert!(!report.is_fully_reproducible());
    }

    #[test]
    fn entries_sorted_by_benchmark_id() {
        let left = vec![
            result("zeta", "solved", true),
            result("alpha", "solved", true),
            result("mu", "solved", true),
        ];
        let report = compare_runs(&left, &left);
        let ids: Vec<&str> = report.entries.iter().map(|e| e.benchmark.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "mu", "zeta"]);
    }

    #[test]
    fn unknown_status_strings_preserved_through_drift() {
        let left = vec![result("XBEN-001", "weird_status", false)];
        let right = vec![result("XBEN-001", "solved", true)];
        let report = compare_runs(&left, &right);
        match &report.entries[0].divergence {
            Divergence::StatusDrift { left, .. } => {
                // Status::Other → preserve raw string for the report.
                assert_eq!(left, "weird_status");
            }
            other => panic!("expected StatusDrift, got {other:?}"),
        }
    }
}
