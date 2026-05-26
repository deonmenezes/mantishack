//! Compare Mantis findings against external scanner baselines.
//!
//! Bullet from Priority 4: *"Public benchmark suite vs. Nuclei, ZAP, Nessus."*
//!
//! For each testbed in [`crate::testbeds`], Mantis runs alongside a baseline
//! scanner. This module models the comparison shape: each tool produces a set
//! of finding identifiers; we compute precision, recall, and F1 against a
//! known ground-truth set, plus per-pair set differences for human review.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// External baseline scanners Mantis benchmarks against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselineScanner {
    /// ProjectDiscovery Nuclei.
    Nuclei,
    /// OWASP ZAP.
    Zap,
    /// Tenable Nessus.
    Nessus,
}

impl BaselineScanner {
    /// Display name (`"Nuclei"`, `"ZAP"`, `"Nessus"`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Nuclei => "Nuclei",
            Self::Zap => "ZAP",
            Self::Nessus => "Nessus",
        }
    }

    /// All baseline scanners in stable order.
    pub const fn all() -> [BaselineScanner; 3] {
        [Self::Nuclei, Self::Zap, Self::Nessus]
    }
}

/// Set of finding identifiers (e.g. `vuln_class` strings or CWE IDs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingSet {
    /// Finding identifiers reported by the scanner.
    pub items: Vec<String>,
}

impl FindingSet {
    /// Construct from any iterable of string-likes.
    pub fn from_iter<I, S>(it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            items: it.into_iter().map(Into::into).collect(),
        }
    }

    fn as_set(&self) -> HashSet<&str> {
        self.items.iter().map(String::as_str).collect()
    }
}

/// Precision / recall / F1 vs a ground-truth set.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ConfusionStats {
    /// True positives.
    pub tp: usize,
    /// False positives.
    pub fp: usize,
    /// False negatives.
    pub fn_: usize,
    /// Precision: tp / (tp + fp). Zero when tp + fp = 0.
    pub precision: f64,
    /// Recall: tp / (tp + fn). Zero when tp + fn = 0.
    pub recall: f64,
    /// F1: harmonic mean of precision and recall.
    pub f1: f64,
}

impl ConfusionStats {
    /// Compute confusion stats for a scanner's findings against ground truth.
    pub fn compute(scanner: &FindingSet, ground_truth: &FindingSet) -> Self {
        let scanner_set = scanner.as_set();
        let truth_set = ground_truth.as_set();

        let tp = scanner_set.intersection(&truth_set).count();
        let fp = scanner_set.difference(&truth_set).count();
        let fn_ = truth_set.difference(&scanner_set).count();

        let precision = if tp + fp == 0 {
            0.0
        } else {
            tp as f64 / (tp + fp) as f64
        };
        let recall = if tp + fn_ == 0 {
            0.0
        } else {
            tp as f64 / (tp + fn_) as f64
        };
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };

        Self {
            tp,
            fp,
            fn_,
            precision,
            recall,
            f1,
        }
    }
}

/// One row in the benchmark report: how Mantis vs. baseline performed on one
/// testbed, with set-difference detail for human review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkRow {
    /// Testbed id (matches `mantis_bench::testbeds::Testbed::id`).
    pub testbed_id: String,
    /// Which baseline this row compares Mantis against.
    pub baseline: BaselineScanner,
    /// Stats for Mantis vs ground truth.
    pub mantis_stats: ConfusionStats,
    /// Stats for the baseline vs ground truth.
    pub baseline_stats: ConfusionStats,
    /// Findings Mantis found that the baseline missed.
    pub mantis_only: Vec<String>,
    /// Findings the baseline found that Mantis missed.
    pub baseline_only: Vec<String>,
}

impl BenchmarkRow {
    /// Build a comparison row from raw finding sets.
    pub fn new(
        testbed_id: impl Into<String>,
        baseline: BaselineScanner,
        mantis: &FindingSet,
        baseline_findings: &FindingSet,
        ground_truth: &FindingSet,
    ) -> Self {
        let mantis_set = mantis.as_set();
        let baseline_set = baseline_findings.as_set();
        let mantis_only: Vec<String> = mantis_set
            .difference(&baseline_set)
            .map(|s| (*s).to_string())
            .collect();
        let baseline_only: Vec<String> = baseline_set
            .difference(&mantis_set)
            .map(|s| (*s).to_string())
            .collect();

        Self {
            testbed_id: testbed_id.into(),
            baseline,
            mantis_stats: ConfusionStats::compute(mantis, ground_truth),
            baseline_stats: ConfusionStats::compute(baseline_findings, ground_truth),
            mantis_only,
            baseline_only,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_names_are_canonical() {
        assert_eq!(BaselineScanner::Nuclei.name(), "Nuclei");
        assert_eq!(BaselineScanner::Zap.name(), "ZAP");
        assert_eq!(BaselineScanner::Nessus.name(), "Nessus");
    }

    #[test]
    fn finding_set_from_iter_collects() {
        let s = FindingSet::from_iter(["sqli", "xss", "ssrf"]);
        assert_eq!(s.items.len(), 3);
    }

    #[test]
    fn confusion_stats_perfect_classifier() {
        let mantis = FindingSet::from_iter(["sqli", "xss"]);
        let truth = FindingSet::from_iter(["sqli", "xss"]);
        let stats = ConfusionStats::compute(&mantis, &truth);
        assert_eq!(stats.tp, 2);
        assert_eq!(stats.fp, 0);
        assert_eq!(stats.fn_, 0);
        assert!((stats.precision - 1.0).abs() < 1e-9);
        assert!((stats.recall - 1.0).abs() < 1e-9);
        assert!((stats.f1 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn confusion_stats_partial_match() {
        let mantis = FindingSet::from_iter(["sqli", "xss", "ssrf"]);
        let truth = FindingSet::from_iter(["sqli", "xss", "csrf"]);
        let stats = ConfusionStats::compute(&mantis, &truth);
        assert_eq!(stats.tp, 2);
        assert_eq!(stats.fp, 1);
        assert_eq!(stats.fn_, 1);
        // precision = 2/3, recall = 2/3, f1 = 2/3
        assert!((stats.precision - 2.0 / 3.0).abs() < 1e-9);
        assert!((stats.recall - 2.0 / 3.0).abs() < 1e-9);
        assert!((stats.f1 - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn confusion_stats_no_findings_gives_zero_precision_zero_recall() {
        let empty = FindingSet::default();
        let truth = FindingSet::from_iter(["sqli"]);
        let stats = ConfusionStats::compute(&empty, &truth);
        assert_eq!(stats.tp, 0);
        assert_eq!(stats.fp, 0);
        assert_eq!(stats.fn_, 1);
        assert_eq!(stats.precision, 0.0);
        assert_eq!(stats.recall, 0.0);
        assert_eq!(stats.f1, 0.0);
    }

    #[test]
    fn confusion_stats_all_false_positives() {
        let mantis = FindingSet::from_iter(["xss"]);
        let truth = FindingSet::from_iter(["sqli"]);
        let stats = ConfusionStats::compute(&mantis, &truth);
        assert_eq!(stats.tp, 0);
        assert_eq!(stats.fp, 1);
        assert_eq!(stats.fn_, 1);
        assert_eq!(stats.precision, 0.0);
        assert_eq!(stats.recall, 0.0);
        assert_eq!(stats.f1, 0.0);
    }

    #[test]
    fn benchmark_row_captures_mantis_only_findings() {
        let mantis = FindingSet::from_iter(["sqli", "xss", "ssrf"]);
        let baseline = FindingSet::from_iter(["sqli", "xss"]);
        let truth = FindingSet::from_iter(["sqli", "xss", "ssrf"]);
        let row = BenchmarkRow::new("dvwa", BaselineScanner::Nuclei, &mantis, &baseline, &truth);
        assert_eq!(row.mantis_only, vec!["ssrf".to_string()]);
        assert!(row.baseline_only.is_empty());
    }

    #[test]
    fn benchmark_row_captures_baseline_only_findings() {
        let mantis = FindingSet::from_iter(["sqli"]);
        let baseline = FindingSet::from_iter(["sqli", "xss"]);
        let truth = FindingSet::from_iter(["sqli", "xss"]);
        let row = BenchmarkRow::new("dvwa", BaselineScanner::Zap, &mantis, &baseline, &truth);
        assert_eq!(row.baseline_only, vec!["xss".to_string()]);
        assert!(row.mantis_only.is_empty());
    }

    #[test]
    fn benchmark_row_serializes() {
        let mantis = FindingSet::from_iter(["sqli"]);
        let baseline = FindingSet::from_iter(["sqli"]);
        let truth = FindingSet::from_iter(["sqli"]);
        let row = BenchmarkRow::new("dvwa", BaselineScanner::Nuclei, &mantis, &baseline, &truth);
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"testbed_id\":\"dvwa\""));
        assert!(json.contains("\"baseline\":\"nuclei\""));
    }
}
