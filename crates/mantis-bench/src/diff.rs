//! Compare two benchmark snapshots. Highlights every benchmark
//! whose status changed between baseline and candidate — used to
//! prove (or disprove) that a Mantis change moved the needle on
//! the scoreboard.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::result::{BenchmarkResult, Status};
use crate::scoreboard::Scoreboard;

/// One per benchmark id that exists in either snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffRow {
    pub benchmark: String,
    pub baseline_status: Option<String>,
    pub candidate_status: Option<String>,
    /// Positive = improvement (e.g. no_flag → solved). Negative =
    /// regression (e.g. solved → no_flag). `0` = no change.
    pub direction: i8,
}

impl DiffRow {
    pub fn label(&self) -> &'static str {
        match (self.baseline_status.as_deref(), self.candidate_status.as_deref()) {
            (None, Some(_)) => "added",
            (Some(_), None) => "removed",
            (Some(a), Some(b)) if a == b => "unchanged",
            (Some("solved"), Some(_)) => "regressed",
            (Some(_), Some("solved")) => "improved",
            (Some(_), Some(_)) => "shifted",
            (None, None) => "ghost",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDiff {
    pub baseline_solved: usize,
    pub baseline_total: usize,
    pub candidate_solved: usize,
    pub candidate_total: usize,
    /// Solve-count delta (candidate − baseline). Positive = better.
    pub solve_delta: i64,
    pub improved: Vec<DiffRow>,
    pub regressed: Vec<DiffRow>,
    pub unchanged: usize,
}

impl RunDiff {
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Mantis benchmark diff\n\n");
        let _ = writeln!(
            s,
            "**Baseline:** {} / {} solved · **Candidate:** {} / {} solved · **Δ: {:+}**\n",
            self.baseline_solved,
            self.baseline_total,
            self.candidate_solved,
            self.candidate_total,
            self.solve_delta
        );

        if !self.improved.is_empty() {
            let _ = writeln!(s, "## Improvements ({})\n", self.improved.len());
            s.push_str("| benchmark | before | after |\n|---|---|---|\n");
            for r in &self.improved {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} |",
                    r.benchmark,
                    r.baseline_status.as_deref().unwrap_or("(missing)"),
                    r.candidate_status.as_deref().unwrap_or("(missing)")
                );
            }
            s.push('\n');
        }

        if !self.regressed.is_empty() {
            let _ = writeln!(s, "## Regressions ({}) ⚠️\n", self.regressed.len());
            s.push_str("| benchmark | before | after |\n|---|---|---|\n");
            for r in &self.regressed {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} |",
                    r.benchmark,
                    r.baseline_status.as_deref().unwrap_or("(missing)"),
                    r.candidate_status.as_deref().unwrap_or("(missing)")
                );
            }
            s.push('\n');
        }

        let _ = writeln!(s, "**Unchanged:** {}", self.unchanged);
        s
    }
}

pub fn diff_runs(baseline: &[BenchmarkResult], candidate: &[BenchmarkResult]) -> RunDiff {
    let base_by_id: HashMap<&str, &BenchmarkResult> =
        baseline.iter().map(|r| (r.benchmark.as_str(), r)).collect();
    let cand_by_id: HashMap<&str, &BenchmarkResult> =
        candidate.iter().map(|r| (r.benchmark.as_str(), r)).collect();

    let mut all_ids: Vec<&str> = base_by_id
        .keys()
        .chain(cand_by_id.keys())
        .copied()
        .collect();
    all_ids.sort();
    all_ids.dedup();

    let mut improved = Vec::new();
    let mut regressed = Vec::new();
    let mut unchanged = 0usize;

    for id in all_ids {
        let b = base_by_id.get(id);
        let c = cand_by_id.get(id);
        let row = DiffRow {
            benchmark: id.to_string(),
            baseline_status: b.map(|r| r.status.clone()),
            candidate_status: c.map(|r| r.status.clone()),
            direction: classify_direction(
                b.map(|r| r.status_enum()),
                c.map(|r| r.status_enum()),
            ),
        };
        if row.direction > 0 {
            improved.push(row);
        } else if row.direction < 0 {
            regressed.push(row);
        } else {
            unchanged += 1;
        }
    }

    let baseline_solved = baseline.iter().filter(|r| r.status == "solved").count();
    let candidate_solved = candidate.iter().filter(|r| r.status == "solved").count();

    RunDiff {
        baseline_solved,
        baseline_total: baseline.len(),
        candidate_solved,
        candidate_total: candidate.len(),
        solve_delta: candidate_solved as i64 - baseline_solved as i64,
        improved,
        regressed,
        unchanged,
    }
}

/// Map a (baseline_status, candidate_status) pair to a directional
/// integer: positive = improvement, negative = regression, zero =
/// no change. Used to bucket DiffRows.
fn classify_direction(b: Option<Status>, c: Option<Status>) -> i8 {
    match (b, c) {
        (None, Some(Status::Solved)) => 1,
        (None, _) => 0, // newly attempted, not yet solved — neutral
        (Some(Status::Solved), Some(Status::Solved)) => 0,
        (Some(_), Some(Status::Solved)) => 1,
        (Some(Status::Solved), Some(_)) => -1,
        (Some(a), Some(b)) if a == b => 0,
        (Some(_), Some(_)) => 0,
        (Some(_), None) => -1, // candidate dropped a benchmark
    }
}

/// Convenience: take two result vectors and return both the per-
/// run scoreboards alongside the diff. Useful for one-shot CLI
/// output.
pub fn diff_with_scoreboards(
    baseline: &[BenchmarkResult],
    candidate: &[BenchmarkResult],
) -> (Scoreboard, Scoreboard, RunDiff) {
    (
        Scoreboard::from_results(baseline),
        Scoreboard::from_results(candidate),
        diff_runs(baseline, candidate),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn br(id: &str, status: &str) -> BenchmarkResult {
        BenchmarkResult {
            benchmark: id.into(),
            level: "1".into(),
            tags: vec![],
            expected_flag: "".into(),
            target_url: "".into(),
            status: status.into(),
            flag_found: status == "solved",
            duration_sec: 100,
            notes: "".into(),
        }
    }

    #[test]
    fn improvement_flagged_when_no_flag_becomes_solved() {
        let baseline = vec![br("a", "no_flag"), br("b", "solved")];
        let candidate = vec![br("a", "solved"), br("b", "solved")];
        let d = diff_runs(&baseline, &candidate);
        assert_eq!(d.improved.len(), 1);
        assert_eq!(d.regressed.len(), 0);
        assert_eq!(d.improved[0].benchmark, "a");
        assert_eq!(d.solve_delta, 1);
    }

    #[test]
    fn regression_flagged_when_solved_becomes_no_flag() {
        let baseline = vec![br("a", "solved"), br("b", "solved")];
        let candidate = vec![br("a", "no_flag"), br("b", "solved")];
        let d = diff_runs(&baseline, &candidate);
        assert_eq!(d.improved.len(), 0);
        assert_eq!(d.regressed.len(), 1);
        assert_eq!(d.regressed[0].benchmark, "a");
        assert_eq!(d.solve_delta, -1);
    }

    #[test]
    fn unchanged_benchmarks_count_towards_unchanged() {
        let baseline = vec![br("a", "solved"), br("b", "no_flag")];
        let candidate = vec![br("a", "solved"), br("b", "no_flag")];
        let d = diff_runs(&baseline, &candidate);
        assert_eq!(d.unchanged, 2);
        assert_eq!(d.improved.len(), 0);
        assert_eq!(d.regressed.len(), 0);
        assert_eq!(d.solve_delta, 0);
    }

    #[test]
    fn benchmarks_only_in_candidate_register_as_neutral_unless_solved() {
        let baseline: Vec<BenchmarkResult> = vec![];
        let candidate = vec![br("new1", "solved"), br("new2", "no_flag")];
        let d = diff_runs(&baseline, &candidate);
        // "new1" newly added AND solved → improved.
        assert_eq!(d.improved.len(), 1);
        assert_eq!(d.improved[0].benchmark, "new1");
        // "new2" newly added but not solved → neutral (unchanged bucket).
        assert_eq!(d.unchanged, 1);
        assert_eq!(d.regressed.len(), 0);
        // Candidate has 1 solved; baseline has 0 → delta = 1.
        assert_eq!(d.solve_delta, 1);
    }

    #[test]
    fn solve_delta_reflects_actual_count_difference() {
        let baseline = vec![br("a", "solved"), br("b", "no_flag")];
        let candidate = vec![br("a", "solved"), br("b", "solved"), br("c", "solved")];
        let d = diff_runs(&baseline, &candidate);
        assert_eq!(d.baseline_solved, 1);
        assert_eq!(d.candidate_solved, 3);
        assert_eq!(d.solve_delta, 2);
    }

    #[test]
    fn markdown_renders_improvements_and_regressions() {
        let baseline = vec![br("a", "solved"), br("b", "no_flag")];
        let candidate = vec![br("a", "no_flag"), br("b", "solved")];
        let d = diff_runs(&baseline, &candidate);
        let md = d.to_markdown();
        assert!(md.contains("Improvements (1)"));
        assert!(md.contains("Regressions (1)"));
        assert!(md.contains("⚠️"));
    }
}
