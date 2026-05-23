//! Scoreboard rendering — per-tag, per-level, and overall stats.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::result::{BenchmarkResult, Status};

/// Per-tag breakdown. Used to identify weak vuln classes (e.g.
/// "XSS: 0/23" means Mantis hasn't solved a single XSS benchmark,
/// signalling that class as the highest-ROI improvement target).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagStats {
    pub tag: String,
    pub solved: usize,
    pub no_flag: usize,
    pub timeout: usize,
    pub build_failed: usize,
    pub run_failed: usize,
    pub blocked_phantomjs: usize,
    pub blocked_claude_limit: usize,
    pub blocked_claude_policy: usize,
    pub other: usize,
    pub total: usize,
}

impl TagStats {
    pub fn solve_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.solved as f64 / self.total as f64
        }
    }

    pub fn addressable_total(&self) -> usize {
        self.solved + self.no_flag + self.timeout
    }

    pub fn blocked_total(&self) -> usize {
        self.blocked_phantomjs + self.blocked_claude_limit + self.blocked_claude_policy
    }

    pub fn addressable_unsolved(&self) -> usize {
        self.no_flag + self.timeout
    }

    /// Solve rate over the "addressable" subset — excludes infra
    /// failures (build/run/phantomjs). Better measure of Mantis's
    /// actual capability since infra failures aren't its fault.
    pub fn addressable_solve_rate(&self) -> f64 {
        let addr = self.addressable_total();
        if addr == 0 {
            0.0
        } else {
            self.solved as f64 / addr as f64
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMiss {
    pub benchmark: String,
    pub level: String,
    pub status: String,
    pub tags: Vec<String>,
    pub duration_sec: u64,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scoreboard {
    pub total: usize,
    pub solved: usize,
    pub no_flag: usize,
    pub timeout: usize,
    pub build_failed: usize,
    pub run_failed: usize,
    pub blocked_phantomjs: usize,
    pub blocked_claude_limit: usize,
    pub blocked_claude_policy: usize,
    pub other: usize,
    pub by_tag: Vec<TagStats>,
    pub by_level: BTreeMap<String, TagStats>,
    /// Sorted (newest first) durations of successful solves —
    /// p50 / p90 useful for catching regressions where Mantis
    /// still solves the easy stuff but takes way longer.
    pub solved_durations_sec: Vec<u64>,
    /// Concrete NoFlag/Timeout rows still worth improving. Blocked
    /// infra/provider rows stay out of this list so operators focus
    /// on exploitability gaps.
    pub addressable_misses: Vec<BenchmarkMiss>,
}

impl Scoreboard {
    pub fn from_results(results: &[BenchmarkResult]) -> Self {
        let mut sb = Scoreboard {
            total: results.len(),
            solved: 0,
            no_flag: 0,
            timeout: 0,
            build_failed: 0,
            run_failed: 0,
            blocked_phantomjs: 0,
            blocked_claude_limit: 0,
            blocked_claude_policy: 0,
            other: 0,
            by_tag: Vec::new(),
            by_level: BTreeMap::new(),
            solved_durations_sec: Vec::new(),
            addressable_misses: Vec::new(),
        };

        let mut per_tag: BTreeMap<String, TagStats> = BTreeMap::new();

        for r in results {
            let s = r.status_enum();
            match s {
                Status::Solved => {
                    sb.solved += 1;
                    sb.solved_durations_sec.push(r.duration_sec);
                }
                Status::NoFlag => sb.no_flag += 1,
                Status::Timeout => sb.timeout += 1,
                Status::BuildFailed => sb.build_failed += 1,
                Status::RunFailed => sb.run_failed += 1,
                Status::NoTargetPort => sb.run_failed += 1, // group with run-failures
                Status::BlockedPhantomjs => sb.blocked_phantomjs += 1,
                Status::BlockedClaudeLimit => sb.blocked_claude_limit += 1,
                Status::BlockedClaudePolicy => sb.blocked_claude_policy += 1,
                Status::Other => sb.other += 1,
            }
            if matches!(s, Status::NoFlag | Status::Timeout) {
                sb.addressable_misses.push(BenchmarkMiss {
                    benchmark: r.benchmark.clone(),
                    level: if r.level.is_empty() {
                        "?".to_string()
                    } else {
                        r.level.clone()
                    },
                    status: s.label().to_string(),
                    tags: r.tags.clone(),
                    duration_sec: r.duration_sec,
                    notes: r.notes.clone(),
                });
            }

            // Per-tag stats (every tag the benchmark carries).
            // Untagged benchmarks land under "(no-tags)".
            let tags: Vec<String> = if r.tags.is_empty() {
                vec!["(no-tags)".into()]
            } else {
                r.tags.clone()
            };
            for t in tags {
                let e = per_tag.entry(t.clone()).or_insert(TagStats {
                    tag: t,
                    solved: 0,
                    no_flag: 0,
                    timeout: 0,
                    build_failed: 0,
                    run_failed: 0,
                    blocked_phantomjs: 0,
                    blocked_claude_limit: 0,
                    blocked_claude_policy: 0,
                    other: 0,
                    total: 0,
                });
                e.total += 1;
                match s {
                    Status::Solved => e.solved += 1,
                    Status::NoFlag => e.no_flag += 1,
                    Status::Timeout => e.timeout += 1,
                    Status::BuildFailed => e.build_failed += 1,
                    Status::RunFailed | Status::NoTargetPort => e.run_failed += 1,
                    Status::BlockedPhantomjs => e.blocked_phantomjs += 1,
                    Status::BlockedClaudeLimit => e.blocked_claude_limit += 1,
                    Status::BlockedClaudePolicy => e.blocked_claude_policy += 1,
                    Status::Other => e.other += 1,
                }
            }

            // Per-level stats.
            let level_key = if r.level.is_empty() {
                "?".to_string()
            } else {
                r.level.clone()
            };
            let e = sb.by_level.entry(level_key.clone()).or_insert(TagStats {
                tag: level_key,
                solved: 0,
                no_flag: 0,
                timeout: 0,
                build_failed: 0,
                run_failed: 0,
                blocked_phantomjs: 0,
                blocked_claude_limit: 0,
                blocked_claude_policy: 0,
                other: 0,
                total: 0,
            });
            e.total += 1;
            match s {
                Status::Solved => e.solved += 1,
                Status::NoFlag => e.no_flag += 1,
                Status::Timeout => e.timeout += 1,
                Status::BuildFailed => e.build_failed += 1,
                Status::RunFailed | Status::NoTargetPort => e.run_failed += 1,
                Status::BlockedPhantomjs => e.blocked_phantomjs += 1,
                Status::BlockedClaudeLimit => e.blocked_claude_limit += 1,
                Status::BlockedClaudePolicy => e.blocked_claude_policy += 1,
                Status::Other => e.other += 1,
            }
        }

        sb.solved_durations_sec.sort();
        // Sort tags by total descending so "biggest dataset" tags
        // appear first in the rendered scoreboard.
        sb.by_tag = per_tag.into_values().collect();
        sb.by_tag.sort_by_key(|tag| std::cmp::Reverse(tag.total));
        sb.addressable_misses.sort_by(|a, b| {
            a.benchmark
                .cmp(&b.benchmark)
                .then(a.status.cmp(&b.status))
                .then(a.level.cmp(&b.level))
        });

        sb
    }

    pub fn solve_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.solved as f64 / self.total as f64
        }
    }

    pub fn addressable_total(&self) -> usize {
        self.solved + self.no_flag + self.timeout
    }

    pub fn addressable_solve_rate(&self) -> f64 {
        let addr = self.addressable_total();
        if addr == 0 {
            0.0
        } else {
            self.solved as f64 / addr as f64
        }
    }

    /// p50 / p90 / max of solved benchmark durations.
    pub fn solved_percentiles(&self) -> Option<(u64, u64, u64)> {
        let d = &self.solved_durations_sec;
        if d.is_empty() {
            return None;
        }
        let p50 = d[d.len() / 2];
        let p90_idx = (d.len() as f64 * 0.9).floor() as usize;
        let p90 = d[p90_idx.min(d.len() - 1)];
        let max = *d.last().unwrap();
        Some((p50, p90, max))
    }

    /// Render the scoreboard as operator-readable markdown.
    pub fn to_markdown(&self) -> String {
        self.to_markdown_with_expected_total(None)
    }

    /// Render the scoreboard with optional corpus coverage context.
    pub fn to_markdown_with_expected_total(&self, expected_total: Option<usize>) -> String {
        let mut s = String::new();
        s.push_str("# Mantis benchmark scoreboard\n\n");
        s.push_str(&format!(
            "**Overall:** {} / {} solved ({:.1}%). Addressable: {} / {} ({:.1}%).\n\n",
            self.solved,
            self.total,
            100.0 * self.solve_rate(),
            self.solved,
            self.addressable_total(),
            100.0 * self.addressable_solve_rate()
        ));

        if let Some(expected_total) = expected_total.filter(|n| *n > 0) {
            s.push_str("**Coverage:** ");
            if self.total < expected_total {
                s.push_str(&format!(
                    "{} / {} result rows loaded ({} missing; partial snapshot).\n\n",
                    self.total,
                    expected_total,
                    expected_total - self.total
                ));
            } else if self.total == expected_total {
                s.push_str(&format!(
                    "{} / {} result rows loaded (complete snapshot).\n\n",
                    self.total, expected_total
                ));
            } else {
                s.push_str(&format!(
                    "{} / {} result rows loaded ({} extra; check corpus/results mix).\n\n",
                    self.total,
                    expected_total,
                    self.total - expected_total
                ));
            }
        }

        // Status histogram.
        s.push_str("## Status breakdown\n\n");
        s.push_str("| status | count |\n|---|---:|\n");
        for (name, n) in [
            ("solved", self.solved),
            ("no_flag", self.no_flag),
            ("timeout", self.timeout),
            ("build_failed", self.build_failed),
            ("run_failed", self.run_failed),
            ("blocked_phantomjs", self.blocked_phantomjs),
            ("blocked_claude_limit", self.blocked_claude_limit),
            ("blocked_claude_policy", self.blocked_claude_policy),
            ("other", self.other),
        ] {
            if n > 0 {
                s.push_str(&format!("| {name} | {n} |\n"));
            }
        }
        s.push('\n');

        // Per-level breakdown.
        if !self.by_level.is_empty() {
            s.push_str("## By difficulty level\n\n");
            s.push_str(
                "| level | solved | addressable | blocked | total | addr rate | raw rate |\n\
                 |---|---:|---:|---:|---:|---:|---:|\n",
            );
            for (lvl, st) in &self.by_level {
                s.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {:.1}% | {:.1}% |\n",
                    lvl,
                    st.solved,
                    st.addressable_total(),
                    st.blocked_total(),
                    st.total,
                    100.0 * st.addressable_solve_rate(),
                    100.0 * st.solve_rate()
                ));
            }
            s.push('\n');
        }

        // Per-tag breakdown (the most actionable view).
        s.push_str("## By vuln class\n\n");
        s.push_str(
            "| tag | solved | no_flag | timeout | blocked | addressable | total | addr rate | raw rate |\n\
             |---|---:|---:|---:|---:|---:|---:|---:|---:|\n",
        );
        let mut sorted: Vec<&TagStats> = self.by_tag.iter().collect();
        sorted.sort_by_key(|tag| std::cmp::Reverse(tag.total));
        for st in sorted {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {:.1}% | {:.1}% |\n",
                st.tag,
                st.solved,
                st.no_flag,
                st.timeout,
                st.blocked_total(),
                st.addressable_total(),
                st.total,
                100.0 * st.addressable_solve_rate(),
                100.0 * st.solve_rate()
            ));
        }
        s.push('\n');

        // Solve-duration percentiles.
        if let Some((p50, p90, max)) = self.solved_percentiles() {
            s.push_str("## Solved benchmark durations\n\n");
            s.push_str(&format!(
                "p50: **{p50}s** · p90: **{p90}s** · max: **{max}s** (n={})\n\n",
                self.solved_durations_sec.len()
            ));
        }

        s.push_str("## Remaining addressable misses\n\n");
        if self.addressable_misses.is_empty() {
            s.push_str("(none — remaining unsolved rows are blocked or infra-only)\n\n");
        } else {
            s.push_str(
                "| benchmark | level | status | tags | duration | notes |\n\
                 |---|---:|---|---|---:|---|\n",
            );
            for miss in &self.addressable_misses {
                let tags = if miss.tags.is_empty() {
                    "(no-tags)".to_string()
                } else {
                    miss.tags.join(", ")
                };
                s.push_str(&format!(
                    "| {} | {} | {} | {} | {}s | {} |\n",
                    md_cell(&miss.benchmark),
                    md_cell(&miss.level),
                    md_cell(&miss.status),
                    md_cell(&tags),
                    miss.duration_sec,
                    md_cell(&truncate_note(&miss.notes))
                ));
            }
            s.push('\n');
            s.push_str("Rerun queue:\n\n");
            s.push_str("```text\n");
            for miss in &self.addressable_misses {
                s.push_str(&miss.benchmark);
                s.push('\n');
            }
            s.push_str("```\n\n");
            s.push_str(
                "Emit this list with `mantis bench rerun-failures --addressable --results <results-dir>`.\n\n",
            );
        }

        s.push_str("## Where to invest next\n\n");
        // Surface any tags where Mantis had an addressable miss. Large
        // snapshots naturally put the biggest buckets first, while
        // almost-clean snapshots still show the remaining concrete gaps.
        let mut weak: Vec<&TagStats> = self
            .by_tag
            .iter()
            .filter(|st| st.addressable_unsolved() > 0)
            .collect();
        weak.sort_by(|a, b| {
            b.addressable_unsolved()
                .cmp(&a.addressable_unsolved())
                .then(b.addressable_total().cmp(&a.addressable_total()))
        });
        if weak.is_empty() {
            s.push_str(
                "(no addressable misses surfaced — remaining gaps are blocked or infra-only)\n",
            );
        } else {
            for st in weak.iter().take(8) {
                s.push_str(&format!(
                    "- **{}**: {} unsolved addressable of {} addressable ({:.1}% addressable solve rate; {} total rows). Inspect failed rows and tighten the class playbook/templates.\n",
                    st.tag,
                    st.addressable_unsolved(),
                    st.addressable_total(),
                    100.0 * st.addressable_solve_rate(),
                    st.total
                ));
            }
        }

        s
    }
}

fn md_cell(raw: &str) -> String {
    raw.replace('\n', " ").replace('|', "\\|")
}

fn truncate_note(raw: &str) -> String {
    const MAX: usize = 120;
    let trimmed = raw.trim();
    if trimmed.len() <= MAX {
        return trimmed.to_string();
    }
    let mut out = trimmed[..MAX].trim_end().to_string();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::BenchmarkResult;

    fn br(id: &str, status: &str, tags: &[&str], level: &str, dur: u64) -> BenchmarkResult {
        BenchmarkResult {
            benchmark: id.into(),
            level: level.into(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            expected_flag: "".into(),
            target_url: "".into(),
            status: status.into(),
            flag_found: status == "solved",
            duration_sec: dur,
            notes: "".into(),
            log: "".into(),
        }
    }

    #[test]
    fn from_results_aggregates_totals() {
        let results = vec![
            br("a", "solved", &["idor"], "1", 100),
            br("b", "solved", &["idor"], "1", 200),
            br("c", "no_flag", &["idor"], "1", 1800),
            br("d", "no_flag", &["xss"], "2", 1800),
            br("e", "no_flag", &["xss"], "2", 1800),
            br("f", "build_failed", &["xxe"], "3", 0),
            br("g", "blocked_claude_limit", &["ssti"], "2", 0),
            br("h", "blocked_phantomjs", &["xss"], "2", 0),
            br("i", "blocked_claude_policy", &["command_injection"], "2", 0),
        ];
        let sb = Scoreboard::from_results(&results);
        assert_eq!(sb.total, 9);
        assert_eq!(sb.solved, 2);
        assert_eq!(sb.no_flag, 3);
        assert_eq!(sb.build_failed, 1);
        assert_eq!(sb.blocked_phantomjs, 1);
        assert_eq!(sb.blocked_claude_limit, 1);
        assert_eq!(sb.blocked_claude_policy, 1);
        assert_eq!(sb.addressable_misses.len(), 3);
        assert!((sb.solve_rate() - 2.0 / 9.0).abs() < 1e-9);
        // Addressable excludes the build_failed and blocked rows.
        assert!((sb.addressable_solve_rate() - 2.0 / 5.0).abs() < 1e-9);

        let idor = sb.by_tag.iter().find(|t| t.tag == "idor").unwrap();
        assert_eq!(idor.solved, 2);
        assert_eq!(idor.total, 3);

        let xss = sb.by_tag.iter().find(|t| t.tag == "xss").unwrap();
        assert_eq!(xss.solved, 0);
        assert_eq!(xss.no_flag, 2);
        assert_eq!(xss.blocked_phantomjs, 1);
        assert_eq!(xss.addressable_total(), 2);
        assert_eq!(xss.blocked_total(), 1);
    }

    #[test]
    fn percentiles_compute_correctly() {
        let mut sb = Scoreboard::from_results(&[]);
        sb.solved_durations_sec = vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
        let (p50, p90, max) = sb.solved_percentiles().unwrap();
        assert_eq!(p50, 600);
        assert_eq!(p90, 1000);
        assert_eq!(max, 1000);
    }

    #[test]
    fn markdown_renders_known_sections() {
        let results = vec![
            br("a", "solved", &["idor"], "1", 100),
            br("b", "no_flag", &["xss"], "2", 1800),
        ];
        let sb = Scoreboard::from_results(&results);
        let md = sb.to_markdown();
        assert!(md.contains("Mantis benchmark scoreboard"));
        assert!(md.contains("Overall"));
        assert!(md.contains("By vuln class"));
        assert!(md.contains("Remaining addressable misses"));
        assert!(md.contains("| b | 2 | no_flag | xss | 1800s |"));
        assert!(md.contains("Rerun queue"));
        assert!(md.contains("mantis bench rerun-failures --addressable"));
        assert!(md.contains("idor"));
        assert!(md.contains("xss"));
    }

    #[test]
    fn markdown_can_show_partial_corpus_coverage() {
        let results = vec![
            br("a", "solved", &["idor"], "1", 100),
            br("b", "no_flag", &["xss"], "2", 1800),
        ];
        let sb = Scoreboard::from_results(&results);
        let md = sb.to_markdown_with_expected_total(Some(5));
        assert!(md.contains("**Coverage:** 2 / 5 result rows loaded"));
        assert!(md.contains("3 missing; partial snapshot"));
    }

    #[test]
    fn weak_tags_surface_zero_solved_with_attempts() {
        // 5 XSS attempts, 0 solved → should surface as a weak tag.
        let results = vec![
            br("a", "no_flag", &["xss"], "2", 1800),
            br("b", "no_flag", &["xss"], "2", 1800),
            br("c", "no_flag", &["xss"], "2", 1800),
            br("d", "no_flag", &["xss"], "2", 1800),
            br("e", "no_flag", &["xss"], "2", 1800),
        ];
        let sb = Scoreboard::from_results(&results);
        let md = sb.to_markdown();
        assert!(md.contains("**xss**: 5 unsolved addressable of 5 addressable"));
    }

    #[test]
    fn weak_tags_surface_low_volume_remaining_misses() {
        let results = vec![
            br("a", "solved", &["ssti"], "2", 100),
            br("b", "solved", &["ssti"], "2", 100),
            br("c", "no_flag", &["ssti"], "2", 100),
        ];
        let sb = Scoreboard::from_results(&results);
        let md = sb.to_markdown();
        assert!(md.contains("**ssti**: 1 unsolved addressable of 3 addressable"));
    }

    #[test]
    fn weak_tags_ignore_blocked_only_rows() {
        let results = vec![
            br("a", "blocked_phantomjs", &["xss"], "2", 0),
            br("b", "blocked_phantomjs", &["xss"], "2", 0),
            br("c", "blocked_phantomjs", &["xss"], "2", 0),
            br("d", "blocked_phantomjs", &["xss"], "2", 0),
            br("e", "blocked_phantomjs", &["xss"], "2", 0),
        ];
        let sb = Scoreboard::from_results(&results);
        let md = sb.to_markdown();
        assert!(md.contains("| xss | 0 | 0 | 0 | 5 | 0 | 5 | 0.0% | 0.0% |"));
        assert!(!md.contains("**xss**:"));
        assert!(!md.contains("Rerun queue"));
        assert!(md.contains("(none — remaining unsolved rows are blocked or infra-only)"));
    }
}
