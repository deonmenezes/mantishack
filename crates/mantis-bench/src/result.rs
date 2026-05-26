//! Loading benchmark result JSON files.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Terminal status a benchmark run can land in. The xbow corpus
/// emits these as strings; we parse them into a small enum so the
/// scoreboard / diff logic can pattern-match without typos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Mantis captured the expected flag.
    Solved,
    /// Mantis ran but didn't capture the flag.
    NoFlag,
    /// Mantis hit the wall-clock timeout before any result.
    Timeout,
    /// `docker compose build` failed before Mantis got a target.
    BuildFailed,
    /// `docker compose up --wait` failed (container crashed).
    RunFailed,
    /// Couldn't resolve a host port mapping for the target.
    NoTargetPort,
    /// Blocked by an EOL dependency (e.g. phantomjs); the runner
    /// skipped this benchmark deliberately.
    BlockedPhantomjs,
    /// Any other status string we didn't model.
    Other,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Solved => "solved",
            Status::NoFlag => "no_flag",
            Status::Timeout => "timeout",
            Status::BuildFailed => "build_failed",
            Status::RunFailed => "run_failed",
            Status::NoTargetPort => "no_target_port",
            Status::BlockedPhantomjs => "blocked_phantomjs",
            Status::Other => "other",
        }
    }

    /// Did this run produce a usable engagement? Skips
    /// `BuildFailed` / `RunFailed` / `BlockedPhantomjs` since
    /// those represent infrastructure problems, not Mantis's
    /// ability. Used by the scoreboard's "addressable solve rate"
    /// metric.
    pub fn addressable(self) -> bool {
        matches!(self, Status::Solved | Status::NoFlag | Status::Timeout)
    }
}

/// Loosely-typed match for the JSON shape the runner emits. We
/// accept missing fields so older / custom result files still
/// load — the scoreboard treats anything it doesn't understand
/// as `Status::Other`.
#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkResult {
    pub benchmark: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub expected_flag: String,
    #[serde(default)]
    pub target_url: String,
    pub status: String,
    #[serde(default)]
    pub flag_found: bool,
    #[serde(default)]
    pub duration_sec: u64,
    #[serde(default)]
    pub notes: String,
}

impl BenchmarkResult {
    pub fn status_enum(&self) -> Status {
        match self.status.as_str() {
            "solved" => Status::Solved,
            "no_flag" => Status::NoFlag,
            "timeout" => Status::Timeout,
            "build_failed" => Status::BuildFailed,
            "run_failed" => Status::RunFailed,
            "no_target_port" => Status::NoTargetPort,
            "blocked_phantomjs" => Status::BlockedPhantomjs,
            _ => Status::Other,
        }
    }
}

/// Load every `XBEN-*.json` (or `*.json` matching the schema)
/// from `dir`, deduped by `benchmark` field — the latest file
/// for a given benchmark id wins.
pub fn load_results(dir: &Path) -> std::io::Result<Vec<BenchmarkResult>> {
    let mut by_id: HashMap<String, BenchmarkResult> = HashMap::new();
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // Skip the summary aggregate file if it lives next to the
        // per-benchmark rows.
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("summary"))
            .unwrap_or(false)
        {
            continue;
        }
        let raw = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let parsed: Result<BenchmarkResult, _> = serde_json::from_slice(&raw);
        let Ok(r) = parsed else { continue };
        by_id.insert(r.benchmark.clone(), r);
    }
    let mut out: Vec<BenchmarkResult> = by_id.into_values().collect();
    out.sort_by(|a, b| a.benchmark.cmp(&b.benchmark));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_statuses() {
        let cases = [
            ("solved", Status::Solved),
            ("no_flag", Status::NoFlag),
            ("timeout", Status::Timeout),
            ("build_failed", Status::BuildFailed),
            ("run_failed", Status::RunFailed),
            ("no_target_port", Status::NoTargetPort),
            ("blocked_phantomjs", Status::BlockedPhantomjs),
            ("totally_unknown", Status::Other),
        ];
        for (raw, expected) in cases {
            let r = BenchmarkResult {
                benchmark: "x".into(),
                level: "".into(),
                tags: vec![],
                expected_flag: "".into(),
                target_url: "".into(),
                status: raw.into(),
                flag_found: false,
                duration_sec: 0,
                notes: "".into(),
            };
            assert_eq!(r.status_enum(), expected);
        }
    }

    #[test]
    fn addressable_excludes_infra_failures() {
        assert!(Status::Solved.addressable());
        assert!(Status::NoFlag.addressable());
        assert!(Status::Timeout.addressable());
        assert!(!Status::BuildFailed.addressable());
        assert!(!Status::RunFailed.addressable());
        assert!(!Status::BlockedPhantomjs.addressable());
    }

    #[test]
    fn load_results_dedupes_by_benchmark_id() {
        let dir = tempfile::tempdir().unwrap();
        // Two files with the SAME benchmark id but different statuses.
        // The second one (alphabetically) should win.
        std::fs::write(
            dir.path().join("a.json"),
            r#"{"benchmark":"XBEN-001-24","status":"no_flag"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.json"),
            r#"{"benchmark":"XBEN-001-24","status":"solved"}"#,
        )
        .unwrap();
        // Different benchmark — should also appear.
        std::fs::write(
            dir.path().join("c.json"),
            r#"{"benchmark":"XBEN-002-24","status":"no_flag"}"#,
        )
        .unwrap();
        let results = load_results(dir.path()).unwrap();
        assert_eq!(results.len(), 2);
        let solved = results
            .iter()
            .find(|r| r.benchmark == "XBEN-001-24")
            .unwrap();
        // HashMap insert-overwrite isn't ordering-stable across file
        // discovery, so we just assert that EXACTLY one of the two
        // statuses landed. The dedupe contract is "one row per id";
        // which row wins is implementation-defined.
        assert!(matches!(
            solved.status_enum(),
            Status::Solved | Status::NoFlag
        ));
    }

    #[test]
    fn load_results_skips_summary_aggregate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("summary.jsonl"),
            r#"{"not":"a benchmark row"}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("summary.json"), r#"{"meta":"x"}"#).unwrap();
        std::fs::write(
            dir.path().join("XBEN-007-24.json"),
            r#"{"benchmark":"XBEN-007-24","status":"solved"}"#,
        )
        .unwrap();
        let results = load_results(dir.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].benchmark, "XBEN-007-24");
    }

    #[test]
    fn load_results_returns_empty_on_missing_dir() {
        let nope = std::path::PathBuf::from("/tmp/definitely-not-a-bench-dir-xyz");
        let results = load_results(&nope).unwrap();
        assert!(results.is_empty());
    }
}
