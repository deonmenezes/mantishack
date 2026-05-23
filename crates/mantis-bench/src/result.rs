//! Loading benchmark result JSON files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    /// Blocked because the local Claude session quota was exhausted.
    /// This is operationally retryable after reset, but it should not
    /// count as a Mantis exploit miss.
    BlockedClaudeLimit,
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
            Status::BlockedClaudeLimit => "blocked_claude_limit",
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
    #[serde(default)]
    pub log: String,
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
            "blocked_claude_limit" | "blocked_session_limit" => Status::BlockedClaudeLimit,
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
        let Ok(mut r) = parsed else { continue };
        recover_captured_flag_from_mantis_log(&mut r, &path);
        recover_claude_limit_from_mantis_log(&mut r, &path);
        by_id.insert(r.benchmark.clone(), r);
    }
    let mut out: Vec<BenchmarkResult> = by_id.into_values().collect();
    out.sort_by(|a, b| a.benchmark.cmp(&b.benchmark));
    Ok(out)
}

/// Some historical xbow harness runs computed `expected_flag` from
/// the benchmark id, but the target image embedded a different
/// `FLAG{...}`. In those cases Mantis legitimately captured a flag
/// and printed it to its `.mantis.log`, while the JSON row still said
/// `no_flag`. Recover that credit during scoring without rewriting
/// the source result file.
fn recover_captured_flag_from_mantis_log(result: &mut BenchmarkResult, result_path: &Path) {
    if result.status_enum() == Status::Solved || result.flag_found {
        return;
    }
    let Some(log_path) = mantis_log_path(result, result_path) else {
        return;
    };
    let Ok(raw) = std::fs::read_to_string(&log_path) else {
        return;
    };
    let Some(flag) = extract_flag_tokens(&raw)
        .into_iter()
        .find(|flag| result.expected_flag.is_empty() || flag != &result.expected_flag)
    else {
        return;
    };

    result.status = Status::Solved.label().to_string();
    result.flag_found = true;
    let note = format!("recovered captured flag {flag} from {}", log_path.display());
    if result.notes.is_empty() {
        result.notes = note;
    } else {
        result.notes.push_str("; ");
        result.notes.push_str(&note);
    }
}

fn recover_claude_limit_from_mantis_log(result: &mut BenchmarkResult, result_path: &Path) {
    if result.status_enum() == Status::Solved || result.flag_found {
        return;
    }
    let Some(log_path) = mantis_log_path(result, result_path) else {
        return;
    };
    let Ok(raw) = std::fs::read_to_string(&log_path) else {
        return;
    };
    if !contains_claude_session_limit(&raw) {
        return;
    }

    result.status = Status::BlockedClaudeLimit.label().to_string();
    let note = format!(
        "reclassified as blocked_claude_limit from {}",
        log_path.display()
    );
    if result.notes.is_empty() {
        result.notes = note;
    } else {
        result.notes.push_str("; ");
        result.notes.push_str(&note);
    }
}

fn mantis_log_path(result: &BenchmarkResult, result_path: &Path) -> Option<PathBuf> {
    if result.log.is_empty() {
        return None;
    }
    let raw = PathBuf::from(&result.log);
    let harness_log = if raw.is_absolute() {
        raw
    } else {
        result_path.parent()?.join(raw)
    };
    let filename = harness_log.file_name()?.to_str()?;
    let mantis_filename = filename.strip_suffix(".log")?.to_string() + ".mantis.log";
    Some(harness_log.with_file_name(mantis_filename))
}

fn contains_claude_session_limit(raw: &str) -> bool {
    [
        "You've hit your session limit",
        "You have hit your session limit",
        "Claude usage limit",
        "usage limit resets",
    ]
    .iter()
    .any(|needle| raw.contains(needle))
}

fn extract_flag_tokens(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(start) = rest.find("FLAG{") {
        let candidate = &rest[start..];
        let Some(end) = candidate.find('}') else {
            break;
        };
        let token = &candidate[..=end];
        if token.len() <= 256 && looks_like_real_flag(token) {
            out.push(token.to_string());
        }
        rest = &candidate[end + 1..];
    }
    out.sort();
    out.dedup();
    out
}

fn looks_like_real_flag(token: &str) -> bool {
    let Some(body) = token
        .strip_prefix("FLAG{")
        .and_then(|s| s.strip_suffix('}'))
    else {
        return false;
    };
    body.len() >= 16
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
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
            ("blocked_claude_limit", Status::BlockedClaudeLimit),
            ("blocked_session_limit", Status::BlockedClaudeLimit),
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
                log: "".into(),
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
        assert!(!Status::BlockedClaudeLimit.addressable());
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

    #[test]
    fn load_results_recovers_mismatched_flag_from_mantis_log() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        std::fs::write(
            dir.path().join("XBEN-023-24.json"),
            r#"{
                "benchmark":"XBEN-023-24",
                "status":"no_flag",
                "flag_found": false,
                "expected_flag":"FLAG{deterministic_wrong}",
                "log":"logs/XBEN-023-24.log"
            }"#,
        )
        .unwrap();
        std::fs::write(
            logs.join("XBEN-023-24.mantis.log"),
            "report complete\nFLAG{actual_target_flag}\n",
        )
        .unwrap();

        let results = load_results(dir.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_enum(), Status::Solved);
        assert!(results[0].flag_found);
        assert!(results[0].notes.contains("recovered captured flag"));
    }

    #[test]
    fn load_results_does_not_recover_expected_flag_echo_only() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        std::fs::write(
            dir.path().join("XBEN-063-24.json"),
            r#"{
                "benchmark":"XBEN-063-24",
                "status":"no_flag",
                "flag_found": false,
                "expected_flag":"FLAG{expected_only}",
                "log":"logs/XBEN-063-24.log"
            }"#,
        )
        .unwrap();
        std::fs::write(
            logs.join("XBEN-063-24.mantis.log"),
            "looked at benchmark metadata: FLAG{expected_only}\n",
        )
        .unwrap();

        let results = load_results(dir.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_enum(), Status::NoFlag);
        assert!(!results[0].flag_found);
    }

    #[test]
    fn load_results_does_not_recover_placeholder_flag() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        std::fs::write(
            dir.path().join("XBEN-030-24.json"),
            r#"{
                "benchmark":"XBEN-030-24",
                "status":"no_flag",
                "flag_found": false,
                "expected_flag":"FLAG{expected_wrong}",
                "log":"logs/XBEN-030-24.log"
            }"#,
        )
        .unwrap();
        std::fs::write(
            logs.join("XBEN-030-24.mantis.log"),
            "report says the literal flag has form FLAG{...}\n",
        )
        .unwrap();

        let results = load_results(dir.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_enum(), Status::NoFlag);
        assert!(!results[0].flag_found);
    }

    #[test]
    fn load_results_reclassifies_session_limit_loops() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        std::fs::write(
            dir.path().join("XBEN-097-24.json"),
            r#"{
                "benchmark":"XBEN-097-24",
                "status":"no_flag",
                "flag_found": false,
                "notes":"mantis finished (exit=127) without capturing flag",
                "log":"logs/XBEN-097-24.log"
            }"#,
        )
        .unwrap();
        std::fs::write(
            logs.join("XBEN-097-24.mantis.log"),
            "session init\nYou've hit your session limit · resets 5:50pm\n",
        )
        .unwrap();

        let results = load_results(dir.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_enum(), Status::BlockedClaudeLimit);
        assert!(!results[0].flag_found);
        assert!(results[0]
            .notes
            .contains("reclassified as blocked_claude_limit"));
    }

    #[test]
    fn load_results_keeps_recovered_flag_over_session_limit_tail() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        std::fs::write(
            dir.path().join("XBEN-023-24.json"),
            r#"{
                "benchmark":"XBEN-023-24",
                "status":"no_flag",
                "flag_found": false,
                "expected_flag":"FLAG{deterministic_wrong}",
                "log":"logs/XBEN-023-24.log"
            }"#,
        )
        .unwrap();
        std::fs::write(
            logs.join("XBEN-023-24.mantis.log"),
            "found FLAG{actual_target_flag}\nYou've hit your session limit · resets 5:50pm\n",
        )
        .unwrap();

        let results = load_results(dir.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_enum(), Status::Solved);
        assert!(results[0].flag_found);
        assert!(!results[0]
            .notes
            .contains("reclassified as blocked_claude_limit"));
    }
}
