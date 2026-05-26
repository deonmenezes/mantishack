//! Nuclei adapter — template-based vulnerability scanner.
//!
//! Nuclei (https://github.com/projectdiscovery/nuclei) runs YAML
//! "templates" against HTTP/DNS/TCP/etc. targets. The community
//! template repository (`projectdiscovery/nuclei-templates`) ships
//! 8000+ templates covering CVEs, misconfigurations, exposures,
//! default credentials, technologies, and more.
//!
//! Install:
//! ```text
//! brew install nuclei
//! # or
//! go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
//! nuclei -update-templates
//! ```
//!
//! Invocation:
//! ```text
//! nuclei -u <target> -jsonl -silent [-severity high,critical]
//!        [-t cves/] [-tags ssrf,xxe] [-rate-limit 50] [-stats=false]
//! ```
//!
//! Each line of stdout is one JSON finding. The adapter parses
//! these into the unified [`Finding`] type so callers don't have
//! to know nuclei's native schema.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::{binary_available, Finding, ScanError, Severity};

const BIN: &str = "nuclei";
const INSTALL_HINT: &str =
    "`brew install nuclei` (or `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`), then run `nuclei -update-templates`";
const DEFAULT_TIMEOUT_SECS: u64 = 600;
const DEFAULT_RATE_LIMIT: u32 = 150;
const DEFAULT_CONCURRENCY: u32 = 25;

/// Builder for one nuclei invocation. Most operators only set
/// `severity_floor` and `tags` — defaults match the upstream
/// recommendations for a scoped engagement.
pub struct NucleiAdapter {
    binary: String,
    timeout: Duration,
    /// Templates filter — paths or directories relative to the
    /// template root, e.g. `vec!["cves/", "exposures/"]`. Empty
    /// runs all loaded templates.
    templates: Vec<String>,
    /// `-tags` filter (comma-joined upstream).
    tags_include: Vec<String>,
    /// `-exclude-tags` filter.
    tags_exclude: Vec<String>,
    /// `-severity` filter — `Some(Low)` keeps Low+. `None` keeps
    /// everything nuclei emits.
    severity_floor: Option<Severity>,
    /// `-rate-limit`. Default 150 — matches nuclei's own default.
    rate_limit: u32,
    /// `-c` concurrency. Default 25.
    concurrency: u32,
    /// Skip the auto-update check at startup. Default `true` so
    /// repeated scans don't hit the network every invocation.
    skip_update_check: bool,
}

impl NucleiAdapter {
    pub fn new() -> Self {
        Self {
            binary: BIN.into(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            templates: Vec::new(),
            tags_include: Vec::new(),
            tags_exclude: Vec::new(),
            severity_floor: None,
            rate_limit: DEFAULT_RATE_LIMIT,
            concurrency: DEFAULT_CONCURRENCY,
            skip_update_check: true,
        }
    }

    pub fn with_binary(mut self, b: impl Into<String>) -> Self {
        self.binary = b.into();
        self
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn with_templates(mut self, t: Vec<String>) -> Self {
        self.templates = t;
        self
    }

    pub fn with_tags(mut self, include: Vec<String>) -> Self {
        self.tags_include = include;
        self
    }

    pub fn with_exclude_tags(mut self, exclude: Vec<String>) -> Self {
        self.tags_exclude = exclude;
        self
    }

    pub fn with_severity_floor(mut self, floor: Severity) -> Self {
        self.severity_floor = Some(floor);
        self
    }

    pub fn with_rate_limit(mut self, rl: u32) -> Self {
        self.rate_limit = rl;
        self
    }

    pub fn with_concurrency(mut self, c: u32) -> Self {
        self.concurrency = c;
        self
    }

    pub fn enable_update_check(mut self) -> Self {
        self.skip_update_check = false;
        self
    }

    pub async fn ensure_available(&self) -> Result<(), ScanError> {
        if binary_available(&self.binary).await {
            Ok(())
        } else {
            Err(ScanError::Unavailable {
                tool: BIN,
                install_hint: INSTALL_HINT,
            })
        }
    }

    /// Scan a single target URL or host. The target is passed
    /// verbatim to nuclei via `-u`; nuclei accepts URLs
    /// (`https://x/`), hostnames (`x.example.com`), and IPs.
    pub async fn scan(&self, target: &str) -> Result<Vec<Finding>, ScanError> {
        self.scan_many(&[target.to_string()]).await
    }

    /// Scan multiple targets in one invocation. Nuclei reads
    /// targets from a stdin-fed list when `-l -` (which we use)
    /// is passed — more efficient than spawning N processes.
    pub async fn scan_many(&self, targets: &[String]) -> Result<Vec<Finding>, ScanError> {
        self.ensure_available().await?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("-jsonl")
            .arg("-silent")
            .arg("-l")
            .arg("-") // read targets from stdin
            .arg("-stats=false")
            .arg("-rate-limit")
            .arg(self.rate_limit.to_string())
            .arg("-c")
            .arg(self.concurrency.to_string());

        if self.skip_update_check {
            cmd.arg("-duc"); // disable update check
        }

        for t in &self.templates {
            cmd.arg("-t").arg(t);
        }
        if !self.tags_include.is_empty() {
            cmd.arg("-tags").arg(self.tags_include.join(","));
        }
        if !self.tags_exclude.is_empty() {
            cmd.arg("-exclude-tags").arg(self.tags_exclude.join(","));
        }
        if let Some(floor) = self.severity_floor {
            cmd.arg("-severity").arg(severity_filter(floor));
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| ScanError::Spawn {
            tool: BIN,
            source: e,
        })?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let joined = targets.join("\n");
            stdin
                .write_all(joined.as_bytes())
                .await
                .map_err(|e| ScanError::Spawn {
                    tool: BIN,
                    source: e,
                })?;
            // Closing stdin is essential — nuclei waits on EOF.
            drop(stdin);
        }

        let out = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(ScanError::Spawn {
                    tool: BIN,
                    source: e,
                })
            }
            Err(_) => {
                return Err(ScanError::Timeout {
                    tool: BIN,
                    seconds: self.timeout.as_secs(),
                });
            }
        };

        // Nuclei occasionally exits with non-zero status even on
        // successful scans (e.g. when some targets are unreachable).
        // We only fail loud if there's NO stdout to parse — in that
        // case the run truly produced nothing useful.
        if !out.status.success() && out.stdout.is_empty() {
            return Err(ScanError::NonZeroExit {
                tool: BIN,
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }

        let raw = std::str::from_utf8(&out.stdout).unwrap_or("");
        parse_nuclei_output(raw)
    }
}

impl Default for NucleiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a severity floor onto the `-severity` flag's comma-joined
/// value. Nuclei accepts `info,low,medium,high,critical` and we
/// pass every level at-or-above the floor.
fn severity_filter(floor: Severity) -> String {
    let all = [
        (Severity::Info, "info"),
        (Severity::Low, "low"),
        (Severity::Medium, "medium"),
        (Severity::High, "high"),
        (Severity::Critical, "critical"),
    ];
    all.iter()
        .filter(|(s, _)| *s >= floor)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse nuclei's JSONL stdout into `Finding`s. Public to the crate
/// for unit tests — invoke via `NucleiAdapter::scan*` in production.
pub(crate) fn parse_nuclei_output(raw: &str) -> Result<Vec<Finding>, ScanError> {
    let mut findings = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| ScanError::BadOutput(format!("line {}: {e}", i + 1)))?;
        if let Some(f) = nuclei_value_to_finding(&value) {
            findings.push(f);
        }
    }
    Ok(findings)
}

/// Convert one parsed JSON value into a `Finding`. Returns `None`
/// for lines that don't look like nuclei findings (defensive — if
/// nuclei ever ships a non-finding event on the JSONL stream, we
/// don't want to choke).
fn nuclei_value_to_finding(v: &serde_json::Value) -> Option<Finding> {
    let template_id = v.get("template-id").and_then(|x| x.as_str()).unwrap_or("");
    if template_id.is_empty() {
        return None;
    }

    let info = v.get("info");
    let name = info
        .and_then(|i| i.get("name"))
        .and_then(|x| x.as_str())
        .unwrap_or(template_id);
    let severity_raw = info
        .and_then(|i| i.get("severity"))
        .and_then(|x| x.as_str())
        .unwrap_or("info");
    let severity = Severity::parse(severity_raw);
    let description = info
        .and_then(|i| i.get("description"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    // Target preference: matched-at (most specific) > host > input.
    let target = v
        .get("matched-at")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("host").and_then(|x| x.as_str()))
        .or_else(|| v.get("input").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();

    let mut f = Finding::new("nuclei", "vuln", target, severity, name)
        .with_description(description)
        .with_meta("template_id", template_id)
        .with_raw(v.clone());

    // Best-effort enrichment from `info.classification`.
    if let Some(cls) = info.and_then(|i| i.get("classification")) {
        if let Some(cves) = cls.get("cve-id").and_then(|x| x.as_array()) {
            let joined = join_json_array_strs(cves, ",");
            if !joined.is_empty() {
                f = f.with_meta("cve", joined);
            }
        }
        if let Some(cwes) = cls.get("cwe-id").and_then(|x| x.as_array()) {
            let joined = join_json_array_strs(cwes, ",");
            if !joined.is_empty() {
                f = f.with_meta("cwe", joined);
            }
        }
        if let Some(score) = cls.get("cvss-score").and_then(|x| x.as_f64()) {
            f = f.with_meta("cvss_score", format!("{score:.1}"));
        }
        if let Some(metrics) = cls.get("cvss-metrics").and_then(|x| x.as_str()) {
            f = f.with_meta("cvss_metrics", metrics);
        }
    }

    if let Some(tags) = info.and_then(|i| i.get("tags")) {
        // Tags can be a JSON array OR a comma-joined string (older
        // template emissions). Handle both.
        let joined = if let Some(arr) = tags.as_array() {
            join_json_array_strs(arr, ",")
        } else if let Some(s) = tags.as_str() {
            s.to_string()
        } else {
            String::new()
        };
        if !joined.is_empty() {
            f = f.with_meta("tags", joined);
        }
    }

    if let Some(ip) = v.get("ip").and_then(|x| x.as_str()) {
        f = f.with_meta("ip", ip);
    }
    if let Some(typ) = v.get("type").and_then(|x| x.as_str()) {
        f = f.with_meta("protocol", typ);
    }
    if let Some(matcher) = v.get("matcher-name").and_then(|x| x.as_str()) {
        if !matcher.is_empty() {
            f = f.with_meta("matcher", matcher);
        }
    }

    Some(f)
}

/// Join the string values inside a JSON array with `sep`, skipping
/// non-string entries. Replaces the
/// `arr.iter().filter_map(...).collect::<Vec<_>>().join(sep)` pattern:
/// the prior code allocated an intermediate Vec<&str> just to feed
/// .join(). Building the result String directly is one fewer
/// allocation per call (and avoids the per-element pointer copy
/// into the Vec).
fn join_json_array_strs(arr: &[serde_json::Value], sep: &str) -> String {
    let mut out = String::new();
    let mut first = true;
    for v in arr {
        if let Some(s) = v.as_str() {
            if !first {
                out.push_str(sep);
            }
            first = false;
            out.push_str(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic single-finding JSONL line shaped like the nuclei
    /// schema, with classification metadata.
    const FIXTURE_CVE_LINE: &str = r#"{"template-id":"CVE-2021-44228","template":"cves/2021/CVE-2021-44228.yaml","info":{"name":"Apache Log4j2 RCE","author":["meme-lord"],"tags":["cve","cve2021","rce","log4j"],"description":"Apache Log4j2 <=2.14.1 JNDI features...","severity":"critical","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":10.0}},"type":"http","host":"https://target.example","matched-at":"https://target.example/login","ip":"1.2.3.4","timestamp":"2024-01-01T00:00:00Z","matcher-status":true,"matcher-name":"jndi-injection"}"#;

    const FIXTURE_INFO_LINE: &str = r#"{"template-id":"tech-detect:nginx","info":{"name":"Nginx Detected","severity":"info","tags":["tech","nginx"]},"type":"http","host":"https://target.example","matched-at":"https://target.example/"}"#;

    #[test]
    fn parses_single_cve_line() {
        let findings = parse_nuclei_output(FIXTURE_CVE_LINE).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.tool, "nuclei");
        assert_eq!(f.kind, "vuln");
        assert_eq!(f.target, "https://target.example/login");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.title, "Apache Log4j2 RCE");
        assert!(f.description.contains("JNDI"));
        assert_eq!(
            f.meta.get("template_id").map(String::as_str),
            Some("CVE-2021-44228")
        );
        assert_eq!(
            f.meta.get("cve").map(String::as_str),
            Some("CVE-2021-44228")
        );
        assert_eq!(f.meta.get("cwe").map(String::as_str), Some("CWE-502"));
        assert_eq!(f.meta.get("cvss_score").map(String::as_str), Some("10.0"));
        assert!(f.meta.get("tags").unwrap().contains("log4j"));
    }

    #[test]
    fn parses_info_line_without_classification() {
        let findings = parse_nuclei_output(FIXTURE_INFO_LINE).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.title, "Nginx Detected");
        // No classification block → no cve/cwe meta entries.
        assert!(!f.meta.contains_key("cve"));
        assert!(!f.meta.contains_key("cwe"));
    }

    #[test]
    fn parses_multiple_jsonl_lines() {
        let raw = format!("{FIXTURE_CVE_LINE}\n{FIXTURE_INFO_LINE}\n");
        let findings = parse_nuclei_output(&raw).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Info);
    }

    #[test]
    fn empty_lines_are_skipped() {
        let raw = format!("\n\n{FIXTURE_INFO_LINE}\n\n");
        let findings = parse_nuclei_output(&raw).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn lines_without_template_id_are_dropped_silently() {
        // Defensive: a stray non-finding JSON object on the stream
        // shouldn't poison the whole batch.
        let raw = r#"{"unrelated":"event"}"#;
        let findings = parse_nuclei_output(raw).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn malformed_json_returns_error_with_line_number() {
        let raw = "not json at all";
        let err = parse_nuclei_output(raw).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 1"), "got: {msg}");
    }

    #[test]
    fn severity_filter_low_keeps_low_through_critical() {
        let filter = severity_filter(Severity::Low);
        assert!(filter.contains("low"));
        assert!(filter.contains("medium"));
        assert!(filter.contains("high"));
        assert!(filter.contains("critical"));
        assert!(!filter.contains("info"));
    }

    #[test]
    fn severity_filter_critical_keeps_only_critical() {
        let filter = severity_filter(Severity::Critical);
        assert_eq!(filter, "critical");
    }

    #[test]
    fn target_falls_back_to_host_then_input() {
        // No matched-at; only host.
        let only_host = r#"{"template-id":"x","info":{"name":"x","severity":"info"},"host":"https://h.example/"}"#;
        let f = &parse_nuclei_output(only_host).unwrap()[0];
        assert_eq!(f.target, "https://h.example/");

        // No matched-at or host; only input.
        let only_input =
            r#"{"template-id":"x","info":{"name":"x","severity":"info"},"input":"i.example.com"}"#;
        let f = &parse_nuclei_output(only_input).unwrap()[0];
        assert_eq!(f.target, "i.example.com");
    }

    #[test]
    fn tags_handle_both_array_and_string_shapes() {
        let arr_form =
            r#"{"template-id":"x","info":{"name":"x","severity":"info","tags":["a","b","c"]}}"#;
        let f = &parse_nuclei_output(arr_form).unwrap()[0];
        assert_eq!(f.meta.get("tags").map(String::as_str), Some("a,b,c"));

        let str_form =
            r#"{"template-id":"y","info":{"name":"y","severity":"info","tags":"d,e,f"}}"#;
        let f = &parse_nuclei_output(str_form).unwrap()[0];
        assert_eq!(f.meta.get("tags").map(String::as_str), Some("d,e,f"));
    }
}
