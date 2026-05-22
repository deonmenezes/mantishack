//! Adapter for [`trufflehog`](https://github.com/trufflesecurity/trufflehog)
//! — TruffleSecurity's secret scanner with live-verification of detected
//! credentials (when the detector supports it). We invoke with `--json`
//! against either a filesystem path or a git URL and parse one secret
//! per JSON line.
//!
//! Install: `brew install trufflehog` or download from
//! https://github.com/trufflesecurity/trufflehog/releases.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::{Finding, ScanError, Severity, binary_available};

const BIN: &str = "trufflehog";
const INSTALL_HINT: &str =
    "`brew install trufflehog` (or download from https://github.com/trufflesecurity/trufflehog/releases)";
const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Shell-out adapter for `trufflehog`.
pub struct TrufflehogAdapter {
    binary: String,
    timeout: Duration,
}

impl TrufflehogAdapter {
    pub fn new() -> Self {
        Self {
            binary: BIN.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn with_binary(mut self, b: impl Into<String>) -> Self {
        self.binary = b.into();
        self
    }
}

impl Default for TrufflehogAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TrufflehogAdapter {
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

    /// Scan a local filesystem path. Runs
    /// `trufflehog --json filesystem <path>`.
    pub async fn scan_filesystem(&self, path: &Path) -> Result<Vec<Finding>, ScanError> {
        self.run(&["--json", "filesystem", &path.to_string_lossy()])
            .await
    }

    /// Scan a git repository URL. Runs `trufflehog --json git <repo_url>`.
    pub async fn scan_git(&self, repo_url: &str) -> Result<Vec<Finding>, ScanError> {
        self.run(&["--json", "git", repo_url]).await
    }

    async fn run(&self, args: &[&str]) -> Result<Vec<Finding>, ScanError> {
        self.ensure_available().await?;

        let child = Command::new(&self.binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ScanError::Spawn { tool: BIN, source })?;

        let timeout = self.timeout;
        let stdout = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(out)) if out.status.success() => out.stdout,
            Ok(Ok(out)) => {
                return Err(ScanError::NonZeroExit {
                    tool: BIN,
                    status: out.status.to_string(),
                    stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                });
            }
            Ok(Err(e)) => return Err(ScanError::Spawn { tool: BIN, source: e }),
            Err(_) => {
                return Err(ScanError::Timeout {
                    tool: BIN,
                    seconds: timeout.as_secs(),
                });
            }
        };

        let raw = std::str::from_utf8(&stdout).unwrap_or("");
        parse_trufflehog_output(raw)
    }
}

/// Extract a `"file:line"`-style location from trufflehog's
/// SourceMetadata block. Trufflehog's schema nests differently per
/// source (Filesystem, Git, S3, GitHub, etc.); this is a best-effort
/// scan over the common shapes.
fn extract_location(meta: &serde_json::Value) -> (String, Vec<(String, String)>) {
    let mut fields: Vec<(String, String)> = Vec::new();
    let data = meta.get("Data").unwrap_or(&serde_json::Value::Null);
    if !data.is_object() {
        return (String::new(), fields);
    }
    // The Data object has exactly one key keyed by source type — e.g.
    // {"Filesystem": {"file": ..., "line": ...}} or {"Git": {...}}.
    let obj = data.as_object().unwrap();
    let mut location = String::new();
    for (source_kind, inner) in obj {
        if !inner.is_object() {
            continue;
        }
        let file = inner
            .get("file")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let line = inner
            .get("line")
            .and_then(|v| match v {
                serde_json::Value::Number(n) => Some(n.to_string()),
                serde_json::Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let commit = inner
            .get("commit")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let repository = inner
            .get("repository")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if !file.is_empty() {
            location = if line.is_empty() {
                file.clone()
            } else {
                format!("{file}:{line}")
            };
            fields.push(("file".to_string(), file));
            if !line.is_empty() {
                fields.push(("line".to_string(), line));
            }
        } else if !repository.is_empty() {
            location = repository.clone();
            fields.push(("repository".to_string(), repository));
        }
        if !commit.is_empty() {
            fields.push(("commit".to_string(), commit));
        }
        fields.push(("source_kind".to_string(), source_kind.clone()));
        break;
    }
    (location, fields)
}

/// Pure parser: take trufflehog's captured JSONL stdout and produce
/// findings.
pub(crate) fn parse_trufflehog_output(raw: &str) -> Result<Vec<Finding>, ScanError> {
    let mut findings = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| ScanError::BadOutput(format!("line {}: {e}", i + 1)))?;

        let detector = value
            .get("DetectorName")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let verified = value
            .get("Verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let redacted = value
            .get("Redacted")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let display_redacted = if redacted.is_empty() {
            "(redacted)".to_string()
        } else {
            redacted.clone()
        };

        let (location, location_fields) = match value.get("SourceMetadata") {
            Some(m) => extract_location(m),
            None => (String::new(), Vec::new()),
        };
        let target = if location.is_empty() {
            "(unknown)".to_string()
        } else {
            location
        };

        let severity = Severity::parse(if verified { "verified" } else { "unverified" });
        let title = format!("{detector} key {display_redacted}");

        let mut f = Finding::new("trufflehog", "secret", target, severity, title)
            .with_meta("detector", detector)
            .with_meta("verified", if verified { "true" } else { "false" });
        for (k, v) in location_fields {
            f = f.with_meta(k, v);
        }
        f = f.with_raw(value);
        findings.push(f);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trufflehog_verified_filesystem_fixture() {
        let raw = "{\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"src/config.py\",\"line\":42}}},\"DetectorName\":\"AWS\",\"DetectorType\":1,\"Verified\":true,\"Raw\":\"AKIA...\",\"Redacted\":\"AKIA…\"}\n";
        let findings = parse_trufflehog_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.tool, "trufflehog");
        assert_eq!(f.kind, "secret");
        assert_eq!(f.target, "src/config.py:42");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.title, "AWS key AKIA…");
        assert_eq!(f.meta.get("detector").map(String::as_str), Some("AWS"));
        assert_eq!(f.meta.get("verified").map(String::as_str), Some("true"));
        assert_eq!(f.meta.get("file").map(String::as_str), Some("src/config.py"));
        assert_eq!(f.meta.get("line").map(String::as_str), Some("42"));
        assert_eq!(
            f.meta.get("source_kind").map(String::as_str),
            Some("Filesystem")
        );
    }

    #[test]
    fn parses_trufflehog_unverified_git_fixture() {
        let raw = "{\"SourceMetadata\":{\"Data\":{\"Git\":{\"file\":\"README.md\",\"line\":7,\"commit\":\"abc123\",\"repository\":\"https://github.com/x/y\"}}},\"DetectorName\":\"GitHub\",\"DetectorType\":2,\"Verified\":false,\"Redacted\":\"ghp_…\"}\n";
        let findings = parse_trufflehog_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.target, "README.md:7");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.meta.get("verified").map(String::as_str), Some("false"));
        assert_eq!(f.meta.get("commit").map(String::as_str), Some("abc123"));
        assert_eq!(f.meta.get("source_kind").map(String::as_str), Some("Git"));
    }

    #[test]
    fn parses_trufflehog_with_no_redacted_field() {
        let raw = "{\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"k.env\",\"line\":1}}},\"DetectorName\":\"Generic\",\"Verified\":false}\n";
        let findings = parse_trufflehog_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 1);
        // Title falls back to "(redacted)" placeholder.
        assert_eq!(findings[0].title, "Generic key (redacted)");
        assert_eq!(findings[0].target, "k.env:1");
    }
}
