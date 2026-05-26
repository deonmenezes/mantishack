//! Adapter for [`subfinder`](https://github.com/projectdiscovery/subfinder)
//! — ProjectDiscovery's passive subdomain enumeration tool. Subfinder
//! aggregates results from ~30+ passive sources (crt.sh, VirusTotal,
//! SecurityTrails, etc.) and emits one JSON object per discovered
//! host. We invoke it with `-oJ -silent` for stable line-delimited
//! JSON suitable for streaming/parse.
//!
//! Install: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
//! or `brew install subfinder`.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::{binary_available, Finding, ScanError, Severity};

const BIN: &str = "subfinder";
const INSTALL_HINT: &str =
    "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  (or `brew install subfinder`)";
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Shell-out adapter for `subfinder`.
pub struct SubfinderAdapter {
    binary: String,
    timeout: Duration,
}

impl SubfinderAdapter {
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

impl Default for SubfinderAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SubfinderAdapter {
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

    /// Enumerate subdomains for `domain`. Runs `subfinder -d <domain>
    /// -oJ -silent` and maps each emitted JSON line into a
    /// [`Finding`].
    pub async fn enumerate(&self, domain: &str) -> Result<Vec<Finding>, ScanError> {
        self.ensure_available().await?;

        let child = Command::new(&self.binary)
            .arg("-d")
            .arg(domain)
            .arg("-oJ")
            .arg("-silent")
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
            Ok(Err(e)) => {
                return Err(ScanError::Spawn {
                    tool: BIN,
                    source: e,
                })
            }
            Err(_) => {
                return Err(ScanError::Timeout {
                    tool: BIN,
                    seconds: timeout.as_secs(),
                });
            }
        };

        let raw = std::str::from_utf8(&stdout).unwrap_or("");
        parse_subfinder_output(raw)
    }
}

/// Pure parser: take the captured subfinder JSONL stdout and produce
/// findings. Kept separate from the spawn logic so tests can pass
/// fixtures without requiring the binary on PATH.
pub(crate) fn parse_subfinder_output(raw: &str) -> Result<Vec<Finding>, ScanError> {
    let mut findings = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| ScanError::BadOutput(format!("line {}: {e}", i + 1)))?;

        let host = value
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if host.is_empty() {
            continue;
        }
        let input = value
            .get("input")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let source = value
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut f = Finding::new(
            "subfinder",
            "subdomain",
            host.clone(),
            Severity::Info,
            format!("subdomain: {host}"),
        )
        .with_raw(value);

        if !input.is_empty() {
            f = f.with_meta("input", input);
        }
        if !source.is_empty() {
            f = f.with_meta("source", source);
        }

        findings.push(f);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subfinder_fixture() {
        let raw = "{\"host\":\"a.example.com\",\"input\":\"example.com\",\"source\":\"crtsh\"}\n\
                   {\"host\":\"b.example.com\",\"input\":\"example.com\",\"source\":\"virustotal\"}\n";
        let findings = parse_subfinder_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].tool, "subfinder");
        assert_eq!(findings[0].kind, "subdomain");
        assert_eq!(findings[0].target, "a.example.com");
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].title, "subdomain: a.example.com");
        assert_eq!(
            findings[0].meta.get("input").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            findings[0].meta.get("source").map(String::as_str),
            Some("crtsh")
        );
        assert_eq!(findings[1].target, "b.example.com");
        assert_eq!(
            findings[1].meta.get("source").map(String::as_str),
            Some("virustotal")
        );
    }

    #[test]
    fn skips_blank_and_hostless_lines() {
        let raw =
            "\n   \n{\"host\":\"x.example.com\",\"source\":\"crtsh\"}\n{\"source\":\"crtsh\"}\n";
        let findings = parse_subfinder_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target, "x.example.com");
        // input is absent so the meta key must not be inserted
        assert!(!findings[0].meta.contains_key("input"));
    }

    #[test]
    fn errors_on_malformed_line() {
        let raw = "{not json}\n";
        let err = parse_subfinder_output(raw).unwrap_err();
        match err {
            ScanError::BadOutput(msg) => assert!(msg.contains("line 1")),
            other => panic!("expected BadOutput, got {other:?}"),
        }
    }
}
