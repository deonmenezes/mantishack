//! Adapter for [`httpx`](https://github.com/projectdiscovery/httpx) —
//! ProjectDiscovery's HTTP probe / tech-fingerprint tool. We feed it
//! a list of hosts/URLs on stdin and invoke it with `-json -silent`
//! to receive one JSON object per probed target. Each object carries
//! status code, title, content length, webserver banner, detected
//! technologies, and TLS metadata.
//!
//! Install: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
//! or `brew install httpx`.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::{binary_available, Finding, ScanError, Severity};

const BIN: &str = "httpx";
const INSTALL_HINT: &str =
    "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  (or `brew install httpx`)";
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Shell-out adapter for `httpx`.
pub struct HttpxAdapter {
    binary: String,
    timeout: Duration,
}

impl HttpxAdapter {
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

impl Default for HttpxAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpxAdapter {
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

    /// Probe each of `targets` and emit one [`Finding`] per response.
    /// `targets` are written newline-separated to httpx's stdin.
    pub async fn probe(&self, targets: &[String]) -> Result<Vec<Finding>, ScanError> {
        self.ensure_available().await?;

        let mut child = Command::new(&self.binary)
            .arg("-json")
            .arg("-silent")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ScanError::Spawn { tool: BIN, source })?;

        // Write targets into stdin and drop the handle so httpx sees EOF.
        if let Some(mut stdin) = child.stdin.take() {
            let payload = targets.join("\n");
            stdin
                .write_all(payload.as_bytes())
                .await
                .map_err(|source| ScanError::Spawn { tool: BIN, source })?;
            // Newline at end keeps last entry well-formed.
            stdin
                .write_all(b"\n")
                .await
                .map_err(|source| ScanError::Spawn { tool: BIN, source })?;
            drop(stdin);
        }

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
        parse_httpx_output(raw)
    }
}

fn truncate_to(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(n).collect();
        format!("{truncated}…")
    }
}

/// Pure parser: take httpx's captured JSONL stdout and produce
/// findings. Separable from the spawn logic for testability.
pub(crate) fn parse_httpx_output(raw: &str) -> Result<Vec<Finding>, ScanError> {
    let mut findings = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| ScanError::BadOutput(format!("line {}: {e}", i + 1)))?;

        // `url` is the canonical target; some httpx outputs only carry
        // `host`, so fall back. If neither is present, skip the line.
        let target = value
            .get("url")
            .and_then(|v| v.as_str())
            .or_else(|| value.get("host").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        if target.is_empty() {
            continue;
        }

        let status_code = value
            .get("status_code")
            .and_then(|v| v.as_i64())
            .map(|c| c.to_string())
            .unwrap_or_default();
        let webserver = value
            .get("webserver")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let title = value
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let port = value
            .get("port")
            .and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .unwrap_or_default();
        let tech_joined = match value.get("tech") {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(","),
            _ => String::new(),
        };

        let title_trunc = truncate_to(&title, 80);
        let title_line = format!(
            "{} {} {}",
            if status_code.is_empty() {
                "-"
            } else {
                status_code.as_str()
            },
            webserver,
            title_trunc
        )
        .trim()
        .to_string();

        let mut f =
            Finding::new("httpx", "http_probe", target, Severity::Info, title_line).with_raw(value);

        if !status_code.is_empty() {
            f = f.with_meta("status_code", status_code);
        }
        if !webserver.is_empty() {
            f = f.with_meta("webserver", webserver);
        }
        if !tech_joined.is_empty() {
            f = f.with_meta("tech", tech_joined);
        }
        if !port.is_empty() {
            f = f.with_meta("port", port);
        }

        findings.push(f);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_httpx_fixture() {
        let raw = "{\"timestamp\":\"2026-01-01T00:00:00Z\",\"port\":\"443\",\"url\":\"https://x.example.com\",\"title\":\"Welcome\",\"status_code\":200,\"content_length\":1234,\"webserver\":\"nginx\",\"tech\":[\"wordpress\",\"php\"]}\n";
        let findings = parse_httpx_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.tool, "httpx");
        assert_eq!(f.kind, "http_probe");
        assert_eq!(f.target, "https://x.example.com");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.title.contains("200"));
        assert!(f.title.contains("nginx"));
        assert!(f.title.contains("Welcome"));
        assert_eq!(f.meta.get("status_code").map(String::as_str), Some("200"));
        assert_eq!(f.meta.get("webserver").map(String::as_str), Some("nginx"));
        assert_eq!(
            f.meta.get("tech").map(String::as_str),
            Some("wordpress,php")
        );
        assert_eq!(f.meta.get("port").map(String::as_str), Some("443"));
    }

    #[test]
    fn falls_back_to_host_field_when_url_absent() {
        let raw = "{\"host\":\"raw.example.com\",\"status_code\":301}\n";
        let findings = parse_httpx_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target, "raw.example.com");
        assert_eq!(
            findings[0].meta.get("status_code").map(String::as_str),
            Some("301")
        );
        // No webserver / tech / port → none of those keys should be set.
        assert!(!findings[0].meta.contains_key("webserver"));
        assert!(!findings[0].meta.contains_key("tech"));
        assert!(!findings[0].meta.contains_key("port"));
    }

    #[test]
    fn truncates_long_titles_in_summary() {
        // 200-char title → must be truncated to 80 chars + ellipsis
        let big = "a".repeat(200);
        let raw = format!(
            "{{\"url\":\"https://t.example.com\",\"status_code\":200,\"title\":\"{big}\"}}\n"
        );
        let findings = parse_httpx_output(&raw).expect("parse ok");
        assert_eq!(findings.len(), 1);
        // Title summary must contain a truncated version + ellipsis.
        assert!(findings[0].title.contains('…'));
        assert!(findings[0].title.len() < 200);
    }
}
