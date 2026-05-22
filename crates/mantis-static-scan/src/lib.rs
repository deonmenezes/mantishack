//! mantis-static-scan — shell-out adapters for best-of-breed
//! open-source security scanners.
//!
//! Each submodule wraps one external CLI tool: `nuclei` (template
//! vuln scanning), `subfinder` (passive subdomain enum), `httpx`
//! (HTTP probing), `trufflehog` (verified secrets), `trivy`
//! (containers / IaC / filesystems / SBOMs). The adapters spawn
//! the tool via `tokio::process::Command`, capture stdout, parse
//! the tool's JSON output, and map results into the unified
//! [`Finding`] type so downstream consumers (`mantis-mcp`,
//! `mantis-recon-tools`, the chat surface) don't have to know
//! which tool produced which finding.
//!
//! Design contract:
//!   * **No FFI / library bindings.** Every adapter shells out to
//!     the upstream binary. Avoids licensing entanglements (some
//!     tools are AGPL but the binary boundary keeps Mantis clean)
//!     and lets operators upgrade tools out-of-band without
//!     rebuilding mantis.
//!   * **JSON-out only.** If the tool doesn't have a `--json` (or
//!     equivalent) flag, the adapter is rejected. Human-formatted
//!     output is too brittle for downstream parsing.
//!   * **Availability check before invocation.** `is_available()`
//!     runs `<tool> --version` (or equivalent) once and caches the
//!     result. Failed checks surface as `ScanError::Unavailable`
//!     with install hints — the calling MCP tool returns this to
//!     the LLM, which can prompt the operator to install.
//!   * **Operator-installable.** Mantis doesn't bundle these
//!     binaries. They're installed via `brew install` /
//!     `go install` / `apt install` etc. Mantis just orchestrates.

pub mod nuclei;
pub mod subfinder;
pub mod httpx;
pub mod trufflehog;
pub mod trivy;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Severity bucket. Mirrors the standard "Info → Critical" ladder
/// used by nuclei, trivy, trufflehog (which calls them Verified /
/// Unverified), and the rest. The adapters normalise their tool's
/// native vocabulary onto this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse the severity strings the upstream tools emit. Accepts
    /// nuclei's lowercase ("info"/"low"/...), trivy's UPPER-CASE
    /// ("LOW"/"HIGH"/...), and trufflehog's "verified"/"unverified"
    /// (mapped to Critical / Medium).
    pub fn parse(raw: &str) -> Severity {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" | "verified" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" | "unverified" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

/// One finding from any of the adapter tools. The shape is
/// intentionally narrow — `raw` preserves the upstream JSON so
/// downstream consumers that want richer detail can pull from
/// there without us having to model every tool's full schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which adapter produced this — e.g. `"nuclei"`, `"trivy"`.
    pub tool: String,
    /// Short category tag — e.g. `"vuln"`, `"subdomain"`, `"secret"`,
    /// `"cve"`, `"misconfig"`. Used by MCP tool callers for filtering
    /// and by the report renderer to group sections.
    pub kind: String,
    /// What the finding is about — a URL, a path, a domain, a
    /// package@version. Free-form; adapters set whatever's most
    /// meaningful for the tool's domain.
    pub target: String,
    pub severity: Severity,
    /// One-line label suitable for a list view.
    pub title: String,
    /// Multi-line description with context the LLM can use to
    /// triage. May contain markdown.
    pub description: String,
    /// Tool-emitted metadata that didn't fit into the above fields.
    /// Useful when the LLM needs to drill into specifics (matched
    /// part, request body, vuln template id, CVE id, etc.).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
    /// The raw JSON line the adapter parsed this from. Preserved
    /// verbatim for callers that want the upstream tool's full
    /// detail without us having to model every field.
    pub raw: serde_json::Value,
}

impl Finding {
    pub fn new(
        tool: impl Into<String>,
        kind: impl Into<String>,
        target: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            kind: kind.into(),
            target: target.into(),
            severity,
            title: title.into(),
            description: String::new(),
            meta: BTreeMap::new(),
            raw: serde_json::Value::Null,
        }
    }

    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    pub fn with_meta(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.meta.insert(k.into(), v.into());
        self
    }

    pub fn with_raw(mut self, raw: serde_json::Value) -> Self {
        self.raw = raw;
        self
    }
}

/// All adapter errors map onto this. The MCP tool wrapper converts
/// `Unavailable` into a clear operator-facing install hint instead
/// of a stack trace.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("`{tool}` is not installed. Install hint: {install_hint}")]
    Unavailable {
        tool: &'static str,
        install_hint: &'static str,
    },
    #[error("`{tool}` spawn failed: {source}")]
    Spawn {
        tool: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("`{tool}` exited with status {status}: {stderr}")]
    NonZeroExit {
        tool: &'static str,
        status: String,
        stderr: String,
    },
    #[error("scanner produced malformed output: {0}")]
    BadOutput(String),
    #[error("`{tool}` timed out after {seconds}s")]
    Timeout { tool: &'static str, seconds: u64 },
}

/// Best-effort check that `binary` is on PATH. Used by every adapter
/// to fail fast with an install hint instead of a confusing spawn
/// error. The check is single-shot and uses `<binary> --version`
/// because every tool we wrap supports it.
pub async fn binary_available(binary: &str) -> bool {
    tokio::process::Command::new(binary)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_parses_common_aliases() {
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::parse("Critical"), Severity::Critical);
        assert_eq!(Severity::parse("verified"), Severity::Critical);
        assert_eq!(Severity::parse("HIGH"), Severity::High);
        assert_eq!(Severity::parse("medium"), Severity::Medium);
        assert_eq!(Severity::parse("moderate"), Severity::Medium);
        assert_eq!(Severity::parse("unverified"), Severity::Medium);
        assert_eq!(Severity::parse("LOW"), Severity::Low);
        assert_eq!(Severity::parse("info"), Severity::Info);
        assert_eq!(Severity::parse("random-junk"), Severity::Info);
    }

    #[test]
    fn severity_orders_low_to_high() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn finding_builder_chains_metadata() {
        let f = Finding::new("nuclei", "vuln", "https://x.example/", Severity::High, "XSS")
            .with_description("reflected XSS in `q` param")
            .with_meta("template_id", "reflected-xss")
            .with_meta("cwe", "CWE-79");
        assert_eq!(f.tool, "nuclei");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.meta.get("template_id").map(String::as_str), Some("reflected-xss"));
        assert_eq!(f.meta.get("cwe").map(String::as_str), Some("CWE-79"));
    }

    #[tokio::test]
    async fn binary_available_returns_false_for_missing() {
        assert!(!binary_available("definitely-not-a-real-binary-mantis-test").await);
    }
}
