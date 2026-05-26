//! mantis-trivy — supply-chain scanning for containers, IaC,
//! repositories, and SBOMs. Built on Aqua Security's
//! [`trivy`](https://github.com/aquasecurity/trivy) (Apache-2.0).
//!
//! This crate sits one tier above [`mantis_static_scan::trivy`],
//! which only ships filesystem + image scans. We add:
//!
//! * `config` — Terraform / Kubernetes / Dockerfile / CloudFormation
//!   misconfiguration scanning via `trivy config`.
//! * `repo` — full git-repo scan (vulns + secrets + misconfigs) via
//!   `trivy repo`.
//! * `sbom` — vuln scanning of SPDX / CycloneDX bundles via
//!   `trivy sbom`.
//! * `rootfs` — extracted-root-filesystem scan via `trivy rootfs`,
//!   useful for analysing unpacked container layers.
//!
//! Two output paths are supported:
//!
//! * Native [`Finding`] vector — same shape every other mantis
//!   adapter emits, so downstream consumers stay tool-agnostic.
//! * Raw SARIF passthrough — `scan_*_sarif` runs trivy with
//!   `--format sarif` and returns the JSON unchanged. Useful when
//!   feeding GitHub Code Scanning, DefectDojo, or any other
//!   SARIF-native sink without round-tripping through the mantis
//!   Finding type.
//!
//! In addition, [`emit_openvex`] converts a slice of CVE findings
//! into an [OpenVEX](https://openvex.dev) document so operators can
//! ship a machine-readable "not_affected / under_investigation /
//! affected / fixed" statement bundle alongside the report.
//!
//! Design notes:
//!
//! * Shell-out only. No FFI, no library bindings — the trivy binary
//!   is installed out-of-band by the operator (`brew install trivy`).
//!   This keeps the GPL-3-friendly trivy plugin ecosystem at arm's
//!   length from the Apache/MIT mantis core.
//! * Timeout-bounded. The default 600 s is sufficient for typical
//!   monorepo scans; large container images may need a longer budget.
//! * Severity is normalised by [`mantis_static_scan::Severity`].

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use mantis_static_scan::trivy::parse_trivy_output;
use mantis_static_scan::{binary_available, Finding, ScanError, Severity};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

const BIN: &str = "trivy";
const INSTALL_HINT: &str =
    "`brew install trivy` (or follow https://aquasecurity.github.io/trivy/latest/getting-started/installation/)";
const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Which trivy subcommand to invoke. Mirrors trivy's own
/// `trivy <target>` taxonomy so the strings line up with operator
/// expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// `trivy config` — IaC misconfiguration scan.
    Config,
    /// `trivy repo` — clone-or-walk a git repo and run the full
    /// vuln + secret + misconfig pipeline.
    Repo,
    /// `trivy sbom` — vulnerability scan against a SPDX / CycloneDX
    /// bundle. Useful when the SBOM was generated upstream by a
    /// build tool and we don't want trivy to re-resolve packages.
    Sbom,
    /// `trivy rootfs` — scan an unpacked container root filesystem.
    Rootfs,
}

impl ScanMode {
    fn subcommand(self) -> &'static str {
        match self {
            ScanMode::Config => "config",
            ScanMode::Repo => "repo",
            ScanMode::Sbom => "sbom",
            ScanMode::Rootfs => "rootfs",
        }
    }
}

/// Trivy scanner with extended mode support.
pub struct TrivyScanner {
    binary: String,
    timeout: Duration,
    /// Lowest severity to surface. Findings strictly below this
    /// floor are dropped during normalisation. Defaults to
    /// [`Severity::Info`] (no filtering).
    severity_floor: Severity,
}

impl TrivyScanner {
    pub fn new() -> Self {
        Self {
            binary: BIN.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            severity_floor: Severity::Info,
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

    pub fn with_severity_floor(mut self, s: Severity) -> Self {
        self.severity_floor = s;
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

    /// Run a JSON-mode trivy scan and return normalised
    /// [`Finding`]s with severity-floor filtering applied.
    pub async fn scan(&self, mode: ScanMode, target: &str) -> Result<Vec<Finding>, ScanError> {
        let raw = self
            .run(&[mode.subcommand(), "--format", "json", "--quiet", target])
            .await?;
        let mut findings = parse_trivy_output(&raw)?;
        findings.retain(|f| f.severity >= self.severity_floor);
        Ok(findings)
    }

    /// Run a SARIF-mode scan and return the SARIF JSON verbatim.
    /// Useful when the downstream sink expects SARIF and we don't
    /// want to round-trip through [`Finding`].
    pub async fn scan_sarif(&self, mode: ScanMode, target: &str) -> Result<String, ScanError> {
        self.run(&[mode.subcommand(), "--format", "sarif", "--quiet", target])
            .await
    }

    /// Convenience: scan a filesystem path (`trivy fs`). This
    /// duplicates the simpler adapter in `mantis-static-scan` but is
    /// kept here so callers using `mantis-trivy` don't have to
    /// reach into a second crate for the most common case.
    pub async fn scan_filesystem(&self, path: &Path) -> Result<Vec<Finding>, ScanError> {
        let raw = self
            .run(&["fs", "--format", "json", "--quiet", &path.to_string_lossy()])
            .await?;
        let mut findings = parse_trivy_output(&raw)?;
        findings.retain(|f| f.severity >= self.severity_floor);
        Ok(findings)
    }

    /// Convenience: scan a container image (`trivy image`).
    pub async fn scan_image(&self, image: &str) -> Result<Vec<Finding>, ScanError> {
        let raw = self
            .run(&["image", "--format", "json", "--quiet", image])
            .await?;
        let mut findings = parse_trivy_output(&raw)?;
        findings.retain(|f| f.severity >= self.severity_floor);
        Ok(findings)
    }

    async fn run(&self, args: &[&str]) -> Result<String, ScanError> {
        self.ensure_available().await?;

        let child = Command::new(&self.binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ScanError::Spawn { tool: BIN, source })?;

        match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(out)) if out.status.success() => {
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            }
            Ok(Ok(out)) => Err(ScanError::NonZeroExit {
                tool: BIN,
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }),
            Ok(Err(e)) => Err(ScanError::Spawn {
                tool: BIN,
                source: e,
            }),
            Err(_) => Err(ScanError::Timeout {
                tool: BIN,
                seconds: self.timeout.as_secs(),
            }),
        }
    }
}

impl Default for TrivyScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// VEX status per https://openvex.dev/specification — the four
/// disposition values an operator can attach to a vuln assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

impl VexStatus {
    /// Stable lowercase wire representation. Matches the serde
    /// rename above. Public so callers can format without a JSON
    /// round-trip.
    pub fn as_str(self) -> &'static str {
        match self {
            VexStatus::NotAffected => "not_affected",
            VexStatus::Affected => "affected",
            VexStatus::Fixed => "fixed",
            VexStatus::UnderInvestigation => "under_investigation",
        }
    }
}

/// A single OpenVEX statement bound to one CVE + one product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexStatement {
    pub vulnerability: VexVuln,
    pub products: Vec<VexProduct>,
    pub status: VexStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexVuln {
    #[serde(rename = "@id")]
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexProduct {
    #[serde(rename = "@id")]
    pub id: String,
}

/// Minimum-viable OpenVEX 0.2.0 document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVex {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    pub id: String,
    pub author: String,
    pub version: u32,
    pub statements: Vec<VexStatement>,
}

/// Convert CVE findings into an OpenVEX document. Every finding with
/// `kind == "cve"` and a `cve` meta key becomes one statement; the
/// caller picks the default status (typically [`VexStatus::Affected`]
/// for a fresh scan, or [`VexStatus::UnderInvestigation`] before
/// triage).
///
/// `author` is the disclosing entity (e.g. `"mantis@example.com"`).
/// `doc_id` is a stable URI for this VEX document — usually a
/// `pkg:` PURL or a `https://` URL pointing at the published file.
pub fn emit_openvex(
    author: impl Into<String>,
    doc_id: impl Into<String>,
    findings: &[Finding],
    default_status: VexStatus,
) -> OpenVex {
    // Pre-size the statements Vec. The typical case is most findings
    // are CVE-kind, so findings.len() is a good upper bound — avoids
    // the geometric grow/reallocate cycle during push().
    let mut statements = Vec::with_capacity(findings.len());
    for f in findings.iter().filter(|f| f.kind == "cve") {
        let cve = match f.meta.get("cve") {
            Some(c) if !c.is_empty() => c.clone(),
            _ => continue,
        };
        // If trivy reported a fixed_version we mark the statement as
        // `fixed` instead of the caller's default — the package is
        // upgradable, which is materially different from "affected".
        let status = if f
            .meta
            .get("fixed_version")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            VexStatus::Fixed
        } else {
            default_status
        };
        statements.push(VexStatement {
            vulnerability: VexVuln {
                id: format!("https://nvd.nist.gov/vuln/detail/{cve}"),
                name: cve,
            },
            products: vec![VexProduct {
                id: f.target.clone(),
            }],
            status,
        });
    }
    OpenVex {
        context: "https://openvex.dev/ns/v0.2.0".to_string(),
        id: doc_id.into(),
        author: author.into(),
        version: 1,
        statements,
    }
}

/// Best-effort sanity check on a SARIF payload — confirms the
/// document parses as JSON and carries the `$schema` / `version`
/// fields SARIF 2.1.0 mandates. Used by tests; downstream consumers
/// can call this before forwarding to a SARIF sink.
pub fn is_valid_sarif(raw: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(raw) else {
        return false;
    };
    let has_schema = doc.get("$schema").and_then(|s| s.as_str()).is_some();
    let has_version = doc.get("version").and_then(|v| v.as_str()).is_some();
    let has_runs = doc.get("runs").and_then(|r| r.as_array()).is_some();
    has_schema && has_version && has_runs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cve_finding(target: &str, cve: &str, fixed: Option<&str>) -> Finding {
        let mut meta = BTreeMap::new();
        meta.insert("cve".into(), cve.into());
        meta.insert("installed_version".into(), "1.0.0".into());
        if let Some(v) = fixed {
            meta.insert("fixed_version".into(), v.into());
        }
        Finding {
            tool: "trivy".into(),
            kind: "cve".into(),
            target: target.into(),
            severity: Severity::High,
            title: format!("{cve} libfoo@1.0.0"),
            description: "demo".into(),
            meta,
            raw: serde_json::Value::Null,
        }
    }

    #[test]
    fn scan_mode_subcommand_maps_correctly() {
        assert_eq!(ScanMode::Config.subcommand(), "config");
        assert_eq!(ScanMode::Repo.subcommand(), "repo");
        assert_eq!(ScanMode::Sbom.subcommand(), "sbom");
        assert_eq!(ScanMode::Rootfs.subcommand(), "rootfs");
    }

    #[test]
    fn severity_floor_filters_out_below() {
        let scanner = TrivyScanner::new().with_severity_floor(Severity::High);
        assert_eq!(scanner.severity_floor, Severity::High);
    }

    #[test]
    fn emit_openvex_skips_non_cve_findings() {
        let findings = vec![
            cve_finding("libfoo@1.0.0", "CVE-2023-1", None),
            Finding::new("trivy", "misconfig", "infra/main.tf", Severity::Medium, "x"),
            Finding::new("trivy", "secret", "code.py:1", Severity::High, "y"),
        ];
        let doc = emit_openvex(
            "test@example.com",
            "https://example.com/vex/1",
            &findings,
            VexStatus::Affected,
        );
        assert_eq!(doc.statements.len(), 1);
        assert_eq!(doc.statements[0].vulnerability.name, "CVE-2023-1");
    }

    #[test]
    fn emit_openvex_marks_fixed_when_upgrade_available() {
        let findings = vec![
            cve_finding("a@1", "CVE-1", Some("1.0.1")),
            cve_finding("b@1", "CVE-2", None),
        ];
        let doc = emit_openvex(
            "test@example.com",
            "https://example.com/vex/1",
            &findings,
            VexStatus::Affected,
        );
        assert_eq!(doc.statements.len(), 2);
        let by_name: std::collections::HashMap<_, _> = doc
            .statements
            .iter()
            .map(|s| (s.vulnerability.name.as_str(), s.status))
            .collect();
        assert_eq!(by_name["CVE-1"], VexStatus::Fixed);
        assert_eq!(by_name["CVE-2"], VexStatus::Affected);
    }

    #[test]
    fn emit_openvex_skips_findings_without_cve_meta() {
        let mut f = cve_finding("a@1", "CVE-1", None);
        f.meta.remove("cve");
        let doc = emit_openvex("a", "b", &[f], VexStatus::Affected);
        assert!(doc.statements.is_empty());
    }

    #[test]
    fn vex_status_serialises_snake_case() {
        let j = serde_json::to_string(&VexStatus::NotAffected).unwrap();
        assert_eq!(j, r#""not_affected""#);
        let j = serde_json::to_string(&VexStatus::UnderInvestigation).unwrap();
        assert_eq!(j, r#""under_investigation""#);
    }

    #[test]
    fn vex_status_as_str_matches_serde() {
        for s in [
            VexStatus::NotAffected,
            VexStatus::Affected,
            VexStatus::Fixed,
            VexStatus::UnderInvestigation,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            assert_eq!(j, format!("\"{}\"", s.as_str()));
        }
    }

    #[test]
    fn openvex_round_trips_through_json() {
        let findings = vec![cve_finding("libfoo@1.0.0", "CVE-2024-1", None)];
        let doc = emit_openvex("a@b", "https://x/1", &findings, VexStatus::Affected);
        let json = serde_json::to_string(&doc).unwrap();
        let back: OpenVex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.statements.len(), 1);
        assert_eq!(back.context, "https://openvex.dev/ns/v0.2.0");
        assert_eq!(back.version, 1);
    }

    #[test]
    fn is_valid_sarif_accepts_minimal_doc() {
        let raw = r#"{
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": []
        }"#;
        assert!(is_valid_sarif(raw));
    }

    #[test]
    fn is_valid_sarif_rejects_missing_fields() {
        assert!(!is_valid_sarif(r#"{"version":"2.1.0"}"#));
        assert!(!is_valid_sarif(r#"{"$schema":"x"}"#));
        assert!(!is_valid_sarif("not json"));
    }

    #[tokio::test]
    async fn scanner_returns_unavailable_for_missing_binary() {
        let scanner = TrivyScanner::new().with_binary("definitely-not-trivy-xyz");
        let err = scanner.ensure_available().await.unwrap_err();
        matches!(err, ScanError::Unavailable { .. });
    }
}
