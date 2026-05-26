//! Adapter for [`trivy`](https://github.com/aquasecurity/trivy) —
//! Aqua Security's all-in-one vulnerability / misconfiguration / secret
//! scanner. Unlike the other adapters in this crate, trivy emits a
//! single JSON document (not JSONL) containing a `Results` array; each
//! result groups vulnerabilities, misconfigurations, and secrets by
//! target (image, lockfile, IaC file).
//!
//! Install: `brew install trivy` or follow
//! https://aquasecurity.github.io/trivy/latest/getting-started/installation/.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::{Finding, ScanError, Severity, binary_available};

const BIN: &str = "trivy";
const INSTALL_HINT: &str =
    "`brew install trivy` (or follow https://aquasecurity.github.io/trivy/latest/getting-started/installation/)";
const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Shell-out adapter for `trivy`.
pub struct TrivyAdapter {
    binary: String,
    timeout: Duration,
}

impl TrivyAdapter {
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

impl Default for TrivyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TrivyAdapter {
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

    /// Scan a filesystem path (`trivy fs --format json --quiet <path>`).
    pub async fn scan_filesystem(&self, path: &Path) -> Result<Vec<Finding>, ScanError> {
        self.run(&["fs", "--format", "json", "--quiet", &path.to_string_lossy()])
            .await
    }

    /// Scan a container image (`trivy image --format json --quiet <image>`).
    pub async fn scan_image(&self, image: &str) -> Result<Vec<Finding>, ScanError> {
        self.run(&["image", "--format", "json", "--quiet", image]).await
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
        parse_trivy_output(raw)
    }
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

/// Pure parser: take trivy's captured JSON document and flatten
/// `Results[*].{Vulnerabilities, Misconfigurations, Secrets}` into
/// individual [`Finding`]s.
pub fn parse_trivy_output(raw: &str) -> Result<Vec<Finding>, ScanError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let doc: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| ScanError::BadOutput(format!("invalid trivy JSON: {e}")))?;

    let mut findings = Vec::new();
    let results = match doc.get("Results").and_then(|r| r.as_array()) {
        Some(r) => r,
        None => return Ok(findings),
    };

    for result in results {
        let target_label = str_field(result, "Target");

        if let Some(vulns) = result.get("Vulnerabilities").and_then(|v| v.as_array()) {
            for v in vulns {
                let cve = str_field(v, "VulnerabilityID");
                let pkg = str_field(v, "PkgName");
                let installed = str_field(v, "InstalledVersion");
                let fixed = str_field(v, "FixedVersion");
                let severity = Severity::parse(&str_field(v, "Severity"));
                let title = str_field(v, "Title");
                let description = str_field(v, "Description");

                let finding_target = format!("{pkg}@{installed} in {target_label}");
                let finding_title = if title.is_empty() {
                    format!("{cve} {pkg}@{installed}")
                } else {
                    format!("{cve} {pkg}@{installed}: {title}")
                };

                let mut f = Finding::new("trivy", "cve", finding_target, severity, finding_title)
                    .with_description(description)
                    .with_raw(v.clone());
                if !cve.is_empty() {
                    f = f.with_meta("cve", cve);
                }
                if !installed.is_empty() {
                    f = f.with_meta("installed_version", installed);
                }
                if !fixed.is_empty() {
                    f = f.with_meta("fixed_version", fixed);
                }
                if !pkg.is_empty() {
                    f = f.with_meta("package", pkg);
                }
                findings.push(f);
            }
        }

        if let Some(miscs) = result.get("Misconfigurations").and_then(|v| v.as_array()) {
            for m in miscs {
                let id = str_field(m, "ID");
                let title = str_field(m, "Title");
                let description = str_field(m, "Description");
                let severity = Severity::parse(&str_field(m, "Severity"));

                let finding_title = if title.is_empty() {
                    format!("misconfig {id}")
                } else {
                    format!("{id}: {title}")
                };

                let mut f = Finding::new(
                    "trivy",
                    "misconfig",
                    target_label.clone(),
                    severity,
                    finding_title,
                )
                .with_description(description)
                .with_raw(m.clone());
                if !id.is_empty() {
                    f = f.with_meta("id", id);
                }
                findings.push(f);
            }
        }

        if let Some(secrets) = result.get("Secrets").and_then(|v| v.as_array()) {
            for s in secrets {
                let rule_id = str_field(s, "RuleID");
                let category = str_field(s, "Category");
                let title = str_field(s, "Title");
                let severity = Severity::parse(&str_field(s, "Severity"));
                let match_text = str_field(s, "Match");
                let start_line = s
                    .get("StartLine")
                    .and_then(|v| match v {
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        serde_json::Value::String(x) => Some(x.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();

                let finding_target = if start_line.is_empty() {
                    target_label.clone()
                } else {
                    format!("{target_label}:{start_line}")
                };
                let finding_title = if title.is_empty() {
                    format!("secret {rule_id}")
                } else {
                    format!("{rule_id}: {title}")
                };

                let mut f = Finding::new(
                    "trivy",
                    "secret",
                    finding_target,
                    severity,
                    finding_title,
                )
                .with_description(match_text)
                .with_raw(s.clone());
                if !rule_id.is_empty() {
                    f = f.with_meta("rule_id", rule_id);
                }
                if !category.is_empty() {
                    f = f.with_meta("category", category);
                }
                if !start_line.is_empty() {
                    f = f.with_meta("line", start_line);
                }
                findings.push(f);
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trivy_vulnerabilities_fixture() {
        let raw = r#"{
            "SchemaVersion": 2,
            "ArtifactName": "alpine:3.18",
            "ArtifactType": "container_image",
            "Results": [{
                "Target": "alpine:3.18 (alpine 3.18.0)",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.1",
                        "FixedVersion": "3.0.2",
                        "Severity": "HIGH",
                        "Title": "OpenSSL flaw",
                        "Description": "Buffer overflow in TLS handshake"
                    },
                    {
                        "VulnerabilityID": "CVE-2024-5678",
                        "PkgName": "musl",
                        "InstalledVersion": "1.2.0",
                        "FixedVersion": "",
                        "Severity": "CRITICAL",
                        "Description": "RCE via libc parser"
                    }
                ]
            }]
        }"#;
        let findings = parse_trivy_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 2);

        let a = &findings[0];
        assert_eq!(a.tool, "trivy");
        assert_eq!(a.kind, "cve");
        assert_eq!(a.target, "openssl@3.0.1 in alpine:3.18 (alpine 3.18.0)");
        assert_eq!(a.severity, Severity::High);
        assert!(a.title.contains("CVE-2023-1234"));
        assert!(a.title.contains("openssl@3.0.1"));
        assert_eq!(a.description, "Buffer overflow in TLS handshake");
        assert_eq!(a.meta.get("cve").map(String::as_str), Some("CVE-2023-1234"));
        assert_eq!(
            a.meta.get("installed_version").map(String::as_str),
            Some("3.0.1")
        );
        assert_eq!(a.meta.get("fixed_version").map(String::as_str), Some("3.0.2"));
        assert_eq!(a.meta.get("package").map(String::as_str), Some("openssl"));

        let b = &findings[1];
        assert_eq!(b.severity, Severity::Critical);
        // fixed_version was empty → must not be inserted
        assert!(b.meta.get("fixed_version").is_none());
    }

    #[test]
    fn parses_trivy_misconfig_and_secret_fixture() {
        let raw = r#"{
            "SchemaVersion": 2,
            "ArtifactName": "./infra",
            "ArtifactType": "filesystem",
            "Results": [{
                "Target": "infra/main.tf",
                "Class": "config",
                "Type": "terraform",
                "Misconfigurations": [
                    {
                        "ID": "AVD-AWS-0061",
                        "Title": "IAM role permits *",
                        "Description": "Wildcard action on IAM role",
                        "Severity": "MEDIUM"
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key",
                        "Category": "AWS",
                        "Title": "AWS Access Key",
                        "Severity": "CRITICAL",
                        "StartLine": 11,
                        "Match": "AKIAIOSFODNN7EXAMPLE"
                    }
                ]
            }]
        }"#;
        let findings = parse_trivy_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 2);

        let m = findings.iter().find(|f| f.kind == "misconfig").unwrap();
        assert_eq!(m.tool, "trivy");
        assert_eq!(m.target, "infra/main.tf");
        assert_eq!(m.severity, Severity::Medium);
        assert!(m.title.contains("AVD-AWS-0061"));
        assert_eq!(m.meta.get("id").map(String::as_str), Some("AVD-AWS-0061"));

        let s = findings.iter().find(|f| f.kind == "secret").unwrap();
        assert_eq!(s.target, "infra/main.tf:11");
        assert_eq!(s.severity, Severity::Critical);
        assert_eq!(s.meta.get("rule_id").map(String::as_str), Some("aws-access-key"));
        assert_eq!(s.meta.get("category").map(String::as_str), Some("AWS"));
        assert_eq!(s.meta.get("line").map(String::as_str), Some("11"));
    }

    #[test]
    fn empty_or_resultsless_trivy_json_yields_zero_findings() {
        let raw = r#"{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"image"}"#;
        let findings = parse_trivy_output(raw).expect("parse ok");
        assert_eq!(findings.len(), 0);

        let findings_empty = parse_trivy_output("").expect("parse ok");
        assert_eq!(findings_empty.len(), 0);
    }

    #[test]
    fn errors_on_malformed_trivy_json() {
        let raw = "{not json}";
        let err = parse_trivy_output(raw).unwrap_err();
        match err {
            ScanError::BadOutput(msg) => assert!(msg.contains("invalid trivy JSON")),
            other => panic!("expected BadOutput, got {other:?}"),
        }
    }
}
