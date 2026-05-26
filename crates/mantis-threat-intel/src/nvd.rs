//! NVD CVE 2.0 JSON reader.
//!
//! NVD publishes CVE data in the CVE 2.0 JSON schema at
//! <https://nvd.nist.gov/developers/vulnerabilities>. A page-shaped response
//! envelope wraps a `vulnerabilities` array; each item carries a `cve` object
//! with `id`, `descriptions`, `metrics` (CVSS v2 / v3.0 / v3.1 / v4.0),
//! `weaknesses` (CWE list), and `references`.
//!
//! Mantis consumes the subset needed for hypothesis prioritization and
//! report enrichment: ID, English description, primary CVSS score and
//! severity bucket, and CWE references.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Errors returned when parsing NVD payloads.
#[derive(Debug, thiserror::Error)]
pub enum NvdError {
    /// JSON parse failure.
    #[error("failed to parse NVD JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

/// CVSS severity bucket as reported by NVD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// No metric / unscored.
    None,
    /// 0.0
    Informational,
    /// 0.1–3.9
    Low,
    /// 4.0–6.9
    Medium,
    /// 7.0–8.9
    High,
    /// 9.0–10.0
    Critical,
}

impl Severity {
    /// Map a numeric base score to the NVD severity bucket using CVSS v3 cuts.
    pub fn from_base_score(score: f32) -> Self {
        if score <= 0.0 {
            Self::Informational
        } else if score < 4.0 {
            Self::Low
        } else if score < 7.0 {
            Self::Medium
        } else if score < 9.0 {
            Self::High
        } else {
            Self::Critical
        }
    }

    /// Parse the NVD textual severity (`"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`).
    pub fn from_label(label: &str) -> Self {
        match label.to_ascii_uppercase().as_str() {
            "INFORMATIONAL" => Self::Informational,
            "LOW" => Self::Low,
            "MEDIUM" => Self::Medium,
            "HIGH" => Self::High,
            "CRITICAL" => Self::Critical,
            _ => Self::None,
        }
    }
}

/// Subset of one CVE record from NVD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    /// CVE identifier, e.g. `"CVE-2021-44228"`.
    pub id: String,
    /// English description (concatenation of all `lang == "en"` descriptions).
    pub description: String,
    /// Highest-tier CVSS base score we found (v4 > v3.1 > v3.0 > v2).
    pub base_score: Option<f32>,
    /// Severity bucket corresponding to `base_score`.
    pub severity: Severity,
    /// CWE identifiers referenced in `weaknesses`.
    pub cwes: Vec<String>,
    /// Published date (ISO 8601 string from NVD).
    pub published: String,
    /// Last modified date.
    pub last_modified: String,
}

/// Raw envelope of the NVD CVE 2.0 page response.
#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    vulnerabilities: Vec<VulnEntry>,
}

#[derive(Debug, Deserialize)]
struct VulnEntry {
    cve: RawCve,
}

#[derive(Debug, Deserialize)]
struct RawCve {
    id: String,
    #[serde(default)]
    descriptions: Vec<LangString>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    weaknesses: Vec<Weakness>,
    #[serde(default)]
    published: String,
    #[serde(rename = "lastModified", default)]
    last_modified: String,
}

#[derive(Debug, Default, Deserialize)]
struct Metrics {
    #[serde(rename = "cvssMetricV40", default)]
    v4: Vec<MetricEntry>,
    #[serde(rename = "cvssMetricV31", default)]
    v31: Vec<MetricEntry>,
    #[serde(rename = "cvssMetricV30", default)]
    v30: Vec<MetricEntry>,
    #[serde(rename = "cvssMetricV2", default)]
    v2: Vec<MetricEntry>,
}

#[derive(Debug, Deserialize)]
struct MetricEntry {
    #[serde(rename = "cvssData", default)]
    cvss_data: CvssData,
    #[serde(default, rename = "baseSeverity")]
    base_severity: String,
}

#[derive(Debug, Default, Deserialize)]
struct CvssData {
    #[serde(default, rename = "baseScore")]
    base_score: f32,
    #[serde(default, rename = "baseSeverity")]
    base_severity: String,
}

#[derive(Debug, Deserialize)]
struct LangString {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct Weakness {
    #[serde(default)]
    description: Vec<LangString>,
}

impl Cve {
    /// Parse a single CVE record from the NVD per-CVE JSON shape (the body
    /// returned by `/rest/json/cves/2.0` with a single ID query).
    ///
    /// Accepts either the page envelope `{ "vulnerabilities": [...] }` or a
    /// raw `{ "cve": { ... } }` wrapper.
    pub fn from_json(json: &str) -> Result<Self, NvdError> {
        // Try the page-envelope shape first, then fall back to the single-entry shape.
        if let Ok(env) = serde_json::from_str::<Envelope>(json) {
            if let Some(first) = env.vulnerabilities.into_iter().next() {
                return Ok(Self::from_raw(first.cve));
            }
        }
        let entry: VulnEntry = serde_json::from_str(json)?;
        Ok(Self::from_raw(entry.cve))
    }

    fn from_raw(raw: RawCve) -> Self {
        let description = raw
            .descriptions
            .iter()
            .filter(|d| d.lang.eq_ignore_ascii_case("en"))
            .map(|d| d.value.as_str())
            .collect::<Vec<&str>>()
            .join(" ");

        let (base_score, severity) = best_metric(&raw.metrics);

        let cwes = raw
            .weaknesses
            .into_iter()
            .flat_map(|w| {
                w.description
                    .into_iter()
                    .filter(|d| d.lang.eq_ignore_ascii_case("en"))
                    .map(|d| d.value)
            })
            .filter(|v| v.starts_with("CWE-"))
            .collect();

        Self {
            id: raw.id,
            description,
            base_score,
            severity,
            cwes,
            published: raw.published,
            last_modified: raw.last_modified,
        }
    }
}

/// Pick the best (highest-tier) CVSS metric: v4 → v3.1 → v3.0 → v2.
fn best_metric(m: &Metrics) -> (Option<f32>, Severity) {
    let pick = |tier: &[MetricEntry]| -> Option<(f32, String)> {
        tier.first().map(|e| {
            let label = if !e.base_severity.is_empty() {
                e.base_severity.clone()
            } else {
                e.cvss_data.base_severity.clone()
            };
            (e.cvss_data.base_score, label)
        })
    };
    let chosen = pick(&m.v4).or_else(|| pick(&m.v31)).or_else(|| pick(&m.v30)).or_else(|| pick(&m.v2));
    match chosen {
        Some((score, label)) if !label.is_empty() => (Some(score), Severity::from_label(&label)),
        Some((score, _)) => (Some(score), Severity::from_base_score(score)),
        None => (None, Severity::None),
    }
}

/// In-memory index of many CVEs keyed by CVE ID (case-insensitive on lookup).
#[derive(Debug, Default, Clone)]
pub struct CveIndex {
    by_id: HashMap<String, Cve>,
}

impl CveIndex {
    /// Empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from an NVD page envelope (`{ "vulnerabilities": [...] }`).
    pub fn from_envelope_json(json: &str) -> Result<Self, NvdError> {
        let env: Envelope = serde_json::from_str(json)?;
        let mut idx = Self::new();
        for entry in env.vulnerabilities {
            idx.insert(Cve::from_raw(entry.cve));
        }
        Ok(idx)
    }

    /// Insert one CVE.
    pub fn insert(&mut self, cve: Cve) {
        self.by_id.insert(cve.id.to_ascii_uppercase(), cve);
    }

    /// Number of indexed CVEs.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Lookup by CVE id, case-insensitive.
    pub fn lookup(&self, cve_id: &str) -> Option<&Cve> {
        self.by_id.get(&cve_id.to_ascii_uppercase())
    }

    /// Iterate all entries.
    pub fn entries(&self) -> impl Iterator<Item = &Cve> {
        self.by_id.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENVELOPE: &str = r#"{
        "resultsPerPage": 1,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2024-04-03T17:15:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints."},
                        {"lang": "es", "value": "Las características JNDI..."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL"
                                },
                                "baseSeverity": "CRITICAL"
                            }
                        ],
                        "cvssMetricV2": [
                            {
                                "cvssData": {"baseScore": 9.3},
                                "baseSeverity": "HIGH"
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-20"}]
                        },
                        {
                            "source": "secondary",
                            "type": "Secondary",
                            "description": [{"lang": "en", "value": "CWE-917"}]
                        }
                    ]
                }
            }
        ]
    }"#;

    #[test]
    fn parses_envelope_to_single_cve() {
        let cve = Cve::from_json(ENVELOPE).unwrap();
        assert_eq!(cve.id, "CVE-2021-44228");
        assert!(cve.description.contains("Log4j2"));
        assert_eq!(cve.base_score, Some(10.0));
        assert_eq!(cve.severity, Severity::Critical);
        assert_eq!(cve.cwes, vec!["CWE-20", "CWE-917"]);
    }

    #[test]
    fn from_envelope_json_builds_index() {
        let idx = CveIndex::from_envelope_json(ENVELOPE).unwrap();
        assert_eq!(idx.len(), 1);
        assert!(!idx.is_empty());
        assert!(idx.lookup("cve-2021-44228").is_some());
    }

    #[test]
    fn severity_from_base_score_buckets() {
        assert_eq!(Severity::from_base_score(0.0), Severity::Informational);
        assert_eq!(Severity::from_base_score(3.9), Severity::Low);
        assert_eq!(Severity::from_base_score(4.0), Severity::Medium);
        assert_eq!(Severity::from_base_score(6.9), Severity::Medium);
        assert_eq!(Severity::from_base_score(7.0), Severity::High);
        assert_eq!(Severity::from_base_score(8.9), Severity::High);
        assert_eq!(Severity::from_base_score(9.0), Severity::Critical);
        assert_eq!(Severity::from_base_score(10.0), Severity::Critical);
    }

    #[test]
    fn severity_from_label_uppercased() {
        assert_eq!(Severity::from_label("low"), Severity::Low);
        assert_eq!(Severity::from_label("Medium"), Severity::Medium);
        assert_eq!(Severity::from_label("HIGH"), Severity::High);
        assert_eq!(Severity::from_label("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_label("garbage"), Severity::None);
    }

    #[test]
    fn description_includes_only_english() {
        let cve = Cve::from_json(ENVELOPE).unwrap();
        // Spanish description must be excluded.
        assert!(!cve.description.contains("Las características"));
    }

    #[test]
    fn prefers_v31_over_v2() {
        let cve = Cve::from_json(ENVELOPE).unwrap();
        // V3.1 says 10.0; V2 says 9.3. Best metric is V3.1.
        assert_eq!(cve.base_score, Some(10.0));
    }

    #[test]
    fn handles_no_metrics() {
        let json = r#"{
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [{"lang": "en", "value": "Test"}]
                }
            }]
        }"#;
        let cve = Cve::from_json(json).unwrap();
        assert_eq!(cve.base_score, None);
        assert_eq!(cve.severity, Severity::None);
    }

    #[test]
    fn weaknesses_filter_non_cwe_strings() {
        let json = r#"{
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0002",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "weaknesses": [{
                        "description": [
                            {"lang": "en", "value": "CWE-79"},
                            {"lang": "en", "value": "NVD-CWE-Other"}
                        ]
                    }]
                }
            }]
        }"#;
        let cve = Cve::from_json(json).unwrap();
        assert_eq!(cve.cwes, vec!["CWE-79"]);
    }

    #[test]
    fn parse_error_for_malformed_json() {
        let err = Cve::from_json("{ broken").unwrap_err();
        assert!(matches!(err, NvdError::Parse(_)));
    }

    #[test]
    fn falls_back_to_score_derived_severity_when_label_missing() {
        let json = r#"{
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0003",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 8.1}
                        }]
                    }
                }
            }]
        }"#;
        let cve = Cve::from_json(json).unwrap();
        assert_eq!(cve.base_score, Some(8.1));
        assert_eq!(cve.severity, Severity::High);
    }

    #[test]
    fn index_lookup_is_case_insensitive() {
        let idx = CveIndex::from_envelope_json(ENVELOPE).unwrap();
        assert!(idx.lookup("CVE-2021-44228").is_some());
        assert!(idx.lookup("cve-2021-44228").is_some());
        assert!(idx.lookup("CVE-2099-9999").is_none());
    }

    #[test]
    fn iter_entries_returns_all() {
        let idx = CveIndex::from_envelope_json(ENVELOPE).unwrap();
        assert_eq!(idx.entries().count(), 1);
    }
}
