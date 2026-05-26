//! GitHub Security Advisory (GHSA) reader, OSV-format.
//!
//! GitHub publishes the GHSA database in the OSV (Open Source Vulnerability)
//! schema at <https://github.com/github/advisory-database>. Each advisory is
//! one JSON file like:
//!
//! ```jsonc
//! {
//!   "id": "GHSA-jfh8-c2jp-5v3q",
//!   "aliases": ["CVE-2021-44228"],
//!   "summary": "Remote code execution in Log4j",
//!   "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
//!   "affected": [{ "package": { "ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core" } }]
//! }
//! ```
//!
//! This module models the subset Mantis consumes for prioritization. Use
//! [`Advisory::from_json`] for a single record or [`AdvisoryIndex`] to build
//! a CVE → GHSA lookup over many advisories.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Errors returned when parsing GHSA OSV documents.
#[derive(Debug, thiserror::Error)]
pub enum GhsaError {
    /// The provided JSON was not a valid OSV document.
    #[error("failed to parse GHSA/OSV JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Severity entry from the OSV `severity` array.
///
/// OSV allows multiple severity entries (e.g. CVSS_V2 + CVSS_V3 + CVSS_V4).
/// Mantis preserves them all; consumers pick the one they prefer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Severity {
    /// Severity type label (e.g. `"CVSS_V3"`, `"CVSS_V4"`).
    #[serde(rename = "type", default)]
    pub kind: String,
    /// Score string in the type-specific format (e.g. a CVSS vector).
    #[serde(default)]
    pub score: String,
}

/// Affected-package entry from OSV `affected[].package`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// OSV ecosystem (e.g. `"npm"`, `"Maven"`, `"PyPI"`, `"Go"`, `"crates.io"`).
    #[serde(default)]
    pub ecosystem: String,
    /// Package name within the ecosystem.
    #[serde(default)]
    pub name: String,
    /// PURL (Package URL), present on most modern OSV entries.
    #[serde(default)]
    pub purl: Option<String>,
}

/// Affected entry pairing a package with version ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Affected {
    /// Affected package identifier.
    #[serde(default)]
    pub package: Option<Package>,
    /// Specific affected versions (when ranges aren't enumerable).
    #[serde(default)]
    pub versions: Vec<String>,
}

/// One advisory in OSV format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    /// Advisory ID, e.g. `"GHSA-jfh8-c2jp-5v3q"`.
    pub id: String,
    /// Alternative identifiers, typically including the CVE ID.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// One-line summary.
    #[serde(default)]
    pub summary: String,
    /// Long-form description.
    #[serde(default)]
    pub details: String,
    /// Severity entries (CVSS or other).
    #[serde(default)]
    pub severity: Vec<Severity>,
    /// Affected packages with version ranges.
    #[serde(default)]
    pub affected: Vec<Affected>,
    /// Publication timestamp in RFC 3339 form (empty when unknown).
    #[serde(default)]
    pub published: String,
    /// Last-modified timestamp in RFC 3339 form (empty when unknown).
    #[serde(default)]
    pub modified: String,
}

impl Advisory {
    /// Parse a single OSV-formatted advisory from JSON text.
    pub fn from_json(json: &str) -> Result<Self, GhsaError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Return CVE aliases (entries starting with `CVE-`, case-insensitive).
    pub fn cve_aliases(&self) -> impl Iterator<Item = &str> {
        self.aliases
            .iter()
            .map(String::as_str)
            .filter(|a| a.len() >= 4 && a[..4].eq_ignore_ascii_case("CVE-"))
    }

    /// Pick the highest-version CVSS severity, preferring V4 over V3 over V2.
    /// Returns `None` if no CVSS-shaped severity is present.
    pub fn primary_cvss(&self) -> Option<&Severity> {
        // OSV severity `type` field is freeform but well-known values are
        // `"CVSS_V2"`, `"CVSS_V3"`, `"CVSS_V4"`. Higher beats lower.
        const ORDER: &[&str] = &["CVSS_V4", "CVSS_V3", "CVSS_V2"];
        for label in ORDER {
            if let Some(s) = self.severity.iter().find(|s| s.kind == *label) {
                return Some(s);
            }
        }
        self.severity.first()
    }

    /// Ecosystems this advisory affects, deduplicated.
    pub fn affected_ecosystems(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .affected
            .iter()
            .filter_map(|a| a.package.as_ref().map(|p| p.ecosystem.as_str()))
            .filter(|s| !s.is_empty())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// In-memory index of many advisories, keyed for fast CVE lookup.
#[derive(Debug, Default, Clone)]
pub struct AdvisoryIndex {
    by_ghsa: HashMap<String, Advisory>,
    by_cve: HashMap<String, String>, // CVE-id (upper) -> GHSA id
}

impl AdvisoryIndex {
    /// Empty index; populate with [`AdvisoryIndex::insert`] or
    /// [`AdvisoryIndex::extend`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an index from an iterable of advisories.
    pub fn from_advisories(advs: impl IntoIterator<Item = Advisory>) -> Self {
        let mut idx = Self::new();
        idx.extend(advs);
        idx
    }

    /// Insert one advisory. Re-inserting the same GHSA ID overwrites.
    pub fn insert(&mut self, adv: Advisory) {
        for cve in adv.cve_aliases() {
            self.by_cve.insert(cve.to_ascii_uppercase(), adv.id.clone());
        }
        self.by_ghsa.insert(adv.id.clone(), adv);
    }

    /// Insert many.
    pub fn extend(&mut self, advs: impl IntoIterator<Item = Advisory>) {
        for adv in advs {
            self.insert(adv);
        }
    }

    /// Number of indexed advisories.
    pub fn len(&self) -> usize {
        self.by_ghsa.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.by_ghsa.is_empty()
    }

    /// Look up an advisory by its GHSA ID. Case-sensitive (GHSA IDs are not).
    pub fn by_ghsa_id(&self, ghsa_id: &str) -> Option<&Advisory> {
        self.by_ghsa.get(ghsa_id)
    }

    /// Look up an advisory by a CVE alias. Case-insensitive.
    pub fn by_cve(&self, cve_id: &str) -> Option<&Advisory> {
        let ghsa = self.by_cve.get(&cve_id.to_ascii_uppercase())?;
        self.by_ghsa.get(ghsa)
    }

    /// Iterate all advisories in arbitrary order.
    pub fn advisories(&self) -> impl Iterator<Item = &Advisory> {
        self.by_ghsa.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG4J: &str = r#"{
        "id": "GHSA-jfh8-c2jp-5v3q",
        "aliases": ["CVE-2021-44228"],
        "summary": "Remote code execution in Log4j",
        "details": "Apache Log4j 2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "severity": [
            { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }
        ],
        "affected": [
            {
                "package": {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"
                },
                "versions": ["2.0", "2.1"]
            }
        ],
        "published": "2021-12-10T00:00:00Z",
        "modified": "2022-01-15T00:00:00Z"
    }"#;

    const NPM_ADVISORY: &str = r#"{
        "id": "GHSA-1234-5678-90ab",
        "aliases": ["CVE-2024-0001"],
        "summary": "Prototype pollution in left-pad",
        "severity": [
            { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
            { "type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }
        ],
        "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}}]
    }"#;

    #[test]
    fn parses_full_advisory() {
        let a = Advisory::from_json(LOG4J).unwrap();
        assert_eq!(a.id, "GHSA-jfh8-c2jp-5v3q");
        assert_eq!(a.aliases, vec!["CVE-2021-44228"]);
        assert!(a.summary.contains("Log4j"));
        assert_eq!(a.affected.len(), 1);
    }

    #[test]
    fn cve_aliases_filtered_from_alias_list() {
        let a = Advisory {
            id: "GHSA-x".into(),
            aliases: vec![
                "CVE-2024-0001".into(),
                "GHSA-other".into(),
                "cve-2024-0002".into(),
            ],
            ..serde_json::from_str::<Advisory>(LOG4J).unwrap()
        };
        let cves: Vec<&str> = a.cve_aliases().collect();
        assert_eq!(cves.len(), 2);
        assert!(cves.contains(&"CVE-2024-0001"));
        assert!(cves.contains(&"cve-2024-0002"));
    }

    #[test]
    fn primary_cvss_prefers_v4_over_v3() {
        let a = Advisory::from_json(NPM_ADVISORY).unwrap();
        let s = a.primary_cvss().unwrap();
        assert_eq!(s.kind, "CVSS_V4");
    }

    #[test]
    fn primary_cvss_falls_back_to_v3_when_only_v3_present() {
        let a = Advisory::from_json(LOG4J).unwrap();
        let s = a.primary_cvss().unwrap();
        assert_eq!(s.kind, "CVSS_V3");
    }

    #[test]
    fn primary_cvss_returns_none_when_no_severity() {
        let json = r#"{"id":"GHSA-empty","aliases":[]}"#;
        let a = Advisory::from_json(json).unwrap();
        assert!(a.primary_cvss().is_none());
    }

    #[test]
    fn affected_ecosystems_are_deduped() {
        let json = r#"{
            "id": "GHSA-dup",
            "affected": [
                {"package": {"ecosystem": "npm", "name": "a"}},
                {"package": {"ecosystem": "npm", "name": "b"}},
                {"package": {"ecosystem": "PyPI", "name": "c"}}
            ]
        }"#;
        let a = Advisory::from_json(json).unwrap();
        let mut eco = a.affected_ecosystems();
        eco.sort();
        assert_eq!(eco, vec!["PyPI", "npm"]);
    }

    #[test]
    fn index_round_trips_advisories() {
        let log4j = Advisory::from_json(LOG4J).unwrap();
        let npm = Advisory::from_json(NPM_ADVISORY).unwrap();
        let idx = AdvisoryIndex::from_advisories([log4j, npm]);
        assert_eq!(idx.len(), 2);
        assert!(!idx.is_empty());
    }

    #[test]
    fn index_lookup_by_cve_is_case_insensitive() {
        let log4j = Advisory::from_json(LOG4J).unwrap();
        let idx = AdvisoryIndex::from_advisories([log4j]);
        assert!(idx.by_cve("CVE-2021-44228").is_some());
        assert!(idx.by_cve("cve-2021-44228").is_some());
        assert!(idx.by_cve("Cve-2021-44228").is_some());
    }

    #[test]
    fn index_lookup_by_ghsa_id() {
        let log4j = Advisory::from_json(LOG4J).unwrap();
        let idx = AdvisoryIndex::from_advisories([log4j]);
        assert!(idx.by_ghsa_id("GHSA-jfh8-c2jp-5v3q").is_some());
        assert!(idx.by_ghsa_id("does-not-exist").is_none());
    }

    #[test]
    fn index_lookup_returns_none_for_unknown_cve() {
        let idx = AdvisoryIndex::from_advisories([Advisory::from_json(LOG4J).unwrap()]);
        assert!(idx.by_cve("CVE-2099-9999").is_none());
    }

    #[test]
    fn parse_error_is_returned_for_bad_json() {
        let err = Advisory::from_json("{").unwrap_err();
        assert!(matches!(err, GhsaError::Parse(_)));
    }

    #[test]
    fn tolerates_unknown_upstream_fields() {
        let json = r#"{
            "id": "GHSA-tolerant",
            "future_field": {"nested": [1, 2, 3]}
        }"#;
        let a = Advisory::from_json(json).unwrap();
        assert_eq!(a.id, "GHSA-tolerant");
    }

    #[test]
    fn iter_advisories_returns_all() {
        let idx = AdvisoryIndex::from_advisories([
            Advisory::from_json(LOG4J).unwrap(),
            Advisory::from_json(NPM_ADVISORY).unwrap(),
        ]);
        assert_eq!(idx.advisories().count(), 2);
    }
}
