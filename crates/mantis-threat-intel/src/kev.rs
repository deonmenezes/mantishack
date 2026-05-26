//! CISA Known Exploited Vulnerabilities (KEV) catalog reader.
//!
//! The CISA KEV catalog enumerates CVEs that have been observed exploited in
//! the wild. Mantis uses it to escalate hypothesis priority for any CVE-tagged
//! finding that intersects the catalog.
//!
//! Source feed (operator-side fetch — *not* a target HTTP call, so it does not
//! route through `mantis-egress`): <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
//!
//! The catalog is a JSON document with a `vulnerabilities` array; each entry
//! carries `cveID`, vendor/product, dates, required action, and a
//! `knownRansomwareCampaignUse` flag. This module models only the fields Mantis
//! consumes and tolerates upstream additions via `#[serde(default)]`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Errors returned when loading or querying the KEV catalog.
#[derive(Debug, thiserror::Error)]
pub enum KevError {
    /// The provided JSON was not a valid KEV catalog document.
    #[error("failed to parse KEV catalog JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Whether a KEV entry is tied to a known ransomware campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RansomwareUse {
    /// CISA has linked the CVE to an active ransomware campaign.
    Known,
    /// CISA has not linked the CVE to a ransomware campaign.
    Unknown,
}

impl RansomwareUse {
    fn from_feed(raw: &str) -> Self {
        if raw.eq_ignore_ascii_case("known") {
            Self::Known
        } else {
            Self::Unknown
        }
    }
}

/// Priority bucket Mantis assigns to a CVE based on its KEV membership.
///
/// The score is an integer 0–100 so it can be combined linearly with other
/// signal sources (CVSS, exploit availability, network exposure) in the
/// planner without introducing yet another enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevPriority(pub u8);

impl KevPriority {
    /// Score for a CVE that is not on the KEV list.
    pub const NOT_IN_KEV: KevPriority = KevPriority(0);
    /// Score for a KEV-listed CVE with no ransomware association.
    pub const IN_KEV: KevPriority = KevPriority(75);
    /// Score for a KEV-listed CVE tied to a known ransomware campaign.
    pub const IN_KEV_RANSOMWARE: KevPriority = KevPriority(100);

    /// Numeric score in the range 0..=100.
    pub fn score(self) -> u8 {
        self.0
    }
}

/// A single entry in the KEV catalog.
///
/// Only fields Mantis consumes are modeled; the upstream feed carries
/// additional fields that are silently ignored via `serde(default)` on the
/// catalog container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    /// CVE identifier, e.g. `CVE-2021-44228`.
    #[serde(rename = "cveID")]
    pub cve_id: String,
    /// Vendor or project name.
    #[serde(rename = "vendorProject", default)]
    pub vendor_project: String,
    /// Affected product name.
    #[serde(default)]
    pub product: String,
    /// Human-readable vulnerability name.
    #[serde(rename = "vulnerabilityName", default)]
    pub vulnerability_name: String,
    /// Date CISA added the CVE to the catalog (YYYY-MM-DD).
    #[serde(rename = "dateAdded", default)]
    pub date_added: String,
    /// Short description of the vulnerability.
    #[serde(rename = "shortDescription", default)]
    pub short_description: String,
    /// Action federal agencies are required to take.
    #[serde(rename = "requiredAction", default)]
    pub required_action: String,
    /// Deadline for the required action (YYYY-MM-DD).
    #[serde(rename = "dueDate", default)]
    pub due_date: String,
    /// Ransomware-campaign association as reported by CISA.
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    pub known_ransomware_campaign_use: String,
    /// CWE identifiers associated with the entry.
    #[serde(default)]
    pub cwes: Vec<String>,
}

impl KevEntry {
    /// Returns the ransomware-use bucket for this entry.
    pub fn ransomware_use(&self) -> RansomwareUse {
        RansomwareUse::from_feed(&self.known_ransomware_campaign_use)
    }

    /// Returns the Mantis priority bucket for this entry.
    pub fn priority(&self) -> KevPriority {
        match self.ransomware_use() {
            RansomwareUse::Known => KevPriority::IN_KEV_RANSOMWARE,
            RansomwareUse::Unknown => KevPriority::IN_KEV,
        }
    }
}

/// Raw top-level shape of the CISA KEV feed.
#[derive(Debug, Deserialize)]
struct RawCatalog {
    #[serde(default)]
    title: String,
    #[serde(rename = "catalogVersion", default)]
    catalog_version: String,
    #[serde(rename = "dateReleased", default)]
    date_released: String,
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
}

/// In-memory view of the CISA KEV catalog with O(1) CVE lookup.
///
/// Construct with [`KevCatalog::from_json`] (passing the catalog JSON text) or
/// [`KevCatalog::from_entries`] (for tests and unit-level wiring).
#[derive(Debug, Clone)]
pub struct KevCatalog {
    title: String,
    catalog_version: String,
    date_released: String,
    by_cve: HashMap<String, KevEntry>,
}

impl KevCatalog {
    /// Build a catalog from the CISA KEV JSON document.
    pub fn from_json(json: &str) -> Result<Self, KevError> {
        let raw: RawCatalog = serde_json::from_str(json)?;
        Ok(Self::from_raw(raw))
    }

    /// Build a catalog from an in-memory list of entries. Useful for tests and
    /// when entries are sourced from somewhere other than the upstream feed.
    pub fn from_entries(entries: impl IntoIterator<Item = KevEntry>) -> Self {
        let mut by_cve = HashMap::new();
        for entry in entries {
            by_cve.insert(entry.cve_id.to_ascii_uppercase(), entry);
        }
        Self {
            title: String::new(),
            catalog_version: String::new(),
            date_released: String::new(),
            by_cve,
        }
    }

    fn from_raw(raw: RawCatalog) -> Self {
        let mut by_cve = HashMap::with_capacity(raw.vulnerabilities.len());
        for entry in raw.vulnerabilities {
            by_cve.insert(entry.cve_id.to_ascii_uppercase(), entry);
        }
        Self {
            title: raw.title,
            catalog_version: raw.catalog_version,
            date_released: raw.date_released,
            by_cve,
        }
    }

    /// Catalog title as advertised by CISA.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// CISA-published catalog version string.
    pub fn catalog_version(&self) -> &str {
        &self.catalog_version
    }

    /// Release date of the loaded catalog (YYYY-MM-DD).
    pub fn date_released(&self) -> &str {
        &self.date_released
    }

    /// Number of vulnerabilities in the catalog.
    pub fn len(&self) -> usize {
        self.by_cve.len()
    }

    /// Whether the catalog contains zero entries.
    pub fn is_empty(&self) -> bool {
        self.by_cve.is_empty()
    }

    /// Look up an entry by CVE ID. Comparison is case-insensitive.
    pub fn lookup(&self, cve_id: &str) -> Option<&KevEntry> {
        self.by_cve.get(&cve_id.to_ascii_uppercase())
    }

    /// Whether the given CVE appears in the KEV catalog.
    pub fn is_kev(&self, cve_id: &str) -> bool {
        self.by_cve.contains_key(&cve_id.to_ascii_uppercase())
    }

    /// Priority bucket for the CVE — defaults to [`KevPriority::NOT_IN_KEV`].
    pub fn priority(&self, cve_id: &str) -> KevPriority {
        self.lookup(cve_id)
            .map(KevEntry::priority)
            .unwrap_or(KevPriority::NOT_IN_KEV)
    }

    /// Iterate all entries in arbitrary order.
    pub fn entries(&self) -> impl Iterator<Item = &KevEntry> {
        self.by_cve.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed real-shape fixture: two CVEs, one ransomware-linked, one not.
    const FIXTURE: &str = r#"{
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2024.05.01",
        "dateReleased": "2024-05-01T00:00:00.000Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
                "requiredAction": "For all affected software assets for which updates exist, apply available updates per vendor instructions.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "notes": "https://logging.apache.org/log4j/2.x/security.html",
                "cwes": ["CWE-20", "CWE-917"]
            },
            {
                "cveID": "CVE-2019-19781",
                "vendorProject": "Citrix",
                "product": "Application Delivery Controller and Gateway",
                "vulnerabilityName": "Citrix ADC and Gateway Directory Traversal Vulnerability",
                "dateAdded": "2021-11-03",
                "shortDescription": "Citrix Application Delivery Controller (ADC) and Gateway directory traversal vulnerability.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2022-05-03",
                "knownRansomwareCampaignUse": "Unknown",
                "cwes": ["CWE-22"]
            }
        ]
    }"#;

    #[test]
    fn parses_catalog_metadata() {
        let cat = KevCatalog::from_json(FIXTURE).unwrap();
        assert_eq!(
            cat.title(),
            "CISA Catalog of Known Exploited Vulnerabilities"
        );
        assert_eq!(cat.catalog_version(), "2024.05.01");
        assert_eq!(cat.len(), 2);
        assert!(!cat.is_empty());
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let cat = KevCatalog::from_json(FIXTURE).unwrap();
        assert!(cat.lookup("CVE-2021-44228").is_some());
        assert!(cat.lookup("cve-2021-44228").is_some());
        assert!(cat.lookup("Cve-2021-44228").is_some());
    }

    #[test]
    fn known_cves_are_flagged_as_kev() {
        let cat = KevCatalog::from_json(FIXTURE).unwrap();
        assert!(cat.is_kev("CVE-2021-44228"));
        assert!(cat.is_kev("CVE-2019-19781"));
    }

    #[test]
    fn unknown_cve_is_not_in_kev() {
        let cat = KevCatalog::from_json(FIXTURE).unwrap();
        assert!(!cat.is_kev("CVE-2099-0001"));
        assert_eq!(cat.priority("CVE-2099-0001"), KevPriority::NOT_IN_KEV);
        assert_eq!(cat.priority("CVE-2099-0001").score(), 0);
    }

    #[test]
    fn ransomware_linked_entries_get_top_priority() {
        let cat = KevCatalog::from_json(FIXTURE).unwrap();
        let log4j = cat.lookup("CVE-2021-44228").unwrap();
        assert_eq!(log4j.ransomware_use(), RansomwareUse::Known);
        assert_eq!(log4j.priority(), KevPriority::IN_KEV_RANSOMWARE);
        assert_eq!(cat.priority("CVE-2021-44228").score(), 100);
    }

    #[test]
    fn non_ransomware_kev_entries_get_in_kev_priority() {
        let cat = KevCatalog::from_json(FIXTURE).unwrap();
        let citrix = cat.lookup("CVE-2019-19781").unwrap();
        assert_eq!(citrix.ransomware_use(), RansomwareUse::Unknown);
        assert_eq!(citrix.priority(), KevPriority::IN_KEV);
        assert_eq!(cat.priority("CVE-2019-19781").score(), 75);
    }

    #[test]
    fn entry_carries_cwes() {
        let cat = KevCatalog::from_json(FIXTURE).unwrap();
        let log4j = cat.lookup("CVE-2021-44228").unwrap();
        assert_eq!(log4j.cwes, vec!["CWE-20", "CWE-917"]);
    }

    #[test]
    fn parse_error_is_returned_for_bad_json() {
        let err = KevCatalog::from_json("{ not json").unwrap_err();
        assert!(matches!(err, KevError::Parse(_)));
    }

    #[test]
    fn from_entries_round_trip() {
        let entry = KevEntry {
            cve_id: "CVE-2023-12345".into(),
            vendor_project: "Test".into(),
            product: "Thing".into(),
            vulnerability_name: "Test Vuln".into(),
            date_added: "2023-01-01".into(),
            short_description: String::new(),
            required_action: String::new(),
            due_date: String::new(),
            known_ransomware_campaign_use: "Known".into(),
            cwes: vec!["CWE-79".into()],
        };
        let cat = KevCatalog::from_entries([entry]);
        assert_eq!(cat.len(), 1);
        assert!(cat.is_kev("CVE-2023-12345"));
        assert_eq!(
            cat.priority("cve-2023-12345"),
            KevPriority::IN_KEV_RANSOMWARE
        );
    }

    #[test]
    fn iter_entries_returns_all() {
        let cat = KevCatalog::from_json(FIXTURE).unwrap();
        let count = cat.entries().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn tolerates_unknown_upstream_fields() {
        // Upstream feed may add fields; we should ignore unknowns rather than
        // refuse to parse the catalog.
        let json = r#"{
            "title": "test",
            "vulnerabilities": [{
                "cveID": "CVE-2024-0001",
                "futureField": {"nested": true}
            }]
        }"#;
        let cat = KevCatalog::from_json(json).unwrap();
        assert!(cat.is_kev("CVE-2024-0001"));
    }
}
