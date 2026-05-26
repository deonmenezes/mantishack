//! Compliance and framework tagging for Mantis claims.
//!
//! All compliance metadata Mantis attaches to claims and reports lives behind
//! this one crate's API. The taxonomies shipped today:
//!
//! - [`cwe`] — typed `Cwe` wrapper for CWE identifiers.
//! - [`owasp`] — OWASP Top 10 (2021) + CWE → category mapping.
//! - [`asvs`] — OWASP Application Security Verification Standard v4 chapters.
//! - [`masvs`] — OWASP Mobile Application Security Verification Standard v2 controls.
//! - [`mitre`] — MITRE ATT&CK techniques + CWE → technique mapping.
//! - [`regulatory`] — PCI-DSS, SOC2, HIPAA framework tagging.
//! - [`vuln_class`] — single-entry point: `tags_for("sqli") → ComplianceTags`.

#![deny(missing_docs)]

pub mod asvs;
pub mod cwe;
pub mod masvs;
pub mod mitre;
pub mod owasp;
pub mod regulatory;
pub mod vuln_class;

pub use asvs::{asvs_for_cwe, AsvsChapter};
pub use cwe::Cwe;
pub use masvs::{masvs_for_cwe, MasvsControl};
pub use mitre::{technique_for_cwe, Tactic, Technique};
pub use owasp::{owasp_for_cwe, OwaspTop10};
pub use regulatory::{
    hipaa_for_cwe, pci_dss_for_cwe, regulatory_for_cwe, soc2_for_cwe, HipaaSafeguard,
    PciDssRequirement, RegulatoryTags, Soc2Criterion,
};
pub use vuln_class::{tags_for, ComplianceTags};
