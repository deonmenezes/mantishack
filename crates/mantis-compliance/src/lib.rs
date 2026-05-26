//! Compliance and framework tagging for Mantis claims.
//!
//! Today this crate provides:
//!
//! - [`Cwe`] — typed wrapper around CWE identifiers (e.g. `CWE-89`).
//! - [`OwaspTop10`] — enum of the 2021 OWASP Top 10 categories with stable IDs.
//! - [`owasp_for_cwe`] — best-known CWE → OWASP Top 10 mapping for common
//!   weaknesses, derived from the official 2021 Top 10 mapping notes.
//!
//! Future modules will cover OWASP ASVS, MASVS, MITRE ATT&CK techniques, and
//! regulatory frameworks (PCI-DSS, SOC2, HIPAA). Keeping all framework tagging
//! behind one crate lets the report generator, scoreboard, and planner reach
//! for compliance metadata without hard-coding tables across the workspace.

#![deny(missing_docs)]

pub mod cwe;
pub mod mitre;
pub mod owasp;
pub mod vuln_class;

pub use cwe::Cwe;
pub use mitre::{technique_for_cwe, Tactic, Technique};
pub use owasp::{owasp_for_cwe, OwaspTop10};
pub use vuln_class::{tags_for, ComplianceTags};
