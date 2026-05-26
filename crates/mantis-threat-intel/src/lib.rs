//! Threat intelligence feed ingestion for Mantis.
//!
//! Today this crate ships the CISA KEV (Known Exploited Vulnerabilities) catalog
//! reader, exposed via [`kev::KevCatalog`]. It lets the planner, hypothesis
//! generator, and report renderer answer two questions in O(1):
//!
//! 1. Is this CVE actively exploited in the wild?
//! 2. If so, with what urgency (ransomware-linked, due-date severity)?
//!
//! Future modules under this crate will cover NVD/CVE feeds, GitHub Security
//! Advisories, and ExploitDB — keeping all upstream threat-intel sources behind
//! one Mantis-facing API surface.

#![deny(missing_docs)]

pub mod ghsa;
pub mod kev;

pub use ghsa::{Advisory, AdvisoryIndex, GhsaError};
pub use kev::{KevCatalog, KevEntry, KevError, KevPriority, RansomwareUse};
