//! Threat intelligence feed ingestion for Mantis.
//!
//! All upstream threat-intel sources Mantis consumes live behind this one
//! crate's API. Today it ships four feed readers:
//!
//! - [`kev`] — CISA Known Exploited Vulnerabilities catalog (priority scoring).
//! - [`ghsa`] — GitHub Security Advisory database (OSV format).
//! - [`nvd`] — NVD CVE 2.0 JSON feeds (descriptions, CVSS, CWE).
//! - [`exploitdb`] — Exploit-DB catalog CSV (public exploit lookup by CVE).
//!
//! All four are pure parsers — they expect already-fetched bytes/strings.
//! Operator-side fetch (HTTPS to CISA, GitHub, NVD, GitLab) is out of scope
//! because the feeds don't go through `mantis-egress` (egress enforces target
//! scope, not operator-side infrastructure pulls).

#![deny(missing_docs)]

pub mod exploitdb;
pub mod ghsa;
pub mod kev;
pub mod nvd;

pub use exploitdb::{ExploitDb, ExploitDbError, ExploitEntry};
pub use ghsa::{Advisory, AdvisoryIndex, GhsaError};
pub use kev::{KevCatalog, KevEntry, KevError, KevPriority, RansomwareUse};
pub use nvd::{Cve, CveIndex, NvdError, Severity};
