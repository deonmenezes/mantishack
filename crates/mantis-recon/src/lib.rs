//! mantis-recon — native Rust recon primitives.
//!
//! ## What this crate is
//!
//! Pure-Rust implementations of the fast, sub-second recon lookups
//! that previously required shelling out to ProjectDiscovery
//! binaries. The companion crate [`mantis-recon-tools`] still wraps
//! the bigger binaries (katana, naabu, amass, nuclei) where a native
//! port doesn't yet make sense.
//!
//! ## Modules
//!
//! - [`passive_subdomain`] — Certificate Transparency log queries
//!   (`crt.sh`) and other passive sources to enumerate subdomains
//!   without sending a single packet to the target.
//! - [`httpx`] — concurrent HTTP/S probe over a host list. Captures
//!   status, title, headers, cert metadata, and reuses the
//!   `mantis-recon-tools` tech-detect rules.
//! - [`dnsx`] — async DNS resolver fronting `tokio::net::lookup_host`.
//!   Records A/AAAA per host; CNAME/MX/NS support is a follow-up.
//!
//! All public types serialize cleanly so the orchestrator can fold
//! them into a `ReconBundle` for downstream LLM-driven exploration.

pub mod dnsx;
pub mod httpx;
pub mod passive_subdomain;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReconError {
    #[error("network: {0}")]
    Network(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),
}

impl From<reqwest::Error> for ReconError {
    fn from(value: reqwest::Error) -> Self {
        ReconError::Network(value.to_string())
    }
}

pub use crate::dnsx::{resolve_a, DnsResolution};
pub use crate::httpx::{probe, HttpProbeResult, ProbeOptions};
pub use crate::passive_subdomain::{
    enumerate_passive, PassiveSource, SubdomainRecord,
};
