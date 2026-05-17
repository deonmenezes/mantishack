//! HTTP probing and content discovery scanner.
//!
//! Phase 0 milestone M0.5 ships the probe scanner. Content discovery
//! lands in a follow-up (M0.5b) once a wordlist + response-shape
//! clusterer are wired up.

pub mod enumerator;
pub mod error;
pub mod probe;

pub use crate::enumerator::{
    enumerate, generate_candidates, EnumerationConfig, DEFAULT_PATHS, DEFAULT_SUBDOMAINS,
};
pub use crate::error::ScannerError;
pub use crate::probe::{HttpProbeScanner, ProbeConfig, ProbeTarget, Surface};
