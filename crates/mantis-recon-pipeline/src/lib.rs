//! mantis-recon-pipeline — deterministic parallel recon.
//!
//! ## Why this exists
//!
//! The LLM-driven flow has the model issue one MCP tool call per
//! scanner: it calls `subfinder`, waits, calls `httpx`, waits,
//! calls `nuclei`, etc. Wall-clock = sum(scanner_durations) + N×
//! LLM-round-trips. For a typical engagement that's 5–10 minutes
//! before the first finding.
//!
//! This crate inverts that: a single Rust function fans out to all
//! five scanners in parallel via `tokio::join!`, runs them
//! concurrently, then hands the LLM a fully-baked [`ReconBundle`]
//! so it can spend its tokens on chain analysis and creative
//! exploitation instead of orchestrating recon.
//!
//! Wall-clock collapses from `sum(durations)` to
//! `max(durations)` — typically a 4–6× speedup on a typical
//! target (where nuclei dominates and the others finish in
//! parallel under its umbrella).
//!
//! ## Architecture
//!
//! ```text
//! run_pipeline(target, opts)
//!   │
//!   ├── tokio::join! { subfinder, httpx, nuclei, trufflehog, trivy }
//!   │     (each task spawned on the runtime; durations overlap)
//!   │
//!   ├── aggregate → Vec<Finding>
//!   ├── detect_anomalies → Vec<Anomaly>  (regex-based deterministic rules)
//!   └── ReconBundle { target, surfaces, fingerprint, findings, anomalies }
//! ```
//!
//! Results are cacheable on disk by (`target`, `scope_hash`,
//! `pipeline_version`) so a repeat invocation within the cache
//! TTL is instant.

pub mod anomaly;
pub mod bundle;
pub mod cache;
pub mod orchestrator;

pub use anomaly::{Anomaly, AnomalyKind};
pub use bundle::{HttpSurface, ReconBundle, ScannerStats};
pub use orchestrator::{run_pipeline, PipelineOptions, PipelineDepth};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("scanner `{scanner}` failed: {source}")]
    Scanner {
        scanner: &'static str,
        #[source]
        source: mantis_static_scan::ScanError,
    },
    #[error("cache I/O: {0}")]
    CacheIo(#[from] std::io::Error),
    #[error("cache serialize: {0}")]
    CacheSerialize(#[from] serde_json::Error),
    #[error("invalid target `{0}` — must be a host, URL, or domain")]
    BadTarget(String),
}
