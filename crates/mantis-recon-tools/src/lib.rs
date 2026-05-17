//! Detection + invocation of external recon binaries.
//!
//! Mirrors hacker-bob's optional-tools list:
//! `subfinder`, `httpx`, `nuclei`, `amass`, `assetfinder`, `chaos`,
//! `dnsx`, `tlsx`, `katana`, `subzy`, plus `jwt_tool` (Python).
//!
//! Design:
//! - **Detection** ([`ToolInventory::scan`]) — runs at engagement
//!   start (and from `mantis doctor`). For each known tool, looks
//!   up the binary on `PATH` and tries to read a version string.
//! - **Invocation** ([`run_subfinder`], [`run_httpx`], …) — thin
//!   wrappers that shell out, parse the tool's canonical line-
//!   delimited output, and return owned Rust types. Each invocation
//!   fast-fails when the tool isn't present (returns
//!   [`ToolError::NotInstalled`]) so callers can use the
//!   `if let Ok(out) = run_subfinder(...).await { fold-in(out) }`
//!   pattern without a separate detection round-trip.
//!
//! **Mantis runs without any of these tools.** Their presence
//! widens the surface set the orchestrator passes to the
//! enumerator + auth-diff stages.

pub mod intel;
pub mod inventory;
pub mod runners;

pub use crate::intel::{
    detect_tech, extract_js_endpoints, graphql_introspection_enabled, metadata_paths,
    wayback_urls, well_known_paths, WaybackUrl,
};
pub use crate::inventory::{ToolInfo, ToolInventory, ToolKind};
pub use crate::runners::{
    run_dnsx, run_httpx, run_jwt_tool_decode, run_katana, run_subfinder, run_tlsx, NucleiHit,
    run_nuclei,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolError {
    #[error("tool `{0}` is not installed on PATH")]
    NotInstalled(String),
    #[error("tool `{tool}` failed: exit={exit_code:?}, stderr: {stderr}")]
    Failed {
        tool: String,
        exit_code: Option<i32>,
        stderr: String,
    },
    #[error("tool `{0}` invocation timed out")]
    Timeout(String),
    #[error("tool `{tool}` output parse error: {message}")]
    Parse { tool: String, message: String },
}
