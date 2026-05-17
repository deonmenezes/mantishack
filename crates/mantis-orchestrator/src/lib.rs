//! End-to-end auth-bug pipeline.
//!
//! Implements the full chain hacker-bob's `bob-hunt` slash command
//! runs as a sequence of MCP tool calls — but in Rust, as one
//! callable function:
//!
//! ```text
//! signup(attacker)  ──┐
//! signup(victim)    ──┤
//!                     ├──> for each endpoint: auth-diff (unauth,attacker,victim)
//! enumerate(target) ──┘     ────> classify ──> findings
//! ```
//!
//! All four stages share the same `AuthProfile` zeroization
//! semantics (secrets drop on scope exit) and report through one
//! [`AuthBugReport`] structure suitable for archival into the
//! per-target folder layout.

pub mod archive;
pub mod discover;
pub mod find_auth_bugs;

pub use crate::archive::{write_archive, ArchiveError, ArchiveOutcome};
pub use crate::discover::{discover, discover_with_cookie, DiscoveredAuthConfig};
pub use crate::find_auth_bugs::{
    find_auth_bugs, find_auth_bugs_with_profiles, AuthBugConfig, AuthBugReport, EndpointResult,
    OrchestratorError,
};
