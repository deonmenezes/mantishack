//! # Apache-2.0 §4(b) notice — derivative work
//!
//! Portions of this file are derived from or mirror algorithm
//! shape, named constants, threshold values, or workflow logic from
//! Hacker Bob (<https://github.com/vmihalis/hacker-bob>),
//! Copyright 2026 Michail Vasileiadis, licensed under the Apache
//! License, Version 2.0. The surrounding Rust implementation is
//! independent and was written from scratch.
//!
//! See the project NOTICE for the upstream attribution and the
//! compliance-history apology. This notice is provided per
//! Apache-2.0 §4(b) ("You must cause any modified files to carry
//! prominent notices stating that You changed the files").
//!
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
