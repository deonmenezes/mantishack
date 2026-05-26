//! Subcommand: `mantis tools <name>` — leaf utility tools exposed as CLI
//! commands, mirroring the MCP utility-tool surface in `mantis-mcp`.
//!
//! ## Why this exists
//!
//! Mantis is transitioning from an MCP-centric agent interface to a
//! CLI-canonical interface. The pure-compute MCP tools (`mantis_decode_jwt`,
//! `mantis_diff_responses`, `mantis_summarize_url`, …) move into this module
//! first because they have no daemon dependency and migrate cleanly.
//!
//! Each subcommand:
//!
//! 1. Takes its inputs as flags / args
//! 2. Performs a pure-compute transform
//! 3. Writes a single JSON document to stdout
//! 4. Exits non-zero only on argument-parse failure (compute always succeeds
//!    by design — invalid inputs become structured `warnings` in the output)
//!
//! ## Why JSON to stdout
//!
//! Agents calling Mantis via Claude Code's `Bash` tool or Codex's shell read
//! stdout. Single-document JSON is trivially parseable. Errors and progress
//! go to stderr.
//!
//! ## Migration relationship to `mantis-mcp`
//!
//! For each tool migrated here, the corresponding MCP tool in `mantis-mcp`
//! either (a) shells out to the CLI subcommand (Phase 2), or (b) calls the
//! same shared implementation (Phase 1, current). Today the MCP and CLI
//! paths are independent implementations of the same algorithm; the planned
//! follow-up is to extract the algorithms into a shared crate
//! (`mantis-tools`) so both surfaces are thin wrappers.
//!
//! See `docs/MCP_TO_CLI_MIGRATION.md` for the full migration plan.

use anyhow::Result;
use clap::Subcommand;

mod decode_jwt;

/// `mantis tools <subcommand>` argument tree.
#[derive(Subcommand, Debug)]
pub(crate) enum ToolsCmd {
    /// Decode a JWT without verifying its signature.
    ///
    /// Always succeeds with a structured payload, even on malformed input —
    /// invalid inputs become structured `warnings` in the output JSON so
    /// the caller (typically an LLM agent) can reason about the failure
    /// mode without retrying.
    ///
    /// Accepts a bare JWT or a `Bearer <jwt>` string.
    DecodeJwt {
        /// The JWT to decode. Compact serialization: `header.payload.signature`,
        /// three dot-separated base64url-encoded segments.
        #[arg(long)]
        jwt: String,
    },
}

/// Dispatch entry point for `mantis tools …`. Writes a JSON document to
/// stdout for every successful subcommand.
pub(crate) fn run(cmd: ToolsCmd) -> Result<()> {
    match cmd {
        ToolsCmd::DecodeJwt { jwt } => {
            let decoded = decode_jwt::decode(&jwt);
            let s = serde_json::to_string_pretty(&decoded)?;
            println!("{s}");
            Ok(())
        }
    }
}
