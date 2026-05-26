# MCP → CLI architectural migration

## Goal

Move Mantis's agent-facing interface from MCP (Model Context Protocol) to a
CLI-native model where `mantis-cli` is the canonical surface and any future
MCP server is a thin wrapper.

## Why we're doing this

1. **Compatibility breadth.** CLI works with any agent runtime that can spawn
   a subprocess — Claude Code's `Bash` tool, Codex's shell, OpenAI Assistants
   via tools that invoke commands, and any future framework. MCP only works
   with MCP-aware clients.
2. **Auditability.** Every operation becomes a discrete shell invocation that
   can be logged, signed via the merkle event log, replayed, and hashed for
   reproducibility — exactly the property `mantis-chain` was built around.
3. **Crash isolation.** Each tool runs in its own process. A bad scan or a
   hung HTTP request can't bring down a long-running MCP server (because
   there isn't one).
4. **Composability.** Operators can pipe `mantis-cli tools …` output through
   `jq`, save to files, integrate with CI, drive from any shell. That's
   harder over MCP transport.
5. **Single source of truth.** Today the tool logic lives in
   `crates/mantis-mcp/src/utility_tools.rs` and the dispatch lives in
   `crates/mantis-mcp/src/server.rs`. After migration the logic lives in
   `crates/mantis-cli/src/tools/<name>.rs` and any MCP server consumes the
   CLI as a subprocess.

## Scope

`crates/mantis-mcp/src/server.rs` registers **134** tools. They split into
two categories:

| Category | Examples | Migration approach |
|---|---|---|
| Stateless utility tools | `decode_jwt`, `diff_responses`, `summarize_url`, `extract_secrets`, `score_finding`, `hash_request`, `extract_html_forms`, `extract_links` | Move to `mantis-cli tools <kebab-name>`. No daemon dependency. First migration target. |
| Daemon-backed engagement tools | `mantis_create_engagement`, `mantis_authorize_engagement`, `mantis_start_engagement`, `mantis_status_engagement`, `mantis_record_finding`, `mantis_list_findings`, … | Move under `mantis-cli engagement <verb>` (most already exist there). Wire MCP shim to subprocess into them. Second migration target. |

This document focuses on the stateless utility tools first because they have
no daemon dependency, no gRPC plumbing, and no shared state — they're the
cleanest possible migration. Once the pattern is proven on those, the same
recipe applies (with the addition of `--daemon` flag plumbing) to the
daemon-backed tools.

## The per-tool migration recipe

For each MCP tool you want to migrate, do these steps in order, **in one
atomic PR** so the build never bisects to a broken state:

### Step 1 — Create the CLI module

Add `crates/mantis-cli/src/tools/<kebab_name>.rs` with:

- A `pub(super)` result struct (e.g. `DecodedJwt`) that derives
  `Serialize` so it can round-trip to stdout JSON.
- A `pub(super) fn <name>(args…) -> ResultStruct` that performs the pure
  compute and returns the structured result.
- A `#[cfg(test)] mod tests` block covering at minimum: happy path, every
  warning code, malformed-input fallback, and one JSON-round-trip sanity
  test.

Port the algorithm from `crates/mantis-mcp/src/utility_tools.rs` (or
wherever it currently lives). Do not depend on `mantis-mcp`; this module
must be self-contained inside `mantis-cli`. Duplication is intentional and
short-lived — the planned follow-up (Phase 3 below) extracts both copies
into a shared `mantis-tools` crate.

### Step 2 — Add a clap subcommand

In `crates/mantis-cli/src/tools.rs`, add a variant to `ToolsCmd`:

```rust
/// One-line description for `--help`.
///
/// Longer paragraph explaining behavior, warning semantics, and the
/// JSON output shape.
KebabName {
    /// Field doc.
    #[arg(long)]
    field: String,
},
```

And a match arm in `pub(crate) fn run(cmd: ToolsCmd) -> Result<()>`:

```rust
ToolsCmd::KebabName { field } => {
    let result = kebab_name::function(&field);
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
```

### Step 3 — Verify

```
cargo build -p mantis-cli
cargo test -p mantis-cli
cargo clippy -p mantis-cli --all-targets -- -D warnings
cargo run -p mantis-cli -- tools <kebab-name> [args]   # smoke
```

### Step 4 — Update MCP tool to delegate (Phase 2, deferred)

Once enough tools are CLI-native, update each MCP tool body in
`crates/mantis-mcp/src/server.rs` to shell out to `mantis-cli tools
<kebab-name>` via `tokio::process::Command`. This keeps MCP backward-
compatible during the transition while routing through the canonical
implementation.

### Step 5 — Retire the MCP-internal copy (Phase 3, end-state)

Once every MCP tool delegates to the CLI, the original logic in
`crates/mantis-mcp/src/utility_tools.rs` (and equivalents) can be deleted.
At that point the MCP server is a pure dispatch layer — or optionally,
removed entirely if no clients depend on it.

## Phase plan

The migration is incremental on purpose so each tool lands as one focused PR
and the project ships a working product every step of the way.

### Phase 1 — Stateless utility tools to CLI (in progress)

- [x] `mantis tools decode-jwt` — JWT decoder + warnings.
- [ ] `mantis tools diff-responses` — structural HTTP-response diff.
- [ ] `mantis tools summarize-url` — URL parser + classifier.
- [ ] `mantis tools extract-secrets` — credential / secret-shape scanner.
- [ ] `mantis tools score-finding` — 5-axis finding pre-grader.
- [ ] `mantis tools hash-request` — stable request-shape hash.
- [ ] `mantis tools extract-html-forms` — form extractor from HTML.
- [ ] `mantis tools extract-links` — URL extractor from text blobs.

Each lands as a separate PR following the recipe above. No phase-2 work
until phase-1 utility tools are complete.

### Phase 2 — MCP delegates to CLI

For every tool migrated in Phase 1, refactor the corresponding
`#[tool]`-annotated function in `crates/mantis-mcp/src/server.rs` to invoke
`mantis-cli tools <name>` via subprocess. The MCP server becomes a thin
adapter; the algorithm lives in the CLI.

### Phase 3 — Extract shared library (optional)

If the duplication between MCP-internal and CLI-internal copies becomes
painful (it probably will once Phase 1 has ~5 tools), extract the algorithms
into a new `mantis-tools` crate. Both `mantis-cli` and `mantis-mcp` depend
on it. The duplication that Phase 1 intentionally tolerated is then
eliminated.

### Phase 4 — Daemon-backed tools

Apply the same pattern to engagement / daemon-backed tools. Most have
existing CLI entry points already (`mantis engagement create`,
`mantis engagement status`, …) — the work is wiring MCP to delegate rather
than adding new CLI commands.

### Phase 5 — Retire `mantis-mcp` (decision pending)

Once every MCP tool delegates to the CLI and no client requires the MCP
transport specifically, the `crates/mantis-mcp/` crate can be marked
deprecated and eventually removed. Whether to do this depends on customer /
operator demand for the MCP UX in Claude Code; the architectural option is
preserved either way.

## Honest acknowledgement

This migration also has a secondary effect: the prompt files under
`plugin/claude-code/agents/` and `prompts/roles/` currently reference
`mcp__mantis__mantis_*` tool names that are derivative from Hacker Bob's
`bounty_*` tool names. As those tools move to `mantis-cli tools …`, the
prompts that orchestrate them must be rewritten to invoke
`Bash` → `mantis-cli` instead of the MCP tool surface.

That rewrite is an organic product-change rewrite (the underlying tool
surface changed) rather than a license-compliance rewrite. It happens to
land the same outcome — the prompt layer becomes independent of the
Hacker-Bob-derived MCP tool naming — but the driver is the architectural
migration, not the license history. The `NOTICE` file documents the
license history separately and is unaffected by this migration.

See `NOTICE` "Apology and compliance history" for the license-side narrative.

## Conventions

- **Every CLI tool subcommand outputs a single JSON document to stdout.**
  Errors and progress go to stderr. Exit code 0 on success.
- **Subcommand names are kebab-case** (`decode-jwt`, not `decode_jwt`).
- **Field flags are kebab-case** (`--engagement-id`, not `--engagement_id`).
- **Result structs use snake_case field names** because they're serialized
  to JSON and downstream consumers (LLM agents, jq, scripts) expect that
  convention.
- **Pure-compute tools must never panic on bad input.** Malformed input
  becomes a structured `warnings` array; the tool still exits 0 because
  the *transform* succeeded. Argument-parse failures (clap-level) are the
  only path to non-zero exit.
- **No daemon dependency for Phase-1 tools.** Anything that needs a daemon
  belongs in Phase 4, not Phase 1.

## Tracking

Each tool migration is one PR. Each PR title follows the pattern:

```
feat(cli): migrate <kebab-name> from mantis-mcp to mantis-cli tools
```

The body must:

1. Name the source MCP tool and its current location.
2. Confirm the new CLI subcommand produces equivalent JSON output (sample
   command + sample output in the PR body).
3. List every behavioral difference between the MCP and CLI versions
   (typically: none, but document any).
4. Reference this document.
