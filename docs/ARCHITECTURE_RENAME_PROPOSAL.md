# Architectural rename proposal — Mantis-native execution vocabulary

## Why

The [transition audit](./TRANSITION_AUDIT.md) flags four families of naming
that currently echo Hacker Bob's vocabulary:

1. The parallel-hunter orchestration model (`wave` / `handoff` / `merge`).
2. The chain-attempt outcome enum (`confirmed` / `denied` / `blocked` /
   `inconclusive` / `not_applicable`).
3. The severity-ladder rules (`LOW+LOW=LOW`, `max input + 1`, etc.).
4. The role-completion markers (`MANTIS_*_DONE`, mechanically renamed from
   `BOB_*_DONE`).

Renaming alone doesn't transform derivative content into original work — but
a *fresh design* with *fresh names* documents the architectural break
explicitly. This document proposes the new vocabulary so that subsequent
clean-room rewrites (prompts, wave.rs, completion markers) can adopt it
consistently from the first PR.

This is a proposal, not a landed change. Each rename lands as its own
atomic PR with the affected code/prompts updated together.

## Design principles for the new vocabulary

1. **Different domain metaphor.** Hacker Bob's vocabulary borrows from
   maritime / military imagery (`wave`, `handoff`, `merge`). Mantis is a
   forensics + evidence-chain product. The new vocabulary borrows from
   forensic investigation / scientific replication / cryptographic
   verification — domains the Rust substrate already operates in.
2. **Different semantics where possible.** Some renames are also semantic
   changes (e.g., the outcome enum gains/loses values), not just relabels.
   Where semantics differ from the upstream, that is explicitly documented
   below.
3. **Names that describe what the construct does** in Mantis, not what it
   does in the upstream system.

## Proposed renames

### 1. Parallel-hunter orchestration

| Concept | Current name | Proposed name | Why |
|---|---|---|---|
| One round of parallel hunters launched together | `wave` | `pass` | "Pass" is a forensic-investigation term. A pass over evidence yields a report; the next pass is informed by what the prior pass found. |
| The artifact a hunter produces on completion | `handoff` | `transcript` | A transcript is a verbatim record of what the hunter did. Mirrors Mantis's evidence-chain ethos. |
| Combining multiple hunters' artifacts | `merge handoffs` | `reconcile transcripts` | "Reconcile" implies the deduplication + conflict-resolution step Mantis performs, where "merge" was generic. |
| Directory layout for pass artifacts | `waves/<n>/chain-attempts.jsonl` | `passes/<n>/findings.ndjson` | Renamed root directory + extension matches the broader ecosystem (NDJSON is the standard name for the line-delimited JSON format). |

Semantic notes:
- The `pass` index is still 0-based and monotonically increasing per
  engagement. Behavior identical.
- `reconcile transcripts` is a stronger operation than `merge handoffs`: it
  must produce a deterministic order and resolve dup-finding collisions by
  evidence-hash. (HB's `merge` was a simple append.)

### 2. Chain-attempt outcome enum

| Current | Proposed | Semantic delta |
|---|---|---|
| `confirmed` | `verified` | Aligns with Mantis's `mantis-verify` crate naming. |
| `denied` | `refuted` | Stronger word; matches the "refutation" semantic of the verifier round. |
| `blocked` | `gated` | "Gated" is what Mantis's egress proxy returns when an out-of-scope target is dropped. Names the actual mechanism, not a generic word. |
| `inconclusive` | `unresolved` | Less ambiguous; "inconclusive" can imply weakness, "unresolved" implies "needs another pass." |
| `not_applicable` | `out_of_scope` | Maps to Mantis's existing `mantis-scope` crate vocabulary. |

The proposed enum:

```rust
pub enum ChainOutcome {
    Verified,
    Refuted,
    Gated,
    Unresolved,
    OutOfScope,
}
```

Semantic notes:
- The five-value cardinality is preserved because the underlying problem
  shape is the same (verification has finite outcomes).
- `Gated` carries an additional structured field in Mantis (the scope-rule
  that fired), where HB's `blocked` was a string. This makes Mantis's
  outcome a richer record than the upstream.

### 3. Severity-ladder rules

Current rules (per `NOTICE`):

> `LOW+LOW=LOW`; `max input + 1` without rationale; `max input + 2` with
> `elevation:` rationale; no jump-the-rung.

Proposed semantics — *different rules, not a rename of identical rules*:

- **Pin-down rule.** Two findings of severity `X` chain to a finding of
  severity at least `X` (was: `LOW+LOW=LOW`). The floor is the higher of
  the chain inputs, not the lower.
- **Elevation by chain length.** Each additional verified link in a chain
  raises the maximum elevation by 1 (was: `max input + 1`). A 3-link chain
  can elevate up to `max input + 2`, no rationale required.
- **Elevation by stated impact.** Beyond `+chain_length`, additional
  elevation requires a structured `impact:` clause with named asset and
  named loss surface (was: free-form `elevation:` rationale).
- **No more "jump-the-rung"** — replaced by structured floor + ceiling
  computation: `severity = clamp(floor_of_inputs + chain_length + impact_bonus,
  LOW, CRITICAL)`.

This is a real algorithmic change, not a rename. Implementation lands in
`crates/mantis-mcp/src/wave.rs` (to be renamed — see §5 below) with new
tests covering each rule independently.

### 4. Role-completion markers

| Current | Proposed |
|---|---|
| `MANTIS_HUNTER_DONE` | `HUNTER_PASS_FILED` |
| `MANTIS_VERIFIER_DONE` | `VERIFIER_PASS_FILED` |
| `MANTIS_CHAIN_DONE` | `CHAIN_PASS_FILED` |
| `MANTIS_RECON_DONE` | `RECON_PASS_FILED` |
| `MANTIS_GRADER_DONE` | `GRADER_PASS_FILED` |
| `MANTIS_REPORT_DONE` | `REPORT_PASS_FILED` |

Different shape (no `MANTIS_` prefix, role name first, action `PASS_FILED`
matches the `pass` / `transcript` vocabulary from §1). The marker is no
longer a generic "I'm done" beacon; it's a specific "this role's transcript
for this pass is filed to disk."

### 5. File / module renames

| Current path | Proposed path | Why |
|---|---|---|
| `crates/mantis-mcp/src/wave.rs` | `crates/mantis-mcp/src/pass.rs` | Matches new vocabulary. |
| `plugin/claude-code/playbooks/cap-*.md` | `plugin/claude-code/handbook/method-*.md` | New directory + filename pattern. "Handbook" / "method" rather than "playbook" / "capability-pack". |
| `prompts/roles/` | `prompts/passes/` | Aligns with the pass-based orchestration model. |
| `plugin/claude-code/agents/` | `plugin/claude-code/passes/` | Same. |

## What this does NOT change

- The Rust crate structure outside `mantis-mcp/src/wave.rs` and the prompt
  directories.
- The MCP tool naming (which is already being migrated to CLI under
  `mantis tools <name>` separately — see `MCP_TO_CLI_MIGRATION.md`).
- The daemon's gRPC proto wire format. Field names in `mantis.v1.*` can be
  renamed at a major-version proto bump; until then, the gRPC layer remains
  compatible.
- The `mantis-chain` merkle event log format. Renaming wouldn't help here
  and would break replay against historical engagements.

## Implementation ordering

Each row in the [transition audit](./TRANSITION_AUDIT.md) becomes its own
PR. The renames in this proposal land in this order:

1. **This proposal doc itself** — establishes the vocabulary so subsequent
   PRs reference it.
2. **Severity ladder rules** in `wave.rs` — new algorithm, new tests. The
   file stays at `wave.rs` for this step to keep the diff focused.
3. **Chain-outcome enum rename** with serde compatibility shim (accepts
   both old and new variant names during a transition window for any
   persisted state).
4. **Completion-marker rename** — search-and-replace + prompt updates that
   are part of the broader prompt clean-room (those PRs are pending anyway).
5. **File / module path renames** (`wave.rs` → `pass.rs`, etc.) — last,
   because they cause the largest diff. Done as `git mv` so blame survives.

## Open questions for resolution before implementation

- Should the `Gated` outcome carry a typed `scope_rule_id` field, or stay
  string-based for serde compatibility with older event-log entries? (Lean:
  add a new typed field, keep an optional fallback string.)
- Do the `_PASS_FILED` markers need to remain backward-compatible with
  any external tooling that grep's for `MANTIS_*_DONE`? Audit needed.
- Is "pass" / "transcript" / "reconcile" the right metaphor, or is there
  a better one? Open to alternatives but the principle is: must not echo
  `wave` / `handoff` / `merge`.

## Faithful acknowledgement

This proposal is the design step; no derivative content has been replaced
yet. Each subsequent PR will land one row of the proposal and update the
[transition audit](./TRANSITION_AUDIT.md) accordingly.

Hacker Bob remains the architectural inspiration in `NOTICE` regardless of
what specific names Mantis uses internally — the renames don't erase the
inspiration credit, they just make the Mantis implementation independent
of the upstream's vocabulary and semantics.
