# Transition audit — Mantis independence checklist

## Purpose

Mantis is transitioning from a hybrid (Rust substrate + ports from Hacker Bob)
to a fully independent project where **no line of code, no prompt, no
architectural primitive, and no execution-flow name is derivative content**.

This document is the single source of truth for the transition state. Every
potentially-derivative item is enumerated here with its clean-room
replacement status. The transition is "done" when every row is checked.

The license history that motivated this transition is documented separately
in [`NOTICE`](../NOTICE) and [`PORTING.md`](../PORTING.md); those remain as
historical record and are not affected by the transition itself.

## Status legend

- `[ ]` — Still derivative; clean-room replacement not yet shipped.
- `[~]` — Clean-room replacement in progress on a tracked branch / PR.
- `[x]` — Clean-room replacement landed on `main`. The new content was
  written without reference to the upstream original, with the process
  documented in the corresponding PR.

A `[x]` requires evidence: the PR description must state the clean-room
process used (air-gap, cooling-off period, who wrote it, what inputs they
had access to).

## Items

### 1. Code (Rust)

The Rust workspace (60+ crates) is original work. The `NOTICE` explicitly
attests this: *"All Rust code in `crates/` and Mantis-original playbook
markdown is written from scratch."*

| Item | Status | Evidence |
|---|---|---|
| `crates/mantis-core` | `[x]` | Original. No Hacker Bob equivalent (HB is Node.js). |
| `crates/mantis-daemon` | `[x]` | Original. |
| `crates/mantis-egress` | `[x]` | Original — Mantis differentiator, no HB equivalent. |
| `crates/mantis-chain` | `[x]` | Original — merkle event log. |
| `crates/mantis-event-store` | `[x]` | Original. |
| `crates/mantis-fsm` | `[x]` | Original. |
| `crates/mantis-hibernation` | `[x]` | Original. |
| `crates/mantis-claim` | `[x]` | Original. |
| `crates/mantis-verify` | `[x]` | Original. |
| `crates/mantis-mcp` (substrate code) | `[x]` | Independent Rust impl on `rmcp` crate. |
| `crates/mantis-threat-intel` | `[x]` | Original (shipped 2026-05-25). |
| `crates/mantis-compliance` | `[x]` | Original (shipped 2026-05-25). |
| `crates/mantis-notify` | `[x]` | Original (shipped 2026-05-25). |
| `crates/mantis-bench` (testbeds, baseline, reproducibility) | `[x]` | Original (shipped 2026-05-25). |
| `crates/mantis-cli` | `[x]` | Original. |
| `crates/mantis-cli/src/tools/decode_jwt.rs` | `[x]` | Clean port of Mantis-internal `mantis_decode_jwt`; algorithm was always original to Mantis. PR #74. |

### 2. Agent prompts (Markdown) — derivative content, transition pending

The 35 files below were ported verbatim from Hacker Bob and currently carry
Apache-2.0 §4(b) headers. Each must be replaced with a clean-room rewrite
that:

- Uses different organizing principles (different section headers, different
  flow, different examples).
- References `mantis-cli` invocations (not `mcp__mantis__mantis_*` tool names).
- Uses Mantis-original execution-flow markers (see item 4).
- Has no line of text identical to the original.
- Drops the §4(b) header (new content is not derivative).

Process: see [`docs/CLEAN_ROOM_PROCESS.md`](./CLEAN_ROOM_PROCESS.md) (to be
created with the first rewrite).

#### `plugin/claude-code/agents/` (16 files)

| File | Status |
|---|---|
| `balanced-verifier.md` | `[ ]` |
| `brutalist-verifier.md` | `[ ]` |
| `chain-builder.md` | `[ ]` |
| `deep-recon-agent.md` | `[ ]` |
| `evidence-agent.md` | `[ ]` |
| `final-verifier.md` | `[ ]` |
| `grader.md` | `[ ]` |
| `hunter-agent.md` | `[ ]` |
| `hunter-cosmwasm-agent.md` | `[ ]` |
| `hunter-evm-agent.md` | `[ ]` |
| `hunter-move-agent.md` | `[ ]` |
| `hunter-substrate-agent.md` | `[ ]` |
| `hunter-svm-agent.md` | `[ ]` |
| `recon-agent.md` | `[ ]` |
| `report-writer.md` | `[ ]` |
| `surface-router-agent.md` | `[ ]` |

#### `prompts/roles/` (19 ported files; 3 Mantis-original)

| File | Status |
|---|---|
| `balanced-verifier.md` | `[ ]` |
| `brutalist-verifier.md` | `[ ]` |
| `chain.md` | `[ ]` |
| `debug.md` | `[ ]` |
| `deep-recon.md` | `[ ]` |
| `evidence.md` | `[ ]` |
| `final-verifier.md` | `[ ]` |
| `grader.md` | `[ ]` |
| `hunter-cosmwasm.md` | `[ ]` |
| `hunter-evm.md` | `[ ]` |
| `hunter-move.md` | `[ ]` |
| `hunter-substrate.md` | `[ ]` |
| `hunter-svm.md` | `[ ]` |
| `hunter.md` | `[ ]` |
| `orchestrator.md` | `[ ]` |
| `recon.md` | `[ ]` |
| `reporter.md` | `[ ]` |
| `status.md` | `[ ]` |
| `surface-router.md` | `[ ]` |
| `chain-deep.md` | `[x]` | Mantis-original. |
| `grade-deep.md` | `[x]` | Mantis-original. |
| `verify-cascade-deep.md` | `[x]` | Mantis-original. |

### 3. Architectural primitives in Rust code

These are constructs documented in `NOTICE` as "ported verbatim into
`crates/mantis-mcp/src/wave.rs`". They need fresh designs with different
semantics, not just renamed values.

| Item | Current state | Status |
|---|---|---|
| Chain-attempt outcome enum (`confirmed`, `denied`, `blocked`, `inconclusive`, `not_applicable`) | Verbatim ported per `NOTICE` | `[ ]` |
| Severity ladder rules (`LOW+LOW=LOW`; `max input + 1` without rationale; `max input + 2` with `elevation:` rationale; no jump-the-rung) | Verbatim ported per `NOTICE` | `[ ]` |
| Wave / handoff / merge naming for parallel hunter agents | Inspired by HB's `bounty_start_next_wave` / `bounty_write_wave_handoff` / `bounty_merge_wave_handoffs` | `[ ]` |
| JSONL append model for chain attempts (`waves/<n>/chain-attempts.jsonl`) | Pattern conceptually borrowed from HB's `mcp/lib/chain-attempts.js` | `[ ]` |
| Capability-playbook flat-markdown layout under `plugin/claude-code/playbooks/` | Pattern borrowed from HB's `mcp/lib/capability-playbooks.js` directory convention | `[ ]` |

### 4. Execution-flow markers

| Item | Current state | Status |
|---|---|---|
| Completion markers (`MANTIS_HUNTER_DONE`, `MANTIS_VERIFIER_DONE`, etc.) | Mechanical rename of HB's `BOB_*_DONE` scheme | `[ ]` |
| Phase-transition signals | Pattern echoes HB's FAN_OUT / merge phases | `[ ]` |

### 5. Inspiration-only items (no clean-room required)

These items are architectural concepts, not copyrightable artifacts. They
require attribution under "Third-party attributions" in `NOTICE` but NOT
clean-room replacement.

| Item | Status |
|---|---|
| MCP-tool-orchestrated workflow as a *concept* | `[x]` Concept; not copyrightable |
| Parallel-hunter-wave as a *concept* | `[x]` Concept; not copyrightable |
| Three-round verification cascade as a *concept* | `[x]` Concept; not copyrightable |

These remain credited as inspiration in `NOTICE` even after the transition
completes. Inspiration credit is permanent; what changes is whether the
*implementation* is independent.

## Definition of done

The transition is complete when:

1. Every row in sections 2, 3, and 4 is `[x]`.
2. The `NOTICE` file's "Status as of [date]" section is updated to state that
   no derivative content is currently distributed by Mantis.
3. The Apache-2.0 §4(b) headers are removed from the (now-replaced) prompt
   files because the new versions are not derivative works.
4. `PORTING.md` is updated to a historical-only document (the present-tense
   port inventory becomes past-tense, since current Mantis contains no
   active ports).
5. The historical NOTICE "Apology and compliance history" section **stays**
   — it is a permanent record of the prior derivative period, not something
   that is "fixed" by the transition.

## Process invariants

Throughout the transition, the project maintains:

- **No covering of tracks.** The git history shows the derivative period;
  no commits are rewritten or squashed to hide it.
- **Self-disclosure stays.** `NOTICE`'s apology section is permanent.
- **Per-PR transparency.** Every clean-room rewrite PR explicitly states the
  process used and which derivative item it replaces.
- **Inspiration credit preserved.** Hacker Bob remains credited in `NOTICE`
  as architectural inspiration, even after no implementation is shared.

## How to use this document

When opening a PR that lands a clean-room replacement, update the
corresponding row from `[ ]` to `[~]` (during development) or `[x]` (when
merged). Include the PR number and an "Evidence" column entry noting which
process was used (air-gap, cooling-off, contributor identity, etc.).

This document is part of the audit trail.
