# PORTING.md — Exhaustive Hacker Bob → Mantis Port Inventory

> **What this file is.** A complete, machine-extractable record of every file, symbol, constant, tool name, completion marker, and convention that Mantis ports from [vmihalis/hacker-bob](https://github.com/vmihalis/hacker-bob) (Apache-2.0, Copyright 2026 Michail Vasileiadis). This document supplements [`NOTICE`](./NOTICE) (the legal attribution + apology) and [`CONTRAST.md`](./CONTRAST.md) (the operator-facing comparison). If you need to verify any specific claim about what was or wasn't ported, this is the source of truth.
>
> **Generated:** 2026-05-25. The per-file inventory below was extracted programmatically from the `Apache-2.0 §4(b)` headers that mark every ported file; the symbol-level table was extracted from `Mirrors hacker-bob's` / `Ports hacker-bob's` docstring markers in the Rust crates. If a port is added or removed, regenerate this file by running `scripts/regen-porting.sh` (TODO) or re-extract from the §4(b) markers.

## Quick links

- Upstream: [vmihalis/hacker-bob](https://github.com/vmihalis/hacker-bob)
- License: Apache-2.0 ([LICENSE](https://github.com/vmihalis/hacker-bob/blob/main/LICENSE))
- Upstream NOTICE (reproduced verbatim in our [`NOTICE`](./NOTICE)): [hacker-bob/NOTICE](https://github.com/vmihalis/hacker-bob/blob/main/NOTICE)
- Apology + compliance history: [`NOTICE`](./NOTICE), "Apology and compliance history" section
- Public paper trail filed with upstream: [hacker-bob#49](https://github.com/vmihalis/hacker-bob/issues/49)

## Section 1 — Conventions applied to every port

Every ported file applies the following uniform transformations. They are documented once here so per-file headers can stay short.

### 1.1 Tool-name rename (`bounty_*` → `mantis_*`)

Every MCP tool call in upstream prompts uses the `bounty_*` prefix; Mantis runs an equivalent tool table under the `mantis_*` prefix. The mapping is 1:1 by suffix.

| Hacker Bob tool | Mantis tool | Notes |
|---|---|---|
| `bounty_http_scan` | `mantis_http_scan` | HTTP probe primitive |
| `bounty_signup_detect` | (Rust direct, no MCP tool) | logic in `crates/mantis-orchestrator/src/discover.rs` |
| `bounty_temp_email` | (not yet ported) | see "Not yet ported" |
| `bounty_auto_signup` | (not yet ported) | needs Patchright + CAPTCHA solver, see "Not yet ported" |
| `bounty_write_chain_attempt` | `mantis_record_chain_attempt` | severity ladder enforced server-side |
| `bounty_start_next_wave` | `mantis_start_wave` | parallel hunter coordination |
| `bounty_write_wave_handoff` | `mantis_write_handoff` | per-hunter handoff |
| `bounty_merge_wave_handoffs` | `mantis_merge_wave` | wave reconciliation |
| `bounty_*` (every other tool referenced in ported prompts) | `mantis_*` (same suffix) | Some are implemented as Rust calls inside the daemon and never exposed as MCP tools |

Every `bounty_*` reference in a ported prompt was mechanically renamed to `mantis_*` at port time. If a ported prompt references a `mantis_*` tool that does not yet exist in `crates/mantis-mcp/src/server.rs`, that is a documented gap — see [`CONTRAST.md`](./CONTRAST.md) "What hacker-bob has that Mantis still lacks."

### 1.2 Session-path rename

| Hacker Bob | Mantis |
|---|---|
| `~/bounty-agent-sessions/[domain]/` | `./mantishack-<engagement-id>/` |

All ported prompts and skill files reference the Mantis path scheme. Engagement state is filesystem-backed plus mirrored into a per-engagement RocksDB store via `crates/mantis-event-store`.

### 1.3 Completion-marker rename

Each ported agent emits a structured `*_DONE` marker on completion. Mantis renames the prefix:

| Hacker Bob marker | Mantis marker | Emitted by |
|---|---|---|
| `BOB_HUNTER_DONE` | `MANTIS_HUNTER_DONE` | per-surface hunter agent |
| `BOB_CHAIN_DONE` | `MANTIS_CHAIN_DONE` | chain-builder agent |
| `BOB_VERIFY_DONE` | `MANTIS_VERIFY_DONE` | brutalist / balanced / final verifier agents |
| `BOB_EVIDENCE_DONE` | `MANTIS_EVIDENCE_DONE` | evidence-agent |
| `BOB_GRADE_DONE` | `MANTIS_GRADE_DONE` | grader agent |
| `BOB_REPORT_DONE` | `MANTIS_REPORT_DONE` | report-writer agent |

The marker payload schema is preserved verbatim (mode, surface_id / claim_id, summary fields).

### 1.4 Slash-command rename

| Hacker Bob slash command | Mantis slash command |
|---|---|
| `/bob-hunt` | `/mantis-scan` (primary) + `/mantishack` (one-shot pipeline) |
| `/bob-status` | `/mantis-status` |
| `/bob-debug` | `/mantis-doctor` |
| `/bob-egress` | `/mantis-egress` |
| `/bob-export` | `/mantis-export` |
| `/bob-update` | `/mantis-update` |

The Mantis slash-command set additionally includes Mantis-original commands not present upstream: `/mantis-claim`, `/mantis-daemon`, `/mantis-report`, `/mantis-resume`, `/mantis-wave`. Those are Mantis-native and not ports.

### 1.5 No source porting beyond what is listed in Section 2

The Rust runtime crates (`crates/mantis-core`, `mantis-event-store`, `mantis-egress`, `mantis-scope`, `mantis-runtime`, `mantis-daemon`, `mantis-tenant`, `mantis-k8s`, `mantis-gateway`, `mantis-tui*`, etc.) are independent Rust implementations. They do not port hacker-bob source. The files in Section 2 are the complete inventory of ported and derived material.

## Section 2 — Per-file port inventory

Every file in this section carries an `Apache-2.0 §4(b)` change-notice header pointing at the same upstream URL listed here. **Total: 104 ported files** across 11 destination directories.

### `.claude/agents/` — 16 ported files

- [`.claude/agents/balanced-verifier.md`](./.claude/agents/balanced-verifier.md) ← [`.claude/agents/balanced-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/balanced-verifier.md)
- [`.claude/agents/brutalist-verifier.md`](./.claude/agents/brutalist-verifier.md) ← [`.claude/agents/brutalist-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/brutalist-verifier.md)
- [`.claude/agents/chain-builder.md`](./.claude/agents/chain-builder.md) ← [`.claude/agents/chain-builder.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/chain-builder.md)
- [`.claude/agents/deep-recon-agent.md`](./.claude/agents/deep-recon-agent.md) ← [`.claude/agents/deep-recon-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/deep-recon-agent.md)
- [`.claude/agents/evidence-agent.md`](./.claude/agents/evidence-agent.md) ← [`.claude/agents/evidence-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/evidence-agent.md)
- [`.claude/agents/final-verifier.md`](./.claude/agents/final-verifier.md) ← [`.claude/agents/final-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/final-verifier.md)
- [`.claude/agents/grader.md`](./.claude/agents/grader.md) ← [`.claude/agents/grader.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/grader.md)
- [`.claude/agents/hunter-agent.md`](./.claude/agents/hunter-agent.md) ← [`.claude/agents/hunter-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-agent.md)
- [`.claude/agents/hunter-cosmwasm-agent.md`](./.claude/agents/hunter-cosmwasm-agent.md) ← [`.claude/agents/hunter-cosmwasm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-cosmwasm-agent.md)
- [`.claude/agents/hunter-evm-agent.md`](./.claude/agents/hunter-evm-agent.md) ← [`.claude/agents/hunter-evm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-evm-agent.md)
- [`.claude/agents/hunter-move-agent.md`](./.claude/agents/hunter-move-agent.md) ← [`.claude/agents/hunter-move-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-move-agent.md)
- [`.claude/agents/hunter-substrate-agent.md`](./.claude/agents/hunter-substrate-agent.md) ← [`.claude/agents/hunter-substrate-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-substrate-agent.md)
- [`.claude/agents/hunter-svm-agent.md`](./.claude/agents/hunter-svm-agent.md) ← [`.claude/agents/hunter-svm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-svm-agent.md)
- [`.claude/agents/recon-agent.md`](./.claude/agents/recon-agent.md) ← [`.claude/agents/recon-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/recon-agent.md)
- [`.claude/agents/report-writer.md`](./.claude/agents/report-writer.md) ← [`.claude/agents/report-writer.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/report-writer.md)
- [`.claude/agents/surface-router-agent.md`](./.claude/agents/surface-router-agent.md) ← [`.claude/agents/surface-router-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/surface-router-agent.md)

### `.claude/commands/` — 3 ported files

- [`.claude/commands/mantis-egress.md`](./.claude/commands/mantis-egress.md) ← [`.claude/commands/bob-egress.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/commands/bob-egress.md)
- [`.claude/commands/mantis-export.md`](./.claude/commands/mantis-export.md) ← [`.claude/commands/bob-export.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/commands/bob-export.md)
- [`.claude/commands/mantis-update.md`](./.claude/commands/mantis-update.md) ← [`.claude/commands/bob-update.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/commands/bob-update.md)

### `.claude/skills/` — 3 ported files

- [`.claude/skills/mantis-debug/SKILL.md`](./.claude/skills/mantis-debug/SKILL.md) ← [`.claude/skills/bob-debug/SKILL.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/skills/bob-debug/SKILL.md)
- [`.claude/skills/mantis-hunt/SKILL.md`](./.claude/skills/mantis-hunt/SKILL.md) ← [`.claude/skills/bob-hunt/SKILL.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/skills/bob-hunt/SKILL.md)
- [`.claude/skills/mantis-status/SKILL.md`](./.claude/skills/mantis-status/SKILL.md) ← [`.claude/skills/bob-status/SKILL.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/skills/bob-status/SKILL.md)

### `(repo root)` — 3 ported files

- [`CLAUDE.md`](./CLAUDE.md) ← [`CLAUDE.md`](https://github.com/vmihalis/hacker-bob/blob/main/CLAUDE.md)
- [`DISCLAIMER_BOB_STYLE.md`](./DISCLAIMER_BOB_STYLE.md) ← [`DISCLAIMER.md`](https://github.com/vmihalis/hacker-bob/blob/main/DISCLAIMER.md)
- [`SECURITY_BOB_STYLE.md`](./SECURITY_BOB_STYLE.md) ← [`SECURITY.md`](https://github.com/vmihalis/hacker-bob/blob/main/SECURITY.md)

### `crates/mantis-auth-differential/` — 2 ported files

- [`crates/mantis-auth-differential/src/classify.rs`](./crates/mantis-auth-differential/src/classify.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-auth-differential/src/lib.rs`](./crates/mantis-auth-differential/src/lib.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-auth/` — 1 ported file

- [`crates/mantis-auth/src/lib.rs`](./crates/mantis-auth/src/lib.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-fsm/` — 7 ported files

- [`crates/mantis-fsm/src/adjudication.rs`](./crates/mantis-fsm/src/adjudication.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-fsm/src/coverage.rs`](./crates/mantis-fsm/src/coverage.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-fsm/src/evidence.rs`](./crates/mantis-fsm/src/evidence.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-fsm/src/grade.rs`](./crates/mantis-fsm/src/grade.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-fsm/src/lib.rs`](./crates/mantis-fsm/src/lib.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-fsm/src/state.rs`](./crates/mantis-fsm/src/state.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-fsm/src/verification.rs`](./crates/mantis-fsm/src/verification.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-mcp/` — 3 ported files

- [`crates/mantis-mcp/src/lib.rs`](./crates/mantis-mcp/src/lib.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-mcp/src/server.rs`](./crates/mantis-mcp/src/server.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-mcp/src/wave.rs`](./crates/mantis-mcp/src/wave.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-orchestrator/` — 2 ported files

- [`crates/mantis-orchestrator/src/discover.rs`](./crates/mantis-orchestrator/src/discover.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-orchestrator/src/lib.rs`](./crates/mantis-orchestrator/src/lib.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-pack/` — 1 ported file

- [`crates/mantis-pack/src/lib.rs`](./crates/mantis-pack/src/lib.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-recon-tools/` — 2 ported files

- [`crates/mantis-recon-tools/src/inventory.rs`](./crates/mantis-recon-tools/src/inventory.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-recon-tools/src/lib.rs`](./crates/mantis-recon-tools/src/lib.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-report/` — 1 ported file

- [`crates/mantis-report/src/severity.rs`](./crates/mantis-report/src/severity.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-scanner-http/` — 1 ported file

- [`crates/mantis-scanner-http/src/probe.rs`](./crates/mantis-scanner-http/src/probe.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `crates/mantis-signup/` — 2 ported files

- [`crates/mantis-signup/src/email.rs`](./crates/mantis-signup/src/email.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)
- [`crates/mantis-signup/src/lib.rs`](./crates/mantis-signup/src/lib.rs) ← [`https://github.com/vmihalis/hacker-bob`](https://github.com/vmihalis/hacker-bob)

### `npm/mantishack/plugin/` — 18 ported files

- [`npm/mantishack/plugin/claude-code/agents/balanced-verifier.md`](./npm/mantishack/plugin/claude-code/agents/balanced-verifier.md) ← [`.claude/agents/balanced-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/balanced-verifier.md)
- [`npm/mantishack/plugin/claude-code/agents/brutalist-verifier.md`](./npm/mantishack/plugin/claude-code/agents/brutalist-verifier.md) ← [`.claude/agents/brutalist-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/brutalist-verifier.md)
- [`npm/mantishack/plugin/claude-code/agents/chain-builder.md`](./npm/mantishack/plugin/claude-code/agents/chain-builder.md) ← [`.claude/agents/chain-builder.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/chain-builder.md)
- [`npm/mantishack/plugin/claude-code/agents/deep-recon-agent.md`](./npm/mantishack/plugin/claude-code/agents/deep-recon-agent.md) ← [`.claude/agents/deep-recon-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/deep-recon-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/evidence-agent.md`](./npm/mantishack/plugin/claude-code/agents/evidence-agent.md) ← [`.claude/agents/evidence-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/evidence-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/final-verifier.md`](./npm/mantishack/plugin/claude-code/agents/final-verifier.md) ← [`.claude/agents/final-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/final-verifier.md)
- [`npm/mantishack/plugin/claude-code/agents/grader.md`](./npm/mantishack/plugin/claude-code/agents/grader.md) ← [`.claude/agents/grader.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/grader.md)
- [`npm/mantishack/plugin/claude-code/agents/hunter-agent.md`](./npm/mantishack/plugin/claude-code/agents/hunter-agent.md) ← [`.claude/agents/hunter-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/hunter-cosmwasm-agent.md`](./npm/mantishack/plugin/claude-code/agents/hunter-cosmwasm-agent.md) ← [`.claude/agents/hunter-cosmwasm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-cosmwasm-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/hunter-evm-agent.md`](./npm/mantishack/plugin/claude-code/agents/hunter-evm-agent.md) ← [`.claude/agents/hunter-evm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-evm-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/hunter-move-agent.md`](./npm/mantishack/plugin/claude-code/agents/hunter-move-agent.md) ← [`.claude/agents/hunter-move-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-move-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/hunter-substrate-agent.md`](./npm/mantishack/plugin/claude-code/agents/hunter-substrate-agent.md) ← [`.claude/agents/hunter-substrate-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-substrate-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/hunter-svm-agent.md`](./npm/mantishack/plugin/claude-code/agents/hunter-svm-agent.md) ← [`.claude/agents/hunter-svm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-svm-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/recon-agent.md`](./npm/mantishack/plugin/claude-code/agents/recon-agent.md) ← [`.claude/agents/recon-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/recon-agent.md)
- [`npm/mantishack/plugin/claude-code/agents/report-writer.md`](./npm/mantishack/plugin/claude-code/agents/report-writer.md) ← [`.claude/agents/report-writer.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/report-writer.md)
- [`npm/mantishack/plugin/claude-code/agents/surface-router-agent.md`](./npm/mantishack/plugin/claude-code/agents/surface-router-agent.md) ← [`.claude/agents/surface-router-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/surface-router-agent.md)
- [`npm/mantishack/plugin/claude-code/playbooks/README.md`](./npm/mantishack/plugin/claude-code/playbooks/README.md) ← [`prompts/playbooks`](https://github.com/vmihalis/hacker-bob/tree/main/prompts/playbooks)
- [`npm/mantishack/plugin/claude-code/playbooks/cap-multi-account-differential.md`](./npm/mantishack/plugin/claude-code/playbooks/cap-multi-account-differential.md) ← [`prompts/playbooks/C4_multi_account_differential.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/playbooks/C4_multi_account_differential.md)

### `plugin/claude-code/agents/` — 16 ported files

- [`plugin/claude-code/agents/balanced-verifier.md`](./plugin/claude-code/agents/balanced-verifier.md) ← [`.claude/agents/balanced-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/balanced-verifier.md)
- [`plugin/claude-code/agents/brutalist-verifier.md`](./plugin/claude-code/agents/brutalist-verifier.md) ← [`.claude/agents/brutalist-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/brutalist-verifier.md)
- [`plugin/claude-code/agents/chain-builder.md`](./plugin/claude-code/agents/chain-builder.md) ← [`.claude/agents/chain-builder.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/chain-builder.md)
- [`plugin/claude-code/agents/deep-recon-agent.md`](./plugin/claude-code/agents/deep-recon-agent.md) ← [`.claude/agents/deep-recon-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/deep-recon-agent.md)
- [`plugin/claude-code/agents/evidence-agent.md`](./plugin/claude-code/agents/evidence-agent.md) ← [`.claude/agents/evidence-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/evidence-agent.md)
- [`plugin/claude-code/agents/final-verifier.md`](./plugin/claude-code/agents/final-verifier.md) ← [`.claude/agents/final-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/final-verifier.md)
- [`plugin/claude-code/agents/grader.md`](./plugin/claude-code/agents/grader.md) ← [`.claude/agents/grader.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/grader.md)
- [`plugin/claude-code/agents/hunter-agent.md`](./plugin/claude-code/agents/hunter-agent.md) ← [`.claude/agents/hunter-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-agent.md)
- [`plugin/claude-code/agents/hunter-cosmwasm-agent.md`](./plugin/claude-code/agents/hunter-cosmwasm-agent.md) ← [`.claude/agents/hunter-cosmwasm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-cosmwasm-agent.md)
- [`plugin/claude-code/agents/hunter-evm-agent.md`](./plugin/claude-code/agents/hunter-evm-agent.md) ← [`.claude/agents/hunter-evm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-evm-agent.md)
- [`plugin/claude-code/agents/hunter-move-agent.md`](./plugin/claude-code/agents/hunter-move-agent.md) ← [`.claude/agents/hunter-move-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-move-agent.md)
- [`plugin/claude-code/agents/hunter-substrate-agent.md`](./plugin/claude-code/agents/hunter-substrate-agent.md) ← [`.claude/agents/hunter-substrate-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-substrate-agent.md)
- [`plugin/claude-code/agents/hunter-svm-agent.md`](./plugin/claude-code/agents/hunter-svm-agent.md) ← [`.claude/agents/hunter-svm-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/hunter-svm-agent.md)
- [`plugin/claude-code/agents/recon-agent.md`](./plugin/claude-code/agents/recon-agent.md) ← [`.claude/agents/recon-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/recon-agent.md)
- [`plugin/claude-code/agents/report-writer.md`](./plugin/claude-code/agents/report-writer.md) ← [`.claude/agents/report-writer.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/report-writer.md)
- [`plugin/claude-code/agents/surface-router-agent.md`](./plugin/claude-code/agents/surface-router-agent.md) ← [`.claude/agents/surface-router-agent.md`](https://github.com/vmihalis/hacker-bob/blob/main/.claude/agents/surface-router-agent.md)

### `plugin/claude-code/playbooks/` — 2 ported files

- [`plugin/claude-code/playbooks/README.md`](./plugin/claude-code/playbooks/README.md) ← [`prompts/playbooks`](https://github.com/vmihalis/hacker-bob/tree/main/prompts/playbooks)
- [`plugin/claude-code/playbooks/cap-multi-account-differential.md`](./plugin/claude-code/playbooks/cap-multi-account-differential.md) ← [`prompts/playbooks/C4_multi_account_differential.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/playbooks/C4_multi_account_differential.md)

### `prompts/playbooks/` — 2 ported files

- [`prompts/playbooks/C2_doc_vs_behavior.md`](./prompts/playbooks/C2_doc_vs_behavior.md) ← [`prompts/playbooks/C2_doc_vs_behavior.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/playbooks/C2_doc_vs_behavior.md)
- [`prompts/playbooks/C4_multi_account_differential.md`](./prompts/playbooks/C4_multi_account_differential.md) ← [`prompts/playbooks/C4_multi_account_differential.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/playbooks/C4_multi_account_differential.md)

### `prompts/roles/` — 19 ported files

- [`prompts/roles/balanced-verifier.md`](./prompts/roles/balanced-verifier.md) ← [`prompts/roles/balanced-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/balanced-verifier.md)
- [`prompts/roles/brutalist-verifier.md`](./prompts/roles/brutalist-verifier.md) ← [`prompts/roles/brutalist-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/brutalist-verifier.md)
- [`prompts/roles/chain.md`](./prompts/roles/chain.md) ← [`prompts/roles/chain.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/chain.md)
- [`prompts/roles/debug.md`](./prompts/roles/debug.md) ← [`prompts/roles/debug.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/debug.md)
- [`prompts/roles/deep-recon.md`](./prompts/roles/deep-recon.md) ← [`prompts/roles/deep-recon.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/deep-recon.md)
- [`prompts/roles/evidence.md`](./prompts/roles/evidence.md) ← [`prompts/roles/evidence.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/evidence.md)
- [`prompts/roles/final-verifier.md`](./prompts/roles/final-verifier.md) ← [`prompts/roles/final-verifier.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/final-verifier.md)
- [`prompts/roles/grader.md`](./prompts/roles/grader.md) ← [`prompts/roles/grader.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/grader.md)
- [`prompts/roles/hunter-cosmwasm.md`](./prompts/roles/hunter-cosmwasm.md) ← [`prompts/roles/hunter-cosmwasm.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/hunter-cosmwasm.md)
- [`prompts/roles/hunter-evm.md`](./prompts/roles/hunter-evm.md) ← [`prompts/roles/hunter-evm.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/hunter-evm.md)
- [`prompts/roles/hunter-move.md`](./prompts/roles/hunter-move.md) ← [`prompts/roles/hunter-move.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/hunter-move.md)
- [`prompts/roles/hunter-substrate.md`](./prompts/roles/hunter-substrate.md) ← [`prompts/roles/hunter-substrate.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/hunter-substrate.md)
- [`prompts/roles/hunter-svm.md`](./prompts/roles/hunter-svm.md) ← [`prompts/roles/hunter-svm.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/hunter-svm.md)
- [`prompts/roles/hunter.md`](./prompts/roles/hunter.md) ← [`prompts/roles/hunter.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/hunter.md)
- [`prompts/roles/orchestrator.md`](./prompts/roles/orchestrator.md) ← [`prompts/roles/orchestrator.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/orchestrator.md)
- [`prompts/roles/recon.md`](./prompts/roles/recon.md) ← [`prompts/roles/recon.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/recon.md)
- [`prompts/roles/reporter.md`](./prompts/roles/reporter.md) ← [`prompts/roles/reporter.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/reporter.md)
- [`prompts/roles/status.md`](./prompts/roles/status.md) ← [`prompts/roles/status.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/status.md)
- [`prompts/roles/surface-router.md`](./prompts/roles/surface-router.md) ← [`prompts/roles/surface-router.md`](https://github.com/vmihalis/hacker-bob/blob/main/prompts/roles/surface-router.md)


## Section 3 — Symbol-level ports (Rust crates)

Each row below names a specific Rust symbol (struct, enum, constant, function, method, or algorithm shape) that Mantis carries from a named upstream Hacker Bob file. The surrounding Rust implementation is original — these are the islands of explicit derivation.

| Mantis crate · symbol | Upstream Hacker Bob source | Nature of port |
|---|---|---|
| `mantis-mcp/src/wave.rs` · `ChainAttemptOutcome` enum | `prompts/roles/chain.md` + `mcp/lib/chain-attempts.js` | **Verbatim port** of the outcome variants (`confirmed`, `denied`, `blocked`, `inconclusive`, `not_applicable`) |
| `mantis-mcp/src/wave.rs` · severity-ladder rules | `prompts/roles/chain.md` | **Verbatim port** of: `LOW + LOW = LOW`, `max(input)+1` without rationale, `max(input)+2` with explicit `elevation:` rationale, no jump-the-rung |
| `mantis-mcp/src/wave.rs` · wave / handoff / merge protocol | `bounty_start_next_wave` / `bounty_write_wave_handoff` / `bounty_merge_wave_handoffs` | Inspired-by — pattern and tool surface ported, Rust implementation is independent |
| `mantis-mcp/src/server.rs` · `// Ported MCP-tool surface` block | Hacker Bob's `bounty_*` tool table | Each Mantis tool is named to match the hacker-bob equivalent; descriptions cite the upstream tool by name |
| `mantis-fsm/src/grade.rs` · `GRADE_HOLD_MIN_SCORE = 20`, `GRADE_SUBMIT_MIN_SCORE = 40` | Hacker Bob's grader | **Verbatim port** of the SUBMIT ≥ 40 / HOLD 20–39 / SKIP < 20 thresholds plus the "at least one Medium-or-higher finding" rule |
| `mantis-fsm/src/grade.rs` · 5-axis score | Hacker Bob's grader | **Verbatim port** of the axes: `impact (0–30) + proof_quality (0–25) + severity_accuracy (0–15) + chain_potential (0–15) + report_quality (0–15)` |
| `mantis-fsm/src/adjudication.rs` · `build_verification_adjudication` | `mcp/lib/verification.js` `buildVerificationAdjudication` (~L756) | **Ports verbatim** the adjudication-plan-hash construction and the surrounding attempt/snapshot infrastructure |
| `mantis-fsm/src/adjudication.rs` · `SMALL_REPORTABLE_THRESHOLD = 5` | `VERIFY_SMALL_REPORTABLE_THRESHOLD` | **Verbatim** constant value |
| `mantis-fsm/src/adjudication.rs` · `QA_SAMPLE_MAX = 10` | `VERIFY_QA_SAMPLE_MAX` | **Verbatim** constant value |
| `mantis-fsm/src/coverage.rs` · `CoverageKey` tuple | `mcp/lib/coverage.js` coverage-row tuple | **Mirrors** the (surface, method, endpoint, bug_class, auth_profile) shape |
| `mantis-fsm/src/coverage.rs` · `COVERAGE_STATUS_VALUES` | `coverage.js COVERAGE_STATUS_VALUES` | **Verbatim** status enum values |
| `mantis-fsm/src/evidence.rs` · `EvidencePack` | `mcp/lib/evidence.js` | **Mirrors** the bounded per-finding artifact shape (`representative_samples`, `replay_summary`, `report_snippet`) |
| `mantis-fsm/src/evidence.rs` · `validate_pack_coverage` | `requireValidEvidencePacksForFinalReportableFindings` | **Mirrors** the validation rule |
| `mantis-fsm/src/verification.rs` · brutalist / balanced / final pipeline | `mcp/lib/verification.js` | **Mirrors** the three-round cascade shape; per-round emission per finding; downstream gate requirement |
| `mantis-auth/src/lib.rs` · `AuthProfile`, `AuthStore` | `mcp/lib/auth.js` + `mcp/lib/tools/auth-store.js` | **Ports** the cookie/header/query injection model; Rust adds zeroize-on-drop semantics |
| `mantis-auth-differential/src/lib.rs` · classify pipeline | `mcp/lib/auth-differential.js` | **Ports** the differential-response classifier pipeline |
| `mantis-auth-differential/src/classify.rs` · classification heuristics | `auth-differential.js` classifier | **Mirrors** the diff → classification ruleset |
| `mantis-scanner-http/src/probe.rs` · `auth_profile` field | `bounty_http_scan` `auth_profile` argument | **Mirrors** the argument shape |
| `mantis-orchestrator/src/discover.rs` · Supabase signup detection | `bounty_signup_detect` Supabase shape | **Specialized port** of the heuristics for Supabase-on-the-front-end shape |
| `mantis-orchestrator/src/lib.rs` · `discover_and_signup_and_hunt` chain | `/bob-hunt` slash-command sequence | **Mirrors** the orchestrator workflow as one Rust function instead of a multi-step prompt |
| `mantis-pack/src/lib.rs` · `CapabilityPack` shape | `mcp/lib/capability-packs.js` | **Mirrors** the directory-layout convention (flat markdown files keyed by capability id) |
| `mantis-pack/src/lib.rs` · `WebPack` (Mantis v1 default) | Hacker Bob's `web` pack | **Mirrors** the technique set for the web profile |
| `mantis-recon-tools/src/lib.rs` · optional-tools list | Hacker Bob's optional-tools list (`subfinder`, `httpx`, `katana`, `nuclei`, `jwt_tool`) | **Mirrors** the inventory; binaries install-time-fetched, not vendored |
| `mantis-report/src/severity.rs` · `Informational` tier noise filter | Hacker Bob's `reportable: true` + `info` disposition | **Mirrors** the noise-filter semantics |

## Section 4 — What is NOT a port

For full transparency, these directories and files are Mantis-original work that *references* hacker-bob without deriving from it. They intentionally do **not** carry §4(b) headers.

### 4.1 Mantis-original Rust crates (never derived from hacker-bob)

`crates/mantis-core`, `mantis-proto`, `mantis-workspace`, `mantis-event-store`, `mantis-scope`, `mantis-egress`, `mantis-hypothesis`, `mantis-planner`, `mantis-posterior`, `mantis-claim`, `mantis-primitive`, `mantis-report` (Rust runtime), `mantis-playbook`, `mantis-memory`, `mantis-operator-model`, `mantis-trajectory`, `mantis-tuner`, `mantis-hibernation`, `mantis-scheduler`, `mantis-tenant`, `mantis-k8s`, `mantis-registry`, `mantis-fuzzer`, `mantis-sandbox`, `mantis-synthesizer`, `mantis-chain`, `mantis-tui`, `mantis-tui-ratatui`, `mantis-web-ui`, `mantis-gateway`, `mantis-runtime`, `mantis-crawler`, `mantis-crawler-dynamic`, `mantis-bench*`, `mantis-cli`, `mantis-daemon`, `mantis-server`, `mantis-static-scan`, `mantis-tiered-exec`, `mantis-video`, `mantis-mcp` (except the wave/handoff and ported-tool-surface portions noted in Section 3).

### 4.2 Mantis-original prompts and playbooks

- `prompts/roles/chain-deep.md`, `grade-deep.md`, `verify-cascade-deep.md` — Mantis-deep-mode extensions, no upstream equivalent
- `prompts/playbooks/C5_*.md` … `C19_*.md` — Mantis-original capability playbooks (the only ports are `C2` and `C4`)
- `plugin/claude-code/playbooks/cap-dmarc-takeover.md`, `cap-source-map-exploit.md`, `cap-subdomain-takeover.md`, `cap-vercel-challenge-bypass.md` — Mantis-original capabilities
- `.claude/commands/mantishack.md`, `claim.md`, `daemon.md`, `doctor.md`, `report.md`, `resume.md`, `scan.md`, `status.md`, `wave.md` — Mantis-native CLI surface
- `.claude/skills/mantishack/` — Mantis-native one-shot pipeline skill

### 4.3 Mantis-original infrastructure

- `crates/mantis-egress` — cryptographic scope-enforcing proxy (no upstream equivalent; hacker-bob does per-tool JS checks)
- `crates/mantis-event-store` — merkle-signed event log
- `crates/mantis-fsm` — Rust FSM library (gates, transitions, override-reason audit log)
- `crates/mantis-hibernation` — snapshot/restore for serverless
- `crates/mantis-k8s` — Kubernetes operator
- `crates/mantis-registry` — OCI plugin registry with Ed25519 signature verification

### 4.4 Mantis-original packaging

- `Formula/mantishack.rb` (Homebrew formula)
- `deploy/docker/Dockerfile`
- `install.sh`, `install.ps1`
- `npm/mantishack/`, `npm/mantis-cli/`, `npm/platforms/*` package wrappers
- `npm/build.sh`, `npm/PUBLISH.md`

### 4.5 Documentation that mentions hacker-bob without porting

`NOTICE`, `CONTRAST.md`, `README.md`, `CHANGELOG.md`, `AGENTS.md`, `docs/MANTIS_WORKFLOW.md`, `docs/IMPROVEMENTS_100.md`, `benches/vs-bob/README.md`, `reports/BENCHMARK_VS_BOB.md`, `reports/BENCHMARK_RESULTS.md`. Hacker Bob is the subject or attribution target, not the source.

## Section 5 — Capabilities hacker-bob has that Mantis has not ported

These are documented gaps. Reproduced from [`CONTRAST.md`](./CONTRAST.md) for completeness.

| Upstream capability | Mantis status | Reason |
|---|---|---|
| 106 MCP tools (full surface) | ~19 implemented | The agent prompts reference tools by canonical hacker-bob names; the Rust side implements the most-used subset. Filing-style gap report: search the prompts for `mantis_` tool references that don't appear in `crates/mantis-mcp/src/server.rs`. |
| `bounty_auto_signup` (Patchright + CAPTCHA solver) | Not ported | Mantis-auth captures manually-pasted profiles only |
| `bounty_temp_email` | Not ported | Manual email provisioning |
| `bounty_run_auth_differential` | Partial — `crates/mantis-auth-differential` ports the classifier, but the orchestrator-driven multi-account flow is not yet wired end-to-end | Highest-impact single missing tool |
| Smart-contract chain families (EVM / SVM / Aptos / Sui / Substrate / CosmWasm) | Out of scope for v1 (web-only) | The agent prompts ship so future packs plug in without prompt rewrites |
| Capability eval harness (`bounty_evaluate_capabilities`) | Not ported | Regression harness for capability packs; planned for v2 |
| `bounty_chain_frontier` / `bounty_query_chain_tree` (content-addressed chain state tree) | Partial — `mantis_record_chain_attempt` exists, content-addressed lineage tree does not | v2 |

If a ported prompt references a `mantis_*` tool that doesn't exist, file an issue with the tool name and we'll either port it or carve out a Mantis-native equivalent.

## Section 6 — Verification

To independently verify this inventory:

```bash
# Count §4(b) markers (should match the 104 in Section 2):
grep -rln 'Apache-2.0 §4(b)' . --include='*.md' --include='*.rs' \
  --exclude-dir=target --exclude-dir=node_modules --exclude-dir=.git | wc -l

# Extract the full (file -> upstream) mapping:
grep -rln 'Apache-2.0 §4(b)' . --include='*.md' --include='*.rs' \
  --exclude-dir=target --exclude-dir=node_modules --exclude-dir=.git \
  | while read f; do
      url=$(grep -oE 'https://github.com/vmihalis/hacker-bob[^ )>*]*' "$f" | head -1)
      echo "$f -> $url"
    done
```

If the verification mismatches Section 2 of this file, regenerate (Section 2 is mechanically derived and intentionally trivial to reproduce — divergence means the headers and this index drifted).

## Section 7 — Legal posture

- Mantis is dual-licensed under [Apache-2.0](./LICENSE-APACHE) OR [MIT](./LICENSE-MIT).
- All ported files retain Apache-2.0 attribution per §4(b) (per-file header), §4(c) (upstream copyright preserved in NOTICE and CONTRAST.md), and §4(d) (upstream NOTICE reproduced verbatim in [`NOTICE`](./NOTICE)).
- For a window prior to 2026-05-25, the §4(a)/(b)/(d) mechanics were incomplete even though attribution was present — see the "Apology and compliance history" section in [`NOTICE`](./NOTICE). The gap is fully remediated; a public paper trail is filed at [hacker-bob#49](https://github.com/vmihalis/hacker-bob/issues/49).
- If you redistribute Mantis or a derivative work, you must propagate [`NOTICE`](./NOTICE) (including the "Upstream NOTICE" section that contains Hacker Bob's verbatim NOTICE text).
