# Mantis vs Hacker-Bob — side-by-side

Mantis ports hacker-bob's agent / prompt / capability-pack / 3-round-cascade workflow onto a stronger runtime substrate. This file is the operator-facing index of what differs and why.

Hacker-bob upstream: <https://github.com/vmihalis/hacker-bob>. Mantis takes the workflow that makes hacker-bob's results good and reimplements it on top of a Rust daemon, a merkle-signed event log, and a cryptographic egress proxy.

## TL;DR — what you get from Mantis that hacker-bob doesn't

| Capability | Hacker-bob | Mantis |
|---|---|---|
| Process model | MCP server inside the host CLI; dies with the host | Long-running gRPC daemon; engagements survive CLI restarts and host swaps |
| State store | JSON files under `~/bounty-agent-sessions/[domain]/` | Daemon + RocksDB-backed `mantis-event-store` with BLAKE3 leaves and Ed25519 tree heads, plus mirrored JSON under `./mantishack-<id>/` |
| Scope enforcement | Per-tool checks in JavaScript | `mantis-egress`: CONNECT proxy that verifies every outbound destination against a signed `ScopeManifest` before forwarding; out-of-scope hits never leave the laptop |
| Audit | `pipeline-events.jsonl` (plain JSON) | Merkle inclusion proofs verifiable by anyone with the workspace public key via the standalone `mantis-verify` binary |
| FSM correctness | Encoded in JS prompt-side checks (`phase-gates.js`) | Rust library `crates/mantis-fsm`, 86 unit tests, JSON round-trip, fingerprintable state |
| Verification cascade | brutalist → balanced → final, `adjudication_plan_hash` enforced in JS | Same cascade, `adjudication_plan_hash` enforced in Rust + gate-tested + persisted in the merkle log |
| Severity floor | Reportability gate inside the report-writer prompt | Same gate, plus a runtime severity floor in `crates/mantis-report` (default drops `info`; configurable per render) |
| Concurrency | Single-process JS event loop | Tokio-backed async daemon; parallel hunters share the event store with `O_APPEND` semantics |
| Hibernation | Not supported | `mantis-hibernation` snapshots state; engagements resume after a serverless cold-start |
| Multi-tenant isolation | One project / one MCP server | `mantis-tenant` namespaces; one daemon serves many engagements with key-isolated egress profiles |

## What Mantis ports verbatim from hacker-bob

These are the parts of hacker-bob that make its results good. Mantis copies them, retargets the tool names, and runs them on its own runtime.

### Agent prompts (`.claude/agents/`)

- `recon-agent.md`, `deep-recon-agent.md`, `surface-router-agent.md`
- `hunter-agent.md` (+ chain-family variants — kept as templates for future packs)
- `chain-builder.md`
- `brutalist-verifier.md`, `balanced-verifier.md`, `final-verifier.md`
- `evidence-agent.md`, `grader.md`, `report-writer.md`

Every prompt is a port of the corresponding hacker-bob agent with `bounty_*` MCP tool calls renamed to `mantis_*` and `~/bounty-agent-sessions/[domain]/` renamed to `./mantishack-<engagement-id>/`. The workflow logic, severity heuristics, capability-pack table, and `BOB_*_DONE` (now `MANTIS_*_DONE`) markers are preserved verbatim. See [hacker-bob's agents](https://github.com/vmihalis/hacker-bob/tree/main/.claude/agents) for the original.

### Slash commands (`.claude/commands/`)

`/mantis-hunt`, `/mantis-status`, `/mantis-debug`, `/mantis-export`, `/mantis-update`, `/mantis-egress` — renames of hacker-bob's `/bob-*` family.

### Role prompts (`prompts/roles/`)

`orchestrator.md`, `recon.md`, `deep-recon.md`, `surface-router.md`, `hunter.md`, `hunter-{evm,svm,move,substrate,cosmwasm}.md`, `chain.md`, `brutalist-verifier.md`, `balanced-verifier.md`, `final-verifier.md`, `evidence.md`, `grader.md`, `reporter.md`, `status.md`, `debug.md`. Mirrors `prompts/roles/` upstream.

### Capability playbooks (`prompts/playbooks/`)

`C2_doc_vs_behavior.md`, `C4_multi_account_differential.md`, … — orchestrator-driven differential workflows.

### Knowledge base (`.mantis/knowledge/`)

`hunter-techniques.json` and friends — surface-pattern → technique mappings. Ported as-is; the patterns are runtime-agnostic.

## What Mantis adds on top of the ported workflow

### 1. Linear FSM with gate library

`crates/mantis-fsm` encodes the seven phases (`RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT`), every gate (`pending_wave`, `unexplored_high_surfaces`, `blocked_high_surfaces`, `open_requeue_coverage`, `chain_attempts_missing`, `verification_incomplete`, `evidence_packs_invalid`, `grade_missing`), and the override-reason audit log as a tested Rust library. Hacker-bob encodes the same logic but in JavaScript and only enforces it inside prompt bodies.

### 2. Merkle event log

`crates/mantis-event-store` writes every event as a BLAKE3 leaf into a per-engagement merkle tree, signed by an Ed25519 workspace key. A third-party auditor verifies the report's claims against the merkle root with `mantis-verify --proof <bundle> --public-key <hex>` — they do not need to trust Mantis or the operator.

### 3. Cryptographic scope enforcement

`crates/mantis-egress` is a localhost CONNECT proxy that every Mantis-originated request goes through. It evaluates each destination against the engagement's signed `ScopeManifest`. Out-of-scope hits get logged as `ScopeDecisionLogged{in_scope: false, ...}` events and refused at the proxy — they never reach the network. Hacker-bob checks scope per-tool inside JS; nothing prevents a misbehaving tool from leaking out.

### 4. `adjudication_plan_hash` cascade gate, hardened

Hacker-bob's `buildVerificationAdjudication` computes the plan hash in JS (`verification.js:756`) and the final-verifier prompt is told to reference it. Mantis enforces this in [`crates/mantis-fsm/src/adjudication.rs`](./crates/mantis-fsm/src/adjudication.rs):

- `Adjudication::plan_hash` is computed deterministically over (attempt_id, snapshot_hash, brutalist_hash, balanced_hash, agreed, disagreements, replay_required, qa_sample).
- `SessionState::gate_verify_to_grade()` refuses to open `VERIFY → GRADE` unless `final.references_plan_hash == current.adjudication.plan_hash`.
- Wrong plan hash, missing plan hash, missing adjudication, or any drift in earlier rounds → hard refusal with a structured `BlockerCode::VerificationIncomplete`.
- Every step (`VerificationAttemptOpened`, `VerificationRoundWritten`, `AdjudicationBuilt`) lands in the merkle log.

This means the cascade gate is **provable** — a verifier can replay the events and assert the plan hash bound the final round to specific brutalist and balanced rounds.

### 5. Severity floor at render time

`crates/mantis-report` exposes `Report::with_severity_floor(...)` and the MCP `mantis_render_report` tool exposes `severity_floor` (default: `low` — drops `info` noise). Hacker-bob's reportability gate lives in the report-writer prompt; it relies on the LLM honoring the rule. Mantis enforces it in Rust before any markdown is emitted, and the summary table surfaces the suppressed count.

### 6. Authenticated request replay

`crates/mantis-auth` ships `AuthProfile` (cookies / headers / query, with values zeroized on drop), `AuthStore` (atomic per-engagement persistence), and a redacted listing path. `crates/mantis-scanner-http` injects the profile into every probe — cookies join into one `Cookie:` header, custom headers override defaults, query parameters are appended. Hacker-bob has the same surface in `mcp/lib/auth.js` and `mcp/lib/tools/auth-store.js`; Mantis re-implements it in Rust with zeroize semantics.

### 7. Hibernation

`crates/mantis-hibernation` snapshots and restores engagement state. Useful for serverless deployments (Lambda / Cloud Run) where the daemon process can be reaped at any time.

## What hacker-bob has that Mantis still lacks

Honest accounting — these are the gaps the next iterations close.

| Capability | Status |
|---|---|
| 106 MCP tools | Mantis exposes ~19. The agent prompts reference tools by canonical hacker-bob names; the Rust side implements the most-used subset. Gap list: search the prompts for `mantis_` tool references that don't appear in `crates/mantis-mcp/src/server.rs`. |
| Browser automation (`auto_signup` / Patchright + CAPTCHA solver) | Not ported. Mantis-auth captures manually-pasted profiles only. |
| `bounty_run_auth_differential` (the auth-bypass detector) | Not ported. Highest-impact single missing tool. |
| Smart-contract families (EVM / SVM / Aptos / Sui / Substrate / CosmWasm) | Out of scope for Mantis v1 (web-only). The agent prompts ship anyway so future packs plug in without prompt rewrites. |
| Capability eval harness | Not ported. Hacker-bob's `bounty_evaluate_capabilities` is a regression harness for capability packs; useful for v2. |
| `bounty_chain_frontier` / `bounty_query_chain_tree` (content-addressed chain state tree) | Partial — `mantis_record_chain_attempt` exists; the content-addressed lineage tree does not. |

If you hit "tool not found" while running a ported prompt, that's the gap — file an issue with the tool name and we'll either port it or carve out a Mantis-native equivalent.

## License compatibility

Hacker-bob is Apache-2.0. Mantis is Apache-2.0 OR MIT (dual). Files ported from hacker-bob retain attribution in their headers / docstrings; we credit `vmihalis/hacker-bob` upstream.

## When to use which

- **Use hacker-bob** if you want the canonical Node-based workflow, you live inside Claude Code / Codex, you don't need cross-session persistence, and you're OK with per-tool scope checks.
- **Use Mantis** if you want long-lived engagements, cryptographic scope + merkle-verifiable audit, the same prompts running on a Rust daemon, or you plan to deploy to serverless / multi-tenant infra.
