# Mantis Repo Instructions

This repository is the install source for the Mantis bug-bounty / pentest framework — a Rust daemon plus Claude-Code-native MCP agent workflow. It ports the hacker-bob agent / prompt / playbook surface onto a stronger runtime substrate. See [`CONTRAST.md`](./CONTRAST.md) for the side-by-side comparison.

## Quick start

If the user wants to run a one-shot pentest against an authorized target:

```sh
# Start the daemon if it isn't already running:
pgrep -x mantis-daemon >/dev/null || (mantis-daemon &)
sleep 1

# Run the full pipeline (single-pass primitive → claim flow):
mantis pentest "$TARGET" --i-have-authorization
```

For **goal-directed** engagements — Mantis keeps iterating waves until a declarative success criterion is met:

```sh
mantis goal "find all endpoints"  --target https://app.example.com --i-have-authorization
mantis goal "find idor"           --target https://api.example.com --i-have-authorization
mantis goal "find vulnerabilities" --target https://app.example.com --i-have-authorization
mantis goal "authenticate and scan" --target https://app.example.com --i-have-authorization
```

The goal is parsed by `mantis_fsm::Goal::parse` into a structured `GoalKind`. Endpoint goals drive a wordlist-based expansion (default 200 candidates: paths + subdomains + `/.well-known` + sitemap-implied URLs). Vuln-class goals drive the primitive→claim catalog. Each pass updates the goal's bookkeeping; the engagement stops on `Met` or budget exhaustion. Live-tested against `app.tenkara.ai` — produced **76 surfaces in 3 passes from a single seed URL** (vs 1 surface from `mantis pentest`).

For an interactive Claude-Code-driven engagement, use the slash commands ported from hacker-bob:

| Hacker-bob | Mantis |
|---|---|
| `/bob-hunt target.com` | `/mantis-hunt target.com` |
| `/bob-status` | `/mantis-status` |
| `/bob-debug` | `/mantis-debug` |
| `/bob-export` | `/mantis-export` |
| `/bob-egress` | `/mantis-egress` |

These live under [`.claude/commands/`](./.claude/commands/) and dispatch into the agent prompts under [`.claude/agents/`](./.claude/agents/).

## Architecture in one paragraph

A long-running **Rust daemon** (`mantis-daemon`, gRPC on `127.0.0.1:50451`) owns engagement state, the scope-enforcing egress proxy, and the BLAKE3 / Ed25519 Merkle event log. The **CLI** (`mantis`) and the **MCP server** (`mantis-mcp`, embedded inside the daemon) are stateless clients. Hunters / verifiers / chain-builders / graders / report-writers run as Claude Code subagents driven by the prompts in [`.claude/agents/`](./.claude/agents/) and [`prompts/`](./prompts/). Every meaningful state change becomes a signed leaf in the merkle tree — operators verify post-hoc with `mantis-verify`.

## Workflow

The pipeline is a strict linear FSM (`crates/mantis-fsm`):

```
RECON -> AUTH -> HUNT -> CHAIN -> VERIFY -> GRADE -> REPORT
```

Every transition runs through a gate. Gates refuse on `pending_wave`, `unexplored_high_surfaces`, `blocked_high_surfaces`, `open_requeue_coverage`, `chain_attempts_missing`, `verification_incomplete`, `evidence_packs_invalid`, or `grade_missing`. Operators can override `HUNT -> CHAIN` and `CHAIN -> VERIFY` with a ≥ 20-char rationale; every override is recorded in the merkle log.

`VERIFY` is a **3-round cascade** — brutalist (skeptic) → balanced (false-negative catcher) → final (fresh re-run). The final round must reference the `adjudication_plan_hash` computed deterministically from brutalist + balanced; any drift hard-refuses `VERIFY -> GRADE`. See [`crates/mantis-fsm/src/adjudication.rs`](./crates/mantis-fsm/src/adjudication.rs).

Read the full walkthrough in [`docs/MANTIS_WORKFLOW.md`](./docs/MANTIS_WORKFLOW.md).

## What lives where

```
.claude/
├── agents/             Subagent prompts ported from hacker-bob's .claude/agents.
│                       Each agent file binds tools, model, and color.
├── commands/           Slash commands (/mantis-hunt, /mantis-status, ...).
└── skills/             User-invocable skills.

prompts/
├── roles/              Role-level prompts (orchestrator, recon, hunter, verifier
│                       cascade, grader, reporter). Mirrors hacker-bob's prompts/roles.
└── playbooks/          Capability playbooks (differential workflows). Mirrors
                        hacker-bob's prompts/playbooks.

.mantis/
├── knowledge/          Technique packs (hunter-techniques.json, etc.) ported from
│                       hacker-bob's .hacker-bob/knowledge.
└── bypass-tables/      WAF bypass tables.

crates/                 Rust workspace (~40 crates). The daemon, FSM, event store,
                        scope manifest, egress proxy, primitives, planner, claim
                        verifier, report renderer, MCP server, and ancillary
                        runtime services.

proto/                  gRPC service definition for the daemon.

docs/                   Architecture and workflow documentation.
```

## What Mantis does that hacker-bob doesn't

- **Daemon-owned state.** Engagement state survives CLI restarts, host swaps, and serverless cold-starts. Hacker-bob's MCP server runs inside the host CLI process and dies with it.
- **Cryptographic scope enforcement.** Every outbound request goes through `mantis-egress`, a CONNECT proxy that verifies the destination against a signed scope manifest. Hacker-bob enforces scope per-tool in JavaScript.
- **Merkle event log.** Every state change is a BLAKE3 leaf in a per-engagement merkle tree, signed by an Ed25519 workspace key. Operators verify with the standalone `mantis-verify` binary. Hacker-bob writes plain JSON.
- **FSM gate library.** The phase transitions and their gates are a tested Rust library (`crates/mantis-fsm`, 86 tests). Hacker-bob encodes the equivalent logic in JS prompt-side checks.
- **`adjudication_plan_hash` cascade gate.** See [`CONTRAST.md`](./CONTRAST.md) for the binding semantics.
- **Severity floor at render time.** Default drops `info` from the rendered report; operators can lower with `--severity-floor info` on `mantis_render_report`.

## Maintainer workflow

- `cargo test --workspace` is the canonical test gate. Current state: 652 tests passing.
- Daemon end-to-end smoke: `mantis pentest https://example.com --i-have-authorization --budget-seconds 60`.
- Live FSM smoke: `cargo run --example exercise_fsm -p mantis-daemon` — walks the most recent engagement through RECON → AUTH → HUNT → CHAIN against the running daemon.
- After editing prompts under `.claude/agents/` or `prompts/`, re-read them in a fresh Claude Code session to verify token replacements (`bounty_*` → `mantis_*`, `bob` → `mantis`) didn't leave stale references.

## What to do when the user says "run mantis against X"

1. Confirm written authorization for the target.
2. Confirm scope (host + path prefixes if narrower than the host).
3. Run `mantis pentest "$TARGET" --i-have-authorization` for a one-shot, OR
4. Drive the wave-fan-out flow via Claude Code: invoke `/mantis-hunt $TARGET` and let the orchestrator prompt dispatch hunters, verifiers, the cascade, and the grader.
5. After completion, render the report (`mantis engagement report <id>` or call `mantis_render_report` via MCP). Default floor drops `info`; pass `--severity-floor low` (default) or `--severity-floor medium` to tighten.

## Refuse to run if

- No written authorization for the target.
- The target overlaps a public service the operator does not control (e.g. shared SaaS, public CDN).
- The user supplies an exploit primitive scope that requests destructive actions (data deletion at scale, account takeover of arbitrary users, etc.) beyond the legitimate test boundary.

The egress proxy enforces the scope manifest cryptographically. The legal gate is yours.
