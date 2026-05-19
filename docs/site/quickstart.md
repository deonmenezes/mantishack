# Quickstart

> **Authorized testing only.** Mantis refuses to run without `--i-have-authorization`. You are responsible for confirming written permission before invoking it. See [Responsible Use](./responsible-use.md).

<p align="center">
  <img src="../assets/mascot/hero.png" alt="Mantis mascot" width="240" />
</p>

This page gets you from zero to a finished engagement in **three commands**.

## Prerequisites

- macOS or Linux (Windows planned)
- The [Claude Code CLI](https://claude.com/claude-code) on `PATH` — Mantis uses it as the LLM orchestrator
- Either Node 14+ (for `npm`/`bun`/`yarn`/`pnpm` install) **or** the Rust toolchain (for source builds)

## 1. Install

Pick whichever package manager you use:

```sh
npm  install -g mantishack
bun  add    -g mantishack
yarn global add mantishack
pnpm add    -g mantishack
```

This installs three binaries to your prefix's `bin/`:
- `mantis` — the CLI
- `mantis-daemon` — the long-running gRPC daemon
- `mantis-mcp` — the MCP server for Claude Code / Codex / OpenCode

Only one prebuilt platform binary is downloaded — the one matching your OS/arch. No postinstall scripts; safe in Bun and pnpm strict mode.

## 2. Wire it up

```sh
mantis init
```

This:
- Copies the Mantis plugin into `~/.claude/plugins/mantis/` (and Codex / OpenCode plugin dirs if present).
- Registers `mantis-mcp` as a user-scope MCP server via `claude mcp add`.
- Spawns the daemon in the background. Logs go to `~/.Mantis/daemon.log`, pid to `~/.Mantis/daemon.pid`.

Re-running `mantis init` is idempotent.

## 3. Run an engagement

```sh
mantis hack app.example.com --i-have-authorization
```

What happens next, end-to-end:

| Phase | What Mantis does |
|---|---|
| **RECON** | Spawns a `recon-agent` sub-agent. Enumerates subdomains, live hosts, archived URLs, JS bundles, JWTs. Writes `attack_surface.json`. |
| **AUTH** | Detects signup endpoints, creates temp emails, signs up an attacker and a victim profile, stores auth. (Skip with `--no-auth`.) |
| **HUNT** | Calls `mantis_start_next_wave`, fans out **≥3 parallel hunter sub-agents**, one per ranked surface. Each writes a wave handoff. Repeats until no assignable candidates remain. |
| **CHAIN** | Spawns `chain-builder`. Tests plausible multi-step exploit chains derived from individual findings. |
| **VERIFY** | Three-round cascade: `brutalist-verifier` (skeptic) → `balanced-verifier` (false-negative catcher) → `final-verifier` (fresh re-run, must reference the deterministic `adjudication_plan_hash`). |
| **GRADE** | `grader` sub-agent scores survivors on a 5-axis rubric → `SUBMIT` / `HOLD` / `SKIP`. |
| **REPORT** | `report-writer` renders the disclosure-ready report to `./mantishack-<engagement-id>/report.md`. |

You'll see live progress streamed to your terminal:

```
[mantishack] → mcp__mantis__mantis_init_session(target_domain=app.example.com)
[mantishack]   ✓ result
[mantishack] → Task(type=recon-agent, background)
[mantishack]   ✓ result
[mantishack] · Recon complete. 12 surfaces discovered.
[mantishack] → Task(type=surface-router-agent)
[mantishack] → mcp__mantis__mantis_transition_phase(target_domain=app.example.com, →AUTH)
…
[mantishack] → mcp__mantis__mantis_start_next_wave
[mantishack] → Task(type=hunter-agent, background)
[mantishack] → Task(type=hunter-agent, background)
[mantishack] → Task(type=hunter-agent, background)
…
[mantishack] · session success (47 turns, $0.84)
[mantishack] orchestrator returned cleanly.
```

## What you get

Under `./mantishack-<engagement-id>/`:

```
mantishack-01K…/
├── attack_surface.json           # Recon output
├── surface-routes.json           # Capability-pack routing per surface
├── findings.jsonl                # Every recorded finding
├── chain-attempts.jsonl          # CHAIN-phase evidence
├── verification-rounds/          # brutalist / balanced / final results
├── evidence-packs.json           # Pre-grade evidence bundle
├── grade-verdict.json            # SUBMIT / HOLD / SKIP + scoring
├── report.md                     # Disclosure-ready report
├── events.jsonl                  # BLAKE3 + Ed25519 signed Merkle log
└── state.json                    # FSM state snapshot
```

Render the report in other formats:

```sh
mantis engagement report <id> --format pdf
mantis engagement report <id> --format hackerone
mantis engagement report <id> --format sarif
mantis engagement report <id> --format openvex
```

## Other entry points

- `mantis pentest <target> --i-have-authorization` — daemon-driven one-shot, no LLM orchestrator.
- `mantis goal "find idor" --target https://api.example.com --i-have-authorization` — goal-directed, multi-wave until the declarative success criterion is met.
- `/mantishack <target>` inside Claude Code — same orchestrator, interactive.

## Troubleshooting

- **`mantis-daemon` not running** — `mantis init --no-plugin --no-mcp` to re-spawn it, or run `mantis-daemon &` manually.
- **`claude` not on PATH** — install Claude Code from https://claude.com/claude-code, then re-run `mantis init`.
- **macOS `zsh: killed`** — likely an unsigned binary getting SIGKILL'd. `cargo install --path crates/mantis-cli --force` or `codesign --force --sign - $(which mantis)` to ad-hoc sign.

## Next steps

- Read [The 7-phase FSM](./concepts/fsm.md) to understand what each phase does.
- See the [CLI reference](./cli/hack.md) for every flag and option.
- Read [Responsible Use](./responsible-use.md) before your first real engagement.
