# `mantis investigate`

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

Flexible follow-up to `mantis hack`. Uses the full Mantis stack — every `mcp__mantis__*` tool, every spawned sub-agent, the egress proxy, the Merkle log — but **without** the rigid 7-phase FSM. Use it to dig into a single finding, audit a code file, or chase a hunch.

## Synopsis

```sh
mantis investigate <subject> [--i-have-authorization] [OPTIONS] [-- <claude args>...]
```

`<subject>` auto-classifies into one of three modes:

| Subject | Mode | Auth required? |
|---|---|---|
| `https://…` or `http://…` | **URL** — offensive investigation; runs `mantis_http_scan` probes | yes (`--i-have-authorization`) |
| Path to a file that exists on disk | **File** — static analysis; the file content is embedded in the prompt (capped at 64 KB) | no |
| Anything else | **Prompt** — free-form; orchestrator decides what to do | no |

## Examples

### Investigate a specific URL

```sh
mantis investigate https://app.example.com/api/users/42 --i-have-authorization
```

Orchestrator will summarize the URL, probe it live, spawn a hunter if needed, and report anything worth elevating into a real finding.

### Audit a suspicious file

```sh
mantis investigate ./src/auth/session.ts
```

Static-analysis pass: looks for hardcoded secrets, unsafe patterns, broken auth checks, missing input validation, SQL-injection / SSRF / RCE primitives, mass-assignment risks. Reports ranked findings.

### Chase a hunch about an existing engagement

```sh
mantis investigate "the IDOR finding F-3 — does it actually compose into ATO via OAuth state confusion?"
```

The orchestrator reads `mantis_read_findings`, walks the chain attempts, decides whether the hypothesis holds up, and reports concretely.

### Bundle with a file path inside a prompt

```sh
mantis investigate "look at ./reports/foo/findings.jsonl and tell me what's most worth verifying first"
```

## Options

| Flag | Default | What |
|---|---|---|
| `--i-have-authorization` | required for URL only | Self-attestation. The legal gate. |
| `--daemon <url>` | `http://127.0.0.1:50451` | Daemon gRPC endpoint. Honors `MANTIS_DAEMON`. |
| `--claude-bin <path>` | _from PATH_ | Override the `claude` binary. Honors `MANTIS_CLAUDE_BIN`. |
| `--output-format text\|json` | `text` | `text` streams pretty events to stderr; `json` streams raw stream-json to stdout. |
| `-- <claude args>...` | — | Forwarded verbatim to the spawned `claude --print`. |

## What's available inside

The investigator system prompt enumerates every tool and agent:

**MCP tools** — all `mcp__mantis__*` tools registered with the daemon (read findings, scan, audit, fetch source, run foundry / halmos / anchor, score, dedupe, decode JWT, diff responses, summarize URL, extract secrets / forms / links, …).

**Sub-agents** spawnable via `Task`:

- `recon-agent`, `deep-recon-agent`, `surface-router-agent`
- `hunter-agent`, `hunter-evm-agent`, `hunter-svm-agent`, `hunter-move-agent`, `hunter-substrate-agent`, `hunter-cosmwasm-agent`
- `chain-builder`
- `brutalist-verifier`, `balanced-verifier`, `final-verifier`
- `evidence-agent`, `grader`, `report-writer`

**What it WON'T do:**

- Drive the 7-phase FSM (no `mantis_create_engagement`, no `mantis_authorize_scope`, no `mantis_transition_phase`). For that, use [`mantis hack`](./hack.md).
- Shell out to `mantis hack` / `mantis pentest` (anti-recursion guard — `mantis` spawned the running `claude`).
- Issue offensive HTTP traffic in `file` or `prompt` mode.

## Inside the REPL

The bare-`mantis` REPL accepts `/investigate <subject>` as a slash command. Typing a URL implicitly attaches `--i-have-authorization` (the in-session attestation), so:

```
mantis> /investigate https://app.example.com/api/users
```

dispatches to `mantis investigate https://app.example.com/api/users --i-have-authorization`.

## Run log

Every event the spawned `claude` emits is recorded to a pretty markdown ledger (`./logs.md` by default; override with `MANTIS_LOG_FILE`). See [`mantis prompt`](./prompt.md#run-log) for the schema.

## See also

- [`mantis hack`](./hack.md) — full FSM engagement
- [`mantis prompt`](./prompt.md) — one-shot ad-hoc prompt
- [`mantis goal`](./goal.md) — goal-directed multi-wave engagement
