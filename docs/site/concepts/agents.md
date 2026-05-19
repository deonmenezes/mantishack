# Sub-agents

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

Mantis ships 16 sub-agent prompts under [`plugin/claude-code/agents/`](https://github.com/deonmenezes/mantishack/tree/main/plugin/claude-code/agents). Each is a focused role with its own MCP tool list, model selection, and `maxTurns` budget. The orchestrator spawns them via Claude Code's `Task` tool.

| Agent | Role | Spawned by |
|---|---|---|
| `recon-agent` | Subdomain + asset enumeration, JS bundle scrape | RECON |
| `deep-recon-agent` | Script-heavy recon with durable lead promotion | RECON (`--deep`) |
| `surface-router-agent` | Capability-pack routing per surface | After RECON |
| `hunter-agent` | Web-surface hunter | HUNT (per assignment) |
| `hunter-evm-agent` | EVM smart-contract hunter | HUNT (per EVM surface) |
| `hunter-svm-agent` | Solana hunter | HUNT (per SVM surface) |
| `hunter-move-agent` | Aptos + Sui Move hunter | HUNT (per Move surface) |
| `hunter-substrate-agent` | Substrate / ink! hunter | HUNT (per Substrate surface) |
| `hunter-cosmwasm-agent` | CosmWasm hunter | HUNT (per CosmWasm surface) |
| `chain-builder` | Multi-step exploit chain construction | CHAIN |
| `brutalist-verifier` | Skeptic verifier (round 1) | VERIFY |
| `balanced-verifier` | False-negative catcher (round 2) | VERIFY |
| `final-verifier` | Fresh re-run with adjudication-plan-hash gate | VERIFY |
| `evidence-agent` | Pre-grade evidence pack assembly | After VERIFY |
| `grader` | 5-axis scoring → SUBMIT/HOLD/SKIP | GRADE |
| `report-writer` | Disclosure-ready report rendering | REPORT |

All agents are MCP-driven — they write artifacts only through `mcp__mantis__*` tools, never directly to disk. This keeps the Merkle event log authoritative.
