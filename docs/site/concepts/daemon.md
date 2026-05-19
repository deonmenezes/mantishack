# Daemon architecture

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

`mantis-daemon` is a long-running gRPC server bound to `127.0.0.1:50451` by default. It owns:

- **Engagement state** — created via `mantis_create_engagement`, survives CLI restarts.
- **Scope manifest** — Ed25519-signed; loaded once at `Authorize`, enforced on every outbound request.
- **Egress proxy** — CONNECT proxy that verifies the destination against the signed scope manifest.
- **Merkle event log** — every state change becomes a BLAKE3 leaf, signed by an Ed25519 workspace key. Operators verify post-hoc with `mantis-verify`.

The CLI (`mantis`) and the MCP server (`mantis-mcp`, embedded inside the daemon) are stateless gRPC clients. Hunters, verifiers, chain-builders, graders, and report-writers run as Claude Code sub-agents driven by prompts in [`prompts/`](https://github.com/deonmenezes/mantishack/tree/main/prompts).

See [`docs/MANTIS_WORKFLOW.md`](https://github.com/deonmenezes/mantishack/blob/main/docs/MANTIS_WORKFLOW.md) for the full architecture walkthrough.
