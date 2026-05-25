---
allowed-tools:
  - Bash
  - AskUserQuestion
---

<!--
This file is a derivative work of Hacker Bob (https://github.com/vmihalis/hacker-bob/blob/main/.claude/commands/bob-egress.md),
Copyright 2026 Michail Vasileiadis, licensed under the Apache License,
Version 2.0. See the project NOTICE file for the upstream attribution
and apology.

Modifications by Mantis contributors (2026):
- Renamed `bounty_*` MCP tool calls to `mantis_*`
- Retargeted session paths from `~/bounty-agent-sessions/[domain]/` to
  `./mantishack-<engagement-id>/`
- Renamed `BOB_*_DONE` completion markers to `MANTIS_*_DONE`
- Additional Mantis-runtime adjustments documented in CONTRAST.md

This notice is provided per Apache-2.0 §4(b) ("You must cause any
modified files to carry prominent notices stating that You changed
the files").
-->

Manage Mantis egress profiles for this project.

**Input:** `$ARGUMENTS` (`list`, `add <name>`, `test <name>`, `enable <name>`, `disable <name>`, or `remove <name>`)

Run:
`node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/mantis-egress.js" "${CLAUDE_PROJECT_DIR:-$PWD}" $ARGUMENTS`

Rules:
- If no subcommand is provided, use `list`.
- For `add <name>`, prefer an environment variable reference such as `--proxy-env MANTIS_EGRESS_GR_RESIDENTIAL_PROXY`; do not ask the operator to paste credentials into chat.
- For `remove <name>`, ask the operator to confirm removal, then rerun with `--yes` only after confirmation.
- Report profile names, enabled status, region, description, and whether a proxy is configured. Never print proxy URLs or credentials.

---

## Mantis runtime notes

This command drives the Rust `mantis-daemon` over gRPC. Engagement state, event log, and scope enforcement live in the daemon — not in this CLI's process. To diagnose, run `mantis doctor`. The daemon binds `127.0.0.1:50451` by default.
