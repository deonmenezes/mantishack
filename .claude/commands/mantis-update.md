---
allowed-tools:
  - Bash
  - AskUserQuestion
---

<!--
This file is a derivative work of Hacker Bob (https://github.com/vmihalis/hacker-bob/blob/main/.claude/commands/bob-update.md),
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

Run the installed Mantis update workflow for this project.

1. Run:
   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/mantis-update.js" plan "${CLAUDE_PROJECT_DIR:-$PWD}"`
2. If the helper says Mantis is already up to date or cannot reach npm, report that result and stop.
3. If an update is available or the install is legacy, ask the operator exactly: `Update now?`
4. Only when the operator confirms, run:
   `npx -y mantis@latest install "${CLAUDE_PROJECT_DIR:-$PWD}"`
5. Then run:
   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/mantis-update.js" clear-cache "${CLAUDE_PROJECT_DIR:-$PWD}"`
6. Tell the operator to fully restart Claude Code in this project before continuing.

---

## Mantis runtime notes

This command drives the Rust `mantis-daemon` over gRPC. Engagement state, event log, and scope enforcement live in the daemon — not in this CLI's process. To diagnose, run `mantis doctor`. The daemon binds `127.0.0.1:50451` by default.
