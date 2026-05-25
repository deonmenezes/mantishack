---
allowed-tools:
  - Bash
---

<!--
This file is a derivative work of Hacker Bob (https://github.com/vmihalis/hacker-bob/blob/main/.claude/commands/bob-export.md),
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

Create a Mantis post-release improvement bundle for the currently installed Mantis version.

Run:
   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/mantis-export.js" "${CLAUDE_PROJECT_DIR:-$PWD}"`

Report the helper output exactly. Do not add flags or run a hunt.

---

## Mantis runtime notes

This command drives the Rust `mantis-daemon` over gRPC. Engagement state, event log, and scope enforcement live in the daemon — not in this CLI's process. To diagnose, run `mantis doctor`. The daemon binds `127.0.0.1:50451` by default.
