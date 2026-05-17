---
allowed-tools:
  - Bash
  - AskUserQuestion
---
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
