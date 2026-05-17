---
allowed-tools:
  - Bash
---
Create a Mantis post-release improvement bundle for the currently installed Mantis version.

Run:
   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/mantis-export.js" "${CLAUDE_PROJECT_DIR:-$PWD}"`

Report the helper output exactly. Do not add flags or run a hunt.

---

## Mantis runtime notes

This command drives the Rust `mantis-daemon` over gRPC. Engagement state, event log, and scope enforcement live in the daemon — not in this CLI's process. To diagnose, run `mantis doctor`. The daemon binds `127.0.0.1:50451` by default.
