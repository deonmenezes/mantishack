---
allowed-tools:
  - Bash
  - AskUserQuestion
---
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
