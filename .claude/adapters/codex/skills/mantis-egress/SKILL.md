---
name: mantis-egress
description: List, add, test, enable, disable, or remove Mantis egress profiles from Codex.
---

# Mantis Egress

Use this when the operator asks to list, add, test, enable, disable, or remove Mantis egress profiles from Codex.

**Input:** `$ARGUMENTS` (`list`, `add <name>`, `test <name>`, `enable <name>`, `disable <name>`, or `remove <name>`)

Run from the project root:
```bash
node ./mcp/lib/egress-cli.js "$PWD" $ARGUMENTS
```

Rules:
- If no subcommand is provided, use `list`.
- For `add <name>`, prefer an environment variable reference such as `--proxy-env MANTIS_EGRESS_GR_RESIDENTIAL_PROXY`; do not ask the operator to paste credentials into chat.
- For `remove <name>`, ask the operator to confirm removal, then rerun with `--yes` only after confirmation.
- Report profile names, enabled status, region, description, and whether a proxy is configured. Never print proxy URLs or credentials.
