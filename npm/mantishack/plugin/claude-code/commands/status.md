---
description: Show the current state of one or all Mantis engagements — claims found, request budget, scope, active experiments. Drives through the mantis MCP server (no daemon CLI shell-out).
---

Show engagement status through the `mantis` MCP server.

**Arguments**: `$ARGUMENTS` is optionally an engagement id (ULID).

- **No id supplied**: call `mantis_engagement_list` and render a compact
  table sorted by `created_at_unix` (most recent first). For each row:
  short id (first 8 chars), name, state, event_count.
- **Id supplied**: call `mantis_engagement_status` with that id and
  render: id, name, state, event_count, scope_hash, created_at_unix
  (humanized). Then call `mantis_list_surfaces` and show the surface
  summary: total, redirects, distinct hosts.

## Hard rules

- **Do not modify state.** No authorize, no scan, no render. Read-only.
- If the MCP server isn't reachable, suggest `/mantis:doctor` to
  diagnose, then stop.
- If the user passes a partial id (first 8 chars only), call
  `mantis_engagement_list` first and disambiguate before any
  per-engagement call.
