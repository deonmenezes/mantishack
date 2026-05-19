---
description: Diagnose the Mantis local setup — daemon reachable, MCP server registered, mantis-mcp binary on PATH, recent engagements summary.
---

Run a diagnostic of the user's Mantis install. Output a compact
pass/fail table; do not modify state.

## Checks

1. **`mantis-daemon` running** — `pgrep -x mantis-daemon` returns a PID.
   If not: tell the user to run `mantis-daemon &` and stop.
2. **`mantis-mcp` on PATH** — `command -v mantis-mcp` returns a path.
   If not: tell the user to `cargo install --path crates/mantis-mcp`
   from the mantishack-daemon repo.
3. **MCP server registered** — call `mantis_engagement_list` through the
   MCP server. If the call succeeds, the MCP server is registered and
   the gRPC channel is open. If it fails, surface the exact error.
4. **Operator key present** — the daemon needs an operator key to sign
   scope manifests. Try `mantis_create_engagement` with an empty name
   and immediately abandon the engagement (no authorize call). If the
   create succeeds, the daemon is healthy. If it errors on "no
   operator", tell the user to run `mantis operator create <name>`.
5. **Recent engagements** — `mantis_engagement_list` already returned a
   list above. Show the user the **3 most recent** engagement ids,
   states, and event counts.

## Output format

```
Mantis doctor
─────────────────────────
✔ mantis-daemon            pid 12345, uptime 1h 23m
✔ mantis-mcp on PATH        /usr/local/bin/mantis-mcp
✔ MCP gRPC channel          7 engagements known
✔ operator key              ok (created engagement 01XXXX, abandoned)

Recent engagements:
  01KRSSYM…   active   events=5
  01KRSW3G…   active   events=5
  01KRSS0R…   active   events=4
```

If any check fails, replace `✔` with `✘` and add a one-line remediation
hint beneath the failed row.

## Hard rules

- **Do not modify any engagement.** No authorize, no scan, no report —
  this is a diagnostic.
- **Do not create persistent engagements.** The operator-key probe in
  step 4 creates a draft engagement; immediately tell the user it's
  abandoned and that running `mantis-mcp` to GC drafts is on them.
