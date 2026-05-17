---
description: Continue an in-flight Mantis engagement — read its current state, decide whether more recon is needed, and either resume the FSM or render the report.
---

Resume an existing Mantis engagement by id.

**Arguments**: `$ARGUMENTS` is the engagement id (a ULID) the user wants
to continue. If not supplied, call `mantis_engagement_list` first, show
the user the available engagements, and ask which one to resume.

## Workflow

1. Call `mantis_engagement_status` with the engagement id to see its
   current state, event count, and scope hash.
2. Branch on `state`:
   - **`draft`** — the engagement was never authorized. Ask the user
     for authorization, then spawn `mantis-orchestrator` from
     `AUTHORIZE`.
   - **`authorized` / `active`** — there is in-flight state. Call
     `mantis_list_surfaces` to inventory progress, then spawn
     `mantis-orchestrator` from `LIST_SURFACES` (skip create/authorize).
   - **`paused` / `completed` / `archived`** — engagement is terminal.
     Offer to render the report via `mantis-reporter` and stop.
3. Always stream a one-line update before any tool call so the user can
   see what you're doing.

## Hard rules

- **Never create a new engagement here.** This is resume only. Refuse
  if the engagement id doesn't exist and offer `/mantis:mantishack`.
- **Never re-authorize scope with different targets** than the
  engagement already has. If the user needs a wider scope, that is a
  new engagement.
- If the daemon is unreachable, prompt the user to start it with
  `mantis-daemon &` and stop.
