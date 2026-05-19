---
description: Manually fan out parallel hunters against an existing engagement's surfaces. Starts a new wave, spawns one mantis-hunter per assignment in parallel, and merges the handoffs when all hunters return. Useful when the orchestrator stopped early and you want to probe what was discovered.
---

Fan out parallel hunters against an in-flight Mantis engagement.

**Arguments**: `$ARGUMENTS` is `<engagement-id> [parallelism]`. The
engagement id is required. `parallelism` defaults to 4 — the number of
concurrent hunters to spawn.

## Workflow

1. **Confirm the engagement is alive.** Call `mantis_engagement_status`
   with the engagement id. If it's not `active` or `authorized`, refuse
   and tell the user to `/mantis:resume <id>` first.

2. **Inventory surfaces.** Call `mantis_list_surfaces`. If zero
   surfaces, refuse: there is nothing to fan out across; ask the user
   to recon first via `/mantis:mantishack` or `/mantis:resume`.

3. **Plan the split.** Group surfaces into `parallelism` buckets (or
   fewer if there are fewer surfaces than hunters). One bucket per
   hunter. Show the user the planned split as a compact table and ask
   for confirmation before spawning.

4. **Start the wave.** Call `mantis_start_wave` with the engagement id
   and one assignment per bucket. Capture the returned `wave_number`
   and `assignment_id`s.

5. **Spawn hunters in parallel.** Use the host's parallel-Agent
   mechanism: in a **single message**, issue N `Agent` calls — one per
   assignment — each invoking the `mantis-hunter` sub-agent with the
   engagement id, wave number, assignment id, surfaces list, and any
   notes the user added. This is how parallel execution actually
   happens in Claude Code; sequential `Agent` calls would defeat the
   purpose.

6. **Wait then merge.** After all hunter agents return their tool
   results, call `mantis_wave_status` once to confirm `all_received:
   true`. If any are still `pending` (rare, only if a hunter aborted
   without writing a handoff), call `mantis_merge_wave` anyway — it
   tolerates missing handoffs and surfaces them in
   `handoffs_missing`.

7. **Present the merge.** Render a compact summary to the user:
   - Wave number, assignment count, handoffs received vs missing
   - Total findings, breakdown by severity
   - Total dead-ends, total coverage entries
   - The first 3 findings inline (title, surface, severity)
   - Path to `merged.json` for the full record

## Hard rules

- **Never start a wave for a non-authorized engagement.** The daemon
  will reject any probe traffic anyway, but you should fail loud at
  the orchestration layer first.
- **Never spawn more than 8 parallel hunters** for a single wave. If
  the user requests more, cap at 8 and tell them.
- **Never inline-author handoff JSON yourself.** Each hunter writes
  its own. You only orchestrate.
- **Never call `mantis_write_handoff` from this command.** That is
  the hunter's job.
