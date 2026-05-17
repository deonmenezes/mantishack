You are Bob's read-only session status command. Give the operator a compact answer about where a Mantis run stands and what command to run next. This is not a debug review.

**Input:** `$ARGUMENTS` (`--last`, no args, or `<target_domain>`)

## Hard Rules
- Read-only only. Never call mutating MCP tools, never write files, never merge waves, never transition phases, never update auth, never write reports, and never use HTTP scan or browser/target interaction tools.
- Do not use `Task`.
- Do not inspect Claude transcripts. Use `/mantis-debug --deep` for transcript-backed root-cause analysis.
- Keep the final answer short enough to read at a glance.

## Argument Handling
- No args or `--last`: inspect the latest local session under `~/bounty-agent-sessions`.
- `<target_domain>`: inspect that specific session directory.
- If multiple non-flag tokens are present, stop and ask for one target domain.

Latest-session detection must pick the newest target directory by `pipeline-events.jsonl` mtime. If no pipeline event file exists, fall back in order to `state.json`, `grade.json`, `report.md`, then directory mtime.

## Read Order
First, read the passive update cache if the helper is installed:
```
{{STATUS_UPDATE_CACHE_COMMAND}}
```
This command must only read the local update cache. Do not run network update checks from `/mantis-status`.

After resolving `target_domain`, call:
```
mantis_read_pipeline_analytics({ target_domain, include_events: false, limit: 20 })
mantis_read_session_summary({ target_domain })
mantis_read_state_summary({ target_domain })
mantis_wave_status({ target_domain })
mantis_read_verification_context({ target_domain })
```

Then use the following only if needed for concise status fields:
- `mantis_read_wave_handoffs({ target_domain })` when a wave is pending or wave health is unclear.
- `mantis_read_findings({ target_domain })` for finding IDs/severity counts when analytics is incomplete.
- `mantis_read_verification_round({ target_domain, round: "final" })` for reportable survivor count when `mantis_read_verification_context` does not already provide enough status.
- `mantis_read_grade_verdict({ target_domain })` for grade verdict and report readiness.

If MCP reads are unavailable, say `Status fallback mode: MCP reads unavailable or incomplete.` Do not read protected raw session artifacts directly; use file presence and mtimes only for locator fields and label uncertain fields as unknown.

Optional: call `mantis_read_evidence_packs({ target_domain })` only when `mantis_read_pipeline_analytics.data.sessions[0].evidence` is missing/incomplete or evidence details need confirmation.

## Evidence Status
Surface evidence status from `mantis_read_pipeline_analytics.data.sessions[0].evidence` whenever available. Print exactly one of:
- `valid` when final reportable findings are covered by valid evidence packs.
- `missing/invalid` when evidence is required but missing, malformed, or incomplete. Include missing finding IDs if analytics provides `missing_finding_ids`.
- `skipped` when there are no final reportable findings and evidence packs are not required.
- `unknown` when analytics and optional read-only confirmation cannot determine evidence readiness.

If evidence is `missing/invalid` for final reportable findings, list it as a blocking issue. Use `/mantishack resume <target_domain>` as the next command when analytics gives a clear `missing_evidence` blocker or missing finding IDs; otherwise use `/mantis-debug <target_domain>` to inspect the unclear state.
If analytics includes `egress` or `geofence_warnings`, include recent egress profile names and any `network_unreachable_target` warning in the blocking issue line. Recommend `/mantishack --egress <profile> resume <target_domain>` only when the operator has chosen the profile.

## V2 Verification Panel
When `mantis_read_verification_context` reports `schema_version: 2`, surface a compact panel built from `archived_attempts`, `current_attempt_id`, and the freshness fields. The panel is part of the verification line, not a separate command. Render:

- Current attempt: `<current_attempt_id>` with the first 8 chars of `snapshot_hash` and one of `current` or `stale` based on `snapshot_hash_current`.
- Adjudication and evidence: print whether `adjudication_status.exists` is true and whether `evidence_match_status.matches` agrees. Mismatch is a blocking issue.
- Replay policy: include the execution mode from `replay_execution_policy` (e.g., `serialized`) so the operator can see what's gating concurrent verification work.
- Archive trail: print `archived_attempts.length` and, when non-zero, the up-to-three most recent entries as `<attempt_id> @ <archived_at> snapshot <snapshot_hash:0..8> files <files_count>`. Suppress the trail entirely when count is zero. Older v1 sessions print `verification: schema v1` and skip the panel.

When `stale_blockers` is non-empty, list each blocker on its own line under the panel and treat the run as blocked.

## Final Answer Shape
Always include:
- Target and phase.
- Wave state: current wave, pending wave, readiness if known.
- Findings, verification, evidence status, grade, and report presence.
- For verification, render the V2 Verification Panel above for v2 sessions; for v1 sessions, include reportable count and the context `next_action` when available.
- Egress profile summary and geofence warning when visible from analytics.
- If the update cache says a Mantis update is available, include `Update: Mantis <version> available. Run /mantis-update.`
- Any blocking issue visible from status reads.
- Next command: usually `/mantishack resume <target_domain>`, `/mantis-debug <target_domain>`, `/mantis-debug --deep <target_domain>`, or no action needed.

Do not include detailed root-cause analysis. If the operator needs that, point them to `/mantis-debug`.
