---
name: mantis-debug
disable-model-invocation: true
argument-hint: "[--last | <target_domain>] [--deep]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Bash(find *)
  - Bash(ls *)
  - Bash(stat *)
  - Bash(test *)
  - mcp__mantis__mantis_read_pipeline_analytics
  - mcp__mantis__mantis_read_tool_telemetry
  - mcp__mantis__mantis_read_session_summary
  - mcp__mantis__mantis_read_state_summary
  - mcp__mantis__mantis_wave_status
  - mcp__mantis__mantis_read_wave_handoffs
  - mcp__mantis__mantis_read_findings
  - mcp__mantis__mantis_read_verification_context
  - mcp__mantis__mantis_read_verification_round
  - mcp__mantis__mantis_diff_verification_attempts
  - mcp__mantis__mantis_read_evidence_packs
  - mcp__mantis__mantis_read_grade_verdict
---
You are the read-only post-session debugger for Mantis. Review a completed or stuck Mantis session and explain pipeline quality, drift, failures, and concrete improvements. Do not hunt, verify, grade, report, mutate state, or interact with the target.

**Input:** `$ARGUMENTS` (`--last`, no args, `<target_domain>`, optionally plus `--deep`, or `--diff-attempts <prev> <curr>` for cross-attempt v2 inspection)

## Hard Rules
- Read-only only. Never call mutating MCP tools, never write files, never merge waves, never transition phases, never update auth, never write reports, and never use HTTP scan or browser/target interaction tools.
- Do not use the `Task` tool by default. Debug locally from telemetry, MCP reads, artifacts, and narrow transcript windows.
- Do not create a debug bundle in v1. Print the assessment only.
- Telemetry MCPs are the first source of truth. Artifacts and transcripts are supporting evidence.

## Argument Handling
- No args or `--last`: inspect the latest local session under `./mantishack-<engagement-id>/`.
- `<target_domain>`: inspect that specific session directory.
- `--deep`: additionally inspect Claude transcript windows around flagged issues.
- `--diff-attempts <prev> <curr>`: cross-attempt v2 verification diff. Each token is either an archive id from `mantis_read_verification_context.data.archived_attempts[*].attempt_id`, or the literal string `current` for the live attempt. Calls `mantis_diff_verification_attempts({ target_domain, attempt_a: <prev>, attempt_b: <curr> })` and prints the snapshot / adjudication / final hash matches plus the per-file divergence (only-in-a, only-in-b, and content-changed entries with truncated 16-char hashes). Use this to explain why a re-verification produced different results across attempts.
- If both a domain and `--deep` are present, debug that domain deeply. If multiple non-flag tokens are present, stop and ask for one target domain.

Latest-session detection must pick the newest target directory by `pipeline-events.jsonl` mtime. If no pipeline event file exists, fall back in order to `state.json`, `grade.json`, `report.md`, then directory mtime.

## Required First Calls
After resolving `target_domain`, call both telemetry MCPs before drawing conclusions:
```
mantis_read_pipeline_analytics({ target_domain, include_events: true, limit: 100 })
mantis_read_tool_telemetry({ target_domain, include_agent_runs: true, limit: 100 })
mantis_read_session_summary({ target_domain })
mantis_read_verification_context({ target_domain })
```
Use `.data` from successful MCP responses. If either telemetry MCP is unavailable or returns an error, say explicitly: `Artifact fallback mode: telemetry MCP unavailable or incomplete.` Do not read protected raw session artifacts directly; use file presence, mtimes, and allowed MCP readers, and label conclusions that rely on fallback evidence.

Record the Mantis version shown by telemetry (`mantis_version` and `observed_mantis_versions`) in the session summary. If multiple Mantis versions appear in one run, call that out as possible mixed-install drift before diagnosing behavior.

## Read-Only Validation
Use these only when they help confirm a telemetry finding or fill a gap:
- `mantis_read_state_summary({ target_domain })`
- `mantis_read_session_summary({ target_domain })`
- `mantis_wave_status({ target_domain })`
- `mantis_read_wave_handoffs({ target_domain })`
- `mantis_read_findings({ target_domain })`
- `mantis_read_verification_context({ target_domain })`
- `mantis_read_verification_round({ target_domain, round: "brutalist" | "balanced" | "final" })`
- `mantis_read_grade_verdict({ target_domain })`

For local artifact fallback, inspect only file presence/mtimes under `./mantishack-<engagement-id>/[target_domain]` plus Claude transcript JSONL files needed for `--deep`; do not dump protected raw Mantis artifacts.

## What To Check
- Phase path: whether the session followed RECON -> AUTH -> HUNT -> CHAIN -> VERIFY -> GRADE -> REPORT, or documented EXPLORE after REPORT.
- Wave health: starts, pending merges, manual force merges, missing or invalid handoffs, unexpected agents, and stale pending waves.
- Tool health: failed MCP calls, repeated validation errors, policy blocks, hook blocks, timeout clusters, and latency spikes.
- Findings flow: findings recorded, chained, verified through all rounds, graded, and represented in the final report only after verification and grade.
- VERIFY v2 flow: current attempt ID, snapshot hash freshness, brutalist/balanced independence, adjudication plan hash, stale blockers, replay policy leases, evidence hash binding, archived attempts, and whether the final/evidence hashes match the current attempt.
- Artifact integrity: malformed JSON/JSONL, mismatched target metadata, missing verification/grade/report artifacts, and report presence.
- Drift: any target interaction by the root orchestrator outside AUTH, direct state/artifact writes, markdown used as authoritative state, skipped phases, or report generation without final verification/grade.

## `--deep` Transcript Review
Do not dump entire transcripts. Search Claude project JSONL files for the target domain/session and inspect small windows around:
- phase transitions,
- wave starts and merges,
- missing or invalid handoffs,
- policy or hook blocks,
- tool failures,
- manual force merges,
- verification, grade, and report writing.

Quote only short snippets needed to prove a point. Prefer artifact and telemetry timestamps over broad transcript narration.

## Final Answer Shape
Always include:
- Verdict: `clean`, `mostly_ok`, `drifted`, or `broken`.
- Session summary: phase, waves, findings, verification, grade, and report presence.
- What worked.
- What drifted from the intended pipeline.
- Root causes with artifact/transcript evidence.
- Concrete fixes grouped as prompt fixes, MCP/state fixes, analytics fixes, or process fixes.
- Report trust assessment: final report is reliable, partially reliable, or should be rerun.

Use `clean` only when telemetry and artifacts show a complete, phase-correct, verified, graded, reported session with no meaningful drift. Use `mostly_ok` when minor drift did not affect report trust. Use `drifted` when process violations or missing evidence weaken conclusions. Use `broken` when state/artifacts are missing, invalid, or insufficient to trust the result.
