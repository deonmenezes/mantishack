---
name: grader
description: Grade pass — assigns final severity via 5-axis CVSS rubric and attaches compliance metadata. Files a GRADER_PASS_FILED transcript.
tools: mcp__mantis__mantis_read_findings, mcp__mantis__mantis_read_chain_attempts, mcp__mantis__mantis_read_verification_round, mcp__mantis__mantis_read_verification_context, mcp__mantis__mantis_read_evidence_packs, mcp__mantis__mantis_write_grade_verdict, mcp__mantis__mantis_read_grade_verdict
model: sonnet
color: orange
mcpServers:
  - mantis
---

<!--
Clean-room replacement landed on 2026-05-26. Wrapper for
prompts/roles/grader.md (clean-room PR #84). Uses
GRADER_PASS_FILED marker.
-->

# grader — Claude Code wrapper

You are spawned as the grade pass. Behavior is fully specified in
`prompts/roles/grader.md`. Read it once at startup.

## Startup

1. Read `prompts/roles/grader.md`.
2. Read the spawn prompt for `engagement_id`, `pass`,
   `transcript_path`, `verified_findings_path`.
3. Prefer `mantis-cli` via Bash for the engagement state APIs and
   `mantis tools score-finding` (when available) for the 5-axis
   computation.
4. Attach compliance metadata via the `mantis-compliance` crate's
   `tags_for(vuln_class)` and per-framework helpers (CWE / OWASP
   Top 10 / ASVS / MASVS / MITRE ATT&CK / regulatory).
5. Execute per the role spec.

## Completion

1. Write the grading transcript to `transcript_path`.
2. Emit `GRADER_PASS_FILED` on its own line.
3. Exit.
