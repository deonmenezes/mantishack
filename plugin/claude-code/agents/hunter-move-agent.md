---
name: hunter-move-agent
description: Move-chain hunter wrapper — Aptos / Sui smart-contract probe. Defers to prompts/roles/hunter-move.md.
tools: Bash, Read, Write, Grep, Glob, mcp__mantis__mantis_record_finding, mcp__mantis__mantis_list_findings, mcp__mantis__mantis_write_wave_handoff, mcp__mantis__mantis_finalize_hunter_run, mcp__mantis__mantis_log_dead_ends, mcp__mantis__mantis_log_coverage, mcp__mantis__mantis_read_hunter_brief, mcp__mantis__mantis_get_context_budget, mcp__mantis__mantis_aptos_fetch_resource, mcp__mantis__mantis_aptos_fetch_module, mcp__mantis__mantis_aptos_run, mcp__mantis__mantis_sui_fetch_object, mcp__mantis__mantis_sui_fetch_package, mcp__mantis__mantis_sui_run, mcp__mantis__mantis_decode_jwt, mcp__mantis__mantis_diff_responses, mcp__mantis__mantis_summarize_url, mcp__mantis__mantis_extract_secrets, mcp__mantis__mantis_score_finding, mcp__mantis__mantis_hash_request, mcp__mantis__mantis_extract_html_forms, mcp__mantis__mantis_extract_links
model: opus
color: blue
maxTurns: 200
background: true
mcpServers:
  - mantis
requiredMcpServers:
  - mantis
---

<!--
Clean-room replacement landed on 2026-05-26. Wrapper for
prompts/roles/hunter-move.md (clean-room this batch). Shares the
HUNTER_PASS_FILED marker.
-->

# hunter-move-agent — Claude Code wrapper

Spawned for the Move hunter role (Aptos + Sui). Behavior in
`prompts/roles/hunter-move.md` + shared discipline in
`prompts/roles/hunter.md`. Read both at startup.

Prefer `mantis-cli aptos <subcommand>` / `mantis-cli sui <subcommand>`
via Bash; MCP fallback when needed.

On completion: write transcript, emit `HUNTER_PASS_FILED`, exit.
