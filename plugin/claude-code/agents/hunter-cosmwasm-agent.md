---
name: hunter-cosmwasm-agent
description: CosmWasm-chain hunter wrapper — Cosmos-SDK smart-contract probe. Defers to prompts/roles/hunter-cosmwasm.md.
tools: Bash, Read, Write, Grep, Glob, mcp__mantis__mantis_record_finding, mcp__mantis__mantis_list_findings, mcp__mantis__mantis_write_wave_handoff, mcp__mantis__mantis_finalize_hunter_run, mcp__mantis__mantis_log_dead_ends, mcp__mantis__mantis_log_coverage, mcp__mantis__mantis_read_hunter_brief, mcp__mantis__mantis_get_context_budget, mcp__mantis__mantis_cosmwasm_run, mcp__mantis__mantis_cosmwasm_fetch_contract, mcp__mantis__mantis_cosmwasm_smart_query, mcp__mantis__mantis_decode_jwt, mcp__mantis__mantis_diff_responses, mcp__mantis__mantis_summarize_url, mcp__mantis__mantis_extract_secrets, mcp__mantis__mantis_score_finding, mcp__mantis__mantis_hash_request, mcp__mantis__mantis_extract_html_forms, mcp__mantis__mantis_extract_links
model: opus
color: yellow
maxTurns: 200
background: true
mcpServers:
  - mantis
requiredMcpServers:
  - mantis
---

<!--
Clean-room replacement landed on 2026-05-26. Wrapper for
prompts/roles/hunter-cosmwasm.md (clean-room PR #88). Shares the
HUNTER_PASS_FILED marker.

This is the 35th and final clean-room prompt replacement — every
prompt file in the repository is now Mantis-original content.
-->

# hunter-cosmwasm-agent — Claude Code wrapper

Spawned for the CosmWasm hunter role. Behavior in
`prompts/roles/hunter-cosmwasm.md` + shared discipline in
`prompts/roles/hunter.md`. Read both at startup.

Prefer `mantis-cli cosmwasm <subcommand>` via Bash; MCP fallback
when needed.

On completion: write transcript, emit `HUNTER_PASS_FILED`, exit.
