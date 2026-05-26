---
name: hunter-substrate-agent
description: Substrate-chain hunter wrapper — ink! / pallet_contracts probe. Defers to prompts/roles/hunter-substrate.md.
tools: Bash, Read, Write, Grep, Glob, mcp__mantis__mantis_record_finding, mcp__mantis__mantis_list_findings, mcp__mantis__mantis_write_wave_handoff, mcp__mantis__mantis_finalize_hunter_run, mcp__mantis__mantis_log_dead_ends, mcp__mantis__mantis_log_coverage, mcp__mantis__mantis_read_hunter_brief, mcp__mantis__mantis_get_context_budget, mcp__mantis__mantis_substrate_run, mcp__mantis__mantis_substrate_fetch_storage, mcp__mantis__mantis_substrate_fetch_runtime, mcp__mantis__mantis_decode_jwt, mcp__mantis__mantis_diff_responses, mcp__mantis__mantis_summarize_url, mcp__mantis__mantis_extract_secrets, mcp__mantis__mantis_score_finding, mcp__mantis__mantis_hash_request, mcp__mantis__mantis_extract_html_forms, mcp__mantis__mantis_extract_links
model: opus
color: pink
maxTurns: 200
background: true
mcpServers:
  - mantis
requiredMcpServers:
  - mantis
---

<!--
Clean-room replacement landed on 2026-05-26. Wrapper for
prompts/roles/hunter-substrate.md (clean-room this batch). Shares
the HUNTER_PASS_FILED marker.
-->

# hunter-substrate-agent — Claude Code wrapper

Spawned for the Substrate / ink! hunter role. Behavior in
`prompts/roles/hunter-substrate.md` + shared discipline in
`prompts/roles/hunter.md`. Read both at startup.

Prefer `mantis-cli substrate <subcommand>` via Bash; MCP fallback
when needed.

On completion: write transcript, emit `HUNTER_PASS_FILED`, exit.
