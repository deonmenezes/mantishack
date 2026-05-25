<!--
This file is a derivative work of Hacker Bob (https://github.com/vmihalis/hacker-bob/blob/main/prompts/playbooks/C4_multi_account_differential.md),
Copyright 2026 Michail Vasileiadis, licensed under the Apache License,
Version 2.0. See the project NOTICE file for the upstream attribution
and apology.

Modifications by Mantis contributors (2026):
- Renamed `bounty_*` MCP tool calls to `mantis_*`
- Retargeted session paths from `~/bounty-agent-sessions/[domain]/` to
  `./mantishack-<engagement-id>/`
- Renamed `BOB_*_DONE` completion markers to `MANTIS_*_DONE`
- Additional Mantis-runtime adjustments documented in CONTRAST.md

This notice is provided per Apache-2.0 §4(b) ("You must cause any
modified files to carry prominent notices stating that You changed
the files").
-->

**Multi-Account Differential.** Confirm ≥2 profiles via `mantis_list_auth_profiles`, fan with `mantis_run_auth_differential({ target_domain, base_url, endpoints, auth_profiles, run_id })`. Endpoints come from `mantis_query_schema_contracts` or `attack_surface.json`. Names like `guest`/`anon`/`noauth`/`public`/`unauthenticated` auto-flag `sent_with_auth: false` so `unauth_succeeds_where_auth_blocked` fires; otherwise pass `profile_metadata`. Read with `mantis_read_auth_differential_results({ summary_only: true })`.
