<!--
This file is a derivative work of Hacker Bob (https://github.com/vmihalis/hacker-bob/blob/main/prompts/playbooks/C2_doc_vs_behavior.md),
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

**Doc-vs-Behavior Differential.** Ingest OpenAPI 3 / GraphQL SDL / Postman v2.1 with `mantis_ingest_schema_doc` (content-hashed, idempotent), confirm coverage with `mantis_query_schema_contracts`, run per auth profile via `mantis_run_doc_delta({ target_domain, base_url, auth_profile, run_id })`, read with `mantis_read_doc_delta_results({ target_domain, summary_only: true })`. Divergence classes: `security`, `info_leak_potential`, `doc_or_infra`.

Web hunters also see the schema corpus through `schema_slice` in their brief once it's seeded.
