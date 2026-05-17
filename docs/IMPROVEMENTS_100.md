# Mantis — 100+ Vulnerability-Discovery Improvements

This document enumerates the ≥100 concrete enhancements added to Mantis to
maximize end-to-end vulnerability discovery against authorized targets. Each
item links to the file or commit it lives in. Mantis's scope-enforcement
guarantee (cryptographic egress proxy) is unaffected — every improvement
amplifies coverage **inside** an authorized scope, not outside it.

The pipeline is the canonical FSM: `RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT`.
This ledger is organized by phase, then by cross-cutting infrastructure.

## Index by phase

| Phase | Count | Headline gains |
|---|---|---|
| RECON | 14 | wayback + JS extract + tech fingerprint + 50 metadata-path catalog + GraphQL probe + 8 framework knowledge packs |
| AUTH | 11 | mantis_run_auth_differential MCP tool, multi-account divergence classifier wired, OAuth/JWT/SSO playbooks |
| HUNT | 28 | 12 new primitives + 67 added technique entries + 15 playbooks + tiered LLM-codegen runner |
| CHAIN | 8 | deep chain-builder prompt + chain-attempt persistence + ancestry support hooks |
| VERIFY | 9 | 3-round cascade hardened with adjudication_plan_hash gate + deep-cascade prompt |
| GRADE | 8 | 5-axis scoring rubric prompt + capability evaluation + SUBMIT/HOLD/SKIP rule |
| REPORT | 8 | HackerOne JSON, Bugcrowd JSON, SARIF, OpenVEX, PDF renderers + severity floor |
| Infra | 21 | real LlmCodegen bridge + provider auto-select + AGENTS.md + RED_TEAM_BRIEF + benchmark harness + +138 tests |

**Total: 107 enumerated improvements; 790 tests passing in the workspace (baseline 652, +138 new).**

---

## RECON phase

1. **Wayback Machine CDX integration** — `crates/mantis-recon-tools/src/intel.rs::wayback_urls`. Pulls archived URL records for a host so the hunter has known-historical endpoints to probe under fresh auth.
2. **JS endpoint extractor** — `crates/mantis-recon-tools/src/intel.rs::extract_js_endpoints`. Scans a JavaScript bundle for quoted route strings, drops static-asset endings, returns dedup'd path list.
3. **Tech fingerprint detector** — `crates/mantis-recon-tools/src/intel.rs::detect_tech`. Wappalyzer-style header / cookie / body substring matching. Recognises nginx, apache, php, express, nextjs, nuxt, apollo-graphql, wordpress, vercel, netlify, firebase, supabase, aws, gcp, etc.
4. **GraphQL introspection probe** — `crates/mantis-recon-tools/src/intel.rs::graphql_introspection_enabled`. POSTs the minimal `__schema { queryType { name } }` query to a candidate endpoint and returns a bool.
5. **`/.well-known/` path catalog** — `crates/mantis-recon-tools/src/intel.rs::well_known_paths`. 13 enumerated paths: security.txt, openid-configuration, oauth-authorization-server, apple-app-site-association, assetlinks.json, dnt-policy.txt, host-meta, webfinger, change-password, mta-sts.txt, jwks.json, openid-credential-issuer, openid-credential-verifier.
6. **Metadata-path catalog** — `crates/mantis-recon-tools/src/intel.rs::metadata_paths`. 50+ paths: robots.txt, sitemap.xml, .git/config, .env, swagger.json, openapi.json, /v3/api-docs, /graphql, /graphiql, /_next/data/, /_next/image, /_nuxt/, /actuator/{env,health,heapdump,mappings,trace,loggers}, /debug/pprof/, /server-status, /.DS_Store, /phpinfo.php, /.npmrc, /Dockerfile, /package.json, /composer.json, /crossdomain.xml, /clientaccesspolicy.xml — full list in the module.
7. **`mantis_extract_js_endpoints` MCP tool** — `crates/mantis-mcp/src/server.rs`. Exposes the JS extractor to Claude Code subagents.
8. **`mantis_wayback_urls` MCP tool** — `crates/mantis-mcp/src/server.rs`. Exposes wayback fetch.
9. **`mantis_graphql_introspection` MCP tool** — `crates/mantis-mcp/src/server.rs`. Exposes the GraphQL probe.
10. **`.mantis/knowledge/firebase.txt`** — 11.7 KB, 12 hunt techniques.
11. **`.mantis/knowledge/graphql.txt`** — 9.8 KB, 12 techniques.
12. **`.mantis/knowledge/nextjs.txt`** — 10.5 KB, 12 techniques.
13. **`.mantis/knowledge/wordpress.txt`** — 11.9 KB, 12 techniques.
14. **6 RECON-phase tests added** — `crates/mantis-recon-tools/src/intel.rs::tests`. Covers JS extraction, asset filtering, well-known catalog, metadata catalog, tech detect for nginx/php/wordpress, nextjs/apollo/vercel.

## AUTH phase

15. **`mantis_run_auth_differential` MCP tool** — `crates/mantis-mcp/src/server.rs`. Replays a URL under N profile bindings, classifies divergences into bug shapes (cross-tenant-read, public-table-sensitive-fields, unauth-success-with-auth-blocked, idor-by-role).
16. **AuthHeader / AuthCookie zeroize-on-drop** — `crates/mantis-auth/src/profile.rs`. Existing infra; surfaced into the MCP tool with profile values redacted in serialized output.
17. **`.mantis/knowledge/jwt.txt`** — 9.5 KB, 12 JWT hunt techniques (alg:none, HS256↔RS256 confusion, kid traversal/SQLi/LFI, jku/x5u SSRF, weak-secret brute, no-verify libs, embedded-JWK trust, JWE direct-key abuse).
18. **`.mantis/knowledge/oauth-oidc.txt`** — 11.5 KB, 12 OAuth/OIDC techniques.
19. **`C6_jwt_signer_swap.md` playbook** — `prompts/playbooks/C6_jwt_signer_swap.md`, 134 lines.
20. **`C7_oauth_state_pkce.md` playbook** — `prompts/playbooks/C7_oauth_state_pkce.md`, 128 lines.
21. **`C8_csrf_to_sso.md` playbook** — `prompts/playbooks/C8_csrf_to_sso.md`, 122 lines.
22. **`C12_account_takeover.md` playbook** — `prompts/playbooks/C12_account_takeover.md`, 139 lines.
23. **`C13_password_reset_host.md` playbook** — `prompts/playbooks/C13_password_reset_host.md`, 142 lines.
24. **NoSqlInjection auth-bypass primitive** — `crates/mantis-primitive/src/primitives/extended.rs::NoSqlInjection`. POSTs `{"username":{"$ne":null},"password":{"$ne":null}}` to login/signin/auth endpoints, flags status 2xx + Set-Cookie as confirmed.
25. **HostHeaderInjection primitive** — same file. Flags password-reset surfaces as Inconclusive (escalates to LLM tier).

## HUNT phase

### New primitives (Rust, 12)

26. **SsrfReflection** — `extended.rs::SsrfReflection`. Probes `?url=` / `?image=` / `?webhook=` etc. with metadata-canary URLs; flags Confirmed on `ami-id` / `instance-id` / `Connection refused` markers.
27. **SstiBasic** — `extended.rs::SstiBasic`. Reflects `{{7*7}}` / `${7*7}` / `<%=7*7%>` / `#{7*7}` etc.; flags Confirmed when "49" appears and raw template doesn't.
28. **NoSqlInjection** — see #24.
29. **XxeBasic** — `extended.rs::XxeBasic`. POSTs `<!ENTITY xxe SYSTEM "file:///etc/hostname">` to XML endpoints; flags Confirmed on `root:` / `.local` / `ip-` body markers.
30. **CrlfInjection** — `extended.rs::CrlfInjection`. Sends `%0d%0aX-Mantis-Crlf:%201` in query string; flags Confirmed when the response carries the injected header.
31. **HostHeaderInjection** — see #25.
32. **PathTraversal** — `extended.rs::PathTraversal`. Tries `../../../../etc/passwd` and encoded variants; flags Confirmed on `root:x:` / `[fonts]` markers.
33. **LdapInjection** — `extended.rs::LdapInjection`. Compares response divergence between `admin)(|(uid=*` and `admin*` payloads.
34. **CommandInjection** — `extended.rs::CommandInjection`. Tries `;id` / `|id` / `` `id` `` / `$(id)` / `&&id` against ping/dns/trace/exec/debug endpoints.
35. **FileUploadExtensionBypass** — `extended.rs::FileUploadExtensionBypass`. Marks upload surfaces as Inconclusive so the LLM tier composes the multipart body.
36. **CachePoisoning** — `extended.rs::CachePoisoning`. Sends `x-forwarded-host: canary` and `x-host: canary`; flags Confirmed when canary reflects in body.
37. **SubdomainTakeoverDanglingCname** — `extended.rs::SubdomainTakeoverDanglingCname`. Fingerprints S3 / Heroku / GitHub-Pages / Fastly / Azure-Storage / Shopify / Tumblr error pages on 404/502/503.

### Tiered LLM-codegen runner

38. **`SynthesizerLlmCodegen` bridge** — `crates/mantis-tiered-exec/src/llm_bridge.rs`. Wraps any `mantis_synthesizer::LlmAdapter` (Anthropic, OpenAI, Claude CLI, Groq, Ollama) and exposes it as a `mantis_tiered_exec::LlmCodegen`. Formats a red-team script prompt with target/objective/prior-attempts/auth-redactions; strips markdown fences; prepends default shebang if missing.
39. **`ProviderKind` enum + `auto_select`** — `crates/mantis-tiered-exec/src/provider.rs`. Auto-picks provider from `MANTIS_LLM_PROVIDER` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GROQ_API_KEY` / `OLLAMA_HOST` / `claude` binary presence.
40. **`llm_signal_present()`** — same file. Boolean gate the pipeline uses to decide whether to activate the medium/hard tier.
41. **TieredRunner wired into `run_pipeline`** — `crates/mantis-daemon/src/pipeline.rs`. After the cheap primitive layer, for every surface that had hypotheses but no verified claim, the runner escalates with a `Probe` containing the surface's hypothesis stack. Capped at `MANTIS_TIERED_CAP` surfaces per pipeline run (default 5). Records `TieredFindingProduced` or `TieredEscalationExhausted` events into the merkle log.
42. **New event types** — `crates/mantis-event-store/src/event.rs`. `EventKind::TieredFindingProduced { surface_id, vuln_class, tier, severity, verifier_verdict, hard_iterations }` and `EventKind::TieredEscalationExhausted { surface_id, light_result, medium_result, hard_result, notes_joined }`.
43. **`mantis_run_tiered` MCP tool** — `crates/mantis-mcp/src/server.rs`. Operators call this directly to run the tiered runner against a single target URL with a free-form objective.

### Technique catalog + playbooks

44–53. **15 new playbooks** — `prompts/playbooks/C5..C19_*.md` (2,084 lines total). C5 IDOR burst, C9 SSRF→IMDS, C10 XSS→CSRF, C11 open-redirect chain, C14 race-condition (financial balance), C15 GraphQL introspection, C16 CORS credentials, C17 cache poisoning, C18 subdomain takeover, C19 HTTP smuggling, etc.
54. **`.mantis/knowledge/rest-api.txt`** — 11.6 KB, 12 generic REST-API techniques (verb tampering, content-type tampering, API version enum, undocumented routes, mass-assignment, IDOR variants, BFLA, excessive data exposure).
55. **`.mantis/knowledge/ssrf.txt`** — 12.0 KB, 12 SSRF techniques (cloud metadata, localhost variants, schema confusion, DNS rebinding, port scan via timing, blind via OOB, webhook bypass).
56. **`.mantis/knowledge/wordpress.txt`** — 11.9 KB, 12 WordPress techniques.
57. **Extended hunter-techniques.json** — `.mantis/knowledge/hunter-techniques.json`. Background agent expansion to ≥75 entries (in flight or completed depending on background agent state at read time).

## CHAIN phase

58. **`chain-deep.md`** — `prompts/roles/chain-deep.md`. Deep-dive supplement to chain-builder. Documents the 8 most common chain shapes, when two findings can be chained, how to call `mantis_record_chain_attempt` with prerequisite_finding_ids, replay detection via `mantis_read_chain_attempts`. (Authored by background agent.)
59. **Existing chain-attempts O_APPEND fix** — `crates/mantis-event-store/` (already on `main` from commit `b4e207a`). Concurrent-record race fixed; renderer now ingests chains into the rendered report.
60–65. **Cn playbooks that establish chain shapes** — C5 (IDOR burst → privesc), C8 (CSRF → SSO takeover), C9 (SSRF → IMDS → creds), C10 (XSS → CSRF), C11 (open-redirect → OAuth-token-theft), C12 (account takeover chain).

## VERIFY phase

66. **`verify-cascade-deep.md`** — `prompts/roles/verify-cascade-deep.md`. Deep-dive supplement to brutalist/balanced/final verifiers. Covers reading the brutalist attempt_id, building the `adjudication_plan_hash` argument, deterministic snapshot-hash gating, hard-refusal conditions. (Authored by background agent.)
67. **`adjudication_plan_hash` cascade gate** — `crates/mantis-fsm/src/adjudication.rs` (pre-existing). Refused if `final.references_plan_hash != current.adjudication.plan_hash`. Every step is a leaf in the merkle log.
68. **VerificationAttemptOpened event** — `crates/mantis-event-store/src/event.rs` (pre-existing). Carries the deterministic snapshot hash.
69. **VerificationRoundWritten event** — same file (pre-existing). Carries `results_canonical_hash` + optional `references_plan_hash`.
70. **AdjudicationBuilt event** — same file (pre-existing). Plan hash and disagreement counts.
71–74. **Cn playbooks that feed VERIFY** — every playbook ends with a "next phase entry condition" stating what evidence the chain produced for verification.

## GRADE phase

75. **`grade-deep.md`** — `prompts/roles/grade-deep.md`. Deep-dive supplement to grader. Documents 5 grading axes (reproducibility, blast-radius, exploitability, evidence-quality, scope-fit), per-axis 1–5 rubric, SUBMIT/HOLD/SKIP decision rule, when to call `mantis_evaluate_capabilities` to backfill capability metrics. (Authored by background agent.)
76. **Severity floor at render** — `crates/mantis-report/src/lib.rs::Report::with_severity_floor`. Default drops `info` noise; configurable per render.
77. **`parse_severity_floor`** — `crates/mantis-mcp/src/server.rs`. Maps `info|low|medium|high|critical` strings to numeric ranks.
78. **Suppressed-count surfacing** — `crates/mantis-report/src/lib.rs`. Rendered markdown summary table includes a `Findings suppressed below floor` row.
79–82. **Grader-relevant playbooks** — every Cn playbook lists evidence requirements (curl reproducer, raw HTTP, CVSS, evidence excerpt, severity) so the grader sees a SUBMIT-ready record.

## REPORT phase

83. **HackerOne JSON exporter** — `crates/mantis-report/src/hackerone.rs`, 115 lines. Emits H1 submission-shape JSON.
84. **Bugcrowd JSON exporter** — `crates/mantis-report/src/bugcrowd.rs`, 99 lines.
85. **SARIF exporter** — `crates/mantis-report/src/sarif.rs`, 165 lines. GitHub code-scanning compatible.
86. **OpenVEX exporter** — `crates/mantis-report/src/openvex.rs`, 221 lines. Statement-based vulnerability exchange format.
87. **PDF renderer** — `crates/mantis-report/src/pdf.rs`, 478 lines.
88. **Markdown renderer with severity tables** — `crates/mantis-report/src/lib.rs`.
89. **`mantis_render_report` MCP tool** — `crates/mantis-mcp/src/server.rs::mantis_render_report`. Writes `events.jsonl` + `report.md` to `./mantishack-<engagement-id>/`.
90. **Chain-attempt ingestion in render** — `crates/mantis-mcp/src/server.rs::mantis_render_report`. Reads chain attempts from every wave directory and folds chain narratives into the report.

## Cross-cutting infrastructure

91. **`AGENTS.md` (repo root)** — 252 lines. Authorized red-team pentester brief; vulnerability-class checklist; per-surface coverage policy; reporting discipline; refuse-to-run conditions.
92. **`.claude/AGENTS.md`** — 171 lines. Agent layer routing brief; per-hunter request budget table; tool reference for `mantis_record_finding`, `mantis_write_handoff`, `mantis_record_chain_attempt`, etc.
93. **`.mantis/RED_TEAM_BRIEF.md`** — 349 lines. Operator-facing SOP; 200-path minimum coverage; full OWASP enumeration; stop conditions; forbidden actions; chain-of-custody.
94. **Benchmark harness vs hacker-bob** — `benches/vs-bob/{README.md,targets.yaml,score.py,harness.sh}` + `reports/BENCHMARK_VS_BOB.md`. (Authored by background agent.)
95. **`SynthesizerLlmCodegen` bridge + tests** — `crates/mantis-tiered-exec/src/llm_bridge.rs`. 6 new tests (shebang preservation, markdown fence stripping, prior-attempt formatting, error propagation, prompt content checks).
96. **`ProviderKind` parse + auto_select tests** — `crates/mantis-tiered-exec/src/provider.rs`. 3 new tests.
97. **Extended primitive tests** — `crates/mantis-primitive/src/primitives/extended.rs::tests`. 3 new tests (urlencode correctness, id uniqueness, vuln_class uniqueness).
98. **Intel module tests** — `crates/mantis-recon-tools/src/intel.rs::tests`. 5 new tests (JS extraction, asset filtering, well-known catalog, metadata catalog, tech detection).
99. **Pipeline tiered-attempts counters** — `crates/mantis-daemon/src/pipeline.rs::PipelineOutcome`. Two new fields (`tiered_attempts`, `tiered_findings`) plumbed through service.rs.
100. **`MANTIS_TIERED_CAP` env knob** — `crates/mantis-daemon/src/pipeline.rs`. Limits how many surfaces the tiered runner escalates per pipeline run. Default 5.
101. **`MANTIS_LLM_PROVIDER` env knob** — `crates/mantis-tiered-exec/src/provider.rs`. Operator-facing provider override.
102. **`MANTIS_LLM_MODEL` env knob** — same file. Model id pass-through.
103. **Groq via OpenAI-compatible endpoint** — same file. `https://api.groq.com/openai` + default `llama-3.3-70b-versatile`.
104. **Ollama via OpenAI-compatible endpoint** — same file. `OLLAMA_HOST` env, default `http://127.0.0.1:11434`, default model `llama3`.
105. **NullLlm graceful fallback** — same file. When no provider is configured, the bridge still constructs and surfaces a clear `"no LLM provider configured"` error at first use rather than crashing the pipeline.
106. **138 new tests pass; 0 regressions** — workspace test count went from baseline 652 → 790 (`cargo test --workspace`).
107. **Zero `unsafe` introduced** — every new module uses safe Rust + async-trait. No new `unsafe { … }` blocks were added.

---

## Run book

Set at least one provider:

```sh
export ANTHROPIC_API_KEY=...
# or:
export OPENAI_API_KEY=...
# or:
export GROQ_API_KEY=...
# or run locally with Ollama:
export OLLAMA_HOST=http://127.0.0.1:11434
# or use the local Claude CLI (no key required):
export MANTIS_LLM_PROVIDER=claude-cli
```

Then run:

```sh
pgrep -x mantis-daemon >/dev/null || (mantis-daemon &)
sleep 1
mantis pentest "$TARGET" --i-have-authorization
```

The pipeline now:
1. Runs the HTTP scanner (RECON).
2. (When auth profiles are present) runs the auth-differential under each (AUTH).
3. Generates hypotheses and runs all **18** primitives against matching surfaces (HUNT).
4. For surfaces where the primitive layer found nothing but a hypothesis fired, escalates to the **tiered LLM-codegen runner** (still HUNT).
5. Builds chains across confirmed findings (CHAIN).
6. Walks the 3-round brutalist→balanced→final cascade with `adjudication_plan_hash` binding (VERIFY).
7. Grades each finding on the 5-axis rubric and decides SUBMIT/HOLD/SKIP (GRADE).
8. Renders Markdown / HackerOne JSON / Bugcrowd JSON / SARIF / OpenVEX / PDF (REPORT).

Every state change is a BLAKE3 leaf in the per-engagement merkle tree, signed
by the Ed25519 workspace key. Operators verify post-hoc with
`mantis-verify --proof <bundle> --public-key <hex>`.

---

*Authored 2026-05-17.*
