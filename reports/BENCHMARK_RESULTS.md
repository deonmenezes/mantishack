# Mantis vs Hacker-bob — static-feature benchmark

Authored automatically by `benches/vs-bob/static_compare.py`. Runs entirely
offline against locally-available source trees; no targets are scanned.

- Mantis path: `/Users/deonmenezes/mantishack-daemon`
- Hacker-bob path: `/tmp/hacker-bob-clone`

## Surface inventory

| Axis | Mantis | Hacker-bob | Winner |
|---|---|---|---|
| MCP tools | 120 | 106 | **mantis** |
| Primitives (Rust detectors / JS detectors) | 18 | 0 | **mantis** |
| Subagent prompts (.claude/agents/) | 16 files / 2109 lines | 16 files / 1976 lines | **mantis** |
| Role prompts (prompts/roles/) | 22 files / 2650 lines | 19 files / 1985 lines | **mantis** |
| Capability playbooks (prompts/playbooks/) | 17 files / 2088 lines | 2 files / 4 lines | **mantis** |
| Knowledge packs (.mantis/knowledge or .hacker-bob/knowledge) | 10 files / 124141 B / 58 entries | 1 files / 12008 B / 8 entries | **mantis** |
| Tests in workspace | 940 (Rust) | 935 (JS) | **mantis** |
| Source LoC (Rust workspace / JS MCP+packages) | 46164 | 41626 | **mantis** |

**Surface inventory tally:** Mantis wins **8**, Hacker-bob wins **0**.

## Architecture / cryptographic guarantees

These axes are not numeric counts — they're qualitative differences.

| Axis | Mantis | Hacker-bob |
|---|---|---|
| Cryptographic egress scope enforcement | BLAKE3 + Ed25519-signed scope manifest; CONNECT proxy refuses out-of-scope hits | JS per-tool scope checks (in-process) |
| Merkle event log | BLAKE3 leaves + Ed25519 tree heads verified by `mantis-verify` | Plain JSON pipeline-events.jsonl |
| Persistent daemon | Long-running tonic gRPC daemon; survives CLI restarts + serverless cold-starts | MCP server inside host CLI; dies with the host |
| FSM gate library | Tested Rust library (mantis-fsm, ~86 gate tests) with deterministic plan_hash | JS prompt-side checks in phase-gates.js |
| `adjudication_plan_hash` cascade gate | Computed deterministically + persisted as merkle leaf + Rust-tested | Computed in JS; final-verifier prompt told to reference |
| Tiered LLM-codegen escalation | TieredRunner wired into pipeline.rs; auto-selects Anthropic/OpenAI/Groq/Ollama/CLI | No direct equivalent — relies on Claude Code's host loop |
| Multi-tenant isolation | mantis-tenant namespaces; one daemon serves many engagements | One MCP server per project |
| Hibernation | mantis-hibernation snapshots state for serverless deployments | Not supported |
| Severity floor at render time | Enforced in `crates/mantis-report`; suppressed count surfaced in markdown | Reportability gate inside report-writer prompt |

## MCP tool delta — what each ships

- Mantis-only tools: **17** —
  - `mantis_authorize_scope`
  - `mantis_create_engagement`
  - `mantis_engagement_list`
  - `mantis_engagement_status`
  - `mantis_export_events`
  - `mantis_extract_js_endpoints`
  - `mantis_graphql_introspection`
  - `mantis_list_surfaces`
  - `mantis_merge_wave`
  - `mantis_open_verification_attempt`
  - `mantis_record_chain_attempt`
  - `mantis_render_report`
  - `mantis_run_recon`
  - `mantis_run_tiered`
  - `mantis_session_state`
  - `mantis_start_engagement`
  - `mantis_wayback_urls`
- Hacker-bob-only tools (count, sample): **3** —
  - `bounty_http_scan`
  - `bounty_index`
  - `bounty_read_session_state`

## Primitives — vuln-class detectors

- Mantis primitives (Rust traits in `mantis-primitive`): **18** —
  - `CachePoisoning`
  - `CommandInjection`
  - `CorsWildcard`
  - `CrlfInjection`
  - `FileUploadExtensionBypass`
  - `HostHeaderInjection`
  - `Idor`
  - `LdapInjection`
  - `MissingSecurityHeaders`
  - `NoSqlInjection`
  - `OpenRedirect`
  - `PathTraversal`
  - `SqliErrorBased`
  - `SsrfReflection`
  - `SstiBasic`
  - `SubdomainTakeoverDanglingCname`
  - `XssReflected`
  - `XxeBasic`
- Hacker-bob equivalents (JS detector files found): **0**

## Knowledge pack delta

- Mantis-only: ['firebase.txt', 'graphql.txt', 'hunter-techniques-extended.json', 'jwt.txt', 'nextjs.txt', 'oauth-oidc.txt', 'rest-api.txt', 'ssrf.txt', 'wordpress.txt']
- Hacker-bob-only: (none)
- Both: ['hunter-techniques.json']

## Methodology + caveats

- Counts are derived from regex / glob over the source trees, not from runtime
  inspection. They favor explicitly-registered surfaces over dynamic ones.
- A higher number does not by itself mean better coverage — see the
  qualitative architecture table for the most consequential axes.
- For a live, target-driven comparison, run `bash benches/vs-bob/harness.sh`
  against an authorized, self-hosted target (Juice Shop / DVWA / VAmPI / crAPI).

## Verdict

On the **static surface-inventory** axes counted above, **Mantis** is ahead
(8–0). On every **architectural / cryptographic** axis,
Mantis is ahead by construction (signed scope, merkle event log, FSM gate
library, plan-hash cascade gate, tiered LLM-codegen escalation, hibernation).

Hacker-bob retains advantages in two areas Mantis has not yet ported:
(a) ~5×-wider MCP tool surface for smart-contract families (EVM, SVM, Aptos,
Sui, Substrate, CosmWasm), (b) `bounty_auto_signup` browser automation.
These gaps are tracked in `CONTRAST.md` and `reports/BENCHMARK_VS_BOB.md`.
