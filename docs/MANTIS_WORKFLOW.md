# Mantis Engagement Workflow

This document describes how to run a complete bug bounty engagement end-to-end using Mantis: from recon through hypothesis generation, MCTS-style wave hunting, chain building, multi-round verification, grading, and report generation.

---

## Overview

The Mantis pipeline is a strict finite state machine:

```
RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
                                                  ↓
                                            EXPLORE → CHAIN → VERIFY → GRADE → REPORT
```

Each phase is MCP-owned. The orchestrator coordinates agents and MCP state — it never hunts directly. All durable artifacts live under `./mantishack-<engagement-id>/` and are written only through MCP tools.

---

## Prerequisites

- Mantis MCP server running and registered (`mantis` entry in `.mcp.json`)
- Claude Code restarted in the engagement project directory
- Written authorization for the target (bug bounty program or pen-test agreement)
- Optional recon tools: `subfinder`, `httpx`, `nuclei`, `amass`, `katana`, `dnsx`, `tlsx`, `subzy`

---

## Starting an Engagement

```
/mantishack <target-url-or-domain>
```

Optional flags:
- `--deep` — broader passive recon plus durable surface-lead promotion
- `--no-auth` — skip signup flows, test unauthenticated only
- `--egress <profile>` — use a named operator-managed egress profile
- `--normal` (default) / `--paranoid` / `--yolo` — checkpoint verbosity modes

Resume a paused engagement:
```
/mantishack resume <domain>
```

Force-merge a pending wave that timed out:
```
/mantishack resume <domain> force-merge
```

---

## Phase-by-Phase Reference

### PHASE 1: RECON

The orchestrator calls `mantis_init_session` then spawns either the normal or deep recon agent depending on `--deep`.

**Normal recon** (`prompts/roles/recon.md`):
- 7 Bash-only steps: binary check, subdomain aggregation, live-host probing, family discovery, CDX/Wayback URL collection, safe nuclei pass, JS endpoint extraction.
- Delivers `attack_surface.json` with ranked surfaces.

**Deep recon** (`prompts/roles/deep-recon.md`):
- Same 7 steps but with broader tooling: `amass`, `chaos`, `assetfinder`, `dnsx`, `tlsx`, `subzy`, expanded CDX window.
- Additionally delivers `deep-summary.json` and `surface-leads.json` for durable lead promotion in later waves.

After recon completes the **surface router** (`prompts/roles/surface-router.md`) calls `mantis_route_surfaces` to assign each surface a `capability_pack`, `hunter_agent`, and `brief_profile` triple. This write is MCP-owned; the router does no direct file writes.

### PHASE 2: AUTH

The orchestrator runs a four-tier signup flow using temp-email automation:

1. API-based signup via `mantis_http_scan`
2. Browser-based signup via `mantis_auto_signup` (requires `patchright`)
3. Assisted manual: operator registers with temp credentials
4. Manual token capture via DevTools Console snippet

After signup the orchestrator creates `attacker` and `victim` auth profiles via `mantis_auth_store`, then transitions to HUNT.

Skip AUTH entirely with `--no-auth`.

### PHASE 3: HUNT

The orchestrator calls `mantis_start_next_wave` on each iteration. The MCP assigns surfaces, returns `assignment[]` records, and the orchestrator spawns one hunter per assignment in background workers.

**Generic web hunter** (`prompts/roles/hunter.md`):
- Reads its brief via `mantis_read_hunter_brief` (surface, techniques, traffic, auth profiles, bypass table, coverage).
- Tests crown jewels first: auth, admin, user data, money, uploads, key material.
- Uses two auth profiles for IDOR tests (attacker vs victim).
- Logs coverage via `mantis_log_coverage`, dead ends via `mantis_log_dead_ends`.
- Records proven findings via `mantis_record_finding`.
- Writes final handoff via `mantis_write_wave_handoff`, then calls `mantis_finalize_hunter_run`.
- Finishes with exactly one marker: `MANTIS_HUNTER_DONE {...}`.

**Smart-contract hunters**:
- `prompts/roles/hunter-evm.md` — EVM (Foundry fork PoCs, `bounty_foundry_run`, `bounty_halmos_run`)
- `prompts/roles/hunter-svm.md` — Solana/SVM (Anchor test harness)
- `prompts/roles/hunter-move.md` — Aptos + Sui Move (Move test harness)
- `prompts/roles/hunter-substrate.md` — Substrate / ink! (cargo test)
- `prompts/roles/hunter-cosmwasm.md` — CosmWasm (cw-multi-test harness)

Each SC hunter: fetches verified source, builds a live trust map, exercises bypass conditions from `bob-spec.yaml` trust assumptions, scaffolds a test, runs it via the appropriate MCP harness tool, records `bypass_attempts[]` entries, and writes the handoff.

After all hunters complete in a wave the orchestrator calls `mantis_apply_wave_merge` to reconcile findings. It then decides: start another wave, or transition to CHAIN.

**Capability playbooks** can be invoked by the orchestrator during HUNT for specific differential procedures:
- `prompts/playbooks/C2_doc_vs_behavior.md` — OpenAPI/GraphQL doc-vs-behavior differential
- `prompts/playbooks/C4_multi_account_differential.md` — Multi-account auth differential fan-out

**Turn budget**: hunters must write their handoff by ~170 turns; hard kill at 200.

### PHASE 4: CHAIN

The orchestrator spawns the chain builder (`prompts/roles/chain.md`).

The chain builder:
- Reads findings via `mantis_read_findings` and wave handoff `chain_notes` via `mantis_read_wave_handoffs`.
- Applies severity ladder rules (LOW+LOW ≤ LOW; no jump-the-rung escalations).
- Tests credible composition pivots across web and all SC families.
- Records every tested pivot (confirmed, denied, blocked, not_applicable) via `mantis_write_chain_attempt`.
- Writes `chains.md` under the session directory for human review.
- Finishes with `MANTIS_CHAIN_DONE`.

The `CHAIN → VERIFY` transition is gated: at least one terminal chain attempt must exist.

### PHASE 5: VERIFY

Three-round verification pipeline. The verification schema version (v1 or v2) drives which flow runs.

**Brutalist verifier** (`prompts/roles/brutalist-verifier.md`):
- Aggressively challenges every finding.
- Re-runs each PoC via the pack's replay tool (web: `mantis_http_scan`; SC: the appropriate chain runner).
- Optionally calls `mcp__brutalist__roast` for adversarial critique.
- Writes `round="brutalist"` via `mantis_write_verification_round`.
- Finishes with `MANTIS_VERIFY_DONE`.

**Balanced verifier** (`prompts/roles/balanced-verifier.md`):
- Catches false negatives and over-corrections from brutalist.
- In v1: re-tests denied/downgraded + passes others through.
- In v2: independent round covering the same snapshot findings.
- Can reinstate findings brutalist denied due to tooling failure.
- Writes `round="balanced"`.

**Final verifier** (`prompts/roles/final-verifier.md`):
- Re-runs every reportable finding from scratch.
- In v2: consumes adjudication plan hash from `mantis_build_verification_adjudication`.
- Writes `round="final"` with `adjudication_plan_hash`.

After final verification the **evidence agent** (`prompts/roles/evidence.md`) collects bounded, redacted evidence packs for each reportable finding via `mantis_write_evidence_packs`. Finishes with `MANTIS_EVIDENCE_DONE`.

### PHASE 6: GRADE

The grader (`prompts/roles/grader.md`) scores findings on 5 axes:
- Impact (0–30), Proof quality (0–25), Severity accuracy (0–15), Chain potential (0–15), Report quality (0–15).

Verdicts:
- `SUBMIT` — total ≥ 40 AND ≥ 1 MEDIUM or higher finding.
- `HOLD` — total 20–39. Orchestrator re-runs targeted HUNT wave then loops CHAIN → VERIFY → GRADE.
- `SKIP` — total < 20 or no reportable findings.

Writes grade via `mantis_write_grade_verdict`. Finishes with `MANTIS_GRADE_DONE`.

### PHASE 7: REPORT

The reporter (`prompts/roles/reporter.md`) writes the canonical report:

- Path: `./mantishack-<engagement-id>/report.md`
- Only findings with `reportable: true` in the final verification round are rendered.
- Executive summary (severity counts, top-line findings list).
- Validated chains section (when chains.md is non-empty and non-trivial).
- Per-finding sections branched by `surface_type`: web findings first, then SC grouped by chain family (evm, svm, aptos, sui, substrate, cosmwasm).
- Calls `mantis_report_written` to emit the `report_written` pipeline event.
- Finishes with `MANTIS_REPORT_DONE`.

---

## Monitoring and Debugging

### Status

```
/mantis-status
/mantis-status <domain>
```

Reads pipeline analytics, session summary, state, wave status, and verification context. Shows phase, findings count, wave health, evidence status, grade verdict, and report presence.

### Debug

```
/mantis-debug <domain>
/mantis-debug --deep <domain>
/mantis-debug --diff-attempts <prev-id> <curr-id>
```

Read-only telemetry-driven session analysis. Detects drift, artifact integrity issues, missing handoffs, and verification/grade/report anomalies.

### Key MCP tools for operator visibility

| Tool | Purpose |
|------|---------|
| `mantis_read_pipeline_analytics` | Cross-session pipeline health dashboard |
| `mantis_read_session_summary` | Compact session overview |
| `mantis_read_state_summary` | Current FSM state and pending wave |
| `mantis_wave_status` | Wave completion and pending merges |
| `mantis_read_verification_context` | v1/v2 verification schema, attempt IDs, adjudication |
| `mantis_read_findings` | All recorded findings |
| `mantis_read_chain_attempts` | All chain-builder outcomes |
| `mantis_read_grade_verdict` | Grade verdict |

---

## Example: Full Engagement Walkthrough

**Target**: `app.example-bounty.com` (authorized web application with a React frontend and a REST API).

### Step 1 — Start

```
/mantishack https://app.example-bounty.com --deep
```

The orchestrator calls `mantis_init_session`, spawns the deep recon agent. Recon runs 7 Bash steps: subdomain aggregation (`subfinder`, `amass`), live probing (`httpx`), family discovery, CDX/Wayback URL collection (`katana`), nuclei pass, JS endpoint extraction. After recon, the surface router calls `mantis_route_surfaces`.

Recon surfaces: `surface-api-v2`, `surface-auth`, `surface-admin-panel`.

### Step 2 — AUTH

Orchestrator detects a `/api/auth/register` endpoint. Calls `mantis_signup_detect` + `mantis_temp_email`. Attempts Tier 1 API signup — succeeds. Polls for verification email, completes via `mantis_http_scan`. Creates `attacker` profile. Repeats for `victim` profile. Transitions to HUNT.

### Step 3 — HUNT Wave 1

Orchestrator calls `mantis_start_next_wave`. MCP assigns three surfaces:
- `a1` → `surface-api-v2` (web pack, generic hunter)
- `a2` → `surface-auth` (web pack, generic hunter)
- `a3` → `surface-admin-panel` (web pack, generic hunter)

Hunters launch in background. Each reads its brief, tests crown jewels.

`a1` finds: `/api/v2/users/{id}` returns victim PII with attacker token → IDOR. Records finding `F-1` (HIGH).

`a2` finds: password reset token in HTTP response body → information leak. Records `F-2` (MEDIUM).

`a3`: admin panel returns 403 for attacker and victim. Writes partial handoff, marks WAF-blocked paths.

All hunters write handoffs, call `mantis_finalize_hunter_run`, emit `MANTIS_HUNTER_DONE`. Orchestrator calls `mantis_apply_wave_merge`. Two findings recorded.

### Step 4 — HUNT Wave 2

MCP assigns remaining surface leads from deep recon. One new hunter confirms a stored XSS via the export endpoint → `F-3` (HIGH). Transitions to CHAIN.

### Step 5 — CHAIN

Chain builder reads findings. Tests `F-1 + F-2` (IDOR + reset token leak → ATO chain). Severity ladder: HIGH + MEDIUM = at most HIGH. Records `confirmed` chain attempt. Tests `F-3 + F-1` — no credible link. Records `denied` attempt. Writes `chains.md`, emits `MANTIS_CHAIN_DONE`.

### Step 6 — VERIFY

v2 schema. Orchestrator calls `mantis_read_verification_context`, launches brutalist and balanced verifiers independently.

**Brutalist**: replays `F-1` via `mantis_http_scan` — attacker token still returns victim data. Confirms HIGH. Replays `F-2` — token in response body confirmed MEDIUM. Replays `F-3` — XSS still executes. Confirms HIGH. Writes `brutalist` round.

**Balanced**: independent replay of all three. Agrees. Writes `balanced` round.

Orchestrator calls `mantis_build_verification_adjudication`. Launches final verifier with `adjudication_plan_hash`. Final verifier re-runs all three PoCs, confirms all three reportable. Writes `final` round.

Evidence agent collects one bounded pack per finding. Calls `mantis_write_evidence_packs`. Writes `MANTIS_EVIDENCE_DONE`.

### Step 7 — GRADE

Grader scores:
- `F-1` (IDOR): impact 28, proof 23, severity 14, chain 12 (ATO chain confirmed), report 13 = 90
- `F-2` (info leak): impact 15, proof 20, severity 12, chain 8, report 12 = 67
- `F-3` (stored XSS): impact 26, proof 22, severity 14, chain 5, report 13 = 80

Total: SUBMIT. Calls `mantis_write_grade_verdict`. Emits `MANTIS_GRADE_DONE`.

### Step 8 — REPORT

Reporter writes `./mantishack-<engagement-id>/report.md`:

1. Executive summary: 2 HIGH, 1 MEDIUM. Top-line list: F-1 IDOR, F-3 Stored XSS, F-2 Info Leak.
2. Chains: `F-2 (reset token leak) → F-1 (IDOR) → ATO chain — HIGH`.
3. Per-finding sections with PoC, evidence, impact, remediation.

Calls `mantis_report_written`. Emits `MANTIS_REPORT_DONE`.

---

## Technique and Bypass References

Hunters receive bounded technique summaries through `mantis_read_hunter_brief`. Full technique bodies are fetched on demand via `mantis_read_technique_pack`. The knowledge base lives at `.mantis/knowledge/hunter-techniques.json` and covers:

- REST/API authorization and parser differentials
- GraphQL field-level authorization
- WordPress-specific attack classes
- JWT/OAuth flows
- Upload/SSRF/IDOR/XSS patterns
- Smart-contract bug classes (EVM, SVM, Move, Substrate, CosmWasm)

Bypass tables (compact attacker cheatsheets) live at `.mantis/bypass-tables/`:
- `jwt.txt` — alg:none, HS256/RS256 confusion, kid injection, jku/x5u
- `graphql.txt` — introspection variants, batched queries, alias enum
- `oauth-oidc.txt` — redirect_uri manipulation, state CSRF, PKCE bypass
- `rest-api.txt` — version rollback, method override, mass assignment
- `ssrf.txt` — IP encoding tricks, 169.254.169.254, gopher
- `firebase.txt` — misconfig paths
- `nextjs.txt` — /_next/data leak, Server Actions
- `wordpress.txt` — wp-json enumeration, xmlrpc

---

## Files Written by This Port

| Path | Source |
|------|--------|
| `prompts/roles/*.md` (19 files) | `hacker-bob/prompts/roles/` with renames |
| `prompts/playbooks/C2_doc_vs_behavior.md` | `hacker-bob/prompts/playbooks/` with renames |
| `prompts/playbooks/C4_multi_account_differential.md` | `hacker-bob/prompts/playbooks/` with renames |
| `.mantis/knowledge/hunter-techniques.json` | `hacker-bob/.hacker-bob/knowledge/` verbatim |
| `.mantis/bypass-tables/*.txt` (8 files) | `hacker-bob/.hacker-bob/bypass-tables/` verbatim |
| `docs/FIRST_RUN_BOB_STYLE.md` | `hacker-bob/docs/FIRST_RUN.md` with renames |
| `docs/TROUBLESHOOTING_BOB_STYLE.md` | `hacker-bob/docs/TROUBLESHOOTING.md` with renames |
| `docs/capability-hypergraph.md` | `hacker-bob/docs/capability-hypergraph.md` with renames |
| `docs/context-scaling-architecture.md` | `hacker-bob/docs/context-scaling-architecture.md` with renames |
| `docs/ROADMAP_BOB_STYLE.md` | `hacker-bob/docs/ROADMAP.md` with renames |
| `DISCLAIMER_BOB_STYLE.md` | `hacker-bob/DISCLAIMER.md` with renames |
| `SECURITY_BOB_STYLE.md` | `hacker-bob/SECURITY.md` with renames |
| `docs/MANTIS_WORKFLOW.md` | This document |
