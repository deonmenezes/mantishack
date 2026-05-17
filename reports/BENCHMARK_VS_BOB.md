# Mantis vs Hacker-Bob — Benchmark Analysis

This document frames the benchmark methodology, maps the expected outcome landscape, and
catalogs the honest gap analysis so future iterations close the right gaps in the right order.

The benchmark itself is defined under `benches/vs-bob/`. Run with:

```sh
bash benches/vs-bob/harness.sh <target-id>
```

after starting the daemon.

---

## Methodology

### Principle

Both systems are run against the same four locally-hosted, intentionally-vulnerable
Docker applications under identical operator-controlled conditions. Neither system is
given a head-start (no pre-seeded finding cache, no warmed session state). Results are
exported to JSONL/JSON and scored by the same Python script (`benches/vs-bob/score.py`)
using five axes computed from the raw event log.

### Target applications

| ID | Application | Primary vulnerability surface |
|---|---|---|
| `juiceshop` | OWASP Juice Shop | OWASP Top 10 (SQLi, XSS, broken auth, IDOR, insecure deserialization, XXE) |
| `dvwa` | DVWA | SQLi, XSS, CSRF, command injection, file inclusion, insecure upload |
| `vampi` | VAmPI | OWASP API Security Top 10 (BOLA, broken auth, excessive exposure, mass assignment) |
| `crapi` | OWASP crAPI | API-specific: BOLA, broken function-level auth, SSRF, JWT weakness |

All four are run as localhost Docker containers. No public services are contacted.
Each target is destroyed after its run so there is no state leakage across runs.

### Scoring axes

Each system is scored on five axes. The scorer normalizes coverage, unique_classes,
and severity_sum within the pair (peer-relative, not absolute) so neither system is
penalized for a target having inherently few findings.

| Axis | Weighting | What it measures |
|---|---|---|
| Coverage | 20 % | Distinct surfaces probed |
| Find rate | 25 % | Confirmed findings / total probes |
| Unique classes | 20 % | Breadth across vulnerability categories |
| Severity score | 25 % | Depth — CVSS-approximate weight sum |
| FP estimate | 10 % | Signal quality — 1 − (rejected / raised) |

A confirmed finding is: a Mantis event whose `kind` contains `Confirmed` or
`TieredFinding`, or whose `vuln_class` field is non-null; or a hacker-bob finding
appearing under the `findings`/`confirmed_findings` key.

---

## What We Expected

Before running the benchmark, the architecture-level prediction is:

1. **Mantis will probe more surfaces per engagement.** The daemon-owned event store
   persists state across wave restarts; the orchestrator fans out to at least three
   hunters regardless of initial surface count. Hacker-bob runs a single MCP server
   process — if it is restarted mid-engagement the surface queue is reset.

2. **Find rates will be comparable on short (5-minute) runs.** Both systems use
   the same agent prompts, the same capability playbooks, and the same heuristics.
   Per-finding quality depends on the LLM calls, not the runtime substrate.

3. **Mantis will produce fewer false positives.** The 3-round verification cascade
   (`brutalist → balanced → final`) is identical in both systems, but Mantis enforces
   the `adjudication_plan_hash` binding in Rust and gates `VERIFY → GRADE` on it.
   Hacker-bob enforces the equivalent in JavaScript inside a prompt body; a hallucinating
   LLM can drift through.

4. **Hacker-bob will win on unique_classes on the current codebase** due to its
   larger MCP tool surface (~106 tools vs Mantis's ~19). The gap closes as Mantis
   ports the remaining tools.

5. **Severity scores will track find count** and therefore be proportional to the
   coverage and find-rate gap.

---

## Mantis Advantages Observed (Architecture-Level)

These advantages are structural — they hold regardless of how any individual
benchmark run turns out.

### 1. Daemon-owned state survives restarts

Mantis engagement state lives in the daemon (backed by the BLAKE3 merkle event store).
Killing the CLI, hibernating the laptop, or rotating to a cloud worker does not
lose the surface queue, wave history, or finding set. Hacker-bob's MCP server dies
with the host Node.js process; state lives under `~/bounty-agent-sessions/[domain]/`
and must be re-read on the next invocation. Long-running engagements on real targets
benefit disproportionately from daemon hibernation.

### 2. Cryptographic scope enforcement at the proxy layer

`crates/mantis-egress` is a localhost CONNECT proxy. Every outbound TCP connection
from any Mantis component is evaluated against the engagement's signed `ScopeManifest`
before forwarding. A misbehaving tool, a hallucinating LLM, or a crafted redirect
cannot send traffic outside scope — the proxy refuses and logs a
`ScopeDecisionLogged{in_scope: false}` event. Hacker-bob enforces scope per-tool in
JavaScript; nothing stops a tool from making a raw `fetch()` call that bypasses
the check.

### 3. BLAKE3 merkle audit trail

Every Mantis event is a BLAKE3 leaf in a per-engagement merkle tree signed by the
workspace Ed25519 key. A third-party auditor — a bug-bounty platform, a legal team,
a compliance reviewer — can verify the report's claimed findings against the merkle
root with `mantis-verify --proof <bundle> --public-key <hex>` without trusting the
operator. Hacker-bob writes `pipeline-events.jsonl` in plain JSON; any post-hoc
tampering is undetectable.

### 4. `adjudication_plan_hash` cascade gate in Rust

The 3-round verification cascade is shared verbatim, but Mantis's version is
gate-tested: `SessionState::gate_verify_to_grade()` refuses to open the
`VERIFY → GRADE` transition unless `final.references_plan_hash == current.adjudication.plan_hash`.
Wrong hash, missing hash, missing adjudication, any drift in earlier rounds → hard
`BlockerCode::VerificationIncomplete`. Every step lands in the merkle log. Hacker-bob's
equivalent is a JavaScript function and a prompt instruction; both are bypassable by
LLM drift.

### 5. Tokio-backed parallel hunter fan-out

The orchestrator always fans out to at least three hunters in parallel regardless of
how many surfaces the recon pass found. The Tokio async daemon handles concurrent
event-store writes with `O_APPEND` semantics. Hacker-bob runs on a single-process
Node.js event loop; parallel hunters share one process and compete on the JS microtask
queue.

### 6. 12 extra HTTP primitives with no direct hacker-bob equivalents

Mantis ships `crates/mantis-scanner-http` with endpoint enumeration, probe scheduling,
and auth-profile injection that have no 1:1 counterpart in hacker-bob's tool catalog.
The `crates/mantis-auth-differential` crate implements auth differential scanning
as a Rust primitive. Where hacker-bob's equivalent lives in an LLM prompt,
Mantis runs deterministic code — the result is reproducible.

---

## Hacker-Bob Features We Are Missing and the Plan to Close Them

Honest accounting from the "What hacker-bob has that Mantis still lacks" table in
[`CONTRAST.md`](../CONTRAST.md):

| Capability | Current Status | Closure Plan |
|---|---|---|
| **106 MCP tools** (~87 missing) | Mantis exposes ~19. Agent prompts reference canonical `mantis_*` tool names; the Rust side only implements the most-used subset. Missing tools surface as "tool not found" errors at runtime. | Port tools in decreasing frequency-of-use order. Each port is a `crates/mantis-mcp` handler addition. Gap list: grep prompts for `mantis_` references absent from `crates/mantis-mcp/src/server.rs`. |
| **Browser automation** (`auto_signup` / Patchright + CAPTCHA solver) | Not ported. Mantis-auth captures manually-pasted profiles only. | Add a `mantis_browser_action` MCP tool backed by a headless Chromium process spawned by the daemon. CAPTCHA solver integration is a separate work item. |
| **`bounty_run_auth_differential`** (auth-bypass detector) | Not ported. Highest-impact single missing tool. The `crates/mantis-auth-differential` crate provides the Rust primitive; the MCP binding is not yet wired. | Wire `crates/mantis-auth-differential` into an MCP tool (`mantis_run_auth_differential`) and update the hunter and chain-builder prompts to call it. Estimate: 1 sprint. |
| **Smart-contract families** (EVM / SVM / Aptos / Sui / Substrate / CosmWasm) | Out of scope for Mantis v1 (web-only). Agent prompts ship to allow future plug-in without prompt rewrites. | Separate capability pack per chain family. Each pack adds a `crates/mantis-scanner-<chain>` crate and corresponding MCP tools. Not targeted for v1. |
| **Capability eval harness** | Not ported. Hacker-bob's `bounty_evaluate_capabilities` is a regression harness for capability packs. | Port as `mantis_evaluate_capabilities` with results stored in the merkle log. Target: v2. |
| **`bounty_chain_frontier` / `bounty_query_chain_tree`** (content-addressed chain state tree) | Partial. `mantis_record_chain_attempt` exists; the content-addressed lineage tree that deduplicates equivalent chains does not. | Implement `ChainTree` in `crates/mantis-fsm` backed by the event store. `mantis_chain_frontier` and `mantis_query_chain_tree` MCP tools follow. |

---

## Where Mantis Will Beat Bob Even at Parity

These advantages compound as tool coverage closes the gap.

**Longer engagements via daemon hibernation.** A 24-hour engagement on a real target
involves operator sleep cycles, network interruptions, and process restarts. Mantis
snapshots state via `crates/mantis-hibernation` and resumes without loss. Hacker-bob
requires the operator to keep a Node.js process alive or accept a cold restart.

**Cryptographic scope enforcement.** At tool parity Mantis is still safer to run
against real targets because the egress proxy is the last line of defense — it does
not depend on LLM compliance. This matters on targets with open-redirect chains or
SSRF vectors where the tool itself may be tricked into out-of-scope requests.

**BLAKE3 merkle audit for bug-bounty submission.** Platforms increasingly require
reproducible evidence packages. Mantis's merkle-signed event log lets a platform
verify a submitted finding chain without trusting the researcher's word. Hacker-bob
produces plain JSONL that an adversarial researcher could trivially forge.

**12 extra HTTP primitives that run deterministic code.** The `crates/mantis-scanner-http`
probe scheduler, the `crates/mantis-auth-differential` auth-bypass detector, and the
`crates/mantis-pack` tiered executor have no LLM in their hot path. Findings generated
by these primitives are reproducible across runs, which is a hard requirement for
responsible disclosure.

**Multi-tenant isolation.** `mantis-tenant` namespaces let one daemon serve multiple
concurrent engagements with key-isolated egress profiles. Hacker-bob is single-tenant
by design (one project per MCP server). A consulting firm running simultaneous
engagements for multiple clients cannot share a hacker-bob instance safely.

---

Run with `bash benches/vs-bob/harness.sh <target-id>` after starting the daemon.
