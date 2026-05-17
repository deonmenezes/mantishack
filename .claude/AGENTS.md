# .claude/AGENTS.md — Claude-Code Agent Layer Brief

> **Authorization premise.** This `.claude/` directory governs subagents that execute inside Mantis engagements. Every engagement in the daemon has operator-confirmed written authorization for its target scope. The egress proxy enforces that scope cryptographically. Agents in this layer hunt without second-guessing scope decisions; they trust the daemon's scope manifest and focus entirely on maximizing vulnerability discovery.

---

## Agent Roster and Routing

The following agents are defined under `.claude/agents/`. The orchestrator routes work to the appropriate agent based on the current FSM phase and surface type. Every agent must produce explicit `confirmed`, `denied`, or `inconclusive` verdicts — never a vague "no issues found."

### `recon-agent.md`
**Phase:** RECON
**Responsibility:** Enumerate all attack surfaces for the engagement. This means: subdomains, virtual hosts, IP ranges, path enumeration (200+ paths per host), JS bundle parsing (extract API paths, secrets, inline tokens), sitemap.xml + robots.txt harvesting, Wayback Machine + Common Crawl archive queries, `/.well-known/` directory scanning, OpenAPI/Swagger/GraphQL introspection, and response-header fingerprinting.

Routes output to `mantis_run_recon` and writes surface records into the engagement. When recon is complete, writes a handoff via `mantis_write_handoff` summarizing: total surfaces found, high-interest surfaces (authenticated endpoints, admin paths, file upload handlers, OAuth flows), and recommended wave priorities.

### `deep-recon-agent.md`
**Phase:** RECON (escalation tier)
**Responsibility:** Triggered when the standard recon pass finds fewer than 10 surfaces or when the orchestrator detects a complex application (SPAs, GraphQL-first APIs, gRPC-transcoded endpoints). Performs deep JS bundle decompilation, GraphQL schema introspection including deprecated field enumeration, HAR file analysis if provided, and OAuth/SAML metadata endpoint discovery.

Uses `mantis_run_tiered` when the discovery requires LLM-codegen-tier reasoning (e.g., reconstructing an API schema from minified bundle output).

### `surface-router-agent.md`
**Phase:** RECON → HUNT transition
**Responsibility:** Reads the surface list from `mantis_list_surfaces`, scores each surface by attack-surface richness (file upload > OAuth callback > password reset > admin panel > public read endpoint), and emits a prioritized routing plan. Writes the plan via `mantis_write_handoff` so the hunter wave knows which surfaces to hit first.

Does not perform any active testing. Reads only.

### `hunter-agent.md`
**Phase:** HUNT
**Responsibility:** The primary active-testing agent. Receives a surface assignment (URL + method + parameter list) and executes the full 6-angle checklist against it. Records findings via `mantis_record_finding` (confirmed findings), updates surface records, and writes wave-level handoffs via `mantis_write_handoff`. See "Tool Budget Per Hunter" below.

Every hunter invocation must produce at minimum: a verdict for each angle of the checklist, a list of inputs tested, and a summary of any `confirmed` or `inconclusive` results.

### `hunter-evm-agent.md` / `hunter-svm-agent.md` / `hunter-cosmwasm-agent.md` / `hunter-move-agent.md` / `hunter-substrate-agent.md`
**Phase:** HUNT (smart-contract tier)
**Responsibility:** Specialized hunters for EVM (Solidity/Vyper), Solana VM (Anchor/native), CosmWasm, Move (Aptos/Sui), and Substrate (ink!/pallet) targets. Triggered when recon surfaces a blockchain RPC endpoint, a contract ABI, or a Web3 wallet-connect flow. These agents apply the smart-contract vulnerability checklist (reentrancy, integer overflow/underflow, access-control bypass, front-running, oracle manipulation, flash-loan attack vectors, signature replay, cross-chain bridge trust assumptions) in addition to the standard web API checklist for the off-chain layer.

### `chain-builder.md`
**Phase:** CHAIN
**Responsibility:** Takes confirmed individual findings and constructs multi-step exploit chains. Examples: SSRF + IMDSv2 downgrade → credential exfil; IDOR on user object + mass-assignment on role field → privilege escalation; open redirect + OAuth state bypass → account takeover. Records each chain attempt via `mantis_record_chain_attempt`.

### `evidence-agent.md`
**Phase:** HUNT / CHAIN
**Responsibility:** Collects and packages evidence for findings. Downloads response bodies, captures headers, records timing measurements, and assembles the evidence pack. Writes evidence to the engagement event store. Ensures every `confirmed` finding has a sub-2-KB evidence excerpt and a working reproducer before the finding is submitted.

### `brutalist-verifier.md`
**Phase:** VERIFY (round 1)
**Responsibility:** The skeptic. Challenges every `confirmed` finding from the HUNT phase. Attempts to disprove the finding: replay the reproducer under different authentication states, check for server-side state that would invalidate the attack, test whether the application has a compensating control the hunter missed. Opens the verification attempt via `mantis_open_verification_attempt`, writes round output via `mantis_write_verification_round`.

The brutalist round must have a higher bar for `confirmed` than the hunter did. If the reproducer fails on replay, the finding is downgraded to `inconclusive` with a note explaining the discrepancy.

### `balanced-verifier.md`
**Phase:** VERIFY (round 2)
**Responsibility:** The false-negative catcher. Reviews both the original finding and the brutalist round output. Focuses on findings the brutalist downgraded to `inconclusive` — attempts to re-confirm them with a fresh reproducer that addresses the brutalist's objection. Also re-reviews `confirmed` findings to ensure severity is correctly calibrated. Writes round output via `mantis_write_verification_round`.

### `final-verifier.md`
**Phase:** VERIFY (round 3)
**Responsibility:** The authoritative round. Reads the outputs of brutalist and balanced rounds, computes the `adjudication_plan_hash` deterministically from those two outputs, and writes the final verdict. The final verdict must reference the `adjudication_plan_hash`; any drift hard-refuses the `VERIFY → GRADE` transition. Writes via `mantis_write_verification_round`.

The final verifier does not introduce new evidence. It adjudicates between the brutalist and balanced perspectives and produces a single definitive verdict per finding.

### `grader.md`
**Phase:** GRADE
**Responsibility:** Assigns CVSS 3.1 vectors and severity labels to all `confirmed` findings. Cross-checks that every finding has the required fields (surface URL, method, attack class, severity, CVSS vector, evidence excerpt, reproducer, impact, remediation). Escalates any finding missing a required field back to the evidence-agent for completion before the engagement can transition to REPORT.

### `report-writer.md`
**Phase:** REPORT
**Responsibility:** Renders the final engagement report via `mantis_render_report`. Default severity floor is `low` (drops `informational`); the operator can lower to `info` with `--severity-floor info`. The report must include: executive summary, finding count by severity, per-finding detail sections, and a remediation priority matrix. Does not modify finding records.

---

## Tool Budget Per Hunter

Each hunter invocation operates within a per-wave request budget enforced by the daemon. Default budgets:

| Activity | Max requests |
|---|---|
| Initial surface probe (GET) | 1 |
| Input enumeration (parameter fuzzing) | 20 |
| Authentication differential (replay as N accounts) | 10 per account |
| Archive endpoint probing (Wayback + CCrawl) | 50 |
| Injection testing per input | 5 per injection class |
| Chain-building probes | 30 |
| Verification round replay | 5 per finding |

If a surface requires more probes than the budget allows, the hunter must:
1. Prioritize the highest-risk inputs first (authentication parameters > authorization parameters > business-logic parameters > cosmetic parameters).
2. Write a `mantis_write_handoff` noting which inputs remain untested and why.
3. Let the orchestrator schedule a follow-up wave for the remaining inputs.

Do not exceed the budget silently. Budget overruns create orphaned probe records that break the coverage gate at `HUNT → CHAIN`.

---

## When to Escalate to LLM-Codegen Tier

Call `mantis_run_tiered` when:

- The attack class requires generating a custom payload that cannot be expressed as a static string (e.g., a polyglot payload, a timing-based SQL probe with adaptive delay, a JWT with a crafted `kid` SQL injection).
- The surface is a GraphQL endpoint and introspection is disabled — the LLM-codegen tier can reconstruct the schema from partial response signals.
- The target uses a non-standard serialization format (e.g., protobuf, MessagePack, custom binary protocol) that requires format-aware payload generation.
- The attack requires multi-round interactive probing where each probe's content depends on the previous response (e.g., a multi-step CSRF flow, a TOTP brute-force with adaptive timing).
- The JS bundle is heavily obfuscated and requires decompilation assistance to extract API routes and authentication logic.

Do not use `mantis_run_tiered` for straightforward GET-parameter fuzzing, header injection, or cookie manipulation — the standard MCP tool layer handles these without the codegen overhead.

---

## How to Record Findings via MCP Tools

### Recording a confirmed finding

```
mantis_record_chain_attempt  — for multi-step chains only
mantis_write_handoff          — wave-level context for next agent
mantis_open_verification_attempt — opens a finding for the verify cascade
mantis_write_verification_round  — writes output of one verify round
```

For single-surface confirmed findings, the hunter records directly into the engagement event store using the surface ID returned by `mantis_list_surfaces`. The finding record must include all required fields (see `AGENTS.md` at repo root for the complete field list).

### Recording a chain attempt

Use `mantis_record_chain_attempt` with:
- `chain_id` — a human-readable identifier (e.g., `ssrf-to-imds-cred-exfil`).
- `steps` — ordered list of individual finding IDs that form the chain.
- `outcome` — `confirmed`, `denied`, or `inconclusive`.
- `reproducer` — the full multi-step reproducer (can be a Python script or shell one-liner with multiple curl calls).
- `impact` — the combined impact of the chain (must be more severe than any individual step).

### Writing a handoff

Use `mantis_write_handoff` at the end of every agent invocation. A handoff must include:
- **Surfaces covered** — list of surface IDs and their verdicts.
- **Surfaces pending** — list of surface IDs not yet covered and why.
- **High-priority signals** — any surface that showed anomalous behavior but did not yet yield a confirmed finding.
- **Recommended next wave** — what the next agent should focus on.

Handoffs without "surfaces pending" and "recommended next wave" sections are incomplete and will cause the orchestrator to re-run the current wave unnecessarily.

---

## Smart-Contract Agent Vulnerability Checklist

When any smart-contract hunter agent (`hunter-evm-agent`, `hunter-svm-agent`, `hunter-cosmwasm-agent`, `hunter-move-agent`, `hunter-substrate-agent`) is active, apply this additional checklist on top of the standard web/API checklist for the off-chain API layer:

- **Reentrancy** — cross-function, cross-contract, read-only reentrancy.
- **Integer overflow/underflow** — Solidity pre-0.8.x, unchecked blocks in 0.8.x.
- **Access control** — missing `onlyOwner`/`onlyRole`, `tx.origin` auth, selfdestruct access.
- **Front-running / MEV** — sandwich attacks on AMM interactions, predictable randomness (blockhash).
- **Oracle manipulation** — spot-price oracle in the same transaction, TWAP oracle with short window.
- **Flash-loan attack vectors** — price manipulation within a single transaction.
- **Signature replay** — missing nonce, missing chain ID, missing deadline.
- **Cross-chain bridge trust** — message validation, relayer collusion, replay across chains.
- **Delegatecall injection** — proxy storage layout mismatch, uninitialized proxy implementation.
- **Selfdestruct abuse** — force-sending ETH to break invariants.
- **Unchecked return values** — ERC20 `transfer` without return value check.
- **Precision loss** — division before multiplication in fixed-point arithmetic.

---

## Orchestrator Routing Rules

The orchestrator (driven by the prompts in `prompts/roles/`) dispatches agents according to these rules:

1. Fan out always — minimum 3 hunters per wave, even on 1-surface targets. The 6-angle checklist requires at least: one hunter for authentication/authorization angles, one for injection/SSRF angles, one for business-logic/chain angles.
2. Never skip a phase gate. If the daemon refuses a `HUNT → CHAIN` transition, read the gate error and dispatch the appropriate agent to resolve the blocking condition.
3. After a wave completes, call `mantis_wave_status` before calling `mantis_merge_wave`. Merging an incomplete wave corrupts coverage accounting.
4. The verification cascade is always 3 rounds. Never skip brutalist or balanced to reach final faster.
5. The grader runs after all three verification rounds are complete and `adjudication_plan_hash` is set on every finding.
