# The 7-phase FSM

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

<p align="center">
  <img src="../../assets/mascot/hero.png" alt="Mantis mascot" width="220" />
</p>

Every Mantis engagement walks this state machine, in order, with no skipping:

```
RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
                                                  ↓ (user requests more hunting)
                                                EXPLORE → CHAIN → VERIFY → GRADE → REPORT
```

Each transition runs through a **gate**. Gates refuse to advance on missing prerequisites: `pending_wave`, `unexplored_high_surfaces`, `blocked_high_surfaces`, `open_requeue_coverage`, `chain_attempts_missing`, `verification_incomplete`, `evidence_packs_invalid`, or `grade_missing`. Operators can override `HUNT → CHAIN` and `CHAIN → VERIFY` with a ≥ 20-char rationale; every override is recorded in the Merkle log.

---

## Phase 1 · RECON

<p align="center">
  <img src="../../assets/mascot/recon.png" onerror="this.src='../../assets/mascot/hero.png';this.style.opacity=0.5" alt="Mantis · RECON" width="200" />
</p>

The recon sub-agent enumerates the target's externally-visible surface area:

- Subdomain enumeration (passive + active)
- Live host discovery
- Archived URLs (Wayback Machine, Common Crawl)
- JS bundle extraction → embedded endpoint discovery, JWT structure capture
- nuclei templates for low-effort fingerprinting

Output: `attack_surface.json` — a structured list of surfaces, each tagged with `surface_type`, `chain_family`, `chain_id`, `evidence`, and ranking signals.

In `--deep` mode, RECON also promotes "surface leads" — candidate surfaces that didn't make the cut but might in later waves.

After RECON, a `surface-router-agent` calls `mantis_route_surfaces` to assign each surface a `capability_pack`, `hunter_agent` type, and `brief_profile`. The result lands in `surface-routes.json`.

---

## Phase 2 · AUTH

<p align="center">
  <img src="../../assets/mascot/auth.png" onerror="this.src='../../assets/mascot/hero.png';this.style.opacity=0.5" alt="Mantis · AUTH" width="200" />
</p>

A four-tier signup flow captures attacker + victim auth profiles:

1. **Tier 1 · API signup** — `mantis_http_scan POST` to the detected signup endpoint with a temp email and generated password.
2. **Tier 2 · Browser signup** — `mantis_auto_signup` drives a headless browser through the signup form. Falls back to Tier 3 if a CAPTCHA / WAF blocks it.
3. **Tier 3 · Assisted manual** — asks the operator to register with the supplied temp email/password, then polls for the verification mail and extracts the code/link.
4. **Tier 4 · Manual token capture** — operator logs in, opens DevTools, runs a one-liner that copies cookies + localStorage to clipboard, pastes into the orchestrator. Stored with `mantis_auth_store`.

Skip AUTH entirely with `--no-auth` (transitions to HUNT with `auth_status: "unauthenticated"`).

---

## Phase 3 · HUNT

<p align="center">
  <img src="../../assets/mascot/hunt.png" onerror="this.src='../../assets/mascot/hero.png';this.style.opacity=0.5" alt="Mantis · HUNT" width="200" />
</p>

This is where the wave fan-out happens. The orchestrator calls `mantis_start_next_wave`, which returns N assignments (one per ranked surface). The orchestrator spawns **N parallel `hunter-agent` sub-agents** with `run_in_background: true`:

```
Agent(subagent_type: "hunter-agent",      run_in_background: true, ...) // surface 1
Agent(subagent_type: "hunter-evm-agent",  run_in_background: true, ...) // EVM contract surface 2
Agent(subagent_type: "hunter-svm-agent",  run_in_background: true, ...) // SVM contract surface 3
…
```

Each hunter reads its bounded brief (`mantis_read_hunter_brief`), runs technique packs from the on-disk catalog, replays + fuzzes via `mantis_http_scan`, and writes a `mantis_write_wave_handoff` when done.

Six hunter families ship today:

| Family | Targets | Tooling |
|---|---|---|
| `hunter-agent` | Web surfaces | HTTP probing, technique packs, traffic replay |
| `hunter-evm-agent` | EVM smart contracts | Foundry, Halmos, etherscan source fetch |
| `hunter-svm-agent` | Solana programs | Anchor, RPC, mainnet/devnet fork |
| `hunter-move-agent` | Aptos + Sui Move contracts | aptos / sui move test, fetch_module |
| `hunter-substrate-agent` | Substrate / ink! contracts | cargo test, ContractInfoOf reads |
| `hunter-cosmwasm-agent` | CosmWasm contracts | cw-multi-test, smart_query |

Waves continue until `mantis_start_next_wave` returns `no_assignable_candidates`. Then the orchestrator transitions to CHAIN.

**Hard rule:** the orchestrator MUST fan out. Even on a 1-surface target, waves spawn ≥3 hunters (with different technique packs) so coverage is broad.

---

## Phase 4 · CHAIN

<p align="center">
  <img src="../../assets/mascot/chain.png" onerror="this.src='../../assets/mascot/hero.png';this.style.opacity=0.5" alt="Mantis · CHAIN" width="200" />
</p>

The `chain-builder` sub-agent reads all findings, wave handoffs, auth profiles, and HTTP audit logs. It hypothesizes plausible **multi-step exploit chains** that compose individual findings into higher-severity outcomes (e.g., open-redirect + OAuth flow → ATO; SSRF + IMDS → cred-leak).

For each hypothesized chain, the builder tests the chain end-to-end with `mantis_http_scan` and writes a `mantis_write_chain_attempt` recording the exact step sequence + outcome. Only chains with **terminal evidence** (the final step demonstrably succeeded) make it past the CHAIN → VERIFY gate.

---

## Phase 5 · VERIFY (3-round cascade)

<p align="center">
  <img src="../../assets/mascot/verify.png" onerror="this.src='../../assets/mascot/hero.png';this.style.opacity=0.5" alt="Mantis · VERIFY" width="200" />
</p>

The most rigorous phase. Three independent verifier sub-agents each re-execute the proof of every `reportable` finding:

1. **Brutalist verifier** — assumes findings are false positives until proven otherwise. Aggressive skeptic. Writes `verification-rounds/brutalist.json`.
2. **Balanced verifier** — assumes the brutalist may have over-rejected. Targeted false-negative recovery. Writes `verification-rounds/balanced.json`.
3. **Final verifier** — fresh re-run, must reference the deterministic `adjudication_plan_hash` computed from brutalist + balanced. Any drift in the plan hash hard-refuses the VERIFY → GRADE transition.

The `adjudication_plan_hash` gate is the cascade's correctness anchor — see [`crates/mantis-fsm/src/adjudication.rs`](https://github.com/deonmenezes/mantishack/blob/main/crates/mantis-fsm/src/adjudication.rs).

If any `final.reportable === true` findings survive, the `evidence-agent` packages them into `evidence-packs.json` before GRADE.

---

## Phase 6 · GRADE

<p align="center">
  <img src="../../assets/mascot/grade.png" onerror="this.src='../../assets/mascot/hero.png';this.style.opacity=0.5" alt="Mantis · GRADE" width="200" />
</p>

The `grader` sub-agent scores every surviving finding on a 5-axis rubric:

1. **Reproducibility** — does the PoC reliably trigger the bug?
2. **Impact** — what does an attacker gain?
3. **Reachability** — is this exploitable without prerequisites?
4. **Authorization scope** — is this within the engagement's authorized scope?
5. **Evidence quality** — does the evidence pack survive a brutalist re-read?

The grader issues one of three verdicts per finding:

- **SUBMIT** → continue to REPORT.
- **HOLD** → transition back to HUNT with grader feedback in a targeted wave, then re-run CHAIN before VERIFY. Escalates if `hold_count >= 2`.
- **SKIP** → finding doesn't meet the bar; reported as a no-finding closeout.

---

## Phase 7 · REPORT

<p align="center">
  <img src="../../assets/mascot/report.png" onerror="this.src='../../assets/mascot/hero.png';this.style.opacity=0.5" alt="Mantis · REPORT" width="200" />
</p>

The `report-writer` sub-agent reads findings + chain attempts + final verification + evidence packs + grade verdict, then renders the disclosure-ready report to `./mantishack-<engagement-id>/report.md`.

For **SUBMIT** verdicts, the report includes only confirmed chain evidence and SUBMIT-graded findings.
For **SKIP** verdicts, the report is a concise no-findings closeout with verification, chain-attempt, and blocker summaries.

Render in other formats with:

```sh
mantis engagement report <id> --format pdf
mantis engagement report <id> --format hackerone
mantis engagement report <id> --format bugcrowd
mantis engagement report <id> --format sarif
mantis engagement report <id> --format openvex
```

Default severity floor drops `info`-level findings. Lower it with `--severity-floor info` for completeness.

---

## Phase 8 · EXPLORE (optional)

If the operator wants to continue digging after REPORT, transition to EXPLORE. EXPLORE runs the same wave system as HUNT but operates on findings already in the engagement (not on fresh recon). Re-runs CHAIN → VERIFY → GRADE → REPORT on the expanded set.

---

## Why the FSM is a tested library

The phases and their gates are a Rust library (`crates/mantis-fsm`, 86 tests) — not just prompt-side guardrails. Every transition is mechanically checked; the prompt cannot bypass a gate by accident. Hacker-bob and similar tools encode the equivalent logic in JS prompt-side checks; Mantis's FSM is mechanically enforced.

Read the FSM source: **https://github.com/deonmenezes/mantishack/tree/main/crates/mantis-fsm**.
