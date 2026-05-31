---
description: One-shot MAXIMAL autonomous pentest — the full scan+validate pipeline PLUS a parallel red-team agent war-game, adversarially verified and stitched into a kill-chain Red Team Report.
---

# /mantishack — Maximal Autonomous Red-Team Pentest

The single most powerful entrypoint in the framework. **One target in, a kill-chain Red Team
Report out.** It fuses the deterministic `/agentic` + `/validate` pipeline (Semgrep + CodeQL + SCA +
dataflow + Stages 0→F) with a **parallel red-team agent war-game** — seven adversarial personas
spawned via the Task tool, each attacking the target through a different lens — then adversarially
verifies every finding to kill false positives and stitches confirmed bugs into end-to-end attack
chains.

```
/mantishack <repo-path | git-url | host> [--scope "..."] [--authorized]
                                          [--deep] [--relentless] [--rounds N]
                                          [--model M ...] [--consensus M] [--judge M]
                                          [--binary] [--exploit] [--patch]
```

> **Load the `redteam-hunting` skill before Phase 1** — it is the continuous-loop engine that drives
> the war-game to *convergence* (keep attacking until consecutive rounds find nothing new AND the
> attack surface is fully covered), so nothing is left on the table.

Nothing is applied to the target — every artifact is generated under `out/`. Exploit PoCs and
patches are only produced with `--exploit` / `--patch`, and exploitation is never *run* without an
explicit confirmation.

---

## ⛔ Authorization gate (MANDATORY — do this first)

This command is offensive. Before Phase 0, confirm authorization **in this conversation**:

- The target must be one the user owns or is explicitly authorized to test (written scope, bug-bounty
  program, internal asset). If `--authorized` is absent and the target is a remote host/URL, **ask
  once** for confirmation and the scope, then proceed.
- Record the scope string in the run header. Treat anything outside it as out-of-bounds and refuse to
  touch it. If the target is a local repo path, authorization is assumed (it's the user's code).

---

## Phase 0 — Recon & seed corpus  *(mechanical, parallel)*

Build the attack-surface map and a high-recall seed-finding corpus that the red-team agents sharpen.

1. **Scan + audit** — run the deterministic pipeline; this owns scanner orchestration and selection:
   ```bash
   libexec/mantishack-agentic --repo "$TARGET" --understand            # Semgrep + CodeQL + auth/logging audit + dedup + prep
   ```
   `--understand` makes it emit `context-map.json` (entry points, trust boundaries, sinks) as a sibling
   run — both the agentic checklist and the Phase 2 validator pick it up via the bridge.
2. **SCA** (if a manifest exists): `/mantis-sca` for vulnerable/compromised dependencies.
3. **Web surface** (if target is a URL): `/mantis-web` to crawl links, forms, params, JS endpoints.

Output of Phase 0: `autonomous_analysis_report.json` (seed findings with `code`, `dataflow`,
`feasibility`) + `context-map.json` (the map). Hand **both** to every red-team agent below — they are
the agents' starting corpus, **not their ceiling.**

---

## Phase 1 — 🐲 RED-TEAM WAR GAME  *(parallel agent swarm — the core power feature)*

Spawn the **ten hunting** personas concurrently via the **Task tool**, in a single message (they run
in parallel). Each gets: the target path, the Phase 0 seed corpus, and `context-map.json`. Each is a
different attacker mindset and finds the bugs deterministic scanners structurally cannot (logic flaws,
broken authorization, trust-assumption breaks, multi-step chains). Skip any whose surface the target
lacks (e.g. no CI config → skip `supply-chain-saboteur`):

| Persona (Task subagent) | War-game lens | Primarily surfaces |
|---|---|---|
| `threat-actor-wargame` | "build the cheapest kill chain to the crown jewels" | initial-access → privesc → impact paths |
| `insider-betrayal-sim` | "a trusted user / dependency turns hostile" | IDOR / BOLA / BFLA, privesc, supply-chain hooks |
| `single-point-of-compromise` | "where does ONE bug = total compromise" | secret stores, auth middleware, deserializers, SSRF egress |
| `threat-landscape-shift` | "what emerging attack breaks today's defenses" | desync/smuggling, dep-confusion, prompt-injection & tool-abuse |
| `assumption-pressure-test` | "attack every implicit trust assumption" | confused-deputy, parser differentials, mass-assignment, 2nd-order injection |
| `llm-agent-abuse` | "coerce the AI/agent surface" | prompt injection (direct + indirect/RAG), tool-call hijack, model-output → eval/SQL/shell, secret leakage |
| `workflow-abuse-economist` | "abuse the business logic, not the bug" | price/coupon/quota/refund tampering, free-trial re-abuse, state-machine skips |
| `federated-identity-breaker` | "break the SSO handshake, not the JWT" | OAuth redirect_uri/state theft, PKCE downgrade, SAML XSW, account-linking takeover |
| `http-edge-desync` | "make two HTTP hops disagree" | request smuggling (CL.TE/TE.CL/CL.0), cache poisoning, cache deception |
| `supply-chain-saboteur` | "own the build, own everything" | poisoned-pipeline execution, runner secret exfil, dependency confusion, container escape |

Each persona returns findings in the standard block (`## [SEVERITY] … Location / Type / Attack vector
/ Impact / PoC / Reachability / Remediation`).

**Continuous loop until converged** — run by the `redteam-hunting` skill (load it now). Maintain a
coverage ledger under `$OUTPUT_DIR/hunt/`: every attack-surface unit (source, sink, route,
trust-boundary, auth-check, deserializer, secret), seeded from `context-map.json`, tagged
`unexplored / explored / finding`. Each round:

1. Prioritize `unexplored` units (crown-jewel-adjacent first) and re-spawn the hunters against them,
   passing the `findings` + `dead_ends` ledgers as exclusion lists (never re-chase a disproven lead,
   never re-report a dup).
2. **Rotate the attack lens** each round (kill-chain → trust-flip → chokepoint → assumption →
   differential → variant → chain → emerging) so a single blind spot can't hide a bug all run.
3. Merge new findings (dedup by `(file, line, CWE)`), mark units `explored`.

**Convergence = the definition of "found all of it":** stop only when **K consecutive dry rounds**
(zero new deduped findings; `K=2` default, `K=3` with `--relentless`) **AND** zero `unexplored` units
remain. If `--rounds N` or the budget cap is hit *first*, you have **NOT** converged — say so and list
every still-`unexplored` unit as residual risk. Never let a truncated run read as "all clear."

> Hunting tip for each agent: lead with `/mantis-understand --hunt` (variant enumeration of a seed
> pattern across the codebase) and `--trace` (source→sink dataflow), then fall back to raw
> Grep/Read. Never claim a finding you haven't read in context.

---

## Phase 2 — Validate & prove  *(Stages 0→A→B→C→D→E→F)*

Every candidate — pipeline seeds **and** war-game findings — must survive the exploitability-validation
pipeline before it counts. **You (Claude) are the LLM for these stages.**

```bash
libexec/mantishack-validation-helper 0 --target "$TARGET"     # inventory + checklist; imports context-map.json
# then, in order, loading .claude/skills/exploitability-validation/stage-{a,b,c,d}-*.md:
libexec/mantishack-validation-helper A "$OUTPUT_DIR" --target "$TARGET"   # one-shot assessment
libexec/mantishack-validation-helper B "$OUTPUT_DIR" --target "$TARGET"   # hypotheses + proximity (0-10)
libexec/mantishack-validation-helper C "$OUTPUT_DIR" --target "$TARGET"   # sanity: code verbatim, flow real, reachable
libexec/mantishack-validation-helper D "$OUTPUT_DIR" --target "$TARGET"   # ruling + CVSS vector
libexec/mantishack-validation-helper F "$OUTPUT_DIR" --target "$TARGET"   # self-consistency retry
```

Stage E (binary feasibility) runs only for memory-corruption findings or when `--binary` is set.
**A finding is "confirmed" only if a source→sink path is proven reachable** (dataflow/reachability),
not on pattern match alone.

---

## Phase 3 — ⚔️ Adversarial verification  *(kill false positives)*

Spawn `skeptical-auditor-teardown` via the Task tool to **refute** each confirmed finding *and* each
control the code claims is safe ("input validated", "internal-only", "authz enforced"). Posture:
*broken until proven safe.* With `--deep`, run 3 independent skeptics per finding and demote any that a
**majority** refute. Survivors are the real findings. This is what separates this command from a raw
scan dump — most "plausible" findings die here.

(Optional, orthogonal model votes for extra confidence: `--consensus M` blind second opinion,
`--judge M` non-blind critique of the reasoning. Use multiple `--model` for cross-family correlation.)

---

## Phase 4 — 🔗 Kill-chain stitching

Take the surviving confirmed findings and chain them into end-to-end attack paths
(recon → initial access → privilege escalation → lateral movement → impact). A medium-sev SSRF + a
medium-sev deserializer on the same egress path may be a **critical** RCE chain — score the *chain*,
not just the links. Assign a CVSS v3.1 vector to each chain.

---

## Phase 5 — 🎯 RED TEAM REPORT

Spawn `red-team-report` via the Task tool to synthesize everything into the final deliverable:

- **Executive blast-radius summary** — what an attacker owns and how fast.
- **TOP 3 CRITICAL findings/chains**, ranked by **likelihood × severity**, each with: attack vector,
  full kill-chain walkthrough, realistic exploitation timeline, CVSS v3.1 vector, and the **single
  highest-ROI fix**.
- **Full findings table** (all confirmed, with CWE + CVSS).
- **Prioritized remediation roadmap.**

Write it to `out/<run>/red-team-report.md` and present the executive summary + TOP 3 inline.

---

## Power flags

| Flag | Effect |
|---|---|
| `--relentless` | **Find-all-of-it mode.** Loops the war-game until convergence (K=3 consecutive dry rounds + zero unexplored surface), 3× adversarial refutation per finding, multi-model. No early exit. |
| `--deep` | Loop-until-dry hunting (K=2) + 3× refutation + multi-model. Strong default for a real review. |
| `--rounds N` | Hard cap on war-game rounds (safety stop; default 2). Hitting it = *not converged*, reports residual risk. |
| `--model M` (repeatable) | Each model independently analyses; results correlated (agreement matrix, unique insights). |
| `--consensus M` / `--judge M` | Blind second opinion / non-blind critique of the primary reasoning. |
| `--binary` | Enable Stage E binary feasibility (chain-breaks, mitigations) for memory-corruption findings. |
| `--exploit` / `--patch` | Generate PoCs / secure patches for confirmed-exploitable findings (generated, never applied/run). |

---

## Why this is the most powerful command

- **Recall × precision.** Deterministic scanners (Semgrep/CodeQL/SCA) give breadth; the red-team agent
  swarm gives the depth scanners can't — business logic, broken authZ, trust-boundary and multi-step
  chain bugs. Neither alone is enough; together they dominate.
- **Many adversarial lenses, in parallel.** Five hunter personas attack simultaneously, each a distinct
  attacker model, so coverage isn't bottlenecked on one line of reasoning.
- **Adversarially verified.** A dedicated skeptic tries to *disprove* every finding — false positives
  die before they reach the report.
- **Reachability-proven & chain-stitched.** Findings are confirmed only with a real source→sink path,
  then composed into kill chains and CVSS-scored — the output is an attack plan, not a lint dump.

---

## Quick examples

```bash
/mantishack ./target-repo                         # full local review, 2 war-game rounds
/mantishack ./target-repo --deep --exploit        # maximal: loop-until-dry, 3× refute, PoCs
/mantishack https://app.example.com --authorized --scope "app.example.com only"
/mantishack ./svc --model gemini-2.5-pro --model gpt-5 --judge claude-opus-4-6
```
