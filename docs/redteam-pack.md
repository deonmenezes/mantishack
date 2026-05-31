# Red-Team Pack — `/mantishack` war-game agents

A battery of adversarial vulnerability-hunting agents, CWE strategy packs, and a relentless
continuous-loop engine, all wired into the flagship **`/mantishack`** command. Where a baseline
Semgrep/CodeQL pass gives breadth, this pack adds the depth scanners structurally miss — business
logic, broken authorization, trust-boundary breaks, and multi-step attack chains — and keeps hunting
until consecutive rounds find nothing new.

## What's in it

### Flagship command — `.claude/commands/mantishack.md`
`/mantishack <target>` runs the full pipeline in six phases: **recon & seed corpus** (scan + auth
audit + attack-surface map) → **red-team war-game** (parallel agent swarm) → **validate & prove**
(Stages 0→F, reachability required) → **adversarial verification** (refute every finding) →
**kill-chain stitching** → **Red Team Report** (TOP-3 critical, CVSS, highest-ROI fixes).
Power flags: `--relentless` (find-all-of-it convergence), `--deep`, `--rounds N`, `--model`,
`--consensus`, `--judge`, `--binary`, `--exploit`, `--patch`.

### Continuous-loop engine — `.claude/skills/redteam-hunting/SKILL.md`
The "keep going until it's all found" engine. Maintains a coverage ledger (every source/sink/route/
trust-boundary tagged `unexplored/explored/finding`), a dead-end memory, and a technique-rotation
matrix. **Convergence = K consecutive dry rounds AND zero unexplored surface.** A capped/truncated run
must report residual `unexplored` units — it never reads as "all clear" when it isn't.

### Red-team agent personas — `.claude/agents/`
Each maps a classic adversarial "war-game" lens to a vuln-hunting mission:

| Persona | Lens | Hunts |
|---|---|---|
| `threat-actor-wargame` | cheapest kill chain to crown jewels | initial-access → privesc → impact paths |
| `insider-betrayal-sim` | a trusted user/dependency turns hostile | IDOR/BOLA/BFLA, privesc, supply-chain hooks |
| `single-point-of-compromise` | where one bug = total compromise | secret stores, auth middleware, deserializers, SSRF egress |
| `threat-landscape-shift` | emerging attacks that break today's defenses | desync, dep-confusion, prompt-injection & tool-abuse |
| `assumption-pressure-test` | attack every implicit trust assumption | confused-deputy, parser differentials, mass-assignment, 2nd-order injection |
| `skeptical-auditor-teardown` | refute "it's secure" (false-positive killer) | adversarial verification of findings + controls |
| `llm-agent-abuse` | coerce the AI/agent surface | prompt injection (direct + indirect/RAG), tool-call hijack, model-output→eval/SQL/shell, secret leakage |
| `workflow-abuse-economist` | abuse business logic, not the bug | price/coupon/quota/refund tampering, free-trial re-abuse, state-machine skips |
| `federated-identity-breaker` | break the SSO handshake, not the JWT | OAuth redirect_uri/state theft, PKCE downgrade, SAML XSW, account-linking takeover |
| `http-edge-desync` | make two HTTP hops disagree | request smuggling (CL.TE/TE.CL/CL.0), cache poisoning, cache deception |
| `supply-chain-saboteur` | own the build, own everything | poisoned-pipeline execution, runner secret exfil, dependency confusion, container escape |
| `red-team-report` | synthesize | kill-chain stitching, CVSS, TOP-3 critical report |

### CWE strategy packs — `core/llm/cwe_strategies/strategies/`
Web/app-tier coverage (the existing strategies skew toward C/kernel memory bugs). Auto-discovered by
`core/llm/cwe_strategies/loader.py` and injected into the per-function audit prompt by signal scoring —
**no registration needed.**

- `deserialization.yml` — CWE-502 object injection (pickle, yaml.load, ObjectInputStream, unserialize…)
- `ssrf.yml` — CWE-918 SSRF + cloud-metadata theft, allowlist bypass, DNS rebinding
- `broken_object_authz.yml` — CWE-639/862/863 IDOR/BOLA/BFLA
- `template_injection.yml` — CWE-1336/917 SSTI + expression-language injection
- `auth_token_confusion.yml` — CWE-347/287/345 JWT/token confusion, alg:none, key confusion
- `toctou_race.yml` — CWE-367/362 web-tier check-then-act races, double-spend, idempotency gaps
- `ai_tool_abuse.yml` — CWE-1427/94/77 LLM prompt injection, tool-call abuse, unsafe model output → eval/SQL/shell
- `business_logic.yml` — CWE-840/841/770 price/coupon/quota/refund tampering, state-machine sequencing
- `oauth_saml_oidc.yml` — CWE-1275/352/347 OAuth/OIDC/SAML flow attacks, XSW, account-linking takeover
- `request_smuggling_cache_poisoning.yml` — CWE-444/525/348 HTTP desync, web cache poisoning + deception
- `cicd_supply_chain.yml` — CWE-1395/94/250 poisoned-pipeline execution, dependency confusion, container/IaC escape

## Usage

```bash
/mantishack ./target-repo --relentless --exploit     # maximal: loop-to-convergence + PoCs
/mantishack ./svc --deep --model gemini-2.5-pro --judge claude-opus-4-6
/mantishack https://app.example.com --authorized --scope "app.example.com only"
```

Individual personas are also launchable directly via the Task tool when you want a single lens.

## Coverage

12 personas + 11 CWE strategy packs across the full modern web/app + AI attack surface: kill-chains,
authorization, trust assumptions, deserialization, SSRF, SSTI, JWT, TOCTOU, **LLM/agent abuse,
business-logic abuse, OAuth/OIDC/SAML flows, HTTP desync + cache poisoning, and CI/CD + container
supply-chain** — the five gap classes the completeness critic flagged are now closed.
