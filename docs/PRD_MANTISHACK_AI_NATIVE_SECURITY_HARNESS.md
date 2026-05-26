# MantisHack PRD: AI-Native Security Harness Upgrade

**Product:** MantisHack  
**Repository:** `deonmenezes/mantishack`  
**Document type:** Product Requirements Document  
**Version:** Draft v1.0  
**Date:** 2026-05-26  
**Owner:** Deon Menezes  
**Status:** Ready for implementation planning  

---

## 1. Executive Summary

MantisHack should evolve from an AI-assisted security CLI into an **AI-native authorized security research operating system**.

The current repository already has strong foundations:

- Rust workspace with daemon, CLI, scanner, MCP, egress, report, fuzzer, crawler, sandbox, plugin, web UI, gateway, Kubernetes, and other modules.
- Plugin support for Claude Code, Codex CLI, and OpenCode.
- Slash-command interface for `/mantishack`, `/mantis-scan`, `/mantis-status`, `/mantis-claim`, `/mantis-report`, and `/mantis-daemon`.
- Standalone CLI flow through `mantis` and `mantis-daemon`.
- Scope-aware architecture with `mantis-egress` as the single network boundary.
- Evidence-grade reporting and verifiable claim pipeline.
- Auto-installed recon tools such as `subfinder`, `httpx`, `katana`, `nuclei`, and `jwt_tool`.

The next version should focus on making MantisHack feel like a coordinated security team inside every AI coding harness.

The upgrade should derive architectural ideas from modern multi-agent harnesses like Oh My OpenAgent / Oh My OpenCode, especially:

- Multi-harness adapter design.
- Team Mode with parallel specialist agents.
- Intent classification before execution.
- Skill-embedded MCP servers.
- Hash-anchored edits for safe report and file modification.
- Tmux-based live visibility.
- Hierarchical `AGENTS.md` context generation.
- Model routing by task category.
- One-command workflows that complete planning, testing, verification, and reporting.

This PRD describes how to productize those ideas for MantisHack while preserving the most important rule:

> **MantisHack must only support authorized security testing against in-scope assets.**

---

## 2. Product Vision

### 2.1 Vision Statement

MantisHack is an AI-native security harness that helps authorized operators find, verify, document, and responsibly disclose vulnerabilities across software systems.

It should combine:

- Security research workflows.
- Agent orchestration.
- MCP tools.
- CLI/TUI workflows.
- Scope enforcement.
- Evidence integrity.
- High-quality reporting.
- Human approval gates.

### 2.2 Positioning

MantisHack should not be positioned as a random scanner, exploit toy, or generic AI coding assistant.

It should be positioned as:

> **The AI operating system for authorized security research.**

### 2.3 Product Promise

A user should be able to run:

```bash
/mantishack https://example.com
```

and get a complete, safe, auditable flow:

```text
authorization check
scope manifest
planning
recon
testing
verification
evidence capture
claim creation
report generation
disclosure-ready output
```

---

## 3. Current State

### 3.1 Existing Capabilities

Based on the current repository direction, MantisHack already supports or plans to support:

- A daemon-driven architecture.
- Rust-based CLI and service components.
- MCP server implementation.
- Scope enforcement through `mantis-egress`.
- Evidence event storage.
- Claim verification.
- Multiple report formats.
- Plugin surface for Claude Code, Codex CLI, and OpenCode.
- Recon tooling auto-installation.
- Deployment modes such as Docker, systemd, Kubernetes, and serverless.

### 3.2 Current Product Gap

The repo has strong technical infrastructure, but the product experience needs to become clearer and more orchestrated.

Current gap:

```text
Many powerful modules exist, but users need a guided AI workflow that feels complete, safe, and obvious.
```

The next update should turn the tool from a crate-rich platform into a polished operator experience.

---

## 4. Goals

### 4.1 Primary Goals

1. Create a unified multi-harness architecture for Claude Code, Codex CLI, OpenCode, and future harnesses.
2. Introduce Mantis Team Mode with parallel security agents.
3. Add a mandatory authorization and intent gate before any active testing.
4. Build skill-embedded MCPs for web, API, mobile, cloud, secrets, recon, reporting, and disclosure.
5. Add hash-anchored evidence and report edits.
6. Add a planning-first workflow through `/mantis-plan`.
7. Improve `/mantishack` into a full one-command engagement flow.
8. Add Tmux or TUI visibility for live multi-agent runs.
9. Generate hierarchical security context files for repositories.
10. Improve reporting quality, severity calibration, and reproducibility.

### 4.2 Secondary Goals

1. Make Mantis easier to demo.
2. Make Mantis safer for open-source usage.
3. Make Mantis easier to extend with plugins.
4. Make Mantis friendly to bug bounty, startup security, internal security teams, and compliance teams.
5. Make the architecture commercially clean and legally defensible.

---

## 5. Non-Goals

MantisHack should not:

1. Bypass authorization requirements.
2. Encourage scanning random internet targets.
3. Run destructive testing by default.
4. Perform credential stuffing, password attacks, DoS, spam, or persistence.
5. Hide activity from target systems.
6. Exfiltrate sensitive data.
7. Auto-submit bug bounty reports without user review.
8. Copy code, assets, prompts, or restricted-license implementation from other projects.
9. Depend on one model provider.
10. Become a bloated wrapper over scanners without agentic reasoning.

---

## 6. Target Users

### 6.1 Solo Security Researcher

Wants to test authorized targets quickly and generate clean reports.

Needs:

- Fast recon.
- Guided scope setup.
- Verification.
- Evidence capture.
- Professional reports.

### 6.2 Startup Founder / CTO

Wants to audit their own app before attackers do.

Needs:

- Simple onboarding.
- Safe defaults.
- Clear risk summary.
- Actionable remediation.
- Minimal security jargon.

### 6.3 Bug Bounty Hunter

Wants help organizing, testing, and reporting valid findings.

Needs:

- Program scope import.
- Evidence chain.
- Severity calibration.
- Duplicate reduction.
- Report export.

### 6.4 Internal Security Team

Wants repeatable authorized testing across internal assets.

Needs:

- Multi-tenant support.
- Scheduling.
- Audit logs.
- Team workflows.
- Compliance reporting.

### 6.5 AI Coding Agent User

Wants to run Mantis inside Claude Code, Codex CLI, or OpenCode.

Needs:

- Slash commands.
- MCP tools.
- Context-aware workflows.
- Natural-language plans.
- Safe file edits.

---

## 7. Product Principles

1. **Authorization first.** The tool must confirm scope before action.
2. **Evidence over vibes.** Every finding must have reproducible proof.
3. **Verify before reporting.** Unverified leads should never become claims.
4. **Human approval for risky steps.** The operator remains accountable.
5. **Composable tools.** Agents, MCP servers, scanners, and reports should be modular.
6. **Harness agnostic.** Mantis should run across Claude Code, Codex, OpenCode, and future agent runtimes.
7. **No context flooding.** Load only the skills and tools needed for the task.
8. **Transparent operation.** Users should see what agents are doing.
9. **Professional output.** Reports must be concise, credible, and disclosure-ready.
10. **Legal defensibility.** Every run should leave a clean audit trail.

---

## 8. Proposed Product Architecture

### 8.1 High-Level Architecture

```text
User
  |
  | slash command / CLI / TUI / Web UI
  v
Harness Adapter Layer
  |-- Claude Code adapter
  |-- Codex CLI adapter
  |-- OpenCode adapter
  |-- Standalone CLI adapter
  v
Mantis MCP Layer
  |-- skills
  |-- tools
  |-- permissions
  |-- context injection
  v
Mantis Orchestrator
  |-- IntentGate
  |-- ScopeGuard
  |-- Team Mode coordinator
  |-- Model router
  |-- Task scheduler
  v
Execution Layer
  |-- mantis-egress
  |-- recon tools
  |-- scanner modules
  |-- crawler modules
  |-- static analysis
  |-- mobile/binary analysis
  |-- cloud checks
  v
Evidence Layer
  |-- event store
  |-- screenshots
  |-- HTTP transcripts
  |-- request/response diffs
  |-- PoC artifacts
  |-- hashes and signatures
  v
Claim and Report Layer
  |-- verified findings
  |-- severity calibration
  |-- remediation
  |-- exports: md, pdf, h1, bugcrowd, sarif, openvex
```

### 8.2 Core Modules

Existing modules should be organized around this product mental model:

```text
crates/
├── mantis-core                 shared primitives and traits
├── mantis-cli                  standalone command interface
├── mantis-daemon               long-running engagement service
├── mantis-mcp                  MCP server and tool exposure
├── mantis-orchestrator         agent planning and task coordination
├── mantis-egress               scope-enforced network boundary
├── mantis-scope                signed scope manifests
├── mantis-recon                recon orchestration
├── mantis-recon-tools          tool install and health checks
├── mantis-scanner-http         HTTP scanning
├── mantis-api                  API testing
├── mantis-mobile               mobile analysis
├── mantis-binary               binary/package analysis
├── mantis-secrets              secrets scanning
├── mantis-static-scan          repository static analysis
├── mantis-claim                finding and verification model
├── mantis-report               report generation
├── mantis-event-store          audit log and evidence storage
├── mantis-chat                 agent chat interface
├── mantis-chat-tui             terminal chat UI
├── mantis-web-ui               browser UI
├── mantis-gateway              multi-platform operator gateway
├── mantis-plugin               WASM plugin host
├── mantis-sandbox              record-replay sandboxing
├── mantis-compliance           compliance mapping
├── mantis-notify               Slack, email, webhook notifications
```

---

## 9. Key Feature Requirements

## F1. Multi-Harness Adapter Layer

### Problem

Mantis currently targets multiple host CLIs, but the product should formalize this as an adapter layer.

### Requirement

Create a clear separation between:

```text
core security logic
MCP tool definitions
host-specific slash commands
host-specific config format
host-specific install path
```

### Supported Harnesses

| Harness | Priority | Required |
|---|---:|---|
| Claude Code | P0 | Yes |
| Codex CLI | P0 | Yes |
| OpenCode | P0 | Yes |
| Standalone CLI | P0 | Yes |
| Cursor | P1 | Optional |
| Windsurf | P2 | Optional |
| Custom MCP host | P1 | Yes |

### Implementation Notes

Add or formalize:

```text
adapters/
├── claude-code/
├── codex/
├── opencode/
├── standalone/
└── mcp-generic/
```

Each adapter should define:

```text
commands
config format
install path
permissions
MCP registration
context injection
uninstall process
health check
```

### Acceptance Criteria

- The installer can detect installed harnesses.
- The user can select which harnesses to install into.
- Each harness exposes the same command set.
- Adapter code does not duplicate core security logic.
- A failing adapter does not break standalone CLI.

---

## F2. Mantis Team Mode

### Problem

Security testing involves many parallel tasks. One agent cannot efficiently handle recon, API testing, auth testing, mobile analysis, verification, and report writing at the same time.

### Requirement

Create a Team Mode where a lead agent coordinates specialist agents.

### Proposed Agent Roles

```text
Mantis Lead
├── ScopeGuard Agent
├── Recon Agent
├── Web Surface Agent
├── API Agent
├── Auth Logic Agent
├── Secrets Agent
├── Mobile/Binary Agent
├── Verification Agent
├── Report Agent
└── Disclosure Agent
```

### Agent Responsibilities

#### Mantis Lead

- Creates the engagement plan.
- Delegates tasks.
- Monitors status.
- Stops unsafe or out-of-scope activity.
- Produces final operator summary.

#### ScopeGuard Agent

- Checks authorization.
- Parses scope manifest.
- Blocks out-of-scope tasks.
- Maintains allowlist and denylist.

#### Recon Agent

- Runs passive and safe active recon.
- Uses tools like subfinder, httpx, katana, dnsx, and nuclei where permitted.
- Produces discovered surfaces.

#### Web Surface Agent

- Tests web application surfaces.
- Checks auth boundaries, access control, headers, exposed routes, and misconfigurations.
- Does not run destructive tests.

#### API Agent

- Parses OpenAPI specs.
- Maps endpoints.
- Tests authorization and validation boundaries.
- Generates safe reproduction steps.

#### Auth Logic Agent

- Looks for login, signup, reset, invitation, session, token, and role issues.
- Prioritizes business logic and account boundary flaws.

#### Secrets Agent

- Scans supplied repositories or artifacts for secrets.
- Redacts sensitive values in output.
- Provides safe remediation.

#### Mobile/Binary Agent

- Extracts URLs and endpoints from APK, IPA, EXE, DMG, or app bundles.
- Sends discovered endpoints into scoped web/API pipeline.

#### Verification Agent

- Re-tests suspected findings.
- Determines exploitability.
- Records exact evidence.
- Prevents false positives from entering the report.

#### Report Agent

- Writes professional reports.
- Includes impact, steps, evidence, remediation, severity, and scope proof.
- Produces markdown, PDF, SARIF, OpenVEX, HackerOne, and Bugcrowd formats.

#### Disclosure Agent

- Drafts responsible disclosure messages.
- Never sends without human approval.

### Acceptance Criteria

- Team Mode can run at least 3 agents in parallel.
- The lead can pause, stop, and reassign tasks.
- All tasks are visible in status output.
- Each task has a scope decision attached.
- Findings require verification before report inclusion.

---

## F3. ScopeGuard and IntentGate

### Problem

Users may provide vague, broad, or unsafe prompts. Mantis must understand intent before taking action.

### Requirement

Before any engagement, Mantis must classify the request.

### Intent Categories

```text
authorized_test
own_asset_test
bug_bounty_scope_test
internal_security_audit
learning_or_demo
report_generation_only
out_of_scope_or_unknown
unsafe_request
```

### ScopeGuard Checks

Before running active testing:

1. Does the user claim authorization?
2. Is there a signed scope manifest?
3. Is the target included in scope?
4. Are excluded paths respected?
5. Are rate limits defined?
6. Are destructive actions disabled?
7. Are credentials provided safely?
8. Is the activity logged?

### Required User Flow

```text
User: /mantishack https://example.com

Mantis:
1. asks for or loads scope manifest
2. explains allowed actions
3. confirms authorization
4. creates engagement ID
5. starts only after scope is valid
```

### Unsafe Request Handling

Mantis must refuse or redirect requests involving:

- Credential theft.
- Persistence.
- Exfiltration.
- Evasion.
- DoS.
- Unauthorized third-party targets.
- Bypassing rate limits.
- Malware behavior.
- Unapproved exploitation.

### Acceptance Criteria

- `/mantishack` cannot run active testing without a valid scope decision.
- All outbound traffic must route through `mantis-egress`.
- Every tool call must include a scope verdict.
- Out-of-scope requests are blocked with clear explanation.
- Safe demo mode exists for local targets.

---

## F4. Skill-Embedded MCPs

### Problem

Loading every tool into every session bloats context and confuses agents.

### Requirement

Create domain-specific skills that expose MCP tools only when needed.

### Proposed Skills

```text
.skills/
├── web-security/
├── api-security/
├── auth-testing/
├── recon/
├── secrets-detection/
├── mobile-analysis/
├── binary-analysis/
├── cloud-security/
├── compliance-mapping/
├── report-writing/
├── disclosure/
└── remediation/
```

### Each Skill Contains

```text
SKILL.md
permissions.json
tools.json
mcp-server config
examples/
safety.md
acceptance.md
```

### Example Skill Metadata

```json
{
  "name": "api-security",
  "description": "Authorized API security testing and endpoint analysis",
  "risk_level": "medium",
  "requires_scope": true,
  "default_rate_limit": "safe",
  "tools": ["openapi_parse", "endpoint_map", "auth_boundary_check"],
  "blocked_actions": ["credential_stuffing", "destructive_fuzzing"]
}
```

### Acceptance Criteria

- Skills are loaded only when needed.
- Each skill has permissions and safety boundaries.
- Skills can be used across Claude Code, Codex CLI, OpenCode, and standalone CLI.
- MCP tool names are consistent across harnesses.

---

## F5. Hash-Anchored Evidence and Report Edits

### Problem

AI agents can corrupt reports or overwrite evidence if they edit stale files.

### Requirement

Implement hash-anchored editing for sensitive files.

### Sensitive File Types

```text
scope manifests
evidence logs
claim files
report drafts
disclosure drafts
config files
AGENTS.md
```

### Editing Model

When Mantis reads a file, each line or block gets a stable identifier:

```text
12#A7F3| ## Finding Summary
13#B91C| Password reset flow allows...
14#D002| Impact: Account takeover...
```

Edits must reference IDs.

If the file changed, the edit is rejected.

### Acceptance Criteria

- Report edits never silently overwrite changed content.
- Evidence files are append-only unless explicitly unlocked.
- Claim changes are tracked with before/after hashes.
- User can run `mantis verify-evidence` to check integrity.

---

## F6. Planning-First Workflow

### Problem

Users often jump straight into scanning without defining scope, risk, or desired output.

### Requirement

Add a first-class planning flow.

### New Command

```bash
/mantis-plan <target>
```

### Flow

```text
1. classify target
2. collect authorization info
3. create scope manifest
4. detect asset type
5. choose skills
6. generate task plan
7. estimate risk
8. ask for final operator approval
```

### Example Output

```text
Engagement Plan: example.com
Type: web application
Authorization: user-attested plus signed scope required
Allowed actions: passive recon, safe HTTP probing, endpoint discovery
Blocked actions: DoS, brute force, destructive fuzzing
Skills: recon, web-security, report-writing
Estimated duration: short
Next command: /mantis-scan ENG-01HX...
```

### Acceptance Criteria

- `/mantis-plan` never runs active testing.
- It produces a saved plan.
- User can approve, edit, or cancel.
- `/mantishack` internally calls the planner before execution.

---

## F7. Improved `/mantishack` One-Command UX

### Problem

The main command should feel magical, but safe.

### Requirement

`/mantishack` should orchestrate the entire authorized workflow.

### Required Pipeline

```text
input target
  ↓
IntentGate
  ↓
ScopeGuard
  ↓
Planner
  ↓
Team Mode selection
  ↓
Recon
  ↓
Surface map
  ↓
Testing
  ↓
Verification
  ↓
Claim generation
  ↓
Report generation
  ↓
Operator summary
```

### Command Options

```bash
/mantishack <target>
/mantishack <target> --scope scope.yaml
/mantishack <target> --mode passive
/mantishack <target> --mode safe-active
/mantishack <target> --report pdf
/mantishack <target> --team
/mantishack <target> --no-team
/mantishack <target> --dry-run
```

### Acceptance Criteria

- One command can complete an engagement on a local or authorized target.
- Operator gets clear progress.
- All risky actions require either prior config permission or explicit confirmation.
- Report is generated at the end.

---

## F8. Model Routing by Task Category

### Problem

Different tasks need different model capabilities and costs.

### Requirement

Add category-based model routing.

### Categories

```text
quick_triage
deep_reasoning
code_review
report_writing
planner
verification
summarization
```

### Example Config

```json
{
  "model_routing": {
    "quick_triage": "cheap-fast-model",
    "deep_reasoning": "strongest-reasoning-model",
    "report_writing": "writing-model",
    "verification": "deterministic-low-temp-model",
    "planner": "strongest-reasoning-model"
  }
}
```

### Acceptance Criteria

- Agents request categories, not model names.
- Users can override model mapping.
- Missing model config falls back safely.
- Model routing works across supported harnesses.

---

## F9. Live Tmux / TUI Visibility

### Problem

Users need to trust what agents are doing.

### Requirement

Create a live engagement view.

### Modes

1. Tmux view.
2. Ratatui terminal UI.
3. Web UI stream.

### Suggested Layout

```text
┌──────────────────────┬──────────────────────┐
│ Lead / Plan          │ ScopeGuard           │
├──────────────────────┼──────────────────────┤
│ Recon Agent          │ Web/API Agent        │
├──────────────────────┼──────────────────────┤
│ Verification Agent   │ Report Agent         │
└──────────────────────┴──────────────────────┘
```

### Status Data

Each agent should show:

```text
state
current task
scope verdict
last tool call
evidence count
finding count
blocked action count
```

### Acceptance Criteria

- User can watch agents run.
- User can pause an agent.
- User can stop the entire engagement.
- Logs are saved to the event store.

---

## F10. Hierarchical Security Context Generation

### Problem

Agents perform better when they understand repository structure and security assumptions.

### Requirement

Add a command to generate contextual `AGENTS.md` files.

### New Command

```bash
/mantis-init-deep
```

or

```bash
mantis init-deep
```

### Output

```text
AGENTS.md
src/AGENTS.md
api/AGENTS.md
auth/AGENTS.md
mobile/AGENTS.md
infra/AGENTS.md
```

### File Contents

Each generated `AGENTS.md` should include:

```text
module purpose
security-sensitive files
auth assumptions
known risks
testing limits
safe commands
unsafe commands
reporting rules
```

### Acceptance Criteria

- Command analyzes repo structure.
- Files are generated with user approval.
- Existing `AGENTS.md` files are not overwritten without confirmation.
- Output improves future Mantis and AI-agent sessions.

---

## F11. Findings Lifecycle

### Problem

Security tools often mix leads, false positives, and verified findings.

### Requirement

Create a strict lifecycle.

### Finding States

```text
lead
candidate
needs_verification
verified
duplicate
false_positive
accepted_risk
reported
fixed
regression_tested
```

### Rules

- Only `verified` findings can enter final reports.
- `false_positive` and `duplicate` findings remain in audit history.
- Severity must be explained.
- Evidence must be attached.
- Remediation must be actionable.

### Acceptance Criteria

- Every finding has a state.
- State transitions are logged.
- Report generator ignores unverified findings by default.
- User can include appendix with leads if desired.

---

## F12. Report Quality Upgrade

### Problem

Reports need to be credible, concise, and accepted by security teams.

### Requirement

Improve report templates.

### Required Report Sections

```text
Executive Summary
Scope and Authorization
Methodology
Findings Table
Finding Details
Impact
Steps to Reproduce
Evidence
Affected Assets
Severity
Remediation
Retest Notes
Appendix
```

### Export Formats

```text
markdown
pdf
html
sarif
openvex
hackerone
bugcrowd
json
```

### Acceptance Criteria

- Reports can be generated in multiple formats.
- Sensitive values are automatically redacted.
- Each finding has reproducible steps.
- Reports include legal scope proof.

---

## F13. Safe Tool Registry

### Problem

External tools need safety metadata, install metadata, and scope requirements.

### Requirement

Create a tool registry.

### Registry Fields

```json
{
  "name": "nuclei",
  "category": "scanner",
  "install_method": "auto",
  "path": "tools/recon/bin/nuclei",
  "requires_scope": true,
  "risk_level": "medium",
  "network_access": true,
  "default_enabled": false,
  "allowed_modes": ["passive", "safe-active"],
  "blocked_modes": ["destructive"],
  "license": "external"
}
```

### Acceptance Criteria

- `mantis doctor` shows tool health.
- Tools have risk metadata.
- High-risk tools require explicit config.
- Missing tools degrade gracefully.

---

## F14. Plugin and Integration System

### Problem

Mantis will need to integrate with scanners, bug bounty systems, ticketing, and compliance platforms.

### Requirement

Add a signed plugin system.

### Plugin Types

```text
scanner
report_exporter
notification
compliance_mapper
evidence_collector
scope_importer
model_provider
```

### Security Requirements

- Plugins must declare permissions.
- Plugins must be signed.
- Plugins run through sandbox where possible.
- Plugins cannot bypass `mantis-egress`.
- Plugins cannot access secrets unless explicitly granted.

### Acceptance Criteria

- WASM plugins can be loaded.
- Plugin manifest is verified.
- Unsafe plugin permissions require user approval.
- Plugin execution is logged.

---

## 10. User Stories

### US1: Founder Audits Own Startup

As a startup founder, I want to run Mantis against my own web app so that I can discover serious issues before customers or attackers do.

Acceptance:

- User creates scope.
- User runs safe scan.
- Mantis produces report.
- No out-of-scope traffic occurs.

### US2: Bug Bounty Researcher Tests In-Scope Target

As a bug bounty researcher, I want to import a program scope and run guided testing so that I can produce valid reports faster.

Acceptance:

- Program scope is imported.
- Exclusions are respected.
- Report includes program name and scope evidence.
- Findings are verified before export.

### US3: Developer Runs Security Review Before Deploy

As a developer, I want Mantis to inspect my repo before deployment so that I can fix security issues early.

Acceptance:

- Mantis analyzes local repo.
- Mantis generates `AGENTS.md`.
- Mantis finds secrets and insecure patterns.
- Mantis suggests remediation.

### US4: Security Team Runs Scheduled Engagement

As an internal security team, I want scheduled scans with reports so that I can track security drift.

Acceptance:

- Runs on schedule.
- Compares diff from previous run.
- Notifies team.
- Stores audit trail.

### US5: AI Agent Uses Mantis Tools

As an AI coding agent, I want to call Mantis MCP tools so that I can safely reason about security without uncontrolled shell commands.

Acceptance:

- MCP tools expose limited permissions.
- Tool calls include scope decisions.
- Agent receives structured results.
- Dangerous tools are unavailable by default.

---

## 11. Command Design

### 11.1 Slash Commands

```text
/mantishack <target>
/mantis-plan <target>
/mantis-scan <engagement_id>
/mantis-status [engagement_id]
/mantis-claim <finding_id>
/mantis-report <engagement_id>
/mantis-init-deep
/mantis-doctor
/mantis-scope create
/mantis-scope verify
/mantis-team status
/mantis-team pause <agent>
/mantis-team resume <agent>
/mantis-stop <engagement_id>
```

### 11.2 Standalone CLI Commands

```bash
mantis doctor
mantis init
mantis init-deep
mantis scope create
mantis scope verify scope.yaml
mantis engagement create "name" --target https://example.com --scope scope.yaml
mantis engagement plan ENG_ID
mantis engagement start ENG_ID
mantis engagement status ENG_ID --watch
mantis engagement stop ENG_ID
mantis engagement report ENG_ID --format pdf
mantis evidence verify ENG_ID
mantis team status ENG_ID
```

---

## 12. Configuration

### 12.1 Project Config

```json
{
  "mantis": {
    "mode": "safe-active",
    "team_mode": {
      "enabled": true,
      "max_parallel_agents": 4,
      "live_view": "tmux"
    },
    "scope": {
      "manifest": "./mantis.scope.yaml",
      "require_signed_scope": true
    },
    "reports": {
      "default_format": "markdown",
      "redact_secrets": true,
      "include_unverified_leads": false
    },
    "model_routing": {
      "planner": "strongest-reasoning-model",
      "quick_triage": "cheap-fast-model",
      "verification": "deterministic-low-temp-model",
      "report_writing": "writing-model"
    }
  }
}
```

### 12.2 Scope Manifest Example

```yaml
version: 1
engagement: example-security-review
owner: Example Inc
authorization:
  type: written
  reference: AUTH-2026-001
targets:
  include:
    - https://app.example.com
    - https://api.example.com
  exclude:
    - https://payments.example.com
    - https://admin.example.com/destructive-test-area
limits:
  rate_limit: low
  destructive_tests: false
  credential_attacks: false
  dos_tests: false
  data_exfiltration: false
reporting:
  contact: security@example.com
  formats:
    - markdown
    - pdf
```

---

## 13. Data Models

### 13.1 Engagement

```json
{
  "id": "ENG_01HX...",
  "name": "example-security-review",
  "target": "https://example.com",
  "scope_manifest": "scope.yaml",
  "status": "running",
  "mode": "safe-active",
  "created_at": "2026-05-26T00:00:00Z",
  "agents": [],
  "findings": [],
  "evidence_events": []
}
```

### 13.2 Finding

```json
{
  "id": "FINDING_01HX...",
  "state": "verified",
  "title": "Password reset flow allows account takeover",
  "severity": "critical",
  "confidence": "high",
  "affected_assets": [],
  "impact": "",
  "steps_to_reproduce": [],
  "evidence_ids": [],
  "remediation": "",
  "scope_verdict": "in_scope"
}
```

### 13.3 Evidence Event

```json
{
  "id": "EV_01HX...",
  "engagement_id": "ENG_01HX...",
  "type": "http_transcript",
  "hash": "blake3:...",
  "timestamp": "2026-05-26T00:00:00Z",
  "agent": "verification-agent",
  "scope_verdict": "in_scope",
  "redactions": [],
  "artifact_path": "evidence/http/EV_01HX.json"
}
```

---

## 14. Safety and Responsible Use Requirements

### 14.1 Mandatory Safety Controls

Mantis must enforce:

1. Signed or user-attested scope before active testing.
2. Egress proxy routing for all network traffic.
3. Rate limits by default.
4. Destructive actions disabled by default.
5. Credential attacks disabled.
6. DoS testing disabled.
7. Sensitive data redaction.
8. No automatic disclosure sending.
9. Human approval for risky transitions.
10. Audit logs for all tool calls.

### 14.2 Modes

```text
demo
passive
safe-active
verified-active
internal-lab
```

### 14.3 Blocked by Default

```text
brute force
credential stuffing
DoS
persistence
evasion
data exfiltration
malware generation
unauthorized third-party scanning
secret dumping
mass scanning
```

### 14.4 Operator Confirmations

Human approval is required before:

- Running active tests.
- Testing authentication boundaries with provided accounts.
- Generating a final report.
- Exporting to bug bounty platforms.
- Sending any disclosure message.
- Enabling high-risk plugins.

---

## 15. Metrics and KPIs

### 15.1 Product Metrics

```text
time_to_first_plan
time_to_first_verified_finding
false_positive_rate
verified_finding_rate
report_acceptance_rate
scope_block_count
unsafe_request_block_count
agent_task_completion_rate
average_engagement_duration
```

### 15.2 Quality Metrics

```text
evidence_completeness_score
reproduction_success_rate
severity_accuracy_score
report_clarity_score
redaction_accuracy
```

### 15.3 Adoption Metrics

```text
installs
active projects
active engagements
CLI command usage
MCP tool usage
reports generated
plugins installed
```

---

## 16. Release Plan

## Phase 0: Product Cleanup

**Goal:** Make the current experience understandable.

Tasks:

- Update README around authorized testing.
- Add clear command map.
- Add architecture diagram.
- Add `mantis doctor`.
- Add example scope manifest.
- Add demo target instructions.

Deliverable:

```text
MantisHack can be installed, understood, and run safely in demo mode.
```

## Phase 1: Multi-Harness Adapter Layer

**Goal:** Cleanly support Claude Code, Codex CLI, OpenCode, and standalone CLI.

Tasks:

- Create adapter abstraction.
- Move host-specific logic into adapters.
- Standardize slash commands.
- Add install and uninstall flows.
- Add adapter health checks.

Deliverable:

```text
One core Mantis engine, multiple host surfaces.
```

## Phase 2: ScopeGuard and IntentGate

**Goal:** Make authorization and scope enforcement product-grade.

Tasks:

- Add intent classifier.
- Add scope validation.
- Attach scope verdict to every task.
- Block out-of-scope actions.
- Add safe refusal messages.

Deliverable:

```text
Mantis cannot accidentally run active testing without valid scope.
```

## Phase 3: Team Mode

**Goal:** Create parallel specialist agents.

Tasks:

- Add team coordinator.
- Add agent registry.
- Add task queue.
- Add agent status.
- Add pause/resume/stop.

Deliverable:

```text
Mantis can run multiple security agents in parallel with visible status.
```

## Phase 4: Skill-Embedded MCPs

**Goal:** Modularize capabilities.

Tasks:

- Define skill schema.
- Build first skills: recon, web-security, api-security, report-writing.
- Add skill loader.
- Add permission metadata.
- Add MCP server lifecycle.

Deliverable:

```text
Skills load tools on demand without context bloat.
```

## Phase 5: Evidence and Report Integrity

**Goal:** Make reports safer and more credible.

Tasks:

- Add hash-anchored edits.
- Add evidence verification.
- Add finding lifecycle.
- Improve report templates.
- Add redaction tests.

Deliverable:

```text
Reports are verifiable, professional, and safe to share.
```

## Phase 6: Live UX

**Goal:** Make the product demo-worthy.

Tasks:

- Add Tmux layout.
- Improve Ratatui TUI.
- Stream status to web UI.
- Add live event feed.
- Add final summary view.

Deliverable:

```text
Users can watch the AI security team operate in real time.
```

---

## 17. Acceptance Criteria for v1 Upgrade

The upgrade is complete when:

1. User can install Mantis into Claude Code, Codex CLI, or OpenCode.
2. User can run `mantis doctor` and see tool/harness status.
3. User can run `/mantis-plan <target>` without active testing.
4. User can create and verify a scope manifest.
5. User can run `/mantishack <target> --scope scope.yaml`.
6. All outbound traffic goes through `mantis-egress`.
7. Team Mode can run at least 3 agents.
8. Each finding moves through a lifecycle.
9. Only verified findings appear in final reports.
10. Report can export to markdown and PDF.
11. Evidence integrity can be verified.
12. Unsafe requests are refused or redirected safely.
13. Existing standalone CLI still works.
14. Documentation includes examples and safe demo target.

---

## 18. Risks and Mitigations

### Risk 1: Product is perceived as unsafe

Mitigation:

- Keep authorization-first messaging.
- Add visible scope enforcement.
- Add safe modes.
- Document responsible use clearly.
- Make refusal behavior strong.

### Risk 2: Multi-agent runs become chaotic

Mitigation:

- Use a lead coordinator.
- Require task state.
- Limit parallelism.
- Add pause and stop.
- Log every tool call.

### Risk 3: Reports contain false positives

Mitigation:

- Add Verification Agent.
- Require evidence.
- Use finding lifecycle.
- Separate leads from verified findings.

### Risk 4: License contamination from inspiration projects

Mitigation:

- Do not copy source code.
- Do not copy assets.
- Do not copy exact prompts.
- Implement clean-room architecture.
- Keep attribution notes if inspiration is mentioned.

### Risk 5: Too many features delay launch

Mitigation:

- Ship phases.
- Start with adapter cleanup, ScopeGuard, and planning.
- Add Team Mode after core safety works.
- Keep v1 narrow and polished.

---

## 19. Open Questions

1. Should Mantis use YAML, JSON, or TOML as the primary config format?
2. Should Team Mode be enabled by default or opt-in?
3. What is the default model routing strategy?
4. Should scope manifests require cryptographic signatures in v1 or v2?
5. Should high-risk tools be completely unavailable in open-source builds?
6. Should report export to HackerOne and Bugcrowd be manual-only?
7. Should the web UI be included in v1 or postponed?
8. Should Mantis provide hosted cloud mode later?
9. How should plugin signing be managed?
10. What demo target should be included for safe onboarding?

---

## 20. Suggested GitHub Issues

Create these issues in the repository:

```text
[PRD] Add multi-harness adapter layer
[PRD] Add ScopeGuard and IntentGate
[PRD] Add /mantis-plan command
[PRD] Upgrade /mantishack one-command workflow
[PRD] Add Team Mode coordinator
[PRD] Add agent registry and security agent roles
[PRD] Add skill-embedded MCP architecture
[PRD] Add hash-anchored report editing
[PRD] Add finding lifecycle state machine
[PRD] Add evidence verification command
[PRD] Add Tmux live engagement view
[PRD] Add hierarchical AGENTS.md generation
[PRD] Add model routing by task category
[PRD] Add safe tool registry
[PRD] Improve report templates
[PRD] Add demo mode and demo target
[PRD] Add adapter health checks to mantis doctor
```

---

## 21. Implementation Prompt for Claude / Codex / OpenCode

Use this prompt inside the repo:

```text
You are working inside the MantisHack repository.

Your task is to implement the next product upgrade described in docs/PRD_MANTISHACK_AI_NATIVE_SECURITY_HARNESS.md.

Rules:
1. Do not remove authorization or scope enforcement.
2. Do not add unsafe default behavior.
3. Keep all active network traffic routed through mantis-egress.
4. Preserve existing CLI behavior.
5. Separate core logic from host-specific adapters.
6. Prefer small, reviewable commits.
7. Add tests for every safety-critical component.
8. Do not copy code, assets, or prompts from Oh My OpenAgent or other restricted-license projects.
9. Implement ideas cleanly using original code.
10. Update docs after each feature.

Start with Phase 1:
- Create a harness adapter abstraction.
- Move Claude Code, Codex CLI, OpenCode, and standalone CLI integration behind this abstraction.
- Add adapter health checks to mantis doctor.
- Add tests.
- Update README.
```

---

## 22. Final Product Narrative

MantisHack should feel like this:

```text
A founder, developer, or security researcher opens their AI coding CLI.
They type /mantishack.
Mantis asks for scope.
Mantis plans the engagement.
A visible AI security team starts working.
Recon maps the surface.
Specialists test only what is allowed.
Verification turns leads into evidence-backed findings.
Reports are generated professionally.
Everything is logged, scoped, and defensible.
```

That is the product.

Not just an AI scanner.

Not just a wrapper around tools.

Not just another terminal bot.

**MantisHack becomes the authorized AI security harness for the modern software world.**
