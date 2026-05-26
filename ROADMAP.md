# Mantis Integration Roadmap

Open-source pentesting tools and capabilities to integrate or take inspiration from, organized by priority and architectural fit.

> **Architectural principle:** Mantis's differentiator isn't feature breadth — it's the scope-enforced egress, cryptographic evidence chain, and claim verification layer. Every integration should route through `mantis-egress` and produce verifiable claims. Frame integrations as *"Mantis runs X with provenance and scope enforcement"* rather than *"Mantis is a Rust rewrite of X."*

---

## Priority 1 — Highest ROI

### `mantis-nuclei` — Nuclei template engine integration
- **Upstream:** [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) (MIT)
- **Why:** Instant access to 10,000+ community-maintained vulnerability templates (CVEs, misconfigurations, exposures, takeovers).
- **Approach:** Parse Nuclei YAML templates as a hypothesis source feeding `mantis-hypothesis`. Execute through `mantis-egress`. Templates become evidence-backed claims.
- **Effort:** Medium. Template DSL is well-documented and the matcher logic is straightforward.
- **Impact:** Massive coverage expansion with one adapter crate.

### `mantis-cloud-aws` / `mantis-cloud-azure` / `mantis-cloud-gcp` — Cloud security
- **Upstream inspiration:** [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) (Apache-2.0), [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) (GPL-2.0, inspiration only), [RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu) (BSD-3-Clause)
- **Why:** Cloud is the biggest current gap. Massive enterprise demand. Prowler alone has 300+ AWS checks.
- **Approach:** Port Prowler's check definitions to Rust, or implement clean-room equivalents. Each cloud as its own crate to keep auth/SDK dependencies isolated.
- **License note:** Prowler is Apache-2.0 — directly portable. ScoutSuite is GPL — inspiration only.
- **Effort:** Large per cloud, but parallelizable.
- **Impact:** Unlocks enterprise pentest engagements.

### `mantis-ad` — Active Directory & Windows
- **Upstream inspiration:** [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) (BSD-2-Clause), [fortra/impacket](https://github.com/fortra/impacket) (Apache-1.1), [ly4k/Certipy](https://github.com/ly4k/Certipy) (MIT)
- **Why:** Biggest gap on the network/internal side. AD pentesting is core to red team engagements.
- **Approach:** Native Rust SMB/LDAP/Kerberos/MSSQL protocol implementations. Start with enumeration (users, shares, ACLs), then move to credential operations and AD CS abuse.
- **Effort:** Large — protocol implementations are non-trivial.
- **Impact:** Opens entire internal/red-team market.

### `mantis-defectdojo` — Vulnerability management output
- **Upstream:** [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) (BSD-3-Clause)
- **Why:** Most-used open-source vulnerability management platform. Direct integration makes Mantis immediately usable in real enterprise security programs.
- **Approach:** Output adapter in `mantis-report` that pushes findings to DefectDojo via its REST API. Map Mantis claims to DefectDojo findings with full evidence chain attached.
- **Effort:** Small. Well-documented API.
- **Impact:** Enterprise-ready in days, not months.

---

## Priority 2 — High Value

### `mantis-recon` — Reconnaissance toolchain
- **Upstream:** ProjectDiscovery suite (all MIT) — [subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx), [katana](https://github.com/projectdiscovery/katana), [naabu](https://github.com/projectdiscovery/naabu), [dnsx](https://github.com/projectdiscovery/dnsx), [tlsx](https://github.com/projectdiscovery/tlsx), [cdncheck](https://github.com/projectdiscovery/cdncheck)
- **Also:** [owasp-amass/amass](https://github.com/owasp-amass/amass) (Apache-2.0)
- **Why:** Complete recon pipeline. Amass's graph database approach pairs well with Mantis's capability-graph chain discovery.
- **Approach:** Reimplement core logic in Rust per tool, or vendor as subprocesses behind `mantis-egress`. Probably a mix: subfinder/httpx/dnsx as native Rust, larger tools as sandboxed plugins.
- **Effort:** Medium per component.
- **Impact:** Closes recon gap entirely.

### `mantis-secrets` — Secret scanning
- **Upstream:** [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (MIT), [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) (AGPL-3.0, inspiration only)
- **Why:** Exposed secrets are among the highest-impact findings. Easy to scan during recon (JS files, public repos, response bodies).
- **Approach:** Regex + entropy-based detection on artifacts crawled by `mantis-crawler` and `mantis-scanner-http`. Verify findings by attempting authentication (where authorized).
- **Effort:** Small to medium.
- **Impact:** Quick wins, high-severity findings.

### `mantis-api` — API-specific testing
- **Upstream inspiration:** [assetnote/kiterunner](https://github.com/assetnote/kiterunner) (Apache-2.0), [dolevf/graphw00f](https://github.com/dolevf/graphw00f) (BSD-3-Clause), graphql-cop
- **Why:** Modern apps are API-driven. Most pentesting tools handle APIs poorly. GraphQL, gRPC, and OpenAPI-aware testing is genuinely underserved.
- **Approach:**
  - OpenAPI/Swagger schema parsing → automatic endpoint enumeration with parameter fuzzing
  - GraphQL introspection + query mutation testing
  - gRPC reflection-based discovery (extend `mantis-proto`)
  - Route-aware fuzzing instead of brute-force path discovery
- **Effort:** Medium.
- **Impact:** Differentiator. Few tools do this well.

### `mantis-payloads` — Payload corpus
- **Upstream:** [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (MIT), [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) (MIT)
- **Why:** Feeds `mantis-primitive` and `mantis-fuzzer` with battle-tested payloads.
- **Approach:** Vendor as a structured corpus crate. Categorized by vulnerability class. Versioned for reproducibility (important for your evidence chain).
- **Effort:** Small.
- **Impact:** Improves quality of automated exploitation attempts.

---

## Priority 3 — Strategic Additions

### `mantis-trivy` — Container & dependency scanning
- **Upstream:** [aquasecurity/trivy](https://github.com/aquasecurity/trivy) (Apache-2.0)
- **Why:** Supply-chain coverage. Container images, IaC files, SBOM analysis.
- **Approach:** Either shell out to Trivy or port specific check categories. Output integrates with existing SARIF/OpenVEX reporters.
- **Effort:** Small if shelling out, large if porting.

### `mantis-web-fuzz` — Advanced web fuzzing
- **Upstream inspiration:** [ffuf/ffuf](https://github.com/ffuf/ffuf) (MIT), [epi052/feroxbuster](https://github.com/epi052/feroxbuster) (MIT, already Rust)
- **Why:** `mantis-fuzzer` is grammar-aware/coverage-based. Adding HTTP-specific modes (vhost, parameter, header, path, recursive) closes a gap.
- **Approach:** New crate or extend `mantis-fuzzer` with HTTP mode. feroxbuster is Rust and MIT-licensed — directly compatible.
- **Effort:** Small to medium.

### `mantis-mobile` — Mobile application testing
- **Upstream inspiration:** [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) (GPL-3.0, inspiration only), [frida/frida](https://github.com/frida/frida) (wxWindows License)
- **Why:** Significant market, mostly underserved by automated tooling.
- **Approach:** Static analysis of APK/IPA files (manifest, permissions, hardcoded secrets, insecure config). Dynamic via Frida bindings.
- **License note:** Avoid copying MobSF code — GPL conflicts with your Apache/MIT.
- **Effort:** Large.

### `mantis-binary` — Binary analysis primitives
- **Upstream:** [angr/angr](https://github.com/angr/angr) (BSD-2-Clause), [radareorg/radare2](https://github.com/radareorg/radare2) (LGPL-3.0 with exceptions)
- **Why:** Enables binary exploitation primitives, useful for the synthesizer.
- **Approach:** r2pipe bindings or angr via Python subprocess. Keep at arms-length given LGPL complexity.
- **Effort:** Medium.

---

## Priority 4 — Ecosystem & Quality

### Threat intelligence feeds
Lives under [`mantis-threat-intel`](./crates/mantis-threat-intel). One crate, one module per feed source, behind a unified Mantis-facing API.

- [x] **KEV (Known Exploited Vulnerabilities) prioritization** — `mantis_threat_intel::kev::KevCatalog` parses the CISA feed, exposes O(1) `is_kev` / `priority` / `lookup`, and scores ransomware-linked CVEs at 100/100.
- [x] **CVE/NVD ingestion** — `mantis_threat_intel::nvd` parses NVD CVE 2.0 envelopes into `Cve` records with primary CVSS (v4 > v3.1 > v3.0 > v2), severity bucket, CWE list, and a `CveIndex` for many-CVE lookup.
- [x] **ExploitDB integration** — `mantis_threat_intel::exploitdb` parses the `files_exploits.csv` catalog and exposes `exploits_for_cve` / `has_public_exploit` for primitive enrichment and hypothesis weighting.
- [x] **GitHub Security Advisory feed** — `mantis_threat_intel::ghsa` parses OSV-format advisories with `Advisory::from_json`, picks the highest-version CVSS via `primary_cvss`, and supports many-advisory CVE → GHSA lookup through `AdvisoryIndex`.

### Reporting integrations

- [x] **Slack / Discord / Teams notifications** — [`mantis-notify`](./crates/mantis-notify) ships provider-agnostic `Notification` + per-provider payload formatters (Slack Block Kit, Discord embed, Teams MessageCard). HTTP delivery is owned by the daemon's dispatcher so it routes through `mantis-egress`.
- [x] **Jira / Linear ticket creation** — `mantis_notify::jira` emits a Jira REST v3 create-issue body (ADF description, configurable project/issue type/priority/labels). `mantis_notify::linear` emits the `issueCreate` GraphQL mutation envelope with severity auto-mapped to Linear's 0–4 priority scale.
- [x] **GitHub Security tab integration (SARIF upload)** — `mantis_notify::github_sarif` gzip+base64-encodes a SARIF document and wraps it in the `POST /repos/{owner}/{repo}/code-scanning/sarifs` envelope (commit_sha, ref, tool_name, checkout_uri, started_at).
- [x] **HackerOne / Bugcrowd direct submission** — `mantis_notify::hackerone` emits the JSON:API `reports` create body (severity auto-mapped to H1 rating, weakness_id and structured_scope passthrough). `mantis_notify::bugcrowd` emits the `submissions` body with severity auto-mapped to VRT P1–P5 and target relationship.

### Operator experience
- Web UI improvements (live scan visualization, evidence inspection)
- VS Code extension for engagement management
- Mobile companion app for status / notifications
- Resume-interrupted-scans with full state restoration

### Compliance & frameworks
Lives under [`mantis-compliance`](./crates/mantis-compliance). Static lookup tables + typed identifiers, no network.

- [x] **CWE classification** — `mantis_compliance::Cwe` typed wrapper (parse / display / serde).
- [x] **OWASP Top 10 (2021) coverage** — `mantis_compliance::OwaspTop10` enum + `owasp_for_cwe` mapping covering the Notable-CWEs sets from the 2021 release.
- [x] **MITRE ATT&CK technique mapping** — `mantis_compliance::mitre` exposes `Technique`, `Tactic`, a curated catalog of common pentest-report techniques, and a `technique_for_cwe` heuristic mapper.
- [x] **OWASP ASVS coverage matrix** — `mantis_compliance::asvs` ships the 14 V-chapter taxonomy + `asvs_for_cwe` mapping for primary CWE → chapter tagging.
- [x] **OWASP MASVS coverage** — `mantis_compliance::masvs` ships the 7-category v2 taxonomy (STORAGE/CRYPTO/AUTH/NETWORK/PLATFORM/CODE/RESILIENCE) + CWE mapping for mobile findings.
- [x] **PCI-DSS / SOC2 / HIPAA finding tagging** — `mantis_compliance::regulatory` provides `PciDssRequirement` (Req 1–12), `Soc2Criterion` (CC6/CC7/CC8, A1, C1, PI1, P), `HipaaSafeguard` (Admin/Physical/Technical) + a unified `regulatory_for_cwe → RegulatoryTags` triple.

### Testing & validation

- [x] **Regression testbed catalog** — `mantis_bench::testbeds` ships static `Testbed` entries for [DVWA](https://github.com/digininja/DVWA), [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [WebGoat](https://github.com/WebGoat/WebGoat), and a [VulnHub](https://www.vulnhub.com/) placeholder — each with Docker image, default port, expected `vuln_class` findings, and recommended scan profile. Harness for actual run/compare lives in the engagement runner.
- [x] **Public benchmark suite vs. Nuclei, ZAP, Nessus** — `mantis_bench::baseline` provides `BaselineScanner` (Nuclei/ZAP/Nessus), `FindingSet`, `ConfusionStats` (precision/recall/F1), and `BenchmarkRow` capturing Mantis-only vs baseline-only deltas against ground truth.
- [ ] Reproducibility tests for evidence chain — tracked in `mantis-verify` / `mantis-chain` (chain replays exist; CI-level reproducibility harness still pending).

---

## AI Agent Differentiation

Mantis's AI integration (Claude Code, Codex, OpenCode) is already a differentiator. Worth studying:

- [PentestGPT](https://github.com/GreyDGL/PentestGPT) (MIT) — USENIX Security 2024 paper, three-module reasoning design
- [PentAGI](https://github.com/vxcontrol/pentagi) — multi-agent architecture, Docker sandboxing
- Anthropic's [computer-use](https://docs.anthropic.com/en/docs/build-with-claude/computer-use) — relevant for browser-based exploitation steps

Consider: a `mantis-agent` crate exposing primitives that agents call (rather than agents wrapping Mantis). Agents stay in their host CLI; Mantis stays the substrate.

---

## License Compatibility Quick Reference

Mantis is dual-licensed Apache-2.0 OR MIT. Compatibility for direct code integration:

| Upstream license | Direct integration | Notes |
|---|---|---|
| MIT | ✅ Yes | Most permissive |
| BSD (2/3-Clause) | ✅ Yes | Compatible |
| Apache-2.0 | ✅ Yes | Native fit |
| ISC | ✅ Yes | MIT-equivalent |
| MPL-2.0 | ⚠️ File-level | MPL files stay MPL |
| LGPL-3.0 | ⚠️ Dynamic link only | Avoid static linking |
| GPL-2.0 | ❌ Incompatible | Apache patent clause conflicts |
| GPL-3.0 | ❌ Infects project | Inspiration only |
| AGPL-3.0 | ❌ Network-triggering | Inspiration only |

**Practical pattern:** Keep GPL-tool integrations as optional plugins users install separately so Mantis core stays Apache/MIT clean. The WASM plugin host (`mantis-plugin`) is the right place for this.

---

## Suggested Sequencing (12-month view)

**Q1 — Foundation**
- `mantis-nuclei` (template engine)
- `mantis-defectdojo` (output adapter)
- `mantis-payloads` (corpus vendoring)

**Q2 — Coverage**
- `mantis-recon` (subfinder/httpx/katana equivalents)
- `mantis-secrets` (gitleaks-style scanning)
- `mantis-api` (OpenAPI/GraphQL)

**Q3 — Cloud**
- `mantis-cloud-aws` (Prowler port)
- `mantis-cloud-azure`
- `mantis-cloud-gcp`

**Q4 — Internal/Red Team**
- `mantis-ad` (AD enumeration)
- `mantis-ad` credential operations
- AD CS module

---

## Notes

- Every integration must route through `mantis-egress` — no exceptions. That's the security invariant.
- Every integration must produce verifiable claims with evidence — that's the product invariant.
- Prefer Rust-native implementations for core paths; sandboxed plugins (WASM or subprocess) for everything else.
- License attribution belongs in [`CREDITS.md`](./CREDITS.md) and `tools/recon/THIRD_PARTY.md` — keep them current as integrations land.
