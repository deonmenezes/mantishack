# CREDITS.md — Every project that made Mantis possible

Mantis stands on a lot of shoulders. This file credits every open-source project, model, runtime, library, tool, standard, and community that meaningfully contributes to Mantis — beyond the formal `Apache-2.0 §4` attribution machinery in [`NOTICE`](./NOTICE), [`PORTING.md`](./PORTING.md), and [`CONTRAST.md`](./CONTRAST.md).

If you contributed an upstream that we use and aren't credited here, please open an issue or a PR — we want this list to be complete.

---

## 1. Primary derivation — Hacker Bob

**[vmihalis/hacker-bob](https://github.com/vmihalis/hacker-bob)** (Apache-2.0, Copyright 2026 Michail Vasileiadis). The agent prompts, role prompts, slash commands, capability playbook conventions, chain-attempt outcome enum, severity-ladder rules, and `bob-hunt` workflow shape are derived from Hacker Bob. See [`PORTING.md`](./PORTING.md) for the exhaustive 104-file inventory, [`CONTRAST.md`](./CONTRAST.md) for the side-by-side comparison, and [`NOTICE`](./NOTICE) for the formal Apache-2.0 attribution and apology.

---

## 2. AI models and LLM ecosystem

| Project | Where it shows up | License |
|---|---|---|
| **[Nous Research — Hermes](https://huggingface.co/NousResearch)** | Hermes-family open LLMs (Hermes 2, Hermes 3) for fine-tuning and inference patterns | varies per model (Apache-2.0 / Llama / Mistral) |
| **[Anthropic Claude (via API + Claude Code)](https://www.anthropic.com/)** | Primary host LLM for agent execution; Claude Code is the canonical MCP host | proprietary, used as a service |
| **[OpenAI Codex CLI](https://github.com/openai/codex)** | Secondary host LLM CLI integration | Apache-2.0 |
| **[OpenCode](https://opencode.ai/)** | Tertiary host LLM CLI integration | varies |
| **[Model Context Protocol (MCP) spec](https://github.com/modelcontextprotocol)** | Wire protocol Mantis speaks to host LLMs | MIT |
| **[rmcp](https://github.com/modelcontextprotocol/rust-sdk)** | Rust MCP implementation Mantis builds on | MIT |

---

## 3. Operating systems & runtimes

| Project | Where it shows up | License |
|---|---|---|
| **[Linux kernel](https://kernel.org/)** | Primary runtime for the daemon, recon binaries, sandboxing | GPL-2.0 |
| **[GNU userland / glibc / musl](https://www.gnu.org/)** | Standard runtime for Linux builds | GPL / LGPL |
| **[macOS / Darwin](https://opensource.apple.com/)** | Secondary supported runtime | APSL + various |
| **[Rust toolchain](https://www.rust-lang.org/)** | Compiler, cargo, rustup | Apache-2.0 / MIT |
| **[Node.js](https://nodejs.org/)** | npm package distribution, the `bin/mantis*.js` shims | MIT |
| **[Bun](https://bun.sh/)** | Alternate JS runtime for the npm package | MIT |
| **[Deno](https://deno.com/)** | Optional JS runtime compatibility | MIT |
| **[Docker](https://www.docker.com/) / [OCI](https://opencontainers.org/)** | Containerization (`deploy/docker/Dockerfile`) | Apache-2.0 |
| **[Homebrew](https://brew.sh/)** | macOS distribution (`Formula/mantishack.rb`) | BSD-2-Clause |

---

## 4. Cryptography & integrity

| Project | Where it shows up | License |
|---|---|---|
| **[BLAKE3](https://github.com/BLAKE3-team/BLAKE3)** | Merkle event-log leaves, content hashing throughout | CC0 / Apache-2.0 |
| **[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)** | Workspace key signing + Merkle tree heads | BSD-3-Clause |
| **[ring](https://github.com/briansmith/ring)** | TLS primitives via rustls | ISC + BSD + MIT |
| **[rustls](https://github.com/rustls/rustls)** | TLS for outbound HTTP and the egress proxy | Apache-2.0 / MIT / ISC |
| **[zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)** | Secret-wiping on drop in `crates/mantis-auth` | Apache-2.0 / MIT |

---

## 5. Rust async ecosystem & core libraries

| Project | Where it shows up | License |
|---|---|---|
| **[Tokio](https://tokio.rs/)** | Async runtime powering the entire daemon | MIT |
| **[Tower](https://github.com/tower-rs/tower)** | Middleware abstraction for the gRPC server | MIT |
| **[Hyper](https://hyper.rs/)** | HTTP layer | MIT |
| **[reqwest](https://github.com/seanmonstar/reqwest)** | Client side of `mantis-scanner-http` | Apache-2.0 / MIT |
| **[Serde](https://serde.rs/)** | Serialization across every crate | Apache-2.0 / MIT |
| **[serde_json](https://github.com/serde-rs/json)** + **[serde_yaml_ng](https://github.com/acatton/serde-yaml-ng)** + **[toml](https://github.com/toml-rs/toml)** | Format-specific serde adapters | Apache-2.0 / MIT |
| **[Tonic](https://github.com/hyperium/tonic) + [Prost](https://github.com/tokio-rs/prost)** | gRPC + Protobuf for the daemon API | Apache-2.0 / MIT |
| **[anyhow](https://github.com/dtolnay/anyhow) + [thiserror](https://github.com/dtolnay/thiserror)** | Error handling | Apache-2.0 / MIT |
| **[tracing](https://github.com/tokio-rs/tracing)** | Structured logging | MIT |
| **[clap](https://github.com/clap-rs/clap)** | CLI argument parsing | Apache-2.0 / MIT |
| **[schemars](https://github.com/GREsau/schemars)** | JSON-Schema generation for MCP tools | MIT |

---

## 6. Storage

| Project | Where it shows up | License |
|---|---|---|
| **[RocksDB](https://rocksdb.org/)** + **[rust-rocksdb](https://github.com/rust-rocksdb/rust-rocksdb)** | Per-engagement event store | Apache-2.0 / GPL-2.0 |
| **[Supabase](https://supabase.com/)** | Auth + Postgres for the landing page's signup flow | Apache-2.0 |

---

## 7. Offensive-security tooling we invoke or integrate

Recon binaries fetched at install time into `tools/recon/bin/` — full per-binary details in [`tools/recon/THIRD_PARTY.md`](./tools/recon/THIRD_PARTY.md).

| Project | Where it shows up | License |
|---|---|---|
| **[ProjectDiscovery — subfinder](https://github.com/projectdiscovery/subfinder)** | Passive subdomain enumeration | MIT |
| **[ProjectDiscovery — httpx](https://github.com/projectdiscovery/httpx)** | Live-host probe + tech / title / status | MIT |
| **[ProjectDiscovery — katana](https://github.com/projectdiscovery/katana)** | JS-aware crawl | MIT |
| **[ProjectDiscovery — nuclei](https://github.com/projectdiscovery/nuclei)** | Templated checks | MIT |
| **[ProjectDiscovery — nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)** | Community template library | MIT |
| **[ProjectDiscovery — chaos](https://github.com/projectdiscovery/chaos-client)** | Subdomain dataset API client | MIT |
| **[ProjectDiscovery — dnsx](https://github.com/projectdiscovery/dnsx)** | DNS resolution | MIT |
| **[ProjectDiscovery — interactsh](https://github.com/projectdiscovery/interactsh)** | OOB interaction service for SSRF / blind XSS | MIT |
| **[ProjectDiscovery — notify](https://github.com/projectdiscovery/notify)** | Finding-output webhooks | MIT |
| **[OWASP Amass](https://github.com/owasp-amass/amass)** | Recon + asset discovery | Apache-2.0 |
| **[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)** | JWT attack toolkit (subprocess-only, GPL boundary documented) | GPL-3.0 |
| **[OJ/gobuster](https://github.com/OJ/gobuster)** | Brute-force discovery | Apache-2.0 |
| **[Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright)** | Headless browser automation for auth flows (referenced in CONTRAST.md) | Apache-2.0 |
| **[Bearer](https://github.com/Bearer/bearer)** | Static security analysis | Elastic-2.0 |
| **[Trivy](https://github.com/aquasecurity/trivy)** | Vuln scanner | Apache-2.0 |
| **[trufflehog](https://github.com/trufflesecurity/trufflehog)** | Secret detection | AGPL-3.0 |
| **[hashcat](https://hashcat.net/)** | Password recovery (referenced for chain attempts) | MIT |
| **[Hydra](https://github.com/vanhauser-thc/thc-hydra)** | Login brute-forcer (referenced) | AGPL-3.0 |

---

## 8. Standards, taxonomies, and reporting formats

These aren't OSS projects but they're the standards Mantis emits and follows; credit goes to the maintaining bodies.

| Standard | Where it shows up | Maintainer |
|---|---|---|
| **[CVSS v3.1 / v4](https://www.first.org/cvss/)** | Severity scoring on every finding | FIRST.org |
| **[CWE](https://cwe.mitre.org/)** | Weakness classification | MITRE |
| **[SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)** | One of the 6 report output formats | OASIS |
| **[OpenVEX](https://github.com/openvex/spec)** | One of the 6 report output formats | OpenVEX project |
| **[HackerOne report schema](https://api.hackerone.com/)** | One of the 6 report output formats | HackerOne |
| **[Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)** | Vulnerability taxonomy mapping | Bugcrowd |
| **[OWASP Top 10](https://owasp.org/Top10/)** | Bug-class taxonomy | OWASP |

---

## 9. Web stack (landing page + dashboard)

Used in [deonmenezes/mantis-landing-page](https://github.com/deonmenezes/mantis-landing-page) for `mantishack.com`:

| Project | Where it shows up | License |
|---|---|---|
| **[Vite](https://vitejs.dev/)** | Build tool | MIT |
| **[React](https://react.dev/)** | UI framework | MIT |
| **[TypeScript](https://www.typescriptlang.org/)** | Language | Apache-2.0 |
| **[Tailwind CSS](https://tailwindcss.com/)** | Styling | MIT |
| **[shadcn/ui](https://ui.shadcn.com/)** | Component registry | MIT |
| **[Radix UI](https://www.radix-ui.com/)** | Accessible primitives | MIT |
| **[lucide-react](https://lucide.dev/)** | Icon set | ISC |
| **[Supabase JS SDK](https://github.com/supabase/supabase-js)** | Auth client | MIT |

---

## 10. Distribution & CI

| Project | Where it shows up | License |
|---|---|---|
| **[GitHub Actions](https://github.com/features/actions)** | CI + release automation | proprietary, used as a service |
| **[GitHub CLI (`gh`)](https://github.com/cli/cli)** | Operator UX for PRs / issues | MIT |
| **[cargo-chef](https://github.com/LukeMathWalker/cargo-chef)** | Docker layer caching for the daemon image | Apache-2.0 / MIT |
| **[cargo-deny](https://github.com/EmbarkStudios/cargo-deny)** | Dep license & advisory gate | Apache-2.0 / MIT |
| **[rustup](https://rustup.rs/)** | Toolchain manager bootstrapped by `install.sh` | Apache-2.0 / MIT |

---

## 11. Acknowledgement of the broader OSS hacking ecosystem

Mantis builds on decades of open-source offensive-security work. Even when not directly invoked, the following projects shaped the field Mantis operates in and informed our design choices:

- **[Metasploit Framework](https://github.com/rapid7/metasploit-framework)** (BSD-3-Clause) — module pattern, severity model
- **[Burp Suite Community](https://portswigger.net/burp/communitydownload)** (proprietary free tier) — request-replay UX as the workflow gold standard
- **[OWASP ZAP](https://www.zaproxy.org/)** (Apache-2.0) — auto-spider design
- **[sqlmap](https://github.com/sqlmapproject/sqlmap)** (GPL-2.0) — technique catalog and confirmation discipline
- **[Nikto](https://github.com/sullo/nikto)** (GPL-2.0) — checks taxonomy
- **[wpscan](https://github.com/wpscanteam/wpscan)** (proprietary free tier) — WordPress technique inspiration
- **[Semgrep](https://github.com/semgrep/semgrep)** (LGPL-2.1) — pattern-matching philosophy for the static-scan crate
- **[gitleaks](https://github.com/gitleaks/gitleaks)** (MIT) — secret-detection patterns
- **[SecLists](https://github.com/danielmiessler/SecLists)** (MIT) — wordlist conventions
- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** (MIT) — payload-catalog organization
- **[HackTricks](https://github.com/HackTricks-wiki/hacktricks)** (CC-BY-4.0) — knowledge-base structure
- **[crackmapexec / NetExec](https://github.com/Pennyw0rth/NetExec)** (BSD-2-Clause) — network-pivot taxonomy
- **[Nuclei templates community](https://github.com/projectdiscovery/nuclei-templates)** (MIT) — template authorship model

---

## 12. Bug bounty platforms & disclosure programs

Mantis emits reports targeting these platforms. Credit goes to the platforms for hosting authorized testing programs:

- **[HackerOne](https://www.hackerone.com/)**
- **[Bugcrowd](https://bugcrowd.com/)**
- **[Intigriti](https://www.intigriti.com/)**
- **[YesWeHack](https://www.yeswehack.com/)**
- **[Synack](https://www.synack.com/)**
- **[Immunefi](https://immunefi.com/)** (web3)

---

## 13. Communities

The discipline informing this project comes from public security communities. Particular thanks to:

- **[r/netsec](https://www.reddit.com/r/netsec/)** and **[r/bugbounty](https://www.reddit.com/r/bugbounty/)**
- **[The DEF CON community](https://defcon.org/)**
- **[OWASP local chapters](https://owasp.org/chapters/)**
- **[Hacker News security threads](https://news.ycombinator.com/)**
- Disclosure-report authors on **[HackerOne Hacktivity](https://hackerone.com/hacktivity)** and **[Pentester Land's daily list](https://pentester.land/list-of-bug-bounty-writeups.html)** — whose published methodology is referenced in `intel_hints` during hunting

---

## How this list is maintained

- New direct Rust dependency: add to Section 5/6 by category.
- New invoked binary or tool: add to Section 7.
- New AI model or LLM provider: add to Section 2.
- New distribution channel or CI tool: add to Section 10.
- If something we used isn't listed: **open an issue or a PR** — being missing is a bug.

Run `cargo deny check licenses` to validate that every transitive Rust dependency's license is in our allow-list. The full transitive list is generated mechanically by `cargo deny list -f json` and is not duplicated here; this file lists the **direct dependencies and projects you can see Mantis reference**, not the full transitive closure.
