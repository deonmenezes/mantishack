<div align="center">

<img src="docs/assets/mascot/hero.png" alt="Mantis — offensive-security mascot" width="640" />

# Mantis

`stalk · wait · strike · hold`
**Ethically hack and discover vulnerabilities in any software with the power of AI.**

[Quickstart](docs/site/quickstart.md) ·
[Docs](docs/site/README.md) ·
[Responsible Use](docs/site/responsible-use.md) ·
[mantishack.com](https://mantishack.com)

</div>

---

> ## ⚠️  Authorized Testing Only
>
> **Mantis is offensive-security tooling. Use it only against systems you own or have explicit written authorization to test.**
>
> - Running Mantis against systems without permission is illegal in most jurisdictions.
> - Mantis enforces scope cryptographically at the egress proxy, but the **legal gate is yours**.
> - The CLI refuses to start without `--i-have-authorization`. Passing that flag is a self-attestation, not a legal credential.
> - See [Responsible Use](docs/site/responsible-use.md) for the full policy.

---

```
███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗
████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝
██╔████╔██║███████║██╔██╗ ██║   ██║   ██║███████╗
██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██║╚════██║
██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝
```

Daemon-driven, evidence-grade automated security research platform.

Mantis plans, executes, verifies, and reports authorized offensive-security
engagements with cryptographically-verifiable provenance. It writes working
exploits, runs continuously against in-scope assets, and improves
measurably between engagements through learned playbooks, evolutionary
self-tuning, and a self-generated training corpus.

## Install

**Via npm / bun / yarn / pnpm** (recommended, one platform binary auto-selected):

```sh
npm  install -g mantishack
bun  add    -g mantishack
yarn global add mantishack
pnpm add    -g mantishack
```

**Or one-line from source:**

```sh
curl -fsSL https://raw.githubusercontent.com/deonmenezes/mantishack/main/install.sh | bash
```

The installer:
1. Builds `mantis-daemon` and `mantis` (release) into `~/.local/bin`.
2. Detects which AI CLI(s) you have installed and copies the matching
   plugin into the CLI's plugin directory:

   | CLI | Detection | Plugin dir |
   |---|---|---|
   | Claude Code | `claude` on PATH or `~/.claude/` | `~/.claude/plugins/mantis/` |
   | Codex CLI   | `codex` on PATH or `~/.codex/` | `~/.codex/plugins/mantis/` |
   | OpenCode    | `opencode` on PATH or `~/.config/opencode/` | `~/.config/opencode/plugins/mantis/` |

After install you can drive Mantis from any of those CLIs:

```
/mantishack <target>       one-shot end-to-end pentest (every step in one command)
/mantis-scan <target>      kick off an authorized engagement
/mantis-status [id]        engagement status
/mantis-claim <id>         inspect a verified finding
/mantis-report <id>        render a disclosure-ready report
/mantis-daemon             start/stop the daemon
```

`/mantishack` accepts:
- web URL: `https://example.com`
- domain: `example.com`
- Android: `app.apk`
- iOS: `app.ipa`
- Windows: `app.exe`
- macOS: `app.dmg` / `app.app`
- API: any URL pointing at an OpenAPI spec or REST endpoint

Embedded URLs are extracted from packaged-app binaries via
`strings` and pentest-routed through the same web pipeline.

### Don't have an AI CLI yet?

```sh
# Claude Code
curl -fsSL https://claude.ai/install.sh | bash

# Codex CLI (OpenAI)
npm install -g @openai/codex

# OpenCode
curl -fsSL https://opencode.ai/install | bash
```

Then rerun the Mantis installer to wire the plugin in.

## Standalone usage (no AI CLI)

```sh
mantis-daemon &                                    # start the daemon
mantis engagement create "demo" --target https://x # create an engagement
mantis engagement start "demo"                     # begin scanning
mantis engagement status "demo" --watch            # live status
mantis engagement report "demo" --format pdf       # render report
```

## Requirements

- One supported host CLI: Claude Code, Codex, or another MCP-capable host — required for the slash-command surface (`/mantishack`, etc.). The standalone CLI (`mantis hack`, `mantis pentest`) has no AI-CLI dependency.
- A working Rust toolchain — only for source builds. The prebuilt npm binary has no deps.

Recon tools (subfinder, httpx, katana, nuclei, jwt_tool) are **auto-installed** into the per-repo `tools/recon/bin/` directory by `install.sh` / `mantis init`. No manual `go install` step needed; the recon-agent prepends that directory to PATH at engagement start. Run `mantis doctor` to confirm what's installed. Mantis runs without any of them — coverage just narrows.

## Roadmap

See [`ROADMAP.md`](./ROADMAP.md) for the integration roadmap — priority-ordered plan for `mantis-nuclei`, `mantis-cloud-{aws,azure,gcp}`, `mantis-ad`, `mantis-defectdojo`, `mantis-recon`, `mantis-secrets`, `mantis-api`, `mantis-payloads`, plus strategic additions and a 12-month sequencing plan. Architectural invariant: every integration routes through `mantis-egress` and produces verifiable claims.

## Upstream credit — Hacker Bob

**Mantis is built on top of [Hacker Bob](https://github.com/vmihalis/hacker-bob) (Apache-2.0, Copyright 2026 Michail Vasileiadis).** The agent prompts, role prompts, slash commands, capability playbook conventions, chain-attempt outcome enum, severity-ladder rules, and `bob-hunt` workflow shape are derived from Hacker Bob.

For full transparency, three documents describe the derivation:

- [`PORTING.md`](./PORTING.md) — exhaustive per-file, per-symbol, per-tool, per-marker port inventory (104 ported files, every renamed symbol, every changed constant)
- [`CONTRAST.md`](./CONTRAST.md) — operator-facing side-by-side comparison (what Mantis adds vs ports vs lacks)
- [`NOTICE`](./NOTICE) — legal attribution, upstream NOTICE reproduced verbatim per Apache-2.0 §4(d), and an apology for an initial §4 compliance gap that has now been fully remediated

The Mantis Rust daemon, MCP server implementation, egress proxy, FSM runtime, merkle event log, and Kubernetes operator are independent original work. If you find Mantis useful, please also credit Hacker Bob — without it, Mantis would not exist.

## Every other project we credit

For the full thank-you list — AI models (NousResearch/Hermes, Anthropic Claude), runtimes (Linux, Rust, Tokio, Node.js, Bun, Docker), cryptography (BLAKE3, ed25519-dalek, ring, rustls), storage (RocksDB), all the ProjectDiscovery recon tools (subfinder, httpx, katana, nuclei, chaos, dnsx, interactsh, notify), JWT/auth tools (ticarpi/jwt_tool), OWASP Amass, Patchright, Bearer, Trivy, trufflehog, hashcat, Hydra, standards (CVSS, CWE, SARIF, OpenVEX, OWASP Top 10), the web stack (Vite, React, Tailwind, shadcn/ui, Radix UI, Supabase), CI (GitHub Actions, cargo-deny), bug bounty platforms, communities, and the broader OSS hacking ecosystem — see [`CREDITS.md`](./CREDITS.md).

Per-recon-binary licenses + install-time-fetch vs vendoring rationale live in [`tools/recon/THIRD_PARTY.md`](./tools/recon/THIRD_PARTY.md).

## Workspace layout

```
crates/
├── mantis-core/               shared types, errors, traits (no I/O)
├── mantis-proto/              protobuf + tonic-generated types
├── mantis-workspace/          workspace paths, key management, keychain
├── mantis-event-store/        RocksDB-backed event log + Merkle evidence
├── mantis-scope/              scope DSL: parse, sign, verify, evaluate
├── mantis-egress/             scope-enforcing TCP/HTTP egress proxy
├── mantis-scanner-http/       HTTP probing + content discovery
├── mantis-hypothesis/         rule-based hypothesis generator
├── mantis-planner/            MCTS planner with UCB1
├── mantis-posterior/          Bayesian posterior management
├── mantis-claim/              claim model + verifiers
├── mantis-primitive/          exploit-primitive catalog
├── mantis-report/             6 report formats (md/pdf/h1/bugcrowd/sarif/openvex)
├── mantis-playbook/           playbook distiller
├── mantis-memory/             cross-engagement memory
├── mantis-operator-model/     operator preference profile
├── mantis-trajectory/         trajectory compression for training
├── mantis-tuner/              NSGA-II evolutionary tuner
├── mantis-hibernation/        snapshot/restore for serverless
├── mantis-scheduler/          cron + diff reports
├── mantis-tenant/             multi-tenant isolation
├── mantis-k8s/                Kubernetes operator
├── mantis-registry/           OCI plugin registry + Ed25519 signature verify
├── mantis-fuzzer/             grammar-aware coverage fuzzer
├── mantis-sandbox/            record-replay / wasmtime / Firecracker
├── mantis-synthesizer/        corpus + fuzzer + symbolic + LLM pipeline
├── mantis-chain/              capability-graph chain discovery
├── mantis-tui/                terminal-UI model
├── mantis-tui-ratatui/        ratatui terminal renderer
├── mantis-web-ui/             daemon-served Web UI (HTTP + SSE)
├── mantis-gateway/            7-platform operator gateway
├── mantis-runtime/            reactor-per-core / NUMA pinning
├── mantis-crawler/            HTML+JS static endpoint extractor
├── mantis-video/              ffmpeg-based session video capture
├── mantis-benches/            criterion benchmarks vs PRD §11
├── mantis-plugin/             WASM 0.2 component-model plugin host
├── mantis-verify/             standalone evidence-chain verifier (binary)
├── mantis-daemon/             tonic gRPC server + engagement loop (binary)
└── mantis-cli/                operator CLI client (binary)
```

The security-critical crate is `mantis-egress` — it is the single network
boundary. All HTTP traffic from any other component routes through it.
This is enforced at the proxy socket layer, not advisorially.

## Deployment

`deploy/` contains templates for the five §14 deployment modes:

- `deploy/docker/Dockerfile`             — multi-stage build, non-root runtime
- `deploy/systemd/mantis-daemon.service` — hardened systemd unit for VPS
- `deploy/k8s/mantis-deployment.yaml`    — Kubernetes Deployment + RBAC + PVC
- `deploy/modal/mantis_modal.py`         — hibernating serverless on Modal

See `deploy/README.md` for the install commands per mode.

## Authorization

Mantis runs **only against assets you are explicitly authorized to test**.
Every engagement requires a signed scope manifest. The plugin slash
commands re-verify the user has authorization before running any scan.

## License

Dual-licensed under [Apache-2.0](./LICENSE-APACHE) OR [MIT](./LICENSE-MIT), at your option.

Third-party attributions — including the Hacker Bob (Apache-2.0) inspiration documented in [`NOTICE`](./NOTICE) — are preserved per Apache-2.0 §4(d). When redistributing this project or a derivative work, you must propagate the `NOTICE` file's attribution section.
