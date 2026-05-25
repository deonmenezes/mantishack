# mantishack

<p align="center">
  <img src="https://raw.githubusercontent.com/deonmenezes/mantishack/main/docs/assets/mascot/hero.png" alt="Mantis — offensive-security mascot" width="480" />
</p>

> Offensive-security daemon — 7-phase FSM (RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT) with parallel hunter sub-agents, cryptographic scope enforcement, and BLAKE3 / Ed25519 Merkle event logs.

---

> ## ⚠️  Authorized Testing Only
>
> **Mantis is offensive-security tooling. Use it only against systems you own or have explicit written authorization to test.**
>
> - Running Mantis against systems without permission is illegal in most jurisdictions.
> - The CLI refuses to start without `--i-have-authorization`.
> - See the [Responsible Use](https://github.com/deonmenezes/mantishack/blob/main/docs/site/responsible-use.md) policy.

---

## Install

```sh
npm  install -g mantishack
bun  add    -g mantishack
yarn global add mantishack
pnpm add    -g mantishack
```

One of the per-platform binary packages (`@deonmenezes/mantis-cli-darwin-arm64`, `@deonmenezes/mantis-cli-darwin-x64`, `@deonmenezes/mantis-cli-linux-x64`, `@deonmenezes/mantis-cli-linux-arm64`) is selected automatically by your platform — no postinstall script, works in Bun's strict mode.

## Quick start

```sh
# 1. Wire the daemon + MCP server into your local AI CLI (idempotent)
mantis init

# 2. One-shot end-to-end pentest against an authorized target
mantis hack app.example.com --i-have-authorization
```

`mantis hack` drives the full 7-phase FSM via the local Claude Code CLI: parallel hunter sub-agents during HUNT, the 3-round verifier cascade (brutalist → balanced → final), evidence-pack assembly, grading, and report rendering.

## Other commands

```sh
mantis pentest <target> --i-have-authorization     # daemon-driven, one-shot
mantis goal "find idor" --target https://...       # goal-directed, multi-wave
mantis find-auth-bugs --target https://...         # legacy unauth/auth-diff
mantis doctor                                      # diagnose local install
mantis --help
```

## Repository

Source, issue tracker, and docs: **https://github.com/deonmenezes/mantishack**

## Upstream credit — Hacker Bob

Mantis is built on top of [**Hacker Bob**](https://github.com/vmihalis/hacker-bob) (Apache-2.0, Copyright 2026 Michail Vasileiadis). The agent prompts, slash commands, capability playbook conventions, chain-attempt outcome enum, and `bob-hunt` workflow shape are derived from Hacker Bob — see the bundled `NOTICE` file for the full attribution. The Mantis Rust daemon and runtime are independent original work.

## License

Dual-licensed under [Apache-2.0](./LICENSE-APACHE) OR [MIT](./LICENSE-MIT), at your option.

Per Apache-2.0 §4(d), the `NOTICE` file bundled with this package preserves the upstream Hacker Bob attribution and must be retained when redistributing this package or a derivative work.
