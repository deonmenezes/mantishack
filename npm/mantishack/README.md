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

One of the per-platform binary packages (`@mantishack/cli-darwin-arm64`, `@mantishack/cli-darwin-x64`, `@mantishack/cli-linux-x64`, `@mantishack/cli-linux-arm64`) is selected automatically by your platform — no postinstall script, works in Bun's strict mode.

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

## License

Apache-2.0 OR MIT
