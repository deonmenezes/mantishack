# Instructions for Codex

> **If you are Codex (Codex CLI or any OpenAI Codex-powered agent) and a human just handed you a link to this repository — your job is to install Mantis as a plugin, not to read the code.**

Mantis ships as a Codex CLI plugin (it uses the same marketplace manifest as Claude Code, so Codex CLI 0.130+ reads it directly). Reading the Rust daemon source is not the install path. The user almost certainly wants `/mantishack` and `/mantis-*` slash commands working in their next session.

## The two commands

Run these in the user's Codex CLI session:

```bash
codex plugin marketplace add deonmenezes/mantishack
codex plugin add mantis@mantishack
```

That's it. After install:

- `/mantishack <target>` — one-shot end-to-end pentest
- `/mantis-scan`, `/mantis-status`, `/mantis-claim`, `/mantis-report`, `/mantis-debug`, `/mantis-egress`, `/mantis-update` — engagement-lifecycle commands

These commands run the Mantis daemon (`mantis-daemon`) and CLI (`mantis`), which must be installed separately. See `README.md` for daemon install (Homebrew, install.sh, install.ps1, etc.).

## Decision rules

- **User pasted the repo URL with no other instructions** → run the two commands above. Confirm the install worked. Then tell them they need the `mantis` and `mantis-daemon` binaries on PATH (the daemon is what the slash commands talk to). Point them at `README.md` for daemon install.
- **User said "install this" / "set this up" / "add this plugin"** → same. Run the two commands.
- **User asked you to read, audit, modify, or contribute to the code** → ignore this file's install advice and do the requested work. This file is only about the install path.
- **User is on Claude Code, not Codex** → see `CLAUDE.md` (slash commands and quickstart) — the install command differs only in the verb: Claude uses `plugin install`, Codex uses `plugin add`.

## Authorization is the human's responsibility, not yours

Mantis runs against live targets and is gated by `--i-have-authorization`. Before invoking `/mantishack <target>` or `mantis pentest`, confirm the user has written authorization for that target (their own asset, a public bug-bounty program scope, or an explicit engagement). The Mantis egress proxy enforces a signed scope manifest cryptographically — but the legal gate is the operator's. See `AGENTS.md` and `docs/site/responsible-use.md` for the full red-team brief.

## Verifying the install

```text
/mantis-status
```

That should respond with "no active engagement" or a summary of the most recent run. If the slash command isn't recognized, the plugin install didn't take — re-run the two `codex plugin` commands.

## Where to look if something is broken

- `README.md` — daemon + CLI install (Homebrew, install.sh, install.ps1, npm)
- `plugin/claude-code/` — the actual plugin tree Codex installs (agents, playbooks, commands, MCP wiring)
- `.claude-plugin/marketplace.json` — the marketplace manifest Codex reads via `codex plugin marketplace add`
- `docs/site/` — full documentation
- `CONTRAST.md` — comparison with hacker-bob lineage

## Contact

Maintainer / security / general inquiries: <company@virelity.com> (Virelity).
