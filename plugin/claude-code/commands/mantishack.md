---
description: One-shot end-to-end Mantis pentest, driven by the LLM through the mantis MCP server. Use when the user says `/mantishack <target>`. Inspired by hacker-bob's MCP-tool-orchestrated model; the host LLM owns the FSM and the wall-clock budget, replacing the rigid `mantis pentest` poll loop.
---

You are kicking off an authorized Mantis engagement against the target
the user named. **You do not call `mantis pentest` anymore.** That
command's poll loop has no client-side budget enforcement and hangs on
recon dead-ends (see the `app.tenkara.ai` regression). Instead, drive
the engagement through the `mantis` MCP server's tools, with the
`mantis-orchestrator` sub-agent owning the FSM.

## Before any tool call — two gates, in order

1. **Authorization gate (legal).** Ask the user:
   > Do you have **explicit written authorization** to run
   > offensive-security tests against `<target>`?

   If the answer is anything other than a clear yes, refuse and stop.
   Mantis enforces scope cryptographically at the egress proxy, but
   the legal gate is yours.

2. **Scope gate (technical).** Print the target the user wants to test
   and ask them to confirm. For a packaged app (`.apk`, `.ipa`, `.exe`,
   `.dmg`, `.app`), mention that Mantis will extract embedded URLs and
   include those.

## Preflight

Verify the local setup is healthy before delegating to the
orchestrator:

```sh
# Daemon must be running so the MCP server can reach it.
pgrep -x mantis-daemon >/dev/null || (mantis-daemon &)
sleep 1
```

If the user has never run `/mantis:doctor`, suggest they do so once to
confirm `mantis-mcp` is on PATH and the operator key is present.

## Delegation

Once both gates pass, **spawn the `mantis-orchestrator` sub-agent**
with the user's target as input. The orchestrator owns the full FSM:

```
CREATE → AUTHORIZE → RECON → LIST_SURFACES (redirect loop) → REPORT
```

The orchestrator enforces a tool-call budget (60 MCP calls per
engagement) so we do not relive the 46-minute `app.tenkara.ai` hang.
Stream every progress line the orchestrator emits back to the user.

## When the orchestrator finishes

The orchestrator's final message includes the engagement id, surfaces
discovered, redirect-followed count, and the path to `report.md`.
Offer the user follow-ups:

- `/mantis:status <id>` — re-inspect engagement state
- `/mantis:resume <id>` — continue if recon stopped early
- Re-rendering the report with `mantis-reporter` if they want a fresh
  copy

## LLM credentials — no API key needed

Mantis's recon, hypothesis, verifier, and report stages run without an
LLM. The synthesizer's LLM payload path uses the `claude-cli` provider
by default (shells out to the local `claude` CLI; reuses Claude Code's
own auth). The user can confirm reachability with:

```sh
mantis llm probe --provider claude-cli
```

Other providers (`anthropic`, `openai`) require their respective env
keys; the default does not.

## Hard rules

- **Refuse to run** if the user cannot confirm authorization.
- **Do not call `mantis pentest` from this command.** That path is the
  bug we're working around.
- **Do not authorize scope** beyond what the user explicitly named.
  The orchestrator will follow same-host redirects; cross-host
  redirects need a fresh user confirmation before re-authorizing.
