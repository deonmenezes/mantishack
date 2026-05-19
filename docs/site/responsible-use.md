# Responsible Use Policy

> **Use Mantis only against systems you own or have explicit written authorization to test.**

<p align="center">
  <img src="../assets/mascot/hero.png" alt="Mantis mascot" width="320" />
</p>

## The two gates

Every Mantis engagement passes through two gates:

### 1. The legal gate (yours)

Before you invoke `mantis hack`, `mantis pentest`, `mantis goal`, or `/mantishack`, **you** confirm that you have written permission to test the target. The CLI prompts:

```sh
mantis hack example.com
# Error: refusing to start: `mantis hack` runs offensive-security tests against example.com.
# Re-run with --i-have-authorization once you have written permission.
```

You must affirmatively pass `--i-have-authorization`. That flag is a self-attestation. **Mantis cannot verify it.** The legal gate is yours.

### 2. The technical gate (Mantis enforces it cryptographically)

Mantis builds an Ed25519-signed **scope manifest** at engagement start that names every authorized host. Every outbound HTTP request the daemon dispatches goes through the `mantis-egress` CONNECT proxy, which verifies the destination against that signed manifest. Out-of-scope requests are refused before they leave the host.

This means:
- Even if a sub-agent attempts to call an out-of-scope URL, the proxy blocks it.
- Even if the LLM hallucinates a target, the proxy blocks it.
- Same-host redirects are followed automatically; cross-host redirects require fresh authorization.

## Authorized-scope checklist

Before kicking off an engagement, confirm in writing:

- [ ] **What hosts are in scope?** Specific domains, subdomain wildcards, IP ranges?
- [ ] **What hosts are explicitly out of scope?** Shared infrastructure, partner SaaS, identity providers, CDNs?
- [ ] **What categories of testing are permitted?** Recon-only? Authenticated probing? Exploit demonstration? Lateral movement?
- [ ] **What are the rate limits / disruption thresholds?** Are you allowed to fuzz, or only probe?
- [ ] **What is the engagement window?** Time-bound or open-ended?
- [ ] **Who is the point of contact** if something goes wrong (e.g., an inadvertent DOS)?
- [ ] **What is the data-handling rule?** Can you read user data? Must you redact it from findings?
- [ ] **What is the disclosure timeline?** Coordinated disclosure to whom, by when?

## Examples of unauthorized use (do not do this)

- ❌ Running `mantis hack google.com --i-have-authorization` because you read a tutorial and want to try the tool.
- ❌ Testing a bug-bounty target that's listed but with a scope statement that excludes the host you're hitting.
- ❌ Pivoting from your authorized scope into adjacent infrastructure ("they share AWS, so this is also in scope").
- ❌ Continuing testing past the agreed engagement window.
- ❌ Using Mantis to attack systems you have a personal grievance against.

## Examples of authorized use

- ✅ A signed pentest engagement letter for `corp.example.com` and listed subdomains. You authorize `https://corp.example.com/` and explicit subdomains; the egress proxy refuses anything else.
- ✅ A public bug-bounty program with an explicit scope statement. You authorize only the hosts named.
- ✅ Your own personal site, your own AWS account, your own infrastructure.
- ✅ CTF challenges and intentionally-vulnerable lab environments (e.g., HackTheBox, TryHackMe, DVWA, your local Docker compose).
- ✅ A purple-team exercise against your employer's production with management sign-off in writing.

## When something goes wrong

If you discover Mantis has hit something out of your authorized scope (e.g., an unexpected cross-host redirect, a misconfigured proxy):

1. **Stop the engagement immediately** with Ctrl-C, then `mantis-daemon` shutdown.
2. **Preserve the evidence** — the Merkle event log under `./mantishack-<engagement-id>/events.jsonl` is signed and immutable.
3. **Notify the affected party** if appropriate, following your jurisdiction's rules.
4. **File an issue at https://github.com/deonmenezes/mantishack/issues** if you suspect a bug in Mantis's scope enforcement.

## Reporting findings

Mantis renders reports in multiple formats — Markdown, PDF, HackerOne JSON, Bugcrowd JSON, SARIF, OpenVEX. Use the format your program requires.

The default severity floor drops `info`-level findings from the rendered report. For coordinated-disclosure programs, lower the floor with `--severity-floor info` to include everything.

## License

Apache-2.0 OR MIT.
