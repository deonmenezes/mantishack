# Disclaimer

> **Mantis is offensive-security tooling for use only on systems you own or have explicit written authorization to test.**

<p align="center">
  <img src="../assets/mascot/hero.png" alt="Mantis mascot" width="320" />
</p>

## Authorized testing only

By using Mantis, you affirm that:

1. **You have explicit written authorization** to test every target host, asset, and account included in your scope manifest. "Explicit written" means a signed pentest engagement letter, a bug-bounty program scope statement, an internal corporate authorization, or equivalent — verbal permission is not sufficient.
2. **You have read and understand the laws of your jurisdiction** governing offensive-security testing. In many jurisdictions, accessing computer systems without authorization is a criminal offense (Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK, etc.) regardless of the technical sophistication of the testing.
3. **You will respect the scope** of your authorization. Mantis enforces scope cryptographically at the egress proxy, but you remain legally responsible for what you direct it to test.
4. **You will not use Mantis to attack systems you do not control**, including but not limited to:
   - Public services or shared infrastructure not explicitly in your scope
   - Third-party SaaS used by your target but operated by another party
   - Systems belonging to people who did not consent to testing
5. **You will not use Mantis for destructive operations** beyond your authorization, including:
   - Data deletion at scale
   - Account takeover of arbitrary users
   - Denial-of-service against production systems
   - Lateral movement into networks you don't own

## What Mantis enforces

Mantis enforces certain technical guardrails by default:

- **Scope manifest signing** — every outbound HTTP request goes through `mantis-egress`, a CONNECT proxy that verifies the destination against an Ed25519-signed scope manifest. Out-of-scope requests are refused before they leave the host.
- **Workflow gates** — every phase transition runs through a gate that refuses to advance on missing prerequisites, terminal blockers, or incomplete chain attempts.
- **Refuse-to-start** — the CLI refuses to begin an offensive run without `--i-have-authorization` (or the equivalent confirmation in the slash command).

## What Mantis does NOT enforce

- **Legal authorization** — the `--i-have-authorization` flag is a self-attestation, not a legal credential. Mantis cannot verify whether you actually have permission. **That is your responsibility.**
- **Reasonableness of scope** — if you load a signed scope manifest that authorizes destructive operations, Mantis will follow it. Authorize narrowly.

## When Mantis will refuse to run

Even with `--i-have-authorization`, Mantis (and the operators of this software) reserve the right to refuse to run when:

- The target overlaps a public service the operator does not control (e.g., shared SaaS, public CDN).
- The user supplies an exploit primitive scope that requests destructive actions at scale beyond a reasonable test boundary.
- The target is a critical-infrastructure system (utilities, medical, transportation) without overwhelming evidence of authorization.

## License

Apache-2.0 OR MIT. The license includes a standard liability disclaimer; you assume all risk and liability for your use of this software.
