# Disclaimer

Mantis is an autonomous security testing tool. Read this before using it.

## Authorization is your responsibility

Bob will scan, probe, and attempt exploitation of any target you point him at. He may send real requests to third-party services, internal or private-network hosts, authentication providers, SaaS integrations, webhooks, CDNs, or cloud metadata-style hosts when instructed or when a chain depends on them. He does not verify that you have permission. **You are solely responsible for ensuring that:**

1. The target is in scope of an active bug bounty program, a written penetration testing agreement, or a system you own.
2. The authorization permits the testing methods Mantis may perform, including automated scanning, authenticated testing, account creation, signup flows, CAPTCHA-solving services, chaining, and PoC execution.
3. Any accounts, credentials, personas, or test data used by Mantis are permitted for the target and testing method.
4. Any third-party, internal, private-network, customer, vendor, identity-provider, or downstream systems Mantis may touch are explicitly authorized for the planned testing, or the policy clearly allows that interaction.
5. You understand and follow all rate limits, data handling rules, disclosure rules, and rules of engagement that apply to the test.

If you do not have explicit written authorization, do not run Bob.

## Mantis does not enforce scope for you

Bob has internal guard hooks (`scope-guard.sh`, `scope-guard-mcp.sh`) and audit logging via `mantis_http_scan`, but these are operational aids only. They are not legal, authorization, or scope enforcement controls. They do not verify permission, enforce bug bounty scope, or guarantee containment. The bug bounty program's policy or written testing agreement is the only source of truth.

## Legal context

This documentation is not legal advice. Consult qualified counsel if you are unsure whether your authorization covers a target, account, method, automation, or third-party system.

Unauthorized access to computer systems is a criminal offense in most jurisdictions, including but not limited to:

- **United States** — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **European Union** — Directive 2013/40/EU on attacks against information systems, transposed nationally
- **United Kingdom** — Computer Misuse Act 1990
- **Most other jurisdictions** — equivalent computer-misuse statutes

Bug bounty safe-harbor language in a program's policy is a contractual authorization, not a legal exemption. It only protects you within its stated scope. Read the safe-harbor clause for every program before testing.

## No warranty, no liability

Mantis is provided "AS IS" under the Apache License, Version 2.0. See [`LICENSE`](LICENSE), Sections 7 and 8.

The authors and contributors are not liable for:

- Damage caused by Bob's scans, probes, or exploit attempts to in-scope, out-of-scope, or third-party systems.
- Service disruption to a target.
- Data loss, integrity issues, or downstream effects.
- Legal action taken against you for unauthorized access.
- Findings that are wrong, fabricated, hallucinated, or misclassified.

## Responsible disclosure norms

If Mantis produces a finding that you intend to submit:

1. Verify the finding manually before reporting. Verifier rounds reduce false positives but do not eliminate them.
2. Submit through the program's official channel. Do not publicly disclose, sell, or weaponize.
3. Respect any embargo or coordinated-disclosure timeline the program requests.
4. Do not retain extracted data beyond what is needed to demonstrate impact. Delete it after submission.

## Reporting issues in Mantis itself

If you find a security issue in Mantis — for example, a way Mantis could be tricked into attacking the operator's own machine or an unintended target — please open a private security advisory on GitHub instead of a public issue.

## Acknowledgement

By installing or running Mantis, you acknowledge that you have read this disclaimer, that you have explicit authorization for any target you scan, and that you accept all risk and legal responsibility for the use of the tool.
