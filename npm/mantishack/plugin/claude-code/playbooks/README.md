<!--
This file is a derivative work of Hacker Bob (https://github.com/vmihalis/hacker-bob/tree/main/prompts/playbooks),
Copyright 2026 Michail Vasileiadis, licensed under the Apache License,
Version 2.0. See the project NOTICE for the upstream attribution and
the compliance-history apology.

Modifications by Mantis contributors (2026): renamed `bounty_*` MCP
tool calls to `mantis_*`, retargeted session paths, renamed completion
markers, plus Mantis-runtime adjustments documented in CONTRAST.md.

This notice is provided per Apache-2.0 §4(b).
-->

# Mantis Capability Playbooks

Each `.md` here is a **capability pack** — a structured procedure a
hunter runs to confirm a specific vuln class with chain-strength
evidence. Inspired by Hacker Bob's `prompts/playbooks/` and capability
pack model (Apache 2.0; see `/NOTICE`).

## Why these exist

Hacker Bob's hunter discipline explicitly **forbids** recording these
as standalone findings:

> missing security headers, SPF/DKIM/DMARC, GraphQL introspection,
> banner/version disclosure without working exploit, clickjacking
> without PoC, tabnabbing, CSV injection, CORS wildcard without
> credentialed exfil, logout CSRF, self-XSS, open redirect, mobile
> app client_secret, SSRF DNS-only, host header injection, rate limit
> on non-critical forms, logout session issues, concurrent sessions,
> internal IP disclosure, missing cookie flags, password autocomplete.
>
> Only keep one if you prove the chain.

A "chain" means: the finding plus another finding it enables, with
the composition recorded via `mantis_record_chain_attempt` and
severity rated under the ladder:

| Inputs | Max chain severity |
|--------|--------------------|
| LOW + LOW | LOW (no hand-wave to medium) |
| LOW + MEDIUM | MEDIUM |
| MEDIUM + MEDIUM | MEDIUM (unless explicit elevation rationale) |
| HIGH + anything | HIGH (unless explicit elevation rationale to CRITICAL) |
| Inputs at SEV-X cannot produce chain at SEV-(X+2) under any rationale |

This file (`playbooks/README.md`) and every `cap-*.md` next to it are
the source of truth for what counts as a "real" finding. The hunter
agent (`agents/mantis-hunter.md`) references this directory.

## Available capability packs

| Pack | What it confirms | Typical severity if confirmed |
|------|------------------|-------------------------------|
| `cap-source-map-exploit.md` | Production source map exposes original code with secrets / internal URLs | `medium`–`high` |
| `cap-dmarc-takeover.md` | DMARC `rua` target domain is registrable / expired | `critical` if registrable |
| `cap-vercel-challenge-bypass.md` | Vercel Security Checkpoint bypass via known techniques | `high` if bypassed |
| `cap-doc-vs-behavior.md` | OpenAPI/sitemap declared route returns wrong behavior (security divergence) | `medium`–`high` |
| `cap-multi-account-differential.md` | Endpoint returns the same response for unauth vs auth — broken authn | `high` |
| `cap-subdomain-takeover.md` | CNAME points to unowned third-party service (heroku-app-not-found, etc.) | `high`–`critical` |
| `cap-framer-site-pivot.md` | Framer site ID enumerates sibling sites under same Framer account | `medium` |
| `cap-version-cve.md` | Detected version matches a known unpatched CVE | varies |

Hunters select capability packs based on the `vuln_classes` hint in
their assignment. Each pack tells the hunter exactly which Bash
commands to run and what response patterns count as a confirmed
finding.
