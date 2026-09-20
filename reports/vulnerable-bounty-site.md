# Scan log: vulnerable-bounty-site.vercel.app

Authorized discovery-only target for the recurring (every-4-hours) Mantis
maintenance routine. Owner-deployed Vercel app used as a practice/bounty
target for this tool. Scope: discovery only -- no active exploitation, no
destructive requests, no writes to remote data, reasonable rate limits.

This file is a running log, one entry per routine run, so later runs can
diff against prior findings.

---

## 2026-09-18T20:30Z -- run blocked before any request reached the target

**Result: no scan performed. 0 requests sent to the target.**

This session's outbound network egress is mediated by an organization
policy-enforcing proxy (see `/root/.ccr/README.md` in the execution
environment). `vulnerable-bounty-site.vercel.app` is not on this session's
egress allowlist:

- Plain `curl` to `https://vulnerable-bounty-site.vercel.app/` failed the
  CONNECT tunnel with a `403` from the egress proxy
  (`connect_rejected -- organization policy`).
- The harness's own `WebFetch` tool independently returned
  `EGRESS_BLOCKED` for the same domain.

Both the proxy README and this session's own operating instructions are
explicit that a `403`/`407` policy denial from the egress proxy must be
reported, not retried or routed around (no alternate DNS, no unsetting
`HTTPS_PROXY`, no other tool as a workaround) -- so no further attempts were
made this run.

**Action needed from the repo owner:** add `vulnerable-bounty-site.vercel.app`
(and, per the routine's own prompt, the other 9 authorized targets once
provided) to this session's/environment's outbound egress allowlist. Until
that's done, this recurring routine cannot execute the discovery-scan half
of its job against this target -- only the detection-capability-improvement
half (task 1) can run.

---

## 2026-09-20T12:29Z -- still blocked, unchanged across at least 4 days / multiple runs

**Result: no scan performed. 0 requests sent to the target.**

Re-verified independently this run rather than assuming the prior entries
still held:

- `curl https://vulnerable-bounty-site.vercel.app/` -- CONNECT tunnel
  rejected with `403` (`connect_rejected: gateway answered 403 to CONNECT
  (policy denial or upstream failure)`).
- The proxy's own `/__agentproxy/status` endpoint lists this exact host
  under `recentRelayFailures` for this run's timestamp, and its `noProxy`
  allowlist has no entry for `vercel.app` or this subdomain.

This is the same failure mode logged on 2026-09-16 (two earlier entries,
see the sibling `reports/vulnerable-bounty-site-scan-log` branch/PR) and
2026-09-18 (above) -- the egress allowlist gap has now persisted across at
least four days and several 4-hourly firings of this routine without being
addressed. No findings, positive or negative, can be produced until it is.

**Action needed from the repo owner (unchanged, now overdue):** add
`vulnerable-bounty-site.vercel.app` to this environment's outbound-egress
allowlist (or run this routine's scan half from an environment whose policy
permits reaching authorized external targets). Every run until then will
keep producing this identical "blocked, no findings" result.
