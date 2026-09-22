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

---

## 2026-09-20T20:27Z -- still blocked, unchanged

**Result: no scan performed. 0 requests sent to the target.**

Re-verified independently again this run:

- `curl https://vulnerable-bounty-site.vercel.app/` -- CONNECT tunnel
  rejected with `403` (exit code 56).
- The proxy's `/__agentproxy/status` endpoint recorded this exact host
  under `recentRelayFailures` at `2026-09-20T20:27:12.332Z`:
  `connect_rejected -- "gateway answered 403 to CONNECT (policy denial or
  upstream failure)"`. `noProxy` still has no `vercel.app` entry.

Same failure mode as every prior entry in this log. No scan traffic sent,
per the proxy README's instruction not to retry or route around a policy
403.

**Action needed from the repo owner (unchanged, now overdue):** add
`vulnerable-bounty-site.vercel.app` to this environment's outbound-egress
allowlist. This gap has now blocked every run of the discovery-scan half
of this routine since at least 2026-09-16 -- multiple days and roughly
two dozen 4-hourly firings with zero scan traffic reaching the authorized
target.

---

## 2026-09-22T08:30Z -- still blocked, unchanged (day 6+)

**Result: no scan performed. 0 requests sent to the target.**

Re-verified independently again this run:

- `curl https://vulnerable-bounty-site.vercel.app/` -- CONNECT tunnel
  rejected with `403` (exit code 56, `CONNECT tunnel failed, response 403`).
- The proxy's own `/__agentproxy/status` endpoint recorded this exact host
  under `recentRelayFailures` at `2026-09-22T08:29:56.172Z`:
  `connect_rejected -- "gateway answered 403 to CONNECT (policy denial or
  upstream failure)"`. `noProxy` still has no `vercel.app` entry.
- This PR (`#180`, still open/draft) has sat unaddressed since
  `2026-09-18T20:31Z`; its two prior comments are about unrelated CI
  infra failures (`cargo-deny`, `repo-checks/build-test`), not this egress
  gap -- no owner response to the actual blocker yet.

Same failure mode as every prior entry in this log, now spanning at least
6 days and roughly three dozen 4-hourly firings with zero scan traffic ever
reaching the authorized target. This run also implemented an unrelated
detection-coverage improvement (path-traversal/CWE-22 sink rules in
`source_sink_scan`, separate PR) since the scan half of the routine remains
fully blocked by this same unresolved infra gap.

**Action needed from the repo owner (unchanged, now significantly overdue):**
add `vulnerable-bounty-site.vercel.app` to this environment's
outbound-egress allowlist, or run the scan half of this routine from an
environment whose network policy permits reaching authorized external
targets. No amount of retrying from inside this environment will change
the outcome -- this needs an out-of-band config change, not another scan
attempt.
