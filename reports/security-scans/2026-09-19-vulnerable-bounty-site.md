# Discovery scan — vulnerable-bounty-site.vercel.app — 2026-09-19

Recurring 4-hourly maintenance routine, authorized-discovery-scan leg.

## Authorized target

- `https://vulnerable-bounty-site.vercel.app` (only target in scope for this run)

## Outcome: scan not performed — blocked by session network egress policy

Every attempt to reach the target failed at the TLS-CONNECT stage, before any
HTTP request left this session:

```
$ curl -sS -D - https://vulnerable-bounty-site.vercel.app/
curl: (56) CONNECT tunnel failed, response 403
HTTP/1.1 403 Forbidden
```

The session's outbound-HTTPS agent proxy (`$HTTPS_PROXY` ->
`http://127.0.0.1:41823`) recorded the same denial in its own status log:

```json
{
  "ts": "2026-09-19T08:30:37.570Z",
  "kind": "connect_rejected",
  "detail": "gateway answered 403 to CONNECT (policy denial or upstream failure)",
  "host": "vulnerable-bounty-site.vercel.app:443"
}
```

Per the proxy's own operator guidance (`/root/.ccr/README.md`): a 403/407 on
CONNECT means "the destination host is not allowed by your organization's
egress policy for this session. Do not retry or route around it — report the
blocked host." This run did not retry with a different tool/transport and did
not attempt to bypass the proxy or disable TLS verification.

**No requests reached the target.** No scan data of any kind (headers, body,
security posture, injection probes) was collected this run, so there is
nothing to compare against a future baseline yet.

## Why this matters for the routine

This routine is asked each cycle to run a discovery-only scan against this
target using the repo's own scanning capabilities (`mantis_http_audit`,
`source_sink_scan`, etc. plus manual HTTP probing). `mantis_http_audit` is a
pure evidence-formatter (it never makes network calls — it only redacts/hashes
already-captured raw HTTP text), so reaching the target at all requires this
session's own outbound HTTP access, which is currently denied for this host
by the environment's egress allowlist.

## Recommended fix

Add `vulnerable-bounty-site.vercel.app` (and the other 9 targets mentioned as
forthcoming) to the egress allowlist for the environment/session this
scheduled routine runs in, so future runs can actually reach it. Until that's
done, this leg of the routine will keep reporting the same blocked-host
outcome every cycle.

## This run's other leg (detection-improvement)

Unrelated to the above: this run also opened
https://github.com/deonmenezes/mantishack/pull/183, adding SSRF (CWE-918)
sink coverage to the `source_sink_scan` heuristic. See that PR for details.
