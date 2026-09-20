# Scan report: vulnerable-bounty-site.vercel.app

- **Run date:** 2026-09-20
- **Target (authorized):** `https://vulnerable-bounty-site.vercel.app`
- **Scope:** discovery-only (no active exploitation, no destructive requests)
- **Result:** scan could not run -- blocked at the network layer

## What happened

This routine executes inside a Claude Code remote session whose outbound
HTTPS traffic is routed through a sandboxed egress proxy with an
organization-level allowlist. Every request to
`vulnerable-bounty-site.vercel.app` was rejected by that proxy before it
left the sandbox:

```
$ curl -sS -D - https://vulnerable-bounty-site.vercel.app/
HTTP/1.1 403 Forbidden
...
curl: (56) CONNECT tunnel failed, response 403
```

The proxy's own status endpoint confirms this is a policy denial, not a
target-side failure or rate limit:

```json
{
  "recentRelayFailures": [
    {
      "kind": "connect_rejected",
      "detail": "gateway answered 403 to CONNECT (policy denial or upstream failure)",
      "host": "vulnerable-bounty-site.vercel.app:443"
    }
  ]
}
```

A control request to `https://example.com/` from the same session failed
identically (`connect_rejected`, "organization policy"), confirming this
session's egress is denied for essentially all external domains outside a
small allowlist (npm/PyPI/crates/Go proxy/Anthropic API endpoints) -- it is
not specific to this target and not something fixable from inside the
session (no proxy bypass or TLS-verification override was attempted, per
this environment's own operating rules).

Claude Code's `WebFetch` tool, which uses a separate first-party fetch path,
hit the same block: `EGRESS_BLOCKED` for this domain.

## No findings this run

Because no request reached the target, there is nothing to report against
XSS, SQL injection, auth/session flaws, misconfiguration, or exposed
secrets for this run. This is a coverage gap in the *environment*, not a
statement about the target's security posture.

## What would unblock this

To let this recurring routine actually reach the authorized target, the
session's/environment's network egress policy needs an allowlist entry for
`vulnerable-bounty-site.vercel.app` (and, per the task description, the
other ~9 authorized targets once they're added). Once egress is permitted,
this routine can drive the scan through `mantis_http_audit` for
evidence-pack capture plus direct recon (headers, common paths, forms) and
register any real findings through `mantis_findings` per the normal
detect -> validate pipeline.
