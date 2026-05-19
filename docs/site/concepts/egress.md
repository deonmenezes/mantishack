# Egress + scope enforcement

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

`mantis-egress` is a CONNECT proxy that verifies every outbound request against an Ed25519-signed scope manifest. The daemon spawns one per active engagement; the URL is injected into every `mantis_http_scan` call.

## Scope manifest

A signed JSON document naming the authorized hosts:

```json
{
  "engagement_id": "01K...",
  "hosts": ["app.example.com", "api.example.com"],
  "budget_seconds": 1800,
  "signature": "ed25519:..."
}
```

Generated automatically by `mantis hack` / `mantis pentest` from the `<target>` argument and signed with the workspace key (created on first `mantis init`).

## How enforcement works

1. Every sub-agent's HTTP tool (`mantis_http_scan`) is configured with the proxy URL.
2. Each request goes through a CONNECT tunnel to the proxy.
3. The proxy parses the destination host, verifies it against the signed manifest, refuses if out-of-scope.
4. Same-host redirects are followed automatically; cross-host redirects require fresh authorization.

## Egress profiles

`--egress <profile>` selects a named operator-managed egress profile. Profiles let you:

- Route traffic through specific datacenter regions (e.g., `--egress eu-west-1`)
- Use different exit IPs per engagement
- Apply per-profile rate-limits

Manage profiles with `mantis egress` (see `mantis egress --help`).

## Geofence handling

If the daemon detects repeated `INTERNAL_ERROR`, timeouts, or `network_unreachable_target` on first-party hosts (often a sign of geofencing), the orchestrator surfaces the blocked context and asks the operator to resume with a different egress profile rather than silently rotating.
