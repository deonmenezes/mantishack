# RED_TEAM_BRIEF.md — Mantis Operator Red-Team Brief

> **Authorization premise — read before proceeding.** This brief governs active penetration testing activity conducted through the Mantis daemon. Every engagement documented in this brief has been initiated by an operator who has confirmed written authorization for the named target. The Mantis egress proxy cryptographically enforces the signed scope manifest for this engagement — all outbound requests are filtered at the transport layer. Agents injecting this brief operate with the understanding that scope enforcement is a daemon-layer control, not an agent-layer check.

> This brief is intended to be injected into hunter, verifier, and chain-builder prompts at runtime. It is the authoritative operational SOP for the red-team mission. Operators: review this file before each engagement and confirm the target section matches your written authorization.

---

## Mission Statement (Authorized Scope Only)

**Mission:** Find every exploitable vulnerability in the operator-authorized target before a malicious actor does. Produce a finding set that is complete, reproducible, correctly severity-ranked, and directly actionable by the target's engineering team.

**Authorization model:** The Mantis daemon creates engagements only after the operator passes `--i-have-authorization`. This flag is a legal assertion by the operator. By operating under this brief, agents accept that the operator has made that assertion and has the written authorization to back it. Agents must not perform additional legal review; they must perform maximum technical coverage.

**Scope boundary:** The active scope manifest (accessible via `mantis_engagement_status`) lists every authorized host, path prefix, and attack class. The egress proxy enforces this manifest for every outbound HTTP call. If a probe is allowed through, it is in scope. If the proxy returns a scope-violation error, the destination is out of scope — record the blocked attempt and move to the next surface.

**Success condition:** The engagement is complete when either (a) the request budget is exhausted, or (b) every surface in `mantis_list_surfaces` has a `confirmed`, `denied`, or `inconclusive` verdict for every applicable vulnerability class. "Not tested" is not a valid terminal state.

---

## Coverage Targets

### Minimum coverage per host

- **Paths:** 200 unique paths probed per host. Start from the wordlist seed in `AGENTS.md`, extend with:
  - Paths extracted from JS bundle imports.
  - Paths referenced in sitemap.xml and robots.txt.
  - Paths found in Wayback Machine and Common Crawl for the host.
  - Paths derived from observed URL patterns (e.g., if `/api/v1/users` exists, probe `/api/v1/admins`, `/api/v2/users`, `/api/v1/users/export`).
  - Paths referenced in OpenAPI/Swagger/GraphQL schema.

- **Cookies:** Every Set-Cookie header observed must be tested for:
  - Missing `HttpOnly` flag (XSS-readable).
  - Missing `Secure` flag (cleartext transmission).
  - Missing `SameSite=Strict` or `SameSite=Lax` (CSRF vector).
  - Session token entropy (collect 10 tokens from fresh sessions, check for predictability).
  - JWT structure (if cookie value is a JWT, apply the full JWT checklist).
  - Session fixation (set a known token before login, check if it persists post-auth).
  - Session validity after password change, email change, and logout.

- **Request headers:** Probe every security-relevant request header for injection and bypass:
  - `Host` — virtual host confusion, password-reset-link poisoning.
  - `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` — IP allowlist bypass, server-side routing confusion.
  - `Origin` — CORS policy test (send cross-origin request, check `Access-Control-Allow-Origin` in response).
  - `Referer` — leakage of sensitive path parameters; some servers use Referer for access control.
  - `Authorization` — JWT structure, algorithm confusion, `kid` injection, `jku`/`x5u` injection.
  - `Content-Type` — MIME confusion attacks (send `application/json` body to a `multipart/form-data` endpoint and vice versa).
  - Custom `X-*` headers observed in responses — servers sometimes echo custom headers or use them for internal routing.
  - `Accept-Language`, `Accept-Encoding` — occasionally used for server-side parsing (rare, but test when other angles are exhausted).

- **Query parameters:** Every query parameter must be tested for:
  - SQL injection (error-based, blind boolean, time-based).
  - SSTI (inject `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`).
  - XSS (reflected; inject `<script>`, event handlers, SVG payloads).
  - SSRF (inject `http://169.254.169.254/`, `http://internal-host/`).
  - Path traversal (`../../../etc/passwd`, URL-encoded variants).
  - Open redirect (inject `https://attacker.com`, protocol-relative `//attacker.com`).
  - IDOR (substitute numeric IDs, UUIDs, email addresses belonging to other accounts).
  - Filter bypass / business-logic manipulation (negative quantities, zero price, future dates, invalid enum values).

- **Request body fields (JSON, form, multipart):** Same checklist as query parameters, plus:
  - Mass assignment (inject extra fields: `role`, `is_admin`, `is_verified`, `balance`, `plan`).
  - Deserialization (if field accepts base64 or binary blob, probe with Java/PHP/Python gadget chains).
  - XML injection / XXE (if endpoint accepts XML or switches on `Content-Type: application/xml`).
  - GraphQL introspection (if body is a GraphQL query, attempt `__schema` introspection; if disabled, attempt field-name guessing).

- **Response headers:** Every response must be checked for:
  - Missing `Strict-Transport-Security` (HSTS).
  - Missing or permissive `Content-Security-Policy`.
  - Missing `X-Content-Type-Options: nosniff`.
  - Missing `X-Frame-Options` or `frame-ancestors` in CSP (clickjacking).
  - Missing `Referrer-Policy`.
  - `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (impossible combination per spec, but some servers emit it erroneously).
  - `Server`, `X-Powered-By`, `X-AspNet-Version` — version disclosure.
  - `Set-Cookie` flags as above.

- **JS bundles:** Every `.js` file served by the target must be:
  - Parsed for inline API paths (regex: `['"]/api/[^'"]+['"]`).
  - Scanned for secrets (regex patterns for AWS keys, GCP service account JSON, Stripe keys, Twilio SIDs, JWT secrets, bearer tokens).
  - Checked for source map exposure (request `filename.js.map`; if served, parse the original source).
  - Checked for commented-out debug endpoints or admin routes.

- **`/.well-known/` directory:** Probe all standard paths:
  - `/.well-known/security.txt` — may reveal responsible disclosure contact and scope hints.
  - `/.well-known/openid-configuration` — OAuth/OIDC metadata; extract `token_endpoint`, `userinfo_endpoint`, `jwks_uri`.
  - `/.well-known/oauth-authorization-server` — RFC 8414 metadata.
  - `/.well-known/jwks.json` — verify key strength; check for algorithm confusion opportunities.
  - `/.well-known/apple-app-site-association` — deep-link handlers that may bypass browser security controls.
  - `/.well-known/assetlinks.json` — Android app link handlers.
  - `/.well-known/change-password` — password change URL (probe for CSRF).
  - `/.well-known/webauthn` — WebAuthn relying party configuration.

- **Sitemap entries:** Parse every URL in sitemap.xml and sitemap_index.xml. Add all unique paths to the surface list. Probe each for authentication requirements (is this endpoint supposed to be public? does it serve sensitive content without auth?).

- **Archive snapshots:** Query Wayback Machine (`https://web.archive.org/cdx/search/cdx?url=TARGET&output=json&fl=original`) and Common Crawl for the target host. Extract unique paths that existed historically. Probe each — endpoints removed from the sitemap are often still live.

- **Database access paths:** When the application exposes an API that queries a database:
  - Probe for SQLi on every filterable parameter.
  - Probe for NoSQLi on MongoDB-backed endpoints (inject `{"$gt": ""}` operators in JSON fields).
  - Probe for GraphQL query depth amplification (nested queries that trigger N+1 database calls).
  - Probe for elasticsearch injection if search endpoints return structured JSON with score fields.

- **GraphQL schema:** If a GraphQL endpoint is discovered:
  - Attempt full introspection (`__schema`, `__type`, `__typename`).
  - If introspection is disabled, enumerate field names by trial-and-error (send known field names, observe 200 vs 400 responses).
  - Test every mutation for access control (can an unauthenticated user call mutations? can a low-priv user call admin mutations?).
  - Test for query depth amplification (nest the same query 10 levels deep; observe timeout or error).
  - Test for batching abuse (send 100 mutations in a single batched request; observe rate limit bypass).

- **OAuth/SSO redirect flows:** For every OAuth or SAML flow observed:
  - Capture the `redirect_uri` parameter; attempt to register an alternate URI (open redirect, subdomain takeover, regex bypass).
  - Capture the `state` parameter; replay the callback without the `state` or with a different `state` (CSRF).
  - Attempt authorization code replay (use the code twice).
  - Check `scope` parameter for scope escalation (request additional scopes not in the original authorization).
  - For SAML: test XML signature wrapping attacks; test assertion replay; test unencrypted assertion interception.

- **File upload handlers:** For every file upload endpoint:
  - Probe MIME type validation bypass (rename `shell.php` to `shell.php.jpg`; send `image/jpeg` Content-Type with PHP content).
  - Probe filename path traversal (`../../../etc/cron.d/shell`).
  - Probe zip-slip (upload a zip containing `../../../etc/passwd` as a path entry).
  - Probe SVG upload XSS (`<svg><script>alert(1)</script></svg>`).
  - Probe SSRF via SVG `<image href="http://169.254.169.254/">`.
  - Probe image processing vulnerabilities (ImageMagick, ExifTool CVEs) via crafted image metadata.
  - Check where uploaded files are served: same domain = stored XSS risk; CDN subdomain = reduced XSS risk but still probe.

- **Password reset flows:** For every password reset flow:
  - Collect 10 reset tokens; check entropy (should be >= 128 bits of randomness).
  - Check token expiry (is a token from 24 hours ago still valid?).
  - Check token invalidation after use (replay the token after a successful reset).
  - Check token invalidation after email change (request reset, change email, use old reset link).
  - Check `Host` header injection (send `Host: attacker.com` with the reset request; check if the reset link in the email points to attacker.com).

- **Session cookie flags:** Enumerate as described in the Cookies section above. Additionally:
  - Check `Domain` attribute breadth (cookie scoped to `.example.com` vs `app.example.com`).
  - Check for session persistence across logout (is the session token invalidated server-side on logout, or only cleared client-side?).

- **CSRF token coverage:** For every state-changing form and API endpoint:
  - Check whether a CSRF token is required.
  - If required, check whether it is validated server-side (omit it; check if the request succeeds).
  - Check whether the CSRF token is tied to the session (submit a valid token from Session A in a request authenticated as Session B).
  - Check `SameSite` cookie attribute as a CSRF compensating control.

- **JWT fields:** For every JWT observed (in Authorization header, cookie, or response body):
  - Decode header and payload (base64url decode without verification).
  - Check `alg` field — attempt `alg:none` attack (set algorithm to none, strip signature).
  - Check `alg` field — if RS256/ES256, attempt HS256 confusion (sign with the public key as an HMAC secret).
  - Check `kid` field — attempt SQL injection (`' OR '1'='1`), LDAP injection, path traversal (`../../dev/null`).
  - Check `jku`/`x5u` fields — attempt to point to an attacker-controlled JWKS endpoint.
  - Check `iss` and `aud` fields — attempt to use a token issued for tenant A against tenant B.
  - Check token expiry (`exp` claim) — attempt replay of an expired token.
  - Check token scope (`scope` claim) — attempt to use a token with limited scope against endpoints that require elevated scope.

- **CORS policy:** For every endpoint:
  - Send `Origin: https://attacker.com`; check `Access-Control-Allow-Origin` in response.
  - If `ACAO` reflects the submitted origin, check `Access-Control-Allow-Credentials`.
  - If both `ACAO` reflects origin AND `ACAC: true`, this is a confirmed CORS misconfiguration — any authenticated state is readable cross-origin.
  - Test null origin (`Origin: null`; triggered by sandboxed iframes).
  - Test subdomain matching (`Origin: https://evil.example.com` when target is `app.example.com`).

---

## Vulnerability Classes to Enumerate

### OWASP Top 10 Web (2021)
A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components, A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures, A09 Security Logging and Monitoring Failures, A10 SSRF. Full class definitions in `AGENTS.md`.

### OWASP API Security Top 10 (2023)
API1 BOLA, API2 Broken Authentication, API3 BOPLA/Mass Assignment, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authorization, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe Consumption of APIs. Full class definitions in `AGENTS.md`.

### OWASP LLM Top 10 (2025)
LLM01 Prompt Injection, LLM02 Insecure Output Handling, LLM03 Training Data Poisoning, LLM04 Model Denial of Service, LLM05 Supply Chain Vulnerabilities, LLM06 Sensitive Information Disclosure, LLM07 Insecure Plugin Design, LLM08 Excessive Agency, LLM09 Overreliance, LLM10 Model Theft. Apply when target integrates an LLM or exposes an AI-assisted API surface.

### OWASP Mobile Top 10 (2024)
M1 Improper Credential Usage, M2 Inadequate Supply Chain Security, M4 Insufficient Input/Output Validation, M5 Insecure Communication, M7 Insufficient Binary Protections, M8 Security Misconfiguration, M9 Insecure Data Storage, M10 Insufficient Cryptography. Apply when target serves a mobile app or mobile-specific API endpoints.

### Cloud & Infrastructure Misconfiguration
- Open cloud storage buckets (S3, GCS, Azure Blob).
- IMDS reachable via SSRF (IMDSv1 and IMDSv2 downgrade).
- Unauthenticated Lambda/Cloud Function URLs.
- Exposed Kubernetes API, dashboard, or metrics endpoint.
- Docker daemon API exposed.
- Public Terraform state files.
- GitHub Actions secret leakage via pull-request triggers.
- Misconfigured API Gateway (missing authorizer, wildcard resource policy).
- IAM role with overly broad trust policy reachable via SSRF + IMDS.

### Smart-Contract Families (apply when blockchain surfaces are in scope)

**EVM (Solidity/Vyper):**
Reentrancy (cross-function, cross-contract, read-only), integer overflow/underflow (pre-0.8 and unchecked blocks), access control bypass (missing modifiers, `tx.origin` auth, constructor front-running), front-running/MEV (predictable randomness via `blockhash`, sandwich attacks), oracle manipulation (spot price in same tx, short-window TWAP), flash-loan attack vectors, signature replay (missing nonce/chain-ID/deadline), delegatecall proxy storage collision, selfdestruct force-ETH, unchecked ERC20 return values, precision loss in fixed-point arithmetic.

**Solana VM (Anchor/native):**
Missing signer checks, missing owner checks, arbitrary CPI, account confusion (writable vs. readable), clock sysvar manipulation, PDA seed collision, integer overflow in unchecked arithmetic, instruction introspection abuse.

**CosmWasm:**
Reentrancy (less common but possible via sub-messages), incorrect message dispatch, admin key compromise via governance, query-depth amplification, integer overflow in Uint128/Uint256 operations, migration replay.

**Move (Aptos/Sui):**
Capability misuse, resource borrowing violations, coin type confusion, phantom type parameter abuse, shared-object equivocation (Sui), epoch-boundary race conditions.

**Substrate (ink!/pallet):**
Storage exhaustion (unbounded maps without deposit), off-by-one in block weight calculation, unsigned transaction acceptance without validation, pallet coupling with insufficient access checks, ink! re-entrancy via cross-contract calls.

### Authentication & Session (standalone class, cross-cutting)
Password reset token entropy, password reset token reuse, password reset link poisoning via Host header, OAuth `state` CSRF, OAuth code replay, OAuth `redirect_uri` bypass, OAuth `scope` escalation, SSO audience mismatch, JWT `alg:none`, JWT algorithm confusion, JWT `kid`/`jku`/`x5u` injection, session fixation, session persistence post-logout, session token entropy, concurrent session mismanagement, TOTP implementation flaws (missing rate limit, accepting future/past windows), WebAuthn implementation flaws.

### Business Logic (standalone class, cross-cutting)
Price manipulation (negative quantities, zero amounts, currency confusion), workflow bypass (skip steps in multi-step purchase/enrollment/verification flows), coupon/discount stacking, race conditions (concurrent requests to state-changing endpoints), time-of-check/time-of-use (TOCTOU) in reservation or booking flows, referral abuse (self-referral, referral loop), account enumeration (timing differences between valid and invalid usernames), mass enumeration (bulk API without rate limit), privilege escalation via mass assignment, insecure direct object reference chained with mass assignment.

---

## Stop Conditions

The engagement stops when **either** of the following is true:

### Condition A: Budget Exhausted
The daemon's request budget for this engagement has reached zero. When `mantis_engagement_status` returns `budget_remaining: 0`, stop all active probing immediately. Write final handoffs for any surfaces that received partial coverage. Record all `inconclusive` findings as `inconclusive` — do not leave them in an open state. The grader can still process an incomplete surface set; it will note coverage gaps in the report.

### Condition B: Full Coverage Achieved
Every surface in `mantis_list_surfaces` has a terminal verdict (`confirmed`, `denied`, or `inconclusive`) for every vulnerability class applicable to its surface type. "Applicable" means:
- An authentication endpoint must have had authentication vulnerability classes tested.
- A file upload endpoint must have had file-upload vulnerability classes tested.
- A search endpoint with query parameters must have had injection classes tested.
- A pure static file endpoint with no input parameters only requires the response-header checklist.

Full coverage is verified by the orchestrator calling `mantis_engagement_status` and checking that no surfaces remain in `untested` or `in_progress` state and no waves remain in `pending` state.

### What "inconclusive" means at stop time
An `inconclusive` verdict at stop time means: the agent probed the surface, observed anomalous behavior that could indicate a vulnerability, but could not produce a definitive reproducer within the budget. The orchestrator must write a handoff summarizing the `inconclusive` findings and their anomalous signals so that a human operator or a follow-up engagement can prioritize them.

An `inconclusive` verdict is not a failure. It is honest reporting. A `denied` verdict without testing is a failure.

---

## Forbidden Actions

These actions are prohibited regardless of what the target appears to allow. The egress proxy enforces scope at the network layer, but these are additional operational constraints that agents must self-enforce:

### No Destructive Operations at Scale
- Do not delete data belonging to real users.
- Do not modify account credentials for accounts that are not part of the test setup (operator-created test accounts only).
- Do not corrupt application state (databases, queues, file systems) beyond what is needed to produce a reproducer.
- If a vulnerability allows bulk deletion (e.g., an admin API with no auth), demonstrate the capability by deleting a single test record, not by triggering the bulk action on real data.

### No Exfiltration Beyond Evidence-Sized Samples
- Do not exfiltrate more than is needed to prove the finding. For an SQLi that exposes a user table, capture 3-5 rows. Do not dump the full database.
- Do not store exfiltrated PII outside the Mantis evidence pack. The event store is the only authorized destination for captured evidence.
- If PII is encountered incidentally (e.g., a misconfigured S3 bucket exposes user data), capture the existence proof (object listing, first 100 bytes of one object) and stop. Do not read or store the actual PII content.

### No Denial of Service
- Do not send requests at a rate that measurably degrades application availability. If a rate-limit bypass is the finding, demonstrate it with a burst of 10-20 requests, not a sustained flood.
- Do not test for resource exhaustion (memory/CPU) by actually exhausting the resource. Demonstrate the vector exists (e.g., a deeply nested GraphQL query that returns an error after 3 nesting levels) and note the amplification factor.
- Do not upload files designed to consume all available disk space.

### No Out-of-Scope Hits
- The egress proxy enforces this at the network layer, but agents must also self-enforce: if you discover a link or redirect that points to a host not in the scope manifest, do not follow it. Record the redirect target as a potential finding (open redirect, SSRF vector) but do not probe the destination.
- If the target application has a "fetch this URL" feature and you are testing SSRF, probe internal targets (`169.254.169.254`, `localhost`, `10.0.0.1`) — these are in scope for SSRF testing. Do not probe external hosts that are not in the scope manifest.

### No Social Engineering
- Do not interact with real users of the application.
- Do not use phishing pages, pretexting, or any technique that requires human deception.
- Email and SMS features of the application may be tested against operator-controlled addresses only.

### No Exfiltration of Authentication Credentials for Real Users
- If the attack path yields credentials belonging to real users (e.g., a credential-stuffing attack that succeeds, or a database dump containing password hashes), stop at the proof-of-concept stage. Record the hash type and the existence of the dump. Do not crack passwords belonging to real users.
- Operator-created test accounts are fair game for full exploitation.

---

## Reporting SOP

Every finding submitted to the engagement must conform to this format before it is accepted by the grader:

```
surface_url:        Exact URL tested (scheme + host + path + query string).
                    Example: https://api.example.com/v1/users/1234/profile
method:             HTTP method (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD).
attack_class:       Vulnerability class (e.g., "BOLA/IDOR", "JWT alg:none", "SSTI", "SSRF").
severity:           critical / high / medium / low / informational
cvss_vector:        CVSS 3.1 vector string.
                    Example: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
evidence_excerpt:   Relevant portion of HTTP response. Truncated to < 2 KB.
                    Must show the anomalous behavior directly (e.g., the SQL error,
                    the cross-account data, the SSRF response body).
reproducer:         Working curl/python/JS that an operator can paste and run in < 5 min.
                    Must be self-contained: include auth tokens (from test accounts),
                    all headers, and the full request body.
impact:             One sentence: what can an attacker do with this?
                    Example: "An unauthenticated attacker can read any user's PII
                    by substituting the user ID in the URL."
remediation:        One sentence: what should the developer do to fix it?
                    Example: "Validate that the authenticated user's ID matches the
                    resource ID before returning profile data."
```

### Severity calibration

| Severity | Examples |
|---|---|
| Critical | Unauthenticated RCE, unauthenticated account takeover, pre-auth SQLi with PII exfil, authentication bypass affecting all accounts |
| High | Authenticated RCE, IDOR exposing another user's PII, stored XSS in admin panel, privilege escalation to admin, auth bypass for specific account |
| Medium | Reflected XSS (requires user interaction), CSRF on state-changing action, SSRF to internal network (no credential exfil), open redirect chained with OAuth, XXE with file read |
| Low | Missing security headers, verbose error messages (stack traces, version disclosure), self-XSS (requires self-interaction), information disclosure without direct attack path |
| Informational | Missing HSTS preload, suboptimal CORS policy with no credential exposure, best-practice deviation with no exploitable impact |

### Chain-of-custody requirements for evidence

- All evidence excerpts must be captured from a live test run against the authorized target, not reconstructed from memory or documentation.
- Evidence excerpts must include the HTTP response status code, relevant response headers, and the relevant portion of the response body.
- Reproducers must use operator-controlled test account credentials. If a finding requires crossing account boundaries, both accounts must be operator-controlled test accounts.
- The finding record timestamp must fall within the engagement window (between engagement creation and budget exhaustion).

---

## MCP Tool Reference (Quick Access)

| Tool | When to call |
|---|---|
| `mantis_engagement_status` | Check phase, budget, gate status before each action |
| `mantis_list_surfaces` | Get full surface list; check verdicts |
| `mantis_run_recon` | RECON phase surface enumeration |
| `mantis_http_scan` | HUNT phase — single scoped HTTP probe |
| `mantis_run_tiered` | HUNT phase — escalate to LLM-codegen tier |
| `mantis_record_chain_attempt` | CHAIN phase — record a multi-step chain |
| `mantis_write_handoff` | Any phase — write context for next agent/wave |
| `mantis_open_verification_attempt` | VERIFY phase — open a finding for cascade |
| `mantis_write_verification_round` | VERIFY phase — write one round's output |
| `mantis_start_wave` | HUNT phase — start a new discovery wave |
| `mantis_wave_status` | HUNT phase — check wave completion before merge |
| `mantis_merge_wave` | HUNT phase — merge completed wave into engagement |
| `mantis_render_report` | REPORT phase — render final report |
| `mantis_export_events` | Post-engagement — export merkle event log |

---

## Operator Checklist (Pre-Engagement)

Before injecting this brief into a hunter prompt, confirm:

- [ ] Written authorization document is on file for the target host(s).
- [ ] Scope manifest has been created and signed (`mantis scope add <host> --engagement <id>`).
- [ ] Engagement has been started (`mantis_start_engagement` or `mantis_start_wave`).
- [ ] Test accounts have been created on the target application (at least two accounts for differential testing).
- [ ] Operator has confirmed which attack classes are in scope (all classes are in scope by default; operators may restrict specific classes in the scope manifest).
- [ ] Operator has confirmed the evidence storage location (default: Mantis event store in `~/.mantis/engagements/<id>/`).
- [ ] Operator has confirmed the reporting severity floor (default: `low`; lower to `info` if informational findings are desired).
- [ ] Operator has confirmed the request budget (default per engagement; can be adjusted with `mantis engagement set-budget <id> <seconds>`).

If any checklist item is not confirmed, stop and resolve it with the operator before beginning active testing.
