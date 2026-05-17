# C18_subdomain_takeover

Identify dangling DNS records that point to external services no longer provisioned under the target's account (CNAME to S3, Heroku, Vercel, Netlify, GitHub Pages, Azure, Fastly, etc.) and confirm takeover by claiming the resource on the external service. A confirmed subdomain takeover allows the attacker to serve arbitrary content — including credential-harvesting pages, CORS-bypass pages, or cookie-stealing XSS — on a trusted subdomain. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Recon produced a subdomain list with CNAME records pointing to third-party hosting platforms.
- DNS resolution returns `NXDOMAIN` or a platform-specific "not configured" page for one or more subdomains.
- Bug-class hints include `subdomain-takeover`, `dangling-dns`, `cname-takeover`, or `s3-takeover`.
- The target scope explicitly includes subdomains (`*.target.com`).

---

## Workflow

1. **Load assignment and enumerate subdomains.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From recon surface data, extract all subdomains with CNAME records pointing to external hosting platforms. The recon agent (deep-recon) should have seeded DNS data; check the brief for `attack_surface` entries with `surface_type: subdomain` or DNS hints.

2. **Resolve CNAME targets.**
   For each subdomain with a CNAME, query the CNAME destination:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/", headers: { "Host": "orphan.target.com" }, egress_profile })
   ```
   Alternatively, perform a DNS lookup via:
   ```
   mantis_run_tiered({ target_domain, wave, agent, surface_id, task: "dns_cname_resolve", subdomain: "orphan.target.com", egress_profile })
   ```
   Check whether the CNAME resolves to an active platform response or a "not found" / unclaimed page.

3. **Platform fingerprinting — identify takeover candidates.**
   Match the response body or error message to known platform fingerprints:
   - **Heroku:** `No such app` / `herokucdn.com`
   - **GitHub Pages:** `There isn't a GitHub Pages site here`
   - **S3:** `NoSuchBucket` / `s3.amazonaws.com`
   - **Vercel:** `The deployment you are looking for does not exist`
   - **Netlify:** `Not Found - Request ID:`
   - **Azure App Service:** `You do not have permission to view this directory or page`
   - **Fastly:** `Fastly error: unknown domain`
   - **Surge.sh:** `project not found`
   - **ReadMe.io:** `Project doesnt exist`
   For each matched platform, note the subdomain, CNAME target, and fingerprint.

4. **Confirm dangling DNS (no active resource).**
   For S3-style CNAMEs, check whether the bucket exists:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/", headers: { "Host": "orphan.target.com.s3.amazonaws.com" }, egress_profile })
   ```
   A `NoSuchBucket` error confirms the bucket is unclaimed.
   For Heroku/Vercel/GitHub Pages CNAMEs, a matching platform error page confirms the app/site is unclaimed.

5. **Claim the external resource.**
   Claim the unclaimed resource on the external platform:
   - **S3:** Create an S3 bucket named `orphan.target.com` (if bucket name matches subdomain) in the same region.
   - **GitHub Pages:** Create a repository named `orphan.target.com` under any GitHub account and enable Pages.
   - **Heroku:** Create a Heroku app with the matching name.
   - **Vercel:** Add the dangling domain to an attacker-controlled Vercel project.
   - **Netlify:** Add the custom domain to a Netlify site.
   After claiming, serve a plain-text file: `mantis-takeover-proof-<engagement_id>.txt`.

6. **Confirm takeover.**
   Fetch the subdomain and confirm the attacker-controlled content is served:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/mantis-takeover-proof-<engagement_id>.txt", headers: { "Host": "orphan.target.com" }, egress_profile })
   ```
   A 200 response with the controlled content confirms the takeover.

7. **Assess cookie scope and CORS impact.**
   Check whether the parent domain sets cookies with `Domain=.target.com` (which would make session cookies accessible from the taken-over subdomain):
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/", auth_profile: "attacker", egress_profile })
   ```
   Inspect `Set-Cookie` headers for `Domain=.target.com`. If present, the takeover gains access to parent-domain cookies from the subdomain context.

8. **Test CORS trust.**
   Check whether the main application trusts the subdomain as a CORS origin:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Origin": "https://orphan.target.com" }, auth_profile: "victim", egress_profile })
   ```
   If `Access-Control-Allow-Origin: https://orphan.target.com` and `Access-Control-Allow-Credentials: true` are returned, the takeover enables cross-site data theft.

9. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "orphan.target.com", method: "GET", bug_class: "subdomain_takeover", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "CNAME points to unclaimed S3 bucket; bucket created; controlled content served" }] })
   ```

10. **Record chain attempt.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "subdomain-takeover-to-cookie-theft", step: "takeover_confirmed", evidence: "orphan.target.com serves attacker-controlled content; parent-domain sets cookies with Domain=.target.com", outcome: "finding_recorded" })
    ```

11. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "Subdomain takeover — orphan.target.com (S3 bucket unclaimed)", severity: "high", cwe: "CWE-350", endpoint: "https://orphan.target.com/", description: "...", proof_of_concept: "<CNAME chain + NoSuchBucket response + claim confirmation + controlled content served>", response_evidence: "...", impact: "Attacker controls a trusted subdomain; can harvest credentials, steal cookies, bypass CORS", validated: true })
    ```

12. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["Subdomain takeover confirmed; cookies with Domain=.target.com in scope — feeds C16 CORS chain", "If parent CORS trusts subdomain, pivot to C16_cors_credentials"] })
    ```

13. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "content_serve_confirm", notes: "Fetch proof file from subdomain; confirm attacker-controlled content served on successive requests" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- DNS CNAME chain: the subdomain, its CNAME record value, and the platform it points to.
- Platform-specific "unclaimed" fingerprint: full response body showing the not-found/unclaimed error page.
- Claim confirmation: the attacker-controlled content served at the subdomain (HTTP 200 response body with proof file content).
- Cookie scope analysis: the `Set-Cookie` response from the parent domain showing `Domain=.target.com` (if present).
- CORS trust analysis: the parent API response showing `Access-Control-Allow-Origin: https://orphan.target.com` (if present).

---

## Stop conditions

- All subdomains with CNAMEs are actively claimed (no "not found" pages, no NXDOMAIN).
- The external platform does not allow claiming a resource matching the target's subdomain without ownership verification (e.g. GitHub requires repository ownership verification for Pages).
- DNS TTL is very short and CNAME is being actively rotated; no stable takeover window.
- Program rules exclude subdomain takeover or require specific impact beyond just serving content.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **NXDOMAIN without CNAME.** A bare NXDOMAIN (no CNAME record) is not a subdomain takeover — it is just a missing DNS record. Only pursue takeover for subdomains with an active CNAME pointing to an external platform.
- **Platform not claimable.** Some platforms (e.g. AWS CloudFront) require domain validation before a custom domain works; the CNAME alone does not enable takeover. Confirm the specific platform allows unclaimed custom domain registration.
- **Already-claimed by the target.** Some platforms return a "not configured" page even when the domain is claimed, if the specific path or app is not configured. Confirm by attempting to register the resource, not just by reading the error page.
- **Content delivery vs. cookie access.** Serving content from a subdomain is a medium-severity finding on its own. Only escalate to high/critical if cookie scope, CORS trust, or OAuth redirect trust is confirmed.

---

## Next chain

Feeds into **C16_cors_credentials** (if the parent API trusts the subdomain as a CORS origin), **C17_cache_poisoning** (if the CDN treats the subdomain as a trusted origin for cache key purposes), and **C10_xss_to_csrf** (serve XSS from the trusted subdomain to attack the parent domain).
