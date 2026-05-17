# C12_account_takeover

Systematically probe all account-takeover vectors: email-confirmation bypass, password-reset with Host-header injection, two-factor authentication bypass, and session fixation. Any one confirmed path is sufficient for a critical finding. This playbook assembles the ATO surface comprehensively rather than targeting a single vector. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface includes account registration, password reset, email confirmation, 2FA, or session management endpoints.
- Prior waves have confirmed partial ATO primitives (IDOR, CSRF, XSS, JWT bypass) that need escalation to full takeover.
- Bug-class hints include `account-takeover`, `password-reset`, `2fa-bypass`, `session-fixation`, or `email-confirm-bypass`.
- Two auth profiles (`attacker` and `victim`) are registered.

---

## Workflow

1. **Load assignment and map account-lifecycle endpoints.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From traffic and recon, catalogue: `/register`, `/confirm-email`, `/forgot-password`, `/reset-password`, `/api/2fa/*`, `/login`, `/logout`, session-cookie names and attributes.

2. **Email-confirmation bypass.**
   Register a new account with the attacker's email. Before confirming the email, attempt to log in and perform authenticated actions:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/login", body: { email: "attacker-unconfirmed@evil.com", password: "Testpass1!" }, egress_profile })
   ```
   If authenticated actions succeed without email confirmation, record as a bypass. Also test:
   - Reusing another user's confirmation token on the attacker's account.
   - IDOR on the confirmation endpoint: `GET /confirm?token=USER_OWNED_TOKEN&email=attacker@evil.com`.
   - Guessable or sequential confirmation tokens.

3. **Password-reset Host-header injection.**
   Trigger a password-reset flow for the victim's email while injecting a crafted `Host` header:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/forgot-password", body: { email: "victim@example.com" }, headers: { "Host": "attacker.com", "X-Forwarded-Host": "attacker.com" }, egress_profile })
   ```
   If the application constructs the reset link using the Host header, the victim receives a reset URL pointing to `attacker.com`. The victim clicking it delivers the reset token to the attacker. Also test `X-Original-Host`, `X-Host`, and `Forwarded: host=attacker.com` variants.

4. **Password-reset token analysis.**
   Request a reset token for the attacker's own account. Analyze the token: length, entropy, time-based components, HMAC structure. Test:
   - Token reuse (use the same token twice).
   - Token persistence (does the token expire after use or time?).
   - Parallel reset: request two tokens simultaneously and confirm both are valid (no invalidation of prior tokens).
   - IDOR on the reset endpoint: `POST /reset-password?token=ATTACKER_TOKEN` with `email=victim@example.com` in the body.

5. **Two-factor authentication bypass.**
   For surfaces with 2FA, test the following bypass vectors:
   a. **Step skip:** After entering credentials, skip the 2FA step by directly accessing a post-login endpoint:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/dashboard", auth_profile: "attacker", egress_profile })
   ```
   b. **Backup code enumeration:** Test whether backup codes are short (6-8 digits) and rate-limit-free:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/auth/2fa/backup", body: { code: "000001" }, auth_profile: "attacker", egress_profile })
   ```
   c. **TOTP code reuse:** Use an already-validated TOTP code in a second login attempt within the same 30-second window.
   d. **2FA flow CSRF:** If the 2FA completion endpoint lacks CSRF protection, a CSRF attack from an already-half-authenticated session can complete the 2FA step.
   e. **Race condition on 2FA:** Send two simultaneous 2FA completion requests with the same code — one may succeed if the check is not atomic.

6. **Session fixation.**
   Obtain a pre-authentication session cookie, then attempt to reuse it after the victim authenticates:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/login", egress_profile })
   ```
   Capture the session cookie from the pre-auth response. Provide this cookie to the victim session (via CSRF or XSS). Check whether the server issues a new session ID after authentication or reuses the pre-auth ID. If reused, the attacker knowing the pre-auth cookie gains authenticated access.

7. **Session cookie attribute review.**
   For each session cookie, verify:
   - `HttpOnly` flag (missing = readable by XSS).
   - `Secure` flag (missing = transmitted over HTTP).
   - `SameSite` attribute (missing/Lax = CSRF risk).
   - Short expiry (missing = long-lived session risk).
   Record only as a finding if a concrete exploit chain is demonstrated (do not report missing flags as standalone findings per hunter-agent rules).

8. **Concurrent session / session invalidation.**
   Log in as victim; then log in again as victim from a second profile. Confirm whether the first session is invalidated. If not, test whether a stolen old session cookie still grants access after a password change.

9. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/auth/forgot-password", method: "POST", bug_class: "password_reset_host_header", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "Reset link constructed with X-Forwarded-Host value attacker.com" }] })
   ```

10. **Record chain attempt.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "ato-host-header", step: "reset_link_injected", evidence: "Victim reset email contains link pointing to attacker.com; token in attacker-controlled URL", outcome: "partial_evidence" })
    ```

11. **Record finding.**
    Call `mantis_list_findings` first. Record the strongest confirmed vector:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "Password reset via Host-header injection — account takeover", severity: "critical", cwe: "CWE-640", endpoint: "/api/auth/forgot-password", description: "...", proof_of_concept: "<injected Host header + resulting reset URL + token capture + victim account access>", response_evidence: "...", impact: "Attacker receives victim's password-reset token; resets password and takes over account", validated: true })
    ```

12. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["Host-header ATO confirmed; feeds report", "2FA step-skip partial — needs rate-limit test in next wave"] })
    ```

13. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "reset_token_capture", notes: "Re-trigger reset with Host injection; confirm token arrives at attacker-controlled host" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- For Host-header: the injected header value, the reset email link (or server response confirming the link was constructed with the injected host), and the token captured at the attacker-controlled endpoint.
- For email-confirm bypass: the authenticated session established without confirmation, with the profile page showing an unconfirmed status.
- For 2FA bypass: the specific step skipped, the direct endpoint accessed, and the authenticated response body.
- For session fixation: the pre-auth session cookie, the post-auth response showing the same cookie, and the authenticated response when using that cookie as attacker.

---

## Stop conditions

- All account-lifecycle endpoints require current-password confirmation for sensitive changes.
- Password-reset uses the application-configured base URL (from config, not Host header); Host injection has no effect.
- 2FA bypass vectors all trigger rate-limiting or step-validation.
- Session regenerated on authentication; fixation not viable.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Host header affecting non-reset emails.** Host-header injection that only affects marketing emails is not a finding. Confirm it affects the password-reset link specifically.
- **2FA bypass in dev/staging only.** Confirm the bypass works on the production surface, not a dev environment with 2FA disabled.
- **Email not delivered as proof.** Do not claim the Host-header injection works unless the modified link is observed (via server response, attacker-controlled mail server, or explicit confirmation). Inference is not proof.
- **Session invalidation race.** Concurrent-session issues are not standalone findings. Only record if a concrete exploit path exists (e.g. attacker reuses a session cookie after the victim changes their password).

---

## Next chain

This is often the terminal escalation point. Feeds the **GRADE** phase directly. May also feed **C10_xss_to_csrf** (if ATO requires XSS-extracted CSRF token) and **C13_password_reset_host** (dedicated Host-header playbook for deeper analysis of that vector).
