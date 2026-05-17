# C5_idor_burst

Burst IDOR over a numeric-ID surface using a two-account differential. Enumerate object identifiers owned by the victim account, replay each request as the attacker, and confirm that the response body contains victim-owned data — proving horizontal privilege escalation. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface exposes numeric or UUID-shaped IDs in URL path segments, query params, or JSON body fields (`/api/orders/1234`, `?doc_id=99`, `{"invoice_id": 7}`).
- At least two auth profiles (`attacker` and `victim`) are registered in the Mantis auth registry (`mantis_list_auth_profiles`).
- Traffic summary or recon shows GET/PUT/DELETE endpoints that reference a single resource by ID.
- Bug-class hints include `idor`, `bac` (broken access control), or `object-level-authorization`.

---

## Workflow

1. **Load assignment.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   Confirm `attacker` and `victim` auth profiles are present. If either is missing, record `blocked_prereqs[{ kind: "auth_missing", identifier_hint: "victim", reason: "IDOR differential requires two accounts" }]` and set `surface_status: partial`.

2. **Enumerate victim-owned IDs.**
   Authenticate as victim. Iterate known resource-listing endpoints (`/api/orders`, `/api/documents`, `/api/invoices`, etc.) via:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/orders", auth_profile: "victim", egress_profile })
   ```
   Extract all numeric/UUID IDs from the response. Collect at least 20 unique IDs. If pagination exists, follow `next_page` / `cursor` fields for up to 5 pages.

3. **Baseline attacker ownership.**
   Authenticate as attacker. Fetch the same listing endpoint:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/orders", auth_profile: "attacker", egress_profile })
   ```
   Note which IDs the attacker legitimately owns. Remove these from the victim ID list to avoid false positives.

4. **Burst replay — read access.**
   For each victim-only ID, replay the direct-object endpoint as the attacker. Send all requests within a short window (burst) to defeat naive rate-limit mitigations:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/orders/{victim_id}", auth_profile: "attacker", egress_profile })
   ```
   Flag any response with HTTP 200 and a body containing victim-owned fields (email, name, PII, financial data) as a candidate finding.

5. **Confirm write/delete access.**
   For the strongest candidate IDs, attempt mutation:
   ```
   mantis_http_scan({ target_domain, method: "PUT", path: "/api/orders/{victim_id}", body: {...}, auth_profile: "attacker", egress_profile })
   mantis_http_scan({ target_domain, method: "DELETE", path: "/api/orders/{victim_id}", auth_profile: "attacker", egress_profile })
   ```
   Do NOT commit irreversible mutations unless the program rules explicitly permit destructive testing. Prefer PUT with a benign field change (e.g. `"notes": "mantis-test"`) or stop at confirmation that the server accepts the request with a 200/204.

6. **Parameter type variants.**
   If numeric IDs are protected, test:
   - String/UUID equivalents if the API accepts both.
   - Negative integers, zero, very large integers.
   - JSON array wrapping: `{"order_id": [victim_id]}`.
   - Header-based ID references (`X-Resource-Id`, `X-User-Id`).

7. **Log coverage after each endpoint class.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/orders/{id}", method: "GET", bug_class: "idor", auth_profile: "attacker", status: "tested"|"promising", evidence_summary: "..." }] })
   ```

8. **Record chain attempt.**
   After confirming at least one read IDOR:
   ```
   mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "idor-to-data-exfil", step: "read_access_confirmed", evidence: "attacker received victim order data: HTTP 200 body contains victim email", outcome: "partial_evidence" })
   ```

9. **Record finding.**
   Call `mantis_list_findings` first. If not duplicate, record:
   ```
   mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "IDOR on /api/orders/{id} — cross-account read", severity: "high", cwe: "CWE-639", endpoint: "/api/orders/{victim_id}", description: "...", proof_of_concept: "<full request/response>", response_evidence: "...", impact: "Attacker can read any victim's order data", validated: true })
   ```

10. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["IDOR on /api/orders — feeds C12 account takeover if PII leaks session tokens"] })
    ```

11. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "differential_replay", notes: "Re-run steps 4-5 with fresh auth tokens to confirm persistence" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full HTTP request including all headers (Authorization, Cookie) for both attacker and victim profiles.
- Full HTTP response body showing victim-owned data in the attacker's response.
- Side-by-side: attacker's own resource response vs. victim's resource response (body diff).
- Confirmed object owner mismatch: victim email/user_id in attacker's response body.
- If write access confirmed: before/after state of the mutated field (from victim's perspective).

---

## Stop conditions

- All victim IDs tested for read access; no cross-account data returned.
- Two consecutive WAF blocks on IDOR variants — log both, mark WAF-blocked, stop.
- Attacker and victim share the same account scope (e.g. same organization tenancy) — record as informational, do not escalate.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Shared-resource false positive.** Ensure the resource is genuinely victim-owned, not a public or shared workspace resource. Check the victim-listing response for ownership metadata.
- **204 with empty body.** A 204 on DELETE is not proof of access — the server may silently swallow requests. Confirm the resource is actually gone from the victim's listing.
- **Sequential ID coincidence.** If the attacker's next legitimate ID happens to be the same numeric value as a victim's ID, the test is invalid. Use IDs from the victim's listing endpoint, not guessed values.
- **Replay without fresh tokens.** Always re-authenticate both profiles at the start of each wave. Stale tokens produce misleading 401s.
- **Missing deduplication.** Call `mantis_list_findings` before recording to avoid duplicating findings from prior waves.

---

## Next chain

Feeds into **C12_account_takeover** (if PII or session material is leaked), **C4_multi_account_differential** (structured auth-differential across all endpoints), and **C16_cors_credentials** (if the IDOR endpoint is also CORS-credentialed).
