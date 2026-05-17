# C14_race_condition_finbal

Test race conditions on balance-affecting endpoints — withdrawal, transfer, coupon redemption, referral bonus, promo application, refund, and point accrual — by sending concurrent requests within a narrow timing window. A successful race bypasses the server's idempotency or balance-check logic, allowing a single-use resource (a coupon, a balance, a transfer limit) to be consumed multiple times in parallel before any write commits. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface has financial or credit-balance endpoints: withdrawal, transfer, checkout, coupon, promo, referral, refund, or point-redemption.
- Recon or traffic shows endpoints that perform a read-check-write pattern on a shared resource.
- The application lacks explicit idempotency keys (`Idempotency-Key` header) or the keys are not enforced server-side.
- Bug-class hints include `race-condition`, `double-spend`, `idempotency`, `toctou`, or `balance-bypass`.

---

## Workflow

1. **Load assignment and map balance-affecting endpoints.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   From traffic summary and recon, list all endpoints that modify a shared numeric resource: `/api/wallet/withdraw`, `/api/coupon/redeem`, `/api/checkout/apply-promo`, `/api/referral/claim`, `/api/points/redeem`.

2. **Baseline: single request behavior.**
   Establish the pre-race account state (balance, coupon status, etc.):
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/wallet/balance", auth_profile: "attacker", egress_profile })
   ```
   Send one normal request and observe the result (balance deducted once, coupon marked used, etc.):
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/coupon/redeem", body: { code: "TESTCOUPON" }, auth_profile: "attacker", egress_profile })
   ```
   Confirm the idempotency behavior in a single-request context before racing.

3. **Idempotency key test.**
   Check whether the endpoint accepts an `Idempotency-Key` header:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/wallet/withdraw", body: { amount: 1 }, headers: { "Idempotency-Key": "mantis-test-key-1" }, auth_profile: "attacker", egress_profile })
   ```
   Send the same request twice with the same key. If the second request does NOT deduplicate (returns 200 with a second deduction instead of returning the cached first response), the key is not enforced.

4. **Concurrent burst — parallel request race.**
   Reset the coupon or use a fresh account state. Send N concurrent requests (start with N=5, increase to N=20 if results are mixed):
   ```
   mantis_run_tiered({ target_domain, wave, agent, surface_id, task: "race_burst", endpoint: "/api/coupon/redeem", method: "POST", body: { code: "TESTCOUPON" }, auth_profile: "attacker", concurrency: 20, egress_profile })
   ```
   Count responses: if more than one returns a success status (200/201) with a non-zero credit applied, the race condition is confirmed.

5. **Single-packet attack (HTTP/2).**
   For maximum race window compression, send all parallel requests in a single HTTP/2 DATA frame (single-packet attack). This ensures requests arrive at the application layer simultaneously, eliminating network jitter as a timing factor. Confirm the endpoint supports HTTP/2:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/wallet", headers: { ":scheme": "https" }, auth_profile: "attacker", egress_profile })
   ```
   If HTTP/2 is confirmed, note it in the proof_of_concept.

6. **Last-write-wins on balance check.**
   For transfer/withdrawal endpoints, race two concurrent withdrawal requests each for the full account balance:
   ```
   mantis_run_tiered({ target_domain, wave, agent, surface_id, task: "race_burst", endpoint: "/api/wallet/withdraw", method: "POST", body: { amount: 100, currency: "USD" }, auth_profile: "attacker", concurrency: 2, egress_profile })
   ```
   If both return 200 and the account goes to -100 (negative balance) or two successful withdrawal receipts are issued, a double-spend is confirmed.

7. **Promo-code race.**
   Apply the same discount code from two concurrent sessions:
   ```
   mantis_run_tiered({ target_domain, wave, agent, surface_id, task: "race_burst", endpoint: "/api/checkout/apply-promo", method: "POST", body: { promo: "SAVE50" }, auth_profile: "attacker", concurrency: 10, egress_profile })
   ```
   If the promo is applied twice (discount applied twice, or two concurrent orders each receive the discount), record as a financial race condition.

8. **Post-race state check.**
   After the race burst, check the account state:
   ```
   mantis_http_scan({ target_domain, method: "GET", path: "/api/wallet/balance", auth_profile: "attacker", egress_profile })
   mantis_http_scan({ target_domain, method: "GET", path: "/api/wallet/transactions", auth_profile: "attacker", egress_profile })
   ```
   Count successful transactions vs. expected. If balance exceeds what a single-use resource should yield, the race is proven.

9. **Log coverage.**
   ```
   mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/coupon/redeem", method: "POST", bug_class: "race_condition_double_spend", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "20 concurrent requests: 3 returned 200 with credit applied; balance shows 3x single redemption" }] })
   ```

10. **Record chain attempt.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "race-double-spend", step: "balance_inflated", evidence: "Coupon TESTCOUPON redeemed 3 times concurrently; balance shows 3x credit", outcome: "finding_recorded" })
    ```

11. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "Race condition on coupon redemption — double-spend", severity: "high", cwe: "CWE-362", endpoint: "/api/coupon/redeem", description: "...", proof_of_concept: "<20 concurrent POST requests; 3 returned 200; transaction log shows 3 credits>", response_evidence: "...", impact: "Attacker redeems a single-use coupon multiple times; financial loss to platform", validated: true })
    ```

12. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["Race on /api/coupon/redeem confirmed double-spend; severity high", "Withdrawal race needs funded test wallet to confirm negative balance"] })
    ```

13. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "race_replay", notes: "Reset coupon state; run 20-concurrent burst again; confirm >1 success response" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Pre-race account state (balance, coupon status, promo status).
- The concurrent request parameters: number of threads, timing window, HTTP version.
- Count of success responses returned and the specific success condition (200 with credit, balance change).
- Post-race transaction log showing multiple credits/debits from the single-use resource.
- If negative balance confirmed: balance before and after showing double-spend.

---

## Stop conditions

- All success responses deduplicate to exactly one effective transaction; extra requests return 409 (conflict) or 423 (locked).
- Database-level locking observed: all concurrent requests except one block and return after a delay with a rejection.
- Idempotency keys enforced server-side: repeated key returns cached response; race ineffective.
- Endpoint requires unique idempotency key per request and rejects duplicates.
- Two WAF blocks on burst requests — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **Network jitter masking the race.** If requests arrive at different times due to network latency, the race window may not be tight enough. Use HTTP/2 single-packet delivery or `mantis_run_tiered` concurrency for tighter timing.
- **Test environment serialization.** Some test/staging environments use single-threaded request processing; race conditions only manifest in production multi-threaded setups. Note if testing on staging.
- **Compensation logic.** Some platforms detect and reverse double-spends asynchronously (e.g. within seconds). Check the balance again 30 seconds after the race to confirm the credit is not rolled back.
- **Inflated concurrency without evidence.** Sending 100 concurrent requests is not itself a finding. The finding is the observation of multiple success responses for a single-use resource. Count and document each success.

---

## Next chain

Feeds into **GRADE** phase directly for financial impact findings. May chain with **C5_idor_burst** (if IDOR allows racing on other users' balance endpoints) and **C12_account_takeover** (if withdrawal race can drain victim accounts via IDOR).
