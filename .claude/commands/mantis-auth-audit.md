---
description: Audit authentication (JWT, cookies) and security logging coverage automatically
---

# /mantis-auth-audit - Authentication + Logging Audit

You are helping the user run Mantishack's automatic authentication + security-logging audit on a code repository. This is an **opinionated subset** of `/mantis-scan` that focuses on the bugs most likely to compromise an application's auth boundary or hide an attack in production.

## What it checks

Semgrep rules live under `engine/semgrep/rules/auth/` and `engine/semgrep/rules/logging/`. They are selected by passing those directory names as policy groups (`--policy-groups auth,logging`); each rule is also tagged `mantis_capability: auth-audit` in its metadata for downstream grouping. The current rule pack covers:

| Family | Rule | Severity |
|---|---|---|
| JWT | `alg=none` accepted | HIGH |
| JWT | Hardcoded HMAC secret | HIGH |
| JWT | Missing `exp` claim | MEDIUM |
| JWT | No audience / issuer pinning | MEDIUM |
| Cookies | Missing `HttpOnly` | HIGH |
| Cookies | Missing `Secure` | HIGH |
| Cookies | Missing `SameSite` | MEDIUM |
| Cookies | Session id passed in URL query | HIGH |
| Logging | Auth failure with no log line | MEDIUM |
| Logging | Privileged action with no audit log | MEDIUM |
| Logging | Raw JWT / bearer / session-id written to logs | HIGH |
| TLS | `verify=False` on outbound HTTP | HIGH (inherited from `auth/tls-skip-verify`) |

## Your Task

1. **Identify the target**: ask which directory / repository to audit if not specified.

2. **Run the auth audit** (the `auth` and `logging` policy groups map to the
   `engine/semgrep/rules/auth/` and `engine/semgrep/rules/logging/` rule dirs):
   ```bash
   python3 mantishack.py scan --repo <path> --policy-groups auth,logging
   ```

3. **Then run the LLM validation pass** so the findings get exploitability triage (not just lint output). Use the `/mantis-validate` command on the same target:
   ```
   /mantis-validate <path>
   ```

4. **Report**:
   - Group findings by family (JWT / cookies / logging / TLS).
   - For each finding, show the severity, file:line, and the one-line message.
   - Call out anything HIGH explicitly at the top of the summary.
   - If the validation pass marked any finding `is_exploitable: true`, lead with that.

5. **Help fix issues**: offer to generate patches for the HIGH findings using `/mantis-patch` and to add the missing audit log lines.

## Relationship to `/mantis-agentic`

`/mantis-agentic` runs the full scan → dedup → prep → analysis pipeline. To make
the agentic run cover the same auth + logging rules, include them in its policy
groups (`--policy-groups auth,logging`, or add them to your existing group list).
Use `/mantis-auth-audit` when you only want the auth + logging subset on its own
(faster, more targeted).

## Example invocations

```bash
# Audit a single repo (auth + logging rule packs only)
/mantis-auth-audit /path/to/code

# Full agentic run that includes the auth/logging packs, then validates
/mantis-agentic /path/to/code --policy-groups auth,logging --validate
```
