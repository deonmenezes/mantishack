---
description: Audit authentication (JWT, cookies) and security logging coverage automatically
---

# /mantis-auth-audit - Authentication + Logging Audit

You are helping the user run Mantishack's automatic authentication + security-logging audit on a code repository. This is an **opinionated subset** of `/mantis-scan` that focuses on the bugs most likely to compromise an application's auth boundary or hide an attack in production.

## What it checks

Semgrep rules under `engine/semgrep/rules/auth/` and `engine/semgrep/rules/logging/` are filtered by the `mantis_capability: auth-audit` tag. The current rule pack covers:

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

2. **Run the auth audit**:
   ```bash
   python3 mantishack.py scan --repo <path> \
     --rules engine/semgrep/rules/auth \
     --rules engine/semgrep/rules/logging \
     --policy-group jwt \
     --tag auth-audit
   ```

3. **Then run the LLM validation pass** so the findings get exploitability triage (not just lint output):
   ```bash
   python3 mantishack.py validate --repo <path> --tag auth-audit
   ```

4. **Report**:
   - Group findings by family (JWT / cookies / logging / TLS).
   - For each finding, show the severity, file:line, and the one-line message.
   - Call out anything HIGH explicitly at the top of the summary.
   - If the validation pass marked any finding `is_exploitable: true`, lead with that.

5. **Help fix issues**: offer to generate patches for the HIGH findings using `/mantis-patch` and to add the missing audit log lines.

## Automatic invocation

`/mantis-agentic` runs this audit as **step 2.5** of its pipeline by default — you do not need to call `/mantis-auth-audit` separately when running the full agentic workflow. Use this command when you only want the auth + logging subset (faster, more targeted).

## Example invocations

```bash
# Audit a single repo
/mantis-auth-audit /path/to/code

# Audit + validate + auto-patch in one shot
/mantis-agentic /path/to/code --auth-audit --validate
```
