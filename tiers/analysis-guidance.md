# Adversarial Analysis Guidance
# Auto-loads: After Python scan completes (keywords: "findings", "results", "vulnerabilities")
# Token cost: ~300 tokens
# Purpose: Help user prioritize Python's findings with adversarial thinking

## Purpose

**Python scans everything in parallel** (no priority order in execution).
**This guide helps Claude analyze results** with adversarial lens to help user prioritize review.

---

## Result Analysis Priority (Not Execution Priority)

When Python returns findings, help user focus on highest-impact issues first:

### 1. Secrets/Credentials (If Found)
**Why review first:**
- Instant compromise (no exploitation needed)
- Maximum impact (cloud infrastructure, full account access)
- Examples: AWS keys, GitHub tokens, database passwords, API keys

**Present to user:** "Found [N] secrets - instant compromise risk - REVIEW FIRST"

### 2. Input Validation Issues (If Found)
**Why review second:**
- Most common and highly exploitable
- Direct impact (SQLi = database access, XSS = account takeover, command injection = RCE)
- Examples: SQL injection, XSS, command injection, deserialization

**Present to user:** "Found [N] input validation issues - high exploitability - REVIEW SECOND"

### 3. Authentication/Authorization (If Found)
**Why review third:**
- Critical access control failures
- Enables unauthorized access
- Examples: Missing auth checks, broken access control, IDOR, JWT issues

**Present to user:** "Found [N] auth issues - unauthorized access - REVIEW THIRD"

### 4. Cryptography Issues (If Found)
**Why review fourth:**
- Data protection failures
- Examples: Weak algorithms (MD5, SHA1, DES), hardcoded keys, weak random

**Present to user:** "Found [N] crypto issues - data protection - REVIEW FOURTH"

### 5. Configuration Issues (If Found)
**Why review last:**
- Security baseline problems
- Examples: Debug mode in production, insecure CORS, missing headers

**Present to user:** "Found [N] config issues - security baseline - REVIEW LAST"

---

## Decision Template

After analyzing and prioritizing Python's results:

```
Results: [N] findings from Python

[Summarize with adversarial priority ordering]

What next?
1. Deep - Analyze top findings in detail
2. Fix - Apply patches / review exploits Python generated
3. Generate report - Summarize and export
4. Retry - Run Python again with different parameters
5. Done - Finish

Your choice? [1-5]
```

**Execute user choice, then repeat template.**

---

## Important Notes

- This is for **presenting results**, not changing Python's execution
- Python scans everything (parallel, no priority order)
- Claude helps user understand what matters most
- User can always override this prioritization

**Example:**
```
User: "Show me config issues first, I don't care about secrets"
Claude: ✓ Showing config issues first (your priority)
```

User always has final say on what to review.
