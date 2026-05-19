# `mantis goal`

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

Goal-directed engagement. Mantis keeps iterating waves until a declarative success criterion is met (or budget is exhausted).

```sh
mantis goal "find all endpoints"   --target https://app.example.com --i-have-authorization
mantis goal "find idor"            --target https://api.example.com --i-have-authorization
mantis goal "find vulnerabilities" --target https://app.example.com --i-have-authorization
mantis goal "authenticate and scan" --target https://app.example.com --i-have-authorization
```

The goal is parsed by `mantis_fsm::Goal::parse` into a structured `GoalKind`. Endpoint goals drive a wordlist-based expansion (default 200 candidates). Vuln-class goals drive the primitive→claim catalog. Each pass updates the goal's bookkeeping; the engagement stops on `Met` or budget exhaustion.

Live-tested against `app.tenkara.ai` — produced 76 surfaces in 3 passes from a single seed URL (vs 1 surface from `mantis pentest`).
