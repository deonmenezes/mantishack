---
name: osv-dependency-scan
description: Run osv-scanner via the mantis_osv_scanner MCP server for SCA (vulnerable dependency) findings
---

Use `osv_scan({ path })` (mantis_osv_scanner MCP server) for the **Detect** stage's SCA coverage: known-vulnerable dependencies matched against the OSV database, recursively across manifests/lockfiles under `path`.

- Each result is a `candidate` keyed by package + version + advisory id (CVE/GHSA). A vulnerable dependency being present does **not** mean the vulnerable code path is reachable or exercised by the application -- that's a separate reachability question.
- `severity` is the advisory's own GHSA-style rating when the database sets one; for advisories that don't (most PyPI/crates.io/Go-native records), it's computed from the raw CVSS v3 vector instead, and the result also carries `cvss_vector`/`cvss_score` in that case. Only `"unknown"` means neither was available -- don't treat it as a real severity when triaging.
- Before validating, check whether the vulnerable function/API of the dependency is actually called anywhere in the target codebase (grep/ast-grep for the relevant import or call). If it's an unused transitive dependency, note that in the rejection reason rather than dropping the finding silently.
- Prefer `offline: true` only when the environment has no network access to query the live OSV database; note in your report that offline results may be stale.
- If `osv-scanner` reports `available: false`, say so explicitly -- don't claim SCA coverage you didn't actually get.
