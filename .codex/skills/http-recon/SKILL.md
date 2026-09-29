---
name: http-recon
description: Run a single passive, discovery-only GET/HEAD request against an explicitly authorized live URL and surface security-misconfiguration candidates (missing hardening headers, weak cookie flags, version disclosure, debug pages) using the mantis_http_recon MCP server
---

Use `http_recon_scan` (`mantis_http_recon` MCP server) during Recon/Detect against a **live, running target you are explicitly authorized to test** -- not source code. It is the only wired capability in this catalog that touches the network; every other scanner (`semgrep`, `codeql`, `osv-scanner`, `trufflehog`, `bandit`, `trivy`) analyzes local source/deps and `http_audit` only post-processes traffic you already captured.

Before calling it: confirm scope and authorization for the exact host, same as any active-testing step in the `mantis-pipeline` skill. If authorization is unclear, do not call this tool -- stay on read-only static analysis.

What it does: one GET (or HEAD) request to the URL you pass, following up to 3 redirects, then analyzes only the plain response it got back:

- Missing hardening headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and clickjacking protection (`X-Frame-Options` or a CSP `frame-ancestors`).
- Weak `Set-Cookie` flags: missing `Secure` / `HttpOnly` / `SameSite`.
- Version-disclosing `Server` / `X-Powered-By` headers.
- A bounded (2KB) body preview checked against a small set of verbose debug/error-page patterns (Python traceback, Spring Whitelabel error, PHP DB warnings, `phpinfo()`, .NET unhandled exception, generic stack trace).

What it deliberately does NOT do, and never ask it to: send payloads, attempt auth bypass, brute-force paths, or touch more than the one URL you gave it. It refuses loopback/private/link-local hosts outright so it can't be pointed at internal infrastructure by accident. It is GET/HEAD only -- no state-changing methods.

Every hit is a `candidate` (class + subtype + bounded evidence + note), never a severity -- route it through `mantis_findings` `finding_create` like any other Detect-stage output, and let Validate/Reachability decide if it's worth confirming. A single passive scan is weak evidence on its own (e.g. a missing CSP is a hardening gap, not proof of an XSS); do not mark anything `confirmed` from this tool alone.
