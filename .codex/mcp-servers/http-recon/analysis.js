"use strict";

/**
 * Pure response-analysis functions for mantis-http-recon, split out of
 * server.js so they can be unit-tested without loading the stdio transport
 * (which attaches stdin listeners and calls process.exit on stdin close).
 */

const HARDENING_HEADERS = [
  {
    header: "strict-transport-security",
    subtype: "missing-hsts",
    note: "No Strict-Transport-Security header -- HTTPS is not enforced by the browser for future visits.",
  },
  {
    header: "content-security-policy",
    subtype: "missing-csp",
    note: "No Content-Security-Policy header -- reduces defense-in-depth against XSS/data-injection.",
  },
  {
    header: "x-content-type-options",
    subtype: "missing-x-content-type-options",
    note: "No X-Content-Type-Options: nosniff -- browsers may MIME-sniff responses.",
  },
  {
    header: "referrer-policy",
    subtype: "missing-referrer-policy",
    note: "No Referrer-Policy header -- full URLs (possibly with sensitive query params) may leak via the Referer header.",
  },
  {
    header: "permissions-policy",
    subtype: "missing-permissions-policy",
    note: "No Permissions-Policy header -- browser features are not explicitly restricted.",
  },
];

const CLICKJACKING_HEADERS = ["x-frame-options"];

const VERSION_DISCLOSURE_HEADERS = ["server", "x-powered-by"];

const DEBUG_PAGE_PATTERNS = [
  [/whitelabel error page/i, "spring-boot-whitelabel-error"],
  [/traceback \(most recent call last\)/i, "python-traceback"],
  [/warning:\s*(mysql|pg_query|mysqli)_/i, "php-db-warning"],
  [/\bphpinfo\(\)/i, "phpinfo-disclosure"],
  [/stack trace:/i, "generic-stack-trace"],
  [/An unhandled exception occurred/i, "dotnet-unhandled-exception"],
];

function sortHeaderEntries(headers) {
  return Object.entries(headers).map(([name, value]) => [
    name.toLowerCase(),
    Array.isArray(value) ? value.join(", ") : String(value ?? ""),
  ]);
}

// Flags hostnames that would send this tool's only network call at internal
// infrastructure instead of the intended external target.
function isBlockedHost(hostname) {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "0.0.0.0" || h === "::1" || h === "::") return true;
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 127) return true; // loopback
    if (a === 10) return true; // RFC1918
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
    if (a === 192 && b === 168) return true; // RFC1918
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
  }
  return false;
}

function analyzeHeaders(headers) {
  const entries = sortHeaderEntries(headers);
  const byName = new Map(entries);
  const candidates = [];

  for (const { header, subtype, note } of HARDENING_HEADERS) {
    if (!byName.has(header)) {
      candidates.push({
        class: "security-misconfiguration",
        subtype,
        evidence: { missing_header: header },
        note,
      });
    }
  }

  const hasFrameOptions = CLICKJACKING_HEADERS.some((h) => byName.has(h));
  const csp = byName.get("content-security-policy") || "";
  const hasFrameAncestors = /frame-ancestors/i.test(csp);
  if (!hasFrameOptions && !hasFrameAncestors) {
    candidates.push({
      class: "security-misconfiguration",
      subtype: "missing-clickjacking-protection",
      evidence: { missing_header: "x-frame-options / csp frame-ancestors" },
      note: "Neither X-Frame-Options nor a CSP frame-ancestors directive is set -- page may be embeddable in a hostile iframe.",
    });
  }

  for (const header of VERSION_DISCLOSURE_HEADERS) {
    const value = byName.get(header);
    if (value && /[0-9]/.test(value)) {
      candidates.push({
        class: "security-misconfiguration",
        subtype: "version-disclosure",
        evidence: { header, value: value.slice(0, 200) },
        note: `${header} discloses a specific server/framework version, narrowing an attacker's exploit search.`,
      });
    }
  }

  return candidates;
}

function analyzeCookies(setCookieHeaders) {
  if (!setCookieHeaders || setCookieHeaders.length === 0) return [];
  const candidates = [];
  for (const raw of setCookieHeaders) {
    const [nameValue] = raw.split(";", 1);
    const cookieName = (nameValue.split("=")[0] || "").trim() || "(unnamed)";
    const lower = raw.toLowerCase();
    const missing = [];
    if (!lower.includes("secure")) missing.push("Secure");
    if (!lower.includes("httponly")) missing.push("HttpOnly");
    if (!lower.includes("samesite")) missing.push("SameSite");
    if (missing.length > 0) {
      candidates.push({
        class: "security-misconfiguration",
        subtype: "weak-cookie-flags",
        evidence: { cookie: cookieName, missing_flags: missing },
        note: `Cookie '${cookieName}' is missing: ${missing.join(", ")}.`,
      });
    }
  }
  return candidates;
}

function analyzeBodyPreview(bodyPreview) {
  if (!bodyPreview) return [];
  const candidates = [];
  for (const [pattern, subtype] of DEBUG_PAGE_PATTERNS) {
    const match = bodyPreview.match(pattern);
    if (match) {
      candidates.push({
        class: "information-disclosure",
        subtype,
        evidence: { matched_text: match[0].slice(0, 200) },
        note: "Response body looks like a verbose debug/error page, which can leak stack traces, paths, or framework internals.",
      });
    }
  }
  return candidates;
}

module.exports = {
  analyzeHeaders,
  analyzeCookies,
  analyzeBodyPreview,
  isBlockedHost,
};
