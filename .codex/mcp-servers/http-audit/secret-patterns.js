"use strict";

/**
 * Secret-bearing header names and inline value shapes that must never survive
 * into an HTTP evidence pack (PRD section 9/11: "never raw secrets/tokens/
 * cookies/full bodies" in findings/evidence). Split out from server.js so the
 * patterns can be unit-tested without booting the MCP stdio transport.
 */

// Header names whose values are secret-bearing and must never survive into an
// evidence pack.
const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "x-access-token",
  "x-amz-security-token",
  "x-csrf-token",
  "x-xsrf-token",
  "private-token", // GitLab personal/project access tokens
  "cf-access-client-secret", // Cloudflare Access service tokens
]);

// Inline secret shapes that can appear anywhere in a body/URL.
const SECRET_VALUE_PATTERNS = [
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "[REDACTED_GH_TOKEN]"],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED_SLACK_TOKEN]"],
  [
    /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
    "[REDACTED_SLACK_WEBHOOK]",
  ],
  [/\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, "[REDACTED_STRIPE_KEY]"],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, "[REDACTED_GOOGLE_API_KEY]"],
  [
    /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    "[REDACTED_SENDGRID_KEY]",
  ],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, "[REDACTED_NPM_TOKEN]"],
  [
    /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    "[REDACTED_JWT]",
  ],
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    "[REDACTED_PRIVATE_KEY]",
  ],
  [/\b[A-Za-z0-9._%+-]+:[^@\s/]{6,}@/g, "[REDACTED_USERINFO]@"], // user:pass@ in URLs
  // Generically-named secret-bearing query/form params -- shape-based patterns above
  // can't catch these since the secret value itself has no distinctive shape.
  [
    /\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\s]+)/gi,
    (_match, name) => `${name}=[REDACTED]`,
  ],
];

function redactValue(value) {
  let out = String(value);
  for (const [re, repl] of SECRET_VALUE_PATTERNS) out = out.replace(re, repl);
  return out;
}

module.exports = { SENSITIVE_HEADERS, SECRET_VALUE_PATTERNS, redactValue };
