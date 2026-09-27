"use strict";

const crypto = require("node:crypto");

// Header names whose values are secret-bearing and must never survive into an
// evidence pack (PRD section 11 secrets/DLP).
const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "x-amz-security-token",
  "x-csrf-token",
  "x-xsrf-token",
]);

// Inline secret shapes that can appear anywhere in a body/URL.
const SECRET_VALUE_PATTERNS = [
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "[REDACTED_GH_TOKEN]"],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED_SLACK_TOKEN]"],
  [
    /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    "[REDACTED_JWT]",
  ],
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    "[REDACTED_PRIVATE_KEY]",
  ],
  // Common SaaS/cloud API key shapes that a generic named-param match below
  // can't reliably catch (e.g. they show up in URLs or bodies with no
  // recognizable param name, such as a Google Maps `key=` query param that
  // isn't covered by the generic list, or inline in JSON/text).
  [/\bAIza[0-9A-Za-z_-]{35,}\b/g, "[REDACTED_GOOGLE_API_KEY]"],
  [/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g, "[REDACTED_STRIPE_KEY]"],
  [
    /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b/g,
    "[REDACTED_SENDGRID_KEY]",
  ],
  [
    /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
    "[REDACTED_SLACK_WEBHOOK]",
  ],
  [/\bnpm_[A-Za-z0-9]{36,}\b/g, "[REDACTED_NPM_TOKEN]"],
  [/\b[A-Za-z0-9._%+-]+:[^@\s/]{6,}@/g, "[REDACTED_USERINFO]@"], // user:pass@ in URLs
  // Generically-named secret-bearing query/form params -- shape-based patterns above
  // can't catch these since the secret value itself has no distinctive shape.
  [
    /\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\s]+)/gi,
    (_match, name) => `${name}=[REDACTED]`,
  ],
];

const MAX_BODY_PREVIEW = 512;

function sha256(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function redactValue(value) {
  let out = String(value);
  for (const [re, repl] of SECRET_VALUE_PATTERNS) out = out.replace(re, repl);
  return out;
}

function redactHeaders(headers) {
  const redactedNames = [];
  const kept = headers.map(({ name, value }) => {
    if (SENSITIVE_HEADERS.has(name.toLowerCase())) {
      redactedNames.push(name);
      return { name, value: "[REDACTED]" };
    }
    return { name, value: redactValue(value) };
  });
  return { headers: kept, redactedNames };
}

function summarizeBody(body) {
  if (!body) return { present: false, bytes: 0 };
  const bytes = Buffer.byteLength(body, "utf8");
  const preview = redactValue(body).slice(0, MAX_BODY_PREVIEW);
  return {
    present: true,
    bytes,
    sha256: sha256(body),
    preview:
      preview + (body.length > MAX_BODY_PREVIEW ? " ...[truncated]" : ""),
  };
}

module.exports = {
  SENSITIVE_HEADERS,
  SECRET_VALUE_PATTERNS,
  MAX_BODY_PREVIEW,
  sha256,
  redactValue,
  redactHeaders,
  summarizeBody,
};
