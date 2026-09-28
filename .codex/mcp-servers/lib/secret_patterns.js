"use strict";

/**
 * Single source of truth for "this string looks like a raw secret" across
 * the Mantis MCP servers (PRD section 9/11: never let raw
 * secrets/tokens/cookies land in a finding or an evidence pack).
 *
 * Previously `findings/server.js` and `http-audit/server.js` each kept their
 * own copy of this pattern list. They had already drifted: the findings
 * refusal backstop was missing the URL-userinfo and named-secret-param
 * shapes that http-audit redacted, so a payload like `...?password=hunter2`
 * could pass the "does this look like a secret" guard and be written into
 * the append-only findings log. Consumers should import from here instead of
 * keeping a local copy, so the two paths can't fall out of sync again.
 */
const SECRET_PATTERNS = [
  {
    name: "aws_access_key",
    source: "\\bAKIA[0-9A-Z]{16}\\b",
    replacement: "[REDACTED_AWS_KEY]",
  },
  {
    name: "github_token",
    source: "\\bgh[pousr]_[A-Za-z0-9]{20,}\\b",
    replacement: "[REDACTED_GH_TOKEN]",
  },
  {
    name: "slack_token",
    source: "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b",
    replacement: "[REDACTED_SLACK_TOKEN]",
  },
  {
    name: "stripe_key",
    source: "\\bsk_(?:live|test)_[A-Za-z0-9]{16,}\\b",
    replacement: "[REDACTED_STRIPE_KEY]",
  },
  {
    name: "google_api_key",
    source: "\\bAIza[0-9A-Za-z_-]{35}\\b",
    replacement: "[REDACTED_GOOGLE_API_KEY]",
  },
  {
    name: "npm_token",
    source: "\\bnpm_[A-Za-z0-9]{36}\\b",
    replacement: "[REDACTED_NPM_TOKEN]",
  },
  {
    name: "jwt",
    source:
      "\\bey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    replacement: "[REDACTED_JWT]",
  },
  {
    name: "pem_private_key",
    source:
      "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    replacement: "[REDACTED_PRIVATE_KEY]",
  },
  {
    name: "url_userinfo",
    source: "\\b[A-Za-z0-9._%+-]+:[^@\\s/]{6,}@",
    replacement: "[REDACTED_USERINFO]@",
  },
  {
    // Generically-named secret-bearing query/form params -- shape-based
    // patterns above can't catch these since the secret value itself has no
    // distinctive shape.
    name: "named_secret_param",
    source:
      "\\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\\s]+)",
    flags: "i",
    replacement: (_match, name) => `${name}=[REDACTED]`,
  },
];

// Regex objects are stateful when built with the "g" flag (lastIndex
// advances across calls to .test()), so build a fresh RegExp per call
// instead of caching one on the pattern -- cheap, and avoids the classic
// "global regex .test() silently returns false every other call" bug.
function globalRegex(pattern) {
  const flags = (pattern.flags || "").replace("g", "") + "g";
  return new RegExp(pattern.source, flags);
}

function testRegex(pattern) {
  const flags = (pattern.flags || "").replace("g", "");
  return new RegExp(pattern.source, flags);
}

function redactValue(value) {
  let out = String(value);
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(globalRegex(pattern), pattern.replacement);
  }
  return out;
}

function containsSecret(value) {
  const hay = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return SECRET_PATTERNS.some((pattern) => testRegex(pattern).test(hay));
}

module.exports = { SECRET_PATTERNS, redactValue, containsSecret };
