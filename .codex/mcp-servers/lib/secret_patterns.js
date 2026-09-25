"use strict";

/**
 * Shared secret-shape patterns for the Mantis DLP backstop (PRD section 9/11:
 * "never raw secrets/tokens/cookies/full bodies" in findings/evidence/reports).
 *
 * Single source of truth so the findings-spine guard (`findings/server.js`)
 * and the evidence redactor (`http-audit/server.js`) can't drift out of sync
 * -- a pattern added to catch a new secret shape in one must not be silently
 * missing from the other.
 *
 * Each entry is `[regex, replacement]`: `replacement` is only used by
 * callers that redact (String.prototype.replace); callers that only need a
 * yes/no DLP check (String.prototype.test) can ignore it. Every regex here
 * carries the `g` flag for redaction's sake -- callers doing repeated
 * `.test()` calls on different strings MUST reset `lastIndex = 0` before
 * each call, since a global regex's `lastIndex` persists across calls and
 * `.test()` (unlike `.replace()`) does not reset it for you.
 */
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
  [/\b[A-Za-z0-9._%+-]+:[^@\s/]{6,}@/g, "[REDACTED_USERINFO]@"], // user:pass@ in URLs
  // Generically-named secret-bearing query/form params -- shape-based patterns above
  // can't catch these since the secret value itself has no distinctive shape.
  [
    /\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\s]+)/gi,
    (_match, name) => `${name}=[REDACTED]`,
  ],
];

module.exports = { SECRET_VALUE_PATTERNS };
