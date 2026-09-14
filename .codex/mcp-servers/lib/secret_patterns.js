"use strict";

/**
 * Canonical secret-shape patterns shared by every Mantis component that must
 * never let a raw credential escape into a finding, evidence pack, or report
 * (PRD section 9/11 secrets/DLP). One list means a shape added here protects
 * both the http-audit redactor and the findings-spine guard instead of the
 * two drifting out of sync -- which is what happened before this file
 * existed: http-audit redacted generic `token=`/`password=`/`secret=` query
 * params and `user:pass@` URLs, but the findings-spine guard's own pattern
 * list didn't include those shapes, so the same raw secret that would be
 * stripped from an HTTP evidence pack could still slip straight into a
 * finding's `claim`/`location` text.
 *
 * `source` is a flag-free regex source string. Callers pick the flags their
 * use case needs:
 *   - `detectionPattern(shape)`: a non-global RegExp for `.test()`. Safe to
 *     build once and reuse across many calls (no `lastIndex` statefulness).
 *   - `redactionPattern(shape)`: a global RegExp for `.replace()`.
 */
const SECRET_SHAPES = [
  {
    name: "aws_access_key",
    source: "\\bAKIA[0-9A-Z]{16}\\b",
    flags: "",
    replacement: "[REDACTED_AWS_KEY]",
  },
  {
    name: "github_token",
    source: "\\bgh[pousr]_[A-Za-z0-9]{20,}\\b",
    flags: "",
    replacement: "[REDACTED_GH_TOKEN]",
  },
  {
    name: "slack_token",
    source: "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b",
    flags: "",
    replacement: "[REDACTED_SLACK_TOKEN]",
  },
  {
    name: "jwt",
    source:
      "\\bey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    flags: "",
    replacement: "[REDACTED_JWT]",
  },
  {
    name: "pem_private_key",
    source:
      "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    flags: "",
    replacement: "[REDACTED_PRIVATE_KEY]",
  },
  {
    name: "url_userinfo",
    source: "\\b[A-Za-z0-9._%+-]+:[^@\\s/]{6,}@",
    flags: "",
    replacement: "[REDACTED_USERINFO]@",
  },
  {
    // Generically-named secret-bearing query/form params -- shape-based
    // patterns above can't catch these since the secret value itself has no
    // distinctive shape.
    name: "generic_named_secret",
    source:
      "\\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\\s]+)",
    flags: "i",
    replacement: (_match, key) => `${key}=[REDACTED]`,
  },
];

function detectionPattern(shape) {
  return new RegExp(shape.source, shape.flags.replace(/g/g, ""));
}

function redactionPattern(shape) {
  const flags = shape.flags.includes("g") ? shape.flags : `${shape.flags}g`;
  return new RegExp(shape.source, flags);
}

module.exports = { SECRET_SHAPES, detectionPattern, redactionPattern };
