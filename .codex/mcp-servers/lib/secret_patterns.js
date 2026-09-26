"use strict";

/**
 * Canonical secret-shaped-string patterns shared by every DLP backstop in the
 * Mantis stack (PRD section 9/11: "never raw secrets/tokens/cookies/full
 * bodies"). `mantis_http_audit` redacts these out of evidence packs and the
 * findings spine (`mantis_findings`) refuses to persist a payload that
 * contains one; both used to keep their own copy of this list, and the
 * findings-spine copy had drifted behind -- it missed user:pass@ URL
 * credentials and generically-named secret params (`password=`, `api_key=`,
 * etc.) that http-audit already redacted. One shared list means the two
 * can't silently diverge again.
 *
 * Each entry is `[source, replacement, caseInsensitive?]`: `source` is a
 * RegExp source string (no `g`/`i` flags baked in, so callers choose `g` for
 * a replace-all pass or no flags for a single `.test()`), `replacement` is
 * either a literal string or a `String.replace` callback used only by
 * callers that redact rather than merely detect, and `caseInsensitive`
 * (default false) preserves each pattern's original case sensitivity --
 * e.g. `AKIA...` and PEM markers are upper-case by spec, so staying
 * case-sensitive there avoids widening what counts as secret-shaped.
 */
const SECRET_PATTERN_SPECS = [
  [String.raw`\bAKIA[0-9A-Z]{16}\b`, "[REDACTED_AWS_KEY]"],
  [String.raw`\bgh[pousr]_[A-Za-z0-9]{20,}\b`, "[REDACTED_GH_TOKEN]"],
  [String.raw`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`, "[REDACTED_SLACK_TOKEN]"],
  [
    String.raw`\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`,
    "[REDACTED_JWT]",
  ],
  [
    String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`,
    "[REDACTED_PRIVATE_KEY]",
  ],
  // user:pass@ credentials embedded in a URL.
  [String.raw`\b[A-Za-z0-9._%+-]+:[^@\s/]{6,}@`, "[REDACTED_USERINFO]@"],
  // Generically-named secret query/form params -- shape-based patterns above
  // can't catch these since the secret value itself has no distinctive shape.
  [
    String.raw`\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\s]+)`,
    (_match, name) => `${name}=[REDACTED]`,
    /* caseInsensitive */ true,
  ],
];

// Redaction regexes: global, for a String.replace pass across a whole value.
function redactionPatterns() {
  return SECRET_PATTERN_SPECS.map(([source, replacement, caseInsensitive]) => [
    new RegExp(source, caseInsensitive ? "gi" : "g"),
    replacement,
  ]);
}

// Detection regexes: non-global, for a single RegExp.test() guard.
function detectionPatterns() {
  return SECRET_PATTERN_SPECS.map(
    ([source, , caseInsensitive]) =>
      new RegExp(source, caseInsensitive ? "i" : ""),
  );
}

module.exports = { redactionPatterns, detectionPatterns };
