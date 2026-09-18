#!/usr/bin/env node
"use strict";

/**
 * Secret-shape patterns shared by every Mantis DLP backstop (PRD section
 * 9/11: raw secrets/tokens/keys/cookies must never land in a finding or an
 * evidence pack). `http-audit` uses this list to redact inline secrets out of
 * captured HTTP text; `findings` uses the same list to refuse a
 * finding_create/update payload that still carries one. They used to keep two
 * independently-maintained copies of this list, which had drifted: the
 * findings-spine guard was missing the `user:pass@` URL-userinfo shape and
 * the generic named-param shape (`password=...`, `api_key=...`, etc.), so a
 * secret that http-audit would have redacted could still slip straight into
 * a finding's evidence/description untouched. Keeping one shared list means
 * the two enforcement points can no longer diverge.
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
  // Generically-named secret-bearing query/form params -- shape-based patterns
  // above can't catch these since the secret value itself has no distinctive
  // shape.
  [
    /\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\s]+)/gi,
    (_match, name) => `${name}=[REDACTED]`,
  ],
];

// Boolean guard: does `value` contain a secret-shaped substring? Builds a
// fresh, non-global copy of each pattern per call so repeated calls can't trip
// on stale `lastIndex` state left behind by reusing a module-level `g`-flagged
// RegExp with `.test()`.
function containsSecret(value) {
  const hay = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return SECRET_VALUE_PATTERNS.some(([re]) => {
    const probe = new RegExp(re.source, re.flags.replace("g", ""));
    return probe.test(hay);
  });
}

function redactValue(value) {
  let out = String(value);
  for (const [re, repl] of SECRET_VALUE_PATTERNS) out = out.replace(re, repl);
  return out;
}

module.exports = { SECRET_VALUE_PATTERNS, containsSecret, redactValue };
