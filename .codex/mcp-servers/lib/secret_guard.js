"use strict";

/**
 * Shared secret-shaped-string guard so raw credentials never land in a
 * finding, evidence blob, or any other tool-owned payload (PRD section 9
 * "never raw secrets/tokens/cookies/full bodies", section 11 secrets/DLP).
 * This is a backstop, not a full DLP engine -- it only catches strings that
 * are shaped like a well-known credential format.
 */

const SECRET_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, // GitHub tokens
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, // Slack tokens
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/, // PEM private keys
  /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, // JWTs
  /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s/@]+:[^\s/@]+@[^\s/@]+/, // user:pass@ in a URL
  /\bAIza[0-9A-Za-z_-]{35}\b/, // Google API key
];

function scanForSecrets(value) {
  const hay = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return SECRET_PATTERNS.some((re) => re.test(hay));
}

module.exports = { SECRET_PATTERNS, scanForSecrets };
