"use strict";

/**
 * Shared secret-shape patterns for the Mantis DLP backstop (PRD section 9/11:
 * "never raw secrets/tokens/cookies/full bodies"). Previously this list was
 * forked between `http-audit/server.js` (redaction) and `findings/server.js`
 * (refusal guard), which had drifted out of sync -- the guard that decides
 * whether a finding/update payload gets REJECTED was missing several shapes
 * the redactor already knew about (generic `token=`/`password=` query params,
 * PEM key bodies, `user:pass@` URLs), so a payload containing e.g. a raw
 * `?api_key=...` value could be accepted by `finding_create` even though
 * `http_audit` would have redacted the same string. Centralizing here means
 * both call sites see every pattern and can't re-diverge.
 *
 * Each entry is `[regex, replacement]`. `replacement` is used by
 * `redactSecrets` (string or `(match, ...groups) => string`); `containsSecret`
 * only needs the regex half.
 */
const SECRET_VALUE_PATTERNS = [
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"], // AWS access key id
  [/\bASIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_STS_KEY]"], // AWS temporary (STS) access key id
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "[REDACTED_GH_TOKEN]"], // GitHub tokens
  [/\bgl[pf]at-[A-Za-z0-9_-]{20,}\b/g, "[REDACTED_GITLAB_TOKEN]"], // GitLab tokens
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED_SLACK_TOKEN]"], // Slack tokens
  [
    /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+\b/g,
    "[REDACTED_SLACK_WEBHOOK]",
  ],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, "[REDACTED_GOOGLE_API_KEY]"], // Google API key
  [/\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, "[REDACTED_STRIPE_KEY]"], // Stripe secret key
  [/\brk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, "[REDACTED_STRIPE_KEY]"], // Stripe restricted key
  [/\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, "[REDACTED_ANTHROPIC_KEY]"], // Anthropic API key
  [/\bsk-proj-[A-Za-z0-9_-]{20,}\b/g, "[REDACTED_OPENAI_KEY]"], // OpenAI project API key
  [/\bnpm_[A-Za-z0-9]{36}\b/g, "[REDACTED_NPM_TOKEN]"], // npm access token
  [
    /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    "[REDACTED_SENDGRID_KEY]",
  ], // SendGrid API key
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
  // shape (this is the pattern that used to exist only in http-audit, not in
  // the findings guard).
  [
    /\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\s]+)/gi,
    (_match, name) => `${name}=[REDACTED]`,
  ],
];

function redactSecrets(value) {
  let out = String(value);
  for (const [re, repl] of SECRET_VALUE_PATTERNS) out = out.replace(re, repl);
  return out;
}

function containsSecret(value) {
  const hay = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return SECRET_VALUE_PATTERNS.some(([re]) => {
    re.lastIndex = 0; // patterns are shared+global; reset before each .test()
    return re.test(hay);
  });
}

module.exports = { SECRET_VALUE_PATTERNS, redactSecrets, containsSecret };
