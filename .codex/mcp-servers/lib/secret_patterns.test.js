"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { redactSecrets, containsSecret } = require("./secret_patterns.js");

test("redacts known secret shapes", () => {
  const cases = [
    ["AKIAABCDEFGHIJKLMNOP", "[REDACTED_AWS_KEY]"],
    ["ASIAABCDEFGHIJKLMNOP", "[REDACTED_AWS_STS_KEY]"],
    ["ghp_" + "a".repeat(36), "[REDACTED_GH_TOKEN]"],
    ["glpat-" + "a".repeat(20), "[REDACTED_GITLAB_TOKEN]"],
    ["xoxb-1234567890-abcdef", "[REDACTED_SLACK_TOKEN]"],
    [
      "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnop",
      "[REDACTED_SLACK_WEBHOOK]",
    ],
    ["AIza" + "a".repeat(35), "[REDACTED_GOOGLE_API_KEY]"],
    ["sk_live_" + "a".repeat(24), "[REDACTED_STRIPE_KEY]"],
    ["rk_test_" + "a".repeat(24), "[REDACTED_STRIPE_KEY]"],
    ["sk-ant-" + "a".repeat(24), "[REDACTED_ANTHROPIC_KEY]"],
    ["sk-proj-" + "a".repeat(24), "[REDACTED_OPENAI_KEY]"],
    ["npm_" + "a".repeat(36), "[REDACTED_NPM_TOKEN]"],
    ["SG." + "a".repeat(20) + "." + "b".repeat(20), "[REDACTED_SENDGRID_KEY]"],
    ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dGhpc2lzYXNpZw", "[REDACTED_JWT]"],
  ];
  for (const [input, marker] of cases) {
    const out = redactSecrets(`prefix ${input} suffix`);
    assert.ok(
      out.includes(marker),
      `expected redaction marker ${marker} for input ${input}, got: ${out}`,
    );
    assert.ok(!out.includes(input), `raw secret leaked through for ${input}`);
  }
});

test("redacts PEM private keys and user:pass@ URLs", () => {
  const pem =
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----";
  assert.equal(redactSecrets(pem), "[REDACTED_PRIVATE_KEY]");

  const url = "https://admin:sup3rSecret@internal.example.com/db";
  const out = redactSecrets(url);
  assert.ok(out.includes("[REDACTED_USERINFO]@"));
  assert.ok(!out.includes("sup3rSecret"));
});

test("redacts generically-named secret query/form params", () => {
  const url = "https://example.com/reset?token=abc123&user=alice";
  const out = redactSecrets(url);
  assert.ok(out.includes("token=[REDACTED]"));
  assert.ok(!out.includes("abc123"));
  assert.ok(out.includes("user=alice"));
});

test("containsSecret flags every shape redactSecrets knows about", () => {
  assert.equal(containsSecret("nothing sensitive here"), false);
  assert.equal(containsSecret("key is AIza" + "a".repeat(35)), true);
  assert.equal(containsSecret("login?password=hunter2&remember=1"), true);
  assert.equal(
    containsSecret(
      "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
    ),
    true,
  );
});

test("containsSecret is stateless across repeated calls (no lastIndex leakage)", () => {
  const value = "sk_live_" + "a".repeat(24);
  assert.equal(containsSecret(value), true);
  assert.equal(containsSecret(value), true);
  assert.equal(containsSecret(value), true);
});

test("containsSecret handles non-string values by stringifying", () => {
  assert.equal(
    containsSecret({ header: "Authorization", value: "ghp_" + "a".repeat(36) }),
    true,
  );
  assert.equal(containsSecret({ a: 1, b: "fine" }), false);
});
