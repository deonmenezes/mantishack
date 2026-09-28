"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { redactValue, containsSecret } = require("./secret_patterns.js");

// Built at runtime (not a string literal) so this fixture doesn't itself
// look like a checked-in Stripe key to secret-scanning tools.
function fakeStripeKey() {
  return `sk_live_${"a".repeat(24)}`;
}

test("redacts an AWS access key", () => {
  assert.equal(
    redactValue("key=AKIAABCDEFGHIJKLMNOP"),
    "key=[REDACTED_AWS_KEY]",
  );
});

test("redacts a Stripe secret key", () => {
  assert.equal(redactValue(fakeStripeKey()), "[REDACTED_STRIPE_KEY]");
});

test("redacts a Google API key", () => {
  const key = `AIza${"a".repeat(35)}`;
  assert.equal(redactValue(key), "[REDACTED_GOOGLE_API_KEY]");
});

test("redacts an npm token", () => {
  const token = `npm_${"a".repeat(36)}`;
  assert.equal(redactValue(token), "[REDACTED_NPM_TOKEN]");
});

test("redacts URL userinfo credentials", () => {
  assert.equal(
    redactValue("https://admin:hunters3cret@example.com/x"),
    "https://[REDACTED_USERINFO]@example.com/x",
  );
});

test("redacts named secret query params", () => {
  assert.equal(
    redactValue("https://example.com/login?password=hunter2&x=1"),
    "https://example.com/login?password=[REDACTED]&x=1",
  );
});

test("containsSecret catches the shapes findings' old backstop missed", () => {
  // Regression for the drift between findings/server.js and
  // http-audit/server.js: the findings refusal guard used to lack these two
  // patterns even though http-audit already redacted them.
  assert.equal(
    containsSecret("https://admin:hunters3cret@example.com/x"),
    true,
  );
  assert.equal(containsSecret("?password=hunter2"), true);
});

test("containsSecret is stateless across repeated calls (no global-regex lastIndex bug)", () => {
  const value = fakeStripeKey();
  assert.equal(containsSecret(value), true);
  assert.equal(containsSecret(value), true);
  assert.equal(containsSecret(value), true);
});

test("containsSecret returns false for ordinary text", () => {
  assert.equal(containsSecret("no secrets here, just plain text"), false);
});

test("redactValue leaves non-secret text untouched", () => {
  const value = "GET /api/users HTTP/1.1";
  assert.equal(redactValue(value), value);
});
