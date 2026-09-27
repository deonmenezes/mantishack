"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  redactValue,
  redactHeaders,
  SENSITIVE_HEADERS,
} = require("./redact.js");

test("redacts AWS access keys", () => {
  assert.equal(
    redactValue("aws_key=AKIAABCDEFGHIJKLMNOP"),
    "aws_key=[REDACTED_AWS_KEY]",
  );
});

test("redacts Google API keys inline in a URL", () => {
  const value =
    "https://maps.googleapis.com/maps/api/geocode/json?key=AIzaSyD9tSrke72PouQMnMXa7eZSW0jkFMBWY0X";
  const redacted = redactValue(value);
  assert.match(redacted, /\[REDACTED_GOOGLE_API_KEY\]/);
  assert.doesNotMatch(redacted, /AIzaSy/);
});

test("redacts Stripe secret keys", () => {
  // Not a real key: a placeholder built from repeated filler characters,
  // just enough to satisfy the key's documented shape.
  const value = `sk_test_${"x".repeat(24)}`;
  assert.equal(redactValue(value), "[REDACTED_STRIPE_KEY]");
});

test("redacts SendGrid API keys", () => {
  // Not a real key: placeholder segments of the right length, not entropy
  // that resembles an issued credential.
  const value = `SG.${"x".repeat(22)}.${"y".repeat(43)}`;
  assert.match(redactValue(value), /\[REDACTED_SENDGRID_KEY\]/);
});

test("redacts Slack incoming webhook URLs", () => {
  const value =
    "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
  assert.equal(redactValue(value), "[REDACTED_SLACK_WEBHOOK]");
});

test("redacts npm publish tokens", () => {
  const value = `npm_${"a".repeat(36)}`;
  assert.equal(redactValue(value), "[REDACTED_NPM_TOKEN]");
});

test("leaves unrelated text untouched", () => {
  assert.equal(
    redactValue("hello world, nothing to see here"),
    "hello world, nothing to see here",
  );
});

test("still redacts sensitive headers by name and everything else passes through", () => {
  const { headers, redactedNames } = redactHeaders([
    { name: "Authorization", value: `Bearer ${"x".repeat(30)}` },
    { name: "X-Request-Id", value: "abc-123" },
  ]);
  assert.deepEqual(redactedNames, ["Authorization"]);
  assert.deepEqual(headers, [
    { name: "Authorization", value: "[REDACTED]" },
    { name: "X-Request-Id", value: "abc-123" },
  ]);
  assert.ok(SENSITIVE_HEADERS.has("authorization"));
});
