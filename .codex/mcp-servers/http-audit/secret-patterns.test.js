"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { redactValue, SENSITIVE_HEADERS } = require("./secret-patterns.js");

test("redacts AWS access keys", () => {
  assert.equal(
    redactValue("key=AKIAABCDEFGHIJKLMNOP"),
    "key=[REDACTED_AWS_KEY]",
  );
});

test("redacts GitHub tokens", () => {
  assert.equal(redactValue(`ghp_${"a".repeat(36)}`), "[REDACTED_GH_TOKEN]");
});

test("redacts Slack webhook URLs", () => {
  assert.equal(
    redactValue("https://hooks.slack.com/services/T000/B000/xyzXYZ123"),
    "[REDACTED_SLACK_WEBHOOK]",
  );
});

test("redacts Stripe secret keys", () => {
  assert.equal(
    redactValue(`sk_live_${"a".repeat(24)}`),
    "[REDACTED_STRIPE_KEY]",
  );
});

test("redacts Google API keys", () => {
  assert.equal(
    redactValue(`AIza${"A".repeat(35)}`),
    "[REDACTED_GOOGLE_API_KEY]",
  );
});

test("redacts SendGrid keys", () => {
  assert.equal(
    redactValue(`SG.${"a".repeat(22)}.${"b".repeat(43)}`),
    "[REDACTED_SENDGRID_KEY]",
  );
});

test("redacts npm tokens", () => {
  assert.equal(redactValue(`npm_${"a".repeat(36)}`), "[REDACTED_NPM_TOKEN]");
});

test("redacts JWTs", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ";
  assert.equal(redactValue(jwt), "[REDACTED_JWT]");
});

test("leaves ordinary text untouched", () => {
  assert.equal(redactValue("hello world, status=ok"), "hello world, status=ok");
});

test("sensitive headers include GitLab and Cloudflare service secrets", () => {
  assert.ok(SENSITIVE_HEADERS.has("private-token"));
  assert.ok(SENSITIVE_HEADERS.has("cf-access-client-secret"));
  assert.ok(SENSITIVE_HEADERS.has("x-access-token"));
});
