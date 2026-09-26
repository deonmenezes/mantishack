"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { redactValue, auditExchange } = require("./server.js");

test("redactValue masks AWS access keys", () => {
  const out = redactValue("key=AKIAABCDEFGHIJKLMNOP");
  assert.equal(out.includes("AKIAABCDEFGHIJKLMNOP"), false);
  assert.match(out, /\[REDACTED_AWS_KEY\]/);
});

test("redactValue masks Google API keys", () => {
  const key = `AIza${"A".repeat(35)}`;
  const out = redactValue(`https://example.com/api?key=${key}`);
  assert.equal(out.includes(key), false);
  assert.match(out, /\[REDACTED_GOOGLE_API_KEY\]/);
});

test("redactValue masks Stripe live and test secret keys", () => {
  const live = `sk_live_${"a".repeat(24)}`;
  const test_ = `sk_test_${"b".repeat(24)}`;
  const out = redactValue(`${live} ${test_}`);
  assert.equal(out.includes(live), false);
  assert.equal(out.includes(test_), false);
  assert.match(out, /\[REDACTED_STRIPE_KEY\]/);
});

test("redactValue masks SendGrid API keys", () => {
  const key = `SG.${"a".repeat(22)}.${"b".repeat(43)}`;
  const out = redactValue(key);
  assert.equal(out.includes(key), false);
  assert.match(out, /\[REDACTED_SENDGRID_KEY\]/);
});

test("redactValue masks npm publish tokens", () => {
  const key = `npm_${"a".repeat(36)}`;
  const out = redactValue(key);
  assert.equal(out.includes(key), false);
  assert.match(out, /\[REDACTED_NPM_TOKEN\]/);
});

test("redactValue masks Slack incoming webhook URLs", () => {
  // Built from repeated segments (not a literal token-shaped string) so this
  // fixture can't be mistaken for a real credential by secret scanners.
  const url = `https://hooks.slack.com/services/T${"0".repeat(9)}/B${"0".repeat(9)}/${"x".repeat(24)}`;
  const out = redactValue(url);
  assert.equal(out.includes(url), false);
  assert.match(out, /\[REDACTED_SLACK_WEBHOOK\]/);
});

test("redactValue leaves unrelated text untouched", () => {
  const text = "GET /health HTTP/1.1";
  assert.equal(redactValue(text), text);
});

test("auditExchange strips a Stripe key from a captured body", () => {
  const key = `sk_live_${"c".repeat(24)}`;
  const request = [
    "POST /charge HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/json",
    "",
    `{"stripe_key":"${key}"}`,
  ].join("\r\n");

  const pack = auditExchange({ request });
  assert.equal(pack.request.body.preview.includes(key), false);
  assert.match(pack.request.body.preview, /\[REDACTED_STRIPE_KEY\]/);
});
