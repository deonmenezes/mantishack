"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { redactValue, auditExchange } = require("./server.js");

test("redactValue strips JSON-quoted secret params (previously missed)", () => {
  const body = '{"user":"alice","api_key":"sk_live_abcdefghijklmnop1234"}';
  const redacted = redactValue(body);
  assert.ok(!redacted.includes("abcdefghijklmnop1234"));
  assert.match(redacted, /"api_key":"\[REDACTED\]"/);
});

test("redactValue strips common cloud/service credential shapes", () => {
  // Values below are synthetic (repeated filler chars in the right shape),
  // not real credentials -- picked so secret scanners don't flag the test.
  assert.equal(
    redactValue(`key=AIza${"x".repeat(35)}`),
    "key=[REDACTED_GOOGLE_API_KEY]",
  );
  assert.equal(
    redactValue(`sk_test_${"0".repeat(16)}`),
    "[REDACTED_STRIPE_KEY]",
  );
  assert.equal(redactValue(`npm_${"0".repeat(36)}`), "[REDACTED_NPM_TOKEN]");
  assert.equal(
    redactValue(`Authorization example: Bearer ${"x".repeat(24)}`),
    "Authorization example: Bearer [REDACTED]",
  );
});

test("auditExchange redacts JSON secrets in a captured response body", () => {
  const response = [
    "HTTP/1.1 200 OK",
    "Content-Type: application/json",
    "",
    '{"status":"ok","access_token":"abcdefghijklmnopqrstuvwxyz123456"}',
  ].join("\r\n");
  const pack = auditExchange({ response });
  assert.ok(
    !pack.response.body.preview.includes("abcdefghijklmnopqrstuvwxyz123456"),
  );
  assert.match(pack.response.body.preview, /"access_token":"\[REDACTED\]"/);
});
