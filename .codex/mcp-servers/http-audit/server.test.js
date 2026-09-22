"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { auditExchange, redactValue } = require("./server.js");

test("redacts a secret-bearing header outside the original narrow allowlist", () => {
  const request = [
    "GET /account HTTP/1.1",
    "Host: example.com",
    "Token: abc123.super-secret-token",
    "Api-Key: live_1234567890",
    "",
    "",
  ].join("\r\n");

  const { request: pack } = auditExchange({ request });
  const values = pack.headers.map((h) => h.value);
  assert.ok(!values.includes("abc123.super-secret-token"));
  assert.ok(!values.includes("live_1234567890"));
  assert.deepEqual(pack.redacted_headers.map((n) => n.toLowerCase()).sort(), [
    "api-key",
    "token",
  ]);
});

test("redacts generically-named secrets shaped as JSON fields, not just query params", () => {
  const body = '{"user":"alice","token":"eyJhbGciOiJIUzI1NiJ9.raw.value"}';
  const request = [
    "POST /login HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/json",
    "",
    body,
  ].join("\r\n");

  const { request: pack } = auditExchange({ request });
  assert.ok(!pack.body.preview.includes("eyJhbGciOiJIUzI1NiJ9.raw.value"));
  assert.ok(pack.body.preview.includes('"token":"[REDACTED]"'));
});

test("redacts provider-specific key shapes added for broader coverage", () => {
  assert.equal(
    redactValue("key=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBc0"),
    "key=[REDACTED_GCP_KEY]",
  );
  assert.equal(
    redactValue("sk_live_51H8xyzABCDEFGHIJKLMNOP"),
    "[REDACTED_STRIPE_KEY]",
  );
  assert.equal(
    redactValue("npm_abcdefghij0123456789ABCDEFGHIJKLMN"),
    "[REDACTED_NPM_TOKEN]",
  );
});

test("still redacts the original header/value shapes unchanged", () => {
  const request = [
    "GET /me HTTP/1.1",
    "Host: example.com",
    "Authorization: Bearer sometoken",
    "Cookie: session=abc",
    "",
    "",
  ].join("\r\n");

  const { request: pack } = auditExchange({ request });
  const byName = Object.fromEntries(
    pack.headers.map((h) => [h.name.toLowerCase(), h.value]),
  );
  assert.equal(byName["authorization"], "[REDACTED]");
  assert.equal(byName["cookie"], "[REDACTED]");
  assert.equal(redactValue("AKIAABCDEFGHIJKLMNOP"), "[REDACTED_AWS_KEY]");
});
