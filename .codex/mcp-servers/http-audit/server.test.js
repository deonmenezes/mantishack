"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { auditExchange, redactValue } = require("./server.js");

test("redacts secret-bearing fields in a JSON request body", () => {
  const request = [
    "POST /api/login HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/json",
    "",
    '{"username":"alice","password":"hunter2","api_key":"abc123XYZ"}',
  ].join("\r\n");

  const pack = auditExchange({ request });
  assert.equal(pack.request.body.preview.includes("hunter2"), false);
  assert.equal(pack.request.body.preview.includes("abc123XYZ"), false);
  assert.match(pack.request.body.preview, /"password":"\[REDACTED\]"/);
  assert.match(pack.request.body.preview, /"api_key":"\[REDACTED\]"/);
  // Non-secret fields survive untouched.
  assert.match(pack.request.body.preview, /"username":"alice"/);
});

test("still redacts form/query-encoded secret params", () => {
  const out = redactValue("token=abc123&user=bob");
  assert.equal(out, "token=[REDACTED]&user=bob");
});

test("redacts provider-shaped keys inline", () => {
  assert.equal(
    redactValue("key is sk_live_ABCDEFGHIJKLMNOPqrst"),
    "key is [REDACTED_STRIPE_KEY]",
  );
  assert.equal(
    redactValue("key is AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"),
    "key is [REDACTED_GOOGLE_API_KEY]",
  );
});

test("redacts Authorization/Cookie headers, keeps other headers intact", () => {
  const request = [
    "GET /api/me HTTP/1.1",
    "Host: example.com",
    "Authorization: Bearer sometoken",
    "Cookie: session=abc",
    "X-Request-Id: 1234",
    "",
    "",
  ].join("\r\n");

  const pack = auditExchange({ request });
  const byName = Object.fromEntries(
    pack.request.headers.map((h) => [h.name.toLowerCase(), h.value]),
  );
  assert.equal(byName["authorization"], "[REDACTED]");
  assert.equal(byName["cookie"], "[REDACTED]");
  assert.equal(byName["x-request-id"], "1234");
  assert.deepEqual(
    new Set(pack.request.redacted_headers),
    new Set(["Authorization", "Cookie"]),
  );
});
