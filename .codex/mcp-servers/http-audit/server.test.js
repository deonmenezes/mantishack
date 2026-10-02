#!/usr/bin/env node
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { auditExchange, redactValue } = require("./server.js");

test("redacts JSON-body secrets by key name, not just form-encoded ones", () => {
  const body = '{"api_key": "abcd1234efgh5678", "user": "bob"}';
  const out = redactValue(body);
  assert.match(out, /"api_key":\s*"\[REDACTED\]"/);
  assert.match(out, /"user":\s*"bob"/);
});

test("redacts shape-based secrets: Stripe, Google API key, npm token", () => {
  const body = [
    "stripe=sk_live_abcdefghijklmnop",
    "google=AIzaSyD-abcdefghijklmnopqrstuvwxyz01234",
    "npm=npm_abcdefghijklmnopqrstuvwxyz0123456789",
  ].join(" ");
  const out = redactValue(body);
  assert.ok(!out.includes("sk_live_abcdefghijklmnop"));
  assert.match(out, /\[REDACTED_STRIPE_KEY\]/);
  assert.ok(!out.includes("AIzaSyD-abcdefghijklmnopqrstuvwxyz01234"));
  assert.match(out, /\[REDACTED_GOOGLE_API_KEY\]/);
  assert.ok(!out.includes("npm_abcdefghijklmnopqrstuvwxyz0123456789"));
  assert.match(out, /\[REDACTED_NPM_TOKEN\]/);
});

test("redacts the Vercel protection-bypass header and other new sensitive headers", () => {
  const request =
    "GET /api/secret HTTP/1.1\n" +
    "Host: example.com\n" +
    "x-vercel-protection-bypass: super-secret-bypass-token\n" +
    "x-access-token: at-12345\n" +
    "x-refresh-token: rt-67890\n\n";
  const pack = auditExchange({ request });
  const byName = Object.fromEntries(
    pack.request.headers.map((h) => [h.name.toLowerCase(), h.value]),
  );
  assert.equal(byName["x-vercel-protection-bypass"], "[REDACTED]");
  assert.equal(byName["x-access-token"], "[REDACTED]");
  assert.equal(byName["x-refresh-token"], "[REDACTED]");
  assert.ok(
    pack.request.redacted_headers.includes("x-vercel-protection-bypass"),
  );
});

test("does not redact unrelated JSON fields", () => {
  const body = '{"name": "mantishack", "count": 3}';
  assert.equal(redactValue(body), body);
});
