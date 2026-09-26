"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { auditExchange, redactValue } = require("./server.js");

// Fixture secrets are assembled from non-adjacent parts so no file on disk
// ever contains a byte-contiguous string matching a real secret scanner's
// pattern (these are shape-correct fakes, not leaked credentials).
const SAMPLE_AWS_KEY = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");
const SAMPLE_GOOGLE_API_KEY = [
  "AIza",
  "SyD9tSrke72PouQMnMXa7eZSW0jkFMB0abc",
].join("");
const SAMPLE_STRIPE_LIVE_KEY = ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join(
  "_",
);
const SAMPLE_STRIPE_TEST_KEY = ["rk", "test", "4eC39HqLyjWDarjtT1zdp7dc"].join(
  "_",
);
const SAMPLE_NPM_TOKEN = ["npm", "a".repeat(36)].join("_");

test("redacts AWS access key shapes", () => {
  assert.equal(redactValue(`key=${SAMPLE_AWS_KEY}`), "key=[REDACTED_AWS_KEY]");
});

test("redacts a Google API key even without a key= prefix", () => {
  const body = JSON.stringify({ apiKey: SAMPLE_GOOGLE_API_KEY });
  assert.equal(redactValue(body), '{"apiKey":"[REDACTED_GOOGLE_API_KEY]"}');
});

test("redacts Stripe live and test secret keys", () => {
  assert.equal(redactValue(SAMPLE_STRIPE_LIVE_KEY), "[REDACTED_STRIPE_KEY]");
  assert.equal(redactValue(SAMPLE_STRIPE_TEST_KEY), "[REDACTED_STRIPE_KEY]");
});

test("redacts npm automation tokens", () => {
  assert.equal(redactValue(SAMPLE_NPM_TOKEN), "[REDACTED_NPM_TOKEN]");
});

test("does not touch unrelated body text", () => {
  const body = "hello world, nothing secret here";
  assert.equal(redactValue(body), body);
});

test("auditExchange redacts a Google API key inside a JSON response body", () => {
  const response = [
    "HTTP/1.1 200 OK",
    "Content-Type: application/json",
    "",
    JSON.stringify({ apiKey: SAMPLE_GOOGLE_API_KEY }),
  ].join("\r\n");

  const pack = auditExchange({ response });
  assert.ok(!pack.response.body.preview.includes(SAMPLE_GOOGLE_API_KEY));
  assert.ok(pack.response.body.preview.includes("[REDACTED_GOOGLE_API_KEY]"));
});

test("auditExchange still redacts sensitive header names wholesale", () => {
  const request = [
    "GET /api/account HTTP/1.1",
    "Host: example.com",
    `Authorization: Bearer ${SAMPLE_STRIPE_LIVE_KEY}`,
    "",
    "",
  ].join("\r\n");

  const pack = auditExchange({ request });
  const auth = pack.request.headers.find(
    (h) => h.name.toLowerCase() === "authorization",
  );
  assert.equal(auth.value, "[REDACTED]");
  assert.deepEqual(pack.request.redacted_headers, ["Authorization"]);
});
