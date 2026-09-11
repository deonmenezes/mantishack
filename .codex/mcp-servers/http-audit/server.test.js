"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { auditExchange, redactValue } = require("./server.js");

test("redacts sensitive headers by name", () => {
  const pack = auditExchange({
    request:
      "GET /api HTTP/1.1\r\nAuthorization: Bearer supersecrettoken\r\nCookie: sid=abc123\r\n\r\n",
  });
  const authHeader = pack.request.headers.find(
    (h) => h.name.toLowerCase() === "authorization",
  );
  const cookieHeader = pack.request.headers.find(
    (h) => h.name.toLowerCase() === "cookie",
  );
  assert.equal(authHeader.value, "[REDACTED]");
  assert.equal(cookieHeader.value, "[REDACTED]");
  assert.deepEqual(
    pack.request.redacted_headers.sort(),
    ["Authorization", "Cookie"].sort(),
  );
});

test("redacts form-encoded secret params in the body", () => {
  const out = redactValue("username=alice&password=hunter2&token=abcdef");
  assert.equal(out, "username=alice&password=[REDACTED]&token=[REDACTED]");
});

test("redacts secret-bearing fields in a JSON body", () => {
  const body = '{"username":"alice","password":"hunter2","token":"abc.def"}';
  const out = redactValue(body);
  assert.ok(!out.includes("hunter2"), "password value must not survive");
  assert.ok(!out.includes("abc.def"), "token value must not survive");
  assert.ok(out.includes('"username":"alice"'), "non-secret fields are kept");
  assert.ok(out.includes('"password":"[REDACTED]"'));
  assert.ok(out.includes('"token":"[REDACTED]"'));
});

test("JSON body redaction is case-insensitive on the key", () => {
  const out = redactValue('{"Password":"hunter2","API_KEY":"xyz"}');
  assert.ok(!out.includes("hunter2"));
  assert.ok(!out.includes("xyz"));
});

test("summarizeBody preview never leaks a JSON secret through auditExchange", () => {
  const pack = auditExchange({
    request:
      'POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"email":"a@example.com","password":"hunter2"}',
  });
  assert.ok(!pack.request.body.preview.includes("hunter2"));
  assert.ok(pack.request.body.preview.includes("a@example.com"));
});

test("still redacts shape-based secrets (AWS key, JWT, private key)", () => {
  const aws = redactValue("key=AKIAABCDEFGHIJKLMNOP");
  assert.ok(aws.includes("[REDACTED_AWS_KEY]"));

  const jwt = redactValue(
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789",
  );
  assert.ok(jwt.includes("[REDACTED_JWT]"));
});

test("request_ref/response_ref are stable content hashes over the raw text", () => {
  const raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
  const a = auditExchange({ request: raw });
  const b = auditExchange({ request: raw });
  assert.equal(a.request.request_ref, b.request.request_ref);
  assert.match(a.request.request_ref, /^req-[0-9a-f]{16}$/);
});

test("throws when neither request nor response is provided", () => {
  assert.throws(() => auditExchange({}), /Provide at least one/);
});
