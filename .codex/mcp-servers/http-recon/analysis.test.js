"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  analyzeHeaders,
  analyzeCookies,
  analyzeBodyPreview,
  isBlockedHost,
} = require("./analysis.js");

test("analyzeHeaders flags every missing hardening header on a bare response", () => {
  const candidates = analyzeHeaders({ "content-type": "text/html" });
  const subtypes = candidates.map((c) => c.subtype).sort();
  assert.deepEqual(subtypes, [
    "missing-clickjacking-protection",
    "missing-csp",
    "missing-hsts",
    "missing-permissions-policy",
    "missing-referrer-policy",
    "missing-x-content-type-options",
  ]);
});

test("analyzeHeaders does not flag headers that are present", () => {
  const candidates = analyzeHeaders({
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
    "x-frame-options": "DENY",
  });
  assert.deepEqual(candidates, []);
});

test("analyzeHeaders accepts csp frame-ancestors as clickjacking protection", () => {
  const candidates = analyzeHeaders({
    "content-security-policy": "frame-ancestors 'none'",
  });
  assert.ok(
    !candidates.some((c) => c.subtype === "missing-clickjacking-protection"),
  );
});

test("analyzeHeaders flags version-disclosing Server/X-Powered-By headers", () => {
  const candidates = analyzeHeaders({
    "server": "Apache/2.4.49",
    "x-powered-by": "PHP/7.4.3",
  });
  const subtypes = candidates.filter((c) => c.subtype === "version-disclosure");
  assert.equal(subtypes.length, 2);
});

test("analyzeHeaders does not flag a generic non-versioned Server header", () => {
  const candidates = analyzeHeaders({ server: "nginx" });
  assert.ok(!candidates.some((c) => c.subtype === "version-disclosure"));
});

test("analyzeCookies flags cookies missing Secure/HttpOnly/SameSite", () => {
  const candidates = analyzeCookies(["session=abc123; Path=/"]);
  assert.equal(candidates.length, 1);
  assert.deepEqual(candidates[0].evidence, {
    cookie: "session",
    missing_flags: ["Secure", "HttpOnly", "SameSite"],
  });
});

test("analyzeCookies does not flag a fully-hardened cookie", () => {
  const candidates = analyzeCookies([
    "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
  ]);
  assert.deepEqual(candidates, []);
});

test("analyzeCookies handles no Set-Cookie header", () => {
  assert.deepEqual(analyzeCookies(undefined), []);
  assert.deepEqual(analyzeCookies([]), []);
});

test("analyzeBodyPreview flags a Python traceback", () => {
  const candidates = analyzeBodyPreview(
    "Traceback (most recent call last):\n  File x",
  );
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].subtype, "python-traceback");
});

test("analyzeBodyPreview returns nothing for ordinary HTML", () => {
  assert.deepEqual(analyzeBodyPreview("<html><body>Hello</body></html>"), []);
  assert.deepEqual(analyzeBodyPreview(""), []);
});

test("isBlockedHost refuses loopback, private, and link-local hosts", () => {
  for (const host of [
    "localhost",
    "127.0.0.1",
    "10.0.0.5",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "::1",
  ]) {
    assert.equal(isBlockedHost(host), true, host);
  }
});

test("isBlockedHost allows public hosts", () => {
  for (const host of [
    "example.com",
    "vulnerable-bounty-site.vercel.app",
    "8.8.8.8",
  ]) {
    assert.equal(isBlockedHost(host), false, host);
  }
});
