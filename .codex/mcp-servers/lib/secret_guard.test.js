"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { scanForSecrets } = require("./secret_guard.js");

test("scanForSecrets catches known credential shapes", () => {
  assert.equal(scanForSecrets("AKIAABCDEFGHIJKLMNOP"), true);
  assert.equal(scanForSecrets("ghp_" + "a".repeat(36)), true);
  assert.equal(scanForSecrets("xoxb-1234567890-abcdefghij"), true);
  assert.equal(
    scanForSecrets("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n"),
    true,
  );
  assert.equal(
    scanForSecrets(
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ),
    true,
  );
  assert.equal(scanForSecrets("AIza" + "a".repeat(35)), true);
});

test("scanForSecrets catches credentials embedded in a URL", () => {
  assert.equal(
    scanForSecrets("postgres://admin:S3cr3tPass@db.internal:5432/prod"),
    true,
  );
  assert.equal(scanForSecrets("https://user:hunter2@example.com/path"), true);
});

test("scanForSecrets does not flag ordinary URLs or plain text", () => {
  assert.equal(scanForSecrets("https://example.com/path?a=1&b=2"), false);
  assert.equal(scanForSecrets("http://example.com:8080/page"), false);
  assert.equal(
    scanForSecrets("The bug lives in auth.js around line 42."),
    false,
  );
});

test("scanForSecrets inspects non-string payloads via JSON.stringify", () => {
  assert.equal(
    scanForSecrets({
      claim: "leaked db url",
      location: { file: "db.js" },
      evidence: ["conn=postgres://admin:hunter2@db.internal/prod"],
    }),
    true,
  );
  assert.equal(
    scanForSecrets({ claim: "sql injection", location: { file: "db.js" } }),
    false,
  );
});
