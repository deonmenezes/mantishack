"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  SECRET_SHAPES,
  detectionPattern,
  redactionPattern,
} = require("./secret_patterns.js");

test("detection patterns catch every shape http-audit redacts", () => {
  const samples = {
    aws_access_key: "AKIAABCDEFGHIJKLMNOP",
    github_token: `ghp_${"a".repeat(20)}`,
    slack_token: "xoxb-1111111111-abcdefghij",
    jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    pem_private_key:
      "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
    url_userinfo: "https://alice:sup3rsecret@example.com/path",
    generic_named_secret: "GET /login?password=hunter2&next=/",
  };

  for (const shape of SECRET_SHAPES) {
    const sample = samples[shape.name];
    assert.ok(sample, `missing sample for shape ${shape.name}`);
    assert.match(
      sample,
      detectionPattern(shape),
      `${shape.name} detection pattern should match its sample`,
    );
  }
});

test("detection pattern is reusable across repeated calls (no global lastIndex drift)", () => {
  const shape = SECRET_SHAPES.find((s) => s.name === "generic_named_secret");
  const pattern = detectionPattern(shape);
  const text = "token=abcdef123456";
  assert.equal(pattern.test(text), true);
  assert.equal(
    pattern.test(text),
    true,
    "second .test() call should still match",
  );
});

test("redaction pattern strips the secret and keeps the rest of the string", () => {
  const shape = SECRET_SHAPES.find((s) => s.name === "aws_access_key");
  const redacted = "key is AKIAABCDEFGHIJKLMNOP inline".replace(
    redactionPattern(shape),
    shape.replacement,
  );
  assert.equal(redacted, "key is [REDACTED_AWS_KEY] inline");
});

test("generic named-secret redaction preserves the param name", () => {
  const shape = SECRET_SHAPES.find((s) => s.name === "generic_named_secret");
  const redacted = "password=hunter2&next=/".replace(
    redactionPattern(shape),
    shape.replacement,
  );
  assert.equal(redacted, "password=[REDACTED]&next=/");
});
