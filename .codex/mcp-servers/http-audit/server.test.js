"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { auditExchange, redactValue } = require("./server.js");

test("redacts AWS access key ids", () => {
  assert.equal(
    redactValue("key=AKIAABCDEFGHIJKLMNOP"),
    "key=[REDACTED_AWS_KEY]",
  );
});

test("redacts classic and fine-grained GitHub tokens", () => {
  assert.equal(redactValue("ghp_" + "a".repeat(36)), "[REDACTED_GH_TOKEN]");
  assert.equal(
    redactValue("github_pat_" + "a".repeat(22) + "_" + "b".repeat(59)),
    "[REDACTED_GH_TOKEN]",
  );
});

test("redacts Slack tokens and incoming webhook URLs", () => {
  assert.equal(redactValue("xoxb-" + "1".repeat(12)), "[REDACTED_SLACK_TOKEN]");
  assert.equal(
    redactValue(
      "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    ),
    "[REDACTED_SLACK_WEBHOOK]",
  );
});

test("redacts Stripe live/test secret keys", () => {
  assert.equal(
    redactValue("sk_live_" + "a".repeat(24)),
    "[REDACTED_STRIPE_KEY]",
  );
  assert.equal(
    redactValue("rk_test_" + "a".repeat(24)),
    "[REDACTED_STRIPE_KEY]",
  );
});

test("redacts Google API keys", () => {
  assert.equal(
    redactValue("AIza" + "a".repeat(35)),
    "[REDACTED_GOOGLE_API_KEY]",
  );
});

test("redacts npm and SendGrid tokens", () => {
  assert.equal(redactValue("npm_" + "a".repeat(36)), "[REDACTED_NPM_TOKEN]");
  assert.equal(
    redactValue("SG." + "a".repeat(22) + "." + "b".repeat(43)),
    "[REDACTED_SENDGRID_KEY]",
  );
});

test("still redacts JWTs, PEM private keys, userinfo, and generic secret params", () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZXZhbHVl";
  assert.equal(redactValue(jwt), "[REDACTED_JWT]");

  const pem =
    "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----";
  assert.equal(redactValue(pem), "[REDACTED_PRIVATE_KEY]");

  assert.equal(
    redactValue("https://user:hunter2pw@example.com/"),
    "https://[REDACTED_USERINFO]@example.com/",
  );

  assert.equal(
    redactValue("password=hunter2&next=/home"),
    "password=[REDACTED]&next=/home",
  );
});

test("auditExchange redacts a new secret shape inside a request body and preserves the hash", () => {
  const request =
    "POST /billing HTTP/1.1\n" +
    "Host: example.com\n" +
    "Content-Type: application/x-www-form-urlencoded\n" +
    "\n" +
    "stripe_key=sk_live_" +
    "a".repeat(24);

  const pack = auditExchange({ request });
  assert.ok(!pack.request.body.preview.includes("sk_live_"));
  assert.match(pack.request.body.preview, /\[REDACTED_STRIPE_KEY\]/);
  assert.match(pack.request.request_ref, /^req-[a-f0-9]{16}$/);
});
