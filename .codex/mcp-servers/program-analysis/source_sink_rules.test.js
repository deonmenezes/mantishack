"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(id, text) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `no rule registered with id ${id}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(text);
}

test("every rule id is unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every sink rule carries a cwe", () => {
  for (const rule of RULES) {
    if (rule.kind === "sink") {
      assert.ok(rule.cwe, `sink rule ${rule.id} is missing a cwe`);
    }
  }
});

test("js TLS sinks flag disabled certificate verification", () => {
  assert.ok(
    matches(
      "js.tls.reject_unauthorized_false",
      "https.request({ rejectUnauthorized: false }, cb)",
    ),
  );
  assert.ok(
    matches(
      "js.tls.node_env_disable",
      'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"',
    ),
  );
});

test("js TLS sinks do not flag verification left enabled", () => {
  assert.equal(
    matches(
      "js.tls.reject_unauthorized_false",
      "https.request({ rejectUnauthorized: true }, cb)",
    ),
    false,
  );
});

test("python TLS sinks flag disabled/skipped certificate verification", () => {
  assert.ok(matches("py.tls.verify_false", "requests.get(url, verify=False)"));
  assert.ok(
    matches(
      "py.tls.unverified_context",
      "ctx = ssl._create_unverified_context()",
    ),
  );
  assert.ok(matches("py.tls.cert_none", "context.verify_mode = ssl.CERT_NONE"));
});

test("python TLS sinks do not flag verification left enabled", () => {
  assert.equal(
    matches("py.tls.verify_false", "requests.get(url, verify=True)"),
    false,
  );
});

test("go TLS sink flags InsecureSkipVerify", () => {
  assert.ok(
    matches(
      "go.tls.insecure_skip_verify",
      "tls.Config{InsecureSkipVerify: true}",
    ),
  );
});

test("go TLS sink does not flag verification left enabled", () => {
  assert.equal(
    matches(
      "go.tls.insecure_skip_verify",
      "tls.Config{InsecureSkipVerify: false}",
    ),
    false,
  );
});

test("java TLS sinks flag trust-all patterns", () => {
  assert.ok(
    matches(
      "java.tls.allow_all_hostname_verifier",
      "conn.setHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);",
    ),
  );
  assert.ok(
    matches(
      "java.tls.empty_trust_check",
      "public void checkClientTrusted(X509Certificate[] chain, String authType) {}",
    ),
  );
  assert.ok(
    matches(
      "java.tls.empty_trust_check",
      "public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}",
    ),
  );
});

test("java TLS empty-trust-check sink does not flag a real implementation", () => {
  assert.equal(
    matches(
      "java.tls.empty_trust_check",
      "public void checkServerTrusted(X509Certificate[] chain, String authType) { defaultTrustManager.checkServerTrusted(chain, authType); }",
    ),
    false,
  );
});
