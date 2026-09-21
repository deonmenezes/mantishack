"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function firstMatch(ruleId, sample) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert.ok(rule, `no rule registered with id ${ruleId}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.exec(sample);
}

test("SSRF rules flag dynamic-URL HTTP calls", () => {
  assert.ok(firstMatch("js.ssrf.fetch_dynamic_url", "fetch(userUrl)"));
  assert.ok(
    firstMatch("js.ssrf.axios_dynamic_url", "axios.get(req.query.target)"),
  );
  assert.ok(
    firstMatch("js.ssrf.http_request_dynamic_url", "http.get(targetUrl, cb)"),
  );
  assert.ok(
    firstMatch("py.ssrf.requests_dynamic_url", "requests.get(target_url)"),
  );
  assert.ok(
    firstMatch(
      "py.ssrf.urllib_urlopen_dynamic",
      "urllib.request.urlopen(target_url)",
    ),
  );
  assert.ok(firstMatch("py.ssrf.httpx_dynamic_url", "httpx.get(target_url)"));
  assert.ok(firstMatch("go.ssrf.http_get_dynamic", "http.Get(targetURL)"));
  assert.ok(
    firstMatch(
      "go.ssrf.http_newrequest_dynamic",
      'http.NewRequest("GET", targetURL, nil)',
    ),
  );
  assert.ok(firstMatch("java.ssrf.url_construction", "new URL(targetUrl)"));
  assert.ok(firstMatch("java.ssrf.uri_create", "URI.create(targetUrl)"));
});

test("SSRF rules do not flag string-literal URLs", () => {
  assert.equal(
    firstMatch("js.ssrf.fetch_dynamic_url", 'fetch("https://api.example.com")'),
    null,
  );
  assert.equal(
    firstMatch(
      "py.ssrf.requests_dynamic_url",
      'requests.get("https://api.example.com")',
    ),
    null,
  );
  assert.equal(
    firstMatch(
      "go.ssrf.http_get_dynamic",
      'http.Get("https://api.example.com")',
    ),
    null,
  );
  assert.equal(
    firstMatch(
      "java.ssrf.url_construction",
      'new URL("https://api.example.com")',
    ),
    null,
  );
});

test("every rule id is unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});
