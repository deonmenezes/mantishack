"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matchIds(content, lang) {
  const ids = [];
  for (const rule of RULES.filter((r) => r.lang === lang)) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(content)) ids.push(rule.id);
  }
  return ids;
}

test("SSRF sinks are tagged across supported languages (CWE-918)", () => {
  assert.ok(matchIds("fetch(url)", "js").includes("js.ssrf.fetch"));
  assert.ok(
    matchIds("axios.get(userSuppliedUrl)", "js").includes("js.ssrf.axios"),
  );
  assert.ok(
    matchIds("http.get(req.query.url, cb)", "js").includes(
      "js.ssrf.http_request",
    ),
  );
  assert.ok(
    matchIds("requests.get(request.args['url'])", "py").includes(
      "py.ssrf.requests",
    ),
  );
  assert.ok(
    matchIds("urllib.request.urlopen(target)", "py").includes("py.ssrf.urllib"),
  );
  assert.ok(
    matchIds('resp, err := http.Get(r.URL.Query().Get("url"))', "go").includes(
      "go.ssrf.http_client",
    ),
  );
  assert.ok(
    matchIds(
      "InputStream in = new URL(target).openConnection().getInputStream();",
      "java",
    ).includes("java.net.url_openconnection"),
  );
});

test("every rule reports a CWE for sink rules and none for source rules", () => {
  for (const rule of RULES) {
    if (rule.kind === "sink") {
      assert.ok(rule.cwe, `sink rule ${rule.id} is missing a cwe`);
    } else {
      assert.ok(!rule.cwe, `source rule ${rule.id} should not set a cwe`);
    }
  }
});

test("rule ids are unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.deepEqual(ids, [...new Set(ids)]);
});
