"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `rule ${id} not found`);
  return rule;
}

function fires(rule, text) {
  // Rules carry the `g` flag and are shared/reused across scans, so reset
  // lastIndex the same way the real scanner must to avoid stateful reuse bugs.
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(text);
}

test("js.header_injection.set_header fires on res.setHeader", () => {
  const rule = ruleById("js.header_injection.set_header");
  assert.equal(
    fires(rule, "res.setHeader('X-Callback', req.query.callback);"),
    true,
  );
});

test("js.header_injection.set_header fires on response.set", () => {
  const rule = ruleById("js.header_injection.set_header");
  assert.equal(fires(rule, "response.set('X-Foo', value);"), true);
});

test("js.header_injection.set_header does not fire on unrelated res usage", () => {
  const rule = ruleById("js.header_injection.set_header");
  assert.equal(fires(rule, "res.status(200).json(body);"), false);
});

test("py.header_injection.set_header fires on response.headers[...] assignment", () => {
  const rule = ruleById("py.header_injection.set_header");
  assert.equal(
    fires(rule, "response.headers['X-Redirect'] = request.args['next']"),
    true,
  );
});

test("py.header_injection.set_header does not fire on reading a header", () => {
  const rule = ruleById("py.header_injection.set_header");
  assert.equal(fires(rule, "value = response.headers['X-Redirect']"), false);
});

test("go.header_injection.header_set fires on w.Header().Set", () => {
  const rule = ruleById("go.header_injection.header_set");
  assert.equal(
    fires(rule, 'w.Header().Set("X-Callback", r.FormValue("cb"))'),
    true,
  );
});

test("java.header_injection.set_header fires on response.setHeader", () => {
  const rule = ruleById("java.header_injection.set_header");
  assert.equal(
    fires(rule, 'response.setHeader("X-Foo", request.getParameter("v"));'),
    true,
  );
});

test("java.header_injection.set_header fires on response.addHeader", () => {
  const rule = ruleById("java.header_injection.set_header");
  assert.equal(fires(rule, 'response.addHeader("X-Foo", value);'), true);
});

test("every CWE-113 sink rule is tagged and unique", () => {
  const headerRules = RULES.filter((r) => r.cwe === "CWE-113");
  assert.equal(headerRules.length, 4);
  const ids = headerRules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule ids");
  for (const rule of headerRules) {
    assert.equal(rule.kind, "sink");
    assert.ok(rule.pattern.flags.includes("g"), `${rule.id} must be global`);
  }
});

test("all rule ids across the table are unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule ids in RULES");
});
