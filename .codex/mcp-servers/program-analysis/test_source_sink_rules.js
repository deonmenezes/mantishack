#!/usr/bin/env node
"use strict";

// Regression test for the source/sink heuristic rule table -- in particular
// the new CWE-601 (open redirect) sink coverage. Run with `node
// test_source_sink_rules.js`; exits non-zero on failure.

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(rule, code) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(code);
}

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `expected a rule with id ${id}`);
  return rule;
}

test("js.express.redirect flags unsanitized Express redirects as CWE-601", () => {
  const rule = ruleById("js.express.redirect");
  assert.equal(rule.cwe, "CWE-601");
  assert.ok(matches(rule, "res.redirect(req.query.next);"));
  assert.ok(matches(rule, "response.redirect(target);"));
});

test("py.redirect flags Flask/Django redirects as CWE-601", () => {
  const rule = ruleById("py.redirect");
  assert.equal(rule.cwe, "CWE-601");
  assert.ok(matches(rule, "return redirect(request.args.get('next'))"));
  assert.ok(matches(rule, "return HttpResponseRedirect(next_url)"));
});

test("go.http.redirect flags net/http redirects as CWE-601", () => {
  const rule = ruleById("go.http.redirect");
  assert.equal(rule.cwe, "CWE-601");
  assert.ok(matches(rule, "http.Redirect(w, r, next, http.StatusFound)"));
});

test("java.response.sendredirect flags servlet redirects as CWE-601", () => {
  const rule = ruleById("java.response.sendredirect");
  assert.equal(rule.cwe, "CWE-601");
  assert.ok(
    matches(rule, 'response.sendRedirect(request.getParameter("next"));'),
  );
});

test("every rule stays scoped to its own language and keeps a unique id", () => {
  const seen = new Set();
  for (const rule of RULES) {
    assert.ok(!seen.has(rule.id), `duplicate rule id: ${rule.id}`);
    seen.add(rule.id);
    assert.ok(["js", "py", "go", "java"].includes(rule.lang));
    assert.ok(["source", "sink"].includes(rule.kind));
  }
});
