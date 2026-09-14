#!/usr/bin/env node
"use strict";

// Zero-deps regression test for source_sink_rules.js, using Node's built-in
// test runner. Run directly: node .codex/mcp-servers/program-analysis/test_source_sink_rules.js

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `expected a rule with id ${id}`);
  return rule;
}

function matches(rule, snippet) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(snippet);
}

test("js path-traversal sink rule fires on fs read/write and res.sendFile", () => {
  const rule = ruleById("js.path_traversal.file_read_write");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "fs.readFile(req.query.file, cb)"));
  assert.ok(matches(rule, "fs.readFileSync(userPath)"));
  assert.ok(matches(rule, "fs.createReadStream(req.params.name)"));
  assert.ok(matches(rule, "fs.writeFile(dest, data)"));
  assert.ok(matches(rule, "res.sendFile(req.query.path)"));
  assert.ok(!matches(rule, "const fs = require('fs');"));
});

test("python path-traversal sink rule fires on Flask send_file/send_from_directory", () => {
  const rule = ruleById("py.path_traversal.send_file");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "return send_file(request.args.get('path'))"));
  assert.ok(matches(rule, "send_from_directory(UPLOAD_DIR, filename)"));
  assert.ok(!matches(rule, "def send_file_report(): pass"));
});

test("go path-traversal sink rule fires on ServeFile/Open/ReadFile", () => {
  const rule = ruleById("go.path_traversal.file_read");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, 'http.ServeFile(w, r, r.URL.Query().Get("f"))'));
  assert.ok(matches(rule, "os.Open(userPath)"));
  assert.ok(matches(rule, "os.ReadFile(name)"));
  assert.ok(matches(rule, "ioutil.ReadFile(name)"));
});

test("java path-traversal sink rule fires on File/FileInputStream/FileReader construction", () => {
  const rule = ruleById("java.path_traversal.file_read");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, 'new File(request.getParameter("path"))'));
  assert.ok(matches(rule, "new FileInputStream(userPath)"));
  assert.ok(matches(rule, "new FileReader(name)"));
});

test("every rule has the required shape (lang, kind, id, pattern; cwe on sinks)", () => {
  for (const rule of RULES) {
    assert.equal(typeof rule.lang, "string");
    assert.ok(["source", "sink"].includes(rule.kind));
    assert.equal(typeof rule.id, "string");
    assert.ok(rule.pattern instanceof RegExp);
    assert.ok(
      rule.pattern.flags.includes("g"),
      `${rule.id} pattern must be global`,
    );
    if (rule.kind === "sink") {
      assert.match(
        rule.cwe,
        /^CWE-\d+$/,
        `${rule.id} sink must carry a CWE id`,
      );
    }
  }
});

test("rule ids are unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(ids.length, new Set(ids).size, "duplicate rule id found");
});
