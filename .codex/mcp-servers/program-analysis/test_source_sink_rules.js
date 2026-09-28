#!/usr/bin/env node
"use strict";

// Plain-node regression test for source_sink_rules.js (no test framework wired
// for .codex/mcp-servers yet). Run directly: node test_source_sink_rules.js

const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(rule, snippet) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(snippet);
}

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `expected a rule with id ${id}`);
  return rule;
}

// No duplicate rule ids -- server.js keys findings off rule_id, so a
// collision would silently shadow one rule's coverage.
const ids = RULES.map((r) => r.id);
assert.equal(
  new Set(ids).size,
  ids.length,
  "RULES contains duplicate rule ids",
);

// CWE-22 (path traversal) coverage added in this change.
const cases = [
  {
    id: "js.fs.path_traversal",
    hit: "fs.readFileSync(path.join(baseDir, req.query.file));",
    miss: "fs.watch(configPath, onChange);",
  },
  {
    id: "py.flask.send_file",
    hit: "return send_from_directory(UPLOAD_DIR, request.args['name'])",
    miss: "return jsonify({'ok': True})",
  },
  {
    id: "go.os.path_traversal",
    hit: 'data, err := os.ReadFile(filepath.Join(root, r.URL.Query().Get("f")))',
    miss: 'log.Println(os.Getenv("HOME"))',
  },
];

for (const { id, hit, miss } of cases) {
  const rule = ruleById(id);
  assert.equal(rule.kind, "sink", `${id} should be a sink rule`);
  assert.equal(rule.cwe, "CWE-22", `${id} should be tagged CWE-22`);
  assert.ok(matches(rule, hit), `${id} should match: ${hit}`);
  assert.ok(!matches(rule, miss), `${id} should not match: ${miss}`);
}

console.log(
  `ok - ${cases.length} CWE-22 rule cases passed (${RULES.length} total rules)`,
);
