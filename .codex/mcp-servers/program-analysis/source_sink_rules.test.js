"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `expected a rule with id ${id}`);
  return rule;
}

function matches(rule, source) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(source);
}

test("SQL injection sinks fire on common raw-query call shapes", () => {
  const cases = [
    [
      "js.sql.query_call",
      'connection.query("SELECT * FROM users WHERE id = " + id)',
    ],
    ["js.sql.query_call", "pool.query(`SELECT * FROM users WHERE id = ${id}`)"],
    ["js.sql.query_call", "knex.raw(sql)"],
    [
      "py.sql.cursor_execute",
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ],
    ["py.sql.cursor_execute", "cur.execute(query)"],
    ["go.sql.query_call", "db.Query(query)"],
    ["go.sql.query_call", "tx.ExecContext(ctx, query)"],
  ];

  for (const [ruleId, source] of cases) {
    const rule = ruleById(ruleId);
    assert.equal(rule.kind, "sink");
    assert.equal(rule.cwe, "CWE-89");
    assert.ok(matches(rule, source), `${ruleId} should match: ${source}`);
  }
});

test("SQL injection sinks do not fire on unrelated calls", () => {
  const negatives = [
    ["js.sql.query_call", "urlParams.get(key)"],
    ["py.sql.cursor_execute", "subprocess.execute(cmd)"],
    ["go.sql.query_call", "logger.Query(msg)"],
  ];

  for (const [ruleId, source] of negatives) {
    const rule = ruleById(ruleId);
    assert.equal(
      matches(rule, source),
      false,
      `${ruleId} should not match: ${source}`,
    );
  }
});
