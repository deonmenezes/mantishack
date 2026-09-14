"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(ruleId, content) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert.ok(rule, `rule ${ruleId} should exist`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(content);
}

test("js.sql.dynamic_query flags template-literal interpolation into query/execute", () => {
  assert.ok(
    matches(
      "js.sql.dynamic_query",
      "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
    ),
  );
});

test("js.sql.dynamic_query flags string concatenation into query/execute", () => {
  assert.ok(
    matches(
      "js.sql.dynamic_query",
      'conn.execute("SELECT * FROM users WHERE name = \'" + req.query.name + "\'")',
    ),
  );
});

test("js.sql.dynamic_query does not flag parameterized queries", () => {
  assert.ok(
    !matches(
      "js.sql.dynamic_query",
      'db.query("SELECT * FROM users WHERE id = ?", [req.params.id])',
    ),
  );
});

test("py.sql.dynamic_query flags f-string execute calls", () => {
  assert.ok(
    matches(
      "py.sql.dynamic_query",
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ),
  );
});

test("py.sql.dynamic_query flags percent-formatted execute calls", () => {
  assert.ok(
    matches(
      "py.sql.dynamic_query",
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ),
  );
});

test("py.sql.dynamic_query does not flag parameterized queries", () => {
  assert.ok(
    !matches(
      "py.sql.dynamic_query",
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
  );
});
