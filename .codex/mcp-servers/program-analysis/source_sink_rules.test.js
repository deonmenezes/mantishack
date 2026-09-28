"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(ruleId, content) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert.ok(rule, `no rule registered with id ${ruleId}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(content);
}

test("js.sql.string_built_query flags template-literal interpolation into query()", () => {
  assert.equal(
    matches(
      "js.sql.string_built_query",
      "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)",
    ),
    true,
  );
});

test("js.sql.string_built_query flags string concatenation into execute()", () => {
  assert.equal(
    matches(
      "js.sql.string_built_query",
      "conn.execute('SELECT * FROM users WHERE name = ' + name)",
    ),
    true,
  );
});

test("js.sql.string_built_query does not flag a parameterized query", () => {
  assert.equal(
    matches(
      "js.sql.string_built_query",
      "db.query('SELECT * FROM users WHERE id = ?', [id])",
    ),
    false,
  );
});

test("py.sql.string_built_execute flags an f-string passed to execute()", () => {
  assert.equal(
    matches(
      "py.sql.string_built_execute",
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ),
    true,
  );
});

test("py.sql.string_built_execute flags %-formatting passed to execute()", () => {
  assert.equal(
    matches(
      "py.sql.string_built_execute",
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ),
    true,
  );
});

test("py.sql.string_built_execute does not flag a parameterized query", () => {
  assert.equal(
    matches(
      "py.sql.string_built_execute",
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
    false,
  );
});
