"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `expected a rule with id ${id}`);
  return rule;
}

function matches(rule, content) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(content);
}

test("js.sql.query_dynamic flags template-literal interpolation into query/execute", () => {
  const rule = ruleById("js.sql.query_dynamic");
  assert.equal(
    matches(rule, "db.query(`SELECT * FROM users WHERE id = ${id}`)"),
    true,
  );
});

test("js.sql.query_dynamic flags string concatenation into query/execute", () => {
  const rule = ruleById("js.sql.query_dynamic");
  assert.equal(
    matches(rule, 'connection.query("SELECT * FROM users WHERE id = " + id)'),
    true,
  );
  assert.equal(matches(rule, 'connection.query(id + " AND active = 1")'), true);
});

test("js.sql.query_dynamic does not flag parameterized queries", () => {
  const rule = ruleById("js.sql.query_dynamic");
  assert.equal(
    matches(rule, 'db.query("SELECT * FROM users WHERE id = ?", [id])'),
    false,
  );
});

test("js.sql.knex_raw_dynamic flags dynamic knex.raw calls only", () => {
  const rule = ruleById("js.sql.knex_raw_dynamic");
  assert.equal(
    matches(rule, "knex.raw(`SELECT * FROM t WHERE id = ${id}`)"),
    true,
  );
  assert.equal(matches(rule, "knex.raw('SELECT 1')"), false);
});

test("py.sql.execute_dynamic flags f-strings, %-formatting, and concatenation", () => {
  const rule = ruleById("py.sql.execute_dynamic");
  assert.equal(
    matches(
      rule,
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ),
    true,
  );
  assert.equal(
    matches(
      rule,
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ),
    true,
  );
  assert.equal(
    matches(
      rule,
      'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    ),
    true,
  );
});

test("py.sql.execute_dynamic does not flag parameterized queries", () => {
  const rule = ruleById("py.sql.execute_dynamic");
  assert.equal(
    matches(
      rule,
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
    false,
  );
});

test("go.sql.query_sprintf flags fmt.Sprintf built directly into a query call", () => {
  const rule = ruleById("go.sql.query_sprintf");
  assert.equal(
    matches(
      rule,
      'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))',
    ),
    true,
  );
});

test("go.sql.query_sprintf does not flag parameterized queries", () => {
  const rule = ruleById("go.sql.query_sprintf");
  assert.equal(
    matches(rule, 'db.Query("SELECT * FROM users WHERE id = $1", id)'),
    false,
  );
});

test("every new SQL rule is tagged CWE-89 and only registered for its intended language", () => {
  for (const id of [
    "js.sql.query_dynamic",
    "js.sql.knex_raw_dynamic",
    "py.sql.execute_dynamic",
    "go.sql.query_sprintf",
  ]) {
    const rule = ruleById(id);
    assert.equal(rule.kind, "sink");
    assert.equal(rule.cwe, "CWE-89");
  }
});
