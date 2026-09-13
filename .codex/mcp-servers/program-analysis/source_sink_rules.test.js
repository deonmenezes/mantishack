"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matchingRuleIds(lang, code) {
  const hits = [];
  for (const rule of RULES) {
    if (rule.lang !== lang) continue;
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(code)) hits.push(rule.id);
  }
  return hits;
}

test("js SQL injection sinks fire on template-literal and concat interpolation", () => {
  assert.ok(
    matchingRuleIds(
      "js",
      "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);",
    ).includes("js.sql.query_template_literal"),
  );
  assert.ok(
    matchingRuleIds(
      "js",
      "connection.query('SELECT * FROM users WHERE name = ' + req.body.name);",
    ).includes("js.sql.query_string_concat"),
  );
});

test("js SQL injection sinks stay quiet on parameterized queries", () => {
  assert.deepEqual(
    matchingRuleIds(
      "js",
      "db.query('SELECT * FROM users WHERE id = ?', [id]);",
    ).filter((id) => id.startsWith("js.sql.")),
    [],
  );
  assert.deepEqual(
    matchingRuleIds(
      "js",
      "pool.query('SELECT * FROM users WHERE id = $1', [id]);",
    ).filter((id) => id.startsWith("js.sql.")),
    [],
  );
});

test("py SQL injection sinks fire on f-string, concat, and pre-execute percent interpolation", () => {
  assert.ok(
    matchingRuleIds(
      "py",
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ).includes("py.sql.execute_fstring"),
  );
  assert.ok(
    matchingRuleIds(
      "py",
      'cursor.execute("SELECT * FROM users WHERE name = " + name)',
    ).includes("py.sql.execute_string_concat"),
  );
  assert.ok(
    matchingRuleIds(
      "py",
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ).includes("py.sql.execute_percent_interpolation"),
  );
});

test("py SQL injection sinks stay quiet on parameterized queries", () => {
  assert.deepEqual(
    matchingRuleIds(
      "py",
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ).filter((id) => id.startsWith("py.sql.")),
    [],
  );
  assert.deepEqual(
    matchingRuleIds(
      "py",
      'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    ).filter((id) => id.startsWith("py.sql.")),
    [],
  );
});
