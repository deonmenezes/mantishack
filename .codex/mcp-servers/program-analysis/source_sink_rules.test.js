"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(ruleId, content) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert.ok(rule, `rule ${ruleId} must exist`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(content);
}

test("js.sql.template_literal flags interpolated SQL", () => {
  assert.ok(
    matches(
      "js.sql.template_literal",
      "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
    ),
  );
  assert.ok(
    !matches(
      "js.sql.template_literal",
      "db.query('SELECT * FROM users WHERE id = ?', [userId])",
    ),
  );
});

test("js.sql.string_concat flags concatenated SQL", () => {
  assert.ok(
    matches(
      "js.sql.string_concat",
      "connection.execute('SELECT * FROM users WHERE id = ' + userId)",
    ),
  );
  assert.ok(
    !matches(
      "js.sql.string_concat",
      "connection.execute('SELECT * FROM users WHERE id = ?', [userId])",
    ),
  );
});

test("py.sql.fstring flags f-string SQL", () => {
  assert.ok(
    matches(
      "py.sql.fstring",
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ),
  );
  assert.ok(
    !matches(
      "py.sql.fstring",
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
  );
});

test("py.sql.percent_or_concat flags %-formatted and concatenated SQL", () => {
  assert.ok(
    matches(
      "py.sql.percent_or_concat",
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ),
  );
  assert.ok(
    matches(
      "py.sql.percent_or_concat",
      'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    ),
  );
  assert.ok(
    !matches(
      "py.sql.percent_or_concat",
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
  );
});

test("every rule has a distinct id", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every sink rule declares a CWE", () => {
  for (const rule of RULES.filter((r) => r.kind === "sink")) {
    assert.ok(rule.cwe, `sink rule ${rule.id} must declare a cwe`);
  }
});
