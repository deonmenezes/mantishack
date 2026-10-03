"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function idsMatching(code) {
  const ids = [];
  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(code)) ids.push(rule.id);
  }
  return ids;
}

test("js.sql.string_built_query flags template-literal interpolation", () => {
  const code =
    "db.query(`SELECT * FROM users WHERE id = ${userId}`, callback);";
  assert.ok(idsMatching(code).includes("js.sql.string_built_query"));
});

test("js.sql.string_built_query flags string concatenation", () => {
  const code = 'connection.execute("SELECT * FROM t WHERE x = " + input);';
  assert.ok(idsMatching(code).includes("js.sql.string_built_query"));
});

test("js.sql.string_built_query does not flag parameterized queries", () => {
  const code = 'db.query("SELECT * FROM users WHERE id = ?", [userId]);';
  assert.ok(!idsMatching(code).includes("js.sql.string_built_query"));
});

test("py.sql.string_built_query flags f-strings passed to execute", () => {
  const code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")';
  assert.ok(idsMatching(code).includes("py.sql.string_built_query"));
});

test("py.sql.string_built_query flags % formatting", () => {
  const code = 'cursor.execute("SELECT * FROM t WHERE x = %s" % (value,))';
  assert.ok(idsMatching(code).includes("py.sql.string_built_query"));
});

test("py.sql.string_built_query flags .format( building", () => {
  const code = 'cursor.execute("SELECT * FROM t WHERE x = {}".format(value))';
  assert.ok(idsMatching(code).includes("py.sql.string_built_query"));
});

test("py.sql.string_built_query does not flag parameterized queries", () => {
  const code =
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))';
  assert.ok(!idsMatching(code).includes("py.sql.string_built_query"));
});

test("java.statement.execute coverage is unchanged", () => {
  const code = "statement.executeQuery(sql);";
  assert.ok(idsMatching(code).includes("java.statement.execute"));
});
