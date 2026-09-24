"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matchIds(content, lang) {
  const ids = [];
  for (const rule of RULES.filter((r) => r.lang === lang)) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(content)) ids.push(rule.id);
  }
  return ids;
}

test("js sql sink: flags template-literal interpolation in .query()", () => {
  const src = "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);";
  assert.ok(matchIds(src, "js").includes("js.sql.query_template_literal"));
});

test("js sql sink: flags string concatenation in .query()", () => {
  const src = "db.query('SELECT * FROM users WHERE id = ' + req.query.id);";
  assert.ok(matchIds(src, "js").includes("js.sql.query_string_concat"));
});

test("js sql sink: does not flag parameterized query", () => {
  const src = "db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);";
  const ids = matchIds(src, "js");
  assert.ok(!ids.includes("js.sql.query_template_literal"));
  assert.ok(!ids.includes("js.sql.query_string_concat"));
});

test("py sql sink: flags f-string passed to execute()", () => {
  const src = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")';
  assert.ok(matchIds(src, "py").includes("py.sql.execute_fstring"));
});

test("py sql sink: flags %-formatting and .format() passed to execute()", () => {
  const percent =
    'cursor.execute("SELECT * FROM users WHERE id = %s" % (user_id,))';
  const formatCall =
    'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))';
  assert.ok(
    matchIds(percent, "py").includes("py.sql.execute_concat_or_format"),
  );
  assert.ok(
    matchIds(formatCall, "py").includes("py.sql.execute_concat_or_format"),
  );
});

test("py sql sink: does not flag parameterized query", () => {
  const src = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))';
  const ids = matchIds(src, "py");
  assert.ok(!ids.includes("py.sql.execute_fstring"));
  assert.ok(!ids.includes("py.sql.execute_concat_or_format"));
});
