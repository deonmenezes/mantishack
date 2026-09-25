"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matchIds(lang, content) {
  const hits = [];
  for (const rule of RULES.filter((r) => r.lang === lang)) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(content)) hits.push(rule.id);
  }
  return hits;
}

test("flags JS SQL injection via template-literal interpolation", () => {
  const src = "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);";
  assert.ok(matchIds("js", src).includes("js.sql.query_template_literal"));
});

test("flags JS SQL injection via string concatenation", () => {
  const src = "db.query('SELECT * FROM users WHERE id = ' + req.query.id);";
  assert.ok(matchIds("js", src).includes("js.sql.query_string_concat"));
});

test("does not flag parameterized JS queries as SQL sinks", () => {
  const src = "db.query('SELECT * FROM users WHERE id = ?', [id]);";
  const hits = matchIds("js", src).filter((id) => id.startsWith("js.sql."));
  assert.deepEqual(hits, []);
});

test("flags Python SQL injection via f-string", () => {
  const src = 'cursor.execute(f"SELECT * FROM users WHERE id = {id}")';
  assert.ok(matchIds("py", src).includes("py.sql.execute_fstring"));
});

test("flags Python SQL injection via %/concat formatting", () => {
  const src = 'cursor.execute("SELECT * FROM users WHERE id = %s" % id)';
  assert.ok(matchIds("py", src).includes("py.sql.execute_format_or_concat"));
});

test("does not flag parameterized Python queries as SQL sinks", () => {
  const src = 'cursor.execute("SELECT * FROM users WHERE id = %s", (id,))';
  const hits = matchIds("py", src).filter((id) => id.startsWith("py.sql."));
  assert.deepEqual(hits, []);
});

test("flags Go SQL injection via fmt.Sprintf", () => {
  const src = 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))';
  assert.ok(matchIds("go", src).includes("go.sql.query_sprintf"));
});

test("does not flag parameterized Go queries as SQL sinks", () => {
  const src = 'db.Query("SELECT * FROM users WHERE id = $1", id)';
  const hits = matchIds("go", src).filter((id) => id.startsWith("go.sql."));
  assert.deepEqual(hits, []);
});
