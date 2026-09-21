"use strict";

// Run with: node --test .codex/mcp-servers/program-analysis/source_sink_rules.test.js
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

test("js: flags template-literal-built SQL", () => {
  const src = "db.query(`SELECT * FROM users WHERE id = ${userId}`);";
  assert.ok(matchIds(src, "js").includes("js.sql.template_literal"));
});

test("js: flags string-concat-built SQL", () => {
  const src = 'conn.query("SELECT * FROM users WHERE id = " + userId);';
  assert.ok(matchIds(src, "js").includes("js.sql.string_concat"));
});

test("js: does not flag parameterized queries", () => {
  const src = 'db.query("SELECT * FROM users WHERE id = ?", [userId]);';
  const ids = matchIds(src, "js");
  assert.ok(!ids.includes("js.sql.template_literal"));
  assert.ok(!ids.includes("js.sql.string_concat"));
});

test("py: flags f-string-built SQL", () => {
  const src = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")';
  assert.ok(matchIds(src, "py").includes("py.sql.execute_fstring"));
});

test("py: flags %-formatted and .format()-built SQL", () => {
  const percentSrc =
    'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)';
  const formatSrc =
    'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))';
  assert.ok(
    matchIds(percentSrc, "py").includes("py.sql.execute_percent_or_format"),
  );
  assert.ok(
    matchIds(formatSrc, "py").includes("py.sql.execute_percent_or_format"),
  );
});

test("py: flags concatenation-built SQL", () => {
  const src = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)';
  assert.ok(matchIds(src, "py").includes("py.sql.execute_concat"));
});

test("py: does not flag parameterized queries", () => {
  const src = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))';
  const ids = matchIds(src, "py");
  assert.ok(!ids.includes("py.sql.execute_fstring"));
  assert.ok(!ids.includes("py.sql.execute_percent_or_format"));
  assert.ok(!ids.includes("py.sql.execute_concat"));
});

test("go: flags fmt.Sprintf-built SQL", () => {
  const src =
    'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))';
  assert.ok(matchIds(src, "go").includes("go.sql.sprintf"));
});

test("go: flags concatenation-built SQL", () => {
  const src =
    'db.QueryContext(ctx, "SELECT * FROM users WHERE id = " + userID)';
  assert.ok(matchIds(src, "go").includes("go.sql.string_concat"));
});

test("go: does not flag parameterized queries", () => {
  const src = 'db.Query("SELECT * FROM users WHERE id = $1", userID)';
  const ids = matchIds(src, "go");
  assert.ok(!ids.includes("go.sql.sprintf"));
  assert.ok(!ids.includes("go.sql.string_concat"));
});

test("java statement.execute sink still fires (regression check)", () => {
  const src = 'statement.executeQuery("SELECT * FROM users WHERE id = " + id);';
  assert.ok(matchIds(src, "java").includes("java.statement.execute"));
});
