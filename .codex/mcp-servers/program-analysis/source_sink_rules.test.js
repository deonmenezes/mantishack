"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function idsMatching(lang, kind, snippet) {
  const hits = [];
  for (const rule of RULES.filter((r) => r.lang === lang && r.kind === kind)) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(snippet)) hits.push(rule.id);
  }
  return hits;
}

test("js: template-literal SQL query is flagged as a CWE-89 sink", () => {
  const hits = idsMatching(
    "js",
    "sink",
    "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
  );
  assert.ok(hits.includes("js.sql.query_template_literal"));
});

test("js: concatenated SQL query is flagged as a CWE-89 sink", () => {
  const hits = idsMatching(
    "js",
    "sink",
    'connection.query("SELECT * FROM users WHERE id = " + userId)',
  );
  assert.ok(hits.includes("js.sql.query_string_concat"));
});

test("js: parameterized query is not flagged as a SQL sink", () => {
  const hits = idsMatching(
    "js",
    "sink",
    'db.query("SELECT * FROM users WHERE id = ?", [userId])',
  );
  assert.deepEqual(
    hits.filter((id) => id.startsWith("js.sql.")),
    [],
  );
});

test("py: f-string cursor.execute is flagged as a CWE-89 sink", () => {
  const hits = idsMatching(
    "py",
    "sink",
    'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
  );
  assert.ok(hits.includes("py.sql.execute_fstring"));
});

test("py: %-formatted cursor.execute is flagged as a CWE-89 sink", () => {
  const hits = idsMatching(
    "py",
    "sink",
    'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
  );
  assert.ok(hits.includes("py.sql.execute_percent_format"));
});

test("py: concatenated cursor.execute is flagged as a CWE-89 sink", () => {
  const hits = idsMatching(
    "py",
    "sink",
    'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
  );
  assert.ok(hits.includes("py.sql.execute_string_concat"));
});

test("py: parameterized cursor.execute is not flagged as a SQL sink", () => {
  const hits = idsMatching(
    "py",
    "sink",
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
  );
  assert.deepEqual(
    hits.filter((id) => id.startsWith("py.sql.")),
    [],
  );
});

test("go: Sprintf-built query is flagged as a CWE-89 sink", () => {
  const hits = idsMatching(
    "go",
    "sink",
    'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))',
  );
  assert.ok(hits.includes("go.sql.query_sprintf"));
});

test("go: concatenated query is flagged as a CWE-89 sink", () => {
  const hits = idsMatching(
    "go",
    "sink",
    'db.Exec("SELECT * FROM users WHERE id = " + id)',
  );
  assert.ok(hits.includes("go.sql.query_string_concat"));
});

test("go: parameterized query is not flagged as a SQL sink", () => {
  const hits = idsMatching(
    "go",
    "sink",
    'db.Query("SELECT * FROM users WHERE id = ?", id)',
  );
  assert.deepEqual(
    hits.filter((id) => id.startsWith("go.sql.")),
    [],
  );
});

test("java: existing statement.execute SQL sink coverage is unaffected", () => {
  const hits = idsMatching("java", "sink", "statement.executeQuery(sql)");
  assert.ok(hits.includes("java.statement.execute"));
});
