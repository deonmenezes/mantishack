"use strict";

const assert = require("node:assert");
const { RULES } = require("./source_sink_rules.js");

function matchIds(lang, kind, sample) {
  const hits = [];
  for (const rule of RULES.filter((r) => r.lang === lang && r.kind === kind)) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(sample)) hits.push(rule.id);
  }
  return hits;
}

// JS: raw query-builder calls should be tagged CWE-89
assert.ok(
  matchIds(
    "js",
    "sink",
    "await pool.query(`SELECT * FROM users WHERE id = ${id}`)",
  ).includes("js.sql.query_call"),
  "expected pool.query(...) to match js.sql.query_call",
);
assert.ok(
  matchIds("js", "sink", "knex.raw('SELECT * FROM t WHERE x = ' + x)").includes(
    "js.sql.knex_raw",
  ),
  "expected knex.raw(...) to match js.sql.knex_raw",
);
assert.strictEqual(
  RULES.find((r) => r.id === "js.sql.query_call").cwe,
  "CWE-89",
);

// Python: cursor.execute / Django .objects.raw should be tagged CWE-89
assert.ok(
  matchIds(
    "py",
    "sink",
    "cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)",
  ).includes("py.sql.cursor_execute"),
  "expected cursor.execute(...) to match py.sql.cursor_execute",
);
assert.ok(
  matchIds(
    "py",
    "sink",
    "User.objects.raw('SELECT * FROM auth_user WHERE id = %s' % user_id)",
  ).includes("py.sql.django_raw"),
  "expected .objects.raw(...) to match py.sql.django_raw",
);
assert.strictEqual(
  RULES.find((r) => r.id === "py.sql.cursor_execute").cwe,
  "CWE-89",
);

// Unrelated calls in other languages should not pick up the new JS/Python rules
assert.strictEqual(matchIds("go", "sink", "pool.query(x)").length, 0);

console.log("source_sink_rules.test.js: all assertions passed");
