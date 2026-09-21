#!/usr/bin/env node
"use strict";

/**
 * Lightweight, dependency-free regression test for source_sink_rules.js.
 * Run with `node test_source_sink_rules.js`. Exits non-zero on failure so it
 * can be wired into CI without pulling in a test framework.
 */
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `rule ${id} not found`);
  return rule;
}

function matches(rule, snippet) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(snippet);
}

let passed = 0;
function check(description, condition) {
  assert.ok(condition, description);
  passed++;
}

// -- js.sql.injection_concat -------------------------------------------------
{
  const rule = ruleById("js.sql.injection_concat");
  check(
    "flags template-literal interpolation in .query()",
    matches(rule, "db.query(`SELECT * FROM users WHERE id = ${id}`)"),
  );
  check(
    "flags string concatenation in .execute()",
    matches(rule, 'connection.execute("SELECT * FROM users WHERE id = " + id)'),
  );
  check(
    "flags concatenation in .raw()",
    matches(rule, 'knex.raw("SELECT * FROM t WHERE id = " + id)'),
  );
  check(
    "does not flag a parameterized .query() call",
    !matches(rule, 'db.query("SELECT * FROM users WHERE id = ?", [id])'),
  );
  check(
    "does not flag a query-builder .where() call",
    !matches(rule, "knex('users').where({ id })"),
  );
}

// -- py.sql.injection_format -------------------------------------------------
{
  const rule = ruleById("py.sql.injection_format");
  check(
    "flags an f-string passed to .execute()",
    matches(rule, 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'),
  );
  check(
    "flags %-formatting passed to .execute()",
    matches(
      rule,
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ),
  );
  check(
    "flags .format() passed to .execute()",
    matches(
      rule,
      'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))',
    ),
  );
  check(
    "flags + concatenation passed to .executemany()",
    matches(
      rule,
      'cursor.executemany("SELECT * FROM users WHERE id = " + user_id)',
    ),
  );
  check(
    "does not flag a parameterized .execute() call",
    !matches(
      rule,
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
  );
}

console.log(`ok - ${passed} source/sink rule assertions passed`);
