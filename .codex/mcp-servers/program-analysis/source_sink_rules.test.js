#!/usr/bin/env node
"use strict";

/**
 * Plain-node smoke test for source_sink_rules.js (no test framework wired
 * for the .codex/mcp-servers tree). Run with: node source_sink_rules.test.js
 */
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function idsForLang(lang, kind) {
  return RULES.filter((r) => r.lang === lang && r.kind === kind).map(
    (r) => r.id,
  );
}

function matches(id, sample) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `no rule registered with id ${id}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(sample);
}

// Every rule must have a unique id.
const ids = RULES.map((r) => r.id);
assert.equal(new Set(ids).size, ids.length, "duplicate rule id found");

// Every sink rule must carry a CWE for report clarity.
for (const rule of RULES.filter((r) => r.kind === "sink")) {
  assert.ok(rule.cwe, `sink rule ${rule.id} is missing a cwe`);
}

// SQL injection (CWE-89) coverage should span JS, Python, and Go, not just Java.
for (const lang of ["js", "py", "go", "java"]) {
  const sqlSinks = RULES.filter(
    (r) => r.lang === lang && r.kind === "sink" && r.cwe === "CWE-89",
  );
  assert.ok(sqlSinks.length > 0, `expected a CWE-89 sink rule for ${lang}`);
}

assert.ok(
  matches(
    "js.sql.query",
    "await pool.query(`SELECT * FROM users WHERE id = ${id}`)",
  ),
);
assert.ok(matches("js.sql.raw", "knex.raw(`SELECT * FROM t WHERE x = ${x}`)"));
assert.ok(
  matches(
    "py.sql.cursor_execute",
    'cursor.execute(f"SELECT * FROM t WHERE x = {x}")',
  ),
);
assert.ok(matches("py.django.raw", "User.objects.raw(query)"));
assert.ok(
  matches("go.sql.query", 'db.Query("SELECT * FROM t WHERE x = " + x)'),
);

// Sanity: unrelated code should not trip the new SQL sinks.
assert.ok(!matches("js.sql.query", "const total = items.query.length;"));

console.log(
  `ok - ${ids.length} rules, ${idsForLang("js", "sink").length} JS sinks, all CWE-89 langs covered`,
);
