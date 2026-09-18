"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(id, text) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `no rule registered with id ${id}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(text);
}

test("every rule id is unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every sink rule carries a cwe", () => {
  for (const rule of RULES) {
    if (rule.kind === "sink") {
      assert.ok(rule.cwe, `sink rule ${rule.id} is missing a cwe`);
    }
  }
});

test("js SQLi sinks flag interpolated/concatenated/raw queries", () => {
  assert.ok(
    matches(
      "js.sql.template_interpolation",
      "db.query(`SELECT * FROM users WHERE id = ${id}`)",
    ),
  );
  assert.ok(
    matches(
      "js.sql.string_concat",
      'db.query("SELECT * FROM users WHERE id = " + id)',
    ),
  );
  assert.ok(matches("js.sql.orm_raw_query", "await sequelize.query(rawSql)"));
  assert.ok(
    matches("js.sql.orm_raw_query", "knex.raw(`SELECT * FROM x WHERE y=${z}`)"),
  );
});

test("js SQLi sinks do not flag parameterized queries", () => {
  assert.equal(
    matches(
      "js.sql.template_interpolation",
      "db.query(`SELECT * FROM users WHERE id = ?`, [id])",
    ),
    false,
  );
  assert.equal(
    matches(
      "js.sql.string_concat",
      'db.query("SELECT * FROM users WHERE id = ?", [id])',
    ),
    false,
  );
});

test("python SQLi sinks flag f-string and concat/format interpolation", () => {
  assert.ok(
    matches(
      "py.sql.fstring_interpolation",
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ),
  );
  assert.ok(
    matches(
      "py.sql.string_concat_or_format",
      'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    ),
  );
  assert.ok(
    matches(
      "py.sql.string_concat_or_format",
      'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))',
    ),
  );
});

test("python SQLi sinks do not flag parameterized queries", () => {
  assert.equal(
    matches(
      "py.sql.fstring_interpolation",
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
    false,
  );
});

test("go SQLi sink flags fmt.Sprintf built queries", () => {
  assert.ok(
    matches(
      "go.sql.sprintf_query",
      'rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))',
    ),
  );
});

test("go SQLi sink does not flag parameterized queries", () => {
  assert.equal(
    matches(
      "go.sql.sprintf_query",
      'rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)',
    ),
    false,
  );
});
