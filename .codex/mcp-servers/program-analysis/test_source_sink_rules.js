"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function firstMatch(ruleId, content) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert.ok(rule, `rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.exec(content);
}

test("js.express_fileupload.mv fires on req.files.<field>.mv(...)", () => {
  const m = firstMatch(
    "js.express_fileupload.mv",
    "req.files.avatar.mv('./uploads/' + req.files.avatar.name);",
  );
  assert.ok(m, "expected a match");
});

test("py.werkzeug.file_save fires on file.save(...)", () => {
  const m = firstMatch(
    "py.werkzeug.file_save",
    "file.save(os.path.join(UPLOAD_DIR, file.filename))",
  );
  assert.ok(m, "expected a match");
});

test("go.multipart.formfile fires on r.FormFile(...)", () => {
  const m = firstMatch(
    "go.multipart.formfile",
    'f, header, _ := r.FormFile("avatar")',
  );
  assert.ok(m, "expected a match");
});

test("java.servlet.part_filename fires on Part.getSubmittedFileName()", () => {
  const m = firstMatch(
    "java.servlet.part_filename",
    "String fileName = filePart.getSubmittedFileName();",
  );
  assert.ok(m, "expected a match");
});

test("CWE-434 sink rules carry a cwe id; the new source rules do not", () => {
  const sinkIds = ["js.express_fileupload.mv", "py.werkzeug.file_save"];
  const sourceIds = ["go.multipart.formfile", "java.servlet.part_filename"];
  for (const id of sinkIds) {
    const rule = RULES.find((r) => r.id === id);
    assert.equal(rule.kind, "sink");
    assert.equal(rule.cwe, "CWE-434");
  }
  for (const id of sourceIds) {
    const rule = RULES.find((r) => r.id === id);
    assert.equal(rule.kind, "source");
    assert.equal(rule.cwe, undefined);
  }
});

test("rule table has unique ids and every rule has a valid shape", () => {
  const seen = new Set();
  for (const rule of RULES) {
    assert.ok(!seen.has(rule.id), `duplicate rule id: ${rule.id}`);
    seen.add(rule.id);
    assert.ok(["js", "py", "go", "java"].includes(rule.lang), rule.id);
    assert.ok(["source", "sink"].includes(rule.kind), rule.id);
    assert.ok(rule.pattern instanceof RegExp, rule.id);
    assert.ok(rule.pattern.global, `${rule.id} pattern must have the g flag`);
    if (rule.kind === "sink") {
      assert.match(rule.cwe, /^CWE-\d+$/, `${rule.id} sink needs a cwe id`);
    }
  }
});
