"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `expected a rule with id ${id}`);
  return rule;
}

function matches(rule, snippet) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(snippet);
}

// "Zip Slip" (CWE-22 via unchecked archive-entry names) coverage added this
// run -- one positive and one negative/unrelated-code case per new sink so
// each pattern doesn't regress into a dead rule or a blanket match.

test("js.archive.extract_all_to matches adm-zip's extractAllTo", () => {
  const rule = ruleById("js.archive.extract_all_to");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "new AdmZip(zipPath).extractAllTo(destDir, true)"));
  assert.ok(!matches(rule, "archive.extractAll(destDir)"));
});

test("js.archive.tar_extract matches the tar package's extract call", () => {
  const rule = ruleById("js.archive.tar_extract");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "tar.extract({ file: archivePath, cwd: destDir })"));
  assert.ok(!matches(rule, "myTarThing.extract(path)"));
});

test("py.archive.extractall_unsafe matches bare zipfile/tarfile extractall", () => {
  const rule = ruleById("py.archive.extractall_unsafe");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "zipfile.ZipFile(upload_path).extractall(dest)"));
  assert.ok(matches(rule, "tarfile.open(upload_path).extractall(dest)"));
});

test("py.archive.extractall_unsafe does not flag a filter=-guarded extractall", () => {
  const rule = ruleById("py.archive.extractall_unsafe");
  assert.ok(
    !matches(rule, "tf.extractall(dest, filter='data')"),
    "tarfile's 3.12+ filter= argument makes extraction member-safe",
  );
});

test("go.archive.zip_openreader matches archive/zip's OpenReader", () => {
  const rule = ruleById("go.archive.zip_openreader");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "r, err := zip.OpenReader(uploadPath)"));
  assert.ok(!matches(rule, "http.Get(url)"));
});

test("java.archive.zip_entry_extraction matches the ZipInputStream read loop", () => {
  const rule = ruleById("java.archive.zip_entry_extraction");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "while ((entry = zis.getNextEntry()) != null) {"));
  assert.ok(!matches(rule, "new FileInputStream(uploadDir + filename)"));
});

// Spot-check a couple of pre-existing rules still work after the edit --
// regression guard against a stray typo breaking the shared RULES array.

test("existing js.eval and java.statement.execute rules are unaffected", () => {
  assert.ok(matches(ruleById("js.eval"), "eval(userInput)"));
  assert.ok(
    matches(ruleById("java.statement.execute"), "statement.executeQuery(sql)"),
  );
});
