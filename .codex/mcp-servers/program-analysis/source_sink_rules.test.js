"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function idsMatching(lang, content) {
  const hits = [];
  for (const rule of RULES.filter((r) => r.lang === lang)) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(content)) hits.push(rule.id);
  }
  return hits;
}

function matches(id, text) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `no rule registered with id ${id}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(text);
}

// --- Path traversal (CWE-22) true positives ---

test("js: fs read/write calls with a non-literal path are flagged", () => {
  assert.ok(
    idsMatching(
      "js",
      "fs.readFile(path.join(base, req.params.file), cb)",
    ).includes("js.fs.read_dynamic_path"),
  );
  assert.ok(
    idsMatching("js", "fs.createReadStream(userPath)").includes(
      "js.fs.read_dynamic_path",
    ),
  );
  assert.ok(
    idsMatching("js", "fs.writeFileSync(userPath, data)").includes(
      "js.fs.write_dynamic_path",
    ),
  );
});

test("py: Flask send_file/send_from_directory with a non-literal path are flagged", () => {
  assert.ok(
    idsMatching("py", "send_file(request.args.get('path'))").includes(
      "py.flask.send_file_dynamic",
    ),
  );
  assert.ok(
    idsMatching(
      "py",
      "send_from_directory(UPLOAD_DIR, request.args.get('filename'))",
    ).includes("py.flask.send_from_directory_dynamic"),
  );
});

test("go: os file calls and http.ServeFile with a non-literal path are flagged", () => {
  assert.ok(
    idsMatching(
      "go",
      'os.Open(filepath.Join(base, r.FormValue("f")))',
    ).includes("go.os.open_dynamic_path"),
  );
  assert.ok(
    idsMatching("go", 'http.ServeFile(w, r, r.URL.Query().Get("f"))').includes(
      "go.http.servefile_dynamic",
    ),
  );
});

test("java: File/FileInputStream/Paths.get with a non-literal path are flagged", () => {
  assert.ok(
    idsMatching("java", 'new File(request.getParameter("path"))').includes(
      "java.fs.file_dynamic_path",
    ),
  );
  assert.ok(
    idsMatching(
      "java",
      'new FileInputStream(request.getParameter("path"))',
    ).includes("java.fs.file_dynamic_path"),
  );
  assert.ok(
    idsMatching("java", 'Paths.get(request.getParameter("path"))').includes(
      "java.nio.paths_get_dynamic",
    ),
  );
});

// --- Path traversal (CWE-22) true negatives (literal paths, not flagged) ---

test("js: fs calls with a literal path are not flagged", () => {
  assert.equal(
    matches("js.fs.read_dynamic_path", 'fs.readFile("config.json", cb)'),
    false,
  );
  assert.equal(
    matches(
      "js.fs.write_dynamic_path",
      "fs.writeFileSync(`/tmp/fixed.log`, data)",
    ),
    false,
  );
});

test("py: Flask send_file/send_from_directory with a literal path are not flagged", () => {
  assert.equal(
    matches("py.flask.send_file_dynamic", 'send_file("static/logo.png")'),
    false,
  );
  assert.equal(
    matches(
      "py.flask.send_from_directory_dynamic",
      'send_from_directory(UPLOAD_DIR, "report.pdf")',
    ),
    false,
  );
});

test("go: os file calls and http.ServeFile with a literal path are not flagged", () => {
  assert.equal(
    matches("go.os.open_dynamic_path", 'os.Open("config.yaml")'),
    false,
  );
  assert.equal(
    matches("go.http.servefile_dynamic", 'http.ServeFile(w, r, "index.html")'),
    false,
  );
});

test("java: File/Paths.get with a literal path are not flagged", () => {
  assert.equal(
    matches("java.fs.file_dynamic_path", 'new File("config.properties")'),
    false,
  );
  assert.equal(
    matches("java.nio.paths_get_dynamic", 'Paths.get("config.properties")'),
    false,
  );
});

// A literal argument preceded by whitespace (before or after a comma) must
// still be recognized as literal -- `\s*(?!quote)` is a footgun here because
// the engine backtracks `\s*` to zero-width to dodge the lookahead. Every new
// path-traversal pattern above uses `(?!\s*quote)` instead specifically to
// avoid this.
test("a literal path with surrounding whitespace is still not flagged", () => {
  assert.equal(
    matches("js.fs.read_dynamic_path", 'fs.readFile( "config.json", cb)'),
    false,
  );
  assert.equal(
    matches(
      "py.flask.send_from_directory_dynamic",
      'send_from_directory(UPLOAD_DIR,  "report.pdf")',
    ),
    false,
  );
  assert.equal(
    matches("go.http.servefile_dynamic", 'http.ServeFile(w, r,  "index.html")'),
    false,
  );
  assert.equal(
    matches("java.nio.paths_get_dynamic", 'Paths.get(  "config.properties")'),
    false,
  );
});

// --- whole-ruleset sanity checks ---

test("every rule id is unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every sink rule carries a cwe", () => {
  for (const rule of RULES.filter((r) => r.kind === "sink")) {
    assert.ok(rule.cwe, `sink rule ${rule.id} is missing a cwe`);
  }
});
