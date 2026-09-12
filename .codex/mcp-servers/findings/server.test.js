"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

// server.js starts an MCP stdio server as a side effect of being required and
// resolves its data dir relative to __dirname, so it can't be require()'d
// directly in a unit test. This writes a patched copy next to the real file
// (so its `require("../lib/mcp_stdio.js")` still resolves), pointed at a
// throwaway data dir instead of the real (gitignored) .codex/findings/ event
// log, with the createServer() call stripped so loading it doesn't start a
// stdio server and hang the test process.
const SERVER_PATH = path.join(__dirname, "server.js");

function loadServerWithTempDataDir() {
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "mantis-findings-"));
  const src = fs.readFileSync(SERVER_PATH, "utf8");
  const patched = src
    .replace(
      'const DATA_DIR = path.join(__dirname, "..", "..", "findings");',
      `const DATA_DIR = ${JSON.stringify(tmpDataDir)};`,
    )
    .replace(/createServer\(\{[\s\S]*\}\);\s*$/, "");
  const modPath = path.join(
    __dirname,
    `.server_under_test.${crypto.randomBytes(6).toString("hex")}.js`,
  );
  fs.writeFileSync(
    modPath,
    patched +
      "\nmodule.exports = { findingCreate, findingUpdate, findingGet, findingList };\n",
  );
  try {
    return require(modPath);
  } finally {
    fs.unlinkSync(modPath);
  }
}

function makeCandidate(findingCreate) {
  return findingCreate({
    vuln_class: "sql-injection",
    claim: "unsanitized query built from request.args",
  });
}

test("re-grading one axis does not zero out previously-set axes", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  findingUpdate({
    id: created.id,
    grade: {
      impact: 30,
      proof: 25,
      severity_accuracy: 15,
      chain: 0,
      report_quality: 0,
    },
  });
  // Before the fix: this second call replaced the whole grade object, so
  // impact/proof/severity_accuracy silently reset to 0 and the total
  // dropped from 70 (SUBMIT) to 15 (SKIP) even though nothing got worse.
  const second = findingUpdate({
    id: created.id,
    grade: { report_quality: 15 },
  });

  assert.equal(second.finding.grade.impact, 30);
  assert.equal(second.finding.grade.proof, 25);
  assert.equal(second.finding.grade.severity_accuracy, 15);
  assert.equal(second.finding.grade.report_quality, 15);
  assert.equal(second.finding.grade.total, 85);
  assert.equal(second.disposition, "SUBMIT");
});

test("axes explicitly re-sent overwrite the prior value for that axis", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  findingUpdate({ id: created.id, grade: { impact: 10 } });
  const second = findingUpdate({ id: created.id, grade: { impact: 20 } });

  assert.equal(second.finding.grade.impact, 20);
  assert.equal(second.finding.grade.total, 20);
});

test("a first, single-axis grade still computes total + disposition", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  const updated = findingUpdate({ id: created.id, grade: { chain: 15 } });

  assert.equal(updated.finding.grade.chain, 15);
  assert.equal(updated.finding.grade.total, 15);
  assert.equal(updated.disposition, "SKIP");
});
