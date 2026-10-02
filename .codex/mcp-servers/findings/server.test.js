"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function freshServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mantis-findings-test-"));
  process.env.MANTIS_FINDINGS_DIR = dir;
  delete require.cache[require.resolve("./server.js")];
  return require("./server.js");
}

test("finding_create mints a new id for the first sighting", () => {
  const { findingCreate } = freshServer();
  const result = findingCreate({
    vuln_class: "sql-injection",
    claim: "unsanitized query param reaches the sink",
    location: { file: "src/db.js", lines: "10-12" },
    run: "run-1",
  });
  assert.equal(result.status, "candidate");
  assert.equal(result.deduplicated, undefined);
});

test("finding_create dedupes a repeat sighting at the same vuln_class+location", () => {
  const { findingCreate, findingList } = freshServer();
  const first = findingCreate({
    vuln_class: "sql-injection",
    claim: "unsanitized query param reaches the sink",
    location: { file: "src/db.js", lines: "10-12" },
    run: "run-1",
  });

  const second = findingCreate({
    vuln_class: "sql-injection",
    claim: "same weakness, re-detected on the next scan",
    location: { file: "src/db.js", lines: "10-12" },
    run: "run-2",
  });

  assert.equal(second.deduplicated, true);
  assert.equal(second.id, first.id);
  assert.equal(second.finding.last_seen_run, "run-2");
  assert.equal(second.finding.first_seen_run, "run-1");

  const list = findingList({});
  assert.equal(list.count, 1);
});

test("finding_create does not dedupe a different vuln_class at the same location", () => {
  const { findingCreate, findingList } = freshServer();
  findingCreate({
    vuln_class: "sql-injection",
    claim: "weakness A",
    location: { file: "src/db.js", lines: "10-12" },
    run: "run-1",
  });
  findingCreate({
    vuln_class: "idor",
    claim: "weakness B, different class, same lines",
    location: { file: "src/db.js", lines: "10-12" },
    run: "run-1",
  });

  assert.equal(findingList({}).count, 2);
});

test("finding_create does not dedupe against a rejected finding", () => {
  const { findingCreate, findingUpdate, findingList } = freshServer();
  const first = findingCreate({
    vuln_class: "sql-injection",
    claim: "weakness that turned out to be a false positive",
    location: { file: "src/db.js", lines: "10-12" },
    run: "run-1",
  });
  findingUpdate({
    id: first.id,
    status: "rejected",
    rejected_reason: "parameterized at the sink",
  });

  const second = findingCreate({
    vuln_class: "sql-injection",
    claim: "re-flagged after the sink changed",
    location: { file: "src/db.js", lines: "10-12" },
    run: "run-2",
  });

  assert.equal(second.deduplicated, undefined);
  assert.notEqual(second.id, first.id);
  assert.equal(findingList({}).count, 2);
});

test("finding_create without a location never dedupes", () => {
  const { findingCreate, findingList } = freshServer();
  findingCreate({ vuln_class: "ssrf", claim: "weakness A, no location" });
  findingCreate({ vuln_class: "ssrf", claim: "weakness B, no location" });
  assert.equal(findingList({}).count, 2);
});
