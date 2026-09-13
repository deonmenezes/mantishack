"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

// server.js starts an MCP stdio server as a side effect of being required.
// Load a patched copy next to the real file (so its relative requires still
// resolve) with the createServer() call stripped, so importing it for a unit
// test doesn't hang the test process listening on stdin.
const SERVER_PATH = path.join(__dirname, "server.js");

function loadServerInternals() {
  const src = fs.readFileSync(SERVER_PATH, "utf8");
  const patched = src.replace(/createServer\(\{[\s\S]*\}\);\s*$/, "");
  const modPath = path.join(
    __dirname,
    `.server_under_test.${crypto.randomBytes(6).toString("hex")}.js`,
  );
  fs.writeFileSync(
    modPath,
    patched + "\nmodule.exports = { deriveSeverity, findCvssV3Vector };\n",
  );
  try {
    return require(modPath);
  } finally {
    fs.unlinkSync(modPath);
  }
}

test("database_specific.severity (GHSA vocabulary) is preserved as-is, no CVSS computed", () => {
  const { deriveSeverity } = loadServerInternals();
  const derived = deriveSeverity({
    database_specific: { severity: "MODERATE" },
    severity: [
      {
        type: "CVSS_V3",
        score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      },
    ],
  });
  assert.deepEqual(derived, {
    severity: "MODERATE",
    cvss_vector: null,
    cvss_score: null,
  });
});

test("falls back to the CVSS v3 base score when database_specific.severity is absent (e.g. a PyPI/PYSEC advisory)", () => {
  const { deriveSeverity } = loadServerInternals();
  const derived = deriveSeverity({
    severity: [
      {
        type: "CVSS_V3",
        score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      },
    ],
  });
  assert.equal(derived.severity, "critical");
  assert.equal(derived.cvss_score, 10.0);
  assert.equal(
    derived.cvss_vector,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  );
});

test("a record with neither database_specific.severity nor a CVSS_V3 entry stays 'unknown' rather than guessing", () => {
  const { deriveSeverity } = loadServerInternals();
  assert.deepEqual(deriveSeverity({}), {
    severity: "unknown",
    cvss_vector: null,
    cvss_score: null,
  });
  assert.deepEqual(
    deriveSeverity({ severity: [{ type: "CVSS_V4", score: "..." }] }),
    { severity: "unknown", cvss_vector: null, cvss_score: null },
  );
});

test("a malformed CVSS vector stays 'unknown' instead of a fabricated score", () => {
  const { deriveSeverity } = loadServerInternals();
  const derived = deriveSeverity({
    severity: [{ type: "CVSS_V3", score: "not-a-real-vector" }],
  });
  assert.deepEqual(derived, {
    severity: "unknown",
    cvss_vector: null,
    cvss_score: null,
  });
});

test("findCvssV3Vector picks the CVSS_V3 entry and ignores others", () => {
  const { findCvssV3Vector } = loadServerInternals();
  const vector = findCvssV3Vector({
    severity: [
      { type: "CVSS_V4", score: "CVSS:4.0/..." },
      {
        type: "CVSS_V3",
        score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      },
    ],
  });
  assert.equal(vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
});
