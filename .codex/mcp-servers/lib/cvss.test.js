"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { cvssV3BaseScore, cvssV3Severity } = require("./cvss.js");

test("scope-changed, all-high vector scores 10.0 (critical) -- CVE-2021-44228 Log4Shell vector", () => {
  const score = cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  assert.equal(score, 10.0);
  assert.equal(cvssV3Severity(score), "critical");
});

test("scope-unchanged, low-impact/required-interaction vector scores 5.4 (medium)", () => {
  // Hand-verified against the CVSS v3.1 base equations: ISS = 1-(1-.22)^2 =
  // 0.3916, Impact = 6.42*ISS = 2.5137, Exploitability =
  // 8.22*.85*.77*.85*.62 = 2.8353, Base = Roundup(2.5137+2.8353) = 5.4.
  const score = cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  assert.equal(score, 5.4);
  assert.equal(cvssV3Severity(score), "medium");
});

test("low-severity local vector scores under 4.0 (low)", () => {
  const score = cvssV3BaseScore("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N");
  assert.ok(score > 0 && score < 4.0, `expected a low score, got ${score}`);
  assert.equal(cvssV3Severity(score), "low");
});

test("no-impact vector scores exactly 0.0 (info)", () => {
  const score = cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
  assert.equal(score, 0);
  assert.equal(cvssV3Severity(score), "info");
});

test("CVSS 3.0 vectors are accepted, not just 3.1", () => {
  const score = cvssV3BaseScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  assert.equal(score, 10.0);
});

test("trailing temporal/environmental metrics are ignored, not treated as malformed", () => {
  const withExtras = cvssV3BaseScore(
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:O/RC:C",
  );
  assert.equal(withExtras, 10.0);
});

test("unparsable, unsupported-version, or non-string input returns null, never a guess", () => {
  assert.equal(cvssV3BaseScore("not a vector"), null);
  assert.equal(
    cvssV3BaseScore("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    null,
  );
  assert.equal(
    cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),
    null,
  ); // missing A
  assert.equal(cvssV3BaseScore(undefined), null);
  assert.equal(cvssV3BaseScore(null), null);
});

test("cvssV3Severity refuses to bucket a non-numeric score", () => {
  assert.equal(cvssV3Severity(null), null);
  assert.equal(cvssV3Severity(undefined), null);
  assert.equal(cvssV3Severity(NaN), null);
});

test("qualitative bucket boundaries match the CVSS v3 spec table", () => {
  assert.equal(cvssV3Severity(3.9), "low");
  assert.equal(cvssV3Severity(4.0), "medium");
  assert.equal(cvssV3Severity(6.9), "medium");
  assert.equal(cvssV3Severity(7.0), "high");
  assert.equal(cvssV3Severity(8.9), "high");
  assert.equal(cvssV3Severity(9.0), "critical");
});
