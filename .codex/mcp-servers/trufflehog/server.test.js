"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseTrufflehogOutput, redact } = require("./server.js");

test("extracts file and line from trufflehog filesystem JSON output", () => {
  const stdout = [
    JSON.stringify({
      DetectorName: "AWS",
      Verified: true,
      Raw: "AKIAABCDEFGHIJKLMNOP",
      SourceMetadata: { Data: { Filesystem: { file: "creds.txt", line: 3 } } },
    }),
    JSON.stringify({
      DetectorName: "Generic",
      Verified: false,
      Raw: "shortsecret",
      SourceMetadata: {
        Data: { Filesystem: { file: "config/app.yml", line: 42 } },
      },
    }),
  ].join("\n");

  const findings = parseTrufflehogOutput(stdout);
  assert.equal(findings.length, 2);
  assert.deepEqual(findings[0], {
    detector: "AWS",
    verified: true,
    file: "creds.txt",
    line: 3,
    redacted_secret: redact("AKIAABCDEFGHIJKLMNOP"),
  });
  assert.equal(findings[1].file, "config/app.yml");
  assert.equal(findings[1].line, 42);
});

test("ignores blank lines and malformed JSON lines", () => {
  const stdout = ["", "not json", "  ", ""].join("\n");
  assert.deepEqual(parseTrufflehogOutput(stdout), []);
});

test("tolerates missing SourceMetadata without throwing", () => {
  const stdout = JSON.stringify({
    DetectorName: "Generic",
    Verified: false,
    Raw: "abc",
  });
  const findings = parseTrufflehogOutput(stdout);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, undefined);
  assert.equal(findings[0].line, undefined);
});

test("redact never returns the raw secret", () => {
  assert.equal(
    redact("AKIAABCDEFGHIJKLMNOP"),
    "AKIA...[REDACTED 20 chars]...MNOP",
  );
  const short = redact("abc");
  assert.equal(short, "[REDACTED_SECRET]");
  assert.equal(redact(""), "[REDACTED_SECRET]");
});
