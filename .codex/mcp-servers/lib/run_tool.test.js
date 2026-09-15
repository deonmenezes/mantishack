"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { runCommand, timeoutNote } = require("./run_tool.js");

test("runCommand resolves normally for a fast command", async () => {
  const result = await runCommand(
    "node",
    ["-e", "process.stdout.write('ok')"],
    {
      timeoutMs: 5_000,
    },
  );
  assert.equal(result.notFound, false);
  assert.equal(result.timedOut, false);
  assert.equal(result.code, 0);
  assert.equal(result.stdout, "ok");
});

test("runCommand kills a slow command and reports timedOut", async () => {
  const result = await runCommand(
    "node",
    ["-e", "setTimeout(() => {}, 5000)"],
    { timeoutMs: 200 },
  );
  assert.equal(result.notFound, false);
  assert.equal(result.timedOut, true);
  // SIGKILL leaves no normal exit code.
  assert.notEqual(result.code, 0);
});

test("runCommand reports notFound for a missing binary, not a timeout", async () => {
  const result = await runCommand("definitely-not-a-real-mantis-binary", [], {
    timeoutMs: 5_000,
  });
  assert.equal(result.notFound, true);
  assert.equal(result.timedOut, undefined);
});

test("timeoutNote is null when the run did not time out", () => {
  assert.equal(timeoutNote({ timedOut: false }, "semgrep", 300_000), null);
  assert.equal(timeoutNote(null, "semgrep", 300_000), null);
});

test("timeoutNote flags an incomplete scan, not a clean result, when timed out", () => {
  const note = timeoutNote({ timedOut: true }, "semgrep", 300_000);
  assert.match(note, /semgrep/);
  assert.match(note, /300000ms/);
  assert.match(note, /not a clean or empty result/);
});
