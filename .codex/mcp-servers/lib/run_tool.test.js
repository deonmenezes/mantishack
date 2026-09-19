"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { runCommand } = require("./run_tool.js");

test("runCommand returns full output when under the buffer cap", async () => {
  const result = await runCommand(
    "node",
    ["-e", "process.stdout.write('a'.repeat(1000))"],
    { maxBufferBytes: 1_000_000 },
  );
  assert.equal(result.stdout.length, 1000);
  assert.equal(result.truncated, false);
  assert.equal(result.code, 0);
});

test("runCommand caps stdout instead of retaining it unbounded", async () => {
  // Ask the child to print far more than the cap; the parent must not hold
  // more than ~maxBufferBytes in the `stdout` string, and must say so.
  const result = await runCommand(
    "node",
    ["-e", "process.stdout.write('x'.repeat(5_000_000))"],
    { maxBufferBytes: 1000 },
  );
  assert.ok(
    result.stdout.length <= 1000 + 65536,
    `stdout should stay near the cap, got ${result.stdout.length} bytes`,
  );
  assert.equal(result.truncated, true);
  assert.equal(result.code, 0);
});

test("runCommand caps stderr independently of stdout", async () => {
  const result = await runCommand(
    "node",
    [
      "-e",
      "process.stdout.write('ok'); process.stderr.write('e'.repeat(5_000_000))",
    ],
    { maxBufferBytes: 1000 },
  );
  assert.equal(result.stdout, "ok");
  assert.ok(result.stderr.length <= 1000 + 65536);
  assert.equal(result.truncated, true);
});

test("runCommand still drains and exits normally when the cap is hit", async () => {
  // A child that writes well past the cap and then exits must still be
  // observed to close (not hang because the parent stopped reading its pipe).
  const start = Date.now();
  const result = await runCommand(
    "node",
    ["-e", "process.stdout.write('y'.repeat(20_000_000))"],
    { maxBufferBytes: 1024, timeoutMs: 15_000 },
  );
  assert.equal(result.timedOut, false);
  assert.equal(result.truncated, true);
  assert.ok(
    Date.now() - start < 15_000,
    "should close well before the timeout",
  );
});

test("runCommand leaves output untouched when no cap is exceeded (default)", async () => {
  const result = await runCommand("node", ["-e", "console.log('hello')"]);
  assert.equal(result.stdout, "hello\n");
  assert.equal(result.truncated, false);
});
