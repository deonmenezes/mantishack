"use strict";

const { spawn } = require("node:child_process");

// Default cap on accumulated stdout/stderr per stream. Scanner output is
// normally a few KB-MB of JSON; without a cap, a tool that misbehaves (a
// runaway verbose/debug mode, an infinite log loop, a giant repo dump) grows
// two unbounded strings in the MCP server's memory until the process OOMs,
// taking down every in-flight scan with it. Once a stream crosses the cap we
// stop retaining further chunks (they're still drained off the pipe so the
// child doesn't block on backpressure) and mark the result `truncated`, the
// same "report, don't crash" posture as a missing binary or a timeout.
const DEFAULT_MAX_BUFFER_BYTES = 20 * 1024 * 1024;

/**
 * Runs an external CLI tool and captures stdout/stderr/exit code.
 * Never throws on a missing binary or non-zero exit -- callers decide how to
 * interpret that, since e.g. semgrep/nuclei use non-zero exit codes to mean
 * "findings reported", not "tool failed".
 */
function runCommand(
  command,
  args,
  {
    cwd,
    input,
    timeoutMs = 120_000,
    maxBufferBytes = DEFAULT_MAX_BUFFER_BYTES,
  } = {},
) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd });
    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let truncated = false;
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.on("error", (err) => {
      clearTimeout(timer);
      if (err.code === "ENOENT") {
        resolve({
          notFound: true,
          command,
          stdout: "",
          stderr: "",
          code: null,
        });
      } else {
        resolve({
          notFound: false,
          command,
          stdout: "",
          stderr: String(err),
          code: null,
        });
      }
    });

    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxBufferBytes) {
        truncated = true;
        return;
      }
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > maxBufferBytes) {
        truncated = true;
        return;
      }
      stderr += chunk;
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        notFound: false,
        command,
        stdout,
        stderr,
        code,
        timedOut,
        truncated,
      });
    });

    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();
  });
}

function notFoundMessage(toolName, installHint) {
  return `${toolName} is not installed or not on PATH in this environment. Install it (${installHint}) to enable this tool; until then this server reports rather than fabricates results.`;
}

module.exports = { runCommand, notFoundMessage };
