"use strict";

const { spawn } = require("node:child_process");

/**
 * Runs an external CLI tool and captures stdout/stderr/exit code.
 * Never throws on a missing binary or non-zero exit -- callers decide how to
 * interpret that, since e.g. semgrep/nuclei use non-zero exit codes to mean
 * "findings reported", not "tool failed".
 */
function runCommand(command, args, { cwd, input, timeoutMs = 120_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd });
    let stdout = "";
    let stderr = "";
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
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ notFound: false, command, stdout, stderr, code, timedOut });
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

// A killed-on-timeout run and a clean "nothing to report" run both surface as
// empty/short stdout to a naive caller -- but one is an incomplete scan and
// the other is a real negative. Callers MUST distinguish them (never let a
// timeout read as "no findings"); this gives every scanner wrapper the same
// wording instead of each re-deriving it ad hoc.
function timeoutNote(result, toolName, timeoutMs) {
  if (!result || !result.timedOut) return null;
  return (
    `${toolName} did not finish within ${timeoutMs}ms and was killed -- ` +
    "this is an incomplete/truncated scan, not a clean or empty result. " +
    "Re-run with a narrower path/scope or a larger timeoutMs before trusting an empty finding list."
  );
}

module.exports = { runCommand, notFoundMessage, timeoutNote };
