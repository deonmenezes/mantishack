#!/usr/bin/env node
"use strict";

/**
 * Smoke test for the findings spine's secret-shaped-string refusal guard
 * (`scanForSecrets` in server.js). Spawns the real server over its MCP
 * stdio transport -- same zero-dependency style as the servers themselves,
 * no test framework required. Run with: node test_secret_guard.js
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

// server.js resolves its append-only event log relative to its own path
// (`.codex/findings/events.jsonl`, shared across real runs for cross-run
// dedup). Run the server from a throwaway copy so this smoke test can't
// write test fixtures into that real, gitignored production log.
function makeIsolatedServerCopy() {
  const tmpRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "mantis-findings-test-"),
  );
  const findingsDir = path.join(tmpRoot, "mcp-servers", "findings");
  const libDir = path.join(tmpRoot, "mcp-servers", "lib");
  fs.mkdirSync(findingsDir, { recursive: true });
  fs.mkdirSync(libDir, { recursive: true });
  fs.copyFileSync(
    path.join(__dirname, "server.js"),
    path.join(findingsDir, "server.js"),
  );
  fs.copyFileSync(
    path.join(__dirname, "..", "lib", "mcp_stdio.js"),
    path.join(libDir, "mcp_stdio.js"),
  );
  return { tmpRoot, serverPath: path.join(findingsDir, "server.js") };
}

function withServer(fn) {
  const { tmpRoot, serverPath } = makeIsolatedServerCopy();
  const child = spawn(process.execPath, [serverPath], {
    stdio: ["pipe", "pipe", "inherit"],
  });

  let buffer = "";
  const pending = new Map();
  let nextId = 1;

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let idx = buffer.indexOf("\n");
    while (idx !== -1) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (line) {
        const msg = JSON.parse(line);
        const resolver = pending.get(msg.id);
        if (resolver) {
          pending.delete(msg.id);
          resolver(msg);
        }
      }
      idx = buffer.indexOf("\n");
    }
  });

  function call(name, args) {
    const id = nextId++;
    return new Promise((resolve) => {
      pending.set(id, resolve);
      child.stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id,
          method: "tools/call",
          params: { name, arguments: args },
        })}\n`,
      );
    });
  }

  return fn(call).finally(() => {
    child.stdin.end();
    child.kill();
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });
}

function assert(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exitCode = 1;
  } else {
    console.log(`ok: ${msg}`);
  }
}

async function main() {
  await withServer(async (call) => {
    // Case 1: a clean finding (no secret-shaped strings) must be accepted.
    const clean = await call("finding_create", {
      vuln_class: "idor",
      claim: "The /api/orders/:id handler does not check ownership.",
      attack_vector: "Increment the numeric id as another authenticated user.",
    });
    assert(
      clean.result && clean.result.isError === false,
      "clean finding_create is accepted",
    );

    // Case 2: a generically-named secret param (not covered before this fix)
    // must now be refused.
    const genericSecret = await call("finding_create", {
      vuln_class: "secret-exposure",
      claim: "Found a leaked credential in a debug log line",
      attack_vector: "GET /debug?password=hunter2LeakedValue observed in logs",
    });
    assert(
      genericSecret.result && genericSecret.result.isError === true,
      "generic password= param is refused",
    );

    // Case 3: userinfo-in-URL credentials must be refused.
    const userinfo = await call("finding_create", {
      vuln_class: "secret-exposure",
      claim: "Connection string embeds credentials",
      attack_vector: "postgres://svc_user:sup3rSecretPass@db.internal:5432/app",
    });
    assert(
      userinfo.result && userinfo.result.isError === true,
      "user:pass@ URL credentials are refused",
    );

    // Case 4: a legitimate auth-related claim (no secret VALUE, just the word
    // "auth") must still be accepted -- this guard is a secret detector, not
    // an auth-keyword blocklist, and auth findings are exactly what this tool
    // exists to report.
    const authFinding = await call("finding_create", {
      vuln_class: "broken-access-control",
      claim: "Admin endpoint reachable without auth=required check",
      attack_vector: "auth middleware is skipped for /admin/*",
    });
    assert(
      authFinding.result && authFinding.result.isError === false,
      "legitimate auth-related claim (no secret value) is still accepted",
    );

    // Case 5: previously-covered shapes (JWT) must still be refused
    // (regression check that adding non-global patterns didn't break the
    // existing global-flagged-at-source shapes).
    const jwt = await call("finding_create", {
      vuln_class: "secret-exposure",
      claim: "Session token leaked",
      attack_vector:
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzbm90YXJlYWxzaWc",
    });
    assert(
      jwt.result && jwt.result.isError === true,
      "JWT-shaped string is still refused",
    );
  });
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
