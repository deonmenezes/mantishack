#!/usr/bin/env node
"use strict";

/**
 * Integration test for the mantis_http_audit MCP server: spawns it exactly
 * as the harness would (stdio JSON-RPC), calls http_audit, and asserts the
 * evidence pack redacts every secret shape it claims to cover.
 *
 * Run with: node .codex/mcp-servers/http-audit/server.test.js
 */

const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const { spawn } = require("node:child_process");

const SERVER_PATH = path.join(__dirname, "server.js");

function callHttpAudit(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SERVER_PATH]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", () => {
      const lines = stdout.split("\n").filter(Boolean);
      const responses = lines.map((line) => JSON.parse(line));
      const callResponse = responses.find((r) => r.id === 1);
      if (!callResponse) {
        reject(new Error(`No response to tools/call. stderr: ${stderr}`));
        return;
      }
      resolve(JSON.parse(callResponse.result.content[0].text));
    });

    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "http_audit", arguments: args },
    };
    child.stdin.write(`${JSON.stringify(request)}\n`);
    child.stdin.end();
  });
}

test("redacts newly-added secret shapes from bodies/URLs", async () => {
  const pack = await callHttpAudit({
    request:
      "GET /callback?state=x HTTP/1.1\n" +
      "Host: example.com\n\n" +
      "google=AIzaabcdefghijklmnopqrstuvwxyzABCDEFGHI\n" +
      "openai=sk-abcdefghijklmnopqrstuvwx\n" +
      "stripe=sk_live_abcdefghijklmnop\n" +
      "sendgrid=SG.abcdefghijklmnop.qrstuvwxyzabcdefghij\n" +
      "npm=npm_abcdefghijklmnopqrstuvwxyz0123456789\n" +
      "slack_webhook=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX\n" +
      "header_style=Bearer abcdefghijklmnopqrstuvwxyz0123456789\n",
  });

  const preview = pack.request.body.preview;
  assert.ok(!preview.includes("AIzaabcdefgh"), "Google API key leaked");
  assert.ok(preview.includes("[REDACTED_GOOGLE_API_KEY]"));
  assert.ok(
    !preview.includes("sk-abcdefghijklmnopqrstuvwx"),
    "OpenAI key leaked",
  );
  assert.ok(preview.includes("[REDACTED_OPENAI_KEY]"));
  assert.ok(!preview.includes("sk_live_abcdefghijklmnop"), "Stripe key leaked");
  assert.ok(preview.includes("[REDACTED_STRIPE_KEY]"));
  assert.ok(!preview.includes("SG.abcdefghijklmnop"), "SendGrid key leaked");
  assert.ok(preview.includes("[REDACTED_SENDGRID_KEY]"));
  assert.ok(
    !preview.includes("npm_abcdefghijklmnopqrstuvwxyz0123456789"),
    "npm token leaked",
  );
  assert.ok(preview.includes("[REDACTED_NPM_TOKEN]"));
  assert.ok(!preview.includes("T00000000/B00000000"), "Slack webhook leaked");
  assert.ok(preview.includes("[REDACTED_SLACK_WEBHOOK]"));
  assert.ok(
    !preview.includes("Bearer abcdefghijklmnopqrstuvwxyz0123456789"),
    "Bearer token leaked",
  );
  assert.ok(preview.includes("Bearer [REDACTED]"));
});

test("still redacts pre-existing secret shapes (no regression)", async () => {
  const pack = await callHttpAudit({
    request:
      "GET / HTTP/1.1\n" +
      "Host: example.com\n" +
      "Authorization: Bearer secret-should-be-header-redacted\n\n" +
      "aws=AKIAABCDEFGHIJKLMNOP\n" +
      "gh=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n" +
      "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n" +
      "url=https://user:hunter2@example.com/x\n",
  });

  assert.deepStrictEqual(pack.request.redacted_headers, ["Authorization"]);
  const authHeader = pack.request.headers.find(
    (h) => h.name === "Authorization",
  );
  assert.strictEqual(authHeader.value, "[REDACTED]");

  const preview = pack.request.body.preview;
  assert.ok(preview.includes("[REDACTED_AWS_KEY]"));
  assert.ok(preview.includes("[REDACTED_GH_TOKEN]"));
  assert.ok(preview.includes("[REDACTED_JWT]"));
  assert.ok(preview.includes("[REDACTED_USERINFO]@"));
  assert.ok(!preview.includes("hunter2"));
});

test("leaves ordinary, non-secret request bodies untouched", async () => {
  const pack = await callHttpAudit({
    request: 'POST /search HTTP/1.1\nHost: example.com\n\n{"q":"hello world"}',
  });
  assert.strictEqual(pack.request.body.preview, '{"q":"hello world"}');
});
