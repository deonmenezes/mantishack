#!/usr/bin/env node
"use strict";

// Black-box test for the mantis-http-audit MCP server: drives it over its
// real stdio JSON-RPC transport (same path a Mantis agent uses) rather than
// reaching into internals, so it also guards the wire contract.
//
// Run with: node .codex/mcp-servers/http-audit/server.test.js

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawn } = require("node:child_process");

const SERVER_PATH = path.join(__dirname, "server.js");

function callHttpAudit(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SERVER_PATH]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", () => {
      const lines = stdout.split("\n").filter(Boolean);
      const responses = lines.map((l) => JSON.parse(l));
      const callResponse = responses.find((r) => r.id === 2);
      if (!callResponse) {
        reject(new Error(`no tools/call response; stderr=${stderr}`));
        return;
      }
      resolve(JSON.parse(callResponse.result.content[0].text));
    });

    child.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {},
      }) + "\n",
    );
    child.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "http_audit", arguments: args },
      }) + "\n",
    );
    child.stdin.end();
  });
}

test("redacts a secret carried as a JSON response body field", async () => {
  const response = [
    "HTTP/1.1 200 OK",
    "Content-Type: application/json",
    "",
    '{"user":"alice","access_token":"abcd1234vErYsEcReT","ok":true}',
  ].join("\r\n");

  const pack = await callHttpAudit({ response });
  assert.equal(
    pack.response.body.preview.includes("abcd1234vErYsEcReT"),
    false,
  );
  assert.match(pack.response.body.preview, /"access_token":"\[REDACTED\]"/);
});

test("redacts recognizable secret shapes (Google API key, Stripe key)", async () => {
  const googleKey = "AIza" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R"; // 35 chars after AIza
  assert.equal(googleKey.length, 39);
  const stripeKey = "sk_live_ABCDEFGHIJKLMNOPQRST";
  const request = [
    "POST /billing HTTP/1.1",
    "Host: example.com",
    "",
    `google_key=${googleKey}&stripe=${stripeKey}`,
  ].join("\r\n");

  const pack = await callHttpAudit({ request });
  const preview = pack.request.body.preview;
  assert.equal(preview.includes(googleKey), false);
  assert.equal(preview.includes(stripeKey), false);
  assert.match(preview, /\[REDACTED_GOOGLE_API_KEY\]/);
  assert.match(preview, /\[REDACTED_STRIPE_KEY\]/);
});

test("still redacts the pre-existing query/form key=value shape", async () => {
  const request = [
    "GET /reset?token=supersecretvalue HTTP/1.1",
    "Host: example.com",
    "",
    "",
  ].join("\r\n");

  const pack = await callHttpAudit({ request });
  assert.equal(pack.request.request_line.includes("supersecretvalue"), false);
  assert.match(pack.request.request_line, /token=\[REDACTED\]/);
});

test("leaves non-secret JSON fields untouched", async () => {
  const response = [
    "HTTP/1.1 200 OK",
    "Content-Type: application/json",
    "",
    '{"user":"alice","ok":true}',
  ].join("\r\n");

  const pack = await callHttpAudit({ response });
  assert.match(pack.response.body.preview, /"user":"alice"/);
});
