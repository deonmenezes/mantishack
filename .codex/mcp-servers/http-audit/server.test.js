"use strict";

// Exercises the redaction helpers in server.js directly (no MCP transport
// involved) so the secret-shape patterns can be verified without spawning the
// stdio server. Run with: node --test .codex/mcp-servers/http-audit/server.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const Module = require("node:module");

// server.js calls createServer(...) at module load time, which starts reading
// stdin as an MCP stdio server. Stub `../lib/mcp_stdio.js` before requiring
// server.js so the module loads without wiring up a real transport, and
// capture the config it was built with so the redaction helpers can be
// exercised the same way the real tool handler exercises them.
let capturedConfig;
const mcpStdioPath = path.join(__dirname, "..", "lib", "mcp_stdio.js");
const originalLoad = Module._load;
Module._load = function patchedLoad(request, parent, isMain) {
  if (
    request === "../lib/mcp_stdio.js" ||
    path.resolve(path.dirname(parent.filename), request) === mcpStdioPath
  ) {
    return {
      createServer: (config) => {
        capturedConfig = config;
      },
    };
  }
  return originalLoad.apply(this, arguments);
};
require("./server.js");
Module._load = originalLoad;

function auditExchange(input) {
  const tool = capturedConfig.tools.find((t) => t.name === "http_audit");
  return tool.handler(input);
}

test("redacts a generically-named secret in a form/query-style body", () => {
  const pack = auditExchange({
    request:
      "POST /login HTTP/1.1\nHost: example.com\n\nusername=bob&password=hunter2",
  });
  assert.equal(pack.request.body.preview.includes("hunter2"), false);
  assert.match(pack.request.body.preview, /password=\[REDACTED\]/);
});

test("redacts a generically-named secret in a JSON body", () => {
  const pack = auditExchange({
    request:
      'POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{"username":"bob","password":"hunter2","api_key":"sk-abc123"}',
  });
  assert.equal(pack.request.body.preview.includes("hunter2"), false);
  assert.equal(pack.request.body.preview.includes("sk-abc123"), false);
  assert.match(pack.request.body.preview, /"password":"\[REDACTED\]"/);
  assert.match(pack.request.body.preview, /"api_key":"\[REDACTED\]"/);
  // Non-secret fields are left intact.
  assert.match(pack.request.body.preview, /"username":"bob"/);
});

test("still redacts shape-based secrets (AWS key, JWT) in a JSON body", () => {
  const pack = auditExchange({
    response:
      'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"aws_key":"AKIAABCDEFGHIJKLMNOP","note":"unrelated"}',
  });
  assert.equal(
    pack.response.body.preview.includes("AKIAABCDEFGHIJKLMNOP"),
    false,
  );
  assert.match(pack.response.body.preview, /\[REDACTED_AWS_KEY\]/);
  assert.match(pack.response.body.preview, /"note":"unrelated"/);
});

test("redacts sensitive headers regardless of body redaction", () => {
  const pack = auditExchange({
    request:
      "GET /me HTTP/1.1\nHost: example.com\nAuthorization: Bearer abc.def.ghi\n\n",
  });
  const authHeader = pack.request.headers.find(
    (h) => h.name === "Authorization",
  );
  assert.equal(authHeader.value, "[REDACTED]");
  assert.deepEqual(pack.request.redacted_headers, ["Authorization"]);
});
