"use strict";

// Integration test for the mantis_http_audit MCP server: drives it over its
// real stdio JSON-RPC transport (the same surface an agent uses) rather than
// requiring server.js directly, since requiring it would attach the
// production `process.stdin` listener from mcp_stdio.js to the test process.

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const path = require("node:path");

const SERVER_PATH = path.join(__dirname, "server.js");

function callHttpAudit(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SERVER_PATH]);
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", () => {
      const lines = stdout.split("\n").filter(Boolean);
      const responses = lines.map((line) => JSON.parse(line));
      const callResponse = responses.find((r) => r.id === 2);
      if (!callResponse) {
        reject(new Error(`No tools/call response. stderr: ${stderr}`));
        return;
      }
      const text = callResponse.result.content[0].text;
      resolve(JSON.parse(text));
    });

    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {},
      })}\n`,
    );
    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "http_audit", arguments: args },
      })}\n`,
    );
    child.stdin.end();
  });
}

test("redacts a Stripe secret key embedded in a JSON response body", async () => {
  const fakeKey = `sk_test_${"NOTREAL0".repeat(3)}`;
  const pack = await callHttpAudit({
    response:
      "HTTP/1.1 200 OK\nContent-Type: application/json\n\n" +
      `{"billingKey":"${fakeKey}"}`,
  });
  assert.match(pack.response.body.preview, /\[REDACTED_STRIPE_KEY]/);
  assert.doesNotMatch(pack.response.body.preview, /sk_test_/);
});

test("redacts a Google API key embedded under an unexpected field name", async () => {
  const pack = await callHttpAudit({
    response:
      "HTTP/1.1 200 OK\n\n" +
      '{"mapsClientConfig":"AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWQ"}',
  });
  assert.match(pack.response.body.preview, /\[REDACTED_GOOGLE_API_KEY]/);
});

test("redacts an Anthropic key as sk-ant-... rather than the generic OpenAI shape", async () => {
  const pack = await callHttpAudit({
    response:
      "HTTP/1.1 200 OK\n\n" +
      '{"key":"sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"}',
  });
  assert.match(pack.response.body.preview, /\[REDACTED_ANTHROPIC_KEY]/);
  assert.doesNotMatch(pack.response.body.preview, /sk-ant-/);
});

test("redacts an OpenAI-shaped key", async () => {
  const pack = await callHttpAudit({
    response:
      "HTTP/1.1 200 OK\n\n" +
      '{"key":"sk-abcdefghijklmnopqrstuvwxyz0123456789"}',
  });
  assert.match(pack.response.body.preview, /\[REDACTED_OPENAI_KEY]/);
});

test("redacts a GitHub fine-grained PAT", async () => {
  const pack = await callHttpAudit({
    response:
      "HTTP/1.1 200 OK\n\n" +
      `{"token":"github_pat_${"A".repeat(22)}_${"b".repeat(59)}"}`,
  });
  assert.match(pack.response.body.preview, /\[REDACTED_GH_TOKEN]/);
});

test("redacts a Slack incoming webhook URL", async () => {
  const pack = await callHttpAudit({
    response:
      "HTTP/1.1 200 OK\n\n" +
      '{"webhook":"https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"}',
  });
  assert.match(pack.response.body.preview, /\[REDACTED_SLACK_WEBHOOK]/);
});

test("redacts a SendGrid key and a Twilio key", async () => {
  const fakeTwilioKey = `SK${"00faced0".repeat(4)}`;
  const pack = await callHttpAudit({
    response:
      "HTTP/1.1 200 OK\n\n" +
      '{"sendgrid":"SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEFGH",' +
      `"twilio":"${fakeTwilioKey}"}`,
  });
  assert.match(pack.response.body.preview, /\[REDACTED_SENDGRID_KEY]/);
  assert.match(pack.response.body.preview, /\[REDACTED_TWILIO_KEY]/);
});

test("still redacts a pre-existing shape (AWS key) unaffected by the new patterns", async () => {
  const pack = await callHttpAudit({
    response: "HTTP/1.1 200 OK\n\n" + '{"key":"AKIAABCDEFGHIJKLMNOP"}',
  });
  assert.match(pack.response.body.preview, /\[REDACTED_AWS_KEY]/);
});
