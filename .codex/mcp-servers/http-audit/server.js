#!/usr/bin/env node
"use strict";

const { createServer } = require("../lib/mcp_stdio.js");
const {
  sha256,
  redactValue,
  redactHeaders,
  summarizeBody,
} = require("./redact.js");

/**
 * Mantis HTTP-audit + request-refs (PRD section 6 "Proxy / traffic:
 * HTTP-audit + request-refs", section 8/9 evidence). Pure Node, zero deps,
 * works with no external binary installed.
 *
 * Turns a raw HTTP request/response pair into a BOUNDED, redacted evidence
 * pack plus a stable content hash ("request-ref") that a finding can point at
 * without ever storing the raw secret-bearing exchange (PRD section 9/11:
 * "never raw secrets/tokens/cookies/full bodies" in findings/evidence).
 *
 * Secret-shape redaction lives in `./redact.js` so it can be unit-tested
 * without spinning up the stdio transport (see `redact.test.js`).
 */

// Splits a raw HTTP message into { startLine, headers[], body }. Tolerant of
// CRLF or LF and of a missing body.
function parseHttpMessage(raw) {
  if (!raw || typeof raw !== "string") return null;
  const normalized = raw.replace(/\r\n/g, "\n");
  const sep = normalized.indexOf("\n\n");
  const headPart = sep === -1 ? normalized : normalized.slice(0, sep);
  const body = sep === -1 ? "" : normalized.slice(sep + 2);
  const lines = headPart.split("\n").filter((l) => l.length > 0);
  const startLine = lines.shift() || "";
  const headers = lines.map((line) => {
    const idx = line.indexOf(":");
    if (idx === -1) return { name: line.trim(), value: "" };
    return {
      name: line.slice(0, idx).trim(),
      value: line.slice(idx + 1).trim(),
    };
  });
  return { startLine, headers, body };
}

function auditExchange({ request, response }) {
  if (!request && !response) {
    throw new Error(
      "Provide at least one of `request` or `response` (raw HTTP text).",
    );
  }

  const pack = { tool: "http-audit", kind: "evidence-pack" };

  if (request) {
    const parsed = parseHttpMessage(request);
    if (!parsed)
      throw new Error(
        "`request` must be a non-empty raw HTTP request string (request line + headers + optional body).",
      );
    const { headers, redactedNames } = redactHeaders(parsed.headers);
    // The request-ref hashes the RAW exchange so the same exchange always maps
    // to the same id (dedup/cross-reference), while only the redacted form is
    // ever returned.
    pack.request = {
      request_line: redactValue(parsed.startLine),
      headers,
      redacted_headers: redactedNames,
      body: summarizeBody(parsed.body),
      request_ref: `req-${sha256(request).slice(0, 16)}`,
    };
  }

  if (response) {
    const parsed = parseHttpMessage(response);
    if (!parsed)
      throw new Error(
        "`response` must be a non-empty raw HTTP response string (status line + headers + optional body).",
      );
    const { headers, redactedNames } = redactHeaders(parsed.headers);
    pack.response = {
      status_line: redactValue(parsed.startLine),
      headers,
      redacted_headers: redactedNames,
      body: summarizeBody(parsed.body),
      response_ref: `res-${sha256(response).slice(0, 16)}`,
    };
  }

  pack.note =
    "Bounded, redacted evidence pack. Secret-bearing headers and inline secrets are stripped; " +
    "bodies are hashed + previewed, never stored in full. Attach the *_ref ids to a finding via mantis_findings.";
  return pack;
}

createServer({
  name: "mantis-http-audit",
  version: "0.1.0",
  tools: [
    {
      name: "http_audit",
      description:
        "Turn a raw HTTP request and/or response into a bounded, redacted evidence pack with a stable request-ref hash. Use during Validate/DAST to attach reproducible HTTP evidence to a finding WITHOUT storing raw secrets, cookies, or full bodies. Pure function; no network is made -- you pass in captured text.",
      inputSchema: {
        type: "object",
        properties: {
          request: {
            type: "string",
            description:
              "Raw HTTP request text (request line + headers + optional body).",
          },
          response: {
            type: "string",
            description:
              "Raw HTTP response text (status line + headers + optional body).",
          },
        },
      },
      handler: auditExchange,
    },
  ],
});
