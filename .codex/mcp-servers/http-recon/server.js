#!/usr/bin/env node
"use strict";

const http = require("node:http");
const https = require("node:https");
const { URL } = require("node:url");
const { createServer } = require("../lib/mcp_stdio.js");
const {
  analyzeHeaders,
  analyzeCookies,
  analyzeBodyPreview,
  isBlockedHost,
} = require("./analysis.js");

/**
 * Mantis HTTP-recon (PRD Appendix roadmap item "Recon/DAST toolchain",
 * closes the "no wired capability touches a live target" gap). Pure Node,
 * zero deps.
 *
 * Makes ONE passive, discovery-only request (GET/HEAD, no payloads, no
 * auth-bypass attempts) against an explicitly authorized URL and flags
 * security-misconfiguration candidates from the plain response: missing
 * hardening headers, weak cookie flags, server/framework version
 * disclosure, and verbose error/debug pages (see analysis.js). Never
 * fabricates a severity -- every hit is a `candidate` for the Detect stage,
 * same as every other scanner server in this catalog.
 *
 * Safety: refuses to target loopback/link-local/private-range or
 * non-http(s) hosts, so this tool can't be pointed at internal
 * infrastructure by mistake.
 */

const MAX_REDIRECTS = 3;
const MAX_BODY_PREVIEW_BYTES = 2048;
const DEFAULT_TIMEOUT_MS = 10_000;

function fetchOnce(targetUrl, method, timeoutMs) {
  return new Promise((resolve, reject) => {
    const lib = targetUrl.protocol === "https:" ? https : http;
    const req = lib.request(
      targetUrl,
      {
        method,
        timeout: timeoutMs,
        headers: {
          "user-agent": "mantis-http-recon/0.1 (+authorized-discovery-scan)",
          "accept": "*/*",
        },
      },
      (res) => {
        const chunks = [];
        let bytes = 0;
        let finished = false;
        function finish() {
          if (finished) return;
          finished = true;
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            bodyPreview: Buffer.concat(chunks)
              .toString("utf8")
              .slice(0, MAX_BODY_PREVIEW_BYTES),
          });
        }
        res.on("data", (chunk) => {
          if (bytes < MAX_BODY_PREVIEW_BYTES) {
            chunks.push(chunk);
            bytes += chunk.length;
          } else {
            res.destroy();
          }
        });
        res.on("end", finish);
        res.on("close", finish);
      },
    );
    req.on("timeout", () =>
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`)),
    );
    req.on("error", reject);
    req.end();
  });
}

async function httpReconScan({
  url,
  method = "GET",
  timeout_ms: timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  if (!url || typeof url !== "string") {
    throw new Error(
      "Provide `url` (http:// or https://) of the authorized target.",
    );
  }
  if (method !== "GET" && method !== "HEAD") {
    throw new Error(
      "`method` must be GET or HEAD -- this tool is discovery-only.",
    );
  }

  let current = new URL(url);
  const chain = [current.toString()];

  for (let redirects = 0; ; redirects += 1) {
    if (current.protocol !== "http:" && current.protocol !== "https:") {
      throw new Error(
        `Unsupported protocol '${current.protocol}' -- only http/https are allowed.`,
      );
    }
    if (isBlockedHost(current.hostname)) {
      throw new Error(
        `Refusing to target '${current.hostname}': loopback/private/link-local hosts are out of scope for this tool.`,
      );
    }

    const res = await fetchOnce(current, method, timeoutMs);

    if (
      [301, 302, 303, 307, 308].includes(res.statusCode) &&
      res.headers.location
    ) {
      if (redirects >= MAX_REDIRECTS) {
        throw new Error(
          `Exceeded ${MAX_REDIRECTS} redirects while resolving ${url}`,
        );
      }
      current = new URL(res.headers.location, current);
      chain.push(current.toString());
      continue;
    }

    const setCookie = res.headers["set-cookie"];
    const candidates = [
      ...analyzeHeaders(res.headers),
      ...analyzeCookies(setCookie),
      ...analyzeBodyPreview(res.bodyPreview),
    ];

    return {
      tool: "http-recon",
      kind: "discovery-scan",
      target: url,
      final_url: current.toString(),
      redirect_chain: chain.length > 1 ? chain : undefined,
      status_code: res.statusCode,
      candidates,
      note:
        "Discovery-only: a single GET/HEAD request, no payloads or auth-bypass attempts. Every hit is a candidate " +
        "for the Detect stage, not a confirmed finding -- validate before filing via mantis_findings.",
    };
  }
}

createServer({
  name: "mantis-http-recon",
  version: "0.1.0",
  tools: [
    {
      name: "http_recon_scan",
      description:
        "Discovery-only passive scan of a single, explicitly authorized URL: one GET/HEAD request, then flag security-misconfiguration " +
        "candidates (missing hardening headers, weak cookie flags, version disclosure, verbose debug/error pages). No payloads, no " +
        "auth-bypass attempts, no path brute-forcing. Refuses loopback/private/link-local hosts. Requires explicit scope/authorization " +
        "for the target before use.",
      inputSchema: {
        type: "object",
        properties: {
          url: {
            type: "string",
            description:
              "Full http(s) URL of the authorized target to request once.",
          },
          method: {
            type: "string",
            enum: ["GET", "HEAD"],
            description: "HTTP method to use. Defaults to GET.",
          },
          timeout_ms: {
            type: "number",
            description: "Request timeout in milliseconds. Defaults to 10000.",
          },
        },
        required: ["url"],
      },
      handler: httpReconScan,
    },
  ],
});
