// Mantis CLI · browser-based login (Supabase Auth, supabase-CLI-style handoff).
//
//   `mantis login`   opens https://mantishack.com/cli-login in the browser,
//                    spins up a localhost HTTP server, captures the access +
//                    refresh tokens POSTed back from the /cli-login page,
//                    and writes them to ~/.Mantis/auth.json (0600).
//   `mantis logout`  deletes ~/.Mantis/auth.json.
//   `mantis whoami`  prints the signed-in email (or exit 1 if not signed in).
//
// Override the URL for self-hosted setups with MANTISHACK_URL. Add extra
// dev origins (e.g. http://localhost:5173) via MANTIS_LOGIN_ALLOW_ORIGINS
// as a comma-separated list.
"use strict";

const http = require("node:http");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const LOGIN_URL_BASE = process.env.MANTISHACK_URL || "https://mantishack.com";
const AUTH_DIR = path.join(os.homedir(), ".Mantis");
const AUTH_FILE = path.join(AUTH_DIR, "auth.json");
const LOGIN_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_BODY_BYTES = 16 * 1024; // Supabase JWTs run ~1-2 KB each; 16 KB is comfortably above worst case.

// Allow-list of origins permitted to POST to /callback. Built from
// MANTISHACK_URL plus optional MANTIS_LOGIN_ALLOW_ORIGINS for dev.
function buildAllowedOrigins() {
  const set = new Set();
  try {
    const u = new URL(LOGIN_URL_BASE);
    set.add(`${u.protocol}//${u.host}`);
  } catch {
    // Misconfigured MANTISHACK_URL — fall back to the canonical prod URL only.
    set.add("https://mantishack.com");
  }
  const extra = process.env.MANTIS_LOGIN_ALLOW_ORIGINS || "";
  for (const raw of extra.split(",").map((s) => s.trim()).filter(Boolean)) {
    try {
      const u = new URL(raw);
      set.add(`${u.protocol}//${u.host}`);
    } catch {
      // Skip malformed entries silently.
    }
  }
  return set;
}

function readAuth() {
  try {
    return JSON.parse(fs.readFileSync(AUTH_FILE, "utf8"));
  } catch {
    return null;
  }
}

function writeAuth(data) {
  fs.mkdirSync(AUTH_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
}

function clearAuth() {
  try {
    fs.unlinkSync(AUTH_FILE);
  } catch {}
}

function openBrowser(url) {
  // spawn() with an explicit argv (no shell) — no command-injection
  // surface even if the URL contains shell metacharacters.
  const argv =
    process.platform === "darwin"
      ? ["open", url]
      : process.platform === "win32"
      ? ["cmd", "/c", "start", "", url]
      : ["xdg-open", url];
  try {
    spawn(argv[0], argv.slice(1), { stdio: "ignore", detached: true }).unref();
  } catch {
    // Non-fatal — operator can paste the URL manually.
  }
}

function parseForm(body) {
  const out = Object.create(null);
  for (const pair of body.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const rawKey = eq >= 0 ? pair.slice(0, eq) : pair;
    const rawVal = eq >= 0 ? pair.slice(eq + 1) : "";
    try {
      const k = decodeURIComponent(rawKey.replace(/\+/g, " "));
      // Drop pathological keys early (prototype-pollution defense even
      // though we use a null-proto object).
      if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
      // Reject duplicates — a legitimate browser form never sends them,
      // but a hostile payload could try to overwrite an earlier value
      // with a later one. Keep the FIRST occurrence and ignore the rest.
      if (k in out) continue;
      out[k] = decodeURIComponent(rawVal.replace(/\+/g, " "));
    } catch {
      // Skip malformed pair.
    }
  }
  return out;
}

// Constant-time string compare so a network-adjacent observer can't
// distinguish near-correct cli_sessions by reply latency. 128 bits of
// entropy makes timing attacks impractical anyway, but this costs
// nothing and removes the class.
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function looksLikeJwt(v) {
  // Three base64url segments separated by dots. Supabase access_tokens
  // are JWTs; refresh_tokens are opaque random strings. We don't
  // enforce JWT shape on refresh_token; we just bound its length.
  return typeof v === "string" && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
}

function looksLikeEmail(v) {
  return typeof v === "string" && v.length > 0 && v.length < 320 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

const SUCCESS_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Mantis · signed in</title>
<style>
  html,body{margin:0;background:#050a08;color:#e5e7eb;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    display:grid;place-items:center;min-height:100vh}
  .box{text-align:center;padding:32px;max-width:420px}
  h1{color:#34d399;font-weight:700;margin:0 0 12px;font-size:24px}
  p{color:#94a3b8;margin:6px 0;font-size:14px;line-height:1.5}
  code{color:#34d399;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:13px}
</style></head>
<body><div class="box">
  <h1>You're signed in.</h1>
  <p>Return to your terminal — the Mantis CLI is ready.</p>
  <p style="margin-top:18px">You can close this tab.</p>
</div></body></html>`;

// Hardened response headers used on every reply from the callback
// server. The success page renders inline CSS only and loads no
// scripts, fonts, or images, so an extremely restrictive CSP fits.
const HARDENED_HEADERS = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
};

function startCallbackServer(expectedSession) {
  const allowedOrigins = buildAllowedOrigins();

  return new Promise((resolve, reject) => {
    const server = http.createServer();
    let settled = false;

    const finish = (fn) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // Close after the response flushes so the browser actually renders the success page.
      setTimeout(() => server.close(), 50);
      fn();
    };

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      server.close();
      reject(new Error("login timed out after 5 minutes"));
    }, LOGIN_TIMEOUT_MS);

    function corsHeadersFor(origin) {
      const headers = { ...HARDENED_HEADERS };
      if (origin && allowedOrigins.has(origin)) {
        headers["Access-Control-Allow-Origin"] = origin;
        headers["Vary"] = "Origin";
      }
      return headers;
    }

    server.on("request", (req, res) => {
      // Reject any further requests once we've already accepted one —
      // login is single-shot. Closes the door on race conditions where
      // a second POST lands during the 50ms server.close() delay.
      if (settled) {
        res.writeHead(409, HARDENED_HEADERS);
        res.end("already settled");
        return;
      }

      // Host-header guard — defense against DNS rebinding. The kernel
      // binds us to 127.0.0.1, but a victim browser pointed at
      // attacker.com (rebound to 127.0.0.1 mid-flight) would still hit
      // this server with `Host: attacker.com`. Refuse anything that
      // isn't a loopback hostname.
      const hostHeader = (req.headers.host || "").toString().toLowerCase();
      if (!/^(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?$/.test(hostHeader)) {
        res.writeHead(403, HARDENED_HEADERS);
        res.end("bad host");
        return;
      }

      const origin = (req.headers.origin || "").toString();
      // Reject the literal "null" origin explicitly — sandboxed iframes,
      // file:// pages, and some sandboxed cross-site contexts send it,
      // and we never want any of those flows.
      if (origin === "null") {
        res.writeHead(403, HARDENED_HEADERS);
        res.end("null origin not allowed");
        return;
      }

      if (req.method === "OPTIONS") {
        if (!origin || !allowedOrigins.has(origin)) {
          res.writeHead(403, HARDENED_HEADERS);
          res.end("origin not allowed");
          return;
        }
        res.writeHead(204, {
          ...corsHeadersFor(origin),
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "600",
        });
        res.end();
        return;
      }

      if (req.method !== "POST" || !req.url || !req.url.startsWith("/callback")) {
        res.writeHead(404, { ...HARDENED_HEADERS, "Content-Type": "text/plain" });
        res.end("not found");
        return;
      }

      // Browsers always attach Origin to cross-origin form POSTs (and
      // since /cli-login is on mantishack.com while the server is on
      // 127.0.0.1, this POST is by definition cross-origin). A request
      // missing Origin is therefore not from a real browser following
      // the legitimate flow — reject it.
      if (!origin || !allowedOrigins.has(origin)) {
        res.writeHead(403, { ...HARDENED_HEADERS, "Content-Type": "text/plain" });
        res.end("origin not allowed");
        return;
      }

      // Reject obviously wrong content types early.
      const ctype = (req.headers["content-type"] || "").toString().toLowerCase();
      if (!ctype.startsWith("application/x-www-form-urlencoded")) {
        res.writeHead(415, { ...HARDENED_HEADERS, "Content-Type": "text/plain" });
        res.end("unsupported media type");
        return;
      }

      let body = "";
      let truncated = false;
      req.on("data", (chunk) => {
        body += chunk;
        if (body.length > MAX_BODY_BYTES) {
          truncated = true;
          req.destroy();
        }
      });
      req.on("end", () => {
        if (truncated) return;
        const form = parseForm(body);

        if (!safeEqual(form.cli_session, expectedSession)) {
          res.writeHead(400, { ...HARDENED_HEADERS, "Content-Type": "text/plain" });
          res.end("session mismatch");
          return;
        }
        // Bound token sizes — Supabase JWTs/refresh tokens are well
        // under 8 KB each, refuse anything obviously oversized.
        if (
          !form.access_token ||
          form.access_token.length > 8192 ||
          (form.refresh_token && form.refresh_token.length > 8192)
        ) {
          res.writeHead(400, { ...HARDENED_HEADERS, "Content-Type": "text/plain" });
          res.end("missing or oversized token");
          return;
        }
        if (!looksLikeJwt(form.access_token)) {
          res.writeHead(400, { ...HARDENED_HEADERS, "Content-Type": "text/plain" });
          res.end("malformed access_token");
          return;
        }
        if (form.email && !looksLikeEmail(form.email)) {
          res.writeHead(400, { ...HARDENED_HEADERS, "Content-Type": "text/plain" });
          res.end("malformed email");
          return;
        }

        res.writeHead(200, {
          ...corsHeadersFor(origin),
          "Content-Type": "text/html; charset=utf-8",
        });
        res.end(SUCCESS_HTML);

        finish(() => {
          resolve({
            access_token: form.access_token,
            refresh_token: form.refresh_token || "",
            email: form.email || "",
            expires_at: Number(form.expires_at) || 0,
          });
        });
      });
      req.on("error", () => {
        // Client aborted — ignore; the next request (or the timeout) will resolve.
      });
    });

    server.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });

    server.listen(0, "127.0.0.1");
    server.once("listening", () => {
      const port = server.address().port;
      const url = `${LOGIN_URL_BASE}/cli-login?cli_port=${port}&cli_session=${expectedSession}`;
      process.stderr.write(`[mantis] opening browser to sign in…\n`);
      process.stderr.write(`[mantis] if it doesn't open, paste this URL:\n        ${url}\n`);
      openBrowser(url);
    });
  });
}

async function login() {
  // 256-bit cli_session — generous overkill, and matches typical
  // OAuth state-token entropy. The CLI-side regex accepts 32–64 hex
  // chars; this is 64.
  const cliSession = crypto.randomBytes(32).toString("hex");
  const tokens = await startCallbackServer(cliSession);
  writeAuth({
    email: tokens.email,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: tokens.expires_at,
    obtained_at: Math.floor(Date.now() / 1000),
    url: LOGIN_URL_BASE,
  });
  process.stderr.write(
    `[mantis] signed in${tokens.email ? ` as ${tokens.email}` : ""}\n`,
  );
  process.stderr.write(`[mantis] token saved to ${AUTH_FILE}\n`);
}

function logout() {
  const auth = readAuth();
  if (!auth) {
    process.stderr.write("[mantis] not signed in\n");
    return;
  }
  clearAuth();
  process.stderr.write(`[mantis] signed out${auth.email ? ` (${auth.email})` : ""}\n`);
}

function whoami() {
  const auth = readAuth();
  if (!auth) {
    process.stderr.write("[mantis] not signed in. Run `mantis login`.\n");
    process.exit(1);
  }
  process.stdout.write(`${auth.email || "(unknown)"}\n`);
}

module.exports = { login, logout, whoami, readAuth, AUTH_FILE };
