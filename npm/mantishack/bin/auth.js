// Mantis CLI · browser-based login (Supabase Auth, supabase-CLI-style handoff).
//
//   `mantis login`   opens https://mantishack.com/cli-login in the browser,
//                    spins up a localhost HTTP server, captures the access +
//                    refresh tokens POSTed back from the /cli-login page,
//                    and writes them to ~/.Mantis/auth.json (0600).
//   `mantis logout`  deletes ~/.Mantis/auth.json.
//   `mantis whoami`  prints the signed-in email (or exit 1 if not signed in).
//
// Override the URL for self-hosted setups with MANTISHACK_URL.
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
const MAX_BODY_BYTES = 8192;

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
  const out = {};
  for (const pair of body.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const rawKey = eq >= 0 ? pair.slice(0, eq) : pair;
    const rawVal = eq >= 0 ? pair.slice(eq + 1) : "";
    try {
      out[decodeURIComponent(rawKey.replace(/\+/g, " "))] = decodeURIComponent(
        rawVal.replace(/\+/g, " "),
      );
    } catch {
      // Skip malformed pair.
    }
  }
  return out;
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

function startCallbackServer(expectedSession) {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      server.close();
      reject(new Error("login timed out after 5 minutes"));
    }, LOGIN_TIMEOUT_MS);

    server.on("request", (req, res) => {
      if (req.method === "OPTIONS") {
        res.writeHead(204, {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        });
        res.end();
        return;
      }
      if (req.method !== "POST" || !req.url || !req.url.startsWith("/callback")) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("not found");
        return;
      }
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
        if (body.length > MAX_BODY_BYTES) req.destroy();
      });
      req.on("end", () => {
        const form = parseForm(body);
        if (form.cli_session !== expectedSession) {
          res.writeHead(400, { "Content-Type": "text/plain" });
          res.end("session mismatch");
          return;
        }
        if (!form.access_token) {
          res.writeHead(400, { "Content-Type": "text/plain" });
          res.end("missing token");
          return;
        }
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(SUCCESS_HTML);

        if (!settled) {
          settled = true;
          clearTimeout(timer);
          // Close after the response flushes so the browser actually renders the success page.
          setTimeout(() => server.close(), 50);
          resolve({
            access_token: form.access_token,
            refresh_token: form.refresh_token || "",
            email: form.email || "",
            expires_at: Number(form.expires_at) || 0,
          });
        }
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
  const cliSession = crypto.randomBytes(16).toString("hex");
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
