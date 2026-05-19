#!/usr/bin/env node
// Thin launcher: resolves the prebuilt mantis binary from the
// per-platform package installed via optionalDependencies, then
// execs it with the operator's argv. No postinstall script — works
// in Bun and pnpm strict mode.
//
// To add a new platform: publish @mantishack/cli-<os>-<arch> with a
// `bin/mantis` binary inside, and add it to optionalDependencies in
// package.json.
"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const BIN_NAME = path.basename(process.argv[1] || "mantis");

const PLATFORM_MAP = {
  "darwin-arm64": "@mantishack/cli-darwin-arm64",
  "darwin-x64": "@mantishack/cli-darwin-x64",
  "linux-x64": "@mantishack/cli-linux-x64",
  "linux-arm64": "@mantishack/cli-linux-arm64",
};

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORM_MAP[key];

if (!pkg) {
  console.error(
    `[mantishack] no prebuilt binary for ${key}.\n` +
      `[mantishack] supported: ${Object.keys(PLATFORM_MAP).join(", ")}\n` +
      `[mantishack] build from source: https://github.com/deonmenezes/mantishack`
  );
  process.exit(1);
}

let binaryPath;
try {
  // The platform package ships `bin/mantis`, `bin/mantis-daemon`,
  // and `bin/mantis-mcp`. We pick whichever this shim was named for.
  binaryPath = require.resolve(`${pkg}/bin/${BIN_NAME}`);
} catch (err) {
  console.error(
    `[mantishack] ${pkg} is not installed.\n` +
      `[mantishack] this usually means your package manager skipped optional dependencies.\n` +
      `[mantishack] try: npm i ${pkg} (or bun add ${pkg})`
  );
  console.error(err && err.message ? err.message : err);
  process.exit(1);
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  // Make the sibling binaries (mantis-daemon, mantis-mcp) discoverable
  // on PATH so the main CLI's `which::which("mantis-daemon")` lookups
  // resolve from this install.
  env: {
    ...process.env,
    PATH: `${path.dirname(binaryPath)}${path.delimiter}${process.env.PATH || ""}`,
  },
});

if (result.error) {
  console.error(`[mantishack] failed to exec ${binaryPath}:`, result.error.message);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
