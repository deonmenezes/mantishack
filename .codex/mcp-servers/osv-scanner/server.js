#!/usr/bin/env node
"use strict";

const { createServer } = require("../lib/mcp_stdio.js");
const { runCommand, notFoundMessage } = require("../lib/run_tool.js");
const { cvssV3BaseScore, cvssV3Severity } = require("../lib/cvss.js");

// GHSA-sourced OSV records (most of the npm/Actions/NuGet ecosystem) carry a
// human vocabulary in `database_specific.severity`. Most OSV-native
// ecosystems (PyPI's PYSEC-*, crates.io's RUSTSEC-*, Go's GO-*, ...) don't
// set that field at all and instead publish a raw CVSS vector under the
// schema's top-level `severity` array -- so without this fallback those
// records silently came back as "unknown" (never scored) instead of a real
// severity bucket, which also meant they couldn't be passed through to
// mantis_findings unmodified since "unknown" isn't a valid finding severity.
function findCvssV3Vector(vuln) {
  const entries = Array.isArray(vuln.severity) ? vuln.severity : [];
  const entry = entries.find((e) => e && e.type === "CVSS_V3" && e.score);
  return entry ? entry.score : null;
}

// Only falls back to CVSS when database_specific.severity is absent -- it
// never overrides that field, so this stays purely additive for records that
// already had a usable severity.
function deriveSeverity(vuln) {
  const dbSeverity = vuln.database_specific && vuln.database_specific.severity;
  if (dbSeverity) {
    return { severity: dbSeverity, cvss_vector: null, cvss_score: null };
  }

  const vector = findCvssV3Vector(vuln);
  const score = vector ? cvssV3BaseScore(vector) : null;
  const bucket = cvssV3Severity(score);
  return {
    severity: bucket || "unknown",
    cvss_vector: bucket ? vector : null,
    cvss_score: bucket ? score : null,
  };
}

async function osvScan({ path: targetPath, offline = false }) {
  if (!targetPath) throw new Error("path is required");

  const args = ["--json", "-r"];
  if (offline) args.push("--offline", "--download-offline-databases");
  args.push(targetPath);

  const result = await runCommand("osv-scanner", args, { timeoutMs: 300_000 });
  if (result.notFound) {
    return {
      tool: "osv-scanner",
      available: false,
      message: notFoundMessage(
        "osv-scanner",
        "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest, or brew install osv-scanner",
      ),
    };
  }

  // osv-scanner exits non-zero when vulnerabilities are found; only treat it
  // as a hard failure if stdout isn't parseable JSON at all.
  let parsed;
  try {
    parsed = JSON.parse(result.stdout || "{}");
  } catch {
    return {
      tool: "osv-scanner",
      available: true,
      error: `osv-scanner exited ${result.code} and did not return parseable JSON`,
      stderr: result.stderr.slice(0, 4000),
    };
  }

  const findings = [];
  for (const src of parsed.results || []) {
    for (const pkg of src.packages || []) {
      for (const vuln of pkg.vulnerabilities || []) {
        const derived = deriveSeverity(vuln);
        findings.push({
          source_path: src.source && src.source.path,
          ecosystem: pkg.package && pkg.package.ecosystem,
          package: pkg.package && pkg.package.name,
          version: pkg.package && pkg.package.version,
          vuln_id: vuln.id,
          summary: vuln.summary,
          severity: derived.severity,
          cvss_vector: derived.cvss_vector,
          cvss_score: derived.cvss_score,
          aliases: vuln.aliases || [],
        });
      }
    }
  }

  return {
    tool: "osv-scanner",
    available: true,
    candidate_count: findings.length,
    findings,
  };
}

createServer({
  name: "mantis-osv-scanner",
  version: "0.1.0",
  tools: [
    {
      name: "osv_scan",
      description:
        "SCA scan for known-vulnerable dependencies via osv-scanner, matched against the OSV database. Emits `candidate` findings keyed by package/version -- reachability/exploitability still needs the Validate stage. Severity comes from the advisory's own GHSA-style rating when the database sets one, otherwise from computing the CVSS v3 base score off its raw vector (common for PyPI/crates.io/Go-native advisories) -- `cvss_vector`/`cvss_score` are included when that fallback fired.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description:
              "Directory to scan recursively for dependency manifests/lockfiles.",
          },
          offline: {
            type: "boolean",
            description:
              "Use a local offline vulnerability DB instead of querying the network.",
          },
        },
        required: ["path"],
      },
      handler: osvScan,
    },
  ],
});
