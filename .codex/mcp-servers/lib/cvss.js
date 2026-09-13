"use strict";

/**
 * CVSS v3.0/v3.1 base-score calculator (FIRST.org CVSS v3.1 spec, section
 * 7.4 "Base Metrics Equations"). Deterministic, pure, dependency-free.
 *
 * Only the base score is computed -- temporal/environmental metrics that may
 * appear later in a vector string are parsed (so they don't break matching)
 * but intentionally ignored, matching how OSV/NVD report the base severity.
 */

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { N: 0, L: 0.22, H: 0.56 };

// CVSS Roundup(x): the smallest number of 1 decimal place >= x, per the
// spec's own reference implementation (guards against float error from
// naively doing Math.ceil(x * 10) / 10).
function roundUp(value) {
  const intInput = Math.round(value * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

function parseVector(vector) {
  if (typeof vector !== "string") return null;
  const match = vector.match(/^CVSS:3\.[01]\/(.+)$/);
  if (!match) return null;
  const metrics = {};
  for (const part of match[1].split("/")) {
    const [key, value] = part.split(":");
    if (!key || !value) return null;
    metrics[key] = value;
  }
  const required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  if (!required.every((k) => k in metrics)) return null;
  return metrics;
}

/**
 * Base score (0-10) for a "CVSS:3.0/..." or "CVSS:3.1/..." vector string, or
 * null if the vector can't be parsed (unsupported version, missing/unknown
 * metric value, malformed string). Never guesses -- an unparsable vector is
 * reported as unknown rather than assigned a fabricated score.
 */
function cvssV3BaseScore(vector) {
  const m = parseVector(vector);
  if (!m || (m.S !== "U" && m.S !== "C")) return null;

  const scopeChanged = m.S === "C";
  const av = AV[m.AV];
  const ac = AC[m.AC];
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.PR];
  const ui = UI[m.UI];
  const c = CIA[m.C];
  const i = CIA[m.I];
  const a = CIA[m.A];
  if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;
  const base = scopeChanged
    ? 1.08 * (impact + exploitability)
    : impact + exploitability;
  return roundUp(Math.min(base, 10));
}

// Standard CVSS v3 qualitative severity rating (spec section 5).
function cvssV3Severity(score) {
  if (typeof score !== "number" || Number.isNaN(score)) return null;
  if (score === 0) return "info";
  if (score < 4.0) return "low";
  if (score < 7.0) return "medium";
  if (score < 9.0) return "high";
  return "critical";
}

module.exports = { cvssV3BaseScore, cvssV3Severity };
