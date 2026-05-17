#!/usr/bin/env python3
"""
benches/vs-bob/score.py
-----------------------
Compare Mantis and hacker-bob output for a single benchmark target and produce
a markdown scoring table.

Usage:
    python3 score.py \\
        --mantis runs/<target-id>/mantis-output.jsonl \\
        --bob    runs/<target-id>/bob-output.json \\
        --target <target-id> \\
        [--out   results.md]

Input formats:
    mantis-output.jsonl  - newline-delimited JSON; each line is one Mantis event.
                           A finding event has at least one of:
                             kind: str containing "Confirmed", "TieredFinding"
                             vuln_class: str (non-null)
                           A probe event is any event with kind containing "Probe",
                           "Request", "HttpRequest", or a non-null "url" field.
                           A rejected event has kind containing "Rejected" or
                           "FalsePositive".

    bob-output.json      - single JSON object (or JSONL with a findings wrapper).
                           Accepted shapes:
                             { "findings": [...] }
                             { "confirmed_findings": [...] }
                             { "pipeline_events": [...] }   <- hacker-bob JSONL shape
                           Each finding object should carry a "vuln_class", "severity",
                           and optional "status" field.

Outputs:
    stdout               - markdown comparison table (for terminal / CI logs)
    results.md (default) - full markdown report with per-axis detail

Stdlib only — no third-party packages required.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# CVSS-approximate severity weights
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
    "informational": 0.0,
    "unknown": 1.0,
}

AXIS_WEIGHTS: Dict[str, float] = {
    "coverage": 0.20,
    "find_rate": 0.25,
    "unique_classes": 0.20,
    "severity_score": 0.25,
    "fp_estimate": 0.10,
}

# ---------------------------------------------------------------------------
# Mantis event parsing
# ---------------------------------------------------------------------------

def _is_mantis_probe(event: Dict[str, Any]) -> bool:
    kind = event.get("kind", "")
    if isinstance(kind, str):
        k = kind.lower()
        if any(tok in k for tok in ("probe", "httprequest", "request", "scan")):
            return True
    if event.get("url") or event.get("target_url"):
        return True
    return False


def _is_mantis_finding(event: Dict[str, Any]) -> bool:
    kind = event.get("kind", "")
    if isinstance(kind, str):
        k = kind.lower()
        if any(tok in k for tok in ("confirmed", "tieredfinding", "finding", "vulnerability")):
            return True
    if event.get("vuln_class") is not None:
        return True
    return False


def _is_mantis_rejected(event: Dict[str, Any]) -> bool:
    kind = event.get("kind", "")
    if isinstance(kind, str):
        k = kind.lower()
        if any(tok in k for tok in ("rejected", "falsepositive", "false_positive", "refuted")):
            return True
    if str(event.get("status", "")).lower() in ("rejected", "false_positive"):
        return True
    return False


def _mantis_vuln_class(event: Dict[str, Any]) -> Optional[str]:
    vc = event.get("vuln_class") or event.get("vulnerability_class") or event.get("class")
    if vc:
        return str(vc).strip().lower()
    kind = event.get("kind", "")
    if isinstance(kind, dict):
        for v in kind.values():
            if isinstance(v, dict):
                vc2 = v.get("vuln_class") or v.get("vulnerability_class")
                if vc2:
                    return str(vc2).strip().lower()
    return None


def _mantis_severity(event: Dict[str, Any]) -> str:
    sev = (
        event.get("severity")
        or event.get("cvss_severity")
        or event.get("risk")
        or "unknown"
    )
    return str(sev).strip().lower()


def parse_mantis(path: str) -> Dict[str, Any]:
    """Parse mantis-output.jsonl and return structured summary."""
    probes: int = 0
    findings: List[Dict[str, Any]] = []
    rejected: int = 0
    surfaces: set = set()

    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(
                    f"[score.py] WARNING: mantis line {lineno} not valid JSON ({exc}), skipping",
                    file=sys.stderr,
                )
                continue

            if _is_mantis_probe(ev):
                probes += 1
                url = ev.get("url") or ev.get("target_url") or ""
                if url:
                    surfaces.add(url)

            if _is_mantis_rejected(ev):
                rejected += 1

            if _is_mantis_finding(ev):
                findings.append(
                    {
                        "vuln_class": _mantis_vuln_class(ev),
                        "severity": _mantis_severity(ev),
                        "raw_kind": ev.get("kind"),
                    }
                )

    return {
        "probes": probes,
        "findings": findings,
        "rejected": rejected,
        "surfaces": len(surfaces),
    }


# ---------------------------------------------------------------------------
# Hacker-bob output parsing
# ---------------------------------------------------------------------------

def _bob_finding_vuln_class(f: Dict[str, Any]) -> Optional[str]:
    vc = (
        f.get("vuln_class")
        or f.get("vulnerability_class")
        or f.get("class")
        or f.get("type")
        or f.get("category")
    )
    if vc:
        return str(vc).strip().lower()
    return None


def _bob_finding_severity(f: Dict[str, Any]) -> str:
    sev = (
        f.get("severity")
        or f.get("risk")
        or f.get("cvss_severity")
        or "unknown"
    )
    return str(sev).strip().lower()


def _bob_is_rejected(f: Dict[str, Any]) -> bool:
    status = str(f.get("status", "")).lower()
    return status in ("rejected", "false_positive", "fp", "refuted", "denied")


def _extract_bob_findings(data: Any) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Return (findings_list, probes_count, rejected_count) from hacker-bob JSON.
    Handles multiple output shapes gracefully.
    """
    findings: List[Dict[str, Any]] = []
    probes: int = 0
    rejected: int = 0

    if isinstance(data, list):
        # JSONL / array of pipeline events
        for ev in data:
            if not isinstance(ev, dict):
                continue
            kind = str(ev.get("kind", ev.get("type", ""))).lower()
            if any(tok in kind for tok in ("finding", "confirmed", "vulnerability", "vuln")):
                findings.append(ev)
                if _bob_is_rejected(ev):
                    rejected += 1
            if any(tok in kind for tok in ("probe", "request", "scan", "check")):
                probes += 1
        return findings, probes, rejected

    if isinstance(data, dict):
        # Try standard wrapper keys
        for key in ("confirmed_findings", "findings", "vulnerabilities", "results"):
            if key in data and isinstance(data[key], list):
                raw_list = data[key]
                for f in raw_list:
                    if isinstance(f, dict):
                        findings.append(f)
                        if _bob_is_rejected(f):
                            rejected += 1
                break

        # Probe count from metadata
        for key in ("probes_issued", "probes", "requests_sent", "total_probes"):
            if key in data and isinstance(data[key], (int, float)):
                probes = int(data[key])
                break

        # Pipeline events list inside the dict
        if "pipeline_events" in data and isinstance(data["pipeline_events"], list):
            for ev in data["pipeline_events"]:
                if not isinstance(ev, dict):
                    continue
                kind = str(ev.get("kind", ev.get("type", ""))).lower()
                if any(tok in kind for tok in ("probe", "request")):
                    probes += 1
                if any(tok in kind for tok in ("finding", "confirmed", "vuln")):
                    findings.append(ev)

    return findings, probes, rejected


def parse_bob(path: str) -> Dict[str, Any]:
    """Parse bob-output.json and return structured summary."""
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read().strip()

    # Try as JSONL first
    if "\n" in content:
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        parsed_lines = []
        all_valid = True
        for line in lines:
            try:
                parsed_lines.append(json.loads(line))
            except json.JSONDecodeError:
                all_valid = False
                break
        if all_valid and parsed_lines:
            raw_findings, probes, rejected = _extract_bob_findings(parsed_lines)
        else:
            try:
                data = json.loads(content)
            except json.JSONDecodeError as exc:
                print(f"[score.py] ERROR: bob output is not valid JSON: {exc}", file=sys.stderr)
                return {"probes": 0, "findings": [], "rejected": 0, "surfaces": 0}
            raw_findings, probes, rejected = _extract_bob_findings(data)
    else:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            print(f"[score.py] ERROR: bob output is not valid JSON: {exc}", file=sys.stderr)
            return {"probes": 0, "findings": [], "rejected": 0, "surfaces": 0}
        raw_findings, probes, rejected = _extract_bob_findings(data)

    findings = []
    for f in raw_findings:
        findings.append(
            {
                "vuln_class": _bob_finding_vuln_class(f),
                "severity": _bob_finding_severity(f),
            }
        )

    # surfaces: hacker-bob does not always surface a distinct URL count; approximate
    # from probes if available, else len(findings) as a lower bound
    surfaces = probes if probes > 0 else len(findings)

    return {
        "probes": probes,
        "findings": findings,
        "rejected": rejected,
        "surfaces": surfaces,
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def compute_scores(summary: Dict[str, Any]) -> Dict[str, float]:
    """Compute raw (un-normalized) axis values from a parsed summary."""
    findings = summary["findings"]
    probes = max(summary["probes"], 1)  # avoid divide-by-zero
    confirmed = len(findings)
    rejected = summary["rejected"]

    # Coverage: surfaces probed (raw count; normalized later against peer)
    coverage_raw = float(summary["surfaces"] if summary["surfaces"] > 0 else probes)

    # Find rate: confirmed / probes, capped at 1.0
    find_rate = min(confirmed / probes, 1.0)

    # Unique classes
    classes = set(
        f["vuln_class"] for f in findings if f["vuln_class"] is not None
    )
    unique_classes_raw = float(len(classes))

    # Severity score: sum of CVSS-approximate weights
    severity_sum = sum(
        SEVERITY_WEIGHTS.get(f["severity"], SEVERITY_WEIGHTS["unknown"])
        for f in findings
    )

    # FP estimate: 1 - (rejected / max(raised, 1))
    raised = confirmed + rejected
    fp_score = 1.0 - (rejected / max(raised, 1))

    return {
        "coverage_raw": coverage_raw,
        "find_rate": find_rate,
        "unique_classes_raw": unique_classes_raw,
        "severity_sum": severity_sum,
        "fp_score": fp_score,
        "confirmed": confirmed,
        "rejected": rejected,
        "unique_classes": sorted(classes),
    }


def normalize_and_weight(
    mantis_raw: Dict[str, float],
    bob_raw: Dict[str, float],
) -> Tuple[Dict[str, float], Dict[str, float]]:
    """
    Normalize coverage, unique_classes, and severity_sum between the two systems
    (each axis max = 1.0 across the pair) then apply axis weights.
    """
    def normalize_pair(a: float, b: float) -> Tuple[float, float]:
        mx = max(a, b, 1.0)
        return a / mx, b / mx

    m_cov, b_cov = normalize_pair(
        mantis_raw["coverage_raw"], bob_raw["coverage_raw"]
    )
    m_uc, b_uc = normalize_pair(
        mantis_raw["unique_classes_raw"], bob_raw["unique_classes_raw"]
    )
    m_sev, b_sev = normalize_pair(
        mantis_raw["severity_sum"], bob_raw["severity_sum"]
    )

    def weighted(cov, fr, uc, sev, fp) -> float:
        return (
            AXIS_WEIGHTS["coverage"] * cov
            + AXIS_WEIGHTS["find_rate"] * fr
            + AXIS_WEIGHTS["unique_classes"] * uc
            + AXIS_WEIGHTS["severity_score"] * sev
            + AXIS_WEIGHTS["fp_estimate"] * fp
        )

    m_score = weighted(
        m_cov,
        mantis_raw["find_rate"],
        m_uc,
        m_sev,
        mantis_raw["fp_score"],
    )
    b_score = weighted(
        b_cov,
        bob_raw["find_rate"],
        b_uc,
        b_sev,
        bob_raw["fp_score"],
    )

    mantis_axes = {
        "coverage": round(m_cov * 100, 1),
        "find_rate": round(mantis_raw["find_rate"] * 100, 1),
        "unique_classes": round(m_uc * 100, 1),
        "severity_score": round(m_sev * 100, 1),
        "fp_estimate": round(mantis_raw["fp_score"] * 100, 1),
        "aggregate": round(m_score * 100, 1),
    }
    bob_axes = {
        "coverage": round(b_cov * 100, 1),
        "find_rate": round(bob_raw["find_rate"] * 100, 1),
        "unique_classes": round(b_uc * 100, 1),
        "severity_score": round(b_sev * 100, 1),
        "fp_estimate": round(bob_raw["fp_score"] * 100, 1),
        "aggregate": round(b_score * 100, 1),
    }
    return mantis_axes, bob_axes


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _md_table_row(*cells: str) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def _md_sep(n: int) -> str:
    return "|" + "|".join(["---"] * n) + "|"


def build_markdown(
    target_id: str,
    mantis_summary: Dict[str, Any],
    bob_summary: Dict[str, Any],
    mantis_axes: Dict[str, float],
    bob_axes: Dict[str, float],
    mantis_raw: Dict[str, float],
    bob_raw: Dict[str, float],
) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines: List[str] = []

    lines.append(f"# Benchmark Results — {target_id}")
    lines.append(f"")
    lines.append(f"Generated: {now}")
    lines.append(f"")
    lines.append(f"## Score Summary (normalized, 0–100)")
    lines.append(f"")
    lines.append(_md_table_row("Axis", "Weight", "Mantis", "Hacker-Bob", "Winner"))
    lines.append(_md_sep(5))

    axes_meta = [
        ("Coverage", "20 %", "coverage"),
        ("Find Rate", "25 %", "find_rate"),
        ("Unique Classes", "20 %", "unique_classes"),
        ("Severity Score", "25 %", "severity_score"),
        ("FP Estimate", "10 %", "fp_estimate"),
    ]
    for label, weight, key in axes_meta:
        m_val = mantis_axes[key]
        b_val = bob_axes[key]
        if m_val > b_val:
            winner = "Mantis"
        elif b_val > m_val:
            winner = "Hacker-Bob"
        else:
            winner = "Tie"
        lines.append(_md_table_row(label, weight, f"{m_val}", f"{b_val}", winner))

    lines.append(_md_sep(5))
    m_agg = mantis_axes["aggregate"]
    b_agg = bob_axes["aggregate"]
    overall_winner = "Mantis" if m_agg > b_agg else ("Hacker-Bob" if b_agg > m_agg else "Tie")
    lines.append(_md_table_row("**Aggregate**", "100 %", f"**{m_agg}**", f"**{b_agg}**", f"**{overall_winner}**"))
    lines.append("")

    lines.append("## Raw Counts")
    lines.append("")
    lines.append(_md_table_row("Metric", "Mantis", "Hacker-Bob"))
    lines.append(_md_sep(3))
    lines.append(_md_table_row("Surfaces / probes", mantis_summary["surfaces"] or mantis_summary["probes"], bob_summary["surfaces"] or bob_summary["probes"]))
    lines.append(_md_table_row("Confirmed findings", mantis_raw["confirmed"], bob_raw["confirmed"]))
    lines.append(_md_table_row("Rejected findings", mantis_raw["rejected"], bob_raw["rejected"]))
    lines.append(_md_table_row("Distinct vuln classes", int(mantis_raw["unique_classes_raw"]), int(bob_raw["unique_classes_raw"])))
    lines.append(_md_table_row("Severity sum (CVSS-approx)", round(mantis_raw["severity_sum"], 1), round(bob_raw["severity_sum"], 1)))
    lines.append("")

    # Vuln class tables
    for label, raw in (("Mantis", mantis_raw), ("Hacker-Bob", bob_raw)):
        classes = raw["unique_classes"]
        if classes:
            lines.append(f"## {label} — Confirmed Vulnerability Classes")
            lines.append("")
            lines.append(_md_table_row("Vuln Class", "Count"))
            lines.append(_md_sep(2))
            class_counts: Dict[str, int] = defaultdict(int)
            if label == "Mantis":
                for f in mantis_summary["findings"]:
                    if f["vuln_class"]:
                        class_counts[f["vuln_class"]] += 1
            else:
                for f in bob_summary["findings"]:
                    if f["vuln_class"]:
                        class_counts[f["vuln_class"]] += 1
            for cls in sorted(class_counts, key=lambda c: -class_counts[c]):
                lines.append(_md_table_row(cls, class_counts[cls]))
            lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append(
        "- Scores are normalized within the pair for this target run. "
        "Cross-target comparisons require re-running score.py across all targets."
    )
    lines.append("- FP Estimate = 1 − (rejected / raised). Higher is better.")
    lines.append(
        "- Coverage and severity axes are peer-normalized: the higher-count system "
        "scores 100 on that axis; the other is scaled proportionally."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Run with `bash benches/vs-bob/harness.sh <target-id>` after starting the daemon.")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score Mantis vs hacker-bob outputs and produce a markdown report."
    )
    parser.add_argument(
        "--mantis",
        required=True,
        metavar="PATH",
        help="Path to mantis-output.jsonl",
    )
    parser.add_argument(
        "--bob",
        required=True,
        metavar="PATH",
        help="Path to bob-output.json",
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="TARGET_ID",
        help="Target identifier (e.g. juiceshop)",
    )
    parser.add_argument(
        "--out",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "results.md"
        ),
        metavar="PATH",
        help="Output markdown file (default: benches/vs-bob/results.md)",
    )
    args = parser.parse_args()

    # Validate inputs
    for label, path in (("--mantis", args.mantis), ("--bob", args.bob)):
        if not os.path.isfile(path):
            print(f"[score.py] ERROR: {label} file not found: {path}", file=sys.stderr)
            sys.exit(1)

    print(f"[score.py] Parsing Mantis output: {args.mantis}", file=sys.stderr)
    mantis_summary = parse_mantis(args.mantis)

    print(f"[score.py] Parsing hacker-bob output: {args.bob}", file=sys.stderr)
    bob_summary = parse_bob(args.bob)

    print("[score.py] Computing scores ...", file=sys.stderr)
    mantis_raw = compute_scores(mantis_summary)
    bob_raw = compute_scores(bob_summary)

    mantis_axes, bob_axes = normalize_and_weight(mantis_raw, bob_raw)

    md = build_markdown(
        args.target,
        mantis_summary,
        bob_summary,
        mantis_axes,
        bob_axes,
        mantis_raw,
        bob_raw,
    )

    print(md)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(md)
    print(f"[score.py] Report written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
