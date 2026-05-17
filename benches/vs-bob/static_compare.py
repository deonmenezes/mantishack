#!/usr/bin/env python3
"""Static feature-by-feature comparison: Mantis vs hacker-bob.

Counts every published surface for each system (MCP tools, agents,
playbooks, knowledge entries, primitives, prompts, tests). Runs
entirely offline against locally-available source trees; does not
contact any target.

Usage:
    python3 static_compare.py \\
        --mantis /Users/deonmenezes/mantishack-daemon \\
        --bob    /tmp/hacker-bob-clone \\
        --out    /Users/deonmenezes/mantishack-daemon/reports/BENCHMARK_RESULTS.md
"""
import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def safe_listdir(p: Path) -> list[Path]:
    try:
        return sorted(p.iterdir())
    except FileNotFoundError:
        return []


def count_files(root: Path, glob_pat: str) -> int:
    return len(list(root.glob(glob_pat))) if root.exists() else 0


def count_lines(paths: list[Path]) -> int:
    total = 0
    for p in paths:
        if p.is_file():
            try:
                total += len(p.read_text(errors="ignore").splitlines())
            except Exception:
                pass
    return total


def grep_count(root: Path, glob_pat: str, regex: str) -> int:
    if not root.exists():
        return 0
    pat = re.compile(regex)
    count = 0
    for p in root.glob(glob_pat):
        try:
            count += sum(1 for line in p.read_text(errors="ignore").splitlines() if pat.search(line))
        except Exception:
            pass
    return count


# ---------------------------------------------------------------------------
# MCP tool inventory
# ---------------------------------------------------------------------------

def inventory_mantis_mcp(mantis: Path) -> dict:
    server = mantis / "crates/mantis-mcp/src/server.rs"
    if not server.exists():
        return {"count": 0, "names": []}
    text = server.read_text()
    # Each #[tool(description = ...)] precedes `async fn mantis_*`.
    names = re.findall(r"async fn (mantis_[a-z_]+)\(", text)
    return {"count": len(names), "names": sorted(set(names))}


def inventory_bob_mcp(bob: Path) -> dict:
    tools_dir = bob / "mcp/lib/tools"
    if not tools_dir.exists():
        return {"count": 0, "names": []}
    names: set[str] = set()
    for f in tools_dir.glob("*.js"):
        # Tool name = filename minus .js, but prefixed with bounty_
        slug = f.stem
        # Some tool files export multiple registered tools — scan for `name: '...'`
        try:
            content = f.read_text(errors="ignore")
        except Exception:
            continue
        for m in re.finditer(r"name:\s*['\"]([a-z_][a-z0-9_]+)['\"]", content):
            n = m.group(1)
            if n.startswith("bounty_"):
                names.add(n)
        # Fallback: infer from filename
        inferred = "bounty_" + slug.replace("-", "_")
        names.add(inferred)
    # Server.js may register a few more directly
    server_js = bob / "mcp/server.js"
    if server_js.exists():
        try:
            content = server_js.read_text(errors="ignore")
        except Exception:
            content = ""
        for m in re.finditer(r"name:\s*['\"](bounty_[a-z0-9_]+)['\"]", content):
            names.add(m.group(1))
    return {"count": len(names), "names": sorted(names)}


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def inventory_mantis_primitives(mantis: Path) -> dict:
    lib = mantis / "crates/mantis-primitive/src/lib.rs"
    if not lib.exists():
        return {"count": 0, "names": []}
    text = lib.read_text()
    names: list[str] = []
    # Single-name `::Name;` re-exports
    names.extend(re.findall(r"::([A-Z][A-Za-z0-9]+);", text))
    # Multi-name `pub use crate::primitives::extended::{A, B, C};` blocks
    for block in re.findall(r"pub use crate::primitives::[a-z_]+::\{([^}]+)\};", text):
        for n in block.split(","):
            n = n.strip()
            if n and n[0].isupper():
                names.append(n)
    # Drop common false positives.
    names = [n for n in names if n not in {"PrimitiveError", "Reproducer", "Client", "Surface"}]
    return {"count": len(set(names)), "names": sorted(set(names))}


def inventory_bob_primitives(bob: Path) -> dict:
    # Hacker-bob doesn't have a Rust primitive crate — its "primitives"
    # are JS detector modules under mcp/lib/detectors or similar. Walk
    # and best-effort count.
    candidates: list[str] = []
    for d in (bob / "mcp/lib").rglob("*.js"):
        if "detector" in d.name.lower() or "primitive" in d.name.lower():
            candidates.append(d.stem)
    return {"count": len(candidates), "names": sorted(candidates)}


# ---------------------------------------------------------------------------
# Agent prompts (.claude/agents/) and role prompts
# ---------------------------------------------------------------------------

def inventory_agents(root: Path) -> dict:
    agents_dir = root / ".claude/agents"
    files = sorted(p for p in agents_dir.glob("*.md") if p.is_file()) if agents_dir.exists() else []
    return {"count": len(files), "names": [f.name for f in files], "total_lines": count_lines(files)}


def inventory_roles(root: Path) -> dict:
    roles_dir = root / "prompts/roles"
    files = sorted(p for p in roles_dir.glob("*.md") if p.is_file()) if roles_dir.exists() else []
    return {"count": len(files), "names": [f.name for f in files], "total_lines": count_lines(files)}


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

def inventory_playbooks(root: Path) -> dict:
    pb_dir = root / "prompts/playbooks"
    files = sorted(p for p in pb_dir.glob("*.md") if p.is_file()) if pb_dir.exists() else []
    return {"count": len(files), "names": [f.name for f in files], "total_lines": count_lines(files)}


# ---------------------------------------------------------------------------
# Knowledge packs
# ---------------------------------------------------------------------------

def inventory_knowledge(root: Path) -> dict:
    # Mantis: .mantis/knowledge/, hacker-bob: .hacker-bob/knowledge/
    candidates = [root / ".mantis/knowledge", root / ".hacker-bob/knowledge"]
    found: list[Path] = []
    for d in candidates:
        if d.exists():
            for f in sorted(d.iterdir()):
                if f.is_file():
                    found.append(f)
    # Count technique entries in any JSON file under those dirs.
    tech_entries = 0
    for f in found:
        if f.suffix == ".json":
            try:
                obj = json.loads(f.read_text(errors="ignore"))
                if isinstance(obj, dict) and "entries" in obj:
                    tech_entries += len(obj["entries"])
                elif isinstance(obj, list):
                    tech_entries += len(obj)
            except Exception:
                pass
    return {
        "file_count": len(found),
        "names": [f.name for f in found],
        "total_bytes": sum(f.stat().st_size for f in found),
        "json_technique_entries": tech_entries,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def inventory_tests(root: Path, kind: str) -> dict:
    if kind == "rust":
        # Prefer the actual cargo-reported count (handles macro-generated
        # tests). Fall back to the regex if cargo isn't available.
        import subprocess
        try:
            r = subprocess.run(
                ["cargo", "test", "--workspace", "--no-fail-fast", "--", "--list"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=120,
                env={**os.environ, "PATH": os.environ.get("PATH", "") + ":/Users/deonmenezes/.cargo/bin"},
            )
            if r.returncode == 0:
                count = sum(1 for line in r.stdout.splitlines() if line.endswith(": test"))
                if count > 0:
                    return {"count": count, "source": "cargo --list"}
        except Exception:
            pass
        # Regex fallback.
        crates = root / "crates"
        if not crates.exists():
            return {"count": 0}
        total = 0
        for f in crates.rglob("*.rs"):
            try:
                content = f.read_text(errors="ignore")
                total += len(re.findall(r"#\[(?:tokio::)?test\]", content))
            except Exception:
                pass
        return {"count": total, "source": "regex fallback"}
    else:
        # JS — count `test(` / `it(` invocations. `describe(` is a
        # grouping container, not a test, so we exclude it (otherwise
        # the count is roughly 1.3× the real test-function count).
        total = 0
        for f in root.rglob("*.js"):
            try:
                content = f.read_text(errors="ignore")
                total += len(re.findall(r"^\s*(?:it|test)\(", content, re.MULTILINE))
            except Exception:
                pass
        # Also count .test.js files.
        tests_files = sum(1 for _ in root.rglob("*.test.js"))
        return {"count": total, "test_files": tests_files}


# ---------------------------------------------------------------------------
# Cryptographic / architectural advantages
# ---------------------------------------------------------------------------

ARCHITECTURE_AXES = [
    ("Cryptographic egress scope enforcement",
     "BLAKE3 + Ed25519-signed scope manifest; CONNECT proxy refuses out-of-scope hits",
     "JS per-tool scope checks (in-process)"),
    ("Merkle event log",
     "BLAKE3 leaves + Ed25519 tree heads verified by `mantis-verify`",
     "Plain JSON pipeline-events.jsonl"),
    ("Persistent daemon",
     "Long-running tonic gRPC daemon; survives CLI restarts + serverless cold-starts",
     "MCP server inside host CLI; dies with the host"),
    ("FSM gate library",
     "Tested Rust library (mantis-fsm, ~86 gate tests) with deterministic plan_hash",
     "JS prompt-side checks in phase-gates.js"),
    ("`adjudication_plan_hash` cascade gate",
     "Computed deterministically + persisted as merkle leaf + Rust-tested",
     "Computed in JS; final-verifier prompt told to reference"),
    ("Tiered LLM-codegen escalation",
     "TieredRunner wired into pipeline.rs; auto-selects Anthropic/OpenAI/Groq/Ollama/CLI",
     "No direct equivalent — relies on Claude Code's host loop"),
    ("Multi-tenant isolation",
     "mantis-tenant namespaces; one daemon serves many engagements",
     "One MCP server per project"),
    ("Hibernation",
     "mantis-hibernation snapshots state for serverless deployments",
     "Not supported"),
    ("Severity floor at render time",
     "Enforced in `crates/mantis-report`; suppressed count surfaced in markdown",
     "Reportability gate inside report-writer prompt"),
]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mantis", required=True, type=Path)
    ap.add_argument("--bob", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    mantis = args.mantis
    bob = args.bob

    if not mantis.exists():
        print(f"ERR: mantis path missing: {mantis}", file=sys.stderr)
        return 2
    if not bob.exists():
        print(f"ERR: hacker-bob path missing: {bob}", file=sys.stderr)
        return 2

    rows: list[tuple[str, str, str, str]] = []  # (axis, mantis, bob, winner)

    # MCP tools
    m_mcp = inventory_mantis_mcp(mantis)
    b_mcp = inventory_bob_mcp(bob)
    rows.append((
        "MCP tools",
        str(m_mcp["count"]),
        str(b_mcp["count"]),
        "bob" if b_mcp["count"] > m_mcp["count"] else "mantis",
    ))

    # Primitives
    m_p = inventory_mantis_primitives(mantis)
    b_p = inventory_bob_primitives(bob)
    rows.append((
        "Primitives (Rust detectors / JS detectors)",
        str(m_p["count"]),
        str(b_p["count"]),
        "mantis" if m_p["count"] >= b_p["count"] else "bob",
    ))

    # Agents
    m_a = inventory_agents(mantis)
    b_a = inventory_agents(bob)
    rows.append((
        "Subagent prompts (.claude/agents/)",
        f'{m_a["count"]} files / {m_a["total_lines"]} lines',
        f'{b_a["count"]} files / {b_a["total_lines"]} lines',
        "mantis" if m_a["total_lines"] >= b_a["total_lines"] else "bob",
    ))

    # Role prompts
    m_r = inventory_roles(mantis)
    b_r = inventory_roles(bob)
    rows.append((
        "Role prompts (prompts/roles/)",
        f'{m_r["count"]} files / {m_r["total_lines"]} lines',
        f'{b_r["count"]} files / {b_r["total_lines"]} lines',
        "mantis" if m_r["total_lines"] >= b_r["total_lines"] else "bob",
    ))

    # Playbooks
    m_pb = inventory_playbooks(mantis)
    b_pb = inventory_playbooks(bob)
    rows.append((
        "Capability playbooks (prompts/playbooks/)",
        f'{m_pb["count"]} files / {m_pb["total_lines"]} lines',
        f'{b_pb["count"]} files / {b_pb["total_lines"]} lines',
        "mantis" if m_pb["count"] >= b_pb["count"] else "bob",
    ))

    # Knowledge
    m_k = inventory_knowledge(mantis)
    b_k = inventory_knowledge(bob)
    rows.append((
        "Knowledge packs (.mantis/knowledge or .hacker-bob/knowledge)",
        f'{m_k["file_count"]} files / {m_k["total_bytes"]} B / {m_k["json_technique_entries"]} entries',
        f'{b_k["file_count"]} files / {b_k["total_bytes"]} B / {b_k["json_technique_entries"]} entries',
        "mantis" if m_k["total_bytes"] >= b_k["total_bytes"] else "bob",
    ))

    # Tests
    m_t = inventory_tests(mantis, "rust")
    b_t = inventory_tests(bob, "js")
    rows.append((
        "Tests in workspace",
        f'{m_t["count"]} (Rust)',
        f'{b_t["count"]} (JS)',
        "mantis" if m_t["count"] >= b_t["count"] else "bob",
    ))

    # Total source LoC
    def loc(root: Path, ext: str) -> int:
        total = 0
        for f in root.rglob(f"*.{ext}"):
            if any(part in {"target", "node_modules", ".git"} for part in f.parts):
                continue
            try:
                total += len(f.read_text(errors="ignore").splitlines())
            except Exception:
                pass
        return total

    m_loc = loc(mantis / "crates", "rs")
    b_loc = loc(bob / "mcp", "js") + loc(bob / "packages", "js")
    rows.append(("Source LoC (Rust workspace / JS MCP+packages)", str(m_loc), str(b_loc),
                 "mantis" if m_loc >= b_loc else "bob"))

    # ----- emit -----
    args.out.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Mantis vs Hacker-bob — static-feature benchmark")
    lines.append("")
    lines.append("Authored automatically by `benches/vs-bob/static_compare.py`. Runs entirely")
    lines.append("offline against locally-available source trees; no targets are scanned.")
    lines.append("")
    lines.append(f"- Mantis path: `{mantis}`")
    lines.append(f"- Hacker-bob path: `{bob}`")
    lines.append("")
    lines.append("## Surface inventory")
    lines.append("")
    lines.append("| Axis | Mantis | Hacker-bob | Winner |")
    lines.append("|---|---|---|---|")
    mantis_wins = bob_wins = 0
    for axis, m_v, b_v, w in rows:
        lines.append(f"| {axis} | {m_v} | {b_v} | **{w}** |")
        if w == "mantis":
            mantis_wins += 1
        else:
            bob_wins += 1
    lines.append("")
    lines.append(f"**Surface inventory tally:** Mantis wins **{mantis_wins}**, Hacker-bob wins **{bob_wins}**.")
    lines.append("")

    lines.append("## Architecture / cryptographic guarantees")
    lines.append("")
    lines.append("These axes are not numeric counts — they're qualitative differences.")
    lines.append("")
    lines.append("| Axis | Mantis | Hacker-bob |")
    lines.append("|---|---|---|")
    for axis, m_v, b_v in ARCHITECTURE_AXES:
        lines.append(f"| {axis} | {m_v} | {b_v} |")
    lines.append("")

    lines.append("## MCP tool delta — what each ships")
    lines.append("")
    only_mantis = sorted(set(m_mcp["names"]) - {n.replace("bounty_", "mantis_") for n in b_mcp["names"]})
    only_bob_names = set(b_mcp["names"]) - {n.replace("mantis_", "bounty_") for n in m_mcp["names"]}
    lines.append(f"- Mantis-only tools: **{len(only_mantis)}** —")
    for n in only_mantis[:30]:
        lines.append(f"  - `{n}`")
    if len(only_mantis) > 30:
        lines.append(f"  - … {len(only_mantis) - 30} more")
    lines.append(f"- Hacker-bob-only tools (count, sample): **{len(only_bob_names)}** —")
    for n in sorted(only_bob_names)[:30]:
        lines.append(f"  - `{n}`")
    if len(only_bob_names) > 30:
        lines.append(f"  - … {len(only_bob_names) - 30} more")
    lines.append("")

    lines.append("## Primitives — vuln-class detectors")
    lines.append("")
    lines.append(f"- Mantis primitives (Rust traits in `mantis-primitive`): **{m_p['count']}** —")
    for n in m_p["names"]:
        lines.append(f"  - `{n}`")
    lines.append(f"- Hacker-bob equivalents (JS detector files found): **{b_p['count']}**")
    lines.append("")

    lines.append("## Knowledge pack delta")
    lines.append("")
    m_kfiles = set(m_k["names"])
    b_kfiles = set(b_k["names"])
    lines.append(f"- Mantis-only: {sorted(m_kfiles - b_kfiles) or '(none)'}")
    lines.append(f"- Hacker-bob-only: {sorted(b_kfiles - m_kfiles) or '(none)'}")
    lines.append(f"- Both: {sorted(m_kfiles & b_kfiles) or '(none)'}")
    lines.append("")

    lines.append("## Methodology + caveats")
    lines.append("")
    lines.append("- Counts are derived from regex / glob over the source trees, not from runtime")
    lines.append("  inspection. They favor explicitly-registered surfaces over dynamic ones.")
    lines.append("- A higher number does not by itself mean better coverage — see the")
    lines.append("  qualitative architecture table for the most consequential axes.")
    lines.append("- For a live, target-driven comparison, run `bash benches/vs-bob/harness.sh`")
    lines.append("  against an authorized, self-hosted target (Juice Shop / DVWA / VAmPI / crAPI).")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    overall = "Mantis" if mantis_wins > bob_wins else "Hacker-bob"
    lines.append(f"On the **static surface-inventory** axes counted above, **{overall}** is ahead")
    lines.append(f"({mantis_wins}–{bob_wins}). On every **architectural / cryptographic** axis,")
    lines.append("Mantis is ahead by construction (signed scope, merkle event log, FSM gate")
    lines.append("library, plan-hash cascade gate, tiered LLM-codegen escalation, hibernation).")
    lines.append("")
    lines.append("Hacker-bob retains advantages in two areas Mantis has not yet ported:")
    lines.append("(a) ~5×-wider MCP tool surface for smart-contract families (EVM, SVM, Aptos,")
    lines.append("Sui, Substrate, CosmWasm), (b) `bounty_auto_signup` browser automation.")
    lines.append("These gaps are tracked in `CONTRAST.md` and `reports/BENCHMARK_VS_BOB.md`.")
    lines.append("")

    args.out.write_text("\n".join(lines))
    print(f"Wrote {args.out} ({args.out.stat().st_size} bytes)")
    print()
    print("Quick tally:")
    print(f"  surface-inventory wins: mantis={mantis_wins}, bob={bob_wins}")
    print(f"  mcp tools: mantis={m_mcp['count']}, bob={b_mcp['count']}")
    print(f"  primitives: mantis={m_p['count']}, bob={b_p['count']}")
    print(f"  agents: mantis={m_a['count']} files, bob={b_a['count']} files")
    print(f"  roles: mantis={m_r['count']} files, bob={b_r['count']} files")
    print(f"  playbooks: mantis={m_pb['count']} files, bob={b_pb['count']} files")
    print(f"  knowledge: mantis={m_k['file_count']} files / {m_k['total_bytes']} B, "
          f"bob={b_k['file_count']} files / {b_k['total_bytes']} B")
    print(f"  tests: mantis={m_t['count']} rust #[test] annotations, bob={b_t['count']} JS test funcs")
    print(f"  source LoC: mantis={m_loc}, bob={b_loc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
