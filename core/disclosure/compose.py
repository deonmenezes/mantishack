"""Compose a disclosure email from a MANTISHACK run's report.

Locates a run's report files (filenames vary by mode — web writes
``web_scan_report.json``, agentic writes ``report.md`` + ``findings.json``,
project reports write ``_report/findings.json``), summarises severities, builds
a good-faith cover note, and produces an ``email.message.EmailMessage`` with the
report attached (and a capped inline copy in the body for quick reading).

No network or SMTP here — see ``send`` for delivery.
"""
from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

# Markdown report candidates, in preference order.
_MD_REPORTS = ("report.md", "agentic-report.md", "validation-report.md")
# JSON findings candidates, in preference order (``_report/`` covers project
# aggregate reports). web_scan_report.json carries findings + target.
_JSON_FINDINGS = (
    "findings.json",
    "web_scan_report.json",
    "mantishack_agentic_report.json",
    "orchestrated_report.json",
    "_report/findings.json",
)

# Directories under out/ that are never themselves runs.
_SKIP_DIRS = {"logs", "jobs", "llm_cache", "_sources", "_report"}

# Severity order for the summary table.
_SEV_ORDER = ["critical", "high", "medium", "low", "info", "informational"]

DEFAULT_MAX_BODY_BYTES = 60_000


@dataclass
class ReportLocation:
    out_dir: Path
    report_md: Path | None
    findings_json: Path | None
    target: str | None = None

    @property
    def has_report(self) -> bool:
        return self.report_md is not None or self.findings_json is not None


# --------------------------------------------------------------------------- #
# Locating a run's report
# --------------------------------------------------------------------------- #
def _first_existing(base: Path, names) -> Path | None:
    for name in names:
        p = base / name
        if p.is_file():
            return p
    return None


def _has_report(base: Path) -> bool:
    return (
        _first_existing(base, _MD_REPORTS) is not None
        or _first_existing(base, _JSON_FINDINGS) is not None
    )


def latest_run_dir() -> Path | None:
    """Newest run directory that contains a recognised report.

    Searches the active project's directory (if any) and the default ``out/``
    directory, and returns the most recently modified run dir holding a report.
    ``get_active_run_dir()`` is in-process only, so a standalone ``fullsend``
    invocation cannot use it — this resolver is the cross-process equivalent.
    """
    bases: list[Path] = []
    try:
        from core.run.output import _resolve_active_project

        active = _resolve_active_project()
        if active:
            bases.append(Path(active[0]))
    except Exception:  # noqa: BLE001 - project layer optional
        pass
    try:
        from core.config import MantishackConfig

        bases.append(MantishackConfig.get_out_dir())
    except Exception:  # noqa: BLE001
        pass

    best: Path | None = None
    best_mtime = -1.0
    for base in bases:
        if not base or not base.exists():
            continue
        try:
            children = list(base.iterdir())
        except OSError:
            continue
        for d in children:
            if not d.is_dir():
                continue
            if d.name in _SKIP_DIRS or d.name.startswith("."):
                continue
            if not _has_report(d):
                continue
            try:
                m = d.stat().st_mtime
            except OSError:
                continue
            if m > best_mtime:
                best, best_mtime = d, m
    return best


def locate_report(out_dir: str | Path | None = None) -> ReportLocation | None:
    """Resolve a run directory and its report files.

    With ``out_dir`` given, use it directly; otherwise fall back to the newest
    run dir with a report (active project or ``out/``).
    """
    if out_dir is not None:
        base = Path(out_dir)
    else:
        base = latest_run_dir()
        if base is None:
            return None
    if not base.exists():
        return None

    report_md = _first_existing(base, _MD_REPORTS)
    findings_json = _first_existing(base, _JSON_FINDINGS)
    target = _read_target_hint(findings_json)
    return ReportLocation(
        out_dir=base,
        report_md=report_md,
        findings_json=findings_json,
        target=target,
    )


def _read_target_hint(findings_json: Path | None) -> str | None:
    """Best-effort target/host pulled from a findings/report JSON file."""
    if findings_json is None:
        return None
    try:
        from core.json import load_json

        data = load_json(findings_json)
    except Exception:  # noqa: BLE001
        return None
    if isinstance(data, dict):
        for key in ("target", "url", "repo", "base_url"):
            val = data.get(key)
            if isinstance(val, str) and val:
                return val
    return None


# --------------------------------------------------------------------------- #
# Findings + severity
# --------------------------------------------------------------------------- #
def load_findings(findings_json: Path | None) -> list[dict[str, Any]]:
    if findings_json is None or not findings_json.is_file():
        return []
    try:
        from core.json import load_json

        data = load_json(findings_json)
    except Exception:  # noqa: BLE001
        return []
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if isinstance(data, dict):
        out: list[dict[str, Any]] = []
        for key in ("findings", "sca_findings"):
            val = data.get(key)
            if isinstance(val, list):
                out.extend(f for f in val if isinstance(f, dict))
        return out
    return []


def severity_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(
            f.get("severity")
            or f.get("severity_assessment")
            or "info"
        ).lower()
        if sev == "none":
            sev = "informational"
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _summary_table(counts: dict[str, int]) -> str:
    if not counts:
        return "_(no machine-readable findings summary available)_"
    ordered = sorted(
        counts, key=lambda s: _SEV_ORDER.index(s) if s in _SEV_ORDER else 99
    )
    rows = ["| Severity | Count |", "|----------|-------|"]
    for sev in ordered:
        rows.append(f"| {sev.title()} | {counts[sev]} |")
    total = sum(counts.values())
    rows.append(f"| **Total** | **{total}** |")
    return "\n".join(rows)


# --------------------------------------------------------------------------- #
# Subject + body
# --------------------------------------------------------------------------- #
def build_subject(host_label: str) -> str:
    return (
        f"Security findings for {host_label} — courtesy disclosure (Mantishack)"
    )


def _cover_note(host_label: str) -> str:
    return (
        f"Hello,\n\n"
        f"This is a good-faith, courtesy security disclosure regarding "
        f"{host_label}. The findings summarised below (full report attached) "
        f"were produced by automated security analysis (Mantishack) and are "
        f"shared so your team can review and remediate as appropriate.\n\n"
        f"Please note:\n"
        f"- Reported in good faith, for defensive purposes only.\n"
        f"- Automated results can include false positives; please validate "
        f"before acting.\n"
        f"- No exploitation beyond what was necessary to identify the issues "
        f"was performed.\n"
        f"- If you have a preferred disclosure process or scope, let us know "
        f"and we will follow it.\n"
    )


def build_body(
    host_label: str,
    *,
    report_md: str | None,
    counts: dict[str, int],
    report_path: Path | None,
    attached: bool,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> tuple[str, bool]:
    """Return ``(body, truncated)`` for the disclosure email."""
    parts = [_cover_note(host_label), "\n## Findings summary\n", _summary_table(counts), ""]
    truncated = False
    if report_md:
        section = report_md.strip()
        if len(section.encode("utf-8")) > max_body_bytes:
            clipped = section.encode("utf-8")[:max_body_bytes]
            section = clipped.decode("utf-8", errors="ignore")
            truncated = True
        parts.append("\n## Report (inline preview)\n")
        parts.append("```markdown\n" + section + "\n```")
        if truncated:
            extra = " (complete report attached)" if attached else ""
            parts.append(
                f"\n_Inline preview truncated to {max_body_bytes} bytes{extra}._"
            )
    elif not attached:
        parts.append(
            "\n_No rendered report was found for this run; the summary above "
            "reflects the available findings data._"
        )
    if attached:
        parts.append("\nThe full report is attached to this email.")
    parts.append(
        "\n—\nSent as a courtesy by an operator using Mantishack. "
        "Reply to this email to reach the sender."
    )
    return "\n".join(parts), truncated


# --------------------------------------------------------------------------- #
# EmailMessage assembly
# --------------------------------------------------------------------------- #
def _attach_file(msg: EmailMessage, path: Path) -> None:
    try:
        data = path.read_bytes()
    except OSError:
        return
    if path.suffix == ".md":
        maintype, subtype = "text", "markdown"
    elif path.suffix == ".json":
        maintype, subtype = "application", "json"
    else:
        maintype, subtype = "application", "octet-stream"
    msg.add_attachment(
        data, maintype=maintype, subtype=subtype, filename=path.name
    )


def build_email(
    *,
    sender: str,
    host_label: str,
    location: ReportLocation,
    recipients: list[str],
    cc: list[str] | None = None,
    subject: str | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    attach: bool = True,
) -> tuple[EmailMessage, dict[str, Any]]:
    """Build the disclosure ``EmailMessage`` and a metadata dict."""
    findings = load_findings(location.findings_json)
    counts = severity_summary(findings)
    report_md = location.report_md.read_text(errors="replace") if location.report_md else None

    attachments = []
    if attach:
        for p in (location.report_md, location.findings_json):
            if p is not None and p.is_file():
                attachments.append(p)

    body, truncated = build_body(
        host_label,
        report_md=report_md,
        counts=counts,
        report_path=location.report_md,
        attached=bool(attachments),
        max_body_bytes=max_body_bytes,
    )

    msg = EmailMessage()
    msg["Subject"] = subject or build_subject(host_label)
    if sender:
        msg["From"] = sender
    if recipients:
        msg["To"] = ", ".join(recipients)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg.set_content(body)
    for p in attachments:
        _attach_file(msg, p)

    meta = {
        "subject": msg["Subject"],
        "from": sender or None,
        "to": list(recipients),
        "cc": list(cc or []),
        "report_dir": str(location.out_dir),
        "report_md": str(location.report_md) if location.report_md else None,
        "findings_json": str(location.findings_json) if location.findings_json else None,
        "findings_count": len(findings),
        "severity_counts": counts,
        "attachments": [p.name for p in attachments],
        "truncated": truncated,
    }
    return msg, meta


def plain_body(msg: EmailMessage) -> str:
    """Return the text/plain body of ``msg``.

    ``EmailMessage.get_content()`` raises ``KeyError`` on a multipart message
    (which is what we have once report files are attached), so reach for the
    text/plain part explicitly when multipart.
    """
    if msg.is_multipart():
        part = msg.get_body(preferencelist=("plain",))
        return part.get_content() if part is not None else ""
    return msg.get_content()


# --------------------------------------------------------------------------- #
# Artifact persistence (dry-run preview)
# --------------------------------------------------------------------------- #
def write_artifacts(out_dir: Path, msg: EmailMessage, meta: dict[str, Any]) -> dict[str, str]:
    """Write ``disclosure-email.eml`` + ``disclosure-email.json`` to ``out_dir``."""
    eml_path = out_dir / "disclosure-email.eml"
    json_path = out_dir / "disclosure-email.json"
    try:
        eml_path.write_bytes(bytes(msg))
    except OSError:
        pass
    try:
        from core.json import save_json

        save_json(json_path, meta)
    except Exception:  # noqa: BLE001
        pass
    return {"eml": str(eml_path), "json": str(json_path)}
