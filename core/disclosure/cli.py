"""`/mantis-fullsend` CLI — orchestrate disclosure email preparation and send.

Without ``--send`` this is a dry run: it locates the report, discovers a
recipient, composes the email, writes ``disclosure-email.eml`` /
``disclosure-email.json`` into the run dir, prints a preview, and exits 0.

With ``--send`` it additionally requires SMTP credentials in the environment and
a resolved recipient, then sends via :mod:`core.disclosure.send`.

Exit codes:
  0  success (dry run prepared, or email sent)
  1  no report found to disclose
  2  --send but no recipient could be resolved (pass --to)
  3  --send but SMTP credentials are missing
  4  --send but the SMTP delivery failed
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import compose, contact, send


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mantishack.py fullsend",
        description="Prepare (and optionally send) a responsible-disclosure "
        "email from a MANTISHACK report.",
    )
    p.add_argument(
        "target",
        nargs="?",
        default="",
        help="Target host/URL (recipient discovery + subject) or local path",
    )
    p.add_argument("--to", help="Recipient email (skips auto-discovery)")
    p.add_argument(
        "--cc", action="append", default=[], help="CC recipient (repeatable)"
    )
    p.add_argument(
        "--out",
        help="Run dir holding the report (default: newest run with a report)",
    )
    p.add_argument("--subject", help="Override the email subject")
    p.add_argument(
        "--max-body-bytes",
        type=int,
        dest="max_body_bytes",
        default=compose.DEFAULT_MAX_BODY_BYTES,
        help="Max bytes of report inlined into the body (default: %(default)s)",
    )
    p.add_argument(
        "--no-attach",
        action="store_true",
        help="Do not attach report files (inline preview only)",
    )
    p.add_argument(
        "--send",
        action="store_true",
        help="Actually send via SMTP (requires MANTIS_SMTP_USER / "
        "MANTIS_SMTP_APP_PASSWORD). Without this flag, prepares a dry-run draft.",
    )
    return p


def _print_preview(meta: dict, recipient: contact.DiscoveryResult) -> None:
    print("[mantishack] fullsend — disclosure email prepared")
    print(f"  report dir : {meta['report_dir']}")
    print(
        f"  findings   : {meta['findings_count']} "
        f"({meta['severity_counts'] or 'n/a'})"
    )
    if meta["to"]:
        print(f"  recipient  : {', '.join(meta['to'])}  (source: {recipient.source})")
    else:
        print("  recipient  : NOT FOUND — pass --to <email>")
    if len(recipient.candidates) > 1:
        print(f"  candidates : {', '.join(recipient.candidates)}")
    for note in recipient.notes:
        print(f"  note       : {note}")
    if meta["cc"]:
        print(f"  cc         : {', '.join(meta['cc'])}")
    print(f"  subject    : {meta['subject']}")
    if meta["attachments"]:
        print(f"  attached   : {', '.join(meta['attachments'])}")
    if meta["truncated"]:
        print("  body       : inline preview truncated")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 1. Locate the report to disclose.
    location = compose.locate_report(args.out)
    if location is None or not location.has_report:
        where = args.out or "the newest run dir"
        print(
            f"[mantishack] fullsend: no report found in {where}. "
            "Run a scan first (/mantis-web, /mantis-scan, or /mantis-agentic), "
            "or pass --out <run-dir>.",
            file=sys.stderr,
        )
        return 1

    # 2. Human label for the target/host (CLI target > report's target hint).
    target = args.target or location.target or ""
    host = contact.normalize_host(target)
    host_label = (
        host.split("://", 1)[-1] if host else (target or location.out_dir.name)
    )

    # 3. Discover the recipient (unless --to overrides).
    recipient = contact.discover_recipient(target, to_override=args.to)
    recipients = [recipient.email] if recipient.email else []

    # 4. Sender (only needed/known when sending; for dry run use env or label).
    sender = ""
    if send.credentials_present():
        try:
            sender = send.load_config().from_addr
        except send.SMTPConfigError:
            sender = ""

    # 5. Compose the email.
    msg, meta = compose.build_email(
        sender=sender,
        host_label=host_label,
        location=location,
        recipients=recipients,
        cc=list(args.cc or []),
        subject=args.subject,
        max_body_bytes=args.max_body_bytes,
        attach=not args.no_attach,
    )

    # 6. Persist artifacts (dry-run preview lives next to the report).
    artifacts = compose.write_artifacts(location.out_dir, msg, meta)

    _print_preview(meta, recipient)
    print(f"  eml        : {artifacts['eml']}")

    # 7. Send or stop.
    if not args.send:
        print("\n[mantishack] dry run — no email sent. Review the .eml above.")
        print("  To send: re-run with --send and SMTP env vars set.")
        if not recipients:
            print("NEED_RECIPIENT=1")
        print("DRY_RUN=1")
        return 0

    # --- send path ---
    if not recipients:
        print(
            "\n[mantishack] fullsend: --send requires a recipient but none was "
            "resolved. Pass --to <email>.",
            file=sys.stderr,
        )
        print("NEED_RECIPIENT=1")
        return 2

    try:
        config = send.load_config()
    except send.SMTPConfigError as exc:
        print(f"\n[mantishack] fullsend: {exc}", file=sys.stderr)
        print("NEED_SMTP_CREDS=1")
        return 3

    # Ensure the From matches the authenticated account.
    del msg["From"]
    msg["From"] = config.from_addr

    try:
        receipt = send.send_email(msg, config)
    except Exception as exc:  # noqa: BLE001 - SMTP/OSError -> exit 4
        print(
            f"\n[mantishack] fullsend: send failed: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 4

    # Persist a send receipt next to the report.
    try:
        from core.json import save_json

        save_json(Path(location.out_dir) / "disclosure-sent.json", receipt)
    except Exception:  # noqa: BLE001
        pass

    print(
        f"\n[mantishack] SENT to {', '.join(receipt['to'])} "
        f"via {receipt['host']}:{receipt['port']} (from {receipt['from']})"
    )
    print("SENT=1")
    return 0
