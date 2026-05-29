---
description: Email a finished report to the target's security contact (auto-discovered) via SMTP
---

# /mantis-fullsend — Send a disclosure report by email

Take a finished MANTISHACK run's report, find the target's security contact, and
deliver the report by email. By default it **prepares a dry-run draft** (writes a
previewable `.eml` and prints recipient/subject/body); adding `--send` actually
sends it over SMTP.

> Sending findings to a third party is an **irreversible, outward-facing action**
> and your responsibility. Only do this for targets you are authorized to test
> and disclose to. Per the project safety rules, the `--send` step is a dangerous
> operation: **confirm with the user before running it.**

## Usage

```
/mantis-fullsend [target] [--to <email>] [--cc <email>] [--out <run-dir>]
                 [--subject <text>] [--no-attach] [--max-body-bytes <N>] [--send]
```

- `target` — host/URL (e.g. `example.com`) used to discover the security contact
  and label the subject. May be a local path (falls back to repo metadata). If
  omitted, the target hint is read from the report JSON when present.
- `--to <email>` — recipient; **skips auto-discovery**.
- `--cc <email>` — CC recipient (repeatable).
- `--out <run-dir>` — run directory with the report (default: newest run that
  has a report, in the active project or `out/`).
- `--subject <text>` — override the email subject.
- `--no-attach` — inline preview only; do not attach report files.
- `--max-body-bytes <N>` — cap the report text inlined in the body (default 60000;
  the full report is attached regardless).
- `--send` — actually send via SMTP (otherwise dry run).

## Requirements

- A finished run with a report. `fullsend` finds, in order:
  `report.md` / `agentic-report.md` / `validation-report.md`, then
  `findings.json` / `web_scan_report.json` / `mantishack_agentic_report.json` /
  `orchestrated_report.json` / `_report/findings.json`. Produce one first with
  `/mantis-web`, `/mantis-scan`, or `/mantis-agentic`.
- For `--send`, SMTP credentials in the environment (Gmail submission by default):
  - `MANTIS_SMTP_USER` — your Gmail address / submission user (also the From).
  - `MANTIS_SMTP_APP_PASSWORD` — a Gmail **App Password**
    (https://myaccount.google.com/apppasswords), not your account password.
  - Optional: `MANTIS_SMTP_HOST` (default `smtp.gmail.com`),
    `MANTIS_SMTP_PORT` (default `587`), `MANTIS_SMTP_FROM`.

## Execution

This command is a `mantishack.py` mode — run it verbatim (no pipes/redirects):

1. **Resolve the target** using the DEFAULT TARGET DIRECTORY order
   (active project → `$MANTISHACK_CALLER_DIR` → ask). For disclosure the target
   is normally the live host/URL whose security contact we want.

2. **Dry run first** (always, even when the user wants to send):

   ```bash
   python3 mantishack.py fullsend <resolved_target>
   ```

   Add `--to`, `--cc`, `--out`, `--subject` as the user supplied. This locates
   the report, discovers the recipient, and writes
   `disclosure-email.eml` + `disclosure-email.json` into the run dir. It prints
   `DRY_RUN=1` and, if no recipient was found, `NEED_RECIPIENT=1`.

3. **Confirm with the user.** Show the recipient and **how it was found**
   (`source: security.txt` is the trusted channel; `source: scrape:*` is
   best-effort — call that out and ask the user to confirm the address), plus the
   subject and a short body preview.
   - If `NEED_RECIPIENT=1`, ask the user for the email and re-run step 2 with
     `--to <email>`.

4. **Send only after explicit user confirmation:**

   ```bash
   python3 mantishack.py fullsend <resolved_target> --to <confirmed_email> --send
   ```

   On success it prints `SENT=1` and writes `disclosure-sent.json`. Exit codes:
   `2` = no recipient, `3` = missing SMTP creds, `4` = send failed. If creds are
   missing, tell the user which env vars to set (see Requirements).

5. **Report the outcome** plainly — to whom it was sent, from which account, and
   where the receipt/`.eml` live.

## Notes

- Recipient discovery order: `--to` → `/.well-known/security.txt` (RFC 9116) →
  `/security.txt` → scrape `/security`, `/contact`, home, `/about` → (local
  target) `SECURITY.md` / in-repo `security.txt` / `package.json` author → ask.
- Only the operator-named target host is fetched (http/https, timeout + size
  cap); links inside scraped pages are never followed.
- The cover note states the findings are good-faith, automated (may contain
  false positives), and non-exploitative. Keep disclosure scoped and authorized.
