"""Responsible-disclosure email for MANTISHACK (`/mantis-fullsend`).

Locates a finished run's report, discovers a security/contact email for the
target (RFC 9116 ``security.txt`` first, then page scraping, then ask), composes
a good-faith disclosure email, and — only when ``--send`` is passed and SMTP
credentials are present in the environment — sends it via Gmail SMTP.

Submodules:
  contact  — recipient discovery (security.txt -> scrape -> ask)
  compose  — locate report, build subject/body/EmailMessage, write artifacts
  send     — SMTP delivery using MANTIS_SMTP_USER / MANTIS_SMTP_APP_PASSWORD
  cli      — argument parsing + orchestration (the ``fullsend`` mode entry point)
"""
from __future__ import annotations

__all__ = ["contact", "compose", "send", "cli"]
