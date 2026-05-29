"""SMTP delivery for `/mantis-fullsend`.

Sends a composed ``EmailMessage`` via SMTP using credentials taken **only** from
the environment — never hard-coded, never read from the scanned target. Defaults
to Gmail submission (``smtp.gmail.com:587`` STARTTLS); use a Gmail App Password,
not the account password.

Environment:
  MANTIS_SMTP_USER          submission username / From address (required)
  MANTIS_SMTP_APP_PASSWORD  app password / submission password (required)
  MANTIS_SMTP_HOST          override host (default ``smtp.gmail.com``)
  MANTIS_SMTP_PORT          override port (default ``587``)
  MANTIS_SMTP_FROM          override From address (default = MANTIS_SMTP_USER)

This module performs the irreversible outward action. The CLI gates it behind an
explicit ``--send`` flag and a recipient; the slash command confirms with the
operator first.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

DEFAULT_HOST = "smtp.gmail.com"
DEFAULT_PORT = 587

ENV_USER = "MANTIS_SMTP_USER"
ENV_PASSWORD = "MANTIS_SMTP_APP_PASSWORD"
ENV_HOST = "MANTIS_SMTP_HOST"
ENV_PORT = "MANTIS_SMTP_PORT"
ENV_FROM = "MANTIS_SMTP_FROM"


class SMTPConfigError(RuntimeError):
    """Raised when required SMTP credentials are missing/invalid."""


@dataclass
class SMTPConfig:
    user: str
    password: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    sender: str = ""

    @property
    def from_addr(self) -> str:
        return self.sender or self.user


def load_config(env: dict | None = None) -> SMTPConfig:
    """Build an :class:`SMTPConfig` from the environment.

    Raises :class:`SMTPConfigError` if user or password is missing.
    """
    env = env if env is not None else os.environ
    user = (env.get(ENV_USER) or "").strip()
    password = env.get(ENV_PASSWORD) or ""
    if not user or not password:
        missing = [
            name for name, val in ((ENV_USER, user), (ENV_PASSWORD, password)) if not val
        ]
        raise SMTPConfigError(
            "SMTP credentials missing: set "
            + " and ".join(missing)
            + ". Use a Gmail App Password (https://myaccount.google.com/apppasswords), "
            "not your account password."
        )
    host = (env.get(ENV_HOST) or DEFAULT_HOST).strip()
    port_raw = (env.get(ENV_PORT) or str(DEFAULT_PORT)).strip()
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise SMTPConfigError(f"{ENV_PORT}={port_raw!r} is not an integer") from exc
    sender = (env.get(ENV_FROM) or "").strip()
    return SMTPConfig(user=user, password=password, host=host, port=port, sender=sender)


def credentials_present(env: dict | None = None) -> bool:
    """True if both required SMTP env vars are set (no validation of values)."""
    env = env if env is not None else os.environ
    return bool((env.get(ENV_USER) or "").strip() and (env.get(ENV_PASSWORD) or ""))


def send_email(msg: EmailMessage, config: SMTPConfig, *, timeout: int = 30) -> dict:
    """Send ``msg`` via SMTP STARTTLS. Returns a receipt dict.

    Ensures the message carries a ``From`` matching the authenticated sender
    (Gmail requires it anyway). Raises ``smtplib.SMTPException`` / ``OSError``
    on failure (the CLI translates these to an exit code).
    """
    if not msg["From"]:
        msg["From"] = config.from_addr
    context = ssl.create_default_context()
    with smtplib.SMTP(config.host, config.port, timeout=timeout) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(config.user, config.password)
        # send_message honours To/Cc/Bcc headers for envelope recipients.
        server.send_message(msg)
    to = [a.strip() for a in (msg["To"] or "").split(",") if a.strip()]
    cc = [a.strip() for a in (msg["Cc"] or "").split(",") if a.strip()]
    return {
        "sent": True,
        "host": config.host,
        "port": config.port,
        "from": msg["From"],
        "to": to,
        "cc": cc,
        "subject": msg["Subject"],
    }
