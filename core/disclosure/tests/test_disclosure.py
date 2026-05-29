"""Offline tests for the disclosure package (contact / compose / send / cli).

Written with stdlib ``unittest`` so they run without pytest installed
(``python -m unittest core.disclosure.tests.test_disclosure``) while still being
collected by the repo's ``pytest core packages`` CI (pytest discovers
``unittest.TestCase`` classes natively). No network and no real SMTP: the
fetcher and SMTP layer are injected / patched.
"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from email.message import EmailMessage
from pathlib import Path
from unittest import mock

from core.disclosure import cli as disclosure_cli
from core.disclosure import compose, contact, send


# --------------------------------------------------------------------------- #
# contact: security.txt parsing + ranking
# --------------------------------------------------------------------------- #
class SecurityTxtTests(unittest.TestCase):
    def test_mailto_and_bare(self):
        body = (
            "# policy\n"
            "Contact: mailto:security@example.com\n"
            "Contact: https://example.com/report\n"
            "Contact: abuse@example.com\n"
            "Expires: 2030-01-01T00:00:00Z\n"
        )
        emails = contact.parse_security_txt(body)
        self.assertIn("security@example.com", emails)
        self.assertIn("abuse@example.com", emails)
        self.assertEqual(emails[0], "security@example.com")  # security@ ranks first

    def test_ignores_comments(self):
        self.assertEqual(
            contact.parse_security_txt("# Contact: x@y.com\nPolicy: z\n"), []
        )


class HtmlExtractionTests(unittest.TestCase):
    def test_filters_assets_and_junk(self):
        html = (
            '<a href="mailto:security@site.test">mail</a>'
            '<img src="logo@2x.png">'
            "<p>also support@site.test and noise@sentry.io</p>"
        )
        emails = contact.extract_emails_from_html(html)
        self.assertIn("security@site.test", emails)
        self.assertIn("support@site.test", emails)
        self.assertNotIn("noise@sentry.io", emails)  # junk domain dropped
        self.assertFalse(any(e.endswith(".png") for e in emails))
        self.assertEqual(emails[0], "security@site.test")


class NormalizeHostTests(unittest.TestCase):
    def test_cases(self):
        cases = {
            "example.com": "https://example.com",
            "http://example.com/a/b": "http://example.com",
            "https://x.com/p?q=1": "https://x.com",
            "": None,
            "not a host": None,
            "nohost": None,
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(contact.normalize_host(target), expected)


# --------------------------------------------------------------------------- #
# contact: discovery order
# --------------------------------------------------------------------------- #
class DiscoverRecipientTests(unittest.TestCase):
    def test_override_short_circuits(self):
        res = contact.discover_recipient(
            "example.com", to_override="me@you.test", fetcher=lambda *a, **k: None
        )
        self.assertEqual(res.email, "me@you.test")
        self.assertEqual(res.source, "override")

    def test_security_txt_hit(self):
        def fetcher(url, timeout=10):
            if url.endswith("/.well-known/security.txt"):
                return "Contact: mailto:security@example.com\n"
            return None

        res = contact.discover_recipient("example.com", fetcher=fetcher)
        self.assertEqual(res.email, "security@example.com")
        self.assertEqual(res.source, "security.txt")

    def test_scrape_fallback(self):
        def fetcher(url, timeout=10):
            if url.endswith("security.txt"):
                return None
            if url.endswith("/security"):
                return '<a href="mailto:psirt@example.com">report</a>'
            return None

        res = contact.discover_recipient("https://example.com", fetcher=fetcher)
        self.assertEqual(res.email, "psirt@example.com")
        self.assertEqual(res.source, "scrape:/security")

    def test_none_found(self):
        res = contact.discover_recipient("example.com", fetcher=lambda *a, **k: None)
        self.assertIsNone(res.email)
        self.assertEqual(res.source, "none")
        self.assertTrue(res.notes)

    def test_repo_security_md(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "SECURITY.md").write_text("Report to security@repo.test please.")
            res = contact.discover_recipient(d)
            self.assertEqual(res.email, "security@repo.test")
            self.assertEqual(res.source, "repo:SECURITY.md")

    def test_repo_package_json(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "package.json").write_text(
                json.dumps({"author": {"email": "dev@repo.test"}})
            )
            res = contact.discover_recipient(d)
            self.assertEqual(res.email, "dev@repo.test")
            self.assertEqual(res.source, "repo:package.json")


# --------------------------------------------------------------------------- #
# compose helpers
# --------------------------------------------------------------------------- #
def _make_agentic_run(d: Path):
    (d / "report.md").write_text("# Report\n\nreflected XSS in search\n")
    (d / "findings.json").write_text(
        json.dumps(
            {"findings": [{"severity": "High"}, {"severity": "high"}, {"severity": "low"}]}
        )
    )


class ComposeLocateTests(unittest.TestCase):
    def test_agentic_report_and_summary(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            _make_agentic_run(dd)
            loc = compose.locate_report(dd)
            self.assertIsNotNone(loc)
            self.assertTrue(loc.has_report)
            self.assertEqual(loc.report_md.name, "report.md")
            counts = compose.severity_summary(compose.load_findings(loc.findings_json))
            self.assertEqual(counts, {"high": 2, "low": 1})

    def test_web_report(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            (dd / "web_scan_report.json").write_text(
                json.dumps(
                    {
                        "target": "https://www.example.com",
                        "findings": [{"severity": "medium"}],
                        "total_vulnerabilities": 1,
                    }
                )
            )
            loc = compose.locate_report(dd)
            self.assertTrue(loc.has_report)
            self.assertEqual(loc.findings_json.name, "web_scan_report.json")
            self.assertEqual(loc.target, "https://www.example.com")

    def test_project_report_subdir(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            rep = dd / "_report"
            rep.mkdir()
            (rep / "findings.json").write_text(
                json.dumps({"findings": [{"severity": "critical"}], "sca_findings": []})
            )
            loc = compose.locate_report(dd)
            self.assertTrue(loc.has_report)
            self.assertEqual(loc.findings_json, rep / "findings.json")

    def test_missing(self):
        with tempfile.TemporaryDirectory() as d:
            loc = compose.locate_report(Path(d))
            self.assertIsNotNone(loc)
            self.assertFalse(loc.has_report)


class ComposeEmailTests(unittest.TestCase):
    def test_build_email_attaches_and_summarises(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            _make_agentic_run(dd)
            loc = compose.locate_report(dd)
            msg, meta = compose.build_email(
                sender="me@gmail.com",
                host_label="example.com",
                location=loc,
                recipients=["security@example.com"],
                cc=["cc@example.com"],
            )
            self.assertIsInstance(msg, EmailMessage)
            self.assertEqual(msg["To"], "security@example.com")
            self.assertEqual(msg["Cc"], "cc@example.com")
            self.assertIn("example.com", msg["Subject"])
            self.assertEqual(meta["findings_count"], 3)
            self.assertEqual(set(meta["attachments"]), {"report.md", "findings.json"})
            body = compose.plain_body(msg)
            self.assertIn("good-faith", body)
            self.assertIn("| High | 2 |", body)

    def test_build_body_truncates(self):
        body, truncated = compose.build_body(
            "example.com",
            report_md="x" * 1000,
            counts={"high": 1},
            report_path=Path("/tmp/report.md"),
            attached=True,
            max_body_bytes=100,
        )
        self.assertTrue(truncated)
        self.assertIn("truncated", body.lower())
        self.assertIn("example.com", body)

    def test_write_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            _make_agentic_run(dd)
            loc = compose.locate_report(dd)
            msg, meta = compose.build_email(
                sender="me@gmail.com",
                host_label="example.com",
                location=loc,
                recipients=["security@example.com"],
            )
            paths = compose.write_artifacts(dd, msg, meta)
            self.assertTrue(Path(paths["eml"]).is_file())
            reloaded = json.loads(Path(paths["json"]).read_text())
            self.assertEqual(reloaded["to"], ["security@example.com"])


# --------------------------------------------------------------------------- #
# send: config loading
# --------------------------------------------------------------------------- #
class SendConfigTests(unittest.TestCase):
    def test_missing_raises(self):
        with self.assertRaises(send.SMTPConfigError):
            send.load_config(env={})

    def test_defaults_gmail(self):
        cfg = send.load_config(
            env={"MANTIS_SMTP_USER": "me@gmail.com", "MANTIS_SMTP_APP_PASSWORD": "pw"}
        )
        self.assertEqual(cfg.host, "smtp.gmail.com")
        self.assertEqual(cfg.port, 587)
        self.assertEqual(cfg.from_addr, "me@gmail.com")

    def test_overrides(self):
        cfg = send.load_config(
            env={
                "MANTIS_SMTP_USER": "u",
                "MANTIS_SMTP_APP_PASSWORD": "pw",
                "MANTIS_SMTP_HOST": "smtp.example.com",
                "MANTIS_SMTP_PORT": "2525",
                "MANTIS_SMTP_FROM": "noreply@example.com",
            }
        )
        self.assertEqual(cfg.host, "smtp.example.com")
        self.assertEqual(cfg.port, 2525)
        self.assertEqual(cfg.from_addr, "noreply@example.com")

    def test_bad_port_raises(self):
        with self.assertRaises(send.SMTPConfigError):
            send.load_config(
                env={
                    "MANTIS_SMTP_USER": "u",
                    "MANTIS_SMTP_APP_PASSWORD": "pw",
                    "MANTIS_SMTP_PORT": "not-an-int",
                }
            )

    def test_credentials_present(self):
        self.assertFalse(send.credentials_present(env={}))
        self.assertTrue(
            send.credentials_present(
                env={"MANTIS_SMTP_USER": "u", "MANTIS_SMTP_APP_PASSWORD": "p"}
            )
        )


# --------------------------------------------------------------------------- #
# cli: dry run + send path (mocked)
# --------------------------------------------------------------------------- #
class CliTests(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = disclosure_cli.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_dry_run_writes_eml(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            _make_agentic_run(dd)
            rc, out, _ = self._run(
                ["example.com", "--to", "security@example.com", "--out", str(dd)]
            )
            self.assertEqual(rc, 0)
            self.assertIn("DRY_RUN=1", out)
            self.assertTrue((dd / "disclosure-email.eml").is_file())

    def test_missing_report_returns_1(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _, _ = self._run(["example.com", "--out", str(Path(d) / "nope")])
            self.assertEqual(rc, 1)

    def test_send_without_recipient_returns_2(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            _make_agentic_run(dd)
            with mock.patch.object(
                contact, "discover_recipient",
                return_value=contact.DiscoveryResult(None, "none", [], ["not found"]),
            ), mock.patch.object(send, "credentials_present", return_value=True):
                rc, _, _ = self._run(["example.com", "--out", str(dd), "--send"])
            self.assertEqual(rc, 2)

    def test_send_without_creds_returns_3(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            _make_agentic_run(dd)

            def _raise(env=None):
                raise send.SMTPConfigError("missing")

            with mock.patch.object(
                contact, "discover_recipient",
                return_value=contact.DiscoveryResult(
                    "security@example.com", "override", ["security@example.com"], []
                ),
            ), mock.patch.object(send, "credentials_present", return_value=False), \
                    mock.patch.object(send, "load_config", side_effect=_raise):
                rc, _, _ = self._run(
                    ["example.com", "--to", "security@example.com",
                     "--out", str(dd), "--send"]
                )
            self.assertEqual(rc, 3)

    def test_send_failure_returns_4(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            _make_agentic_run(dd)

            def _boom(msg, config, timeout=30):
                raise OSError("connection refused")

            with mock.patch.object(
                contact, "discover_recipient",
                return_value=contact.DiscoveryResult(
                    "security@example.com", "override", ["security@example.com"], []
                ),
            ), mock.patch.object(send, "credentials_present", return_value=True), \
                    mock.patch.object(
                        send, "load_config",
                        return_value=send.SMTPConfig(user="me@gmail.com", password="pw"),
                    ), mock.patch.object(send, "send_email", side_effect=_boom):
                rc, _, _ = self._run(
                    ["example.com", "--to", "security@example.com",
                     "--out", str(dd), "--send"]
                )
            self.assertEqual(rc, 4)

    def test_send_success(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            _make_agentic_run(dd)
            captured = {}

            def fake_send(msg, config, timeout=30):
                captured["to"] = msg["To"]
                return {
                    "sent": True, "host": config.host, "port": config.port,
                    "from": config.from_addr, "to": [msg["To"]], "cc": [],
                    "subject": msg["Subject"],
                }

            with mock.patch.object(
                contact, "discover_recipient",
                return_value=contact.DiscoveryResult(
                    "security@example.com", "override", ["security@example.com"], []
                ),
            ), mock.patch.object(send, "credentials_present", return_value=True), \
                    mock.patch.object(
                        send, "load_config",
                        return_value=send.SMTPConfig(user="me@gmail.com", password="pw"),
                    ), mock.patch.object(send, "send_email", side_effect=fake_send):
                rc, out, _ = self._run(
                    ["example.com", "--to", "security@example.com",
                     "--out", str(dd), "--send"]
                )
            self.assertEqual(rc, 0)
            self.assertIn("SENT=1", out)
            self.assertEqual(captured["to"], "security@example.com")
            self.assertTrue((dd / "disclosure-sent.json").is_file())


if __name__ == "__main__":
    unittest.main()
