"""Root-level pytest config.

libexec/ scripts now refuse to run without one of CLAUDECODE,
_MANTISHACK_TRUSTED, or MANTISHACK_DIR set in the environment (see the
trust-marker block at the top of each script). Several test suites
subprocess-invoke libexec scripts and inherit env from this test
runner — set the marker once here so every test is treated as a
trusted caller by default.

Tests that exercise the refusal path explicitly pop the marker from
the subprocess env when they spawn the wrapper.

`MANTISHACK_DIR` is also set here. Modules that follow the project's
"hard lookup, no fallbacks" path-safety rule (CLAUDE.md, e.g.
packages/recon/agent.py) read `os.environ["MANTISHACK_DIR"]` at
import time and KeyError if unset. CI runners and developer
shells that don't pre-export MANTISHACK_DIR would otherwise fail
test collection. Set it here to the project root (the directory
this conftest.py lives in) so the import-time lookup succeeds
in every test invocation, while production code paths still
require operators to set it explicitly per the launcher rule.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("_MANTISHACK_TRUSTED", "1")

# Force MANTISHACK_DIR to point at THIS worktree, not whatever the
# developer's login shell exports. ``setdefault`` is a no-op when the
# env var is already set, so a developer with multiple checkouts who
# exports ``MANTISHACK_DIR=/home/me/other-mantishack`` in their profile would
# silently run the test SUBPROCESS bootstrap (e.g.
# core/sandbox/tests/test_fork_safe_warn*.py) against the wrong tree
# — failing with "No module named core.sandbox._fork_safe_warn" when
# the module is new on this branch but missing from the other tree.
#
# CI environments that pre-export MANTISHACK_DIR correctly are unaffected
# (the path already matches). Mismatch surfaces as a one-line warning
# on stderr so the developer notices the divergence.
_conftest_dir = str(Path(__file__).resolve().parent)
_existing = os.environ.get("MANTISHACK_DIR")
if _existing and _existing != _conftest_dir:
    print(
        f"conftest: overriding MANTISHACK_DIR ({_existing!r} → {_conftest_dir!r}) "
        f"to match the worktree this test run lives in",
        file=sys.stderr,
    )
os.environ["MANTISHACK_DIR"] = _conftest_dir


# ---------------------------------------------------------------------------
# Default-tier slow-test guard
# ---------------------------------------------------------------------------
#
# Preventive backstop for the "a default-tier test is slow because it
# does real I/O it should mock" class — real subprocess / network /
# time.sleep / sandbox setup that turns a 30ms unit test into a 30s one.
# faulthandler_timeout (set in tests.yml) catches a *hang*; this catches
# slow-but-finishes, the day it lands, instead of in a later --durations
# sweep.
#
# Activated ONLY when MANTISHACK_MAX_TEST_SECONDS is set — tests.yml sets it
# for the default-tier matrix; nightly.yml deliberately does NOT (its
# `-m "slow or integration"` tests are legitimately slow), and local
# `pytest` is unaffected. The guard FLAGS, it does not kill: every test
# still runs to completion; the session then fails at the end naming the
# offenders, so the signal is "this test got slow", not "killed mid-run".
#
# A genuinely-heavy test is not a bug — mark it @pytest.mark.slow (moves
# it to the nightly tier, out of this guard's scope).

_MAX_TEST_SECONDS = os.environ.get("MANTISHACK_MAX_TEST_SECONDS")
_slow_test_threshold = float(_MAX_TEST_SECONDS) if _MAX_TEST_SECONDS else None
_slow_test_overruns: "list[tuple[str, float]]" = []


def pytest_runtest_logreport(report):
    """Record any test whose CALL phase exceeds the threshold."""
    if _slow_test_threshold is None:
        return
    if report.when == "call" and report.duration > _slow_test_threshold:
        _slow_test_overruns.append((report.nodeid, report.duration))


def pytest_sessionfinish(session, exitstatus):
    """Fail an otherwise-green session if any test overran the threshold."""
    if _slow_test_threshold is None or not _slow_test_overruns:
        return
    if session.exitstatus == 0:
        session.exitstatus = 1


def pytest_terminal_summary(terminalreporter):
    if _slow_test_threshold is None or not _slow_test_overruns:
        return
    tr = terminalreporter
    tr.section("default-tier slow-test guard FAILED", red=True, bold=True)
    tr.write_line(
        f"{len(_slow_test_overruns)} test(s) exceeded "
        f"MANTISHACK_MAX_TEST_SECONDS={_slow_test_threshold}s in the default tier."
    )
    tr.write_line(
        "A default-tier test this slow is almost always real I/O that "
        "should be mocked (subprocess / network / time.sleep / sandbox "
        "setup). Fix it — or, if the cost is genuine, mark it "
        "@pytest.mark.slow so it runs in the nightly tier instead.",
    )
    for nodeid, dur in sorted(_slow_test_overruns, key=lambda x: -x[1]):
        tr.write_line(f"  {dur:7.1f}s  {nodeid}")


# ---------------------------------------------------------------------------
# Auth + logging audit fixtures (mantishack fork extension)
# ---------------------------------------------------------------------------
#
# The /mantis-auth-audit slash command runs Semgrep rules tagged
# `mantis_capability: auth-audit` against the target codebase. The pytest
# fixtures below let test authors *assert* the same things at runtime —
# specifically, that auth-sensitive code paths emit an audit log line and
# do not leak credentials (JWT / cookie / session_id) into log records.
#
# Opt in by marking a test `@pytest.mark.auth_audit` and requesting the
# `assert_audit_log_emitted` fixture. The fixture captures logging via
# pytest's stock `caplog`, then on test teardown verifies:
#   - at least one INFO/WARN log record was emitted
#   - no record contains a raw JWT / cookie / session-id substring
#
# Tests that should run cookie / JWT flows without the audit assertion
# (e.g. negative tests) simply don't request the fixture.

import re
import logging

_CREDENTIAL_LEAK_PATTERNS = (
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    re.compile(r"\bsession[_-]?id\s*=\s*[A-Za-z0-9]{16,}", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}", re.IGNORECASE),
)


def pytest_configure(config):
    """Register mantishack-specific markers so `-m auth_audit` works."""
    config.addinivalue_line(
        "markers",
        "auth_audit: marks a test as exercising an auth-sensitive code path; "
        "use with the `assert_audit_log_emitted` fixture to verify the "
        "code under test emits an audit log and does not leak credentials.",
    )


try:  # pytest is an import-time hard dep of conftest, but guard for safety
    import pytest

    @pytest.fixture
    def assert_audit_log_emitted(caplog):
        """Fail the test if no audit log line was emitted, or if any log
        record contains a raw JWT / session id / bearer token.

        Usage::

            @pytest.mark.auth_audit
            def test_login_logs_failure(client, assert_audit_log_emitted):
                client.post("/login", data={"u": "alice", "p": "wrong"})
                # teardown asserts a log line was emitted and no credential
                # leaked into the log records
        """
        caplog.set_level(logging.INFO)
        yield caplog
        # post-test assertions
        emitted = [r for r in caplog.records if r.levelno >= logging.INFO]
        assert emitted, (
            "auth-audit: test exercised an auth-sensitive path but emitted "
            "no INFO/WARN/ERROR log records. Add an audit-log line on the "
            "auth-success/-failure branch (see "
            "engine/semgrep/rules/logging/missing-auth-audit.yaml)."
        )
        leaks = []
        for record in caplog.records:
            text = record.getMessage()
            for pat in _CREDENTIAL_LEAK_PATTERNS:
                if pat.search(text):
                    leaks.append((record.name, pat.pattern, text[:80]))
        assert not leaks, (
            "auth-audit: log records contain raw credentials. Mask before "
            "logging (e.g. `tok[:4] + '***'`). Leaks: "
            + "; ".join(f"{name}: {patt} -> {snip!r}" for name, patt, snip in leaks)
        )

except ImportError:  # pragma: no cover
    pass
