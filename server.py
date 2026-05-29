#!/usr/bin/env python3
"""Mantishack local scan server.

Runs a small web server on your machine (default http://127.0.0.1:8080) that:

  * serves a single-page scan UI (`app.html`) with live loading screens, and
  * exposes a tiny async scan API the UI drives.

A visitor pastes a link, a NEW scan session starts (its own scan_id + output
dir), the Mantishack engine runs in a background thread, real progress streams
into the loading screen, and the parsed report appears when done.

Protocol
--------
    POST /scan        {"url": "...", "type": "web"}            -> {"scan_id"}
    POST /scan        {"repo": "https://github.com/u/r"}       -> {"scan_id"}
    GET  /scan/<id>   -> {status, current_step, progress, findings, target, error}
    GET  /            -> the scan UI (app.html)
    GET  /health      -> {ok, engine, python}

Run it
------
    cd ~/Downloads/mantishack
    python3 server.py
    # open http://127.0.0.1:8080

Env overrides
-------------
    MANTISHACK_SERVER_HOST   bind host    (default 127.0.0.1 — local only)
    MANTISHACK_SERVER_PORT   bind port    (default 8080)
    MANTISHACK_PYTHON        engine python (default: ./.venv/bin/python if present)
    MANTISHACK_SCAN_TIMEOUT  per-scan cap, seconds (default 900)

Safety: binds to localhost only by default. The engine runs against targets the
operator submits on their own machine. Repo scan accepts only http(s) git URLs,
clones shallow into a temp dir with a sanitised env + timeout, then deletes it.
All subprocess calls use list args (no shell).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ENGINE_DIR = Path(__file__).resolve().parent
HOST = os.environ.get("MANTISHACK_SERVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("MANTISHACK_SERVER_PORT", "8080"))
SCAN_TIMEOUT = int(os.environ.get("MANTISHACK_SCAN_TIMEOUT", "900"))
MAX_BODY_BYTES = 64 * 1024
MAX_ACTIVE_JOBS = 4


def _engine_python() -> str:
    """Pick the interpreter that runs the engine (needs requests/bs4)."""
    env = os.environ.get("MANTISHACK_PYTHON")
    if env and Path(env).exists():
        return env
    venv = ENGINE_DIR / ".venv" / "bin" / "python"
    if venv.exists():
        return str(venv)
    return sys.executable


ENGINE_PY = _engine_python()

# --------------------------------------------------------------------------- #
# Job store
# --------------------------------------------------------------------------- #
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_ACTIVE = threading.Semaphore(MAX_ACTIVE_JOBS)


def _now() -> float:
    return time.time()


def _new_job(target: str, kind: str) -> str:
    scan_id = "scan_" + uuid.uuid4().hex[:12]
    with _JOBS_LOCK:
        _JOBS[scan_id] = {
            "scan_id": scan_id,
            "type": kind,
            "target": target,
            "status": "queued",
            "current_step": "Queued…",
            "progress": 5,
            "findings": [],
            "error": None,
            "started": _now(),
            "finished": None,
        }
    return scan_id


def _update(scan_id: str, **fields) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(scan_id)
        if job:
            job.update(fields)


def _get(scan_id: str) -> dict | None:
    with _JOBS_LOCK:
        job = _JOBS.get(scan_id)
        return dict(job) if job else None


# --------------------------------------------------------------------------- #
# Finding normalisation
# --------------------------------------------------------------------------- #
_SEV_MAP = {
    "critical": "critical", "high": "high", "error": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "warn": "medium",
    "low": "low", "info": "low", "informational": "low", "note": "low", "none": "low",
}


def _norm_sev(raw) -> str:
    return _SEV_MAP.get(str(raw or "").strip().lower(), "low")


def _normalize_findings(raw: list) -> list[dict]:
    out = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        out.append({
            "severity": _norm_sev(
                f.get("severity") or f.get("severity_assessment") or f.get("level")),
            "title": f.get("title") or f.get("vuln_type") or f.get("rule_id")
            or f.get("check_id") or "Finding",
            "file_path": f.get("file_path") or f.get("file") or "",
            "url": f.get("url") or f.get("target") or "",
            "line": f.get("line") or f.get("start_line"),
            "description": f.get("description") or f.get("message")
            or f.get("reasoning") or "",
        })
    return out


def _safe_env() -> dict:
    try:
        from core.config import MantishackConfig
        return MantishackConfig.get_safe_env(include_python_user_base=True)
    except Exception:
        env = dict(os.environ)
        for k in ("LD_PRELOAD", "LD_LIBRARY_PATH"):
            env.pop(k, None)
        return env


def _parse_sarif(path: Path) -> list[dict]:
    findings = []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, OSError):
        return findings
    for run in data.get("runs") or []:
        for res in run.get("results") or []:
            locs = res.get("locations") or [{}]
            first = locs[0] if isinstance(locs, list) and locs and isinstance(locs[0], dict) else {}
            phys = first.get("physicalLocation", {})
            findings.append({
                "rule_id": res.get("ruleId", "unknown"),
                "severity": _norm_sev(res.get("level", "warning")),
                "message": (res.get("message") or {}).get("text", ""),
                "file_path": phys.get("artifactLocation", {}).get("uri", ""),
                "line": phys.get("region", {}).get("startLine"),
            })
    return findings


# --------------------------------------------------------------------------- #
# Engine streaming
# --------------------------------------------------------------------------- #
_STEP_HINTS = [
    (re.compile(r"crawl|discover", re.I), "Crawling target & mapping attack surface…", 35),
    (re.compile(r"semgrep|static", re.I), "Running static analysis…", 45),
    (re.compile(r"codeql", re.I), "Running CodeQL dataflow analysis…", 55),
    (re.compile(r"fuzz|param|inject|xss|sqli|probe|check", re.I), "Probing for vulnerabilities…", 68),
    (re.compile(r"analy", re.I), "Analysing responses…", 82),
    (re.compile(r"report|writing|complete|saved", re.I), "Generating report…", 92),
]


def _stream_engine(cmd: list[str], scan_id: str) -> int:
    proc = subprocess.Popen(
        cmd, cwd=str(ENGINE_DIR), env=_safe_env(),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    deadline = _now() + SCAN_TIMEOUT
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.rstrip()
            if not line:
                continue
            for rx, step, pct in _STEP_HINTS:
                if rx.search(line):
                    cur = _get(scan_id) or {}
                    _update(scan_id, current_step=step,
                            progress=max(cur.get("progress", 0), pct))
                    break
            if _now() > deadline:
                proc.kill()
                _update(scan_id, current_step="Scan timed out — terminating…")
                break
    finally:
        rc = proc.wait()
    return rc


def _newest_run(prefix: str, since: float) -> Path | None:
    out = ENGINE_DIR / "out"
    if not out.is_dir():
        return None
    best, best_m = None, since - 5
    for d in out.iterdir():
        if not d.is_dir() or not d.name.startswith(prefix):
            continue
        try:
            m = d.stat().st_mtime
        except OSError:
            continue
        if m > best_m:
            best, best_m = d, m
    return best


def _run_web_scan(scan_id: str, url: str) -> None:
    _update(scan_id, status="running", current_step="Initializing scan engine…", progress=15)
    started = _now()
    rc = _stream_engine([ENGINE_PY, "mantishack.py", "web", "--url", url], scan_id)
    if rc != 0:
        _update(scan_id, status="failed", error=f"engine exited {rc}", finished=_now())
        return
    findings = []
    d = _newest_run("web_", started)
    if d:
        rep = d / "web_scan_report.json"
        if rep.is_file():
            try:
                data = json.loads(rep.read_text(encoding="utf-8-sig"))
                findings = _normalize_findings(data.get("findings") or [])
            except (ValueError, OSError):
                pass
    _update(scan_id, status="completed", current_step="Scan complete",
            progress=100, findings=findings, finished=_now())


_GIT_URL_RE = re.compile(r"^https?://[\w.\-]+/[\w.\-/]+?(?:\.git)?/?$")


def _run_repo_scan(scan_id: str, repo: str) -> None:
    if not _GIT_URL_RE.match(repo):
        _update(scan_id, status="failed",
                error="repo must be an http(s) git URL (e.g. https://github.com/user/repo)",
                finished=_now())
        return
    _update(scan_id, status="running", current_step="Cloning repository…", progress=15)
    tmp = Path(tempfile.mkdtemp(prefix="mantishack_repo_"))
    clone_dir = tmp / "repo"
    started = _now()
    try:
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", repo, str(clone_dir)],
            cwd=str(tmp), env=_safe_env(),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        if clone.returncode != 0:
            _update(scan_id, status="failed",
                    error="git clone failed: " + (clone.stdout or "")[-300:], finished=_now())
            return
        _update(scan_id, current_step="Running static analysis (Semgrep)…", progress=45)
        rc = _stream_engine([ENGINE_PY, "mantishack.py", "scan", "--repo", str(clone_dir)], scan_id)
        if rc != 0:
            _update(scan_id, status="failed", error=f"scan engine exited {rc}", finished=_now())
            return
        findings = []
        d = _newest_run("scan_", started)
        if d:
            for sarif in list(d.glob("*.sarif")) + list((d / "codeql").glob("*.sarif")):
                findings.extend(_parse_sarif(sarif))
            for sgj in d.glob("semgrep_*.json"):
                try:
                    sg = json.loads(sgj.read_text(encoding="utf-8-sig"))
                    for r in sg.get("results") or []:
                        findings.append({
                            "rule_id": r.get("check_id", "semgrep"),
                            "severity": _norm_sev((r.get("extra") or {}).get("severity")),
                            "message": (r.get("extra") or {}).get("message", ""),
                            "file_path": r.get("path", ""),
                            "line": (r.get("start") or {}).get("line"),
                        })
                except (ValueError, OSError):
                    continue
        _update(scan_id, status="completed", current_step="Scan complete",
                progress=100, findings=_normalize_findings(findings), finished=_now())
    except subprocess.TimeoutExpired:
        _update(scan_id, status="failed", error="clone timed out", finished=_now())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _worker(scan_id: str, kind: str, target: str) -> None:
    if not _ACTIVE.acquire(timeout=SCAN_TIMEOUT):
        _update(scan_id, status="failed", error="server busy, try again", finished=_now())
        return
    try:
        (_run_web_scan if kind == "web" else _run_repo_scan)(scan_id, target)
    except Exception as exc:  # noqa: BLE001 - never crash the worker thread
        _update(scan_id, status="failed", error=f"{type(exc).__name__}: {exc}", finished=_now())
    finally:
        _ACTIVE.release()


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "MantishackScan/1.0"

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("[server] %s\n" % (fmt % args))

    def do_POST(self):
        if self.path.rstrip("/") != "/scan":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(400, {"error": "invalid body length"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._json(400, {"error": "invalid JSON"})
            return

        kind = (payload.get("type") or "").lower()
        url = (payload.get("url") or "").strip()
        repo = (payload.get("repo") or "").strip()

        if repo or kind == "repo":
            target = repo or url
            if not target:
                self._json(400, {"error": "missing repo URL"})
                return
            scan_id = _new_job(target, "repo")
            threading.Thread(target=_worker, args=(scan_id, "repo", target), daemon=True).start()
            self._json(200, {"scan_id": scan_id, "status": "queued"})
            return

        if not url:
            self._json(400, {"error": "missing url"})
            return
        full = url if "//" in url else "https://" + url
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            self._json(400, {"error": "url must be http(s)://host"})
            return
        scan_id = _new_job(full, "web")
        threading.Thread(target=_worker, args=(scan_id, "web", full), daemon=True).start()
        self._json(200, {"scan_id": scan_id, "status": "queued"})

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/scan/"):
            job = _get(path[len("/scan/"):].strip("/"))
            if not job:
                self._json(404, {"error": "unknown scan_id", "status": "failed"})
                return
            self._json(200, job)
            return
        if path == "/health":
            self._json(200, {"ok": True, "engine": str(ENGINE_DIR), "python": ENGINE_PY})
            return
        self._serve_static(path)

    def _serve_static(self, path: str) -> None:
        # Tight allowlist: the SPA itself + an optional assets/ dir for images.
        # The repo is NOT a web root — never serve arbitrary source files.
        rel = path.lstrip("/") or "app.html"
        if rel in ("", "app.html", "index.html"):
            candidate = ENGINE_DIR / "app.html"
        elif rel.startswith("assets/"):
            candidate = (ENGINE_DIR / rel).resolve()
            assets_root = (ENGINE_DIR / "assets").resolve()
            try:
                candidate.relative_to(assets_root)
            except ValueError:
                self._json(403, {"error": "forbidden"})
                return
            if candidate.suffix.lower() not in _CTYPES:
                self._json(403, {"error": "forbidden"})
                return
        else:
            self._json(404, {"error": "not found"})
            return
        if not candidate.is_file():
            self._json(404, {"error": "not found"})
            return
        try:
            data = candidate.read_bytes()
        except OSError:
            self._json(500, {"error": "read error"})
            return
        self.send_response(200)
        self.send_header("Content-Type", _ctype(candidate))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


_CTYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8", ".json": "application/json",
    ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg", ".ico": "image/x-icon", ".webp": "image/webp",
}


def _ctype(p: Path) -> str:
    return _CTYPES.get(p.suffix.lower(), "application/octet-stream")


def main() -> int:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("🦂 Mantishack scan server")
    print(f"   engine : {ENGINE_DIR}")
    print(f"   python : {ENGINE_PY}")
    print(f"   open   : http://{HOST}:{PORT}")
    print("   api    : POST /scan · GET /scan/<id> · GET /health")
    print("   (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
