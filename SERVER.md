# Mantishack local scan server

`server.py` + `app.html` turn the Mantishack engine into a **local web app**:
paste a link, a new scan session starts, and a report comes back — with live
loading screens.

One process serves the scan UI **and** the scan API on a single origin
(default `http://127.0.0.1:8080`).

## Run it

```bash
cd ~/Downloads/mantishack

# one-time: create the engine venv with the web-scan deps
python3 -m venv .venv
.venv/bin/python -m pip install requests beautifulsoup4 lxml

# start the server
python3 server.py
# open http://127.0.0.1:8080
```

`Ctrl-C` to stop. To restart after a crash / port-in-use:

```bash
pkill -f "python3 server.py"      # or: lsof -ti tcp:8080 | xargs kill
```

## How it works

A visitor pastes a URL (or a GitHub repo). The browser hits the API; the server
starts a **new scan session** (its own `scan_id` + output dir), runs the engine
in a background thread, and the page polls for live progress.

| Method | Path           | Purpose |
|--------|----------------|---------|
| POST   | `/scan`        | `{"url":"…","type":"web"}` or `{"repo":"https://github.com/u/r"}` → `{scan_id}` |
| GET    | `/scan/<id>`   | `{status, current_step, progress, findings, target, error}` — drives the loading screen + report |
| GET    | `/`            | the scan UI (`app.html`) |
| GET    | `/health`      | `{ok, engine, python}` |

- **Website scan** runs `mantishack.py web --url <link>`, streams real progress
  into `current_step`, then parses `web_scan_report.json`.
- **GitHub repo scan** shallow-clones an `http(s)` git URL into a temp dir, runs
  `mantishack.py scan --repo <dir>` (Semgrep/CodeQL), parses the SARIF / semgrep
  findings, and deletes the clone.

The UI has three stages: **input → live scanning (animated phase tracker +
progress bar + log) → report (severity tiles + per-finding cards)**.

## Config (env vars)

| Var | Default | Meaning |
|-----|---------|---------|
| `MANTISHACK_SERVER_HOST` | `127.0.0.1` | bind host (**localhost only** by default) |
| `MANTISHACK_SERVER_PORT` | `8080` | bind port |
| `MANTISHACK_PYTHON` | `./.venv/bin/python` | interpreter that runs the engine (needs `requests`/`bs4`) |
| `MANTISHACK_SCAN_TIMEOUT` | `900` | per-scan wall-clock cap (seconds) |

## Safety

- Binds to `127.0.0.1` only — not exposed to your network. Don't bind to
  `0.0.0.0`: it would let anyone on the network drive scans from your host.
- Static serving is allowlisted to `app.html` + `assets/` images — the repo is
  **not** a web root, so source files aren't downloadable.
- Repo scan accepts only `http(s)` git URLs, clones shallow with a sanitised env
  and a timeout, then removes the clone. All engine/git calls use list-argument
  subprocess (no shell).
- Only scan targets you own or are authorized to test.
