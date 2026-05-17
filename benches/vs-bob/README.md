# Mantis vs Hacker-Bob — Benchmark Guide

This directory contains the benchmark harness for running Mantis and hacker-bob side-by-side
against the same locally-hosted vulnerable-application targets and comparing their output.

**All targets must be self-hosted Docker instances under the operator's direct control.**
Never run this benchmark against public services, shared SaaS, or any host you do not own and
have written authorization to test.

---

## Targets

The benchmark defines four authorized target categories. All four are well-known, intentionally
vulnerable web applications distributed as Docker images specifically for security training and
research purposes. Each must be started locally before running the harness.

| ID | Application | Image | Default port | Purpose |
|---|---|---|---|---|
| `juiceshop` | OWASP Juice Shop | `bkimminich/juice-shop` | 3000 | OWASP Top 10, broken auth, IDOR, XSS, SQLi, insecure deserialization |
| `dvwa` | Damn Vulnerable Web App | `vulnerables/web-dvwa` | 80 | SQLi, XSS, CSRF, file inclusion, command injection, brute-force |
| `vampi` | VAmPI | `erev0s/vampi:latest` | 5000 | OWASP API Top 10: BOLA, broken auth, excessive data exposure, mass assignment |
| `crapi` | OWASP crAPI | `owasp/crapi` | 8888 | API-specific: BOLA, broken function-level auth, SSRF, JWT weakness |

### Consent note

All four applications are purpose-built CTF/training targets maintained by OWASP or independent
security researchers. Their intended use is exactly this — being attacked in a local environment
by operators building or evaluating security tooling. No public services are involved. The operator
is responsible for ensuring the Docker containers are not reachable from untrusted networks (use
host-only or bridge networking).

---

## Setup

### Prerequisites

- Docker and `docker compose` installed and running.
- Mantis daemon built from this repo (`cargo build --release --workspace`).
- `mantis` CLI and `mantis-mcp` binary on `$PATH`.
- Node.js / npx available if you want to run the hacker-bob side (`npx -y @vmihalis/hacker-bob`).
- Python 3.8+ (stdlib only) for `score.py`.

### Pull the images (one-time)

```sh
docker pull bkimminich/juice-shop
docker pull vulnerables/web-dvwa
docker pull erev0s/vampi:latest
docker pull owasp/crapi
```

### Start the Mantis daemon

```sh
pgrep -x mantis-daemon >/dev/null || mantis-daemon &
sleep 1
```

---

## Run Mantis

For each target you want to benchmark (replace `<target-id>` with one of: `juiceshop`, `dvwa`,
`vampi`, `crapi`):

```sh
bash benches/vs-bob/harness.sh <target-id>
```

The harness script prints the Docker run command for the target, then runs:

```sh
mantis pentest <url> --i-have-authorization --budget-seconds 300
```

After the run completes it exports events to `benches/vs-bob/runs/<target-id>/mantis-output.jsonl`.

You can also drive a full wave-based engagement for higher coverage:

```sh
mantis goal "find vulnerabilities" --target <url> --i-have-authorization
```

Export the event log afterward:

```sh
mantis engagement export <engagement-id> > benches/vs-bob/runs/<target-id>/mantis-output.jsonl
```

---

## Run Hacker-Bob

Hacker-bob runs as an MCP server inside Claude Code. The harness script echoes the invocation
command but does not execute it automatically. To run it yourself:

```sh
npx -y @vmihalis/hacker-bob bounty <url> 2>&1 | tee benches/vs-bob/runs/<target-id>/bob-output.json
```

If hacker-bob writes its output to `~/bounty-agent-sessions/[domain]/pipeline-events.jsonl`,
copy that file to `benches/vs-bob/runs/<target-id>/bob-output.json` before scoring:

```sh
cp ~/bounty-agent-sessions/<domain>/pipeline-events.jsonl \
   benches/vs-bob/runs/<target-id>/bob-output.json
```

---

## Diff the Outputs

After both runs are complete for a target, call the scorer directly:

```sh
python3 benches/vs-bob/score.py \
  --mantis benches/vs-bob/runs/<target-id>/mantis-output.jsonl \
  --bob    benches/vs-bob/runs/<target-id>/bob-output.json \
  --target <target-id>
```

The script prints a markdown comparison table to stdout and writes the full comparison to
`benches/vs-bob/results.md`.

To see a raw event-level diff (useful for debugging missed findings):

```sh
diff \
  <(jq -r '.vuln_class // empty' benches/vs-bob/runs/<target-id>/mantis-output.jsonl | sort) \
  <(jq -r '.findings[].vuln_class // empty' benches/vs-bob/runs/<target-id>/bob-output.json | sort)
```

---

## Scoring Rubric

Each system is scored on five axes per target. The scorer (`score.py`) computes all five
automatically.

| Axis | Definition | Weight |
|---|---|---|
| **Coverage** | Distinct surfaces probed (URLs / endpoints touched) | 20 % |
| **Find rate** | Confirmed findings / total probes issued | 25 % |
| **Unique classes** | Number of distinct vulnerability classes found | 20 % |
| **Severity score** | Sum of CVSS-approximate weights per finding (critical=9, high=7, medium=5, low=2, info=0) | 25 % |
| **FP estimate** | Findings that were raised then rejected — lower is better; score = 1 - (rejected / raised) | 10 % |

A finding is counted as **confirmed** when:
- Mantis: event `kind` contains `Confirmed`, `TieredFinding`, or the event carries a non-null `vuln_class` field.
- Hacker-bob: entry appears under the `findings` or `confirmed_findings` key in the output JSON.

The aggregate score is a weighted sum normalized to 100. Both systems are scored identically
so the comparison is apples-to-apples.
