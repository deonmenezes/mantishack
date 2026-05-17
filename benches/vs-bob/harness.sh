#!/usr/bin/env bash
# benches/vs-bob/harness.sh
#
# Side-by-side benchmark harness: runs Mantis and hacker-bob against one
# locally-hosted vulnerable-application target, then scores the results.
#
# Usage:
#   bash benches/vs-bob/harness.sh <target-id>
#
# <target-id> must be one of: juiceshop | dvwa | vampi | crapi
#
# IMPORTANT — authorization / consent:
#   All targets are intentionally vulnerable Docker containers that the
#   operator must spin up locally. Never point this script at a public
#   service or a host you do not control with written authorization.
#
# Prerequisites:
#   - mantis daemon running: pgrep -x mantis-daemon || mantis-daemon &
#   - mantis CLI on PATH
#   - npx / Node.js available (for the hacker-bob run)
#   - Python 3 for score.py
#   - Docker images already pulled (see README.md)
#
# The script does NOT call docker, cargo, npm, or npx automatically.
# It prints the exact commands the operator should run out-of-band, then
# proceeds with the Mantis side (which only calls the mantis CLI).
# ---------------------------------------------------------------------------

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benches/vs-bob"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
  echo "Usage: bash ${SCRIPT_NAME} <target-id>"
  echo ""
  echo "Available target IDs: juiceshop  dvwa  vampi  crapi"
  exit 1
fi

TARGET_ID="${1}"

# ---------------------------------------------------------------------------
# Target configuration
# ---------------------------------------------------------------------------
case "${TARGET_ID}" in
  juiceshop)
    TARGET_LABEL="OWASP Juice Shop"
    TARGET_URL="http://localhost:3000"
    DOCKER_IMAGE="bkimminich/juice-shop"
    DOCKER_PORT="3000:3000"
    ;;
  dvwa)
    TARGET_LABEL="Damn Vulnerable Web Application (DVWA)"
    TARGET_URL="http://localhost:8080"
    DOCKER_IMAGE="vulnerables/web-dvwa"
    DOCKER_PORT="8080:80"
    ;;
  vampi)
    TARGET_LABEL="VAmPI"
    TARGET_URL="http://localhost:5000"
    DOCKER_IMAGE="erev0s/vampi:latest"
    DOCKER_PORT="5000:5000"
    ;;
  crapi)
    TARGET_LABEL="OWASP crAPI"
    TARGET_URL="http://localhost:8888"
    DOCKER_IMAGE="owasp/crapi"
    DOCKER_PORT="8888:8888"
    ;;
  *)
    echo "[harness] ERROR: Unknown target-id '${TARGET_ID}'"
    echo "Available: juiceshop  dvwa  vampi  crapi"
    exit 1
    ;;
esac

RUN_DIR="${BENCH_DIR}/runs/${TARGET_ID}"
MANTIS_OUT="${RUN_DIR}/mantis-output.jsonl"
BOB_OUT="${RUN_DIR}/bob-output.json"
SCORE_OUT="${BENCH_DIR}/results.md"

mkdir -p "${RUN_DIR}"

# ---------------------------------------------------------------------------
# Step 1 — Docker instructions (operator runs out-of-band)
# ---------------------------------------------------------------------------
echo "=================================================================="
echo " Mantis vs Hacker-Bob Benchmark Harness"
echo " Target: ${TARGET_LABEL} (${TARGET_ID})"
echo "=================================================================="
echo ""
echo "--- STEP 1: Start the target container (run this yourself) -------"
echo ""
echo "  docker run --rm -d -p ${DOCKER_PORT} --name bench_${TARGET_ID} ${DOCKER_IMAGE}"
echo ""
echo "  Wait for the application to be ready, then press ENTER to continue."
echo "  (For crAPI allow ~60 seconds for full startup.)"
echo ""
read -r -p "  [harness] Press ENTER when the target is ready: "
echo ""

# ---------------------------------------------------------------------------
# Step 2 — Verify daemon is running
# ---------------------------------------------------------------------------
echo "--- STEP 2: Checking Mantis daemon ---------------------------------"
if ! pgrep -x mantis-daemon > /dev/null 2>&1; then
  echo "[harness] WARNING: mantis-daemon is not running."
  echo "[harness] Start it with: mantis-daemon &"
  echo "[harness] Waiting 10 seconds for you to start it ..."
  sleep 10
  if ! pgrep -x mantis-daemon > /dev/null 2>&1; then
    echo "[harness] ERROR: mantis-daemon still not found. Aborting."
    exit 1
  fi
fi
echo "[harness] mantis-daemon is running."
echo ""

# ---------------------------------------------------------------------------
# Step 3 — Run Mantis
# ---------------------------------------------------------------------------
echo "--- STEP 3: Running Mantis -----------------------------------------"
echo "[harness] Command:"
echo "  mantis pentest ${TARGET_URL} --i-have-authorization --budget-seconds 300"
echo ""
echo "[harness] Output will be written to: ${MANTIS_OUT}"
echo ""

# Run mantis and capture the engagement ID from stdout
ENGAGEMENT_ID=""
if mantis pentest "${TARGET_URL}" --i-have-authorization --budget-seconds 300 \
      2>&1 | tee "${RUN_DIR}/mantis-run.log"; then
  echo "[harness] Mantis run complete."
else
  echo "[harness] WARNING: mantis exited with a non-zero status. Check ${RUN_DIR}/mantis-run.log"
fi

# Extract engagement ID from the log (mantis prints "engagement: <id>" or similar)
ENGAGEMENT_ID="$(grep -Eo 'engagement[=: ]+[a-zA-Z0-9_-]+' \
  "${RUN_DIR}/mantis-run.log" 2>/dev/null | head -1 | awk '{print $NF}' || true)"

# Export events to JSONL
if [[ -n "${ENGAGEMENT_ID}" ]]; then
  echo "[harness] Exporting events for engagement ${ENGAGEMENT_ID} ..."
  mantis engagement export "${ENGAGEMENT_ID}" > "${MANTIS_OUT}" \
    || echo "[harness] WARNING: export failed; ${MANTIS_OUT} may be empty."
else
  echo "[harness] Could not determine engagement ID from log."
  echo "[harness] Manually export with:"
  echo "  mantis engagement export <id> > ${MANTIS_OUT}"
  # Create empty file so score.py doesn't hard-fail
  touch "${MANTIS_OUT}"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4 — Hacker-bob instructions (operator runs out-of-band)
# ---------------------------------------------------------------------------
echo "--- STEP 4: Run hacker-bob (run this yourself in a separate terminal)"
echo ""
echo "  npx -y @vmihalis/hacker-bob bounty ${TARGET_URL} 2>&1 | tee ${BOB_OUT}"
echo ""
echo "  OR, if hacker-bob writes to ~/bounty-agent-sessions/:"
echo ""
# Derive a plausible domain slug from the URL (localhost:PORT -> localhost_PORT)
DOMAIN_SLUG="$(echo "${TARGET_URL}" | sed 's|https\?://||;s|[/:]|_|g')"
echo "  cp ~/bounty-agent-sessions/${DOMAIN_SLUG}/pipeline-events.jsonl \\"
echo "     ${BOB_OUT}"
echo ""
echo "[harness] Press ENTER once ${BOB_OUT} is in place to continue scoring."
read -r -p "  [harness] Press ENTER: "
echo ""

# ---------------------------------------------------------------------------
# Step 5 — Score
# ---------------------------------------------------------------------------
echo "--- STEP 5: Scoring ------------------------------------------------"

if [[ ! -s "${BOB_OUT}" ]]; then
  echo "[harness] WARNING: ${BOB_OUT} is missing or empty."
  echo "[harness] Creating a placeholder so score.py can still run."
  echo '{"findings":[]}' > "${BOB_OUT}"
fi

if [[ ! -s "${MANTIS_OUT}" ]]; then
  echo "[harness] WARNING: ${MANTIS_OUT} is missing or empty."
  echo "[harness] Score will reflect zero findings for Mantis."
  touch "${MANTIS_OUT}"
fi

python3 "${BENCH_DIR}/score.py" \
  --mantis "${MANTIS_OUT}" \
  --bob    "${BOB_OUT}" \
  --target "${TARGET_ID}" \
  --out    "${SCORE_OUT}"

echo ""
echo "=================================================================="
echo " Benchmark complete."
echo " Results:  ${SCORE_OUT}"
echo " Mantis log: ${RUN_DIR}/mantis-run.log"
echo " Mantis events: ${MANTIS_OUT}"
echo " Bob output:    ${BOB_OUT}"
echo "=================================================================="

# ---------------------------------------------------------------------------
# Step 6 — Teardown instructions
# ---------------------------------------------------------------------------
echo ""
echo "--- STEP 6: Tear down the target container (run this yourself) ----"
echo ""
echo "  docker stop bench_${TARGET_ID}"
echo ""
