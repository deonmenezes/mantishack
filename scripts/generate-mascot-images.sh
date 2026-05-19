#!/usr/bin/env bash
# scripts/generate-mascot-images.sh
#
# Generates per-FSM-phase mascot variants from the canonical hero
# mascot using OpenAI's `gpt-image-1` model (commonly called "Codex
# image gen 2" / image generation v2). Each phase image is composed
# to match the canonical mantis aesthetic: dark background, neon-green
# armored mantis silhouette, subtle phase-specific accent.
#
# Requirements:
#   - OPENAI_API_KEY env var (https://platform.openai.com/api-keys)
#   - curl, jq, base64
#   - The canonical hero mascot at docs/assets/mascot/hero.png
#
# Usage:
#   OPENAI_API_KEY=sk-... ./scripts/generate-mascot-images.sh
#   OPENAI_API_KEY=sk-... ./scripts/generate-mascot-images.sh recon hunt   # only those phases
#
# Output: docs/assets/mascot/<phase>.png  (1024x1024 PNG)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MASCOT_DIR="${REPO_ROOT}/docs/assets/mascot"
HERO="${MASCOT_DIR}/hero.png"

if [[ ! -f "${HERO}" ]]; then
  echo "[mascot] error: hero mascot not found at ${HERO}" >&2
  echo "[mascot] expected the canonical mantis hero image to be saved there first." >&2
  exit 1
fi

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "[mascot] error: OPENAI_API_KEY env var is required." >&2
  echo "[mascot] get one at https://platform.openai.com/api-keys" >&2
  exit 1
fi

for cmd in curl jq base64; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[mascot] error: '$cmd' not on PATH" >&2; exit 1
  fi
done

# --- Per-phase prompts -------------------------------------------------
# All prompts share a base aesthetic: dark background, neon-green
# armored mantis silhouette, hyper-detailed, dramatic lighting. Each
# phase adds a single visual accent that suggests the phase's role.
BASE_STYLE='hyper-detailed digital illustration, dark navy black background, armored bipedal praying-mantis warrior with glowing pale-green eyes, neon-green and emerald body armor with sharp geometric plating, dramatic cinematic lighting, single subject centered, square 1:1, no text, no logos, no humans'

declare -A PROMPTS=(
  [recon]="${BASE_STYLE}; the mantis is crouched low scanning the horizon with one antenna raised, faint holographic radar rings projected from its eyes, exploring outward, mood: vigilant reconnaissance"
  [auth]="${BASE_STYLE}; the mantis stands at attention holding a glowing key-card token in its forearm claws, a digital lock icon floating above, mood: gaining access credentials"
  [hunt]="${BASE_STYLE}; THREE mantis warriors in a triangle formation each facing a different direction, weapons raised, glowing tactical sigils on their armor, mood: parallel hunt wave fan-out"
  [chain]="${BASE_STYLE}; the mantis holds a glowing chain of three interlocking neon-green rings between its forearms, each ring slightly larger than the last, suggesting a multi-step exploit chain, mood: assembly"
  [verify]="${BASE_STYLE}; THREE identical mantis warriors standing in a row each examining the same glowing artifact in their forearms, brutalist skeptic on the left, balanced in the middle, final on the right, mood: triple verification"
  [grade]="${BASE_STYLE}; the mantis holds a glowing five-pointed crystal in its forearms with rays of light emanating from each point, mood: scoring on five axes"
  [report]="${BASE_STYLE}; the mantis stands beside a floating holographic scroll with neon-green text glyphs, calmly presenting the final disclosure-ready report, mood: completion and disclosure"
)

# --- Decide which phases to generate ----------------------------------
PHASES=()
if [[ $# -gt 0 ]]; then
  PHASES=("$@")
else
  PHASES=(recon auth hunt chain verify grade report)
fi

# --- Generate -----------------------------------------------------------
generate_one() {
  local phase="$1"
  local prompt="${PROMPTS[$phase]:-}"
  if [[ -z "$prompt" ]]; then
    echo "[mascot] unknown phase: $phase  (valid: ${!PROMPTS[*]})" >&2
    return 1
  fi
  local out="${MASCOT_DIR}/${phase}.png"
  echo "[mascot] generating ${phase} -> ${out}"
  local body
  body="$(jq -n --arg p "$prompt" '{
    model: "gpt-image-1",
    prompt: $p,
    size: "1024x1024",
    quality: "high",
    n: 1
  }')"
  local resp
  resp="$(curl -sS https://api.openai.com/v1/images/generations \
    -H "Authorization: Bearer ${OPENAI_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$body")"
  local err
  err="$(echo "$resp" | jq -r '.error.message // empty')"
  if [[ -n "$err" ]]; then
    echo "[mascot] OpenAI error for ${phase}: $err" >&2
    return 1
  fi
  local b64
  b64="$(echo "$resp" | jq -r '.data[0].b64_json')"
  if [[ -z "$b64" || "$b64" == "null" ]]; then
    echo "[mascot] no b64_json in response for ${phase}; full response:" >&2
    echo "$resp" >&2
    return 1
  fi
  echo "$b64" | base64 -d > "$out"
  echo "[mascot]   ✓ wrote ${out} ($(wc -c < "$out") bytes)"
}

for phase in "${PHASES[@]}"; do
  if ! generate_one "$phase"; then
    echo "[mascot] aborting on first failure." >&2
    exit 1
  fi
done

echo
echo "[mascot] done. files in ${MASCOT_DIR}:"
ls -1 "${MASCOT_DIR}"
