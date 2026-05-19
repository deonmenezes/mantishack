#!/usr/bin/env bash
# Install the recon binaries the recon-agent expects into
# `<repo>/tools/recon/bin/`. Idempotent: re-running upgrades to @latest.
#
# - Go binaries (subfinder, httpx, katana, nuclei) via `go install`.
#   GOBIN points at this directory so nothing leaks into $HOME/go/bin.
# - jwt_tool via a `git clone` + a tiny wrapper shim in bin/.
# - Nuclei templates refreshed into templates/ after install.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
TEMPLATES_DIR="$SCRIPT_DIR/templates"
JWT_DIR="$SCRIPT_DIR/jwt_tool"

mkdir -p "$BIN_DIR" "$TEMPLATES_DIR"

log() { printf '\033[1;36m[recon-install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[recon-install]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[recon-install]\033[0m %s\n' "$*" >&2; exit 1; }

ensure_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    die "Homebrew not found and \`go\` is missing. Install Go yourself (https://go.dev/dl/) and re-run, or install Homebrew first."
  fi
}

ensure_go() {
  if command -v go >/dev/null 2>&1; then return; fi
  case "$(uname -s)" in
    Darwin)
      ensure_brew
      log "go not found — installing via Homebrew (this may take a few minutes)"
      brew install go
      ;;
    Linux)
      die "go not found. Install Go 1.21+ from your package manager (apt install golang-go / dnf install golang / etc.) and re-run."
      ;;
    *)
      die "Unsupported OS $(uname -s). Install Go manually and re-run."
      ;;
  esac
  command -v go >/dev/null 2>&1 || die "go install completed but binary still not on PATH"
}

install_go_tool() {
  local pkg="$1"
  log "go install $pkg"
  GOBIN="$BIN_DIR" go install -v "$pkg"
}

install_jwt_tool() {
  if [ -d "$JWT_DIR/.git" ]; then
    log "updating jwt_tool clone"
    git -C "$JWT_DIR" pull --ff-only 2>/dev/null || warn "jwt_tool pull failed; keeping existing checkout"
  else
    log "cloning jwt_tool"
    git clone --depth 1 https://github.com/ticarpi/jwt_tool "$JWT_DIR"
  fi
  # Lazy install of jwt_tool's pip deps in a per-tool venv so we don't touch
  # the host's site-packages. Apple-shipped python3 is fine for this.
  if [ ! -d "$JWT_DIR/.venv" ]; then
    log "creating jwt_tool venv"
    python3 -m venv "$JWT_DIR/.venv"
  fi
  log "pip install jwt_tool requirements"
  "$JWT_DIR/.venv/bin/pip" install --quiet --upgrade pip
  "$JWT_DIR/.venv/bin/pip" install --quiet -r "$JWT_DIR/requirements.txt"

  # Wrapper shim so `jwt_tool` resolves on PATH and the agent's existing
  # `command -v jwt_tool` detection just works.
  cat > "$BIN_DIR/jwt_tool" <<SHIM
#!/usr/bin/env bash
exec "$JWT_DIR/.venv/bin/python" "$JWT_DIR/jwt_tool.py" "\$@"
SHIM
  chmod +x "$BIN_DIR/jwt_tool"
}

refresh_nuclei_templates() {
  if [ ! -x "$BIN_DIR/nuclei" ]; then
    warn "skipping template refresh — nuclei binary missing"
    return
  fi
  log "nuclei -update-templates -ud $TEMPLATES_DIR"
  # Be quiet on success; nuclei is loud by default.
  "$BIN_DIR/nuclei" -update-templates -ud "$TEMPLATES_DIR" >/dev/null 2>&1 || \
    warn "nuclei template update failed (continuing — templates may already exist)"
}

verify() {
  log "verifying installs"
  local fail=0
  for t in subfinder httpx katana nuclei jwt_tool; do
    if [ -x "$BIN_DIR/$t" ]; then
      printf '  \033[1;32mOK\033[0m   %s -> %s\n' "$t" "$BIN_DIR/$t"
    else
      printf '  \033[1;31mFAIL\033[0m %s missing in %s\n' "$t" "$BIN_DIR"
      fail=$((fail+1))
    fi
  done
  [ "$fail" -eq 0 ] || die "$fail tool(s) failed to install"
}

main() {
  ensure_go
  install_go_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  install_go_tool github.com/projectdiscovery/httpx/cmd/httpx@latest
  install_go_tool github.com/projectdiscovery/katana/cmd/katana@latest
  install_go_tool github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  install_jwt_tool
  refresh_nuclei_templates
  verify
  cat <<EOF

\033[1;32m[recon-install] done.\033[0m

Add to PATH (the recon-agent already does this automatically):
  export PATH="$BIN_DIR:\$PATH"

Re-run this script any time to upgrade to @latest.
EOF
}

main "$@"
