#!/usr/bin/env bash
# One-line Mantis installer.
#
#   curl -fsSL https://raw.githubusercontent.com/deonmenezes/mantishack/main/install.sh | bash
#
# - Builds (or downloads, if available) the `mantis-daemon` and
#   `mantis` binaries.
# - Installs them under ~/.local/bin (or $PREFIX/bin).
# - Detects which AI CLI(s) you have installed (claude, codex, opencode)
#   and installs Mantis as a plugin for each, exposing slash
#   commands like /mantis-scan, /mantis-status, /mantis-claim.

set -euo pipefail

PREFIX="${MANTIS_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
PLUGIN_SOURCE_REPO="${MANTIS_REPO:-https://github.com/deonmenezes/mantishack}"
MANTIS_REF="${MANTIS_REF:-main}"
BUILD_DIR="${MANTIS_BUILD_DIR:-$HOME/.cache/mantis-build}"

log() { printf '\033[36m[mantis]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[mantis] warn:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[mantis] error:\033[0m %s\n' "$*" >&2; exit 1; }

uname_s=$(uname -s)
uname_m=$(uname -m)
log "host: $uname_s/$uname_m"

# 1. Toolchain check ----------------------------------------------------------
# rustup installs to ~/.cargo/bin and adds it to PATH via ~/.cargo/env, which
# isn't sourced in a non-login shell. Pick it up here so users don't have to
# restart their terminal after `rustup install`.
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi
if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi
# Auto-install Rust toolchain via rustup if cargo is still missing.
# Honors MANTIS_SKIP_RUSTUP=1 to opt out.
if ! command -v cargo >/dev/null 2>&1; then
    if [ "${MANTIS_SKIP_RUSTUP:-0}" = "1" ]; then
        die "cargo not found and MANTIS_SKIP_RUSTUP=1. Install Rust from https://rustup.rs and rerun."
    fi
    log "cargo not found — installing Rust toolchain via rustup (non-interactive, minimal profile)"
    if ! command -v curl >/dev/null 2>&1; then
        die "curl not found. Install curl (or set MANTIS_SKIP_RUSTUP=1 and install Rust manually) and rerun."
    fi
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
    if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    command -v cargo >/dev/null 2>&1 || die "rustup install ran but cargo is still not on PATH."
    log "rustup installed: $(cargo --version)"
fi
if ! command -v git >/dev/null 2>&1; then
    die "git not found. Install git and rerun."
fi

mkdir -p "$BIN_DIR" "$BUILD_DIR"

# 2. Source checkout ----------------------------------------------------------
if [ -d "$BUILD_DIR/.git" ]; then
    log "updating existing checkout at $BUILD_DIR"
    git -C "$BUILD_DIR" fetch --depth=1 origin "$MANTIS_REF"
    git -C "$BUILD_DIR" checkout -f FETCH_HEAD
else
    log "cloning $PLUGIN_SOURCE_REPO@$MANTIS_REF -> $BUILD_DIR"
    rm -rf "$BUILD_DIR"
    git clone --depth=1 --branch "$MANTIS_REF" "$PLUGIN_SOURCE_REPO" "$BUILD_DIR"
fi

# 3. Build binaries -----------------------------------------------------------
log "building mantis-daemon + mantis (release)"
(cd "$BUILD_DIR" && cargo build --release --bin mantis-daemon --bin mantis)
install -m 0755 "$BUILD_DIR/target/release/mantis-daemon" "$BIN_DIR/mantis-daemon"
install -m 0755 "$BUILD_DIR/target/release/mantis" "$BIN_DIR/mantis"
log "installed: $BIN_DIR/mantis-daemon"
log "installed: $BIN_DIR/mantis"

# 4. AI-CLI plugin installation ----------------------------------------------
PLUGIN_SOURCE="$BUILD_DIR/plugin"
INSTALLED_FOR=()

install_for_claude() {
    if ! command -v claude >/dev/null 2>&1 && [ ! -d "$HOME/.claude" ]; then
        return 1
    fi
    local target="$HOME/.claude/plugins/mantis"
    rm -rf "$target"
    mkdir -p "$(dirname "$target")"
    cp -R "$PLUGIN_SOURCE/claude-code" "$target"
    log "installed plugin for claude-code at $target"
    INSTALLED_FOR+=("claude-code")
}

install_for_codex() {
    if ! command -v codex >/dev/null 2>&1 && [ ! -d "$HOME/.codex" ]; then
        return 1
    fi
    local target="$HOME/.codex/plugins/mantis"
    rm -rf "$target"
    mkdir -p "$(dirname "$target")"
    cp -R "$PLUGIN_SOURCE/codex" "$target"
    log "installed plugin for codex at $target"
    INSTALLED_FOR+=("codex")
}

install_for_opencode() {
    if ! command -v opencode >/dev/null 2>&1 && [ ! -d "$HOME/.config/opencode" ]; then
        return 1
    fi
    local target="$HOME/.config/opencode/plugins/mantis"
    rm -rf "$target"
    mkdir -p "$(dirname "$target")"
    cp -R "$PLUGIN_SOURCE/opencode" "$target"
    log "installed plugin for opencode at $target"
    INSTALLED_FOR+=("opencode")
}

install_for_claude || true
install_for_codex || true
install_for_opencode || true

# 5. PATH wiring -------------------------------------------------------------
# Make sure $BIN_DIR is on PATH for future shells by appending an export to
# the user's shell rc, idempotently. Honors MANTIS_SKIP_PATH=1 to opt out.
PATH_LINE="export PATH=\"$BIN_DIR:\$PATH\""
PATH_MARKER="# added by mantis installer"
PATH_UPDATED_FILES=()

append_path_to() {
    local rc="$1"
    [ -z "$rc" ] && return 0
    # Already exports BIN_DIR? skip.
    if [ -f "$rc" ] && grep -Fq "$BIN_DIR" "$rc"; then
        return 0
    fi
    mkdir -p "$(dirname "$rc")"
    {
        printf '\n%s\n%s\n' "$PATH_MARKER" "$PATH_LINE"
    } >> "$rc"
    PATH_UPDATED_FILES+=("$rc")
}

case ":$PATH:" in
    *":$BIN_DIR:"*)
        : # already on PATH for this shell, but still ensure rc has it for future shells
        ;;
esac

if [ "${MANTIS_SKIP_PATH:-0}" != "1" ]; then
    # Pick rc files based on $SHELL, but also cover both common shells so users
    # who switch between bash and zsh don't get surprised.
    case "${SHELL:-}" in
        */zsh)  append_path_to "$HOME/.zshrc" ;;
        */bash)
            if [ "$(uname -s)" = "Darwin" ]; then
                append_path_to "$HOME/.bash_profile"
            else
                append_path_to "$HOME/.bashrc"
            fi
            ;;
        *)
            # Unknown login shell — cover the common ones.
            [ -f "$HOME/.zshrc" ] && append_path_to "$HOME/.zshrc"
            [ -f "$HOME/.bashrc" ] && append_path_to "$HOME/.bashrc"
            [ -f "$HOME/.bash_profile" ] && append_path_to "$HOME/.bash_profile"
            ;;
    esac
fi

# Make the binaries usable in the *current* shell too (helps when the script
# is sourced; for the typical `curl | bash` case it's harmless).
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) export PATH="$BIN_DIR:$PATH" ;;
esac

# 6. Summary ------------------------------------------------------------------
log "done."
if [ "${#PATH_UPDATED_FILES[@]}" -gt 0 ]; then
    log "added $BIN_DIR to PATH in: ${PATH_UPDATED_FILES[*]}"
    log "open a new terminal, or run:  source ${PATH_UPDATED_FILES[0]}"
fi
if [ "${#INSTALLED_FOR[@]}" -gt 0 ]; then
    log "AI CLIs configured: ${INSTALLED_FOR[*]}"
    log "try:    mantis daemon   # start the daemon"
    log "or in your AI CLI:    /mantis-scan <target>"
else
    warn "no claude/codex/opencode CLI detected — the binaries are installed but no plugin was wired."
    warn "install the CLI you want and rerun this script."
fi
