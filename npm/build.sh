#!/usr/bin/env bash
# npm/build.sh — compile the host's native platform package and the
# top-level `mantishack` package as publishable .tgz tarballs.
#
# By default it builds ONLY the host platform (since cross-compiling
# on a fresh macOS install requires extra toolchains). To build all
# four platforms, run this script on each target machine (or wire a
# GitHub Actions matrix; see README at npm/PUBLISH.md).
#
# Usage:
#   ./npm/build.sh                    # build host platform
#   ./npm/build.sh --all              # build all 4 (needs cross/zig)
#   ./npm/build.sh --target <triple>  # build a specific cargo target
#
# Outputs:
#   npm/dist/mantishack-<ver>.tgz
#   npm/dist/mantishack-cli-<os>-<arch>-<ver>.tgz

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NPM_DIR="${REPO_ROOT}/npm"
DIST_DIR="${NPM_DIR}/dist"
VERSION="$(grep '^version' "${REPO_ROOT}/Cargo.toml" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"

mkdir -p "${DIST_DIR}"

# --- Map cargo target triple → npm platform key ----------------------
# Add a row when you want to ship a new platform.
declare -a TARGETS=()
case "${1:-}" in
  --all)
    TARGETS=(aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu)
    ;;
  --target)
    TARGETS=("$2")
    ;;
  *)
    # Host-only build (no cargo --target flag).
    TARGETS=("")
    ;;
esac

target_to_npm_key() {
  case "$1" in
    aarch64-apple-darwin)        echo "darwin-arm64" ;;
    x86_64-apple-darwin)         echo "darwin-x64"   ;;
    x86_64-unknown-linux-gnu)    echo "linux-x64"    ;;
    aarch64-unknown-linux-gnu)   echo "linux-arm64"  ;;
    "")
      # Host platform — derive from uname.
      local os="$(uname -s | tr '[:upper:]' '[:lower:]')"
      local arch="$(uname -m)"
      [[ "$arch" == "x86_64" ]] && arch="x64"
      [[ "$arch" == "aarch64" ]] && arch="arm64"
      echo "${os}-${arch}"
      ;;
    *) echo "unknown" ;;
  esac
}

# --- Build each requested platform ------------------------------------
cd "${REPO_ROOT}"
for target in "${TARGETS[@]}"; do
  npm_key="$(target_to_npm_key "$target")"
  pkg_dir="${NPM_DIR}/platforms/${npm_key}"
  if [[ ! -d "${pkg_dir}" ]]; then
    echo "[npm/build] skipping ${npm_key}: no package directory at ${pkg_dir}"
    continue
  fi
  echo
  echo "==> building ${npm_key} (target=${target:-host})"

  bin_dir="${pkg_dir}/bin"
  rm -rf "${bin_dir}"
  mkdir -p "${bin_dir}"

  if [[ -n "$target" ]]; then
    cargo build --release --target "$target" -p mantis-cli -p mantis-daemon -p mantis-mcp
    src_root="${REPO_ROOT}/target/${target}/release"
  else
    cargo build --release -p mantis-cli -p mantis-daemon -p mantis-mcp
    src_root="${REPO_ROOT}/target/release"
  fi

  for bin in mantis mantis-daemon mantis-mcp; do
    src="${src_root}/${bin}"
    if [[ ! -x "${src}" ]]; then
      echo "[npm/build] error: ${src} not built"; exit 1
    fi
    cp "${src}" "${bin_dir}/${bin}"
    chmod +x "${bin_dir}/${bin}"
    # On macOS, ad-hoc codesign so the binary doesn't get SIGKILL'd
    # after the package is installed by npm.
    if [[ "$(uname -s)" == "Darwin" ]]; then
      codesign --force --sign - "${bin_dir}/${bin}" 2>/dev/null || true
    fi
  done
  echo "  ✓ binaries copied to ${bin_dir}"

  # Pack the platform package.
  pushd "${pkg_dir}" >/dev/null
  tarball="$(npm pack --pack-destination "${DIST_DIR}" 2>&1 | tail -1)"
  popd >/dev/null
  echo "  ✓ ${DIST_DIR}/${tarball}"
done

# --- Pack the main `mantishack` package -------------------------------
echo
echo "==> packing main mantishack package"
pushd "${NPM_DIR}/mantishack" >/dev/null
tarball="$(npm pack --pack-destination "${DIST_DIR}" 2>&1 | tail -1)"
popd >/dev/null
echo "  ✓ ${DIST_DIR}/${tarball}"

echo
echo "Done. Publishable tarballs:"
ls -1 "${DIST_DIR}"
echo
echo "Next steps:"
echo "  1. Inspect any tarball with: tar tzf ${DIST_DIR}/<file>.tgz"
echo "  2. (Optional) Publish each platform first, then the main package:"
echo "       cd ${NPM_DIR}/platforms/<plat> && npm publish --access public"
echo "       cd ${NPM_DIR}/mantishack && npm publish --access public"
echo "  3. Then anyone can: npm i -g mantishack   (or bun add -g mantishack)"
