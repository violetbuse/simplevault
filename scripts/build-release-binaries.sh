#!/usr/bin/env bash
#
# Build release archives for multiple platforms (runs locally; uses Docker via cross).
# The dist/ directory is removed and recreated first so no stale artifacts remain.
#
# Archives written to dist/:
#   simplevault-<VERSION>-x86_64-unknown-linux-gnu.tar.gz
#   simplevault-<VERSION>-aarch64-unknown-linux-gnu.tar.gz
#   simplevault-<VERSION>-x86_64-pc-windows-gnu.zip
#   simplevault-<VERSION>-aarch64-apple-darwin.tar.gz  (only when run on Apple Silicon macOS)
#
# From Linux or WSL you get the first three; Apple Silicon binaries require running this
# script on an arm64 Mac (or merging dist/ from such a machine).
#
# Prerequisites:
#   - Docker running
#   - cross: cargo install cross --git https://github.com/cross-rs/cross
#   - zip (for the Windows archive), e.g. apt install zip / brew install zip
#
# Usage: ./scripts/build-release-binaries.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

error() {
  echo "Error: $*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || error "docker not found in PATH (required by cross)"
docker info >/dev/null 2>&1 || error "Docker is not running"
command -v cross >/dev/null 2>&1 || error "cross not found. Install with: cargo install cross --git https://github.com/cross-rs/cross"

if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == CYGWIN* ]]; then
  error "Run this script from Linux, WSL, or macOS (not native Windows shell)."
fi

echo "=========================================="
echo "Release binaries (cross + optional native macOS)"
echo "=========================================="
./check-version.sh

VERSION="$(tr -d '[:space:]' < VERSION)"
if [[ -z "$VERSION" ]]; then
  error "VERSION file is empty"
fi

echo "Clearing dist/"
rm -rf dist
mkdir -p dist

CROSS_TARGETS=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-pc-windows-gnu
)

for triple in "${CROSS_TARGETS[@]}"; do
  echo ""
  echo "=== cross build --release --target ${triple} ==="
  cross build --release --locked --target "${triple}"
done

if [[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]]; then
  echo ""
  echo "=== cargo build --release (native aarch64-apple-darwin) ==="
  cargo build --release --locked
else
  echo ""
  echo "Note: Skipping aarch64-apple-darwin (run this script on Apple Silicon macOS to add that archive)."
fi

echo ""
echo "=== Packaging dist/simplevault-${VERSION}-* ==="

package_unix_tgz() {
  local triple=$1
  local bin="target/${triple}/release/simplevault"
  [[ -f "$bin" ]] || error "Missing binary: $bin"
  tar czf "dist/simplevault-${VERSION}-${triple}.tar.gz" -C "target/${triple}/release" simplevault
}

package_windows_zip() {
  local triple=$1
  local bin="target/${triple}/release/simplevault.exe"
  [[ -f "$bin" ]] || error "Missing binary: $bin"
  command -v zip >/dev/null 2>&1 || error "zip not found in PATH (needed for Windows archive)"
  zip -q -j "dist/simplevault-${VERSION}-${triple}.zip" "$bin"
}

for triple in "${CROSS_TARGETS[@]}"; do
  if [[ "$triple" == *windows* ]]; then
    package_windows_zip "$triple"
  else
    package_unix_tgz "$triple"
  fi
done

if [[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]]; then
  [[ -f target/release/simplevault ]] || error "Missing native macOS binary: target/release/simplevault"
  tar czf "dist/simplevault-${VERSION}-aarch64-apple-darwin.tar.gz" -C target/release simplevault
fi

echo ""
echo "Done. Artifacts:"
ls -1 dist/simplevault-"${VERSION}"-* 2>/dev/null || true
