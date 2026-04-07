#!/usr/bin/env bash
#
# Install or upgrade simplevault from GitHub Releases (Linux x86_64/arm64, macOS Apple Silicon).
# If simplevault is already on PATH (or in the install prefix), compares --version to the
# latest release and skips when up to date unless --force is passed.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/violetbuse/simplevault/master/install.sh | bash
#   curl -fsSL ... | bash -s -- --help
#
# Environment:
#   SIMPLEVAULT_INSTALL_REPO   default: violetbuse/simplevault  (owner/name)
#   SIMPLEVAULT_INSTALL_PREFIX default: $HOME/.local/bin
#
set -euo pipefail

GITHUB_REPO="${SIMPLEVAULT_INSTALL_REPO:-violetbuse/simplevault}"
INSTALL_PREFIX="${SIMPLEVAULT_INSTALL_PREFIX:-$HOME/.local/bin}"
DRY_RUN=0
FORCE=0

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Installs simplevault from the latest GitHub release. If already installed, checks
for a newer release and upgrades when needed.

Options:
  --prefix DIR   Install binary to DIR (default: $HOME/.local/bin or SIMPLEVAULT_INSTALL_PREFIX)
  --force        Download and install latest even if the same version is already installed
  --dry-run      Print actions without downloading or writing files
  -h, --help     Show this help

Environment:
  SIMPLEVAULT_INSTALL_REPO    GitHub repo as owner/name (default: violetbuse/simplevault)
  SIMPLEVAULT_INSTALL_PREFIX  Install directory (default: $HOME/.local/bin)

Supported platforms: Linux (x86_64, aarch64), macOS (arm64 only; Intel Mac has no release archive).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --prefix)
      INSTALL_PREFIX="${2:-}"
      if [[ -z "$INSTALL_PREFIX" ]]; then
        echo "Error: --prefix requires a directory" >&2
        exit 1
      fi
      shift 2
      ;;
    *)
      echo "Error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

error() {
  echo "Error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || error "'$1' not found in PATH (required)"
}

download() {
  local url=$1
  local out=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$out" "$url"
  else
    error "Need curl or wget to download"
  fi
}

resolve_triple() {
  local os arch
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Linux)
      case "$arch" in
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64 | arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) error "Unsupported Linux architecture: $arch (need x86_64 or aarch64)" ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        arm64) echo "aarch64-apple-darwin" ;;
        x86_64)
          error "No pre-built binary for Intel Mac. Use Docker, build from source, or see https://github.com/${GITHUB_REPO}/releases"
          ;;
        *) error "Unsupported macOS architecture: $arch" ;;
      esac
      ;;
    *)
      error "Unsupported OS: $os (this script supports Linux and macOS)"
      ;;
  esac
}

fetch_latest_version() {
  need_cmd curl
  local json url
  url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
  json=$(curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$url") || error "Failed to fetch latest release from GitHub (check repo name and network)"

  LATEST_VERSION=$(printf '%s' "$json" | tr ',' '\n' | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v?([^"]+)".*/\1/')
  if [[ -z "${LATEST_VERSION:-}" ]]; then
    error "Could not parse latest release tag from GitHub API"
  fi
}

existing_binary() {
  if command -v simplevault >/dev/null 2>&1; then
    command -v simplevault
    return
  fi
  local p="${INSTALL_PREFIX%/}/simplevault"
  if [[ -x "$p" ]]; then
    echo "$p"
    return
  fi
  return 1
}

version_newer() {
  # Return 0 if $1 > $2 in semver-ish sort
  local a=$1 b=$2 hi
  hi=$(printf '%s\n' "$a" "$b" | sort -V | tail -1)
  [[ "$hi" == "$a" && "$a" != "$b" ]]
}

TRIPLE=$(resolve_triple)
fetch_latest_version

EXISTING=""
if bin=$(existing_binary 2>/dev/null); then
  EXISTING=$bin
fi

CURRENT=""
if [[ -n "$EXISTING" ]]; then
  CURRENT=$("$EXISTING" --version 2>/dev/null | awk '{print $2}' || true)
fi

if [[ -n "$CURRENT" && "$CURRENT" == "$LATEST_VERSION" && "$FORCE" -eq 0 ]]; then
  echo "simplevault $CURRENT is already the latest release."
  echo "  Binary: $EXISTING"
  echo "Re-run with --force to reinstall, or set SIMPLEVAULT_INSTALL_PREFIX to install elsewhere."
  exit 0
fi

if [[ -n "$CURRENT" && "$CURRENT" != "$LATEST_VERSION" ]]; then
  if version_newer "$CURRENT" "$LATEST_VERSION"; then
    echo "Installed simplevault $CURRENT is newer than latest release $LATEST_VERSION."
    echo "  Binary: $EXISTING"
    echo "Use --force to replace it with $LATEST_VERSION anyway."
    exit 0
  fi
  echo "Upgrading simplevault $CURRENT -> $LATEST_VERSION"
elif [[ -z "$CURRENT" && -n "$EXISTING" ]]; then
  echo "Could not read version from $EXISTING; installing latest $LATEST_VERSION"
elif [[ -z "$EXISTING" ]]; then
  echo "Installing simplevault $LATEST_VERSION -> ${INSTALL_PREFIX%/}/simplevault"
fi

ASSET="simplevault-${LATEST_VERSION}-${TRIPLE}.tar.gz"
TAG="v${LATEST_VERSION}"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${ASSET}"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Would download: $DOWNLOAD_URL"
  echo "Would install to: ${INSTALL_PREFIX%/}/simplevault"
  exit 0
fi

need_cmd tar
TMPDIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

ARCHIVE="${TMPDIR}/${ASSET}"
download "$DOWNLOAD_URL" "$ARCHIVE"
tar xzf "$ARCHIVE" -C "$TMPDIR"
[[ -f "${TMPDIR}/simplevault" ]] || error "Archive did not contain simplevault binary"

mkdir -p "$INSTALL_PREFIX"
chmod 755 "${TMPDIR}/simplevault"
mv "${TMPDIR}/simplevault" "${INSTALL_PREFIX%/}/simplevault"

echo "Installed simplevault $LATEST_VERSION to ${INSTALL_PREFIX%/}/simplevault"

if [[ ":${PATH}:" != *":${INSTALL_PREFIX%/}:"* ]]; then
  echo
  echo "Add to PATH if needed:"
  echo "  export PATH=\"${INSTALL_PREFIX%/}:\$PATH\""
  # shellcheck disable=SC2016
  echo "  (add that line to ~/.bashrc or ~/.zshrc)"
fi
