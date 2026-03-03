#!/usr/bin/env bash
#
# Verify that Cargo.toml, client/package.json, and VERSION are all in sync.
# Exits with 1 if any mismatch. Run before build.
#
# Usage: ./check-version.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f VERSION ]]; then
  echo "Error: VERSION file not found"
  exit 1
fi

EXPECTED=$(cat VERSION | tr -d '[:space:]')
if [[ -z "$EXPECTED" ]]; then
  echo "Error: VERSION file is empty"
  exit 1
fi

CARGO_VER=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/' | tr -d '[:space:]')
PKG_VER=$(grep '"version"' client/package.json | head -1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | tr -d '[:space:]')

MISMATCH=""
[[ "$CARGO_VER" != "$EXPECTED" ]] && MISMATCH="${MISMATCH}Cargo.toml has version \"$CARGO_VER\" (expected \"$EXPECTED\")\n"
[[ "$PKG_VER" != "$EXPECTED" ]] && MISMATCH="${MISMATCH}client/package.json has version \"$PKG_VER\" (expected \"$EXPECTED\")\n"

if [[ -n "$MISMATCH" ]]; then
  echo "Version mismatch. VERSION file says: $EXPECTED"
  echo ""
  echo -e "$MISMATCH"
  echo "Update Cargo.toml and client/package.json to match VERSION, or update VERSION to match them."
  exit 1
fi

echo "Version check OK: $EXPECTED (Cargo.toml, client/package.json, VERSION)"
