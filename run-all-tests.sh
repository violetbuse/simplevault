#!/usr/bin/env bash
#
# Run all SimpleVault tests:
#   1. Rust unit/integration tests (cargo test)
#   2. Client API contract tests against dev server (Node/tsx)
#   3. Client API contract tests against production server (Rust binary)
#
# Usage: ./run-all-tests.sh [--no-build]
#   --no-build  Skip building the Rust release binary (contract:rust will fail if not built)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

NO_BUILD=false
for arg in "$@"; do
  case "$arg" in
    --no-build) NO_BUILD=true ;;
  esac
done

echo "=========================================="
echo "1. Rust tests (cargo test)"
echo "=========================================="
cargo test

echo ""
echo "=========================================="
echo "2. Contract tests: dev server"
echo "=========================================="
cd client
node test/run-with-dev-server.mjs
cd ..

echo ""
echo "=========================================="
echo "3. Contract tests: production server (Rust)"
echo "=========================================="
if [ "$NO_BUILD" = false ]; then
  echo "Building Rust release binary..."
  cargo build --release
fi

cd client
node test/run-with-rust-server.mjs
cd ..

echo ""
echo "=========================================="
echo "All tests passed"
echo "=========================================="
