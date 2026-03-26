#!/usr/bin/env bash
#
# Run all SimpleVault tests:
#   1. Rust unit/integration tests (cargo test)
#   2. Rust client transport contract tests
#   3. Client API contract tests against dev server (Node/tsx)
#   4. Client API contract tests against production server (Rust binary)
#   5. DB-enabled query tests (Rust + contract parity via docker compose)
#
# Usage: ./run-all-tests.sh [--no-build] [--no-db-tests]
#   --no-build  Skip building the Rust release binary (contract:rust will fail if not built)
#   --no-db-tests  Skip DB-enabled test suite (run-db-query-tests.sh)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "0. Version check"
echo "=========================================="
./check-version.sh

NO_BUILD=false
NO_DB_TESTS=false
for arg in "$@"; do
  case "$arg" in
    --no-build) NO_BUILD=true ;;
    --no-db-tests) NO_DB_TESTS=true ;;
  esac
done

echo "=========================================="
echo "1. Rust tests (cargo test)"
echo "=========================================="
cargo test

echo ""
echo "=========================================="
echo "2. Rust client transport contract tests"
echo "=========================================="
cargo test --test client_contract --features test-utils

echo ""
echo "=========================================="
echo "3. Contract tests: dev server"
echo "=========================================="
cd client
node test/run-with-dev-server.mjs
cd ..

echo ""
echo "=========================================="
echo "4. Contract tests: production server (Rust)"
echo "=========================================="
if [ "$NO_BUILD" = false ]; then
  echo "Building Rust release binary..."
  cargo build --release
fi

cd client
node test/run-with-rust-server.mjs
cd ..

if [ "$NO_DB_TESTS" = false ]; then
  echo ""
  echo "=========================================="
  echo "5. DB-enabled tests"
  echo "=========================================="
  ./run-db-query-tests.sh
fi

echo ""
echo "=========================================="
echo "All tests passed"
echo "=========================================="
