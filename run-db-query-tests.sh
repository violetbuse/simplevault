#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.db-test.yml"

export SIMPLEVAULT_ENABLE_DB_TESTS=1

if [ -z "${SIMPLEVAULT_TEST_DB_PORT:-}" ]; then
  SIMPLEVAULT_TEST_DB_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
fi
export SIMPLEVAULT_TEST_DB_PORT

export SIMPLEVAULT_TEST_DB_URL="${SIMPLEVAULT_TEST_DB_URL:-postgres://simplevault:simplevault@127.0.0.1:${SIMPLEVAULT_TEST_DB_PORT}/simplevault_test}"
echo "Using DB test port: ${SIMPLEVAULT_TEST_DB_PORT}"

docker compose -f "$COMPOSE_FILE" up -d
cleanup() {
  docker compose -f "$COMPOSE_FILE" down -v
}
trap cleanup EXIT

echo "Waiting for postgres health..."
healthy=false
for _ in $(seq 1 30); do
  compose_ps_json="$(docker compose -f "$COMPOSE_FILE" ps --format json || true)"
  if [[ "$compose_ps_json" == *'"Health":"healthy"'* ]]; then
    healthy=true
    break
  fi
  sleep 1
done

if [ "$healthy" != "true" ]; then
  echo "Postgres did not become healthy in time"
  docker compose -f "$COMPOSE_FILE" ps
  exit 1
fi

# echo "Running Rust tests with DB enabled..."
# cargo test db_query_ -- --nocapture

echo "Running contract tests against Node dev server..."
cd client
node test/run-with-dev-server.mjs

echo "Building Rust release binary..."
cd ..
cargo build --release

echo "Running contract tests against Rust server..."
cd client
node test/run-with-rust-server.mjs
