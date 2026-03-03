#!/usr/bin/env bash
#
# Build all SimpleVault artifacts:
#   1. Docker image (includes Rust release binary)
#   2. Extract binary from image to target/release/
#   3. Docs site
#   4. Client library
#
# Usage: ./build-all.sh [--docker-tag TAG]
#   --docker-tag TAG  Use TAG for the Docker image (default: simplevault:latest)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DOCKER_TAG="simplevault:latest"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker-tag)
      DOCKER_TAG="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

echo "=========================================="
echo "1. Docker image (Rust release binary)"
echo "=========================================="
docker build -t "$DOCKER_TAG" .

echo ""
echo "=========================================="
echo "2. Extract binary to target/release/"
echo "=========================================="
mkdir -p target/release
cid=$(docker create "$DOCKER_TAG")
docker cp "$cid:/app/simplevault" target/release/simplevault
docker rm "$cid" > /dev/null

echo ""
echo "=========================================="
echo "3. Docs site"
echo "=========================================="
cd docs
npm ci
npm run build
cd ..

echo ""
echo "=========================================="
echo "4. Client library"
echo "=========================================="
cd client
npm ci
npm run build
cd ..

echo ""
echo "=========================================="
echo "All builds complete"
echo "=========================================="
echo ""
echo "Artifacts:"
echo "  - Rust binary:  target/release/simplevault"
echo "  - Docker image: $DOCKER_TAG"
echo "  - Docs site:    docs/dist/"
echo "  - Client:       client/dist/"
