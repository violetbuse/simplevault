#!/usr/bin/env bash
#
# Build all SimpleVault artifacts:
#   1. Docker image (includes Rust release binary)
#   2. Extract binary from image to target/release/
#   3. Optional: multi-platform release archives (see --release-binaries)
#   4. Docs site
#   5. Client library
#
# Usage: ./build-all.sh [--docker-tag TAG] [--release-binaries]
#   --docker-tag TAG     Use TAG for the Docker image (default: simplevault:$(cat VERSION))
#   --release-binaries   Also run scripts/build-release-binaries.sh (Docker + cross + zip;
#                        produces dist/simplevault-<VERSION>-* for Linux x64/arm64, Windows x64,
#                        and on Apple Silicon Mac also macOS arm64)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "0. Version check"
echo "=========================================="
./check-version.sh

VERSION=$(cat VERSION | tr -d '[:space:]')
DOCKER_TAG="simplevault:${VERSION}"
BUILD_RELEASE_BINARIES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker-tag)
      DOCKER_TAG="$2"
      shift 2
      ;;
    --release-binaries)
      BUILD_RELEASE_BINARIES=1
      shift
      ;;
    *)
      shift
      ;;
  esac
done

echo "=========================================="
echo "1. Docker image (Rust release binary)"
echo "=========================================="
docker build --build-arg SIMPLEVAULT_VERSION="$VERSION" -t "$DOCKER_TAG" .

echo ""
echo "=========================================="
echo "2. Extract binary to target/release/"
echo "=========================================="
mkdir -p target/release
cid=$(docker create "$DOCKER_TAG")
docker cp "$cid:/app/simplevault" target/release/simplevault
docker rm "$cid" > /dev/null

if [[ "$BUILD_RELEASE_BINARIES" -eq 1 ]]; then
  echo ""
  echo "=========================================="
  echo "3. Multi-platform release archives (dist/)"
  echo "=========================================="
  "$SCRIPT_DIR/scripts/build-release-binaries.sh"
fi

echo ""
echo "=========================================="
echo "4. Docs site"
echo "=========================================="
cd docs
npm ci
npm run build
cd ..

echo ""
echo "=========================================="
echo "5. Client library"
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
if [[ "$BUILD_RELEASE_BINARIES" -eq 1 ]]; then
  echo "  - Release zips: dist/simplevault-${VERSION}-* (Linux x64/arm64, Windows x64; + macOS arm64 on Apple Silicon)"
fi
echo "  - Docker image: $DOCKER_TAG"
echo "  - Docs site:    docs/dist/"
echo "  - Client:       client/dist/"
