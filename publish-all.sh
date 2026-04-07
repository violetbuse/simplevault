#!/usr/bin/env bash

# Publish all SimpleVault artifacts after they have been built by ./build-all.sh
#
# Prerequisites (run manually before this script):
#   ./build-all.sh   (builds dist/simplevault-<VERSION>-* release archives by default)
#
# This script will:
#   1. Deploy docs to Cloudflare (via wrangler)
#   2. Publish the client package to npm
#   3. Publish the Docker image to GitHub Container Registry (GHCR)
#   4. Create a GitHub release with dist/simplevault-<VERSION>-* archives attached
#      (use --linux-binary-only if you built with ./build-all.sh --no-release-binaries)
#
# Usage: ./publish-all.sh [--linux-binary-only]
#
# Required tools (must already be logged in / configured as needed):
#   - docker
#   - npm (with npm auth for publishing the client)
#   - wrangler (with Cloudflare auth for docs deploy)
#   - gh (GitHub CLI, authenticated to the repo owner)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LINUX_BINARY_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --linux-binary-only)
      LINUX_BINARY_ONLY=1
      shift
      ;;
    *)
      shift
      ;;
  esac
done

error() {
  echo "Error: $*" >&2
  exit 1
}

command -v npm >/dev/null 2>&1 || error "npm not found in PATH"
if ! npm whoami >/dev/null 2>&1; then
  error "You are not logged in to npm. Run 'npm login' and try again."
fi

echo "=========================================="
echo "0. Version check"
echo "=========================================="
./check-version.sh

VERSION="$(tr -d '[:space:]' < VERSION)"
if [[ -z "$VERSION" ]]; then
  error "VERSION file is empty"
fi

# Local Docker image produced by ./build-all.sh
LOCAL_DOCKER_TAG="simplevault:${VERSION}"

# Namespace for GHCR images; override with GHCR_NAMESPACE if needed
GHCR_NAMESPACE="${GHCR_NAMESPACE:-violetbuse}"
GHCR_IMAGE_BASE="ghcr.io/${GHCR_NAMESPACE}/simplevault"

# Git tag used for the release
GIT_TAG="v${VERSION}"

echo "=========================================="
echo "SimpleVault publish-all"
echo "Version:          ${VERSION}"
echo "Git tag:          ${GIT_TAG}"
echo "Local Docker tag: ${LOCAL_DOCKER_TAG}"
echo "GHCR image base:  ${GHCR_IMAGE_BASE}"
echo "=========================================="
echo

command -v docker >/dev/null 2>&1 || error "docker not found in PATH"
command -v gh >/dev/null 2>&1 || error "gh (GitHub CLI) not found in PATH"
command -v wrangler >/dev/null 2>&1 || error "wrangler not found in PATH"

if ! docker image inspect "${LOCAL_DOCKER_TAG}" >/dev/null 2>&1; then
  error "Docker image '${LOCAL_DOCKER_TAG}' not found. Run ./build-all.sh first."
fi

if [[ ! -f target/release/simplevault ]]; then
  error "Binary target/release/simplevault not found. Run ./build-all.sh first."
fi

shopt -s nullglob
RELEASE_ASSETS=(dist/simplevault-"${VERSION}"*.tar.gz dist/simplevault-"${VERSION}"*.zip)
shopt -u nullglob

if [[ ${#RELEASE_ASSETS[@]} -eq 0 ]]; then
  if [[ "$LINUX_BINARY_ONLY" -eq 1 ]]; then
    RELEASE_ASSETS=(target/release/simplevault)
    echo "Note: Publishing Docker-extracted Linux binary only (--linux-binary-only)."
  else
    error "No dist/simplevault-${VERSION}-* archives found. Run ./build-all.sh (release archives are built by default), or pass --linux-binary-only to attach only target/release/simplevault."
  fi
fi

echo "=========================================="
echo "1. Deploy docs to Cloudflare"
echo "=========================================="
(
  cd docs
  npm run deploy
)

echo
echo "=========================================="
echo "2. Publish client package to npm"
echo "=========================================="
(
  cd client
  npm publish
)

echo
echo "=========================================="
echo "3. Publish Docker image to GHCR"
echo "=========================================="

GHCR_VERSION_TAG="${GHCR_IMAGE_BASE}:${VERSION}"
GHCR_LATEST_TAG="${GHCR_IMAGE_BASE}:latest"

echo "Tagging local image '${LOCAL_DOCKER_TAG}' as:"
echo "  - ${GHCR_VERSION_TAG}"
echo "  - ${GHCR_LATEST_TAG}"

docker tag "${LOCAL_DOCKER_TAG}" "${GHCR_VERSION_TAG}"
docker tag "${LOCAL_DOCKER_TAG}" "${GHCR_LATEST_TAG}"

echo "Pushing to GHCR (you must be logged in with 'docker login ghcr.io')"
docker push "${GHCR_VERSION_TAG}"
docker push "${GHCR_LATEST_TAG}"

echo
echo "=========================================="
echo "4. Create GitHub release with binary"
echo "=========================================="

if ! git rev-parse "${GIT_TAG}" >/dev/null 2>&1; then
  echo "Git tag '${GIT_TAG}' does not exist. Creating and pushing it."
  git tag "${GIT_TAG}"
  git push origin "${GIT_TAG}"
else
  echo "Git tag '${GIT_TAG}' already exists."
fi

echo "Creating GitHub release '${GIT_TAG}' (or failing if it already exists)..."
gh release create "${GIT_TAG}" \
  --title "simplevault ${GIT_TAG}" \
  --generate-notes \
  "${RELEASE_ASSETS[@]}"

echo
echo "=========================================="
echo "All publish steps complete"
echo "=========================================="

