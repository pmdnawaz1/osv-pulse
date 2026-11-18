#!/usr/bin/env bash
# Download a pinned osv-scanner binary and verify its checksum.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${OSV_SCANNER_VERSION:-v2.7.1}"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux) OS_PART=linux ;;
  Darwin) OS_PART=darwin ;;
  *) echo "Unsupported operating system: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH_PART=amd64 ;;
  arm64|aarch64) ARCH_PART=arm64 ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

ASSET="osv-scanner_${OS_PART}_${ARCH_PART}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"
BASE_URL="https://github.com/google/osv-scanner/releases/download/${VERSION}"
curl -fsSLO "${BASE_URL}/${ASSET}"
curl -fsSLO "${BASE_URL}/osv-scanner_SHA256SUMS"
grep " ${ASSET}\$" osv-scanner_SHA256SUMS | sha256sum --check -
chmod +x "$ASSET"

mkdir -p "$ROOT/bin"
mv "$ASSET" "$ROOT/bin/osv-scanner"
echo "Installed $ASSET ($VERSION) to $ROOT/bin/osv-scanner"
echo "Use it with: export OSV_SCANNER_BIN=$ROOT/bin/osv-scanner"
