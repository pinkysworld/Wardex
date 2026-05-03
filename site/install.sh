#!/usr/bin/env bash
# Wardex quick-install — downloads the latest release for your platform.
# Usage:  curl -sSfL https://pinkysworld.github.io/Wardex/install.sh | bash
#         curl -sSfL https://pinkysworld.github.io/Wardex/install.sh | bash -s -- --version v0.56.0
set -euo pipefail

REPO="pinkysworld/Wardex"
VERSION=""
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 2 ;;
esac
case "$OS" in
  darwin) PLATFORM="${ARCH}-apple-darwin" ;;
  linux)  PLATFORM="${ARCH}-unknown-linux-gnu" ;;
  *) echo "unsupported OS: $OS" >&2; exit 2 ;;
esac

if [[ -z "$VERSION" ]]; then
  VERSION=$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" | grep -m1 '"tag_name":' | cut -d'"' -f4)
fi
[[ -z "$VERSION" ]] && { echo "could not resolve latest version" >&2; exit 1; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
ASSET="wardex-${VERSION}-${PLATFORM}"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}.tar.gz"
echo "→ downloading ${ASSET} from ${URL}"
curl -sSfL "$URL" -o "$TMP/${ASSET}.tar.gz"
tar -xzf "$TMP/${ASSET}.tar.gz" -C "$TMP"

BIN=$(find "$TMP" -type f -name 'wardex*' -perm -u+x | head -n1)
[[ -z "$BIN" ]] && { echo "wardex binary not found in archive" >&2; exit 1; }

install -m 0755 "$BIN" "${INSTALL_DIR}/wardex"
echo "✓ installed wardex ${VERSION} to ${INSTALL_DIR}/wardex"
"${INSTALL_DIR}/wardex" --version || true
echo
echo "Next: verify provenance with  docs/REPRODUCIBILITY.md"
