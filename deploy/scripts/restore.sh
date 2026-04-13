#!/usr/bin/env bash
# Wardex restore script — extracts a backup archive into the var directory
# and validates the restored state.
#
# Usage:
#   restore.sh <archive> [--var-dir /app/var] [--decrypt] [--verify]
#
# Requirements: tar, gzip
# Optional:     age (for decryption), curl (for health-check verification)

set -euo pipefail

VAR_DIR="${WARDEX_VAR_DIR:-./var}"
DECRYPT=false
VERIFY=false
ARCHIVE=""

usage() {
  echo "Usage: $0 <archive-path> [--var-dir DIR] [--decrypt] [--verify]"
  echo ""
  echo "Options:"
  echo "  --var-dir DIR   Target var directory (default: ./var)"
  echo "  --decrypt       Decrypt .age archive before extraction"
  echo "  --verify        Run health check after restore"
  exit 1
}

if [[ $# -lt 1 ]]; then usage; fi

ARCHIVE="$1"; shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --var-dir)  VAR_DIR="$2"; shift 2 ;;
    --decrypt)  DECRYPT=true; shift   ;;
    --verify)   VERIFY=true;  shift   ;;
    -h|--help)  usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ ! -f "${ARCHIVE}" ]]; then
  echo "ERROR: Archive not found: ${ARCHIVE}"
  exit 1
fi

echo "==> Wardex restore starting"
echo "    Archive:  ${ARCHIVE}"
echo "    Target:   ${VAR_DIR}"

# Verify checksum if available
CHECKSUM_FILE=""
for ext in .sha256; do
  if [[ -f "${ARCHIVE}${ext}" ]]; then
    CHECKSUM_FILE="${ARCHIVE}${ext}"
    break
  fi
  # For .age files, check the base archive checksum
  BASE="${ARCHIVE%.age}"
  if [[ -f "${BASE}.sha256" ]]; then
    CHECKSUM_FILE="${BASE}.sha256"
    break
  fi
done

if [[ -n "${CHECKSUM_FILE}" ]]; then
  echo "    Verifying checksum..."
  if command -v sha256sum &>/dev/null; then
    sha256sum -c "${CHECKSUM_FILE}"
  elif command -v shasum &>/dev/null; then
    shasum -a 256 -c "${CHECKSUM_FILE}"
  fi
fi

WORK_ARCHIVE="${ARCHIVE}"

# Decrypt if needed
if [[ "${DECRYPT}" == "true" ]] || [[ "${ARCHIVE}" == *.age ]]; then
  if ! command -v age &>/dev/null; then
    echo "ERROR: 'age' not found. Install via: brew install age  OR  apt install age"
    exit 1
  fi
  WORK_ARCHIVE=$(mktemp /tmp/wardex-restore-XXXXXX.tar.gz)
  echo "    Decrypting..."
  age -d -o "${WORK_ARCHIVE}" "${ARCHIVE}"
fi

# Create backup of current state before overwriting
if [[ -d "${VAR_DIR}" ]] && [[ "$(ls -A "${VAR_DIR}" 2>/dev/null)" ]]; then
  TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
  PRE_RESTORE="${VAR_DIR}/../pre-restore-${TIMESTAMP}.tar.gz"
  echo "    Saving current state to ${PRE_RESTORE}..."
  tar -czf "${PRE_RESTORE}" -C "$(dirname "${VAR_DIR}")" "$(basename "${VAR_DIR}")"
fi

# Extract
mkdir -p "${VAR_DIR}"
echo "    Extracting archive..."
tar -xzf "${WORK_ARCHIVE}" -C "${VAR_DIR}"

# Cleanup temp file
if [[ "${WORK_ARCHIVE}" != "${ARCHIVE}" ]]; then
  rm -f "${WORK_ARCHIVE}"
fi

# List restored items
echo "    Restored contents:"
ls -la "${VAR_DIR}" | tail -n +2 | while read -r line; do
  echo "      ${line}"
done

# Verify health (optional)
if [[ "${VERIFY}" == "true" ]]; then
  WARDEX_PORT="${WARDEX_PORT:-9077}"
  echo "    Checking health at http://localhost:${WARDEX_PORT}/api/healthz/ready ..."
  sleep 2
  if curl -sf "http://localhost:${WARDEX_PORT}/api/healthz/ready" >/dev/null 2>&1; then
    echo "    Health check: PASSED"
  else
    echo "    Health check: FAILED (service may need restart)"
    echo "    Try: systemctl restart wardex  OR  brew services restart wardex"
  fi
fi

echo "==> Restore complete"
