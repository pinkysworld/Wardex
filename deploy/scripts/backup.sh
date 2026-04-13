#!/usr/bin/env bash
# Wardex backup script — produces an encrypted, timestamped archive of all
# persistent state.  Intended for cron / systemd-timer scheduling.
#
# Usage:
#   backup.sh [--var-dir /app/var] [--out-dir /backups] [--encrypt] [--retention 30]
#
# Requirements: tar, gzip, sha256sum (or shasum on macOS)
# Optional:     age (https://github.com/FiloSottile/age) for encryption

set -euo pipefail

VAR_DIR="${WARDEX_VAR_DIR:-./var}"
OUT_DIR="${WARDEX_BACKUP_DIR:-./var/backups}"
ENCRYPT=false
RETENTION_DAYS=30
AGE_RECIPIENT="${WARDEX_BACKUP_AGE_RECIPIENT:-}"

usage() {
  echo "Usage: $0 [--var-dir DIR] [--out-dir DIR] [--encrypt] [--retention DAYS]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --var-dir)    VAR_DIR="$2";       shift 2 ;;
    --out-dir)    OUT_DIR="$2";       shift 2 ;;
    --encrypt)    ENCRYPT=true;       shift   ;;
    --retention)  RETENTION_DAYS="$2"; shift 2 ;;
    -h|--help)    usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
ARCHIVE_NAME="wardex-backup-${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"

mkdir -p "${OUT_DIR}"

echo "==> Wardex backup starting at ${TIMESTAMP}"
echo "    Source:    ${VAR_DIR}"
echo "    Target:    ${ARCHIVE_PATH}"

# Collect all persistent data paths relative to VAR_DIR
BACKUP_PATHS=()
for item in storage cases.json incidents.json reports.json enterprise.json \
            deployments.json agents.json events.json checkpoints policy keys \
            updates spool; do
  if [[ -e "${VAR_DIR}/${item}" ]]; then
    BACKUP_PATHS+=("${item}")
  fi
done

if [[ ${#BACKUP_PATHS[@]} -eq 0 ]]; then
  echo "WARNING: No data found in ${VAR_DIR} — nothing to back up."
  exit 0
fi

echo "    Items:     ${BACKUP_PATHS[*]}"

# Create tar archive
tar -czf "${ARCHIVE_PATH}" -C "${VAR_DIR}" "${BACKUP_PATHS[@]}"

# Optional encryption with age
if [[ "${ENCRYPT}" == "true" ]]; then
  if ! command -v age &>/dev/null; then
    echo "ERROR: 'age' not found. Install via: brew install age  OR  apt install age"
    exit 1
  fi
  if [[ -z "${AGE_RECIPIENT}" ]]; then
    echo "ERROR: Set WARDEX_BACKUP_AGE_RECIPIENT to an age public key or identity file."
    exit 1
  fi
  age -r "${AGE_RECIPIENT}" -o "${ARCHIVE_PATH}.age" "${ARCHIVE_PATH}"
  rm -f "${ARCHIVE_PATH}"
  ARCHIVE_PATH="${ARCHIVE_PATH}.age"
  echo "    Encrypted: ${ARCHIVE_PATH}"
fi

# Generate checksum
if command -v sha256sum &>/dev/null; then
  sha256sum "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"
elif command -v shasum &>/dev/null; then
  shasum -a 256 "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"
fi

SIZE=$(du -h "${ARCHIVE_PATH}" | cut -f1)
echo "    Size:      ${SIZE}"

# Enforce retention — delete backups older than RETENTION_DAYS
if [[ "${RETENTION_DAYS}" -gt 0 ]]; then
  DELETED=$(find "${OUT_DIR}" -name 'wardex-backup-*' -mtime +"${RETENTION_DAYS}" -print -delete | wc -l)
  if [[ "${DELETED}" -gt 0 ]]; then
    echo "    Pruned:    ${DELETED} backup(s) older than ${RETENTION_DAYS} days"
  fi
fi

echo "==> Backup complete: ${ARCHIVE_PATH}"
