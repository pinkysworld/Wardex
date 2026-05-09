#!/usr/bin/env bash

set -euo pipefail

BASE_URL="${WARDEX_BASE_URL:-http://127.0.0.1:8080}"
TOKEN="${WARDEX_ADMIN_TOKEN:-wardex-live-token}"
PACKS=(
  credential_storm
  slow_escalation
  low_battery_attack
  c2_beaconing
  benign_baseline
)

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

response=$(curl --silent --show-error --fail --max-time 15 \
  -H "Authorization: Bearer ${TOKEN}" \
  "${BASE_URL}/api/detection/validation-packs")

printf '%s\n' "$response" | grep -q '"suite_execution"'
printf 'validation-pack-inventory ok\n'

missing=0
for pack in "${PACKS[@]}"; do
  case "$pack" in
    credential_storm) fixture="examples/credential_storm.csv" ;;
    slow_escalation) fixture="examples/slow_escalation.csv" ;;
    low_battery_attack) fixture="examples/low_battery_attack.csv" ;;
    c2_beaconing) fixture="examples/credential_storm_extended.csv" ;;
    benign_baseline) fixture="examples/benign_baseline.csv" ;;
  esac
  if [[ -f "$fixture" ]]; then
    printf '%s fixture=%s status=ready\n' "$pack" "$fixture"
  else
    printf '%s fixture=%s status=missing\n' "$pack" "$fixture"
    missing=$((missing + 1))
  fi
done

if [[ "$missing" -gt 0 ]]; then
  echo "error: ${missing} validation pack fixture(s) missing" >&2
  exit 1
fi
