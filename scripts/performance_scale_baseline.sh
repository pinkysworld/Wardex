#!/usr/bin/env bash

set -euo pipefail

BASE_URL="${WARDEX_BASE_URL:-http://127.0.0.1:8080}"
TOKEN="${WARDEX_ADMIN_TOKEN:-wardex-live-token}"
BUDGET_MS="${WARDEX_PERF_BUDGET_MS:-1500}"
MODE="${1:-all}"

need_curl() {
  if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl is required" >&2
    exit 1
  fi
}

measure_endpoint() {
  local path="$1"
  local label="$2"
  local elapsed_ms
  elapsed_ms=$(curl --silent --show-error --fail --max-time 15 \
    -H "Authorization: Bearer ${TOKEN}" \
    -o /dev/null \
    -w '%{time_total}' \
    "${BASE_URL}${path}" | awk '{ printf "%d", ($1 * 1000) }')
  printf '%s %sms\n' "$label" "$elapsed_ms"
  if [[ "$elapsed_ms" -gt "$BUDGET_MS" ]]; then
    echo "error: ${label} exceeded ${BUDGET_MS}ms budget" >&2
    return 1
  fi
}

need_curl

case "$MODE" in
  --api-error-rate)
    measure_endpoint "/api/performance/scale-baseline" "performance-scale-baseline"
    ;;
  --launchpad)
    measure_endpoint "/api/release/clean-cut" "clean-release-cut"
    measure_endpoint "/api/containers/release-parity" "container-release-parity"
    measure_endpoint "/api/release/verification-center" "release-verification-center"
    measure_endpoint "/api/deployment/self-hosted-wizard" "deployment-wizard"
    measure_endpoint "/api/data-quality/dashboard" "data-quality-dashboard"
    measure_endpoint "/api/performance/scale-baseline" "performance-scale-baseline"
    measure_endpoint "/api/cluster/failover-execution" "cluster-failover-execution"
    measure_endpoint "/api/secrets/rotation-operations" "secrets-rotation-operations"
    measure_endpoint "/api/operator/task-automation" "operator-task-automation"
    measure_endpoint "/api/detection/validation-packs" "detection-validation-packs"
    ;;
  --retained-events)
    measure_endpoint "/api/events/page?limit=25" "retained-event-page"
    ;;
  --support-bundle)
    measure_endpoint "/api/support/bundle" "support-bundle"
    ;;
  all)
    "$0" --launchpad
    "$0" --retained-events
    "$0" --support-bundle
    ;;
  *)
    echo "usage: $0 [all|--api-error-rate|--launchpad|--retained-events|--support-bundle]" >&2
    exit 2
    ;;
esac
