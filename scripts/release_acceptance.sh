#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAYWRIGHT_CLI="$ROOT_DIR/admin-console/node_modules/@playwright/test/cli.js"
PLAYWRIGHT_NODE_MODULES="$ROOT_DIR/admin-console/node_modules"
BASE_URL="${WARDEX_BASE_URL:-http://127.0.0.1:8080}"
TOKEN_FILE="${WARDEX_ADMIN_TOKEN_FILE:-/tmp/wardex_smoke_token}"

require_file() {
  local path="$1"
  local message="$2"
  if [[ ! -f "$path" ]]; then
    echo "error: $message" >&2
    exit 1
  fi
}

run_step() {
  local title="$1"
  shift
  echo
  echo "==> $title"
  "$@"
}

check_site_links() {
  local missing=0
  local file
  local href
  local target

  cd "$ROOT_DIR/site"
  for file in *.html; do
    while IFS= read -r href; do
      target="${href%%[#?]*}"
      case "$target" in
        ""|\#*|http:*|https:*|mailto:*|tel:*|javascript:*|data:*|'${'*)
          continue
          ;;
      esac
      if [[ ! -e "$target" && ! -d "$target" ]]; then
        echo "$file -> $target"
        missing=1
      fi
    done < <(grep -o 'href="[^"]*"' "$file" | sed 's/^href="//; s/"$//')
  done

  if [[ "$missing" -ne 0 ]]; then
    echo "error: site link validation failed" >&2
    exit 1
  fi
}

run_live_smokes() {
  cd "$ROOT_DIR"
  node "$PLAYWRIGHT_CLI" test \
    tests/playwright/live_release_smoke.spec.js \
    tests/playwright/advanced_console_workflows.spec.js \
    tests/playwright/enterprise_console_smoke.spec.js \
    tests/playwright/assistant_ticketing_live.spec.js \
    tests/playwright/siem_settings_live.spec.js \
    tests/playwright/mobile_topbar_smoke.spec.js
}

require_file "$PLAYWRIGHT_CLI" "Playwright CLI not found at $PLAYWRIGHT_CLI. Run npm ci in admin-console first."
require_file "$PLAYWRIGHT_NODE_MODULES/@playwright/test/package.json" "@playwright/test is not installed in admin-console/node_modules. Run npm ci in admin-console first."

if [[ -z "${WARDEX_ADMIN_TOKEN:-}" ]]; then
  require_file "$TOKEN_FILE" "WARDEX_ADMIN_TOKEN is not set and no token file was found at $TOKEN_FILE."
  export WARDEX_ADMIN_TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
fi

if [[ -z "$WARDEX_ADMIN_TOKEN" ]]; then
  echo "error: WARDEX_ADMIN_TOKEN is empty" >&2
  exit 1
fi

export WARDEX_BASE_URL="$BASE_URL"
export NODE_PATH="$PLAYWRIGHT_NODE_MODULES${NODE_PATH:+:$NODE_PATH}"

run_step "Build admin console" bash -lc "cd '$ROOT_DIR/admin-console' && npm run build"
run_step "Build Wardex" bash -lc "cd '$ROOT_DIR' && cargo build"
run_step "Check published site links" check_site_links
run_step "Verify live Wardex admin is reachable at $WARDEX_BASE_URL" curl --silent --show-error --fail --max-time 10 "$WARDEX_BASE_URL/admin/"
run_step "Run routed release smoke suite" run_live_smokes

echo
echo "Release acceptance checks passed for $WARDEX_BASE_URL"