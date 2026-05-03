#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAYWRIGHT_CLI="$ROOT_DIR/admin-console/node_modules/@playwright/test/cli.js"
PLAYWRIGHT_NODE_MODULES="$ROOT_DIR/admin-console/node_modules"
RELEASE_MODE="${WARDEX_RELEASE_ACCEPTANCE_MODE:-managed}"
BASE_URL="${WARDEX_BASE_URL:-}"
TOKEN_FILE="${WARDEX_ADMIN_TOKEN_FILE:-/tmp/wardex_smoke_token}"
MANAGED_STARTUP_TIMEOUT_SECS="${WARDEX_RELEASE_ACCEPTANCE_STARTUP_TIMEOUT_SECS:-180}"
MANAGED_SERVER_PID=""
MANAGED_SERVER_LOG=""
MANAGED_CONFIG_PATH=""
MANAGED_TOKEN_FILE=""

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

cleanup() {
  local exit_code="$1"

  if [[ -n "$MANAGED_SERVER_PID" ]]; then
    kill "$MANAGED_SERVER_PID" 2>/dev/null || true
    wait "$MANAGED_SERVER_PID" 2>/dev/null || true
  fi

  if [[ -n "$MANAGED_SERVER_LOG" && -f "$MANAGED_SERVER_LOG" ]]; then
    if [[ "$exit_code" -ne 0 ]]; then
      echo >&2
      echo "Managed Wardex log: $MANAGED_SERVER_LOG" >&2
      tail -n 80 "$MANAGED_SERVER_LOG" >&2 || true
    else
      rm -f "$MANAGED_SERVER_LOG"
    fi
  fi

  rm -f "$MANAGED_CONFIG_PATH" "$MANAGED_TOKEN_FILE"
  return "$exit_code"
}

trap 'cleanup "$?"' EXIT

pick_free_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

make_temp_path() {
  local prefix="$1"
  local suffix="${2:-}"

  python3 - "$prefix" "$suffix" <<'PY'
import os
import sys
import tempfile

prefix = sys.argv[1]
suffix = sys.argv[2]
tmp_dir = os.environ.get("TMPDIR") or None

handle = tempfile.NamedTemporaryFile(prefix=f"{prefix}-", suffix=suffix, dir=tmp_dir, delete=False)
handle.close()
print(handle.name)
PY
}

resolve_managed_base_url() {
  local requested_url="$1"

  if [[ -z "$requested_url" ]]; then
    local port
    port="$(pick_free_port)"
    echo "http://127.0.0.1:${port}"
    return 0
  fi

  python3 - "$requested_url" <<'PY'
from urllib.parse import urlparse
import sys

parsed = urlparse(sys.argv[1])
if parsed.scheme != "http":
    raise SystemExit("error: managed release acceptance only supports http loopback URLs")
if parsed.hostname not in {"127.0.0.1", "localhost"}:
    raise SystemExit("error: managed release acceptance requires WARDEX_BASE_URL to target localhost or 127.0.0.1")
if parsed.port is None:
    raise SystemExit("error: managed release acceptance requires WARDEX_BASE_URL to include an explicit port")

print(f"http://127.0.0.1:{parsed.port}")
PY
}

base_url_port() {
  python3 - "$1" <<'PY'
from urllib.parse import urlparse
import sys

parsed = urlparse(sys.argv[1])
if parsed.port is None:
    raise SystemExit("error: WARDEX_BASE_URL must include a port")

print(parsed.port)
PY
}

ensure_admin_token() {
  if [[ -n "${WARDEX_ADMIN_TOKEN:-}" ]]; then
    return 0
  fi

  if [[ -f "$TOKEN_FILE" ]]; then
    export WARDEX_ADMIN_TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
    return 0
  fi

  if [[ "$RELEASE_MODE" != "managed" ]]; then
    echo "error: WARDEX_ADMIN_TOKEN is not set and no token file was found at $TOKEN_FILE." >&2
    exit 1
  fi

  MANAGED_TOKEN_FILE="$(make_temp_path "wardex-release-acceptance-token")"
  export WARDEX_ADMIN_TOKEN="$(python3 - <<'PY'
import secrets

print(secrets.token_hex(32))
PY
)"
  printf '%s\n' "$WARDEX_ADMIN_TOKEN" > "$MANAGED_TOKEN_FILE"
  TOKEN_FILE="$MANAGED_TOKEN_FILE"
  export WARDEX_ADMIN_TOKEN_FILE="$TOKEN_FILE"
}

write_managed_config() {
  local source_config="$ROOT_DIR/var/wardex.toml"

  if [[ ! -f "$source_config" ]]; then
    # In CI checkouts the var/ directory is gitignored and the operator-managed
    # base config is absent. Seed a clean default via the binary's init-config
    # subcommand so managed release acceptance can rewrite the loopback bits below.
    mkdir -p "$ROOT_DIR/var"
    (cd "$ROOT_DIR" && cargo run --quiet --release -- init-config "$source_config" >/dev/null) \
      || require_file "$source_config" "Managed release acceptance needs a base config at $source_config."
  fi

  require_file "$source_config" "Managed release acceptance needs a base config at $source_config."

  python3 - "$source_config" "$MANAGED_CONFIG_PATH" "$BASE_URL" <<'PY'
import pathlib
import re
import sys

source_path = pathlib.Path(sys.argv[1])
dest_path = pathlib.Path(sys.argv[2])
base_url = sys.argv[3]
text = source_path.read_text(encoding="utf-8")

patterns = [
    (r"(?m)^server_url\s*=\s*\".*\"$", f'server_url = "{base_url}"'),
    (r"(?m)^rate_limit_read_per_minute\s*=\s*\d+\s*$", "rate_limit_read_per_minute = 0"),
    (r"(?m)^rate_limit_write_per_minute\s*=\s*\d+\s*$", "rate_limit_write_per_minute = 0"),
]

for pattern, replacement in patterns:
    text, count = re.subn(pattern, replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"error: could not update acceptance config pattern {pattern!r}")

dest_path.write_text(text, encoding="utf-8")
PY
}

wait_for_managed_admin() {
  local attempts=0

  until curl --silent --show-error --fail --max-time 2 "$BASE_URL/admin/" >/dev/null; do
    attempts=$((attempts + 1))

    if ! kill -0 "$MANAGED_SERVER_PID" 2>/dev/null; then
      echo "error: managed Wardex exited before $BASE_URL became reachable" >&2
      return 1
    fi

    if [[ "$attempts" -ge "$MANAGED_STARTUP_TIMEOUT_SECS" ]]; then
      echo "error: timed out waiting for managed Wardex at $BASE_URL" >&2
      return 1
    fi

    sleep 1
  done
}

start_managed_wardex() {
  local managed_port
  managed_port="$(base_url_port "$BASE_URL")"

  MANAGED_CONFIG_PATH="$(make_temp_path "wardex-release-acceptance-config" ".toml")"
  MANAGED_SERVER_LOG="$(make_temp_path "wardex-release-acceptance-log" ".log")"

  write_managed_config

  (
    cd "$ROOT_DIR"
    WARDEX_CONFIG_PATH="$MANAGED_CONFIG_PATH" \
      WARDEX_ADMIN_TOKEN="$WARDEX_ADMIN_TOKEN" \
      ./target/debug/wardex start --port "$managed_port"
  ) >"$MANAGED_SERVER_LOG" 2>&1 &
  MANAGED_SERVER_PID=$!

  wait_for_managed_admin
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
  PLAYWRIGHT_HTML_OUTPUT_DIR="${PLAYWRIGHT_HTML_OUTPUT_DIR:-$ROOT_DIR/playwright-report}" \
  PLAYWRIGHT_HTML_OPEN="${PLAYWRIGHT_HTML_OPEN:-never}" \
  node "$PLAYWRIGHT_CLI" test \
    --reporter=list,html \
    tests/playwright/live_release_smoke.spec.js \
    tests/playwright/advanced_console_workflows.spec.js \
    tests/playwright/enterprise_console_smoke.spec.js \
    tests/playwright/assistant_ticketing_live.spec.js \
    tests/playwright/siem_settings_live.spec.js \
    tests/playwright/mobile_topbar_smoke.spec.js
}

require_file "$PLAYWRIGHT_CLI" "Playwright CLI not found at $PLAYWRIGHT_CLI. Run npm ci in admin-console first."
require_file "$PLAYWRIGHT_NODE_MODULES/@playwright/test/package.json" "@playwright/test is not installed in admin-console/node_modules. Run npm ci in admin-console first."

if [[ "$RELEASE_MODE" != "managed" && "$RELEASE_MODE" != "external" ]]; then
  echo "error: WARDEX_RELEASE_ACCEPTANCE_MODE must be either managed or external" >&2
  exit 1
fi

if [[ "$RELEASE_MODE" == "managed" ]]; then
  BASE_URL="$(resolve_managed_base_url "$BASE_URL")"
else
  BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
fi

ensure_admin_token

if [[ -z "$WARDEX_ADMIN_TOKEN" ]]; then
  echo "error: WARDEX_ADMIN_TOKEN is empty" >&2
  exit 1
fi

export WARDEX_BASE_URL="$BASE_URL"
export NODE_PATH="$PLAYWRIGHT_NODE_MODULES${NODE_PATH:+:$NODE_PATH}"

run_step "Build admin console" bash -lc "cd '$ROOT_DIR/admin-console' && npm run build"
run_step "Build Wardex" bash -lc "cd '$ROOT_DIR' && cargo build"
run_step "Check API and SDK contract parity" python3 "$ROOT_DIR/scripts/check_contract_parity.py"
run_step "Check release documentation consistency" python3 "$ROOT_DIR/scripts/validate_release_docs.py"
run_step "Check published site links" check_site_links
if [[ "$RELEASE_MODE" == "managed" ]]; then
  run_step "Start temporary Wardex release instance at $WARDEX_BASE_URL" start_managed_wardex
fi
run_step "Verify live Wardex admin is reachable at $WARDEX_BASE_URL" curl --silent --show-error --fail --max-time 10 "$WARDEX_BASE_URL/admin/"
run_step "Run routed release smoke suite" run_live_smokes

echo
echo "Release acceptance checks passed for $WARDEX_BASE_URL"
