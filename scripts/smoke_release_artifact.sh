#!/usr/bin/env bash

set -euo pipefail

MODE="${1:-}"
shift || true

TMP_ROOT=""
SERVER_PID=""
CONTAINER_NAME=""
PACKAGE_NAME="wardex"
PACKAGE_MANAGER=""
SMOKE_TIMEOUT_SECS="${WARDEX_RELEASE_SMOKE_TIMEOUT_SECS:-90}"

usage() {
  cat <<'EOF'
Usage:
  scripts/smoke_release_artifact.sh archive <artifact.tar.gz>
  scripts/smoke_release_artifact.sh binary <binary_path> <site_dir>
  scripts/smoke_release_artifact.sh deb <artifact.deb>
  scripts/smoke_release_artifact.sh rpm <artifact.rpm>
  scripts/smoke_release_artifact.sh container <image_ref>

The smoke test proves:
  - wardex --version
  - wardex doctor
  - server start
  - GET /api/healthz/ready
  - GET /admin/
  - GET /api/support/bundle (with admin bearer token)
EOF
}

cleanup() {
  local exit_code="${1:-0}"

  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi

  if [[ -n "$CONTAINER_NAME" ]]; then
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi

  if [[ "${WARDEX_RELEASE_SMOKE_REMOVE_PACKAGE:-1}" == "1" ]]; then
    case "$PACKAGE_MANAGER" in
      apt)
        sudo apt-get remove -y "$PACKAGE_NAME" >/dev/null 2>&1 || true
        ;;
      rpm)
        sudo rpm -e "$PACKAGE_NAME" >/dev/null 2>&1 || true
        ;;
    esac
  fi

  if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
    rm -rf "$TMP_ROOT"
  fi

  exit "$exit_code"
}

trap 'cleanup "$?"' EXIT

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command '$cmd' is not available" >&2
    exit 1
  fi
}

make_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/wardex-release-smoke-XXXXXX"
}

pick_free_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

random_token() {
  python3 - <<'PY'
import secrets

print(secrets.token_hex(32))
PY
}

wait_for_http() {
  local url="$1"
  local header_name="${2:-}"
  local header_value="${3:-}"
  local attempt=0

  while true; do
    if [[ -n "$header_name" ]]; then
      if curl --silent --show-error --fail --max-time 2 -H "$header_name: $header_value" "$url" >/dev/null; then
        return 0
      fi
    else
      if curl --silent --show-error --fail --max-time 2 "$url" >/dev/null; then
        return 0
      fi
    fi

    attempt=$((attempt + 1))
    if [[ "$attempt" -ge "$SMOKE_TIMEOUT_SECS" ]]; then
      echo "error: timed out waiting for $url" >&2
      return 1
    fi
    sleep 1
  done
}

link_or_copy_dir() {
  local source_dir="$1"
  local dest_dir="$2"
  if ln -s "$source_dir" "$dest_dir" 2>/dev/null; then
    return 0
  fi
  cp -R "$source_dir" "$dest_dir"
}

run_binary_smoke() {
  local binary_path="$1"
  local work_dir="$2"
  local site_arg="${3:-site}"
  local port token config_path server_log

  binary_path="$(cd "$(dirname "$binary_path")" && pwd)/$(basename "$binary_path")"
  mkdir -p "$work_dir/var"
  config_path="$work_dir/var/wardex.toml"
  server_log="$work_dir/server.log"
  token="$(random_token)"
  port="$(pick_free_port)"

  "$binary_path" --version >/dev/null

  (
    cd "$work_dir"
    WARDEX_CONFIG_PATH="$config_path" "$binary_path" init-config "$config_path" >/dev/null
    WARDEX_CONFIG_PATH="$config_path" "$binary_path" doctor >"$work_dir/doctor.txt"
  )

  (
    cd "$work_dir"
    WARDEX_CONFIG_PATH="$config_path" \
      WARDEX_ADMIN_TOKEN="$token" \
      "$binary_path" serve "$port" "$site_arg"
  ) >"$server_log" 2>&1 &
  SERVER_PID=$!

  wait_for_http "http://127.0.0.1:${port}/admin/"
  wait_for_http "http://127.0.0.1:${port}/api/healthz/ready" "Authorization" "Bearer $token"
  wait_for_http "http://127.0.0.1:${port}/api/support/bundle" "Authorization" "Bearer $token"

  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

smoke_archive() {
  local artifact_path="$1"
  local extract_root binary_path archive_root

  require_cmd tar
  artifact_path="$(cd "$(dirname "$artifact_path")" && pwd)/$(basename "$artifact_path")"
  extract_root="$TMP_ROOT/archive"
  mkdir -p "$extract_root"

  case "$artifact_path" in
    *.tar.gz)
      tar -xzf "$artifact_path" -C "$extract_root"
      ;;
    *)
      echo "error: unsupported archive format '$artifact_path'" >&2
      exit 1
      ;;
  esac

  binary_path="$(find "$extract_root" -type f -name wardex | head -n1)"
  if [[ -z "$binary_path" ]]; then
    echo "error: could not find wardex binary in $artifact_path" >&2
    exit 1
  fi

  archive_root="$(dirname "$binary_path")"
  if [[ ! -d "$archive_root/site" ]]; then
    echo "error: archive root '$archive_root' does not contain site/" >&2
    exit 1
  fi

  run_binary_smoke "$binary_path" "$archive_root" "site"
}

smoke_installed_binary() {
  local binary_path="$1"
  local site_dir="$2"
  local work_dir="$TMP_ROOT/installed"

  mkdir -p "$work_dir"
  link_or_copy_dir "$site_dir" "$work_dir/site"
  run_binary_smoke "$binary_path" "$work_dir" "site"
}

install_deb() {
  local artifact_path="$1"
  require_cmd sudo
  require_cmd dpkg
  artifact_path="$(cd "$(dirname "$artifact_path")" && pwd)/$(basename "$artifact_path")"
  sudo apt-get update -qq
  sudo apt-get install -y "$artifact_path" >/dev/null
  PACKAGE_MANAGER="apt"
  smoke_installed_binary "/usr/bin/wardex" "/usr/share/wardex/site"
}

install_rpm() {
  local artifact_path="$1"
  require_cmd sudo
  require_cmd rpm
  artifact_path="$(cd "$(dirname "$artifact_path")" && pwd)/$(basename "$artifact_path")"
  sudo rpm -i --replacepkgs "$artifact_path" >/dev/null
  PACKAGE_MANAGER="rpm"
  smoke_installed_binary "/usr/bin/wardex" "/usr/share/wardex/site"
}

smoke_container() {
  local image_ref="$1"
  local port token

  require_cmd docker
  port="$(pick_free_port)"
  token="$(random_token)"
  CONTAINER_NAME="wardex-release-smoke-${port}"

  docker pull "$image_ref" >/dev/null
  docker run -d --rm \
    --name "$CONTAINER_NAME" \
    -p "127.0.0.1:${port}:9077" \
    -e "WARDEX_ADMIN_TOKEN=${token}" \
    "$image_ref" >/dev/null

  docker exec "$CONTAINER_NAME" /app/wardex --version >/dev/null
  docker exec "$CONTAINER_NAME" /app/wardex doctor >/tmp/wardex-container-doctor.txt

  wait_for_http "http://127.0.0.1:${port}/admin/"
  wait_for_http "http://127.0.0.1:${port}/api/healthz/ready" "Authorization" "Bearer $token"
  wait_for_http "http://127.0.0.1:${port}/api/support/bundle" "Authorization" "Bearer $token"

  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  CONTAINER_NAME=""
}

if [[ -z "$MODE" || "$MODE" == "--help" || "$MODE" == "-h" ]]; then
  usage
  exit 0
fi

TMP_ROOT="$(make_temp_dir)"
require_cmd curl
require_cmd python3

case "$MODE" in
  archive)
    if [[ $# -ne 1 ]]; then
      usage >&2
      exit 1
    fi
    smoke_archive "$1"
    ;;
  binary)
    if [[ $# -ne 2 ]]; then
      usage >&2
      exit 1
    fi
    smoke_installed_binary "$1" "$2"
    ;;
  deb)
    if [[ $# -ne 1 ]]; then
      usage >&2
      exit 1
    fi
    install_deb "$1"
    ;;
  rpm)
    if [[ $# -ne 1 ]]; then
      usage >&2
      exit 1
    fi
    install_rpm "$1"
    ;;
  container)
    if [[ $# -ne 1 ]]; then
      usage >&2
      exit 1
    fi
    smoke_container "$1"
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
