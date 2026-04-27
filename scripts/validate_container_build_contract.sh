#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wardex-container-build.XXXXXX")"

cleanup() {
  rm -rf "$WORK_DIR"
}

copy_required() {
  local relative_path="$1"
  local source_path="$ROOT_DIR/$relative_path"
  local destination_path="$WORK_DIR/$relative_path"

  if [[ ! -e "$source_path" ]]; then
    echo "error: required build input is missing: $relative_path" >&2
    exit 1
  fi

  mkdir -p "$(dirname "$destination_path")"
  cp -R "$source_path" "$destination_path"
}

require_file_in_workdir() {
  local relative_path="$1"
  local description="$2"
  local path="$WORK_DIR/$relative_path"

  if [[ ! -s "$path" ]]; then
    echo "error: expected $description at $relative_path" >&2
    exit 1
  fi
}

require_executable_in_workdir() {
  local relative_path="$1"
  local description="$2"
  local path="$WORK_DIR/$relative_path"

  if [[ ! -x "$path" ]]; then
    echo "error: expected executable $description at $relative_path" >&2
    exit 1
  fi
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

dockerignore_pattern_matches() {
  local relative_path="$1"
  local pattern="$2"

  pattern="${pattern#/}"
  if [[ -z "$pattern" ]]; then
    return 1
  fi

  if [[ "$pattern" == */ ]]; then
    pattern="${pattern%/}/**"
  fi

  if [[ "$pattern" == *"/"* ]]; then
    [[ "$relative_path" == $pattern ]]
    return
  fi

  local basename="${relative_path##*/}"
  [[ "$basename" == $pattern || "$relative_path" == $pattern || "$relative_path" == $pattern/* ]]
}

require_dockerignore_allows() {
  local relative_path="$1"
  local included=1
  local line pattern negate

  while IFS= read -r line || [[ -n "$line" ]]; do
    pattern="$(trim "${line%$'\r'}")"
    [[ -z "$pattern" || "$pattern" == \#* ]] && continue
    negate=0
    if [[ "$pattern" == '!'* ]]; then
      negate=1
      pattern="${pattern:1}"
    fi
    if dockerignore_pattern_matches "$relative_path" "$pattern"; then
      if [[ "$negate" -eq 1 ]]; then
        included=1
      else
        included=0
      fi
    fi
  done <"$ROOT_DIR/.dockerignore"

  if [[ "$included" -ne 1 ]]; then
    echo "error: .dockerignore excludes required Docker build context input: $relative_path" >&2
    exit 1
  fi
}

require_dockerfile_copy_input() {
  local copy_input="$1"
  if ! grep -E '^[[:space:]]*COPY[[:space:]]' "$ROOT_DIR/Dockerfile" | grep -Fq "$copy_input"; then
    echo "error: Dockerfile builder stage does not COPY required input: $copy_input" >&2
    exit 1
  fi
}

trap cleanup EXIT

# Keep this list aligned with the Docker builder-stage COPY inputs.
required_paths=(
  "Cargo.toml"
  "Cargo.lock"
  "build.rs"
  "src"
  "docs"
  "admin-console"
  "sdk"
  "site"
  "examples"
  "benches"
  "tests"
)

required_docker_context_inputs=(
  "Cargo.toml"
  "Cargo.lock"
  "build.rs"
  "src/server.rs"
  "docs/README.md"
  "admin-console/package.json"
  "sdk/typescript/package.json"
  "site/index.html"
  "examples/README.md"
  "benches/pipeline.rs"
  "tests/api_integration.rs"
)

required_dockerfile_copy_inputs=(
  "Cargo.toml"
  "Cargo.lock"
  "build.rs"
  "src/"
  "docs/"
  "admin-console/"
  "sdk/"
  "site/"
  "examples/"
  "benches/"
  "tests/"
)

for input in "${required_docker_context_inputs[@]}"; do
  require_dockerignore_allows "$input"
done

for input in "${required_dockerfile_copy_inputs[@]}"; do
  require_dockerfile_copy_input "$input"
done

for path in "${required_paths[@]}"; do
  copy_required "$path"
done

cd "$WORK_DIR"
npm ci --prefix admin-console
cargo build --release --features tls --bin wardex

require_executable_in_workdir "target/release/wardex" "release wardex binary"
require_file_in_workdir "admin-console/dist/index.html" "embedded admin console entrypoint"
require_file_in_workdir "site/index.html" "runtime site entrypoint"
require_file_in_workdir "examples/README.md" "runtime examples index"
require_file_in_workdir "docs/README.md" "embedded documentation index"
require_file_in_workdir "sdk/typescript/package.json" "SDK generation input"

echo "container build contract validation passed"
