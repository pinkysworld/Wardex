#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${WARDEX_LOCAL_RELEASE_LOG:-/tmp/wardex-local-release-build.log}"
ACTIVE_TOOLCHAIN="$(rustup show active-toolchain | awk '{print $1}')"
CARGO_BIN="$(rustup which --toolchain "$ACTIVE_TOOLCHAIN" cargo)"
RUSTC_BIN="$(rustup which --toolchain "$ACTIVE_TOOLCHAIN" rustc)"
RUSTDOC_BIN="$(rustup which --toolchain "$ACTIVE_TOOLCHAIN" rustdoc)"
TOOLCHAIN_BIN_DIR="$(dirname "$RUSTC_BIN")"
TARGET_DIR="${WARDEX_LOCAL_RELEASE_TARGET_DIR:-/tmp/wardex-local-release-target}"

cd "$ROOT_DIR"

for cmd in cargo npm rustup tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command '$cmd' is not available" >&2
    exit 1
  fi
done

if ! command -v /usr/bin/zip >/dev/null 2>&1; then
  echo "error: required command '/usr/bin/zip' is not available" >&2
  exit 1
fi

rm -rf release/*
mkdir -p release
rm -rf "$TARGET_DIR"

: >"$LOG_FILE"

{
  rustup target add --toolchain "$ACTIVE_TOOLCHAIN" aarch64-apple-darwin x86_64-pc-windows-gnu x86_64-unknown-linux-musl
  npm ci --prefix admin-console
  npm --prefix admin-console run build
} >>"$LOG_FILE" 2>&1

built=()
failed=()

package_unix() {
  local target="$1"
  local platform="$2"
  local archive="$3"
  local pkg="release/wardex-${platform}"

  rm -rf "$pkg"
  mkdir -p "$pkg"
  cp "$TARGET_DIR/${target}/release/wardex" "$pkg/wardex"
  chmod +x "$pkg/wardex"
  cp -r site "$pkg/site"
  cp -r examples "$pkg/examples"
  cp README.md LICENSE "$pkg/"
  tar -czf "release/${archive}" -C release "wardex-${platform}"
}

macos_signing_identity_configured() {
  [[ -n "${WARDEX_MACOS_CERTIFICATE_BASE64:-}" || -n "${WARDEX_MACOS_CERTIFICATE_PATH:-}" ]]
}

macos_notarization_configured() {
  macos_signing_identity_configured && \
    [[ -n "${WARDEX_MACOS_CERTIFICATE_PASSWORD:-}" ]] && \
    { [[ -n "${WARDEX_MACOS_NOTARY_KEYCHAIN_PROFILE:-}" ]] || \
      { [[ -n "${WARDEX_MACOS_NOTARY_APPLE_ID:-}" ]] && \
        [[ -n "${WARDEX_MACOS_NOTARY_PASSWORD:-}" ]] && \
        [[ -n "${WARDEX_MACOS_NOTARY_TEAM_ID:-}" ]]; }; }
}

maybe_sign_notarize_macos() {
  local target="$1"
  local platform="$2"
  local binary="$TARGET_DIR/${target}/release/wardex"

  if [[ "$platform" != macos-* ]]; then
    return 0
  fi

  if macos_notarization_configured; then
    "$ROOT_DIR/scripts/sign_notarize_macos_release.sh" "$binary" "$platform" >>"$LOG_FILE" 2>&1
    return 0
  fi

  if [[ "${WARDEX_REQUIRE_MACOS_NOTARIZATION:-0}" == "1" ]]; then
    echo "error: macOS notarization credentials are required for ${platform}" >&2
    echo "set WARDEX_MACOS_CERTIFICATE_BASE64 or WARDEX_MACOS_CERTIFICATE_PATH, plus WARDEX_MACOS_CERTIFICATE_PASSWORD, and either WARDEX_MACOS_NOTARY_KEYCHAIN_PROFILE or WARDEX_MACOS_NOTARY_APPLE_ID/WARDEX_MACOS_NOTARY_PASSWORD/WARDEX_MACOS_NOTARY_TEAM_ID" >&2
    exit 1
  fi

  echo "warning: ${platform} archive will not be Gatekeeper-trusted; set WARDEX_REQUIRE_MACOS_NOTARIZATION=1 in release automation" >&2
}

build_unix() {
  local target="$1"
  local platform="$2"
  local archive="$3"

  echo "==> build ${target}" >>"$LOG_FILE"
  if PATH="$TOOLCHAIN_BIN_DIR:$PATH" RUSTC="$RUSTC_BIN" RUSTDOC="$RUSTDOC_BIN" CARGO_TARGET_DIR="$TARGET_DIR" WARDEX_SKIP_ADMIN_BUILD=1 "$CARGO_BIN" build --release --target "$target" >>"$LOG_FILE" 2>&1; then
    maybe_sign_notarize_macos "$target" "$platform"
    package_unix "$target" "$platform" "$archive"
    built+=("release/${archive}")
  else
    failed+=("${target}")
  fi
}

build_windows_gnu() {
  local target="x86_64-pc-windows-gnu"
  local platform="windows-x86_64-gnu"
  local archive="wardex-windows-x86_64-gnu.zip"
  local pkg="release/wardex-${platform}"

  echo "==> build ${target}" >>"$LOG_FILE"
  if PATH="$TOOLCHAIN_BIN_DIR:$PATH" RUSTC="$RUSTC_BIN" RUSTDOC="$RUSTDOC_BIN" CARGO_TARGET_DIR="$TARGET_DIR" WARDEX_SKIP_ADMIN_BUILD=1 CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc "$CARGO_BIN" build --release --target "$target" >>"$LOG_FILE" 2>&1; then
    rm -rf "$pkg"
    mkdir -p "$pkg"
    cp "$TARGET_DIR/${target}/release/wardex.exe" "$pkg/wardex.exe"
    cp -r site "$pkg/site"
    cp -r examples "$pkg/examples"
    cp README.md LICENSE "$pkg/"
    (
      cd release
      /usr/bin/zip -qry "$archive" "wardex-${platform}"
    )
    built+=("release/${archive}")
  else
    failed+=("${target}")
  fi
}

build_linux_musl() {
  local target="x86_64-unknown-linux-musl"
  local platform="linux-x86_64"
  local archive="wardex-linux-x86_64.tar.gz"

  echo "==> build ${target}" >>"$LOG_FILE"
  if command -v cargo-zigbuild >/dev/null 2>&1 && command -v zig >/dev/null 2>&1; then
    if PATH="$TOOLCHAIN_BIN_DIR:$PATH" RUSTC="$RUSTC_BIN" RUSTDOC="$RUSTDOC_BIN" CARGO_TARGET_DIR="$TARGET_DIR" WARDEX_SKIP_ADMIN_BUILD=1 "$CARGO_BIN" zigbuild --release --target "$target" >>"$LOG_FILE" 2>&1; then
      package_unix "$target" "$platform" "$archive"
      built+=("release/${archive}")
      return 0
    fi
  else
    if PATH="$TOOLCHAIN_BIN_DIR:$PATH" RUSTC="$RUSTC_BIN" RUSTDOC="$RUSTDOC_BIN" CARGO_TARGET_DIR="$TARGET_DIR" WARDEX_SKIP_ADMIN_BUILD=1 "$CARGO_BIN" build --release --target "$target" >>"$LOG_FILE" 2>&1; then
      package_unix "$target" "$platform" "$archive"
      built+=("release/${archive}")
      return 0
    fi
  fi

  failed+=("${target}")
}

build_unix x86_64-apple-darwin macos-x86_64 wardex-macos-x86_64.tar.gz
build_unix aarch64-apple-darwin macos-aarch64 wardex-macos-aarch64.tar.gz
build_windows_gnu
build_linux_musl

if [[ ${#built[@]} -gt 0 ]]; then
  (
    cd release
    printf '%s\0' "${built[@]#release/}" | sort -z | xargs -0 shasum -a 256 > SHA256SUMS
    shasum -a 256 -c SHA256SUMS
  ) >>"$LOG_FILE" 2>&1
fi

printf 'BUILT\n'
if [[ ${#built[@]} -gt 0 ]]; then
  printf '%s\n' "${built[@]}"
fi
printf 'FAILED\n'
if [[ ${#failed[@]} -gt 0 ]]; then
  printf '%s\n' "${failed[@]}"
fi
printf 'LOG\n%s\n' "$LOG_FILE"

if [[ ${#built[@]} -eq 0 ]]; then
  exit 1
fi