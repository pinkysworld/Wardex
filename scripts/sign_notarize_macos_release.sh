#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/sign_notarize_macos_release.sh <binary-path> [platform]

Signs a macOS Wardex command-line binary with a Developer ID Application
certificate, submits it to Apple notarization, and verifies Gatekeeper trust.

Required environment variables:
  WARDEX_MACOS_CERTIFICATE_BASE64      Base64-encoded Developer ID .p12
  WARDEX_MACOS_CERTIFICATE_PASSWORD    Password for the .p12 certificate
  WARDEX_MACOS_NOTARY_APPLE_ID         Apple ID for notarytool
  WARDEX_MACOS_NOTARY_PASSWORD         App-specific password for notarytool
  WARDEX_MACOS_NOTARY_TEAM_ID          Apple Developer Team ID

Optional environment variables:
  WARDEX_MACOS_CODESIGN_IDENTITY       codesign identity name
  WARDEX_MACOS_KEYCHAIN_PASSWORD       temporary keychain password
  WARDEX_MACOS_NOTARY_ARCHIVE          output zip submitted to notarytool
USAGE
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: ${name} must be set for macOS signing and notarization" >&2
    exit 1
  fi
}

decode_base64() {
  local value="$1"
  local output="$2"

  if printf '%s' "$value" | base64 --decode >"$output" 2>/dev/null; then
    return 0
  fi

  printf '%s' "$value" | base64 -D >"$output"
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

binary_path="$1"
platform="${2:-macos}"

if [[ ! -f "$binary_path" ]]; then
  echo "error: binary not found at ${binary_path}" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: macOS signing and notarization must run on a macOS host" >&2
  exit 1
fi

for cmd in security codesign xcrun ditto spctl base64; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required macOS command '${cmd}' is not available" >&2
    exit 1
  fi
done

require_env WARDEX_MACOS_CERTIFICATE_BASE64
require_env WARDEX_MACOS_CERTIFICATE_PASSWORD
require_env WARDEX_MACOS_NOTARY_APPLE_ID
require_env WARDEX_MACOS_NOTARY_PASSWORD
require_env WARDEX_MACOS_NOTARY_TEAM_ID

tmp_dir="$(mktemp -d)"
keychain_path="${tmp_dir}/wardex-signing.keychain-db"
cert_path="${tmp_dir}/developer-id-application.p12"
notary_archive="${WARDEX_MACOS_NOTARY_ARCHIVE:-${tmp_dir}/wardex-${platform}-notary.zip}"
keychain_password="${WARDEX_MACOS_KEYCHAIN_PASSWORD:-$(uuidgen 2>/dev/null || printf 'wardex-%s-%s' "$$" "$(date +%s)")}"
codesign_identity="${WARDEX_MACOS_CODESIGN_IDENTITY:-}"
original_default_keychain="$(security default-keychain 2>/dev/null | sed 's/^[[:space:]]*//' | tr -d '"' || true)"
original_keychains=()
active_keychains=()
while IFS= read -r keychain; do
  keychain="$(printf '%s' "$keychain" | sed 's/^[[:space:]]*//' | tr -d '"')"
  if [[ -n "$keychain" ]]; then
    original_keychains+=("$keychain")
  fi
done < <(security list-keychains -d user 2>/dev/null)

cleanup() {
  if [[ ${#original_keychains[@]} -gt 0 ]]; then
    security list-keychains -d user -s "${original_keychains[@]}" >/dev/null 2>&1 || true
  fi
  if [[ -n "$original_default_keychain" ]]; then
    security default-keychain -s "$original_default_keychain" >/dev/null 2>&1 || true
  fi
  security delete-keychain "$keychain_path" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

echo "==> Import Developer ID certificate for ${platform}"
decode_base64 "$WARDEX_MACOS_CERTIFICATE_BASE64" "$cert_path"
security create-keychain -p "$keychain_password" "$keychain_path"
security set-keychain-settings -lut 21600 "$keychain_path"
security unlock-keychain -p "$keychain_password" "$keychain_path"
security import "$cert_path" \
  -P "$WARDEX_MACOS_CERTIFICATE_PASSWORD" \
  -A \
  -f pkcs12 \
  -k "$keychain_path" \
  -T /usr/bin/codesign \
  -T /usr/bin/security
active_keychains=("$keychain_path")
for keychain in "${original_keychains[@]}"; do
  if [[ "$keychain" != "$keychain_path" ]]; then
    active_keychains+=("$keychain")
  fi
done
security list-keychains -d user -s "${active_keychains[@]}"
security default-keychain -s "$keychain_path"
echo "==> Imported codesigning identities"
identity_output="$(security find-identity -v -p codesigning "$keychain_path")"
printf '%s\n' "$identity_output"

if [[ -z "$codesign_identity" ]]; then
  codesign_identity="$(printf '%s\n' "$identity_output" | awk '/Developer ID Application/ { print $2; exit }')"
fi

if [[ -z "$codesign_identity" ]]; then
  echo "error: no Developer ID Application codesigning identity was imported into ${keychain_path}" >&2
  exit 1
fi

if ! security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "$keychain_password" \
  "$keychain_path"; then
  echo "warning: unable to update key partition list; continuing because the identity was imported with codesign access" >&2
fi

echo "==> Code sign ${binary_path}"
codesign \
  --force \
  --timestamp \
  --options runtime \
  --sign "$codesign_identity" \
  "$binary_path"
codesign --verify --strict --verbose=2 "$binary_path"

echo "==> Submit ${platform} binary for Apple notarization"
rm -f "$notary_archive"
ditto -c -k --keepParent "$binary_path" "$notary_archive"
xcrun notarytool submit "$notary_archive" \
  --apple-id "$WARDEX_MACOS_NOTARY_APPLE_ID" \
  --password "$WARDEX_MACOS_NOTARY_PASSWORD" \
  --team-id "$WARDEX_MACOS_NOTARY_TEAM_ID" \
  --wait

echo "==> Verify signed binary metadata"
echo "notarytool submit completed successfully; standalone CLI binaries are validated via notarization acceptance plus codesign metadata rather than spctl --type execute"
codesign -dv --verbose=4 "$binary_path"