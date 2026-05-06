#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/update_github_macos_signing_secrets.sh

Updates the GitHub Actions secrets used by .github/workflows/release.yml for
macOS Developer ID signing and notarization.

Required local inputs:
  WARDEX_MACOS_CERTIFICATE_PATH        Developer ID .p12/.pfx path
                                      default: ~/.wardex-signing/wardex_developer_id_application.p12
  WARDEX_MACOS_CERTIFICATE_PASSWORD    .p12 password; if omitted, read from
                                      macOS Keychain item
                                      wardex-developer-id-application-p12
  WARDEX_MACOS_NOTARY_APPLE_ID         Apple ID for notarytool. If omitted,
                                      the existing GitHub secret is left as-is.
  WARDEX_MACOS_NOTARY_PASSWORD         App-specific password for notarytool. If
                                      omitted, the existing GitHub secret is
                                      left as-is.
  WARDEX_MACOS_NOTARY_TEAM_ID          Apple Developer Team ID. If omitted,
                                      the existing GitHub secret is left as-is.

Optional local inputs:
  WARDEX_MACOS_CODESIGN_IDENTITY       codesign identity name
  WARDEX_MACOS_KEYCHAIN_PASSWORD       CI temporary keychain password
  WARDEX_GITHUB_REPO                   owner/repo, default inferred from git
USAGE
}

base64_one_line() {
  local path="$1"

  if base64 -i "$path" >/dev/null 2>&1; then
    base64 -i "$path" | tr -d '\n'
    return 0
  fi

  base64 <"$path" | tr -d '\n'
}

repo_from_remote() {
  local remote=""
  remote="$(git remote get-url origin 2>/dev/null || true)"
  remote="${remote%.git}"
  remote="${remote#git@github.com:}"
  remote="${remote#https://github.com/}"
  printf '%s' "$remote"
}

keychain_password() {
  local service="wardex-developer-id-application-p12"
  local login_keychain="${HOME}/Library/Keychains/login.keychain-db"

  security find-generic-password \
    -a "$USER" \
    -s "$service" \
    -w "$login_keychain"
}

dotenv_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

write_secret_env_line() {
  local secret_name="$1"
  local value="$2"
  {
    printf '%s=' "$secret_name"
    dotenv_escape "$value"
    printf '\n'
  } >>"$secret_env_file"
}

set_secret_if_present() {
  local env_name="$1"
  local secret_name="$2"
  local value="${!env_name:-}"

  if [[ -n "$value" ]]; then
    write_secret_env_line "$secret_name" "$value"
    echo "   updated ${secret_name}"
  else
    echo "   skipped ${secret_name}; ${env_name} is not set, leaving existing GitHub secret unchanged"
  fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: GitHub CLI 'gh' is required" >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: OpenSSL is required to validate the Developer ID .p12 password before uploading secrets" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "error: gh is not authenticated; run: gh auth login -h github.com --web --git-protocol https --scopes repo,workflow" >&2
  exit 1
fi

certificate_path="${WARDEX_MACOS_CERTIFICATE_PATH:-${HOME}/.wardex-signing/wardex_developer_id_application.p12}"
repo="${WARDEX_GITHUB_REPO:-$(repo_from_remote)}"

if [[ -z "$repo" ]]; then
  echo "error: unable to infer GitHub repository; set WARDEX_GITHUB_REPO=owner/repo" >&2
  exit 1
fi

if [[ ! -f "$certificate_path" ]]; then
  echo "error: Developer ID identity file not found: ${certificate_path}" >&2
  exit 1
fi

certificate_password="${WARDEX_MACOS_CERTIFICATE_PASSWORD:-}"
if [[ -z "$certificate_password" ]]; then
  certificate_password="$(keychain_password)"
fi

if ! openssl pkcs12 \
  -in "$certificate_path" \
  -nokeys \
  -passin pass:"$certificate_password" >/dev/null 2>&1; then
  echo "error: Developer ID .p12 password validation failed for ${certificate_path}; not updating GitHub secrets" >&2
  exit 1
fi

certificate_base64="$(base64_one_line "$certificate_path")"
# CI only needs a deterministic temporary keychain password so the release job
# can create, unlock, and delete its throwaway keychain without prompting.
keychain_password_value="${WARDEX_MACOS_KEYCHAIN_PASSWORD:-wardex-ci-signing-keychain}"
secret_env_file="$(mktemp)"
trap 'rm -f "$secret_env_file"' EXIT

echo "==> Updating macOS signing secrets for ${repo}"
write_secret_env_line MACOS_DEVELOPER_ID_CERTIFICATE_BASE64 "$certificate_base64"
echo "   updated MACOS_DEVELOPER_ID_CERTIFICATE_BASE64"
write_secret_env_line MACOS_DEVELOPER_ID_CERTIFICATE_PASSWORD "$certificate_password"
echo "   updated MACOS_DEVELOPER_ID_CERTIFICATE_PASSWORD"
write_secret_env_line MACOS_KEYCHAIN_PASSWORD "$keychain_password_value"
echo "   updated MACOS_KEYCHAIN_PASSWORD"
set_secret_if_present WARDEX_MACOS_CODESIGN_IDENTITY MACOS_CODESIGN_IDENTITY
set_secret_if_present WARDEX_MACOS_NOTARY_APPLE_ID MACOS_NOTARY_APPLE_ID
set_secret_if_present WARDEX_MACOS_NOTARY_PASSWORD MACOS_NOTARY_APP_PASSWORD
set_secret_if_present WARDEX_MACOS_NOTARY_TEAM_ID MACOS_NOTARY_TEAM_ID
gh secret set --repo "$repo" --env-file "$secret_env_file"

echo "==> GitHub macOS signing secrets updated"