#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <output_root> <suite> <component> <deb> [<deb>...]" >&2
  exit 1
fi

output_root="$1"
suite="$2"
component="$3"
shift 3
debs=("$@")

for cmd in apt-ftparchive dpkg-deb dpkg-scanpackages gzip; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
done

rm -rf "$output_root"
mkdir -p "$output_root/pool/$component"

architectures=()

for deb in "${debs[@]}"; do
  if [[ ! -f "$deb" ]]; then
    echo "missing Debian package: $deb" >&2
    exit 1
  fi

  package_name="$(dpkg-deb -f "$deb" Package)"
  architecture="$(dpkg-deb -f "$deb" Architecture)"
  leading_char="$(printf '%s' "$package_name" | cut -c1 | tr '[:upper:]' '[:lower:]')"
  destination_dir="$output_root/pool/$component/$leading_char/$package_name"

  mkdir -p "$destination_dir"
  cp "$deb" "$destination_dir/"

  architectures+=("$architecture")
done

mapfile -t unique_architectures < <(printf '%s\n' "${architectures[@]}" | sort -u)
architectures_joined="$(printf '%s ' "${unique_architectures[@]}")"
architectures_joined="${architectures_joined%% }"

for architecture in "${unique_architectures[@]}"; do
  binary_dir="$output_root/dists/$suite/$component/binary-$architecture"
  mkdir -p "$binary_dir"

  (
    cd "$output_root"
    dpkg-scanpackages --multiversion --arch "$architecture" pool /dev/null > "dists/$suite/$component/binary-$architecture/Packages"
  )

  gzip -9c "$binary_dir/Packages" > "$binary_dir/Packages.gz"
done

release_config="$(mktemp)"
cat >"$release_config" <<EOF
APT::FTPArchive::Release::Origin "Wardex";
APT::FTPArchive::Release::Label "Wardex";
APT::FTPArchive::Release::Suite "$suite";
APT::FTPArchive::Release::Codename "$suite";
APT::FTPArchive::Release::Architectures "$architectures_joined";
APT::FTPArchive::Release::Components "$component";
APT::FTPArchive::Release::Description "Wardex Debian package repository";
EOF

apt-ftparchive -c="$release_config" release "$output_root/dists/$suite" > "$output_root/dists/$suite/Release"
rm -f "$release_config"

if [[ -n "${APT_GPG_PRIVATE_KEY:-}" ]]; then
  if ! command -v gpg >/dev/null 2>&1; then
    echo "APT_GPG_PRIVATE_KEY is set but gpg is not installed" >&2
    exit 1
  fi

  export GNUPGHOME
  GNUPGHOME="$(mktemp -d)"

  printf '%s\n' "$APT_GPG_PRIVATE_KEY" | gpg --batch --import
  signing_key="$(gpg --batch --list-secret-keys --with-colons | awk -F: '/^sec:/ { print $5; exit }')"

  if [[ -z "$signing_key" ]]; then
    echo "failed to resolve imported APT signing key" >&2
    exit 1
  fi

  gpg_args=(--batch --yes --pinentry-mode loopback --local-user "$signing_key")
  if [[ -n "${APT_GPG_PASSPHRASE:-}" ]]; then
    gpg_args+=(--passphrase "$APT_GPG_PASSPHRASE")
  fi

  gpg "${gpg_args[@]}" --armor --detach-sign --output "$output_root/dists/$suite/Release.gpg" "$output_root/dists/$suite/Release"
  gpg "${gpg_args[@]}" --clearsign --output "$output_root/dists/$suite/InRelease" "$output_root/dists/$suite/Release"
  gpg --batch --armor --export "$signing_key" > "$output_root/wardex-archive-key.asc"

  rm -rf "$GNUPGHOME"
fi