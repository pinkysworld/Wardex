#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <version> <macos_aarch64_sha256> <macos_x86_64_sha256> <linux_x86_64_sha256> <output_path>" >&2
  exit 1
fi

version="$1"
macos_aarch64_sha256="$2"
macos_x86_64_sha256="$3"
linux_x86_64_sha256="$4"
output_path="$5"

mkdir -p "$(dirname "$output_path")"

cat >"$output_path" <<EOF
class Wardex < Formula
  desc "SentinelEdge XDR — AI-powered endpoint detection & response"
  homepage "https://github.com/pinkysworld/Wardex"
  version "$version"
  license "BSL-1.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-macos-aarch64.tar.gz"
      sha256 "$macos_aarch64_sha256"
    else
      url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-macos-x86_64.tar.gz"
      sha256 "$macos_x86_64_sha256"
    end
  end

  on_linux do
    url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-linux-x86_64.tar.gz"
    sha256 "$linux_x86_64_sha256"
  end

  def install
    pkg = Dir["wardex-*"] .find { |path| File.directory?(path) }
    raise "release archive layout changed" unless pkg

    bin.install "#{pkg}/wardex"
    (share/"wardex/site").install Dir["#{pkg}/site/*"] if Dir.exist?("#{pkg}/site")
    (share/"wardex/examples").install Dir["#{pkg}/examples/*"] if Dir.exist?("#{pkg}/examples")
  end

  def post_install
    (var/"wardex").mkpath
    (var/"wardex/backups").mkpath
    (var/"log/wardex").mkpath
  end

  service do
    run [opt_bin/"wardex", "serve", "--port", "8080"]
    keep_alive true
    working_dir var/"wardex"
    log_path var/"log/wardex/wardex.log"
    error_log_path var/"log/wardex/wardex-error.log"
  end

  test do
    assert_match "wardex", shell_output("#{bin}/wardex --version")
  end
end
EOF