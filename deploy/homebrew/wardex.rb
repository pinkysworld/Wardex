class Wardex < Formula
  desc "SentinelEdge XDR — AI-powered endpoint detection & response"
  homepage "https://github.com/pinkysworld/Wardex"
  version "0.46.0"
  license "BSL-1.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-v#{version}-aarch64-apple-darwin.tar.gz"
      # sha256 "PLACEHOLDER"
    else
      url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-v#{version}-x86_64-apple-darwin.tar.gz"
      # sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
    # sha256 "PLACEHOLDER"
  end

  def install
    bin.install "wardex"
    # Install default rules
    (share/"wardex/rules/sigma").install Dir["rules/sigma/*"] if Dir.exist?("rules/sigma")
    (share/"wardex/rules/yara").install Dir["rules/yara/*"] if Dir.exist?("rules/yara")
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
