class Wardex < Formula
  desc "SentinelEdge XDR — AI-powered endpoint detection & response"
  homepage "https://github.com/pinkysworld/Wardex"
  version "0.52.0"
  license "BSL-1.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-macos-aarch64.tar.gz"
      sha256 "a27d183a9127d3f2e6d34819900553e6f3482fba761da0027968e82756a652de"
    else
      url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-macos-x86_64.tar.gz"
      sha256 "4e5077b1746f678c3b04ff5bafc9b9ae8e368a5a6f701fe985863fb124f4923f"
    end
  end

  on_linux do
    url "https://github.com/pinkysworld/Wardex/releases/download/v#{version}/wardex-linux-x86_64.tar.gz"
    sha256 "a665c17ac5706281612c8fa350d5710ceacd7d6567c9cea5e35fd10421cad5b5"
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
