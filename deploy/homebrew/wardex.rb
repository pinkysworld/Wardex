require "json"

class Wardex < Formula
  desc "SentinelEdge XDR — AI-powered endpoint detection & response"
  homepage "https://github.com/pinkysworld/Wardex"
  url "https://github.com/pinkysworld/Wardex/archive/refs/tags/v0.52.5.tar.gz"
  sha256 "68da2b9a429420936434d5c621d213dc3eea18ca6c19682ab382eaa067f603a9"
  license "BUSL-1.1"

  depends_on "node" => :build if OS.mac?
  depends_on "rust" => :build if OS.mac?

  def install
    cargo_bin = "cargo"

    if OS.mac?
      system "npm", "ci", "--prefix", "admin-console"
    else
      ENV["WARDEX_SKIP_ADMIN_BUILD"] = "1"
      ENV["CARGO_HOME"] = ENV.fetch("HOMEBREW_WARDEX_CARGO_HOME", "#{Dir.home}/.cargo")
      ENV["RUSTUP_HOME"] = ENV.fetch("HOMEBREW_WARDEX_RUSTUP_HOME", "#{Dir.home}/.rustup")
      ENV.prepend_path "PATH", File.join(ENV["CARGO_HOME"], "bin")

      rustc_bin = ENV["HOMEBREW_WARDEX_RUSTC_BIN"]
      ENV["RUSTC"] = rustc_bin if rustc_bin.present?

      configured_cargo_bin = ENV["HOMEBREW_WARDEX_CARGO_BIN"]
      cargo_bin = configured_cargo_bin if configured_cargo_bin.present?
    end
    system cargo_bin, "install", *std_cargo_args(path: ".")

    pkgshare.install "examples", "site"
    doc.install "README.md", "LICENSE"
  end

  def post_install
    (var/"wardex").mkpath
    (var/"wardex/backups").mkpath
    (var/"log/wardex").mkpath
  end

  service do
    run [opt_bin/"wardex", "serve", "8080", opt_pkgshare/"site"]
    keep_alive true
    environment_variables PATH: std_service_path_env, WARDEX_CONFIG_PATH: (var/"wardex/wardex.toml").to_s
    working_dir var/"wardex"
    log_path var/"log/wardex/wardex.log"
    error_log_path var/"log/wardex/wardex-error.log"
  end

  test do
    report_path = testpath/"report.json"
    output = shell_output("#{bin}/wardex report #{pkgshare/"examples/benign_baseline.csv"} #{report_path}")
    assert_match "JSON report written to", output
    assert_path_exists report_path

    report = JSON.parse(report_path.read)
    assert_operator report.dig("summary", "total_samples"), :>, 0
    assert_equal report.fetch("summary").fetch("total_samples"), report.fetch("samples").length
    assert report.fetch("summary").key?("max_score")
  end
end
