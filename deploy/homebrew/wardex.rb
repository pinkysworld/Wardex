require "json"

class Wardex < Formula
  desc "SentinelEdge XDR — AI-powered endpoint detection & response"
  homepage "https://github.com/pinkysworld/Wardex"
  url "https://github.com/pinkysworld/Wardex/archive/refs/tags/v0.52.0.tar.gz"
  sha256 "3bfe97e328c26d1e5137e17e6444df0166262a100ff620dcd94536014fc6d06b"
  license "BUSL-1.1"

  depends_on "node" => :build
  depends_on "rust" => :build

  def install
    system "npm", "ci", "--prefix", "admin-console"
    system "cargo", "install", *std_cargo_args(path: ".")

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
