#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${WARDEX_BASE_URL:-http://127.0.0.1:8080}"
OUTPUT_DIR="${WARDEX_EVALUATION_OUTPUT_DIR:-$ROOT_DIR/output/evaluate-to-value}"
TOKEN="${WARDEX_ADMIN_TOKEN:-}"
TOKEN_FILE="${WARDEX_ADMIN_TOKEN_FILE:-$ROOT_DIR/var/.wardex_token}"
CURL_TIMEOUT="${WARDEX_EVALUATION_CURL_TIMEOUT:-30}"
CURL_RETRIES="${WARDEX_EVALUATION_CURL_RETRIES:-2}"

if [[ -z "$TOKEN" ]]; then
  if [[ -f "$TOKEN_FILE" ]]; then
    TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
  else
    echo "error: WARDEX_ADMIN_TOKEN is not set and token file was not found at $TOKEN_FILE" >&2
    exit 1
  fi
fi

mkdir -p "$OUTPUT_DIR"

request() {
  local method="$1"
  local path="$2"
  local output="$3"
  local data="${4:-}"
  local content_type="${5:-application/json}"

  if [[ -n "$data" ]]; then
    curl --silent --show-error --fail \
      --max-time "$CURL_TIMEOUT" \
      --retry "$CURL_RETRIES" \
      --retry-delay 1 \
      --retry-all-errors \
      -X "$method" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: $content_type" \
      --data "$data" \
      "$BASE_URL$path" >"$output"
  else
    curl --silent --show-error --fail \
      --max-time "$CURL_TIMEOUT" \
      --retry "$CURL_RETRIES" \
      --retry-delay 1 \
      --retry-all-errors \
      -X "$method" \
      -H "Authorization: Bearer $TOKEN" \
      "$BASE_URL$path" >"$output"
  fi
}

request_public() {
  local path="$1"
  local output="$2"
  curl --silent --show-error --fail \
    --max-time "$CURL_TIMEOUT" \
    --retry "$CURL_RETRIES" \
    --retry-delay 1 \
    --retry-all-errors \
    "$BASE_URL$path" >"$output"
}

python3 - "$OUTPUT_DIR" "$BASE_URL" "$TOKEN_FILE" <<'PY'
from pathlib import Path
import json
import sys

output_dir = Path(sys.argv[1])
base_url = sys.argv[2]
token_file = sys.argv[3]
note = {
    "journey": "Wardex evaluation-to-value",
    "base_url": base_url,
    "admin_console": f"{base_url}/admin/",
    "token_source": token_file,
    "note": "Seeded first-run proof artifacts are for evaluation only. Do not treat them as live production telemetry.",
}
(output_dir / "00-evaluation-note.json").write_text(json.dumps(note, indent=2) + "\n", encoding="utf-8")
PY

request "GET" "/api/healthz/ready" "$OUTPUT_DIR/01-healthz-ready.json"
request "POST" "/api/support/first-run-proof" "$OUTPUT_DIR/02-first-run-proof.json"
request "GET" "/api/alerts/page?limit=5" "$OUTPUT_DIR/03-alerts-page.json"
request "POST" "/api/response/preview" "$OUTPUT_DIR/04-response-preview.json" '{"action":"block_ip","target":"198.51.100.10"}'
request "GET" "/api/launchpad/evidence-pack" "$OUTPUT_DIR/05-launchpad-evidence-pack.json"
request "GET" "/api/support/bundle" "$OUTPUT_DIR/06-support-bundle.json"
request "GET" "/api/release/deployment-trust-report" "$OUTPUT_DIR/07-deployment-trust-report.json"
request "GET" "/api/release/doctor" "$OUTPUT_DIR/08-release-doctor.json"

case_id="$(python3 - "$OUTPUT_DIR/02-first-run-proof.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    body = json.load(handle)
proof = body.get("proof") or {}
if proof.get("status") != "completed":
    raise SystemExit("error: first-run proof did not complete")
if proof.get("response_status") != "DryRunCompleted":
    raise SystemExit("error: first-run proof did not finish the dry-run response")
case_id = proof.get("case_id")
report_run_id = proof.get("report_run_id")
report_id = proof.get("report_id")
digest = body.get("digest")
telemetry_alerts = (proof.get("telemetry") or {}).get("alerts", 0)
if not all([case_id, report_run_id, report_id, digest]):
    raise SystemExit("error: first-run proof is missing case/report identifiers")
if telemetry_alerts <= 0:
    raise SystemExit("error: first-run proof did not report any seeded alerts")
print(case_id)
PY
)"

request "GET" "/api/report-runs?case_id=${case_id}&source=first_run_proof" "$OUTPUT_DIR/09-report-runs.json"

python3 - "$OUTPUT_DIR" <<'PY'
from pathlib import Path
import json
import sys

output_dir = Path(sys.argv[1])

with (output_dir / "02-first-run-proof.json").open(encoding="utf-8") as handle:
    proof_run = json.load(handle)
with (output_dir / "03-alerts-page.json").open(encoding="utf-8") as handle:
    alerts = json.load(handle)
with (output_dir / "09-report-runs.json").open(encoding="utf-8") as handle:
    report_runs = json.load(handle)
with (output_dir / "07-deployment-trust-report.json").open(encoding="utf-8") as handle:
    trust = json.load(handle)

proof = proof_run.get("proof") or {}
items = alerts.get("items") or []
telemetry_alerts = (proof.get("telemetry") or {}).get("alerts") or 0
if not items and telemetry_alerts <= 0:
    raise SystemExit("error: no alerts were returned after first-run proof seeding")
runs = report_runs.get("runs") or []
if not runs:
    raise SystemExit("error: no report runs were returned for the evaluation case")
customer_artifact = (trust.get("customer_artifact") or {})
if customer_artifact.get("product_name") != "Wardex":
    raise SystemExit("error: deployment trust report did not return the expected Wardex artifact")

summary = {
    "status": "completed",
    "evaluation_only": True,
    "journey": {
        "start": "server ready",
        "proof_seed": "completed",
        "first_alert": (items[0].get("id") or items[0].get("timestamp")) if items else f"seeded:{telemetry_alerts}",
        "response_dry_run": proof.get("response_status"),
        "evidence_export": "launchpad_evidence_pack + support_bundle",
        "deployment_trust_report": customer_artifact.get("product_name"),
    },
    "proof": {
        "case_id": proof.get("case_id"),
        "report_id": proof.get("report_id"),
        "report_run_id": proof.get("report_run_id"),
        "response_request_id": proof.get("response_request_id"),
        "digest": proof_run.get("digest"),
        "telemetry_alerts": telemetry_alerts,
    },
    "artifacts": {
        "healthz_ready": "01-healthz-ready.json",
        "first_run_proof": "02-first-run-proof.json",
        "alerts_page": "03-alerts-page.json",
        "response_preview": "04-response-preview.json",
        "launchpad_evidence_pack": "05-launchpad-evidence-pack.json",
        "support_bundle": "06-support-bundle.json",
        "deployment_trust_report": "07-deployment-trust-report.json",
        "release_doctor": "08-release-doctor.json",
        "report_runs": "09-report-runs.json",
    },
}

(output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2))
PY
