# Evaluate Wardex In 15 Minutes

This is the canonical evaluation path for Wardex. It is designed for local or self-hosted trials and uses seeded first-run proof data plus exported artifacts that are safe to reset.

Important: seeded demo data, first-run proof artifacts, and launchpad demo scenarios are for evaluation only. Do not treat them as live production telemetry or customer evidence.

## 1. Build and start the control plane

```bash
npm ci --prefix admin-console
cargo build --release
./target/release/wardex start
```

Open the admin console:

```text
http://localhost:8080/admin/
```

Read the generated admin token if you did not set `WARDEX_ADMIN_TOKEN` yourself:

```bash
cat var/.wardex_token
```

Paste that token into the console login form. This establishes the operator session for the browser flow while the scripted evaluation below uses the same token for authenticated API proof steps.

## 2. Run the evaluation-to-value script

From the repository root:

```bash
WARDEX_ADMIN_TOKEN="$(cat var/.wardex_token)" bash scripts/evaluate_to_value.sh
```

The script proves the same sequence we expect operators to feel during evaluation:

1. authenticated control plane readiness via `/api/healthz/ready`
2. evaluation-only first-run proof seed via `POST /api/support/first-run-proof`
3. first visible alert via `GET /api/alerts/page?limit=5`
4. response dry-run via `POST /api/response/preview`
5. evidence export via `GET /api/launchpad/evidence-pack`
6. support artifact via `GET /api/support/bundle`
7. deployment proof export via `GET /api/release/deployment-trust-report`
8. release readiness proof via `GET /api/release/doctor`

Artifacts are written to:

```text
output/evaluate-to-value/
```

The most useful file is:

```text
output/evaluate-to-value/summary.json
```

It records the seeded case id, report ids, dry-run response state, and the exported proof artifacts.

## 3. Review the same flow in the product

In the browser:

1. Open **Help & Docs** and run **Run Proof**.
2. Open **Operator Launchpad** and review:
   - `#demo-mode`
   - `#release-gate-automation`
   - `#release-acceptance-report`
3. Open **SOC Workbench** and confirm the seeded case and alert context.
4. Open **Reports & Exports** to review the generated report run history.

## 4. Check the local release posture

```bash
./target/release/wardex doctor
```

This gives you the local readiness and diagnostics view that complements the exported deployment trust report.

## 5. Reset the transient evaluation state if needed

The launchpad demo status can be reset from the UI or with:

```bash
curl -sSf \
  -H "Authorization: Bearer $(cat var/.wardex_token)" \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8080/api/launchpad/demo-reset
```

This only clears transient sample/demo state. It does not replace production cleanup procedures.
