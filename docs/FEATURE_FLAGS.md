# Feature Flags

## Compile-time features (v1.0)

From v1.0, all previously experimental modules are **graduated to stable**
and compiled unconditionally. The `experimental-ml`, `experimental-llm`,
`experimental-quantum`, and `experimental-proof` feature flags have been
removed.

| Module          | Description                                       | Status   |
|-----------------|---------------------------------------------------|----------|
| `ml_engine`     | Gradient-boosted + Random Forest ML triage        | Stable ✓ |
| `llm_analyst`   | LLM-assisted analyst (OpenAI, Anthropic, Ollama)  | Stable ✓ |
| `quantum`       | Post-quantum key rotation (Kyber, Dilithium)      | Stable ✓ |
| `proof`         | Zero-knowledge proofs for privacy forensics       | Stable ✓ |

### Available compile-time features (v1.0)

| Feature | Description |
|---------|-------------|
| `tls`   | TLS support in the `ureq` HTTP client — **enabled by default** |

`tls` is on by default because every outbound integration (threat feeds,
AWS/Azure/GCP collectors, OIDC discovery, webhooks) requires HTTPS.

```bash
# Standard build (TLS + all modules included)
cargo build --release

# Without TLS (outbound HTTPS integrations will not work)
cargo build --release --no-default-features
```

### Upgrading from 0.x

If you previously used `--no-default-features --features experimental-*`,
remove those flags. All modules are now unconditionally compiled. See
`docs/UPGRADE_0_56_TO_1_0.md` for the full migration guide.


## Runtime feature flags

Wardex also supports a runtime feature-flag registry for gradual rollout of
new capabilities without recompilation.

### API endpoints

| Method | Path                               | Description                    |
|--------|------------------------------------|--------------------------------|
| GET    | `/api/feature-flags`               | List all runtime flags         |
| PUT    | `/api/feature-flags/{name}`        | Update a flag's state          |
| POST   | `/api/feature-flags/{name}/toggle` | Toggle a flag on/off           |

### Creating a runtime flag

```bash
curl -X PUT http://localhost:9077/api/feature-flags/new-dashboard \
  -H 'Content-Type: application/json' \
  -d '{"enabled": true, "rollout_pct": 25}'
```

### Checking a flag

```bash
curl http://localhost:9077/api/feature-flags/new-dashboard
```

Runtime flags support canary/gradual rollout via `rollout_pct` (0–100) and
can be toggled without restarting the server.
