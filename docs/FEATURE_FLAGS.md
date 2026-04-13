# Experimental Feature Flags

Wardex ships several experimental modules behind compile-time feature gates.
All are enabled by default; disable them for a leaner build or to avoid
pulling in heavy dependencies.

## Compile-time features

| Feature                  | Module            | Description                                      |
|--------------------------|-------------------|--------------------------------------------------|
| `experimental-ml`        | `ml_engine`       | ONNX-based ML triage and anomaly scoring         |
| `experimental-llm`       | `llm_analyst`     | LLM-assisted analyst (OpenAI, Anthropic, Ollama) |
| `experimental-quantum`   | `quantum`         | Post-quantum key rotation (Kyber, Dilithium)     |
| `experimental-proof`     | `proof`           | Zero-knowledge proofs for privacy forensics      |

### Building without experimental features

```bash
# Minimal core build
cargo build --release --no-default-features

# Only ML triage
cargo build --release --no-default-features --features experimental-ml

# ML + LLM but no quantum/proof
cargo build --release --no-default-features --features experimental-ml,experimental-llm
```

### Default build (all features)

```bash
cargo build --release
```

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
