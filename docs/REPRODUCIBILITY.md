# Reproducibility & Supply-Chain Verification

Wardex publishes every production binary, container image, and Linux package with
cryptographic provenance so that downstream operators can verify what they run.

## What each release ships

For every tagged release (`vX.Y.Z`):

| Artifact                                  | Provenance                                                       |
|------------------------------------------ |----------------------------------------------------------------- |
| `wardex-linux-x86_64.tar.gz`              | SLSA v1.0 build-provenance attestation (GitHub attestation API)  |
| `wardex-macos-{aarch64,x86_64}.tar.gz`    | SLSA v1.0 build-provenance attestation                           |
| `wardex-windows-x86_64.zip`               | SLSA v1.0 build-provenance attestation                           |
| `wardex_<ver>_amd64.deb` / `.rpm`         | Shipped in the same release, signed with the release GPG key     |
| `wardex-sbom.cdx.json`                    | CycloneDX SBOM generated from the release `Cargo.lock`           |
| `ghcr.io/pinkysworld/wardex:<tag>`        | Cosign keyless signature + SLSA v1.0 container provenance        |

## Verify a release archive

Requires [GitHub CLI](https://cli.github.com/) 2.49+.

```bash
# Download an archive from the release page, then:
gh attestation verify wardex-linux-x86_64.tar.gz \
  --repo pinkysworld/Wardex
```

A successful verification confirms the archive was produced by
`.github/workflows/release.yml` on `pinkysworld/Wardex` for the expected tag.

## Verify the container image

```bash
IMAGE=ghcr.io/pinkysworld/wardex:0.53.3

# 1. Cosign keyless signature (subject is the release workflow run)
cosign verify \
  --certificate-identity-regexp "^https://github.com/pinkysworld/Wardex/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE"

# 2. SLSA v1.0 build provenance
gh attestation verify "oci://$IMAGE" --repo pinkysworld/Wardex
```

## Verify SBOM coverage

```bash
# From a release asset archive:
cosign download attestation "$IMAGE" \
  | jq -r '.payload' \
  | base64 -d \
  | jq '.predicate.buildDefinition.externalParameters'
```

The attached CycloneDX SBOM (`wardex-sbom.cdx.json`) enumerates every crate and
transitive dependency with version + license. Diff two releases to see
dependency churn:

```bash
diff <(jq -r '.components[] | "\(.name)@\(.version)"' older-sbom.cdx.json | sort) \
     <(jq -r '.components[] | "\(.name)@\(.version)"' newer-sbom.cdx.json | sort)
```

## Build reproducibility notes

Wardex strives for *bit-similar* reproducibility — identical source and
identical toolchain produce identical output — subject to these caveats:

- `rustc` is pinned to MSRV **1.88.0** at runtime but the release profile uses
  `stable`. Minor `rustc` version changes may alter debug metadata.
- `lto = true` + `codegen-units = 1` remove non-determinism from parallel
  codegen.
- Container base layers (`rust:1.88-bookworm`, `debian:bookworm-slim`) are
  pulled by tag. For strict reproducibility pin to the image digest emitted in
  the SBOM.
- Release archives include platform-specific binaries plus `site/` and
  `examples/`; the latter two are byte-identical across platforms.

## Reporting a discrepancy

If you cannot verify an artifact or find a provenance mismatch, follow the
disclosure process in [`SECURITY.md`](../SECURITY.md).
