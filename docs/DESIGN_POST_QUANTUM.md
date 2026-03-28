# Post-Quantum Logging Upgrade Path

Design document for migrating the audit log and key management from classical cryptography to post-quantum algorithms, covering R11 (Post-Quantum Secure Audit Logs) and R21 (Quantum-Resistant Key Rotation).

## Current state

| Component | Algorithm | Status |
|-----------|-----------|--------|
| Audit chain | SHA-256 hash links | Implemented |
| Checkpoint signing | SHA-256 HMAC | Implemented |
| Proof binding | SHA-256 digests | Implemented |
| Key rotation | None | Not implemented |
| Digital signatures | None (HMAC only) | Not implemented |

SHA-256 is quantum-resistant as a hash function (Grover's algorithm reduces security from 256-bit to 128-bit, which is still adequate). The vulnerability lies in *digital signatures* — once the runtime uses Ed25519 or RSA for signing (swarm protocol, attestation), those become breakable by a sufficiently large quantum computer.

## Migration strategy

### Phase 1 — Classical signatures (prerequisite)

Before upgrading to PQ, the runtime needs proper digital signatures (currently absent):

1. Add Ed25519 signing for audit checkpoints (replacing HMAC).
2. Add Ed25519 signing for the swarm digest protocol (T051).
3. Add Ed25519 signing for build attestation manifests (T053).

### Phase 2 — Hybrid signatures

Adopt a hybrid signature scheme that produces both a classical and a PQ signature for every signed artifact:

```rust
pub struct HybridSignature {
    /// Classical Ed25519 signature (64 bytes).
    pub classical: [u8; 64],
    /// Post-quantum signature (Dilithium3: ~3293 bytes).
    pub post_quantum: Vec<u8>,
    /// Algorithm identifier for the PQ scheme.
    pub pq_algorithm: PqAlgorithm,
}

pub enum PqAlgorithm {
    /// NIST FIPS 204 (ML-DSA, formerly Dilithium)
    MlDsa65,
    /// NIST FIPS 205 (SLH-DSA, formerly SPHINCS+)
    SlhDsaShake128f,
}
```

**Rationale for hybrid:** verification continues to work with classical-only tools during the transition. PQ-aware verifiers check both signatures and reject if either fails.

### Phase 3 — PQ-only mode

Once the ecosystem matures and hybrid overhead is no longer justified:

1. Drop classical signatures from new artifacts.
2. Retain hybrid verification for historical artifacts signed during the transition.
3. Update the trust store to require PQ-only keys.

## Algorithm selection

| Use case | Classical | PQ candidate | PQ signature size | PQ verification time |
|----------|-----------|-------------|-------------------|---------------------|
| Audit checkpoints | Ed25519 (64 B) | ML-DSA-65 (3293 B) | ~50× larger | ~3× slower |
| Swarm digests | Ed25519 (64 B) | ML-DSA-65 (3293 B) | ~50× larger | ~3× slower |
| Build attestation | Ed25519 (64 B) | SLH-DSA-SHAKE-128f (17088 B) | ~267× larger | ~15× slower (but infrequent) |

**Trade-offs:**
- ML-DSA (lattice-based) is fast but produces larger signatures. Preferred for high-frequency operations.
- SLH-DSA (hash-based) has conservative security assumptions but very large signatures and slower signing. Preferred for infrequent, high-assurance operations like build attestation.

## Key management

### Key generation

```rust
pub struct PqKeyPair {
    /// Classical Ed25519 keypair.
    pub classical: Ed25519KeyPair,
    /// Post-quantum keypair (ML-DSA-65).
    pub post_quantum: MlDsaKeyPair,
    /// Key identifier (SHA-256 of concatenated public keys).
    pub key_id: [u8; 32],
    /// Key generation timestamp.
    pub created_at: u64,
    /// Key expiration (0 = no expiry).
    pub expires_at: u64,
}
```

### Key rotation protocol

1. Generate a new `PqKeyPair`.
2. Create a rotation message signed by *both* the old classical key and the old PQ key.
3. The rotation message contains the new public keys and a validity window.
4. Broadcast the rotation message to peers (swarm) and write to the local trust store.
5. Peers verify the rotation signature and add the new keys.
6. After `grace_period` (e.g., 72 hours), the old keys are marked expired.

### Energy-aware rotation scheduling

Key rotation is expensive (ML-DSA key generation takes ~1ms on ARM Cortex-A53). On battery-constrained devices:

1. Defer rotation until battery > `min_rotation_battery_pct` (default: 40%).
2. If below threshold, extend the current key's validity and log the deferral.
3. Perform rotation during scheduled maintenance windows when possible.
4. Never rotate during an active incident response (keys must be stable for audit).

```toml
[crypto.rotation]
algorithm = "hybrid"           # "classical", "hybrid", or "pq-only"
rotation_interval_hours = 168  # 7 days
min_battery_pct = 40
grace_period_hours = 72
defer_during_incident = true
```

## Audit chain changes

The current audit chain uses SHA-256 hash links between entries:

```
entry[n].hash = SHA-256(entry[n].data || entry[n-1].hash)
```

This does **not** need to change for PQ resistance — SHA-256 remains secure. The change is in how *checkpoints* are signed:

**Current (HMAC):**
```
checkpoint.mac = HMAC-SHA-256(key, chain_hash_at_checkpoint)
```

**Target (hybrid signature):**
```
checkpoint.signature = HybridSign(keypair, chain_hash_at_checkpoint)
```

This preserves the linear hash chain while upgrading the trust anchors to PQ-resistant signatures.

## Size impact analysis

| Artifact | Classical size | Hybrid size | Impact |
|----------|---------------|-------------|--------|
| Audit checkpoint | ~96 bytes (HMAC) | ~3,389 bytes | +3.3 KB per checkpoint interval |
| Swarm digest | ~256 bytes | ~3,549 bytes | +3.3 KB per gossip round |
| Build manifest | ~512 bytes | ~17,600 bytes | +17 KB per release (negligible) |
| Audit chain entry | ~128 bytes (hash only) | ~128 bytes (unchanged) | No change |

At a checkpoint interval of 100 entries and 8-sample runs, the overhead is minimal. For high-throughput deployments (10^5 samples), checkpoint size grows by ~33 KB total — acceptable for edge devices with ≥1 MB storage budget.

## Dependency candidates

| Crate | Algorithm | Status |
|-------|-----------|--------|
| `pqcrypto-dilithium` | ML-DSA (FIPS 204) | Wrapper around PQClean reference impl |
| `pqcrypto-sphincsplus` | SLH-DSA (FIPS 205) | Wrapper around PQClean reference impl |
| `oqs-rs` | Multiple PQ algorithms | Wrapper around liboqs (C dependency) |
| `ml-dsa` | ML-DSA pure Rust | RustCrypto project (experimental) |

**Recommendation:** Start with `pqcrypto-dilithium` behind a `pq` feature flag. Move to `ml-dsa` once the RustCrypto implementation stabilizes.

## Implementation phases

1. **v0.1** — Add Ed25519 signing for audit checkpoints (prerequisite — classical signatures).
2. **v0.2** — Define `HybridSignature` and `PqKeyPair` structs behind a `pq` feature flag.
3. **v0.3** — Integrate `pqcrypto-dilithium` for ML-DSA-65 key generation and signing.
4. **v0.4** — Implement hybrid checkpoint signing (classical + PQ).
5. **v0.5** — Add hybrid verification to the chain integrity checker.
6. **v0.6** — Implement energy-aware key rotation scheduling.
7. **v0.7** — Add PQ-only mode and migration tooling for existing audit logs.
