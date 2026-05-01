# Recursion / Rollup Demo

This codebase ships a **rollup-style recursion demo**: two inner STARKs, each
proving a Cairo computation, are aggregated into a single outer "rollup"
STARK that commits to both of them.

## Architecture

```
  ┌─────────────────────────┐     ┌─────────────────────────┐
  │  Inner STARK A          │     │  Inner STARK B          │
  │  AIR = CairoSimple      │     │  AIR = CairoSimple      │
  │  n_trace = 64           │     │  n_trace = 128          │
  │  → pi_hash_A (32 bytes) │     │  → pi_hash_B (32 bytes) │
  └────────────┬────────────┘     └────────────┬────────────┘
               │ pack 4×u64                    │ pack 4×u64
               └───────────────┬───────────────┘
                               ▼
               leaves = [hA0,hA1,hA2,hA3, hB0,hB1,hB2,hB3, 0,…]
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Rollup STARK                                               │
  │  AIR = HashRollup (w=4, 3 deg-2 constraints)                │
  │      C0: idx'      − idx − 1                = 0             │
  │      C1: state_sq  − state·state            = 0             │
  │      C2: state'    − state_sq − leaf        = 0             │
  │  → rolled-up = state[n_rollup]                              │
  │  → public_memory carries (pi_hash_A, pi_hash_B, rolled-up)  │
  └─────────────────────────────────────────────────────────────┘
```

## Why this is "rollup-style" and not "true recursion"

| | Pragmatic rollup (this demo) | True FRI recursion |
|---|---|---|
| Outer AIR encodes | Hash aggregation of inner commitments | The FRI verifier of the inner proof |
| Witness for outer prover | Two pi_hashes (32 bytes each) | Two full inner proofs (~600 KB each) |
| Outer constraint count | 3 (this demo) | Thousands (Merkle paths + degree check) |
| Verifier trust assumption | Verifier checks outer + each inner | Verifier checks outer only |
| Engineering effort | Hours | Weeks (port FRI verifier to AIR) |

Production rollups (StarkNet, zkSync) start with the pragmatic pattern and
graduate to recursion once a verifier-as-AIR exists. The two compose: one
rollup proof can certify the aggregation arithmetic, while a recursion
layer eventually elides the per-inner verification step.

## Running the demo

```bash
cargo test --release -p api --test rollup_demo -- --nocapture
```

Expected output:

```
[STEP 1] Generate inner STARK A (CairoSimple, n_trace=64)
  inner   prove=5 ms size=622006 id=...
  pi_hash_A = 5f4ce0374275f21b7c7d267fe566375a...

[STEP 2] Generate inner STARK B (CairoSimple, n_trace=128)
  inner   prove=7 ms size=799298 id=...
  pi_hash_B = 09c030fb68cfac9d0490e081a7f0bdfe...

[STEP 3] Rollup leaves prepared. Expected aggregate = 0x0de9ce7d6e397a0a

[STEP 4] Generate rollup STARK (HashRollup AIR over both pi_hashes)
  rollup  prove=1 ms size=503031 id=...

[STEP 5] Verify rollup STARK                  → valid=true (2 ms)
[STEP 6] Independently verify inner STARK A   → valid=true (2 ms)
[STEP 7] Independently verify inner STARK B   → valid=true (3 ms)
[STEP 8] Tampered rollup PI → HTTP 400 — rejected pre-FRI

=== ROLLUP DEMO SUCCESS ===
```

## Verifier workflow

To validate a rollup, a relying party performs three independent verifications:

1. **Verify the rollup STARK** — confirms the aggregation arithmetic
   (`state' = state² + leaf` chain) was executed correctly. If valid,
   the rolled-up commitment in `public_memory` is genuinely the hash
   chain over the leaves the prover claimed.

2. **Verify inner STARK A** — confirms the bytes claimed as `pi_hash_A`
   actually came from a real, valid execution of inner program A.

3. **(Optional) Verify inner STARK B** — same for B.

If all three return `valid=true`, the relying party knows: there exist
real, distinct executions whose public commitments hash together to the
rolled-up value carried in the rollup STARK's public inputs.

Tampering at any layer is detected:

| Tamper | Detected by |
|--------|-------------|
| Inner STARK proof | Inner FRI verifier (Merkle / degree check) |
| pi_hash inside rollup public_memory | API consistency check (commitment hash mismatch — HTTP 400 in demo) |
| Rollup STARK proof | Rollup FRI verifier |
| Replace inner proof with fake → forge pi_hash → forge rollup | Forging requires breaking SHA3-256 commitment binding |

## Code map

| File | Purpose |
|------|---------|
| `crates/deep_ali/src/air_workloads.rs` | `AirType::HashRollup`, trace builder, constraint evaluator, `pack_hash_to_leaves`, `compute_hash_rollup_final_state` |
| `crates/api/src/types.rs` | `ProverConfigInput.air_type` config field |
| `crates/api/src/routes/prove.rs` | `air_type: "hash_rollup"` dispatch + width-4 default |
| `crates/api/tests/rollup_demo.rs` | End-to-end test (2 inner + 1 rollup + tamper) |
| `crates/cairo-bench/cairo/hash_rollup.cairo` | Cairo 0 source illustrating the aggregator |

## REST API request shape (rollup proof)

```jsonc
POST /v1/prove
{
  "trace": {
    "format": "starkware-v1",
    "width":  4,
    "length": 16,
    "columns": {
      "col0_idx":      [0, 1, 2, ..., 15],
      "col1_leaf":     [hA0, hA1, hA2, hA3, hB0, hB1, hB2, hB3, 0, ...],
      "col2_state":    [running state values],
      "col3_state_sq": [running state² values]
    }
  },
  "public_inputs": {
    "program_hash":    "0x726f6c6c75702d76310...",   // "rollup-v1" tag
    "initial_pc":      0,
    "initial_ap":      hA0,                           // = leaves[0]
    "initial_fp":      0,                             // state[0]
    "final_pc":        15,
    "final_ap":        0,                             // = leaves[15] (padding)
    "memory_segments": [{"start":0,"stop":16}],
    "public_memory": [
      { "address": 40960, "value": hA0 },             // 0xA000 + 0..3 → pi_hash_A
      { "address": 40961, "value": hA1 },
      { "address": 40962, "value": hA2 },
      { "address": 40963, "value": hA3 },
      { "address": 45056, "value": hB0 },             // 0xB000 + 0..3 → pi_hash_B
      { "address": 45057, "value": hB1 },
      { "address": 45058, "value": hB2 },
      { "address": 45059, "value": hB3 },
      { "address": 49152, "value": rolled_up }        // 0xC000 → final aggregate
    ],
    "range_check_min": 0,
    "range_check_max": 18446744073709551615
  },
  "config": {
    "nist_level":          1,
    "quantum_budget_log2": 40,
    "air_type":            "hash_rollup"
  }
}
```

The `public_memory` entries make the inner-proof commitments and the
rolled-up value programmatically readable from the bundle JSON, so a
verifier walking the rollup proof can extract them and look up the
referenced inner proofs in a content-addressable store.

## Path to true recursion

Replacing the `HashRollup` AIR with a `FriVerifier` AIR converts this from
rollup into recursion. The FriVerifier AIR's constraints would encode:

1. SHA3-256 round function as constraint polynomials (≈ 3000 constraints)
2. Merkle authentication path verification (per-query)
3. FRI fold consistency (per-layer)
4. Final low-degree polynomial reconstruction

Each inner proof becomes the *witness* of one outer-AIR execution; the
outer prover demonstrates "I ran the FRI verifier and it returned true".
This is mechanical engineering work — every component already exists
in our codebase; the missing piece is expressing them as Goldilocks
arithmetic constraints.
