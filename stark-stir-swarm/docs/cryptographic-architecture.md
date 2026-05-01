# Cryptographic Configuration & Defaults

Authoritative reference for **what protocol our STARK code actually
runs** — versus the architectural slots that exist but aren't yet wired
into the prover hot path.  Updated alongside any change to defaults in
`crates/api/src/routes/prove.rs`.

## Protocol stack — what runs end-to-end

| Layer | Component | Default | Where set |
|-------|-----------|---------|-----------|
| Constraint reduction | **DEEP-ALI merge** | always on | `deep_ali::deep_ali_merge_general()` |
| Low-degree testing | **STIR** (was FRI in earlier versions) | **default** | `routes/prove.rs` `use_stir` resolution |
| Folding arity (STIR) | k = 8 (paper Table III) | **default** | `default_schedule(_, true)` |
| Folding arity (FRI) | k = 2 (binary; only proven-secure FRI arity) | **on `fri_mode: "fri"`** | `default_schedule(_, false)` |
| Final commit | `coeff_commit_final = true, d_final = 1` | always on | `DeepFriParams` builder |
| Public-inputs binding | SHA3-256 hash of public inputs absorbed first | always on | `bind_statement_to_transcript` |
| NIST profile resolution | Level × q-budget → (Ext, Hash, r) lookup | from request | `crates/api/src/security.rs` |
| Hash family (Merkle + transcript) | SHA3-256 / SHA3-384 / SHA3-512 | **compile-time feature** | `--features sha3-{256,384,512}` |
| Extension field | Fp⁶ (SexticExt) or Fp⁸ (OcticExt) | derived from NIST profile | `prove.rs` runtime dispatch |
| Parallel proving (rayon) | enabled | **default feature** | `default = ["sha3-256", "parallel"]` |

## STIR default (since this iteration)

Plain FRI is now opt-in via `config.fri_mode = "fri"`.  The default
mode for a `POST /v1/prove` request is **STIR with arity-8 folds**,
which:

* Eliminates the FRI proximity-gap conjecture for higher arities — STIR
  uses out-of-domain sampling and per-round consistency checks that
  yield `σ ≥ 1 − √ρ` for any `k`, so arity 8 is *unconditionally* sound
  in the Johnson regime (paper §III).
* Cuts authentication-path depth from `L+1` to `M+1` per query
  (constant-path commitment theorem, paper §III.B), which dominates
  proof size at production trace lengths.
* Matches Table III of the STIR-FIPS paper end-to-end:
  `k = 8, 1/ρ₀ = 32, M = 6, R = 15, paths/query = 7`.

If you need the legacy binary-fold FRI (e.g. for compatibility with
external verifiers that haven't been updated for STIR), pass
`config.fri_mode: "fri"`.  In that mode the schedule reverts to
arity 2 — **the only FRI arity with a proven proximity-gap soundness
theorem**.  Higher FRI arities require the conjectural Ben-Sasson /
Carmon correlated-agreement extension, which we explicitly reject for
FIPS-140-3 compliance.

## Folding schedule (the actual code)

```rust
// crates/api/src/routes/prove.rs
fn default_schedule(n0: usize, use_stir: bool) -> Vec<usize> {
    let log_n0 = n0.trailing_zeros() as usize;

    if !use_stir {
        // FRI mode: arity-2 binary fold (only proven-secure FRI arity).
        return vec![2usize; log_n0];
    }

    // STIR mode: arity-8 fold + residual to land at size 1.
    let log_arity = 3usize;            // log2(8)
    let full_folds = log_n0 / log_arity;
    let remainder_log = log_n0 % log_arity;
    let mut schedule = vec![8usize; full_folds];
    if remainder_log > 0 { schedule.push(1 << remainder_log); }
    schedule
}
```

Examples:

| `n0` | STIR schedule | FRI schedule |
|------|---------------|--------------|
| `2¹⁰` (1024) | `[8, 8, 8, 2]` | `[2, 2, …, 2]` × 10 |
| `2¹²` (4096) | `[8, 8, 8, 8]` | `[2, …, 2]` × 12 |
| `2²⁴` (16 M) | `[8, 8, 8, 8, 8, 8, 8, 8]` | `[2, …, 2]` × 24 |

Both schedules fold all the way to size 1, which is required by
`d_final = 1` + `coeff_commit_final = true`.

## Hash family selection (FIPS-202 binding wall)

The verifier-touching surface (Merkle commitments **and** Fiat-Shamir
transcript) uses one SHA3 variant chosen at compile time.  The variant
is implied by the **NIST profile** the request asks for — see
[`docs/api-walkthrough.md`](./api-walkthrough.md) §9 and the
`security.rs` lookup table:

| Build feature | Hash | NIST profiles servable |
|---------------|------|------------------------|
| `--features sha3-256` (default) | SHA3-256 | L1 / q=2⁴⁰ |
| `--features sha3-384` | SHA3-384 | L1 / q=2⁶⁵, L3 / q=2⁴⁰ |
| `--features sha3-512` | SHA3-512 | L1 / q=2⁹⁰, L3 / q=2⁶⁵, L3 / q=2⁹⁰, L5 / q=2⁴⁰, L5 / q=2⁶⁵, L5 / q=2⁹⁰ (binding-wall violator, opt-in) |

`GET /v1/security/profiles` returns which rows the running binary can
actually serve — `supported_by_build = true`.

## Dual-hash architecture — measured & resolved

The paper's "dual-hash architecture" confines Poseidon to prover-internal
acceleration and uses SHA-3 for everything verifier-touching.  We
implemented the leaf-compression variant of this (paper §III.B) as an
opt-in feature `poseidon-accel` and **empirically measured the impact
against the SHA-3-only baseline.**

### How `poseidon-accel` is implemented

In `crates/merkle/src/lib.rs`, the `compress_leaf_standalone` function
gains a feature gate:

```rust
#[cfg(feature = "poseidon-accel")]
{
    // Poseidon-T=17 sponge over RATE=16: absorb all field elements,
    // then SHA-3 the resulting 17-element state.
    let state = poseidon_leaf::poseidon_compress(values);
    for v in &state {
        Digest::update(&mut h, field_to_bytes(v));
    }
}
#[cfg(not(feature = "poseidon-accel"))]
{
    for v in values {
        Digest::update(&mut h, field_to_bytes(v));
    }
}
```

This matches the paper's "ephemeral Pos tree, re-committed via SHA-3"
pattern at the leaf level: the field values pass through one Poseidon
permutation per RATE=16 elements, then SHA-3 the state.  Internal Merkle
nodes remain SHA-3 only (Poseidon doesn't help compressing 32-byte
digests).  Both prover and verifier compute the same leaf hash (they
must — the feature is build-time consistent across both halves of the
protocol), so verifier soundness is unchanged either way.

### Measured comparison (Apple M-series, 10 cores, Goldilocks Fp⁶, r=54)

Both variants run the identical pipeline (HashRollup AIR, n_trace = 2ⁿ,
NIST L1 / q=2⁴⁰).  Source: `docs/poseidon-accel-measurement.csv`.

| log₂(n) | n_trace | records | **SHA3-only prove** | **Poseidon-accel prove** | Prover ratio | SHA3 verify | Poseidon verify | Verify ratio | Proof size | RSS |
|--------:|--------:|--------:|---------------------:|--------------------------:|-------------:|-------------:|-----------------:|-------------:|-----------:|----:|
| 14 | 16 K | 4 K | **0.34 s** | 28.08 s | **83.6×** ❌ | 2.5 ms | 119 ms | 47.6× ❌ | 482 KiB (=) | 102 MB (=) |
| 16 | 64 K | 16 K | **1.35 s** | 113.09 s | **83.9×** ❌ | 2.9 ms | 129 ms | 44.3× ❌ | 585 KiB (=) | 411 MB (=) |
| 18 | 256 K | 64 K | **5.46 s** | 452.99 s (≈ 7.5 min) | **83.0×** ❌ | 3.6 ms | 149 ms | 41.5× ❌ | 670 KiB (=) | 1.6 GB (=) |
| 20 | 1 M | 262 K | **22.42 s** | 1815.19 s (≈ 30 min) | **80.9×** ❌ | 4.1 ms | 158 ms | 38.5× ❌ | 787 KiB (=) | 4.4 GB (=) |

**The SHA-3-only path is ~81–84× faster on the prover and ~38–48× faster
on the verifier.**  Proof size and memory are identical (the feature
gate doesn't change the protocol or wire format — only the leaf-hash
internals).

### Why Poseidon loses in software for non-recursive STARKs

* Poseidon T=17, x⁵ S-box: ≈ 100 Goldilocks multiplications per
  permutation + linear layer mixing. Per *leaf*, the prover pays a
  full permutation regardless of leaf width.
* SHA-3-256 on 24–128 bytes (typical FRI leaf widths): one Keccak-f
  block, ~200 cycles on Apple Silicon (with hardware Keccak helpers
  on some CPUs).
* Poseidon's well-known advantage is **inside an AIR** (recursive STARK
  verifier circuits), where SHA-3 costs thousands of constraints but
  Poseidon costs a handful.  We're not in that regime — our verifier
  is native code.

### Decision: SHA-3-only is canonical

The default builds (and all CI test runs) use **SHA-3-only**.
`poseidon-accel` is preserved as a non-default Cargo feature for:

1. Future recursive-STARK use cases where the Poseidon-Merkle root is
   verified inside an AIR.
2. Empirical re-measurement on hardware where Poseidon-vs-SHA-3
   trade-offs differ (e.g. AVX-512-with-no-Keccak-acceleration).
3. Cross-comparison with peer STARK implementations that use Poseidon
   on the verifier path.

### Why this works (DEEP-ALI + STIR make SHA-3 viable)

Traditional FRI STARKs were forced toward algebraic hashes because:

* Each FRI layer opened **Θ(m)** authentication paths per query, and
  with `r ≈ 80` queries × `L ≈ 16` layers × 32-byte SHA-3 hashes, proof
  sizes blew up past 4 MB.

In our pipeline:

* **DEEP-ALI merge** collapses per-query authentication paths from
  `Θ(Σ mₗ)` to `L+1` per query (paper §III) by sampling the composition
  polynomial out-of-domain rather than at every fold layer.
* **STIR** further reduces this to `M+1` paths per query via its
  constant-path commitment theorem (paper §III.B), where `M ≪ L`.
* **Arity-8 fold** with paper-recommended `1/ρ₀ = 32` reduces `M` to 6
  for typical trace lengths, yielding **7 paths per query** (paper
  Table III).

The combined effect is that we make ~10× fewer SHA-3 calls per proof
than a classical FRI would, which is exactly the room needed to make
SHA-3-only competitive.  The DEEP-ALI + STIR architecture is what makes
"FIPS-202-only" practical — the paper's dual-hash isn't a *requirement*,
it's a *belt-and-braces option* for recursive use cases.

## What changed in this iteration

* `crates/api/src/routes/prove.rs`:
  * `use_stir` now defaults to `true`. `fri_mode` accepts only
    `"stir"`, `"fri"`, or absent (= STIR).
  * `default_schedule` is conditional on `use_stir`: arity 8 with
    residual for STIR, arity 2 (binary) for FRI.
* All 8 integration tests pass under the new defaults
  (`level1_q40_smoke`, `level5_q65_e2e`, `dns_rollup`, `rollup_demo`,
  + 5 security profile unit tests).
* Megazone demo (`examples/dns_megazone_demo`) runs cleanly under
  STIR-default.

## Verifying for yourself

```bash
# Confirm STIR is in the proof bundle
cargo test --release -p api --test rollup_demo -- --nocapture
# Look for `"stir": true` in the printed bundle JSON.

# Confirm arity-8 schedule for STIR proofs
STARK_KEEP_OUTPUT=1 cargo test --release -p api --test level5_q65_e2e -- --nocapture
# Then: jq .params.schedule /var/.../sampleoutput.params.json
# Should be [8,8,8,8,8,8,8,8] for n0=2^24, [8,8,8,2] for n0=2^10, etc.

# Confirm FRI mode falls back to arity 2
# (set "fri_mode": "fri" in any /v1/prove request)
```

## See also

* [`docs/api-walkthrough.md`](./api-walkthrough.md) — REST API & NIST profile selection
* [`docs/scaling-analysis.md`](./scaling-analysis.md) — performance measurements (note: pre-STIR-default, retest with STIR for current numbers)
* [`docs/dns-rollup-demo.md`](./dns-rollup-demo.md) — privacy-preserving rollup architecture
* [`docs/recursion-demo.md`](./recursion-demo.md) — rollup vs true recursion
