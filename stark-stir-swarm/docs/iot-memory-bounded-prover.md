# IoT Memory-Bounded Prover — Single-Device Proving at 2²⁵+ Trace

This document explains how to extend the existing in-memory prover so a
**single** IoT device with bounded RAM (≤ 1 GB) can prove traces far
larger than its physical RAM by streaming the LDE / FRI layers through
disk-backed buffers.

This is **complementary** to the swarm/sharding approach in
[`docs/swarm-prover.md`](./swarm-prover.md):

* **Swarm** = many devices each prove a small (in-RAM) shard, then aggregate.
* **Memory-bounded** = one device proves a large trace by spilling to SSD.

Both can be combined: a swarm of memory-bounded devices proves enormous
zones at very low cost.

## The memory wall at 2²⁵ trace (paper-aligned blowup = 32)

| Resource | Size | Notes |
|----------|-----:|-------|
| Trace witness (4 cols × Fp = 8 B) | **1 GB** | At the budget boundary already |
| LDE per column (Fp⁶ = 48 B) | **48 GB** per col, 192 GB for 4 cols | Cannot be RAM-resident |
| Layer-0 Merkle tree (n₀ × 32 B) | **32 GB** | |
| All FRI layers (Σ ≈ 2× LDE size) | **~400 GB** | |

The fundamental observation: **the FRI/STARK algorithm only needs
random access during the query phase**. Everything before that is
sequential — the LDE is produced row-by-row, the Merkle tree is built
leaf-by-leaf, FRI fold layer L→L+1 is a streaming map.

Therefore: keep working buffers small (≤ MB), spill bulk arrays to
SSD via mmap, and let the OS page cache handle hot data.

## Three categories of solution

### Category A — Disk-spillable buffers ⟶ ship-able in days

| Component | Approach | Resident memory |
|-----------|----------|-----------------|
| Trace witness | `mmap`-backed read-only file | OS-paged, 4–16 MB resident |
| LDE per column | `mmap`-backed write-once file (one per column) | O(working chunk) ≈ 4 MB |
| NTT/FFT | Six-step out-of-core (Bailey–Crandall): n=AB → A×B matrix transpose with disk-spilled rows | O(√n) resident |
| Merkle commit | Streaming SHA-3 over leaves; only the right "spine" of the tree (≤ ⌈log₂(n)⌉+1 hashes) lives in RAM | **~1 KB** ← this is the win |
| Each FRI layer | Computed streaming, written to disk, mmap'd on read at query time | O(working chunk) |
| FRI query phase | Random-access reads via mmap (kernel handles paging) | tens of KB |

**Realistic resident memory at 2²⁵ trace: ~50–200 MB.** Disk usage:
~250 GB at blowup = 32, ~16 GB at blowup = 2. (At blowup = 2 the `r`
recalibration kicks in: r=270 instead of 54, but proof size grows ~5×.)

### Category B — Algorithmic memory reductions ⟶ weeks

| Optimisation | Memory saving | Trade-off |
|--------------|---------------|-----------|
| Six-step / Bailey-Crandall FFT | n → √n | ~2× wall-clock for the disk I/O |
| Trace-on-the-fly: re-derive trace rows from a tiny seed | full trace storage | Per-row CPU cost at query time |
| Hash-only Merkle (don't store leaves) | 50–80% of tree | None (already standard) |
| Field-element packing | constant factor | None |
| ρ = 1/2 (blowup 2) | 16× domain shrink | r grows 5× (54 → 270), proof ~5× larger |
| Smaller extension Fp² instead of Fp⁶ | 3× | Lower extension-field security; only L1 / low-q viable |

### Category C — Research-grade approaches ⟶ months

* **Recursive proof composition.** Prove a 2¹⁹ inner trace, then prove
  "I verified a 2¹⁹ STARK" recursively. Each inner proof handles 2¹⁹;
  outer rolls up many inners → effective ≥ 2²⁵.
* **STARK-friendly memory-bounded VM.** Express the AIR's evaluator
  as a bounded-tape computation (Polygon Plonky3 distributed prover
  follows this pattern).
* **Sumcheck-based folding** (Lasso/Jolt). Replaces the LDE Merkle with
  a sumcheck protocol — O(log n) verifier work, O(n) prover work,
  **without** materialising the full LDE.

## Foundation shipped in this iteration

`crates/deep_ali/src/streaming.rs` defines the abstractions the
memory-bounded prover would dispatch through. **No I/O is performed
yet** — this is the trait surface plus a working `StreamingMerkleSpine`
implementation.

### `MemoryBudget`

```rust
pub struct MemoryBudget {
    pub max_resident_bytes: usize,      // soft cap on heap usage
    pub chunk_bytes:        usize,      // streaming I/O chunk size
    pub spill_dir:          PathBuf,    // where mmap spill files live
}

impl MemoryBudget {
    pub fn unbounded() -> Self { ... }                  // current behaviour
    pub fn for_iot(max_mb: usize, dir: ...) -> Self { ... }
    pub fn should_spill(&self, n: usize, elem_size: usize) -> bool { ... }
}
```

Pass this through to the prover and it decides per-allocation whether
to use a `Vec` (resident) or an mmap-backed file (spilled).

### `FpColumnRead` / `FpColumnWrite`

Generic random-read / sequential-write traits over base-field columns.
Implementors choose between `Vec<F>` (current path) and the future
`MmapColumn`. The prover stays agnostic.

### `StreamingMerkleSpine<const N: usize>`

A streaming Merkle tree that holds only the **right spine** in memory.

**Resident state at any time: at most `⌈log₂(n_leaves)⌉ + 1` hashes**,
one per tree level. At n = 2³⁰ that's 31 × 32 B = **992 bytes**, regardless
of how many leaves were pushed. The leaves themselves don't have to be
held — they hash into the spine and disappear.

```rust
let mut spine = StreamingMerkleSpine::<32>::new();
for chunk in lde_stream {
    for leaf_hash in compute_leaf_hashes(chunk) {
        spine.push_leaf(leaf_hash, &node_combine);
    }
}
let root: [u8; 32] = spine.finalise(&node_combine).unwrap();
```

Tested for:
- balanced (2^k) leaf counts via reference comparison
- unbalanced (n=5) leaf counts with paper-standard "duplicate orphans" padding
- resident-size bound (1024 leaves → ≤ 11 hashes resident at any point)

## Resident memory budget — what fits in 1 GB

Per-component when running in bounded mode at 2²⁵ trace:

| Component | Bounded-mode footprint | Why |
|-----------|------------------------:|-----|
| Trace witness (mmap) | ~16 MB resident | OS pages in only the active range |
| Per-column LDE (mmap × 4 cols) | ~16 MB × 4 = **64 MB** | One working chunk per column |
| Six-step FFT working buffer | ~√(2³⁰) × 48 B = 1.5 MB | Square-root memory FFT |
| Merkle spine (per layer × M layers) | 32 × M × 32 B = ~10 KB | StreamingMerkleSpine |
| Streaming FRI fold buffer | 1× chunk = 4 MB | Read-old, write-new |
| Query-phase mmap re-read | ~r × log n × 32 B = ~50 KB | r=54 queries × 30 levels × hash |
| Misc + slack | ~50 MB | |
| **Total resident** | **~150 MB** | Fits 1 GB device with room |

Disk usage: ~250 GB on the device's SSD at blowup=32. For an IoT device
with a smaller SSD (e.g. 32 GB), drop to blowup=2 → 16 GB disk, but
proof size grows ~5× and `r` recalculates from 54 to 270 (Johnson
formula).

## Proposed `deep_fri_prove_streaming` signature

```rust
pub fn deep_fri_prove_streaming<E: TowerField>(
    f0_source: Box<dyn FpColumnRead>,    // streaming trace input
    domain:    FriDomain,
    params:    &DeepFriParams,
    budget:    &MemoryBudget,             // ← new
) -> Result<DeepFriProof<E>, ProveError> {
    // 1. Initialise per-column LDE writers (Vec or Mmap based on budget)
    // 2. Streaming NTT to fill LDE
    // 3. Constraint composition: stream f0_source, write composition column
    // 4. Streaming Merkle commit on each LDE column → root_f0
    // 5. FRI loop: for each layer, stream-read previous, stream-write next,
    //    streaming Merkle commit
    // 6. Sample queries (r positions per layer)
    // 7. mmap-read queried positions, build authentication paths
    // 8. Return DeepFriProof<E> (this is small — bounded by log(n) · r)
}
```

## Remaining work to ship the bounded-mode prover

| Step | Effort | Status |
|------|--------|:------:|
| `MemoryBudget` + column traits | 0.5 day | ✅ shipped (this commit) |
| `StreamingMerkleSpine` (working, tested) | 0.5 day | ✅ shipped (this commit) |
| `MmapFpColumn` / `MmapExtColumn` (mmap-backed Read+Write) | 1 day | ⏳ next |
| Six-step / out-of-core radix-2 NTT | 3 days | ⏳ next |
| Refactor `deep_fri_prove` to dispatch through the column trait | 2 days | ⏳ next |
| Per-shard memory-bounded test (2²² trace on 256 MB cap) | 1 day | ⏳ next |
| 2²⁵-trace integration test on real hardware | 1 day | ⏳ next |
| **Total** | **~9 dev-days** | foundation in place |

## Optional, controlled by config — existing prover unchanged

The streaming prover lives behind `MemoryBudget`. Pass
`MemoryBudget::unbounded()` and the dispatching code falls through to
the existing `Vec`-backed path, byte-for-byte equivalent to today's
behaviour.

A new feature flag `streaming-prover` (off by default) gates the mmap
implementation and its `memmap2` dependency, so deployments that don't
need bounded mode carry no extra deps.

```toml
[features]
default = []
streaming-prover = ["dep:memmap2"]
```

## Combining with the swarm

The most cost-effective deployment:

```
┌──────────────────────────────────────────────────────────────┐
│  Coordinator (single small box)                              │
│  /v1/swarm/prove → partition into shards of size ≤ 2²⁰      │
│                                                                │
│  100 × Raspberry Pi 4 (4 GB each)                             │
│  Each Pi runs streaming prover → fits 2²⁰ trace in 1.5 GB    │
│  Total swarm capacity = 100 × 2²⁰ records = 100 M records    │
│  Wall-clock with full parallelism = single shard prove       │
│                                                                │
│  Total hardware cost: ~$5 K                                   │
│  Compares to: single 1 TB-RAM server, ~$30 K cloud, doesn't   │
│  exist on Apple Silicon                                       │
└──────────────────────────────────────────────────────────────┘
```

Memory-bounded prover + swarm together push the achievable proof size
to **~10 B records** on commodity IoT hardware.

## Code map

| File | What |
|------|------|
| `crates/deep_ali/src/streaming.rs` | `MemoryBudget`, `Fp/Ext ColumnRead/Write` traits, `StreamingMerkleSpine` (with 7 unit tests) |
| `crates/deep_ali/src/lib.rs` | `pub mod streaming;` |
| `docs/iot-memory-bounded-prover.md` | This document |

## Tests

```bash
$ cargo test --release -p deep_ali --features sha3-256 streaming
test result: ok. 7 passed
   - streaming_spine_matches_recursive_tree_8_leaves
   - streaming_spine_unbalanced_5_leaves
   - streaming_spine_resident_size_is_logarithmic
   - budget_should_spill_threshold
   - budget_unbounded_never_spills
   - budget_for_iot_caps_at_target
   - resident_writer_round_trip
```

## What's NOT in this commit

* Actual mmap I/O (would need `memmap2` dep)
* Six-step / out-of-core FFT
* The `deep_fri_prove_streaming` glue
* Integration with the swarm prover so individual devices can take a
  bigger shard

These are tracked in the table above; their interfaces are pinned by
the traits already shipped.

## See also

* [`docs/swarm-prover.md`](./swarm-prover.md) — sharding across devices
* [`docs/scaling-analysis.md`](./scaling-analysis.md) — measured RAM
  per trace size with the existing in-memory prover (the data this
  document's projections are calibrated against)
* [`docs/r-per-blowup.md`](./r-per-blowup.md) — Johnson-formula `r`
  recalibration if you want to drop blowup from 32 to 2 to shrink the
  domain at the cost of more queries
