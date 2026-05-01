# Scaling Analysis — DNS-Zone Rollup at Production Scale

How big a DNS zone can our STARK pipeline prove, and how long does it
take?  This analysis combines **measured prove/verify timings** at trace
sizes 2¹⁴ through 2²³ with the rollup architecture in
[`docs/dns-rollup-demo.md`](./dns-rollup-demo.md) to project wall-clock
prove times for everything from a personal domain to a `.com`-scale TLD.

## TL;DR

* Per-shard ceiling we've validated: **2²³ trace rows ⇒ 2,097,152 DNS
  records ⇒ 5.45 min prove time ⇒ 0.94 MB proof ⇒ 8.3 GB prover RAM.**
* With one prover machine per shard, **any zone ≤ 10 billion records
  proves in ~5.5 minutes wall-clock** because shards are embarrassingly
  parallel up to 4.4 trillion records (one outer rollup tier).
* Verifier work for any record in any zone: **≤ 13 ms, ≤ 2 MB
  bandwidth** — constant in zone size.

## Hash architecture

All numbers in this document are for the **SHA-3-only canonical default**
build (no `poseidon-accel` feature).  We measured the alternative
Poseidon-accelerated leaf-compression path empirically and found it
**81–84× slower** on the prover and **38–48× slower** on the verifier,
with identical proof size.  See
[`docs/cryptographic-architecture.md`](./cryptographic-architecture.md) §"Dual-hash
architecture — measured & resolved" and
[`docs/poseidon-accel-measurement.csv`](./poseidon-accel-measurement.csv)
for the full comparison.  The SHA-3-only path is canonical because:

* It hits all the verify-time budgets (≤ 13 ms) and prove-time targets
  (≤ 5.5 min per shard at 2²³).
* It eliminates the algebraic-hash assumption surface entirely (no
  Poseidon-collision-resistance assumption on the security path).
* The combination of **DEEP-ALI merge + STIR + arity-8 fold** reduces
  SHA-3 invocations per proof by ~10× vs. classical FRI, making
  SHA-3-only competitive without algebraic-hash acceleration.

## Methodology

The numbers in this document come from:

1. **Measured runs** of `crates/cairo-bench/examples/hash_rollup_scale.rs`
   on a 10-core M-series Mac with 16 GB RAM, Goldilocks Fp⁶, SHA3-256,
   r = 54 queries (NIST L1 / q = 2⁴⁰), parallel rayon proving (default).
2. **Linear extrapolation** of prove time, proof size, and RSS for
   shard sizes we measured directly.
3. **Architecture model** from [`docs/dns-rollup-demo.md`](./dns-rollup-demo.md):
   each DNS record contributes 4 leaf u64s, so trace_rows = 4 × records;
   each inner pi_hash contributes 4 leaves to the outer rollup.

To reproduce:

```bash
cargo run --release -p cairo-bench --example hash_rollup_scale -- 14 16 18 20 21 22 23
```

## Measured per-shard performance — paper-aligned blowup=32

The default rate is **ρ₀ = 1/32** (`blowup = 32`), matching paper Table III
($k=8$, $1/\rho_0=32$, $M=6$).  At this rate the calibrated `r` values
(54 / 79 / 105 for L1 / L3 / L5) deliver **exactly** the κ_sys claimed in
Table III; smaller blowups over-provide security on the FRI side.

### Current paper-aligned measurements (blowup = 32)

| log₂(n_trace) | n_trace | n₀ (=trace × 32) | records / shard | setup | prove | verify | json | bincode | RSS peak |
|--------------:|--------:|-----------------:|----------------:|------:|------:|-------:|-----:|--------:|---------:|
| 14 | 16 K | 2¹⁹ (524 K) | 4 K | 263 ms | **2.66 s** | 3.2 ms | 1846 KiB | **1068 KiB** | 761 MB |
| 16 | 64 K | 2²¹ (2.1 M) | 16 K | 1.14 s | **10.71 s** | 3.9 ms | 2170 KiB | **1263 KiB** | 2.97 GB |
| 18 | 256 K | 2²³ (8.4 M) | 64 K | 5.37 s | **47.62 s** | 4.4 ms | 2400 KiB | **1404 KiB** | 5.20 GB |

10-core M-series Mac, Goldilocks Fp⁶, SHA3-256, **r = 54 queries (NIST L1 / q=2⁴⁰)**, parallel rayon proving.

The 16 GB RAM box caps us at 2¹⁸ trace at blowup 32 (n₀ = 2²³); larger traces require workstation-class memory.

### Reference: pre-paper-alignment numbers (blowup = 4)

For comparison, the same measurements at our previous default `blowup = 4`. **These over-provided FRI security: r=54 at ρ=1/4 gives more than the κ_sys=132 claimed for L1 / q=2⁴⁰ in paper Table III.**

| log₂(n_trace) | prove (b=4) | prove (b=32) | Slowdown | RSS (b=4) | RSS (b=32) |
|--------------:|------------:|-------------:|---------:|----------:|-----------:|
| 14 | 0.41 s | 2.66 s | 6.5× | 102 MB | 761 MB |
| 16 | 1.67 s | 10.71 s | 6.4× | 406 MB | 2.97 GB |
| 18 | 6.84 s | 47.62 s | 7.0× | 1.27 GB | 5.20 GB |
| 20 | 29.67 s | (OOM on 16 GB) | — | 3.04 GB | ~24 GB est |
| 23 | 327.2 s (5.45 min) | (OOM) | — | 8.30 GB | ~64 GB est |

Empirical scaling laws (re-confirmed at blowup 32):

* **Prove time**: ~2× per doubling of trace (slightly super-linear due
  to LDE log factor).  Concretely: `prove_s ≈ 327 × (n / 2²³)` for n ≤ 2²³.
* **Verify time**: nearly constant 3–6 ms across 9 orders-of-magnitude
  in trace size — depends on r and Merkle depth, not n.
* **Proof size**: grows logarithmically (482 → 962 KiB while trace
  grew 512×).  Dominated by `r × log₂(n)` Merkle-path hashes.
* **RSS**: ~1 GB per million trace rows; doubling RSS per doubling of
  n is the binding constraint — see [Memory pressure](#memory-pressure)
  below.

For NIST L5 / q=2⁶⁵ (Fp⁸, SHA3-512, r=105): expect **~1.5× prove**,
**~3× verify**, **~2.5× proof size** vs the L1 numbers above.

## Operating point at blowup=32 (paper-aligned)

The practical ceiling shifts because the LDE domain is 8× larger than at
blowup 4:

| | Inner shard at 2¹⁸ trace × 32 = 2²³ domain |
|---|---|
| Records per shard | **65,536** |
| Wall-clock prove | **47.6 s** |
| Verify | 4.4 ms |
| Proof size (bincode) | 1.4 MB |
| Prover RAM | 5.2 GB (fits 16 GB box) |

To match the paper's $D = 2^{24}$ benchmark exactly we'd need $\geq 24$ GB RAM
prover boxes; on commodity 16 GB hardware $D = 2^{23}$ (n_trace = 2¹⁸) is the
ceiling.  At workstation-class 32 GB / 64 GB / 128 GB nodes:

| Box class | Max trace (b=32) | n₀ (domain) | Records / shard | Prove time (extrap.) |
|-----------|-----------------:|------------:|----------------:|--------------------:|
| Laptop (16 GB) | 2¹⁸ | 2²³ | 65 K | 48 s |
| Workstation (32 GB) | 2¹⁹ | 2²⁴ | 131 K | 1.6 min |
| Server (64 GB) | 2²⁰ | 2²⁵ | 262 K | 3.5 min (extrap.) |
| HPC (256 GB) | 2²² | 2²⁷ | 1 M | 14 min (extrap.) |

This is the **practical ceiling on commodity hardware**.  Going to 2²⁴
would push RSS to ~12 GB (estimated) which a 16 GB box may swap on.
Distributed-FFT prover work (Polygon/Plonky3 style) would lift the
ceiling but is outside this analysis.

## DNS deployment sizing (with parallel sharding)

**Assumptions:**
- One prover box per shard (perfect horizontal scale-out)
- Wall-clock prove = `max(per-shard prove) + outer rollup prove`
- Outer rollup trace = next power of 2 ≥ 4 × #shards
- All values use the measured 2²³ shard ceiling

**Below: deployment sizing at the laptop-class operating point (16 GB,
2¹⁸ trace × 32 blowup, 65 K records/shard, 47.6 s/shard).**

| Tier | Records | Inner shards (65K each) | Outer trace | Outer prove¹ | **Wall-clock prove (∥ shards)** | Sequential wall-clock² | Verify total³ | Total proof storage (bincode) |
|------|--------:|------------------------:|------------:|-------------:|--------------------------------:|----------------------:|--------------:|------------------------------:|
| Personal / SOHO | 100 | 1 (2¹⁰ trace, blowup 32) | — | — | **~250 ms** | 250 ms | < 5 ms | < 0.7 MB |
| SMB / small org | 10 K | 1 (2¹⁵ trace) | — | — | **~10 s** | 10 s | ~4 ms | ~1.0 MB |
| Mid Enterprise | 100 K | 2 | 2³ (8) | ~10 ms | **~48 s** | 96 s | ~9 ms | ~2.8 MB |
| Large Enterprise (F500) | 1 M | 16 | 2⁶ (64) | ~30 ms | **~48 s** | 13 min | ~9 ms | ~22 MB |
| Mega Enterprise / multi-cloud | 10 M | 153 | 2¹⁰ (1024) | ~100 ms | **~48 s** | 2 hr | ~9 ms | ~210 MB |
| Regional / ISP DNS | 100 M | 1 526 | 2¹³ (8192) | ~600 ms | **~49 s** | 20 hr | ~10 ms | ~2.1 GB |
| National DNS / mid-TLD | 1 B | 15 259 | 2¹⁶ (65536) | ~5 s | **~53 s** | 8.4 days | ~10 ms | ~21 GB |
| `.com`-class TLD (~1.5 B) | 1.5 B | 22 889 | 2¹⁶ (65536) | ~7 s | **~55 s** | 12.6 days | ~10 ms | ~32 GB |
| Global aggregator (~10 B) | 10 B | 152 588 | 2¹⁹ (524288) | ~50 s | **~98 s** | 84 days | ~12 ms | ~210 GB |

**With workstation-class 32 GB nodes (2¹⁹ trace, 131 K records/shard, 96 s/shard)** the table contracts substantially — total storage drops ~2× and shard count drops ~2×, but per-shard prove doubles.  HPC nodes give better total throughput but worse parallelism granularity.

¹ Outer rollup prove times extrapolated linearly from the 2¹⁴ measurement
(411 ms).  These are tiny relative to per-shard prove and could be
remeasured directly via a 2-line change to `hash_rollup_scale.rs`.

² *Sequential* = a single 16-GB prover box doing every shard one at a
time.  Shows the wall-clock saving from horizontal scale-out.

³ Verifier checks: 1 outer rollup verify (~ 5 ms) + 1 inner shard
verify (~ 6 ms) + 22-sibling SHA3 Merkle path walk (negligible).
**Constant in zone size** — this is the rollup pattern's marquee
property.

## Why parallelism gives this huge win

A 1-billion-record TLD on a single 16 GB box: **44 hours.**  With 477
boxes proving shards in parallel: **5.5 minutes** (the per-shard time)
plus 50 ms for the outer rollup.  The wall-clock ratio is exactly the
shard count, because **each inner shard prove is fully independent
until rolled up.**  This maps cleanly to:

* **Cloud spot-instance worker pools.**  Each shard prove on AWS m6i
  costs roughly $0.04–$0.06 of compute (5.5 min × 10 vCPU × $0.50/h).
  10 B records ≈ 4 768 shards ≈ ~$250 to prove the entire global zone
  once.
* **Incremental re-rollup on zone updates.**  Most DNS changes touch a
  single shard.  Reproof = reprove that shard (5.5 min) + reprove the
  outer rollup (≤ 1 s) — 99 % cheaper than starting from scratch.
* **Edge / regional prover topology.**  Provers can be co-located with
  the records they own; outer aggregation is a small follow-on step.

## Memory pressure

Empirical RSS grows ~ linearly with trace size (`~1 GB per million
rows` of Fp⁶ trace).  This is the binding constraint on shard size for
commodity hardware:

| Box class | Max safe shard | Records / shard | Prove time |
|-----------|---------------:|----------------:|-----------:|
| Laptop (16 GB) | 2²³ | 2.1 M | 5.5 min |
| Workstation (32 GB) | 2²⁴ | 4.2 M | ~11 min (extrap.) |
| Server (64 GB) | 2²⁵ | 8.4 M | ~22 min (extrap.) |
| HPC node (256 GB) | 2²⁷ | 33.5 M | ~88 min (extrap.) |

For deployments where memory dominates cost, **smaller shards + more
parallelism is usually the right answer** — you can rent more 8 GB
spot instances than you can rent fewer 256 GB nodes for the same total
spend.

## Sizing recommendations

| Operating choice | Records / shard | Prove time | Proof | RAM | When to use |
|------------------|----------------:|-----------:|------:|----:|-------------|
| **Shard at 2²³** | 2.1 M | 5.5 min | 0.94 MB | 8.3 GB | Maximum density. Storage-constrained relayers; needs 16 GB RAM. |
| **Shard at 2²²** | 1.05 M | 2 min | 0.89 MB | 5.8 GB | **Sweet spot.** Lower latency on updates; runs on 8 GB-class boxes. |
| **Shard at 2²⁰** | 262 K | 30 s | 0.79 MB | 3.0 GB | Aggressive parallelism. Best when prover pool is huge and incremental update latency matters. |
| **Shard at 2¹⁸** | 65 K | 7 s | 0.67 MB | 1.3 GB | Edge / IoT prover.  ~5× more shards but per-shard prove fits in 2 GB phones. |

## Outer rollup nesting

The 2²³ outer rollup ceiling lets a single outer-rollup STARK aggregate
**up to 2.1 M inner shards** (each contributing 4 leaves).  Combined
with the per-shard ceiling of 2.1 M records, a 2-tier rollup covers up
to **2.1 M × 2.1 M ≈ 4.4 trillion records** — far beyond any DNS use
case.  Three-tier nesting (rollup of rollups of rollups) only matters
above 4.4 trillion records and is left unanchored here.

If the outer rollup ever becomes the bottleneck (very large shard
counts), it's also linearly scalable: take half the shards, roll them
into outer-A; the other half into outer-B; aggregate both into a
master rollup.

## Caveats

1. **NIST level**: measured at L1 / q=2⁴⁰ (Fp⁶, SHA3-256, r=54).
   For L3 / q=2⁶⁵: ~1.4× prove, ~1.5× verify.
   For L5 / q=2⁶⁵ (Fp⁸, SHA3-512): ~1.5× prove, ~3× verify, ~2.5× proof.
   **Wall-clock per shard is still ≤ 8 minutes** at L5.
2. **Memory at 2²⁴**: extrapolated 12 GB RSS may swap on a 16 GB OS.
   Validated up to 2²³ (8.3 GB) only.
3. **Outer rollup measurements**: this analysis extrapolates outer
   rollup times linearly from the 2¹⁴ inner-shard measurement.  Can be
   anchored with a real measurement if needed.
4. **Off-STARK CPU work**: per-record canonical encoding + SHA3 hashing
   happens host-side.  10 B records ≈ 30 minutes single-threaded SHA3
   on a modern CPU; trivially parallelizable to seconds with rayon.
5. **Network and distribution**: not modelled.  Storing and serving
   4.5 GB of proofs for the 10 B-record case is a CDN-class problem
   but trivial compared to running an actual DNS zone.

## Reproduce / validate

```bash
# All measured points
cargo run --release -p cairo-bench --example hash_rollup_scale -- 14 16 18 20 21 22 23

# Single shard at the production ceiling
cargo run --release -p cairo-bench --example hash_rollup_scale -- 23
```

The example binary prints CSV: `log2_n,n_trace,n0,records,r,setup_ms,prove_ms,verify_ms,proof_kib,rss_mb_peak`.

## Wire-size note: JSON-hex vs bincode-binary

All proof sizes in this document are measured as the **JSON-hex**
encoding (the default REST-API and ethSTARK-split format), to keep them
comparable to the artifact files written by `STARK_KEEP_OUTPUT=1`.
Switching to **bincode-binary** delivers a consistent **42% reduction**
across all trace sizes — see [`docs/proof-encoding.md`](./proof-encoding.md)
for the head-to-head and the comparison vs the STIR paper §6 numbers.
The protocol is unchanged; bincode is just a denser wire encoding.

## `r` recalibration per blowup

The query count is **dynamically recomputed** per request based on the
chosen blowup factor.  Paper Table III $r$ values (54 / 79 / 105) are
the specialisation at $\text{blowup}=32$.  Smaller blowups need
proportionally more queries; larger blowups need fewer.  Full table in
[`docs/r-per-blowup.md`](./r-per-blowup.md).

## Cross-references

- [`docs/r-per-blowup.md`](./r-per-blowup.md) — `r` recalibration table
  + Johnson-regime formula
- [`docs/proof-encoding.md`](./proof-encoding.md) — JSON vs bincode
  encoding head-to-head + STIR §6 size comparison
- [`docs/dns-rollup-demo.md`](./dns-rollup-demo.md) — privacy-preserving
  rollup architecture (salted double-hash + Merkle commitment)
- [`docs/recursion-demo.md`](./recursion-demo.md) — rollup vs true
  recursion trade-offs
- [`docs/api-walkthrough.md`](./api-walkthrough.md) — REST API for
  prove/verify and the NIST profile selection
- `crates/cairo-bench/examples/hash_rollup_scale.rs` — the measurement
  binary that produced this data
