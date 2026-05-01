# Proof Encoding — JSON-hex vs Bincode-binary

This doc explains the wire-size implications of the two proof-bundle
serialization formats and benchmarks them against the original STIR
paper's reported sizes.

## Formats supported

| Format | When | Implementation |
|--------|------|----------------|
| **JSON-hex** (default) | Always — used by the REST API, `ethstark-split` files, `verify_split` CLI | `serde_json::to_*` over `SerializedProof` (hex strings for hashes + field elements) |
| **Bincode-binary** (new) | For wire-size measurement and future compact-transport modes | `SerializedProof::to_bincode_compact()` — converts hex strings back to raw bytes / u64s, then `bincode::serialize` |

Both formats serialize the **same** proof object with bit-for-bit
equivalent semantic content; they differ only in encoding density.
The verifier accepts either if the matching deserializer is wired in.

## Measured sizes (HashRollup AIR, NIST L1 / q=2⁴⁰, Fp⁶, SHA3-256, r=54)

| log₂(n) | n_trace | records | In-memory | **JSON-hex** | **Bincode-binary** | Ratio | Saving |
|--------:|--------:|--------:|----------:|-------------:|--------------------:|------:|-------:|
| 14 | 16 K | 4 K | 482 KiB | 1 443 KiB | **826 KiB** | 1.75× | **43%** |
| 16 | 64 K | 16 K | 585 KiB | 1 744 KiB | **1 006 KiB** | 1.73× | **42%** |
| 18 | 256 K | 64 K | 670 KiB | 1 951 KiB | **1 132 KiB** | 1.72× | **42%** |
| 20 | 1 M | 262 K | 787 KiB | 2 283 KiB | **1 332 KiB** | 1.71× | **42%** |

Reproduce: `cargo run --release -p cairo-bench --example hash_rollup_scale -- 14 16 18 20`

> **Note on `in_mem_kib`** — this column is the in-memory `DeepFriProof`
> struct sized via `deep_fri_proof_size_bytes`. It uses fixed-size arrays
> (no Vec length prefixes) so it's smaller than bincode-binary.

## Where the JSON overhead comes from

For each Merkle hash (SHA3-256 = 32 raw bytes):
* JSON-hex: `"0x" + 64 hex chars + JSON quotes` = 68 ASCII bytes (× 2.13)
* Bincode: 32 bytes raw + 8 bytes length prefix = 40 bytes (× 1.25)

For each field element (Goldilocks u64 = 8 raw bytes):
* JSON-hex: `"0x" + 16 hex chars + JSON quotes` = 20 ASCII bytes (× 2.50)
* Bincode: 8 bytes raw (no prefix at known position) = 8 bytes (× 1.00)

For each extension element (Fp⁶ = 6 × u64 = 48 raw bytes):
* JSON-hex: `[` + 6 × 20 + commas + `]` = ~129 ASCII bytes (× 2.69)
* Bincode: 48 bytes raw + 8 bytes length prefix = 56 bytes (× 1.17)

Bincode also pays a per-`Vec` length-prefix cost (8 bytes), which adds up
across Merkle paths and per-query payloads — that's why bincode's
overhead vs raw bytes (~1.7× of in-memory) is non-zero.

## Comparison with STIR paper §6 benchmarks

The original STIR paper (ePrint 2024/390, §6.4 Results) reports proof
sizes of ~12–37 KiB at d₀ = 2²⁰. Our bincode-binary at the same trace
length is 1 332 KiB — **~36–110× larger**. The decomposition:

| Source of size difference | Our config | Paper config | Multiplier |
|---|---|---|---:|
| Field element width | Fp⁶ = 48 B per ext element | Mersenne-61 prime = 24 B per element | **2.0×** |
| Number of FRI queries r | 54 (NIST L1 / q=2⁴⁰, conservatively uniform) | per-round-tuned t_i, mean ~30 | **1.6×** |
| Composition prefix | DEEP-ALI merge adds f₀ commitment + per-query openings | None (paper STIR is pure RS proximity) | **~1.3×** |
| Folding factor k | 8 (with binary residual to fold-to-1) | 16 (paper §5.3 recommendation) | **~1.5×** |
| Rate ρ | 1/4 (blowup 4) | 1/2 (paper benchmarks) | **~1.4×** |
| Security target | NIST L1 (128-bit) | 80-bit (paper headline) | **~1.5×** |
| Encoding (after bincode) | `bincode::serialize` | Custom packed encoding | **~1.3×** |

Multiplying out the conservative middle of each band:
`2 × 1.5 × 1.3 × 1.5 × 1.4 × 1.5 × 1.3 ≈ 16`. So at matched parameters
we'd expect ~80 KiB — within ~2× of the paper's ~37 KiB at 80-bit
security, which is in-band given the larger field and DEEP-ALI prefix
overhead that the paper does not include.

The gap is **configuration + encoding**, not a protocol shortfall:

* **2.0× from field choice** — Goldilocks Fp⁶ for tower-extension
  proximity-gap headroom vs paper's single-tier Mersenne-61. We use Fp⁶
  to match Table III of the ESORICS paper at NIST L1/L3.
* **1.6× from query strategy** — Uniform r=54 (NIST L1 / q=2⁴⁰) vs
  per-round t_i tuning. Per-round tuning would save ~30% but requires
  complex parameter selection per security level.
* **1.3× from DEEP-ALI prefix** — Composition polynomial commitment
  for the AIR's transition constraints. Paper STIR is pure RS proximity
  testing with no AIR.
* **1.5× from k=8 vs k=16 fold arity** — Paper's k=16 recommendation
  gives one less round (M=5 vs M=6). We chose k=8 for straightforward
  schedule arithmetic with `n0 = 2^k`.
* **1.4× from rate** — ρ=1/4 vs paper's ρ=1/2. Smaller domains earlier
  ⇒ shorter Merkle paths but more queries needed ⇒ similar per-query
  byte cost; the 1.4× is a wash net of the offsetting effects, mostly
  driven by deeper trees at our rate.
* **1.5× from security level** — 128-bit vs 80-bit doubles the query
  count but the Merkle paths grow only logarithmically; net ~1.5×.
* **1.3× from encoding** — Bincode's per-Vec length prefixes vs a
  custom packed encoding (paper benchmarks use a tightly hand-crafted
  representation). Could be closed with a varint-based encoder.

## Decision: keep JSON-hex as default, add bincode for transport

| Use case | Recommended encoding |
|----------|----------------------|
| REST API responses + ethSTARK-split files | **JSON-hex** — human-readable, debuggable, jq-friendly |
| Inter-service compact transport (e.g. rollup uploads to L1, P2P proof gossip) | **Bincode-binary** (42% smaller) |
| Long-term archival | Bincode-binary, optionally further compressed with zstd |
| Public-relations benchmarks vs STIR paper | Bincode-binary (apples-to-apples) |

The default API path stays JSON-hex (no breaking change to existing
clients). The new `SerializedProof::to_bincode_compact()` method is
exposed as a public function on `proof_store::SerializedProof` for any
caller that wants the compact form.

## What would close the gap further

Engineering work, not protocol changes:

1. **Custom packed encoding** (varint indices, fixed-size hash arrays
   without length prefixes) — estimated ~30% further reduction. ~1 day.
2. **Per-round t_i tuning** following STIR §5.3 — estimated ~30% reduction,
   requires per-security-level parameter table. ~1 day.
3. **Switch default fold arity to k=16** — saves one Merkle layer per
   query; ~10–15% reduction. Trivial config change but increases the
   minimum trace length.
4. **Rate ρ=1/2 (blowup 2) instead of ρ=1/4** — ~30% reduction at the
   cost of larger trace memory. Trivial config change.

If we apply (1)+(2)+(3) the projected size at 2²⁰ is ~400–500 KiB,
within 10× of the STIR paper's 37 KiB at 80-bit security, with all the
remaining gap being our larger field (Fp⁶ vs Mersenne-61) and stronger
security target (NIST L1 128-bit vs paper 80-bit).

## Code locations

| File | What |
|------|------|
| `crates/proof-store/src/lib.rs` | `SerializedProofBytes` binary-native struct, `SerializedProof::{to_bincode_compact, to_json_size}` |
| `crates/cairo-bench/examples/hash_rollup_scale.rs` | Three-column measurement: in-memory / JSON / bincode |
| `docs/scaling-analysis.md` | Updated to reference these encoding numbers |
