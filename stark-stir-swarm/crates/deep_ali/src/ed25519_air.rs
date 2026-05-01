// ed25519_air.rs — Ed25519 signature verification AIR (RFC 8032 §5.1.7) over Goldilocks.
//
// This module is the *composition layer* for in-circuit Ed25519 verification.
// It glues together four sub-AIRs, each in its own module:
//
//   • `crate::sha512_air`        — SHA-512 of (R || A || M)
//   • `crate::ed25519_field`     — F_{2^255 − 19} arithmetic (planned)
//   • `crate::ed25519_group`     — Edwards25519 point ops (planned)
//   • `crate::ed25519_scalar`    — Double-and-add scalar mult (planned)
//
// The deliverable is a single `Ed25519VerifyAir` exposed via
// `air_workloads::AirType::Ed25519ZskKsk` that proves
//
//     [8] · ([s]·B − R − [k]·A) = O          (the identity point)
//
// where:
//
//   • B is the standard Ed25519 base point.
//   • A is the public key (32-byte compressed Edwards encoding, decompressed in-circuit).
//   • R is the first 32 bytes of the signature (compressed point, decompressed in-circuit).
//   • S is the last 32 bytes of the signature, interpreted as a little-endian
//     scalar ∈ [0, L) where L = 2^252 + 27742317777372353535851937790883648493.
//   • k = SHA-512(R || A || M) reduced mod L.
//
// Per RFC 8032 §5.1.7, this is the *cofactored* verification check ([8] · …);
// the *cofactorless* form (no leading [8]) is also accepted by some
// implementations.  We do the cofactored check because (a) it is what
// RFC 8032 specifies for the strict mode used by RFC 6605 (DNSSEC Ed25519)
// and (b) it admits batch verification, which we may exploit later.
//
// ─────────────────────────────────────────────────────────────────
// USE-CASE: ZSK-signed-by-KSK
// ─────────────────────────────────────────────────────────────────
//
// In the swarm DNS prover this AIR proves the second link of the trust
// chain (after DS→KSK / SHA-256, which is the responsibility of
// `sha256_air`):
//
//   • A    = KSK public key bytes from the parent zone's DNSKEY RRset.
//   • R||S = RRSIG over the ZSK DNSKEY RR.
//   • M    = canonical signed-data of the ZSK DNSKEY RRset
//            (RFC 4034 §3.1.8.1).
//
// Public-input binding `pi_s` (handled at the prover layer in
// `swarm-dns::prove_zsk_ksk_binding`):
//
//   • Bind A_compressed bytes to the public-input KSK pubkey.
//   • Bind R_compressed bytes to the first 32 bytes of the public-input RRSIG.
//   • Bind S_scalar bytes to the last 32 bytes of the public-input RRSIG.
//   • Bind M bytes to the public-input signed-data digest preimage.
//
// The AIR alone proves the algebraic relation; pi_s glues that relation
// to the bytes named in the public input.
//
// ─────────────────────────────────────────────────────────────────
// HIGH-LEVEL TRACE STRUCTURE (segmented)
// ─────────────────────────────────────────────────────────────────
//
// The trace is partitioned into four contiguous segments, each its own
// "phase".  Phase predicates live in the constraint evaluator and gate
// per-segment constraints; cross-segment cells (e.g. the SHA-512 digest
// that becomes the input scalar k) are bound via boundary constraints
// at the segment boundary rows.
//
//   ┌─────────────────────────────────────────────────────────────┐
//   │ Segment 1: SHA-512(R || A || M)                              │
//   │   rows  0 .. N_HASH                                          │
//   │   width = sha512_air::WIDTH (~1500 cols, see sha512_air doc)  │
//   │   produces digest h512 (8 × u64 = 16 limbs).                  │
//   ├─────────────────────────────────────────────────────────────┤
//   │ Segment 2: scalar k = h512 mod L                              │
//   │   rows N_HASH .. N_HASH + N_RED                                │
//   │   width = ed25519_scalar::REDUCE_WIDTH (~80 cols, sketch)     │
//   │   produces 256-bit k_bits via Barrett reduction or schoolbook │
//   │   long-division mod L.  Outputs k as 256 booleanised cells.   │
//   ├─────────────────────────────────────────────────────────────┤
//   │ Segment 3: point decompression (R_aff and A_aff)              │
//   │   rows segment-3-base .. +N_DECOMPRESS (~2 × small block)     │
//   │   width = ed25519_group::DECOMPRESS_WIDTH                     │
//   │   For each compressed (sign_bit, y) input: compute            │
//   │     u = y² − 1   (mod p)                                      │
//   │     v = d·y² + 1 (mod p)                                      │
//   │     x = sqrt(u/v) with sign matching sign_bit, or fail.       │
//   ├─────────────────────────────────────────────────────────────┤
//   │ Segment 4: scalar multiplication and equality check           │
//   │   rows segment-4-base .. + 256·N_DBL_ADD                      │
//   │   width = ed25519_scalar::SCALARMULT_WIDTH                    │
//   │   Computes [s]B and [k]A in parallel via double-and-add over  │
//   │   bit-decomposition of S_scalar and k respectively.           │
//   │   Adds extra rows for cofactor multiplication ([8]) and       │
//   │   final identity check on the residual point.                 │
//   └─────────────────────────────────────────────────────────────┘
//
// Segment boundaries are anchored by row counters in the public input
// so the verifier can slice the trace LDE consistently with the prover.
// All segments are zero-padded up to a power-of-two trace height (the
// framework requires N_TRACE = 2^k).
//
// ─────────────────────────────────────────────────────────────────
// WHY PHASED RATHER THAN INTERLEAVED
// ─────────────────────────────────────────────────────────────────
//
// An alternative is to pack everything into a single wide row with all
// sub-AIRs running in parallel, each on its own column block.  We
// prefer the segmented approach because:
//
//   1. Trace height for the whole thing is dominated by scalar mult
//      (~256 doublings × constant rows-per-double), not by the hash.
//      Interleaving would force every row to carry every block's
//      width, blowing up total cells.
//
//   2. The segments have very different column counts: SHA-512 needs
//      ~1500 cols, point decompress needs ~200, scalar mult needs
//      ~150 per round.  Phase-gated constraints zero out unused cells
//      cheaply (the cells exist as zero in those rows; transition
//      constraints in inactive segments evaluate to zero by gating).
//
//   3. Cross-segment binding stays simple: a single boundary constraint
//      at the row joining segment N with N+1 forces the carry-over
//      cells (e.g. h512 limbs at the end of segment 1 = k-input limbs
//      at the start of segment 2) without needing to thread them
//      through every intermediate row.
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET (rough, will be exact when each sub-AIR lands)
// ─────────────────────────────────────────────────────────────────
//
//   Segment 1  SHA-512        ~1550 trans + boundary on 16 H-limbs
//   Segment 2  k = h mod L     ~120 trans + boundary on 256 k-bits
//   Segment 3  decompress      ~600 trans (2 × decompress)
//   Segment 4  scalar mult    ~3500 trans + final identity check
//   ──────────────────────────────────────────────────────────────
//   TOTAL                     ~5800 transition constraints,
//                             all degree ≤ 2.
//
// All sub-AIRs aim for max degree 2 to keep the composition quotient
// small (degree-2 constraints map to degree-(2·N_TRACE − 2) composition
// polynomials, which the existing FRI blowup factor handles cleanly).
//
// ─────────────────────────────────────────────────────────────────
// IMPLEMENTATION ORDER (see top-level task list)
// ─────────────────────────────────────────────────────────────────
//
//   Phase 1: sha512_air         — IN PROGRESS (this commit lands ref + padding)
//   Phase 2: ed25519_field      — F_{2^255 − 19} mul/add/sub/inverse over Goldilocks
//   Phase 3: ed25519_group      — Edwards add, dbl, decompress
//   Phase 4: ed25519_scalar     — Bit-decomp + double-and-add ladder
//   Phase 5: this file          — Compose; AirType::Ed25519ZskKsk
//   Phase 6: swarm-dns prover   — prove_zsk_ksk_binding
//   Phase 7: swarm-verify hook  — STARK-preferred verify path with dalek fallback
//   Phase 8: bench              — examples/zsk_ksk_bench.rs
//   Phase 9: paper §10.8        — protocol writeup
//
// No code in this file yet — it exists to (a) document the master plan
// so future commits stay coherent and (b) reserve the module path so
// `pub mod ed25519_air;` in `lib.rs` doesn't break the build while the
// sub-AIRs land incrementally.

#![allow(dead_code)]
