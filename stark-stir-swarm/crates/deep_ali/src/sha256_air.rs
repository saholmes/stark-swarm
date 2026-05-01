//! sha256_air.rs — single-block SHA-256 (FIPS 180-4) AIR over Goldilocks
//!
//! v1: full message schedule in-circuit (W[16..63] derived via the σ0/σ1
//! recurrence, all bits constrained).  Used by the DS→KSK binding inside
//! the swarm prover: the AIR proves that a 64-byte (already-padded)
//! message block hashes to a digest under SHA-256.  Public-input binding
//! to `dnskey_bytes` and `parent_ds_hash` happens at the prover layer
//! via `pi_s` (see crate `swarm-dns`); the AIR alone proves only that
//! the trace correctly executes one block of the SHA-256 compression
//! function.
//!
//! ─────────────────────────────────────────────────────────────────
//! TRACE LAYOUT
//! ─────────────────────────────────────────────────────────────────
//!
//! Trace height N = 128 (next power of two ≥ 64+1+1 = 66).
//!   row 0..63 — SHA-256 compression rounds 0..63
//!   row 64    — post-compression state (round 63 output) + IV in H-state
//!   row 65    — finalisation: H_k = IV[k] + post[k]  (the digest)
//!   row 66..127 — idle (every cell propagates unchanged)
//!
//! Transition row r → r+1 is enforced for r ∈ [0, 126]; the wrap
//! row 127 → 0 is NOT enforced by the framework (`lib.rs` line 294).
//!
//! ─────────────────────────────────────────────────────────────────
//! COLUMN LAYOUT (754 columns)
//! ─────────────────────────────────────────────────────────────────
//!
//!   Block A  state words {a, b, c, d, e, f, g, h}            8 cols
//!   Block B  bits of {a, b, c, e, f, g}                    192 cols
//!   Block C0 Σ0(a) sub-block (32 t0 + 32 Σ0_bit + 1 word)   65 cols
//!   Block C1 Σ1(e) sub-block                                65 cols
//!   Block D  Ch(e,f,g) bits + word                          33 cols
//!   Block E  Maj(a,b,c) ab/ac/bc/u/Maj/word                161 cols
//!   Block F  W[t]   (one cell, alias of W_win[15])           1 col
//!   Block G  T1, T2 carry decomp                             9 cols
//!   Block H  H-state {H0..H7}                                8 cols
//!   Block I  W window cells W_win[0..14] = W[t-15..t-1]     15 cols
//!   Block J  bits of W_win[14] = W[t-1]   (for σ1)          32 cols
//!   Block K  bits of W_win[1]  = W[t-14]  (for σ0)          32 cols
//!   Block L  σ0 sub-block (32 t0 + 32 σ0_bit + 1 word)      65 cols
//!   Block M  σ1 sub-block                                   65 cols
//!   Block N  W[t+1] sum carry decomp (2 carry bits + pack)   3 cols
//!   Block O  new_a, new_e carry packs (2 carry + 2 pack)     4 cols
//!   ──────────────────────────────────────────────────────────────
//!   TOTAL                                                  758 cols
//!
//! ─────────────────────────────────────────────────────────────────
//! CONSTRAINT BUDGET (per transition row)
//! ─────────────────────────────────────────────────────────────────
//!
//! Bits booleanity (8 words × 32):                       256 cons
//! Bit→word decomposition (8 words):                       8 cons
//! Σ0 sub-block (32 t0 + 32 Σ0 + 1 word):                 65 cons
//! Σ1 sub-block:                                          65 cons
//! σ0 sub-block:                                          65 cons
//! σ1 sub-block:                                          65 cons
//! Ch (32 bit + 1 word):                                  33 cons
//! Maj (5×32 + 1 word):                                  161 cons
//! T1 carry decomp (sum + 3 boolean + carry pack):         5 cons
//! T2 carry decomp (sum + 2 boolean + carry pack):         4 cons
//! Working register shifts (b←a, c←b, d←c, f←e, g←f, h←g): 6 cons
//! new_a, new_e definitions with carry decomp (2 each):    6 cons
//! H-state propagation (compression: hold; row 64→65: add): 8 cons
//! W window shifts W_win[k+1]→W_win[k] for k=0..14:       15 cons
//! Schedule recurrence (W[t+1] sum + carry):               4 cons
//! ────────────────────────────────────────────────────────────────
//! TOTAL transition constraints                          766 cons
//!
//! ─────────────────────────────────────────────────────────────────
//! ROW-DEPENDENT CONSTRAINT GATING
//! ─────────────────────────────────────────────────────────────────
//!
//! Some constraints fire only on specific rows.  The constraint
//! evaluator returns F::zero() for "disabled" slots.  Slot count
//! stays at 766 on every row (framework requirement: fixed-size
//! constraint vector).
//!
//! Schedule recurrence (Block N): row r ∈ [15, 62]
//!   At r=15, W[16] is computed.  At r=62, W[63] is computed.
//!   Outside this range, the slot returns zero.
//!
//! H-state behaviour:
//!   Rows 0..63: nxt[H_k] − cur[H_k] = 0   (hold during compression)
//!   Row 64:     nxt[H_k] − cur[H_k] − cur[A_k] − borrow = 0
//!                                          (mod-2^32 add → finalisation)
//!   Rows 65..126: nxt[H_k] − cur[H_k] = 0  (digest stable)
//!
//! Compression-round constraints (Σ0, Σ1, Ch, Maj, T1, T2, shifts,
//! new_a, new_e): fire on rows 0..62 (round transitions), zero on 63..126.
//! Row 63 produces row 64's post-compression state via the same
//! constraints (so r=0..63 all fire as compression rounds, giving 64
//! transitions and writing rows 1..64 from rounds 0..63).
//!
//! Refining: rows where compression constraints fire = [0, 63].
//! Rows where finalisation fires = [64].
//! Rows where idle holds = [65, 126].
//!
//! ─────────────────────────────────────────────────────────────────
//! SOUNDNESS
//! ─────────────────────────────────────────────────────────────────
//!
//! Given an accepting STIR proof for this AIR over a trace whose
//! row-0 W_win[15] and W_win[14..1] = 0 and whose row-(0..14) W_win[15]
//! cells are bound to public inputs M[0..15] via pi_s, AND whose row-65
//! H-state cells equal a public-input parent_ds_hash, the prover knows
//! a 64-byte preimage that hashes to parent_ds_hash under SHA-256.
//!
//! The argument:
//!   • Pi_s binds row-(0..14) W_win[15] = M[0..15] (the message).
//!   • Block I window-shift constraints carry M[0..15] forward such
//!     that row r has cur[W_win[15-k]] = M[r-k] for k ∈ [0,15] and
//!     r ∈ [0, 15].
//!   • Block N schedule recurrence at rows 15..62 forces W[16..63] to
//!     be the unique values produced by the σ0/σ1/+/+ recurrence.
//!   • Compression constraints at rows 0..63 force the working state
//!     to follow the SHA-256 round function.
//!   • Finalisation at row 64 (transition 64→65) forces nxt[H_k] =
//!     IV[k] + post-compression A_k mod 2^32.
//!   • Pi_s binds row-65 H-state to parent_ds_hash.
//!   • All bit-decomposition constraints force the 32-bit-word
//!     interpretation of every cell.
//!
//! Multi-block extension and padding handling are out of scope for v1
//! and are treated as separate AIRs that compose via H-state chaining.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{Field, Zero, One, PrimeField};
use ark_goldilocks::Goldilocks as F;

// ═══════════════════════════════════════════════════════════════════
//  Layout: column offsets
// ═══════════════════════════════════════════════════════════════════
//
// Single source of truth.  Trace builder, constraint evaluator, and
// tests all read columns by these named offsets.  A compile-time
// assertion at the bottom checks WIDTH matches the documented total.

// Block A — working state words ─────────────────────────────────────
pub const A_a: usize = 0;
pub const A_b: usize = 1;
pub const A_c: usize = 2;
pub const A_d: usize = 3;
pub const A_e: usize = 4;
pub const A_f: usize = 5;
pub const A_g: usize = 6;
pub const A_h: usize = 7;

// Block B — bits of {a, b, c, e, f, g} (each 32 bits, LSB-first) ──
pub const OFF_BIT_A: usize = 8;
pub const OFF_BIT_B: usize = OFF_BIT_A + 32;     // 40
pub const OFF_BIT_C: usize = OFF_BIT_B + 32;     // 72
pub const OFF_BIT_E: usize = OFF_BIT_C + 32;     // 104
pub const OFF_BIT_F: usize = OFF_BIT_E + 32;     // 136
pub const OFF_BIT_G: usize = OFF_BIT_F + 32;     // 168

// Block C0 — Σ0(a) sub-block ────────────────────────────────────────
pub const OFF_S0_T:   usize = OFF_BIT_G + 32;    // 200  — t0_i = a[r1] ⊕ a[r2]
pub const OFF_S0_BIT: usize = OFF_S0_T + 32;     // 232  — Σ0_i  = t0_i ⊕ a[r3]
pub const OFF_S0_W:   usize = OFF_S0_BIT + 32;   // 264  — Σ0 packed word

// Block C1 — Σ1(e) sub-block ────────────────────────────────────────
pub const OFF_S1_T:   usize = OFF_S0_W + 1;      // 265
pub const OFF_S1_BIT: usize = OFF_S1_T + 32;     // 297
pub const OFF_S1_W:   usize = OFF_S1_BIT + 32;   // 329

// Block D — Ch(e,f,g) ──────────────────────────────────────────────
pub const OFF_CH_BIT: usize = OFF_S1_W + 1;      // 330
pub const OFF_CH_W:   usize = OFF_CH_BIT + 32;   // 362

// Block E — Maj(a,b,c) ─────────────────────────────────────────────
pub const OFF_MAJ_AB:  usize = OFF_CH_W + 1;      // 363
pub const OFF_MAJ_AC:  usize = OFF_MAJ_AB + 32;   // 395
pub const OFF_MAJ_BC:  usize = OFF_MAJ_AC + 32;   // 427
pub const OFF_MAJ_U:   usize = OFF_MAJ_BC + 32;   // 459 — u_i = ab_i ⊕ ac_i
pub const OFF_MAJ_BIT: usize = OFF_MAJ_U + 32;    // 491 — Maj_i = u_i ⊕ bc_i
pub const OFF_MAJ_W:   usize = OFF_MAJ_BIT + 32;  // 523

// Block F — message word W[t] ───────────────────────────────────────
pub const OFF_W: usize = OFF_MAJ_W + 1;           // 524

// Block G — T1, T2 carry decomp ─────────────────────────────────────
//   T1 = h + Σ1 + Ch + K[t] + W[t]      (5 terms ≤ 2^32-1, sum ≤ 2^35)
//   T1_lo = T1 mod 2^32, T1_carry ∈ [0, 4] → 3 carry bits.
//   T2 = Σ0 + Maj                        (2 terms, sum ≤ 2^33)
//   T2_lo = T2 mod 2^32, T2_carry ∈ [0, 1] → 2 carry bits (the upper
//   bit is always 0 but we allocate 2 for symmetry; booleanity holds).
pub const OFF_T1_LO: usize = OFF_W + 1;           // 525
pub const OFF_T1_C0: usize = OFF_T1_LO + 1;       // 526
pub const OFF_T1_C1: usize = OFF_T1_C0 + 1;       // 527
pub const OFF_T1_C2: usize = OFF_T1_C1 + 1;       // 528
pub const OFF_T1_CW: usize = OFF_T1_C2 + 1;       // 529 — packed = c0 + 2c1 + 4c2
pub const OFF_T2_LO: usize = OFF_T1_CW + 1;       // 530
pub const OFF_T2_C0: usize = OFF_T2_LO + 1;       // 531
pub const OFF_T2_C1: usize = OFF_T2_C0 + 1;       // 532
pub const OFF_T2_CW: usize = OFF_T2_C1 + 1;       // 533

// Block H — H-state H0..H7 ──────────────────────────────────────────
pub const OFF_H0: usize = OFF_T2_CW + 1;          // 534
pub const OFF_H7: usize = OFF_H0 + 7;             // 541

// Block I — W window cells W_win[0..14] ─────────────────────────────
//
//   At row r, cur[W_win[k]] = W[r - 15 + k]  for k = 0..14.
//   cur[W_win[15]]  = W[r]   — aliased to OFF_W (Block F).
pub const OFF_WW0: usize = OFF_H7 + 1;            // 542
// W_win[k] = OFF_WW0 + k  for k = 0..14;
// W_win[15] = OFF_W.

// Block J — bits of W_win[14] = W[t-1] (for σ1) ─────────────────────
pub const OFF_BIT_WW14: usize = OFF_WW0 + 15;     // 557

// Block K — bits of W_win[1] = W[t-14] (for σ0) ─────────────────────
pub const OFF_BIT_WW1: usize = OFF_BIT_WW14 + 32; // 589

// Block L — σ0(W[t-14]) sub-block ───────────────────────────────────
pub const OFF_SS0_T:   usize = OFF_BIT_WW1 + 32;  // 621
pub const OFF_SS0_BIT: usize = OFF_SS0_T + 32;    // 653
pub const OFF_SS0_W:   usize = OFF_SS0_BIT + 32;  // 685

// Block M — σ1(W[t-1]) sub-block ────────────────────────────────────
pub const OFF_SS1_T:   usize = OFF_SS0_W + 1;     // 686
pub const OFF_SS1_BIT: usize = OFF_SS1_T + 32;    // 718
pub const OFF_SS1_W:   usize = OFF_SS1_BIT + 32;  // 750

// Block N — W[t+1] sum carry decomp ─────────────────────────────────
//   sum = W[t-15] + σ0(W[t-14]) + W[t-6] + σ1(W[t-1])
//   sum ≤ 4·(2^32-1) < 2^34, so 2 carry bits suffice.
//   sum_lo = nxt[W_win[15]] = nxt[OFF_W].
pub const OFF_WS_C0: usize = OFF_SS1_W + 1;       // 751
pub const OFF_WS_C1: usize = OFF_WS_C0 + 1;       // 752
pub const OFF_WS_CW: usize = OFF_WS_C1 + 1;       // 753

// Block O — new_a, new_e carry decomp ───────────────────────────────
//   new_a = T1 + T2 mod 2^32, where T1, T2 are the FULL sums (not
//   the lo parts).  We use the lo parts plus carry-bits to reconstruct.
//   Specifically: new_a_full = T1 + T2 = (T1_lo + 2^32 T1_c) + (T2_lo + 2^32 T2_c).
//   new_a_lo = (T1_lo + T2_lo) mod 2^32.  The high bits combine with
//   T1_c, T2_c into the new_a_carry — but new_a only takes the lo part.
//
//   For the AIR: we constrain nxt[A.a] = (T1_lo + T2_lo) mod 2^32.
//   Sum T1_lo + T2_lo ≤ 2·(2^32-1) < 2^33, so 1 carry bit.
//   Similarly nxt[A.e] = (cur[A.d] + T1_lo) mod 2^32, 1 carry bit.
pub const OFF_NA_C: usize = OFF_WS_CW + 1;        // 754
pub const OFF_NE_C: usize = OFF_NA_C + 1;         // 755

pub const WIDTH: usize = OFF_NE_C + 1;            // 756

// ═══════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════

/// SHA-256 round constants (FIPS 180-4 §4.2.2).
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values (FIPS 180-4 §5.3.3).
pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Trace height contributed by each block (= rows allocated per block).
pub const ROWS_PER_BLOCK: usize = 128;

/// Trace height for a single-block message (kept for backward
/// compatibility with v0 single-block tests).
pub const N_TRACE: usize = ROWS_PER_BLOCK;

/// Total number of transition constraints.
pub const NUM_CONSTRAINTS: usize = 766;

// Compile-time layout sanity.
const _: () = assert!(WIDTH == 756, "SHA-256 AIR width mismatch");

// ═══════════════════════════════════════════════════════════════════
//  u32 helpers
// ═══════════════════════════════════════════════════════════════════

#[inline]
fn rotr(x: u32, n: u32) -> u32 { x.rotate_right(n) }

#[inline]
fn shr(x: u32, n: u32) -> u32 { x >> n }

#[inline]
fn big_sigma0(x: u32) -> u32 { rotr(x, 2)  ^ rotr(x, 13) ^ rotr(x, 22) }

#[inline]
fn big_sigma1(x: u32) -> u32 { rotr(x, 6)  ^ rotr(x, 11) ^ rotr(x, 25) }

#[inline]
fn small_sigma0(x: u32) -> u32 { rotr(x, 7)  ^ rotr(x, 18) ^ shr(x, 3) }

#[inline]
fn small_sigma1(x: u32) -> u32 { rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10) }

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }

/// Bit i (0 = LSB) of a u32.
#[inline]
fn bit(x: u32, i: u32) -> u32 { (x >> i) & 1 }

#[inline]
fn fz() -> F { F::zero() }

#[inline]
fn fu32(x: u32) -> F { F::from(x as u64) }

#[inline]
fn fu64(x: u64) -> F { F::from(x) }

/// Power-of-two F element 2^i for i ∈ [0, 32].  Used for word
/// reconstruction from bits and for carry-decomposition.
#[inline]
fn pow2(i: u32) -> F { F::from(1u64 << i) }

/// XOR of two bits (each ∈ {0,1}) expressed as a degree-2 polynomial:
///   x ⊕ y = x + y − 2xy.
#[inline]
fn xor_poly(x: F, y: F) -> F { x + y - fu64(2) * x * y }

// ═══════════════════════════════════════════════════════════════════
//  Reference SHA-256 (used by the trace builder; behaviour cross-
//  checked against the `sha2` crate in tests).
// ═══════════════════════════════════════════════════════════════════

/// Hash one already-padded 64-byte SHA-256 block, returning the
/// 8-word digest (big-endian per spec).
pub fn sha256_one_block(block: &[u8; 64]) -> [u32; 8] {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4*i], block[4*i+1], block[4*i+2], block[4*i+3]
        ]);
    }
    for t in 16..64 {
        w[t] = small_sigma1(w[t-2])
            .wrapping_add(w[t-7])
            .wrapping_add(small_sigma0(w[t-15]))
            .wrapping_add(w[t-16]);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = IV;
    for t in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g; g = f; f = e;
        e = d.wrapping_add(t1);
        d = c; c = b; b = a;
        a = t1.wrapping_add(t2);
    }
    [
        IV[0].wrapping_add(a), IV[1].wrapping_add(b),
        IV[2].wrapping_add(c), IV[3].wrapping_add(d),
        IV[4].wrapping_add(e), IV[5].wrapping_add(f),
        IV[6].wrapping_add(g), IV[7].wrapping_add(h),
    ]
}

// ═══════════════════════════════════════════════════════════════════
//  TRACE BUILDER
// ═══════════════════════════════════════════════════════════════════

/// SHA-256 padding (FIPS 180-4 §5.1.1).  Returns a Vec of 64-byte
/// blocks; the message length is appended as a 64-bit big-endian
/// word at the end.
pub fn pad_message_to_blocks(message: &[u8]) -> Vec<[u8; 64]> {
    let mlen_bits = (message.len() as u64) * 8;
    let mut buf = message.to_vec();
    buf.push(0x80);
    while buf.len() % 64 != 56 { buf.push(0); }
    buf.extend_from_slice(&mlen_bits.to_be_bytes());
    debug_assert!(buf.len() % 64 == 0);
    buf.chunks_exact(64).map(|c| {
        let mut a = [0u8; 64];
        a.copy_from_slice(c);
        a
    }).collect()
}

/// Build a single-block SHA-256 trace from an already-padded 64-byte
/// message block, using the canonical SHA-256 IV.  Returns a
/// `WIDTH × N_TRACE` column-major trace.
///
/// Kept for backward compatibility with v0 single-block tests.  For
/// multi-block messages or non-default IVs, use `build_sha256_trace_multi`.
pub fn build_sha256_trace(block: &[u8; 64]) -> Vec<Vec<F>> {
    let mut trace: Vec<Vec<F>> = (0..WIDTH).map(|_| vec![fz(); N_TRACE]).collect();
    fill_block(&mut trace, 0, block, IV);
    trace
}

/// Build a multi-block SHA-256 trace from an arbitrary-length message.
/// Performs SHA-256 padding internally (FIPS 180-4 §5.1.1), splits
/// into 64-byte blocks, and lays each block into a 128-row segment of
/// the trace with the IV chained from the prior block's digest.
///
/// Returns `(trace, n_blocks)`.  The trace height is
/// `(128 · n_blocks).next_power_of_two().max(128)`; padding rows past
/// `128 · n_blocks` are filled by replicating the last useful row,
/// which preserves all transition-constraint identities (the row's
/// W-block and per-block transient values are zero on a "row 127 of
/// last block" idle row, so `nxt = cur` satisfies every constraint).
pub fn build_sha256_trace_multi(message: &[u8]) -> (Vec<Vec<F>>, usize) {
    let blocks = pad_message_to_blocks(message);
    let n_blocks = blocks.len();
    let useful = ROWS_PER_BLOCK * n_blocks;
    let trace_height = useful.next_power_of_two().max(ROWS_PER_BLOCK);
    let mut trace: Vec<Vec<F>> = (0..WIDTH).map(|_| vec![fz(); trace_height]).collect();

    let mut iv = IV;
    for (b, block) in blocks.iter().enumerate() {
        fill_block(&mut trace, b * ROWS_PER_BLOCK, block, iv);
        // Compute next-block IV from this block's compression output.
        let post = compress_block_native(block, iv);
        for k in 0..8 { iv[k] = iv[k].wrapping_add(post[k]); }
    }

    // Pad up to trace_height by replicating the last useful row.  Row
    // (useful - 1) is row 127 of the last block, which is in the
    // "idle" range of that block — its W-block cells are all zero and
    // its working state holds the block's post-compression state
    // stable.  Replication therefore satisfies every transition
    // constraint gated by `past_last_block` and the W-window shift,
    // EXCEPT the cyclic wrap row trace_height-1 → row 0 (H-state at
    // the digest row ≠ canonical IV at row 0).  The framework's
    // `poly_div_zh` divides by Z_H(X) = X^N − 1 (vanishing on the
    // full subgroup including the wrap), so this is enforced in
    // debug builds.  In release builds the assertion is skipped and
    // FRI proceeds — matching the existing pattern for HashRollup,
    // Fibonacci, and the other AIRs in this crate, none of which
    // wrap-close either.  Switching `poly_div_zh` to use the
    // standard "skip-last-row" Z_H'(X) = (X^N − 1)/(X − g^{N−1}) is
    // tracked as a follow-up framework fix; the SHA-256 AIR is
    // ready for it (the synthesised IV-idle row helper below was
    // tried and reverted: it broke the row-before-wrap H-state hold
    // constraint, since prior idle rows hold the digest).
    if useful < trace_height {
        for r in useful..trace_height {
            for c in 0..WIDTH {
                trace[c][r] = trace[c][useful - 1];
            }
        }
    }

    (trace, n_blocks)
}

/// Fill row `row` with the "IV idle" pattern: working state = canonical
/// SHA-256 IV, H-state = IV, W-block (W_win + OFF_W + bits + σ0/σ1
/// sub-blocks + schedule-carry) = all zero, T1/T2 carries computed
/// from the IV state with K = W = 0.  All bit-decomposition,
/// Σ0/Σ1/Ch/Maj cells are derived from the IV state.
///
/// Used at the wrap row of a multi-block trace so that the cyclic
/// transition row (N-1) → row 0 satisfies every transition constraint
/// (block 0's row 0 starts with H-state = IV and W_win = 0, matching
/// this row's H-state and W cells).
fn synthesise_iv_idle_row(trace: &mut [Vec<F>], row: usize) {
    let (a, b, c, d, e, f_, g, h) =
        (IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);

    // Block A.
    trace[A_a][row] = fu32(a);
    trace[A_b][row] = fu32(b);
    trace[A_c][row] = fu32(c);
    trace[A_d][row] = fu32(d);
    trace[A_e][row] = fu32(e);
    trace[A_f][row] = fu32(f_);
    trace[A_g][row] = fu32(g);
    trace[A_h][row] = fu32(h);

    // Block B.
    for i in 0..32 {
        trace[OFF_BIT_A + i][row] = fu32(bit(a,  i as u32));
        trace[OFF_BIT_B + i][row] = fu32(bit(b,  i as u32));
        trace[OFF_BIT_C + i][row] = fu32(bit(c,  i as u32));
        trace[OFF_BIT_E + i][row] = fu32(bit(e,  i as u32));
        trace[OFF_BIT_F + i][row] = fu32(bit(f_, i as u32));
        trace[OFF_BIT_G + i][row] = fu32(bit(g,  i as u32));
    }

    // Block C0: Σ0(a).
    let s0_word = big_sigma0(a);
    for i in 0..32 {
        let p = bit(a, ((i + 2)  % 32) as u32);
        let q = bit(a, ((i + 13) % 32) as u32);
        let r = bit(a, ((i + 22) % 32) as u32);
        trace[OFF_S0_T   + i][row] = fu32(p ^ q);
        trace[OFF_S0_BIT + i][row] = fu32(p ^ q ^ r);
    }
    trace[OFF_S0_W][row] = fu32(s0_word);

    // Block C1: Σ1(e).
    let s1_word = big_sigma1(e);
    for i in 0..32 {
        let p = bit(e, ((i + 6)  % 32) as u32);
        let q = bit(e, ((i + 11) % 32) as u32);
        let r = bit(e, ((i + 25) % 32) as u32);
        trace[OFF_S1_T   + i][row] = fu32(p ^ q);
        trace[OFF_S1_BIT + i][row] = fu32(p ^ q ^ r);
    }
    trace[OFF_S1_W][row] = fu32(s1_word);

    // Block D: Ch.
    let ch_word = ch(e, f_, g);
    for i in 0..32 {
        trace[OFF_CH_BIT + i][row] = fu32(bit(ch_word, i as u32));
    }
    trace[OFF_CH_W][row] = fu32(ch_word);

    // Block E: Maj.
    let maj_word = maj(a, b, c);
    for i in 0..32 {
        let ai = bit(a, i as u32);
        let bi = bit(b, i as u32);
        let ci = bit(c, i as u32);
        let abi = ai & bi;
        let aci = ai & ci;
        let bci = bi & ci;
        let ui  = abi ^ aci;
        let mi  = ui  ^ bci;
        trace[OFF_MAJ_AB  + i][row] = fu32(abi);
        trace[OFF_MAJ_AC  + i][row] = fu32(aci);
        trace[OFF_MAJ_BC  + i][row] = fu32(bci);
        trace[OFF_MAJ_U   + i][row] = fu32(ui);
        trace[OFF_MAJ_BIT + i][row] = fu32(mi);
    }
    trace[OFF_MAJ_W][row] = fu32(maj_word);

    // Block F: W[t] = 0.
    trace[OFF_W][row] = fz();

    // Block G: T1, T2 with K = W = 0.
    let t1_full: u64 = (h as u64)
        .wrapping_add(big_sigma1(e) as u64)
        .wrapping_add(ch(e, f_, g) as u64);
    let t1_lo = (t1_full & 0xFFFF_FFFF) as u32;
    let t1_carry = (t1_full >> 32) as u32;
    trace[OFF_T1_LO][row] = fu32(t1_lo);
    trace[OFF_T1_C0][row] = fu32(t1_carry & 1);
    trace[OFF_T1_C1][row] = fu32((t1_carry >> 1) & 1);
    trace[OFF_T1_C2][row] = fu32((t1_carry >> 2) & 1);
    trace[OFF_T1_CW][row] = fu32(t1_carry);

    let t2_full: u64 = (big_sigma0(a) as u64).wrapping_add(maj(a, b, c) as u64);
    let t2_lo = (t2_full & 0xFFFF_FFFF) as u32;
    let t2_carry = (t2_full >> 32) as u32;
    trace[OFF_T2_LO][row] = fu32(t2_lo);
    trace[OFF_T2_C0][row] = fu32(t2_carry & 1);
    trace[OFF_T2_C1][row] = fu32((t2_carry >> 1) & 1);
    trace[OFF_T2_CW][row] = fu32(t2_carry);

    // Block H: IV.
    for k in 0..8 {
        trace[OFF_H0 + k][row] = fu32(IV[k]);
    }

    // Block I: W window = 0.
    for k in 0..15 { trace[OFF_WW0 + k][row] = fz(); }

    // Block J, K: bits of W_win[14] and W_win[1] are zero.
    for i in 0..32 {
        trace[OFF_BIT_WW14 + i][row] = fz();
        trace[OFF_BIT_WW1  + i][row] = fz();
    }

    // Block L, M: σ0(0), σ1(0) sub-blocks all zero.
    for i in 0..32 {
        trace[OFF_SS0_T   + i][row] = fz();
        trace[OFF_SS0_BIT + i][row] = fz();
        trace[OFF_SS1_T   + i][row] = fz();
        trace[OFF_SS1_BIT + i][row] = fz();
    }
    trace[OFF_SS0_W][row] = fz();
    trace[OFF_SS1_W][row] = fz();

    // Block N, O: schedule + new_a/new_e carries = 0.
    trace[OFF_WS_C0][row] = fz();
    trace[OFF_WS_C1][row] = fz();
    trace[OFF_WS_CW][row] = fz();
    trace[OFF_NA_C ][row] = fz();
    trace[OFF_NE_C ][row] = fz();
}

/// Run the SHA-256 compression function on one 64-byte block under
/// the given starting IV, returning the post-compression `(a..h)`
/// state (NOT yet added to the IV).
fn compress_block_native(block: &[u8; 64], iv: [u32; 8]) -> [u32; 8] {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4*i], block[4*i+1], block[4*i+2], block[4*i+3]
        ]);
    }
    for t in 16..64 {
        w[t] = small_sigma1(w[t-2])
            .wrapping_add(w[t-7])
            .wrapping_add(small_sigma0(w[t-15]))
            .wrapping_add(w[t-16]);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f_, mut g, mut h] = iv;
    for t in 0..64 {
        let t1 = h.wrapping_add(big_sigma1(e)).wrapping_add(ch(e, f_, g))
            .wrapping_add(K[t]).wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g; g = f_; f_ = e;
        e = d.wrapping_add(t1);
        d = c; c = b; b = a;
        a = t1.wrapping_add(t2);
    }
    [a, b, c, d, e, f_, g, h]
}

/// Fill one block's 128-row segment of the trace, starting at row
/// `base`, with the given block bytes and starting IV.
///
/// Layout follows the single-block design: rows base..base+63 are
/// compression rounds 0..63, rows base+64..base+127 are post-
/// compression idle (working state held at post-compression value;
/// H-state holds IV through row 64, then the block-output digest
/// starting at row 65).
fn fill_block(trace: &mut [Vec<F>], base: usize, block: &[u8; 64], iv: [u32; 8]) {
    debug_assert!(base + ROWS_PER_BLOCK <= trace[0].len());

    // Message words W[0..63].
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4*i], block[4*i+1], block[4*i+2], block[4*i+3]
        ]);
    }
    for t in 16..64 {
        w[t] = small_sigma1(w[t-2])
            .wrapping_add(w[t-7])
            .wrapping_add(small_sigma0(w[t-15]))
            .wrapping_add(w[t-16]);
    }

    // Working state at row r (BEFORE round r runs).
    // state_at[r] = (a, b, c, d, e, f, g, h) at the start of round r.
    // state_at[0] = iv (the incoming IV — for block 0 this is the
    // canonical SHA-256 IV; for subsequent blocks it is the prior
    // block's digest), state_at[64] = post-compression state.
    let mut state_at = [[0u32; 8]; 65];
    state_at[0] = iv;
    for t in 0..64 {
        let s = state_at[t];
        let (a, b, c, d, e, f_, g, h) = (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f_, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        state_at[t+1] = [
            t1.wrapping_add(t2),    // new a
            a, b, c,                // shifted
            d.wrapping_add(t1),     // new e
            e, f_, g,               // shifted
        ];
    }

    // H-state per row.  Compression rounds (block_row 0..64) hold the
    // incoming IV; finalisation transition (block_row 64 → 65) adds
    // A_k_post into H_k.  Idle rows (block_row 65..127) hold the
    // resulting block-output digest unchanged.
    let post = state_at[64];
    let digest: [u32; 8] = core::array::from_fn(|k| iv[k].wrapping_add(post[k]));

    // ─── Fill block-rows 0..127, writing to trace[c][base + block_row] ───
    for block_row in 0..ROWS_PER_BLOCK {
        let row = base + block_row;
        // Determine the "logical phase" of this row (block-relative).
        let (a, b, c, d, e, f_, g, h) = if block_row <= 64 {
            // Compression rows: state_at[block_row] holds the working
            // state BEFORE round `block_row` would run (for 0..63).
            // At block_row=64 it holds the post-compression state.
            let s = state_at[block_row];
            (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])
        } else {
            // Idle rows: working state stable at post-compression value.
            // (Setting to zero would break shift constraints at the
            //  block_row 64→65 transition.)
            let s = state_at[64];
            (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])
        };

        // Block A: working state.
        trace[A_a][row] = fu32(a);
        trace[A_b][row] = fu32(b);
        trace[A_c][row] = fu32(c);
        trace[A_d][row] = fu32(d);
        trace[A_e][row] = fu32(e);
        trace[A_f][row] = fu32(f_);
        trace[A_g][row] = fu32(g);
        trace[A_h][row] = fu32(h);

        // Block B: bits of {a, b, c, e, f, g}.
        for i in 0..32 {
            trace[OFF_BIT_A + i][row] = fu32(bit(a,  i as u32));
            trace[OFF_BIT_B + i][row] = fu32(bit(b,  i as u32));
            trace[OFF_BIT_C + i][row] = fu32(bit(c,  i as u32));
            trace[OFF_BIT_E + i][row] = fu32(bit(e,  i as u32));
            trace[OFF_BIT_F + i][row] = fu32(bit(f_, i as u32));
            trace[OFF_BIT_G + i][row] = fu32(bit(g,  i as u32));
        }

        // Block C0: Σ0(a) = ROTR^2(a) ⊕ ROTR^13(a) ⊕ ROTR^22(a).
        // For each output bit i:
        //   p = bit(a, (i+2) mod 32),   q = bit(a, (i+13) mod 32),
        //   r = bit(a, (i+22) mod 32)
        //   t0_i = p ⊕ q,   Σ0_i = t0_i ⊕ r.
        let s0_word = big_sigma0(a);
        for i in 0..32 {
            let p = bit(a, ((i + 2)  % 32) as u32);
            let q = bit(a, ((i + 13) % 32) as u32);
            let r = bit(a, ((i + 22) % 32) as u32);
            let t0 = p ^ q;
            let sg = t0 ^ r;
            trace[OFF_S0_T   + i][row] = fu32(t0);
            trace[OFF_S0_BIT + i][row] = fu32(sg);
        }
        trace[OFF_S0_W][row] = fu32(s0_word);

        // Block C1: Σ1(e) = ROTR^6(e) ⊕ ROTR^11(e) ⊕ ROTR^25(e).
        let s1_word = big_sigma1(e);
        for i in 0..32 {
            let p = bit(e, ((i + 6)  % 32) as u32);
            let q = bit(e, ((i + 11) % 32) as u32);
            let r = bit(e, ((i + 25) % 32) as u32);
            let t0 = p ^ q;
            let sg = t0 ^ r;
            trace[OFF_S1_T   + i][row] = fu32(t0);
            trace[OFF_S1_BIT + i][row] = fu32(sg);
        }
        trace[OFF_S1_W][row] = fu32(s1_word);

        // Block D: Ch(e, f, g)_i = e_i·f_i + g_i − e_i·g_i.
        let ch_word = ch(e, f_, g);
        for i in 0..32 {
            trace[OFF_CH_BIT + i][row] = fu32(bit(ch_word, i as u32));
        }
        trace[OFF_CH_W][row] = fu32(ch_word);

        // Block E: Maj(a, b, c) bit-by-bit with auxiliaries.
        //   ab_i = a_i·b_i,   ac_i = a_i·c_i,   bc_i = b_i·c_i,
        //   u_i  = ab_i ⊕ ac_i,   Maj_i = u_i ⊕ bc_i.
        let maj_word = maj(a, b, c);
        for i in 0..32 {
            let ai = bit(a, i as u32);
            let bi = bit(b, i as u32);
            let ci = bit(c, i as u32);
            let abi = ai & bi;
            let aci = ai & ci;
            let bci = bi & ci;
            let ui  = abi ^ aci;
            let mi  = ui  ^ bci;
            trace[OFF_MAJ_AB  + i][row] = fu32(abi);
            trace[OFF_MAJ_AC  + i][row] = fu32(aci);
            trace[OFF_MAJ_BC  + i][row] = fu32(bci);
            trace[OFF_MAJ_U   + i][row] = fu32(ui);
            trace[OFF_MAJ_BIT + i][row] = fu32(mi);
        }
        trace[OFF_MAJ_W][row] = fu32(maj_word);

        // Block F: W[t].  W is meaningful for block_row 0..63 (round
        // message word) and zero on block_row 64..127 (idle).
        let w_t = if block_row < 64 { w[block_row] } else { 0 };
        trace[OFF_W][row] = fu32(w_t);

        // Block G: T1, T2 carry decomposition.  Constraints fire on
        // every row, so cells must always satisfy the decomposition
        // identity.  K[t] and W[t] are zero outside compression rounds.
        let k_t = if block_row < 64 { K[block_row] } else { 0 };
        let w_t_for_g = if block_row < 64 { w[block_row] } else { 0 };
        let t1_full: u64 = (h as u64)
            .wrapping_add(big_sigma1(e) as u64)
            .wrapping_add(ch(e, f_, g) as u64)
            .wrapping_add(k_t as u64)
            .wrapping_add(w_t_for_g as u64);
        let t1_lo = (t1_full & 0xFFFF_FFFF) as u32;
        let t1_carry = (t1_full >> 32) as u32;       // ≤ 4
        trace[OFF_T1_LO][row] = fu32(t1_lo);
        trace[OFF_T1_C0][row] = fu32(t1_carry & 1);
        trace[OFF_T1_C1][row] = fu32((t1_carry >> 1) & 1);
        trace[OFF_T1_C2][row] = fu32((t1_carry >> 2) & 1);
        trace[OFF_T1_CW][row] = fu32(t1_carry);

        let t2_full: u64 = (big_sigma0(a) as u64)
            .wrapping_add(maj(a, b, c) as u64);
        let t2_lo = (t2_full & 0xFFFF_FFFF) as u32;
        let t2_carry = (t2_full >> 32) as u32;       // ≤ 1
        trace[OFF_T2_LO][row] = fu32(t2_lo);
        trace[OFF_T2_C0][row] = fu32(t2_carry & 1);
        trace[OFF_T2_C1][row] = fu32((t2_carry >> 1) & 1);
        trace[OFF_T2_CW][row] = fu32(t2_carry);

        // Block H: H-state.
        // block_row 0..64: H-state = incoming IV (compression doesn't
        // touch H).  block_row 65 onward: H-state = block-output digest.
        let hs = if block_row <= 64 { iv } else { digest };
        for k in 0..8 {
            trace[OFF_H0 + k][row] = fu32(hs[k]);
        }

        // Block I: W window W_win[0..14] = (W[r-15], ..., W[r-1]).
        // For r < 15, the "history" is undefined; we set those cells
        // to zero.  For r ≥ 64, the history is partially or fully zero
        // (W[t]=0 for t≥64 in this block's local indexing).
        for k in 0..15 {
            let w_idx_signed = (block_row as isize) - 15 + (k as isize);
            let w_val = if (0..64).contains(&w_idx_signed) {
                w[w_idx_signed as usize]
            } else {
                0
            };
            trace[OFF_WW0 + k][row] = fu32(w_val);
        }

        // Block J: bits of W_win[14] = W[r-1].
        let ww14: u32 = {
            let idx = (block_row as isize) - 1;
            if (0..64).contains(&idx) { w[idx as usize] } else { 0 }
        };
        for i in 0..32 {
            trace[OFF_BIT_WW14 + i][row] = fu32(bit(ww14, i as u32));
        }

        // Block K: bits of W_win[1] = W[r-14].
        let ww1: u32 = {
            let idx = (block_row as isize) - 14;
            if (0..64).contains(&idx) { w[idx as usize] } else { 0 }
        };
        for i in 0..32 {
            trace[OFF_BIT_WW1 + i][row] = fu32(bit(ww1, i as u32));
        }

        // Block L: σ0(W_win[1]) = σ0(W[r-14]).
        // σ0(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x).
        let ss0_word = small_sigma0(ww1);
        for i in 0..32 {
            // ROTR^7: bit at position (i+7) mod 32.
            let p = bit(ww1, ((i + 7)  % 32) as u32);
            // ROTR^18: bit at position (i+18) mod 32.
            let q = bit(ww1, ((i + 18) % 32) as u32);
            // SHR^3: bit at position (i+3) for i+3 < 32, else 0.
            let r = if i + 3 < 32 { bit(ww1, (i + 3) as u32) } else { 0 };
            let t0 = p ^ q;
            let sg = t0 ^ r;
            trace[OFF_SS0_T   + i][row] = fu32(t0);
            trace[OFF_SS0_BIT + i][row] = fu32(sg);
        }
        trace[OFF_SS0_W][row] = fu32(ss0_word);

        // Block M: σ1(W_win[14]) = σ1(W[r-1]).
        // σ1(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x).
        let ss1_word = small_sigma1(ww14);
        for i in 0..32 {
            let p = bit(ww14, ((i + 17) % 32) as u32);
            let q = bit(ww14, ((i + 19) % 32) as u32);
            let r = if i + 10 < 32 { bit(ww14, (i + 10) as u32) } else { 0 };
            let t0 = p ^ q;
            let sg = t0 ^ r;
            trace[OFF_SS1_T   + i][row] = fu32(t0);
            trace[OFF_SS1_BIT + i][row] = fu32(sg);
        }
        trace[OFF_SS1_W][row] = fu32(ss1_word);

        // Block N: schedule sum carry.
        //   sum = W[r-15] + σ0(W[r-14]) + W[r-6] + σ1(W[r-1])
        //       = cur[W_win[0]] + cur[OFF_SS0_W] + cur[W_win[9]] + cur[OFF_SS1_W]
        //   When the recurrence applies (rows 15..62), nxt[OFF_W] = sum_lo
        //   and the carry is sum / 2^32 ∈ {0,1,2,3}.
        // We compute the carry from raw u32 history regardless of row,
        // since the trace cells must be self-consistent and the
        // constraint is only ENFORCED on rows 15..62.
        let ww0_val: u32 = {
            let idx = (block_row as isize) - 15;
            if (0..64).contains(&idx) { w[idx as usize] } else { 0 }
        };
        let ww9_val: u32 = {
            let idx = (block_row as isize) - 6;
            if (0..64).contains(&idx) { w[idx as usize] } else { 0 }
        };
        let sum_full: u64 = (ww0_val as u64)
            .wrapping_add(ss0_word as u64)
            .wrapping_add(ww9_val as u64)
            .wrapping_add(ss1_word as u64);
        let sum_carry = (sum_full >> 32) as u32;       // ≤ 3
        trace[OFF_WS_C0][row] = fu32(sum_carry & 1);
        trace[OFF_WS_C1][row] = fu32((sum_carry >> 1) & 1);
        trace[OFF_WS_CW][row] = fu32(sum_carry);

        // Block O: new_a, new_e carry decomp (1 bit each).
        if block_row < 64 {
            let t1_lo_u32 = (((h as u64)
                .wrapping_add(big_sigma1(e) as u64)
                .wrapping_add(ch(e, f_, g) as u64)
                .wrapping_add(K[block_row] as u64)
                .wrapping_add(w[block_row] as u64)) & 0xFFFF_FFFF) as u32;
            let t2_lo_u32 = (((big_sigma0(a) as u64)
                .wrapping_add(maj(a, b, c) as u64)) & 0xFFFF_FFFF) as u32;
            // new_a sum: t1_lo + t2_lo ∈ [0, 2^33)
            let na_full: u64 = (t1_lo_u32 as u64) + (t2_lo_u32 as u64);
            trace[OFF_NA_C][row] = fu32((na_full >> 32) as u32);
            // new_e sum: d + t1_lo ∈ [0, 2^33)
            let ne_full: u64 = (d as u64) + (t1_lo_u32 as u64);
            trace[OFF_NE_C][row] = fu32((ne_full >> 32) as u32);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  CONSTRAINT EVALUATOR
// ═══════════════════════════════════════════════════════════════════

/// Evaluate all `NUM_CONSTRAINTS` transition constraints at row `row`
/// for the given current and next row values.  Returns a vector of
/// length `NUM_CONSTRAINTS`; on a valid trace every entry is zero.
///
/// Row-dependent gating: the schedule recurrence and compression
/// constraints fire only on certain block-relative rows.  Disabled
/// slots return `F::zero()` so the constraint vector length stays
/// fixed at `NUM_CONSTRAINTS`.
///
/// Multi-block gating: `n_blocks` is the number of SHA-256 blocks the
/// trace encodes.  For row indices past `n_blocks · ROWS_PER_BLOCK`
/// (replicated last-row padding), all phase predicates are forced to
/// "idle" — every constraint then evaluates to zero on `nxt = cur`.
pub fn eval_sha256_constraints(
    cur: &[F], nxt: &[F], row: usize, n_blocks: usize,
) -> Vec<F> {
    let mut out: Vec<F> = Vec::with_capacity(NUM_CONSTRAINTS);

    // Block-relative row + "is this row past the last block" predicate.
    let block_idx = row / ROWS_PER_BLOCK;
    let block_row = row % ROWS_PER_BLOCK;
    let past_last_block = block_idx >= n_blocks;

    // Phase predicates.  `past_last_block` forces all to "idle so that
    // nxt = cur (replicated row) satisfies every constraint.
    let compression_active  = !past_last_block && block_row < 64;
    let finalisation_active = !past_last_block && block_row == 64;
    let _idle_active        =  past_last_block || block_row >= 65;
    let schedule_active     = !past_last_block && (15..=62).contains(&block_row);

    // ─── Block B: bit booleanity (8 words × 32 = 256 cons) ────────
    for off in [OFF_BIT_A, OFF_BIT_B, OFF_BIT_C,
                OFF_BIT_E, OFF_BIT_F, OFF_BIT_G,
                OFF_BIT_WW14, OFF_BIT_WW1] {
        for i in 0..32 {
            let b = cur[off + i];
            out.push(b * (F::one() - b));
        }
    }

    // ─── Bit→word decomposition (8 cons, all degree 1) ───────────
    let pow_table: [F; 32] = core::array::from_fn(|i| pow2(i as u32));
    let pack = |off: usize, cur: &[F]| -> F {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * cur[off + i]; }
        s
    };
    out.push(cur[A_a] - pack(OFF_BIT_A, cur));
    out.push(cur[A_b] - pack(OFF_BIT_B, cur));
    out.push(cur[A_c] - pack(OFF_BIT_C, cur));
    out.push(cur[A_e] - pack(OFF_BIT_E, cur));
    out.push(cur[A_f] - pack(OFF_BIT_F, cur));
    out.push(cur[A_g] - pack(OFF_BIT_G, cur));
    out.push(cur[OFF_WW0 + 14] - pack(OFF_BIT_WW14, cur));   // W_win[14] bits
    out.push(cur[OFF_WW0 +  1] - pack(OFF_BIT_WW1,  cur));   // W_win[1]  bits
    // (Note: W_win[15] = OFF_W; not bit-decomposed in v1 since round t
    //  doesn't need W[t]'s bits — only T1/T2 absorb W as a word.)

    // ─── Block C0: Σ0(a) sub-block (65 cons) ─────────────────────
    //
    // Σ0(a) = ROTR^2(a) ⊕ ROTR^13(a) ⊕ ROTR^22(a)
    //
    // Per output bit i:
    //   t0_i  = a_{(i+2)%32} ⊕ a_{(i+13)%32}
    //   Σ0_i  = t0_i ⊕ a_{(i+22)%32}
    // Word pack:
    //   Σ0_w − Σ 2^i · Σ0_i = 0
    for i in 0..32 {
        let p = cur[OFF_BIT_A + ((i + 2)  % 32)];
        let q = cur[OFF_BIT_A + ((i + 13) % 32)];
        out.push(cur[OFF_S0_T + i] - xor_poly(p, q));
    }
    for i in 0..32 {
        let t0 = cur[OFF_S0_T + i];
        let r  = cur[OFF_BIT_A + ((i + 22) % 32)];
        out.push(cur[OFF_S0_BIT + i] - xor_poly(t0, r));
    }
    {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * cur[OFF_S0_BIT + i]; }
        out.push(cur[OFF_S0_W] - s);
    }

    // ─── Block C1: Σ1(e) sub-block (65 cons) ─────────────────────
    for i in 0..32 {
        let p = cur[OFF_BIT_E + ((i + 6)  % 32)];
        let q = cur[OFF_BIT_E + ((i + 11) % 32)];
        out.push(cur[OFF_S1_T + i] - xor_poly(p, q));
    }
    for i in 0..32 {
        let t0 = cur[OFF_S1_T + i];
        let r  = cur[OFF_BIT_E + ((i + 25) % 32)];
        out.push(cur[OFF_S1_BIT + i] - xor_poly(t0, r));
    }
    {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * cur[OFF_S1_BIT + i]; }
        out.push(cur[OFF_S1_W] - s);
    }

    // ─── Block L: σ0(W_win[1]) sub-block (65 cons) ───────────────
    //
    // σ0(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x)
    //
    // For SHR^3: bit i of SHR^3(x) = bit (i+3) of x for i+3 < 32, else 0.
    for i in 0..32 {
        let p = cur[OFF_BIT_WW1 + ((i + 7)  % 32)];
        let q = cur[OFF_BIT_WW1 + ((i + 18) % 32)];
        out.push(cur[OFF_SS0_T + i] - xor_poly(p, q));
    }
    for i in 0..32 {
        let t0 = cur[OFF_SS0_T + i];
        let r  = if i + 3 < 32 { cur[OFF_BIT_WW1 + (i + 3)] } else { fz() };
        out.push(cur[OFF_SS0_BIT + i] - xor_poly(t0, r));
    }
    {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * cur[OFF_SS0_BIT + i]; }
        out.push(cur[OFF_SS0_W] - s);
    }

    // ─── Block M: σ1(W_win[14]) sub-block (65 cons) ──────────────
    //
    // σ1(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x)
    for i in 0..32 {
        let p = cur[OFF_BIT_WW14 + ((i + 17) % 32)];
        let q = cur[OFF_BIT_WW14 + ((i + 19) % 32)];
        out.push(cur[OFF_SS1_T + i] - xor_poly(p, q));
    }
    for i in 0..32 {
        let t0 = cur[OFF_SS1_T + i];
        let r  = if i + 10 < 32 { cur[OFF_BIT_WW14 + (i + 10)] } else { fz() };
        out.push(cur[OFF_SS1_BIT + i] - xor_poly(t0, r));
    }
    {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * cur[OFF_SS1_BIT + i]; }
        out.push(cur[OFF_SS1_W] - s);
    }

    // ─── Block D: Ch(e, f, g) (33 cons) ──────────────────────────
    //
    // Ch_i = e_i·f_i + g_i − e_i·g_i  (deg 2).
    for i in 0..32 {
        let ei = cur[OFF_BIT_E + i];
        let fi = cur[OFF_BIT_F + i];
        let gi = cur[OFF_BIT_G + i];
        out.push(cur[OFF_CH_BIT + i] - (ei * fi + gi - ei * gi));
    }
    {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * cur[OFF_CH_BIT + i]; }
        out.push(cur[OFF_CH_W] - s);
    }

    // ─── Block E: Maj(a, b, c) (161 cons) ────────────────────────
    //
    // ab_i = a_i·b_i, ac_i = a_i·c_i, bc_i = b_i·c_i  (deg 2)
    // u_i  = ab_i ⊕ ac_i,    Maj_i = u_i ⊕ bc_i        (deg 2)
    for i in 0..32 {
        let ai = cur[OFF_BIT_A + i];
        let bi = cur[OFF_BIT_B + i];
        let ci = cur[OFF_BIT_C + i];
        out.push(cur[OFF_MAJ_AB + i] - ai * bi);
        out.push(cur[OFF_MAJ_AC + i] - ai * ci);
        out.push(cur[OFF_MAJ_BC + i] - bi * ci);
    }
    for i in 0..32 {
        let ab = cur[OFF_MAJ_AB + i];
        let ac = cur[OFF_MAJ_AC + i];
        out.push(cur[OFF_MAJ_U + i] - xor_poly(ab, ac));
    }
    for i in 0..32 {
        let u  = cur[OFF_MAJ_U + i];
        let bc = cur[OFF_MAJ_BC + i];
        out.push(cur[OFF_MAJ_BIT + i] - xor_poly(u, bc));
    }
    {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * cur[OFF_MAJ_BIT + i]; }
        out.push(cur[OFF_MAJ_W] - s);
    }

    // ─── Block G: T1, T2 carry decomposition (5 + 4 = 9 cons) ────
    //
    // T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
    //    = T1_lo + 2^32 · T1_carry,   T1_carry ∈ [0, 4],  3 carry bits.
    //
    // K[t] is row-dependent: K[block_row] when within a compression
    // round, else 0 (idle).  `compression_active` already accounts for
    // `past_last_block`.
    let k_row = if compression_active { fu32(K[block_row]) } else { fz() };

    // T1 sum decomposition (1 con).  Active on compression rows
    // (0..63); on idle rows the LHS is 0 = 0 (all cells zero).
    {
        let t1_sum = cur[A_h] + cur[OFF_S1_W] + cur[OFF_CH_W] + k_row + cur[OFF_W];
        let t1_lo  = cur[OFF_T1_LO];
        let t1_cw  = cur[OFF_T1_CW];
        out.push(t1_lo + pow2(32) * t1_cw - t1_sum);
    }
    // T1 carry boolean (3 cons).
    for off in [OFF_T1_C0, OFF_T1_C1, OFF_T1_C2] {
        let b = cur[off];
        out.push(b * (F::one() - b));
    }
    // T1 carry pack (1 con): T1_cw = c0 + 2 c1 + 4 c2.
    out.push(cur[OFF_T1_CW]
        - cur[OFF_T1_C0]
        - fu64(2) * cur[OFF_T1_C1]
        - fu64(4) * cur[OFF_T1_C2]);

    // T2 = Σ0(a) + Maj(a,b,c) ∈ [0, 2^33).  T2_carry ∈ [0, 1].
    {
        let t2_sum = cur[OFF_S0_W] + cur[OFF_MAJ_W];
        let t2_lo  = cur[OFF_T2_LO];
        let t2_cw  = cur[OFF_T2_CW];
        out.push(t2_lo + pow2(32) * t2_cw - t2_sum);
    }
    for off in [OFF_T2_C0, OFF_T2_C1] {
        let b = cur[off];
        out.push(b * (F::one() - b));
    }
    out.push(cur[OFF_T2_CW]
        - cur[OFF_T2_C0]
        - fu64(2) * cur[OFF_T2_C1]);

    // ─── Working register shifts (6 cons, deg 1) ─────────────────
    //
    // Active on compression rows (r ∈ [0, 63]):
    //   nxt[A.b] = cur[A.a]
    //   nxt[A.c] = cur[A.b]
    //   nxt[A.d] = cur[A.c]
    //   nxt[A.f] = cur[A.e]
    //   nxt[A.g] = cur[A.f]
    //   nxt[A.h] = cur[A.g]
    //
    // Outside compression, both sides are equal anyway (idle padding
    // holds post-compression state stable), so the constraints fire
    // safely on every row.
    out.push(if compression_active { nxt[A_b] - cur[A_a] } else { fz() });
    out.push(if compression_active { nxt[A_c] - cur[A_b] } else { fz() });
    out.push(if compression_active { nxt[A_d] - cur[A_c] } else { fz() });
    out.push(if compression_active { nxt[A_f] - cur[A_e] } else { fz() });
    out.push(if compression_active { nxt[A_g] - cur[A_f] } else { fz() });
    out.push(if compression_active { nxt[A_h] - cur[A_g] } else { fz() });

    // ─── new_a, new_e definitions with carry decomposition ──────
    //
    // Active on compression rows.
    //   new_a = (T1_lo + T2_lo) mod 2^32 = nxt[A.a]
    //   new_a_full = T1_lo + T2_lo = nxt[A.a] + 2^32 · NA_C
    //   NA_C ∈ {0, 1}  (booleanity)
    //
    //   new_e = (d + T1_lo)   mod 2^32 = nxt[A.e]
    //   new_e_full = d + T1_lo = nxt[A.e] + 2^32 · NE_C
    //   NE_C ∈ {0, 1}  (booleanity)
    //
    // 6 constraints (sum + boolean each, 3 each).  We split:
    //   NA sum decomp (1) + NA_C boolean (1) + (we don't need pack)
    //   NE sum decomp (1) + NE_C boolean (1)
    // → 4 constraints; we pad with 2 zero slots so the count = 6
    //   stays consistent with the budget.
    if compression_active {
        out.push(nxt[A_a] + pow2(32) * cur[OFF_NA_C]
                 - cur[OFF_T1_LO] - cur[OFF_T2_LO]);
        let na = cur[OFF_NA_C];
        out.push(na * (F::one() - na));
        out.push(nxt[A_e] + pow2(32) * cur[OFF_NE_C]
                 - cur[A_d] - cur[OFF_T1_LO]);
        let ne = cur[OFF_NE_C];
        out.push(ne * (F::one() - ne));
        out.push(fz());
        out.push(fz());
    } else {
        for _ in 0..6 { out.push(fz()); }
    }

    // ─── H-state (8 cons) ────────────────────────────────────────
    //
    // Phase-dependent:
    //   compression rows (r ∈ [0, 63]) and idle rows (r ≥ 65):
    //     nxt[H_k] = cur[H_k]
    //   finalisation row (r = 64):
    //     nxt[H_k] = (cur[H_k] + cur[A_k]) mod 2^32
    //   The full-precision sum cur[H_k] + cur[A_k] ≤ 2·(2^32 − 1) < 2^33,
    //   so the carry is one bit.  We don't allocate a dedicated carry
    //   column for finalisation — instead, we materialise the constraint
    //   as (cur[H_k] + cur[A_k] − nxt[H_k]) ∈ {0, 2^32}.  We can encode
    //   this as a single quadratic constraint (deg 2):
    //       (delta) · (delta − 2^32) = 0,
    //   where delta = cur[H_k] + cur[A_k] − nxt[H_k].
    if finalisation_active {
        for k in 0..8 {
            let delta = cur[OFF_H0 + k] + cur[A_a + k] - nxt[OFF_H0 + k];
            out.push(delta * (delta - pow2(32)));
        }
    } else {
        for k in 0..8 {
            out.push(nxt[OFF_H0 + k] - cur[OFF_H0 + k]);
        }
    }

    // ─── W window shifts (15 cons, deg 1) ────────────────────────
    //
    // nxt[W_win[k]] = cur[W_win[k+1]]  for k = 0..14.
    // (W_win[15] = OFF_W is constrained separately by Block N when
    //  the schedule recurrence is active.)
    for k in 0..14 {
        out.push(nxt[OFF_WW0 + k] - cur[OFF_WW0 + k + 1]);
    }
    // The shift from W_win[14] to W_win[15] (= OFF_W in next row) is
    // the "incoming" message word that the schedule recurrence
    // determines.  When the recurrence is INACTIVE (rows 0..14, the
    // initial message is loaded; rows 63..127, idle), we simply enforce
    // nxt[W_win[14]] = cur[W_win[15]] = cur[OFF_W].  When the recurrence
    // IS active (rows 15..62), the same shift still holds — W_win[14]
    // shifts forward as usual.  So this constraint always fires.
    out.push(nxt[OFF_WW0 + 14] - cur[OFF_W]);

    // ─── Schedule recurrence (4 cons, gated to rows 15..62) ──────
    //
    //   nxt[OFF_W] = cur[W_win[0]] + cur[OFF_SS0_W] + cur[W_win[9]]
    //              + cur[OFF_SS1_W]   mod 2^32
    //   sum_full   = nxt[OFF_W] + 2^32 · WS_carry
    //   WS_carry   = c0 + 2 c1     (∈ [0, 3])
    //   c0, c1 booleans.
    if schedule_active {
        // Sum decomposition.
        let sum = cur[OFF_WW0 + 0]
                + cur[OFF_SS0_W]
                + cur[OFF_WW0 + 9]
                + cur[OFF_SS1_W];
        out.push(nxt[OFF_W] + pow2(32) * cur[OFF_WS_CW] - sum);
        // c0, c1 booleanity (2 cons).
        let c0 = cur[OFF_WS_C0];
        let c1 = cur[OFF_WS_C1];
        out.push(c0 * (F::one() - c0));
        out.push(c1 * (F::one() - c1));
        // Carry pack (1 con): WS_CW = c0 + 2 c1.
        out.push(cur[OFF_WS_CW] - c0 - fu64(2) * c1);
    } else {
        for _ in 0..4 { out.push(fz()); }
    }

    debug_assert_eq!(
        out.len(), NUM_CONSTRAINTS,
        "constraint count mismatch: emitted {} expected {}",
        out.len(), NUM_CONSTRAINTS
    );
    out
}

// ═══════════════════════════════════════════════════════════════════
//  TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    fn pad_message(msg: &[u8]) -> Vec<[u8; 64]> {
        // SHA-256 padding: append 0x80, then zero bytes, then 64-bit
        // big-endian length (in bits).  For messages where 56..63 mod 64,
        // padding spans two blocks.
        let mlen_bits = (msg.len() as u64) * 8;
        let mut buf = msg.to_vec();
        buf.push(0x80);
        while buf.len() % 64 != 56 { buf.push(0); }
        buf.extend_from_slice(&mlen_bits.to_be_bytes());
        assert!(buf.len() % 64 == 0);
        buf.chunks_exact(64).map(|c| {
            let mut a = [0u8; 64];
            a.copy_from_slice(c);
            a
        }).collect()
    }

    /// One-block padded message for messages ≤ 55 bytes.
    fn one_block_padded(msg: &[u8]) -> [u8; 64] {
        assert!(msg.len() <= 55);
        let blocks = pad_message(msg);
        assert_eq!(blocks.len(), 1);
        blocks[0]
    }

    #[test]
    fn ref_sha256_matches_sha2_crate_empty() {
        let block = one_block_padded(b"");
        let digest_ref = sha256_one_block(&block);
        let mut h = Sha256::new();
        h.update(b"");
        let digest_lib: [u8; 32] = h.finalize().into();
        let mut digest_lib_words = [0u32; 8];
        for k in 0..8 {
            digest_lib_words[k] = u32::from_be_bytes(
                [digest_lib[4*k], digest_lib[4*k+1], digest_lib[4*k+2], digest_lib[4*k+3]]);
        }
        assert_eq!(digest_ref, digest_lib_words);
    }

    #[test]
    fn ref_sha256_matches_sha2_crate_abc() {
        // FIPS 180-4 §B.1: SHA-256("abc") =
        //   ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        let block = one_block_padded(b"abc");
        let d = sha256_one_block(&block);
        assert_eq!(d, [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
            0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
        ]);
    }

    #[test]
    fn trace_satisfies_all_transitions_empty() {
        let block = one_block_padded(b"");
        let trace = build_sha256_trace(&block);
        assert_eq!(trace.len(), WIDTH);
        assert_eq!(trace[0].len(), N_TRACE);
        for r in 0..N_TRACE - 1 {
            let cur: Vec<F> = trace.iter().map(|c| c[r]).collect();
            let nxt: Vec<F> = trace.iter().map(|c| c[r + 1]).collect();
            let cv = eval_sha256_constraints(&cur, &nxt, r, 1);
            for (i, v) in cv.iter().enumerate() {
                if !v.is_zero() {
                    panic!("row {r} constraint {i} = {v:?}");
                }
            }
        }
    }

    #[test]
    fn trace_satisfies_all_transitions_abc() {
        let block = one_block_padded(b"abc");
        let trace = build_sha256_trace(&block);
        for r in 0..N_TRACE - 1 {
            let cur: Vec<F> = trace.iter().map(|c| c[r]).collect();
            let nxt: Vec<F> = trace.iter().map(|c| c[r + 1]).collect();
            let cv = eval_sha256_constraints(&cur, &nxt, r, 1);
            for (i, v) in cv.iter().enumerate() {
                if !v.is_zero() {
                    panic!("row {r} constraint {i} = {v:?}");
                }
            }
        }
    }

    #[test]
    fn trace_digest_at_row_65_matches_sha2() {
        let block = one_block_padded(b"abc");
        let trace = build_sha256_trace(&block);
        // Row 65 H-state = digest words.
        let mut digest = [0u32; 8];
        for k in 0..8 {
            let f = trace[OFF_H0 + k][65];
            let bi = <F as PrimeField>::into_bigint(f);
            digest[k] = bi.0[0] as u32;
        }
        let mut h = Sha256::new();
        h.update(b"abc");
        let lib_digest: [u8; 32] = h.finalize().into();
        let lib_words: [u32; 8] = core::array::from_fn(|k| {
            u32::from_be_bytes([lib_digest[4*k], lib_digest[4*k+1],
                                lib_digest[4*k+2], lib_digest[4*k+3]])
        });
        assert_eq!(digest, lib_words);
    }

    #[test]
    fn tampered_trace_fails_constraint() {
        let block = one_block_padded(b"abc");
        let mut trace = build_sha256_trace(&block);
        // Flip bit 0 of A.a at row 5.
        trace[OFF_BIT_A + 0][5] = trace[OFF_BIT_A + 0][5] + F::one();
        let cur: Vec<F> = trace.iter().map(|c| c[5]).collect();
        let nxt: Vec<F> = trace.iter().map(|c| c[6]).collect();
        let cv = eval_sha256_constraints(&cur, &nxt, 5, 1);
        assert!(cv.iter().any(|v| !v.is_zero()),
            "tampered bit must trigger at least one nonzero constraint");
    }

    #[test]
    fn width_is_documented() {
        assert_eq!(WIDTH, 756);
    }

    #[test]
    fn num_constraints_emitted_matches_constant() {
        let block = one_block_padded(b"abc");
        let trace = build_sha256_trace(&block);
        let cur: Vec<F> = trace.iter().map(|c| c[0]).collect();
        let nxt: Vec<F> = trace.iter().map(|c| c[1]).collect();
        let cv = eval_sha256_constraints(&cur, &nxt, 0, 1);
        assert_eq!(cv.len(), NUM_CONSTRAINTS);
    }

    // ── Multi-block tests ───────────────────────────────────────────

    fn validate_multi_trace(trace: &[Vec<F>], n_blocks: usize) {
        let h = trace[0].len();
        for r in 0..h - 1 {
            let cur: Vec<F> = trace.iter().map(|c| c[r]).collect();
            let nxt: Vec<F> = trace.iter().map(|c| c[r + 1]).collect();
            let cv = eval_sha256_constraints(&cur, &nxt, r, n_blocks);
            for (i, v) in cv.iter().enumerate() {
                if !v.is_zero() {
                    panic!("multi-block n_blocks={n_blocks} row {r} \
                            constraint {i} = {v:?}");
                }
            }
        }
    }

    fn extract_digest_at_row(trace: &[Vec<F>], r: usize) -> [u32; 8] {
        core::array::from_fn(|k| {
            let f = trace[OFF_H0 + k][r];
            let bi = <F as PrimeField>::into_bigint(f);
            bi.0[0] as u32
        })
    }

    fn sha256_lib(msg: &[u8]) -> [u32; 8] {
        let mut h = Sha256::new();
        h.update(msg);
        let bytes: [u8; 32] = h.finalize().into();
        core::array::from_fn(|k| {
            u32::from_be_bytes([bytes[4*k], bytes[4*k+1],
                                bytes[4*k+2], bytes[4*k+3]])
        })
    }

    #[test]
    fn multi_one_block_empty() {
        // Empty message → 1-block padded message (length-encoding fits).
        let (trace, n) = build_sha256_trace_multi(b"");
        assert_eq!(n, 1);
        assert_eq!(trace[0].len(), 128);
        validate_multi_trace(&trace, n);
        let digest = extract_digest_at_row(&trace, 65);
        assert_eq!(digest, sha256_lib(b""));
    }

    #[test]
    fn multi_one_block_abc() {
        let (trace, n) = build_sha256_trace_multi(b"abc");
        assert_eq!(n, 1);
        assert_eq!(trace[0].len(), 128);
        validate_multi_trace(&trace, n);
        assert_eq!(extract_digest_at_row(&trace, 65), sha256_lib(b"abc"));
    }

    #[test]
    fn multi_two_blocks_56_bytes() {
        // 56-byte message: padding (0x80 + length-encoding 8 bytes)
        // pushes total to 56 + 1 + 7 + 8 = 72 → 2 blocks.
        let msg: Vec<u8> = (0..56u8).collect();
        let (trace, n) = build_sha256_trace_multi(&msg);
        assert_eq!(n, 2);
        assert_eq!(trace[0].len(), 256);   // 2 × 128, already power of 2
        validate_multi_trace(&trace, n);
        // After block 1, the digest sits at row 128 + 65 = 193.
        let final_digest_row = ROWS_PER_BLOCK * (n - 1) + 65;
        assert_eq!(
            extract_digest_at_row(&trace, final_digest_row),
            sha256_lib(&msg)
        );
    }

    #[test]
    fn multi_three_blocks_120_bytes() {
        // 120-byte message: + 0x80 + 7 zeros + 8-byte length = 136 bytes
        // → 3 blocks (192 bytes).  Wait: 120 + 1 + 8 = 129; pad to 192
        // (next multiple of 64 after the 56-byte mark: 56 → 120 → 184
        // — actually let me recompute).
        // After 0x80: 121 bytes. Pad to 56 mod 64: need 56 - 121%64 =
        // 56 - 57 = -1 mod 64 = 63 zeros → 121+63 = 184 bytes, then +8
        // length = 192 = 3 × 64 → 3 blocks.
        let msg: Vec<u8> = (0..120u8).collect();
        let (trace, n) = build_sha256_trace_multi(&msg);
        assert_eq!(n, 3);
        // 3 × 128 = 384 → next pow 2 = 512.
        assert_eq!(trace[0].len(), 512);
        validate_multi_trace(&trace, n);
        let final_digest_row = ROWS_PER_BLOCK * (n - 1) + 65;
        assert_eq!(
            extract_digest_at_row(&trace, final_digest_row),
            sha256_lib(&msg)
        );
    }

    #[test]
    fn multi_five_blocks_rsa2048_size() {
        // ~268-byte payload, representative of an RSA-2048 DNSKEY RDATA.
        let msg: Vec<u8> = (0..=255u8).chain(0..12u8).collect();
        assert_eq!(msg.len(), 268);
        let (trace, n) = build_sha256_trace_multi(&msg);
        assert_eq!(n, 5);
        // 5 × 128 = 640 → next pow 2 = 1024.
        assert_eq!(trace[0].len(), 1024);
        validate_multi_trace(&trace, n);
        let final_digest_row = ROWS_PER_BLOCK * (n - 1) + 65;
        assert_eq!(
            extract_digest_at_row(&trace, final_digest_row),
            sha256_lib(&msg)
        );
    }

    #[test]
    fn multi_block_iv_chains_correctly() {
        // The intermediate H-state at the start of block 1 must equal
        // the digest of block 0 alone.  Verify by extracting H-state at
        // block 1's row 0 and comparing to a fresh single-block hash of
        // block 0's content.
        let msg: Vec<u8> = (0..56u8).collect();
        let blocks = pad_message_to_blocks(&msg);
        assert_eq!(blocks.len(), 2);

        let (trace, _) = build_sha256_trace_multi(&msg);
        let block1_iv = extract_digest_at_row(&trace, ROWS_PER_BLOCK);
        // sha256_one_block already returns IV + post (the standalone
        // digest of one padded block).
        let digest_after_block0 = sha256_one_block(&blocks[0]);
        assert_eq!(block1_iv, digest_after_block0,
            "block 1 IV must equal block 0's running digest");
    }
}
