//! sha512_air.rs — single- and multi-block SHA-512 (FIPS 180-4 §6.4) AIR over Goldilocks
//!
//! v0 (this commit): reference / padding / native compression only.
//!   - Constants K[0..79], IV[0..7] (FIPS 180-4 §4.2.3, §5.3.5)
//!   - Native sha512_one_block, sha512_compress_block, pad_message_to_blocks
//!   - Tests vs `sha2::Sha512`
//!   - Design header for the AIR layout (filled in next commits)
//!
//! v1 (next commit): full AIR — trace builder, column layout, constraint
//! evaluator, multi-block H-state chaining.  Mirrors `sha256_air.rs` but
//! with 64-bit words decomposed into two 32-bit limbs (lo, hi) because
//! the Goldilocks prime p = 2^64 − 2^32 + 1 is too small to canonically
//! hold a u64 in a single field cell while preserving integer-mod-2^64
//! addition semantics through carry decomposition.
//!
//! Used by the Ed25519 ZSK→KSK binding inside the swarm prover: the AIR
//! proves that the 32-byte concatenation `R || A || M` hashes to a
//! 64-byte digest under SHA-512.  Public-input binding to (R, A, M) and
//! to the digest happens at the prover layer via `pi_s`.
//!
//! ─────────────────────────────────────────────────────────────────
//! GOLDILOCKS u64 REPRESENTATION
//! ─────────────────────────────────────────────────────────────────
//!
//! SHA-256's AIR can store a u32 word in one Goldilocks cell because
//! every u32 is less than the Goldilocks prime p ≈ 2^64.  For SHA-512,
//! a u64 may exceed p.  Consequences and the AIR fix are detailed below
//! in fenced text blocks (not Rust code, just exposition):
//!
//! ```text
//! 1. Bit decomposition w = Σ_{i=0..63} 2^i · b_i (with each b_i
//!    booleanised) does NOT uniquely determine an integer in [0, 2^64):
//!    the field value Σ 2^i b_i mod p is unique, but its "lift" back to
//!    a u64 has two candidates when the field sum lands in [0, 2^32 - 1)
//!    because 2^64 ≡ 2^32 - 1 (mod p).
//!
//! 2. Sums like T1 = h + Σ1 + Ch + K + W (five 64-bit summands) reach
//!    up to 5·(2^64 - 1) ≈ 2^66, which overflows the field.  Carry
//!    decomposition cannot use a single field cell for the full sum.
//!
//! AIR fix (v1):
//!
//!   - Every 64-bit working-state word is stored as TWO 32-bit limbs
//!     (w_lo, w_hi), each in [0, 2^32) and bit-decomposed into 32 bits.
//!     Round constants and message-schedule outputs likewise live as
//!     (lo, hi) pairs.
//!
//!   - Carry decomposition runs separately over lo and hi halves:
//!       sum_lo      = Σ summand_lo[k]              ≤ 5·(2^32-1) < 2^35
//!       sum_lo_lo   = sum_lo mod 2^32
//!       carry_to_hi = sum_lo / 2^32                ∈ [0, 4]   (3 bits)
//!       sum_hi      = Σ summand_hi[k] + carry_to_hi ≤ 2^35
//!       sum_hi_lo   = sum_hi mod 2^32
//!       (top bits of sum_hi are discarded mod 2^64)
//!     All intermediate field cells stay below 2^35 << p.
//!
//!   - σ0/σ1/Σ0/Σ1 rotation gadgets work on bits directly; both lo and
//!     hi halves of the result are reconstructed from output bits via
//!     2^i powers (split at i = 32).
//!
//!   - This roughly doubles the column count vs SHA-256.
//! ```
//!
//! ─────────────────────────────────────────────────────────────────
//! PLANNED TRACE LAYOUT (v1, sketched)
//! ─────────────────────────────────────────────────────────────────
//!
//! ```text
//! Trace height per block N_BLOCK = 128 (next power of two ≥ 80+1+1).
//!   row 0..79   - SHA-512 compression rounds 0..79
//!   row 80      - post-compression state + IV in H-state
//!   row 81      - finalisation: H_k = IV[k] + post[k] (mod 2^64)
//!   row 82..127 - idle
//!
//! Column blocks:
//!   Block A   working state {a..h} as (lo, hi) pairs            16 cols
//!   Block B   bits of {a, b, c, e, f, g} (each 64 bits)        384 cols
//!   Block C0  Σ0(a) sub-block (64 t0 + 64 Σ0_bit + 2 lo/hi)    130 cols
//!   Block C1  Σ1(e) sub-block                                  130 cols
//!   Block D   Ch(e,f,g) bits + (lo, hi)                         66 cols
//!   Block E   Maj(a,b,c) ab/ac/bc/u/Maj/(lo,hi)                322 cols
//!   Block F   W[t] (lo, hi)                                      2 cols
//!   Block G   T1, T2 carry decomp (per-limb)                    16 cols
//!   Block H   H-state {H0..H7} as (lo, hi)                      16 cols
//!   Block I   W window cells W_win[0..14] as (lo, hi)           30 cols
//!   Block J   bits of W_win[14] = W[t-1] (for σ1)               64 cols
//!   Block K   bits of W_win[1]  = W[t-14] (for σ0)              64 cols
//!   Block L   σ0 sub-block                                     130 cols
//!   Block M   σ1 sub-block                                     130 cols
//!   Block N   W[t+1] schedule sum carry (per-limb)               6 cols
//!   Block O   new_a, new_e per-limb carry                        4 cols
//!   ─────────────────────────────────────────────────────────────────
//!   TOTAL                                                      1510 cols
//!
//! Constraint budget: 1526 transition constraints, all degree ≤ 2.
//! ```
//!
//! ─────────────────────────────────────────────────────────────────
//! SOUNDNESS (v1, planned)
//! ─────────────────────────────────────────────────────────────────
//!
//! Identical structure to the SHA-256 AIR.  Pi_s binds the message
//! limbs M[0..15] (each a 64-bit word, two limbs each) at the row-
//! relative indices where W_win[15] is anchored; Block I shifts
//! propagate them; Block N enforces the schedule recurrence on rows
//! 16..78; compression constraints on rows 0..79 force the working
//! state; finalisation at row 80→81 commits the digest.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{Field, Zero, One};
use ark_goldilocks::Goldilocks as F;

// ═══════════════════════════════════════════════════════════════════
//  Constants  (FIPS 180-4 §4.2.3, §5.3.5)
// ═══════════════════════════════════════════════════════════════════

/// SHA-512 round constants K[0..79] (FIPS 180-4 §4.2.3).
/// First sixty-four bits of the fractional parts of the cube roots of
/// the first eighty primes.
pub const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-512 initial hash values H_0 (FIPS 180-4 §5.3.5).
/// First sixty-four bits of the fractional parts of the square roots
/// of the first eight primes.
pub const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// Number of compression rounds per block.
pub const NUM_ROUNDS: usize = 80;

/// Block size in bytes (1024 bits).
pub const BLOCK_BYTES: usize = 128;

/// Trace rows allocated per SHA-512 block in the AIR.  Power of two ≥
/// `NUM_ROUNDS + 1 + 1 = 82` (rounds, post-compression state, finalisation).
pub const ROWS_PER_BLOCK: usize = 128;

// ═══════════════════════════════════════════════════════════════════
//  u64 helpers — match SHA-256's helpers but for 64-bit words.
// ═══════════════════════════════════════════════════════════════════

#[inline]
fn rotr(x: u64, n: u32) -> u64 { x.rotate_right(n) }

#[inline]
fn shr(x: u64, n: u32) -> u64 { x >> n }

/// Σ0(x) = ROTR^28(x) ⊕ ROTR^34(x) ⊕ ROTR^39(x)   (FIPS 180-4 §4.1.3)
#[inline]
pub fn big_sigma0(x: u64) -> u64 { rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39) }

/// Σ1(x) = ROTR^14(x) ⊕ ROTR^18(x) ⊕ ROTR^41(x)
#[inline]
pub fn big_sigma1(x: u64) -> u64 { rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41) }

/// σ0(x) = ROTR^1(x) ⊕ ROTR^8(x) ⊕ SHR^7(x)
#[inline]
pub fn small_sigma0(x: u64) -> u64 { rotr(x, 1)  ^ rotr(x, 8)  ^ shr(x, 7) }

/// σ1(x) = ROTR^19(x) ⊕ ROTR^61(x) ⊕ SHR^6(x)
#[inline]
pub fn small_sigma1(x: u64) -> u64 { rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6) }

#[inline]
pub fn ch(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (!x & z) }

#[inline]
pub fn maj(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }

/// Bit i (0 = LSB) of a u64.
#[inline]
pub fn bit(x: u64, i: u32) -> u64 { (x >> i) & 1 }

/// Lo / hi 32-bit limbs of a u64 — the AIR's canonical representation
/// (each limb fits comfortably in a Goldilocks cell).
#[inline]
pub fn limbs(x: u64) -> (u32, u32) { (x as u32, (x >> 32) as u32) }

/// Reconstruct a u64 from (lo, hi) limbs.
#[inline]
pub fn from_limbs(lo: u32, hi: u32) -> u64 { (lo as u64) | ((hi as u64) << 32) }

// ═══════════════════════════════════════════════════════════════════
//  Native SHA-512 reference (used by trace builder + crosschecked
//  against the `sha2` crate in tests).
// ═══════════════════════════════════════════════════════════════════

/// SHA-512 padding (FIPS 180-4 §5.1.2).  Returns a Vec of 128-byte
/// blocks; the message length is appended as a 128-bit big-endian
/// integer at the end (the upper 64 bits are always zero for any
/// realistically-sized input).
pub fn pad_message_to_blocks(message: &[u8]) -> Vec<[u8; BLOCK_BYTES]> {
    // Length in bits as u128, big-endian.
    let mlen_bits: u128 = (message.len() as u128) * 8;
    let mut buf = message.to_vec();
    buf.push(0x80);
    // Pad with zeros until length ≡ 112 (mod 128) — i.e. 16 bytes
    // remain in the final block for the 128-bit length encoding.
    while buf.len() % BLOCK_BYTES != BLOCK_BYTES - 16 { buf.push(0); }
    buf.extend_from_slice(&mlen_bits.to_be_bytes());
    debug_assert!(buf.len() % BLOCK_BYTES == 0);
    buf.chunks_exact(BLOCK_BYTES).map(|c| {
        let mut a = [0u8; BLOCK_BYTES];
        a.copy_from_slice(c);
        a
    }).collect()
}

/// Run the SHA-512 compression function on one 128-byte block under
/// the given starting IV, returning the post-compression `(a..h)`
/// state (NOT yet added to the IV).
pub fn compress_block_native(block: &[u8; BLOCK_BYTES], iv: [u64; 8]) -> [u64; 8] {
    let mut w = [0u64; NUM_ROUNDS];
    // Message schedule — first sixteen 64-bit big-endian words from the block.
    for i in 0..16 {
        let off = 8 * i;
        w[i] = u64::from_be_bytes([
            block[off], block[off+1], block[off+2], block[off+3],
            block[off+4], block[off+5], block[off+6], block[off+7],
        ]);
    }
    for t in 16..NUM_ROUNDS {
        w[t] = small_sigma1(w[t-2])
            .wrapping_add(w[t-7])
            .wrapping_add(small_sigma0(w[t-15]))
            .wrapping_add(w[t-16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f_, mut g, mut h] = iv;
    for t in 0..NUM_ROUNDS {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f_, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g; g = f_; f_ = e;
        e = d.wrapping_add(t1);
        d = c; c = b; b = a;
        a = t1.wrapping_add(t2);
    }
    [a, b, c, d, e, f_, g, h]
}

/// Hash one already-padded 128-byte SHA-512 block, returning the
/// 8-word digest (big-endian per spec).  Equivalent to `compress` then
/// add to IV.  Useful for single-block tests against `sha2::Sha512`.
pub fn sha512_one_block(block: &[u8; BLOCK_BYTES]) -> [u64; 8] {
    let post = compress_block_native(block, IV);
    [
        IV[0].wrapping_add(post[0]), IV[1].wrapping_add(post[1]),
        IV[2].wrapping_add(post[2]), IV[3].wrapping_add(post[3]),
        IV[4].wrapping_add(post[4]), IV[5].wrapping_add(post[5]),
        IV[6].wrapping_add(post[6]), IV[7].wrapping_add(post[7]),
    ]
}

/// Hash an arbitrary-length message with native SHA-512 (uses the
/// in-crate compression function rather than the `sha2` crate, so
/// this serves as the reference path the AIR will be checked against).
pub fn sha512_native(message: &[u8]) -> [u8; 64] {
    let blocks = pad_message_to_blocks(message);
    let mut h = IV;
    for block in &blocks {
        let post = compress_block_native(block, h);
        for k in 0..8 { h[k] = h[k].wrapping_add(post[k]); }
    }
    let mut digest = [0u8; 64];
    for (k, hk) in h.iter().enumerate() {
        digest[8*k..8*(k+1)].copy_from_slice(&hk.to_be_bytes());
    }
    digest
}

// ═══════════════════════════════════════════════════════════════════
//  Column layout — single source of truth.
// ═══════════════════════════════════════════════════════════════════
//
// Mirrors `sha256_air.rs` block-for-block, but every 64-bit working-
// state word becomes TWO 32-bit limb cells (lo, hi).  The σ/Σ/σ
// sub-blocks store 64 bit-cells (vs 32 for SHA-256) plus a packed
// (lo, hi) pair instead of a single packed word.  Block tags A..P
// follow the SHA-256 file convention.

// Block A — working state {a, b, c, d, e, f, g, h} as (lo, hi) pairs.
// A_x_LO = 2·x, A_x_HI = 2·x + 1, x ∈ {a=0, b=1, ..., h=7}.
pub const A_a_LO: usize = 0;
pub const A_a_HI: usize = 1;
pub const A_b_LO: usize = 2;
pub const A_b_HI: usize = 3;
pub const A_c_LO: usize = 4;
pub const A_c_HI: usize = 5;
pub const A_d_LO: usize = 6;
pub const A_d_HI: usize = 7;
pub const A_e_LO: usize = 8;
pub const A_e_HI: usize = 9;
pub const A_f_LO: usize = 10;
pub const A_f_HI: usize = 11;
pub const A_g_LO: usize = 12;
pub const A_g_HI: usize = 13;
pub const A_h_LO: usize = 14;
pub const A_h_HI: usize = 15;

// Block B — bits of {a, b, c, e, f, g} (each 64 bits LSB-first).
// d and h are NOT bit-decomposed — their u32-ness is enforced via
// working-register shifts from {a, b, c} and {e, f, g}, whose own
// bit-decomposition pins their limbs to [0, 2^32).
pub const OFF_BIT_A: usize = 16;
pub const OFF_BIT_B: usize = OFF_BIT_A + 64;     // 80
pub const OFF_BIT_C: usize = OFF_BIT_B + 64;     // 144
pub const OFF_BIT_E: usize = OFF_BIT_C + 64;     // 208
pub const OFF_BIT_F: usize = OFF_BIT_E + 64;     // 272
pub const OFF_BIT_G: usize = OFF_BIT_F + 64;     // 336

// Block C0 — Σ0(a) sub-block (FIPS §4.1.3): 64 t0_i, 64 Σ0_i, (lo, hi).
pub const OFF_S0_T:   usize = OFF_BIT_G + 64;    // 400
pub const OFF_S0_BIT: usize = OFF_S0_T + 64;     // 464
pub const OFF_S0_LO:  usize = OFF_S0_BIT + 64;   // 528
pub const OFF_S0_HI:  usize = OFF_S0_LO + 1;     // 529

// Block C1 — Σ1(e) sub-block.
pub const OFF_S1_T:   usize = OFF_S0_HI + 1;     // 530
pub const OFF_S1_BIT: usize = OFF_S1_T + 64;     // 594
pub const OFF_S1_LO:  usize = OFF_S1_BIT + 64;   // 658
pub const OFF_S1_HI:  usize = OFF_S1_LO + 1;     // 659

// Block D — Ch(e, f, g) bits + (lo, hi).
pub const OFF_CH_BIT: usize = OFF_S1_HI + 1;     // 660
pub const OFF_CH_LO:  usize = OFF_CH_BIT + 64;   // 724
pub const OFF_CH_HI:  usize = OFF_CH_LO + 1;     // 725

// Block E — Maj(a, b, c) ab/ac/bc/u/Maj/(lo, hi).
pub const OFF_MAJ_AB:  usize = OFF_CH_HI + 1;     // 726
pub const OFF_MAJ_AC:  usize = OFF_MAJ_AB + 64;   // 790
pub const OFF_MAJ_BC:  usize = OFF_MAJ_AC + 64;   // 854
pub const OFF_MAJ_U:   usize = OFF_MAJ_BC + 64;   // 918   u_i = ab_i ⊕ ac_i
pub const OFF_MAJ_BIT: usize = OFF_MAJ_U + 64;    // 982   Maj_i = u_i ⊕ bc_i
pub const OFF_MAJ_LO:  usize = OFF_MAJ_BIT + 64;  // 1046
pub const OFF_MAJ_HI:  usize = OFF_MAJ_LO + 1;    // 1047

// Block F — message word W[t] (lo, hi).
pub const OFF_W_LO: usize = OFF_MAJ_HI + 1;       // 1048
pub const OFF_W_HI: usize = OFF_W_LO + 1;         // 1049

// Block G — T1, T2 carry decomp, per-limb.
//   T1_full = h + Σ1 + Ch + K + W   (5 u64 summands, each ≤ 2^64-1)
//   Per-limb sum ≤ 5·(2^32-1) < 2^35, plus optional carry-in (≤ 4)
//   from the prior limb.  Carry per limb ∈ [0, 4] → 3 carry bits.
//   T1_lo_lo = (h_lo + Σ1_lo + Ch_lo + K_lo + W_lo) mod 2^32
//   T1_lo_carry = (... ) / 2^32                    ∈ [0, 4]
//   T1_hi_lo = (h_hi + Σ1_hi + Ch_hi + K_hi + W_hi + T1_lo_carry) mod 2^32
//   T1_hi_carry = (...) / 2^32                     ∈ [0, 4]   (discarded mod 2^64)
pub const OFF_T1_LO_LO: usize = OFF_W_HI + 1;     // 1050   low 32 bits of lo limb
pub const OFF_T1_LO_C0: usize = OFF_T1_LO_LO + 1; // 1051
pub const OFF_T1_LO_C1: usize = OFF_T1_LO_C0 + 1; // 1052
pub const OFF_T1_LO_C2: usize = OFF_T1_LO_C1 + 1; // 1053
pub const OFF_T1_LO_CW: usize = OFF_T1_LO_C2 + 1; // 1054   c0 + 2c1 + 4c2
pub const OFF_T1_HI_LO: usize = OFF_T1_LO_CW + 1; // 1055
pub const OFF_T1_HI_C0: usize = OFF_T1_HI_LO + 1; // 1056
pub const OFF_T1_HI_C1: usize = OFF_T1_HI_C0 + 1; // 1057
pub const OFF_T1_HI_C2: usize = OFF_T1_HI_C1 + 1; // 1058
pub const OFF_T1_HI_CW: usize = OFF_T1_HI_C2 + 1; // 1059

// T2_full = Σ0 + Maj   (2 u64 summands, per-limb ≤ 2·(2^32-1) < 2^33)
//   Carry per limb ∈ [0, 1] → 1 carry bit (kept symmetric with SHA-256
//   T2 layout: 1 bool + 1 packed cell).
pub const OFF_T2_LO_LO: usize = OFF_T1_HI_CW + 1; // 1060
pub const OFF_T2_LO_C0: usize = OFF_T2_LO_LO + 1; // 1061
pub const OFF_T2_LO_CW: usize = OFF_T2_LO_C0 + 1; // 1062   = c0 (1-bit pack)
pub const OFF_T2_HI_LO: usize = OFF_T2_LO_CW + 1; // 1063
pub const OFF_T2_HI_C0: usize = OFF_T2_HI_LO + 1; // 1064
pub const OFF_T2_HI_CW: usize = OFF_T2_HI_C0 + 1; // 1065

// Block H — H-state (lo, hi) × 8.
pub const OFF_H0_LO: usize = OFF_T2_HI_CW + 1;    // 1066
pub const OFF_H7_HI: usize = OFF_H0_LO + 15;      // 1081

// Block I — W window cells W_win[0..14] as (lo, hi).
//   W_win[k]_LO = OFF_WW0_LO + 2k,  W_win[k]_HI = OFF_WW0_LO + 2k + 1.
//   W_win[15]   = OFF_W (Block F), aliased.
pub const OFF_WW0_LO: usize = OFF_H7_HI + 1;      // 1082
// last cell: OFF_WW0_LO + 2·15 - 1 = 1082 + 29 = 1111

// Block J — bits of W_win[14] = W[t-1] (input to σ1 in the schedule).
pub const OFF_BIT_WW14: usize = OFF_WW0_LO + 30;  // 1112

// Block K — bits of W_win[1] = W[t-14] (input to σ0).
pub const OFF_BIT_WW1: usize = OFF_BIT_WW14 + 64; // 1176

// Block L — σ0(W_win[1]) sub-block.
pub const OFF_SS0_T:   usize = OFF_BIT_WW1 + 64;  // 1240
pub const OFF_SS0_BIT: usize = OFF_SS0_T + 64;    // 1304
pub const OFF_SS0_LO:  usize = OFF_SS0_BIT + 64;  // 1368
pub const OFF_SS0_HI:  usize = OFF_SS0_LO + 1;    // 1369

// Block M — σ1(W_win[14]) sub-block.
pub const OFF_SS1_T:   usize = OFF_SS0_HI + 1;    // 1370
pub const OFF_SS1_BIT: usize = OFF_SS1_T + 64;    // 1434
pub const OFF_SS1_LO:  usize = OFF_SS1_BIT + 64;  // 1498
pub const OFF_SS1_HI:  usize = OFF_SS1_LO + 1;    // 1499

// Block N — schedule sum carry decomp.
//   sum = W_win[0] + σ0(W_win[1]) + W_win[9] + σ1(W_win[14])
//   sum_lo ≤ 4·(2^32-1) < 2^34, carry ∈ [0, 3] → 2 bits.
pub const OFF_WS_LO_C0: usize = OFF_SS1_HI + 1;   // 1500
pub const OFF_WS_LO_C1: usize = OFF_WS_LO_C0 + 1; // 1501
pub const OFF_WS_LO_CW: usize = OFF_WS_LO_C1 + 1; // 1502
pub const OFF_WS_HI_C0: usize = OFF_WS_LO_CW + 1; // 1503
pub const OFF_WS_HI_C1: usize = OFF_WS_HI_C0 + 1; // 1504
pub const OFF_WS_HI_CW: usize = OFF_WS_HI_C1 + 1; // 1505

// Block O — new_a, new_e per-limb carry (1 bit each, lo→hi and hi-overflow).
//   new_a_lo = (T1_lo_lo + T2_lo_lo) mod 2^32, NA_LO_C ∈ {0, 1}
//   new_a_hi = (T1_hi_lo + T2_hi_lo + NA_LO_C) mod 2^32, NA_HI_C ∈ {0, 1}
//   new_e_lo = (d_lo + T1_lo_lo) mod 2^32, NE_LO_C ∈ {0, 1}
//   new_e_hi = (d_hi + T1_hi_lo + NE_LO_C) mod 2^32, NE_HI_C ∈ {0, 1}
pub const OFF_NA_LO_C: usize = OFF_WS_HI_CW + 1;  // 1506
pub const OFF_NA_HI_C: usize = OFF_NA_LO_C + 1;   // 1507
pub const OFF_NE_LO_C: usize = OFF_NA_HI_C + 1;   // 1508
pub const OFF_NE_HI_C: usize = OFF_NE_LO_C + 1;   // 1509

// H-state finalisation does NOT need explicit carry cells.  The
// constraint `delta · (delta − 2^32) = 0` (mirroring SHA-256's
// row-64 trick) handles the lo limb; the hi limb folds in the lo
// carry as `delta_lo · 2^{-32}` (degree-1 polynomial in trace cells)
// before applying the same quadratic gating.  Both reduce to deg-2
// constraints in trace cells without dedicated carry columns.

pub const WIDTH: usize = OFF_NE_HI_C + 1;         // 1510

/// Total number of transition constraints in the SHA-512 AIR.
///
/// Breakdown (mirrors `sha256_air.rs` per-block counts, doubled for
/// 64-bit limb pairs where applicable):
///
///   Bit booleanity:                       8 words × 64 = 512
///   Bit→limb decomp (lo, hi):                       16
///   Σ0 / Σ1 / σ0 / σ1 sub-blocks:        4 × 130 = 520
///   Ch sub-block:                                   66
///   Maj sub-block:                                 322
///   T1 carry decomp (lo + hi):                      10
///   T2 carry decomp (lo + hi):                       6
///   Working register shifts (b←a, c←b, d←c,
///       f←e, g←f, h←g; 6 × 2 limbs):                12
///   new_a, new_e per-limb carries (4 limbs × 2):     8
///   H-state behaviour (per-limb, gated;
///       implicit carry via deg-2 trick):            16
///   W-window shifts (15 shifts × 2 limbs):          30
///   Schedule recurrence (lo + hi):                   8
///   ─────────────────────────────────────────────────
///   TOTAL                                          1526
pub const NUM_CONSTRAINTS: usize = 1526;

// Compile-time layout sanity.
const _: () = assert!(WIDTH == 1510, "SHA-512 AIR width mismatch");

// Single-block trace height (kept for backward compatibility with the
// single-block default registry path; multi-block uses
// `build_sha512_trace_multi` and computes its own height).
pub const N_TRACE: usize = ROWS_PER_BLOCK;

// ═══════════════════════════════════════════════════════════════════
//  F-element helpers (mirror sha256_air.rs)
// ═══════════════════════════════════════════════════════════════════

#[inline]
fn fz() -> F { F::zero() }

#[inline]
fn fu32(x: u32) -> F { F::from(x as u64) }

#[inline]
fn fu64(x: u64) -> F { F::from(x) }

/// Power-of-two F element 2^i for i ∈ [0, 32].
#[inline]
fn pow2(i: u32) -> F { F::from(1u64 << i) }

/// XOR of two bits (each ∈ {0,1}) as a degree-2 polynomial:
///   x ⊕ y = x + y − 2xy.
#[inline]
fn xor_poly(x: F, y: F) -> F { x + y - fu64(2) * x * y }

// ═══════════════════════════════════════════════════════════════════
//  TRACE BUILDER
// ═══════════════════════════════════════════════════════════════════

/// Helper: bit `i` of a u64 cast to F (for i ∈ [0, 64)).
#[inline]
fn fbit(x: u64, i: u32) -> F { F::from(((x >> i) & 1) as u64) }

/// Helper: pack 32 LSB-first bit cells (each F ∈ {0,1}) into the
/// integer `Σ_{k=0}^{31} 2^k · bit_k`, returned as a u32.  Used only
/// inside the trace builder for self-checks; the AIR's pack constraint
/// is expressed directly on field cells in `eval_sha512_constraints`.
#[allow(dead_code)]
#[inline]
fn pack32(bits: &[u64]) -> u32 {
    debug_assert_eq!(bits.len(), 32);
    let mut acc: u32 = 0;
    for (i, b) in bits.iter().enumerate() { acc |= ((*b & 1) as u32) << i; }
    acc
}

/// Build a single-block SHA-512 trace from an already-padded 128-byte
/// message block, using the canonical SHA-512 IV.
///
/// Returns a `WIDTH × N_TRACE` column-major trace.
pub fn build_sha512_trace(block: &[u8; BLOCK_BYTES]) -> Vec<Vec<F>> {
    let mut trace: Vec<Vec<F>> = (0..WIDTH).map(|_| vec![fz(); N_TRACE]).collect();
    fill_block(&mut trace, 0, block, IV);
    trace
}

/// Build a multi-block SHA-512 trace from an arbitrary-length message.
/// Performs SHA-512 padding internally (FIPS 180-4 §5.1.2), splits
/// into 128-byte blocks, lays each block into a 128-row segment of the
/// trace, and chains the IV from the prior block's digest.
///
/// Returns `(trace, n_blocks)`.  Trace height is
/// `(ROWS_PER_BLOCK · n_blocks).next_power_of_two().max(ROWS_PER_BLOCK)`;
/// padding rows past `ROWS_PER_BLOCK · n_blocks` replicate the last
/// useful row, so transition constraints in the past-last-block region
/// evaluate to zero on `nxt = cur`.
pub fn build_sha512_trace_multi(message: &[u8]) -> (Vec<Vec<F>>, usize) {
    let blocks = pad_message_to_blocks(message);
    let n_blocks = blocks.len();
    let useful = ROWS_PER_BLOCK * n_blocks;
    let trace_height = useful.next_power_of_two().max(ROWS_PER_BLOCK);
    let mut trace: Vec<Vec<F>> = (0..WIDTH).map(|_| vec![fz(); trace_height]).collect();

    let mut iv = IV;
    for (b, block) in blocks.iter().enumerate() {
        fill_block(&mut trace, b * ROWS_PER_BLOCK, block, iv);
        let post = compress_block_native(block, iv);
        for k in 0..8 { iv[k] = iv[k].wrapping_add(post[k]); }
    }

    if useful < trace_height {
        for r in useful..trace_height {
            for c in 0..WIDTH {
                trace[c][r] = trace[c][useful - 1];
            }
        }
    }

    (trace, n_blocks)
}

/// Fill one block's 128-row segment of the trace, starting at row
/// `base`, with the given block bytes and starting IV.
///
/// Rows base..base+79 are compression rounds 0..79 (working state at
/// the START of round t held in row base+t).  Row base+80 holds the
/// post-compression state.  Row base+81 holds the block-output digest
/// (= incoming IV + post-compression state, mod 2^64 per word).  Rows
/// base+82..base+127 are idle (working state stable at the post-
/// compression value, H-state stable at the block digest).
fn fill_block(trace: &mut [Vec<F>], base: usize, block: &[u8; BLOCK_BYTES], iv: [u64; 8]) {
    debug_assert!(base + ROWS_PER_BLOCK <= trace[0].len());

    // ─── Step 1: precompute message schedule W[0..79] ───
    let mut w = [0u64; NUM_ROUNDS];
    for i in 0..16 {
        let off = 8 * i;
        w[i] = u64::from_be_bytes([
            block[off], block[off+1], block[off+2], block[off+3],
            block[off+4], block[off+5], block[off+6], block[off+7],
        ]);
    }
    for t in 16..NUM_ROUNDS {
        w[t] = small_sigma1(w[t-2])
            .wrapping_add(w[t-7])
            .wrapping_add(small_sigma0(w[t-15]))
            .wrapping_add(w[t-16]);
    }

    // ─── Step 2: precompute working state at start of each round ───
    // state_at[t] = (a..h) at the START of round t.
    // state_at[0] = iv (canonical SHA-512 IV for block 0; chained IV
    // for subsequent blocks).  state_at[80] = post-compression state.
    let mut state_at = [[0u64; 8]; NUM_ROUNDS + 1];
    state_at[0] = iv;
    for t in 0..NUM_ROUNDS {
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
            a, b, c,                // shifted b←a, c←b, d←c
            d.wrapping_add(t1),     // new e
            e, f_, g,               // shifted f←e, g←f, h←g
        ];
    }

    let post = state_at[NUM_ROUNDS];
    let digest: [u64; 8] = core::array::from_fn(|k| iv[k].wrapping_add(post[k]));

    // ─── Step 3: write rows base..base+ROWS_PER_BLOCK-1 ───
    for block_row in 0..ROWS_PER_BLOCK {
        let row = base + block_row;

        // Working state at this row.  Compression rows hold state_at[r]
        // for r ∈ [0, 80]; idle rows (≥81) hold the post-compression state.
        let s = if block_row <= NUM_ROUNDS {
            state_at[block_row]
        } else {
            state_at[NUM_ROUNDS]
        };
        let (a, b, c, d, e, f_, g, h) = (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);

        // ── Block A: working state (lo, hi) × 8 ──
        let words = [a, b, c, d, e, f_, g, h];
        for k in 0..8 {
            let (lo, hi) = limbs(words[k]);
            trace[A_a_LO + 2*k    ][row] = fu32(lo);
            trace[A_a_LO + 2*k + 1][row] = fu32(hi);
        }

        // ── Block B: bits of {a, b, c, e, f, g} ──
        for i in 0..64 {
            trace[OFF_BIT_A + i][row] = fbit(a,  i as u32);
            trace[OFF_BIT_B + i][row] = fbit(b,  i as u32);
            trace[OFF_BIT_C + i][row] = fbit(c,  i as u32);
            trace[OFF_BIT_E + i][row] = fbit(e,  i as u32);
            trace[OFF_BIT_F + i][row] = fbit(f_, i as u32);
            trace[OFF_BIT_G + i][row] = fbit(g,  i as u32);
        }

        // ── Block C0: Σ0(a) = ROTR^28(a) ⊕ ROTR^34(a) ⊕ ROTR^39(a) ──
        let s0_word = big_sigma0(a);
        for i in 0..64 {
            let p = bit(a, ((i + 28) % 64) as u32);
            let q = bit(a, ((i + 34) % 64) as u32);
            let r = bit(a, ((i + 39) % 64) as u32);
            trace[OFF_S0_T   + i][row] = fu64(p ^ q);
            trace[OFF_S0_BIT + i][row] = fu64(p ^ q ^ r);
        }
        let (s0_lo, s0_hi) = limbs(s0_word);
        trace[OFF_S0_LO][row] = fu32(s0_lo);
        trace[OFF_S0_HI][row] = fu32(s0_hi);

        // ── Block C1: Σ1(e) = ROTR^14(e) ⊕ ROTR^18(e) ⊕ ROTR^41(e) ──
        let s1_word = big_sigma1(e);
        for i in 0..64 {
            let p = bit(e, ((i + 14) % 64) as u32);
            let q = bit(e, ((i + 18) % 64) as u32);
            let r = bit(e, ((i + 41) % 64) as u32);
            trace[OFF_S1_T   + i][row] = fu64(p ^ q);
            trace[OFF_S1_BIT + i][row] = fu64(p ^ q ^ r);
        }
        let (s1_lo, s1_hi) = limbs(s1_word);
        trace[OFF_S1_LO][row] = fu32(s1_lo);
        trace[OFF_S1_HI][row] = fu32(s1_hi);

        // ── Block D: Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g) ──
        let ch_word = ch(e, f_, g);
        for i in 0..64 {
            trace[OFF_CH_BIT + i][row] = fbit(ch_word, i as u32);
        }
        let (ch_lo, ch_hi) = limbs(ch_word);
        trace[OFF_CH_LO][row] = fu32(ch_lo);
        trace[OFF_CH_HI][row] = fu32(ch_hi);

        // ── Block E: Maj(a, b, c) bit-by-bit with auxiliaries.
        //   ab_i = a_i·b_i,  ac_i = a_i·c_i,  bc_i = b_i·c_i,
        //   u_i  = ab_i ⊕ ac_i,  Maj_i = u_i ⊕ bc_i.
        let maj_word = maj(a, b, c);
        for i in 0..64 {
            let ai = bit(a, i as u32);
            let bi = bit(b, i as u32);
            let ci = bit(c, i as u32);
            let abi = ai & bi;
            let aci = ai & ci;
            let bci = bi & ci;
            let ui  = abi ^ aci;
            let mi  = ui  ^ bci;
            trace[OFF_MAJ_AB  + i][row] = fu64(abi);
            trace[OFF_MAJ_AC  + i][row] = fu64(aci);
            trace[OFF_MAJ_BC  + i][row] = fu64(bci);
            trace[OFF_MAJ_U   + i][row] = fu64(ui);
            trace[OFF_MAJ_BIT + i][row] = fu64(mi);
        }
        let (maj_lo, maj_hi) = limbs(maj_word);
        trace[OFF_MAJ_LO][row] = fu32(maj_lo);
        trace[OFF_MAJ_HI][row] = fu32(maj_hi);

        // ── Block F: W[t].  W is meaningful for compression rounds
        //   (block_row 0..79) and zero on idle rows.
        let w_t = if block_row < NUM_ROUNDS { w[block_row] } else { 0 };
        let (w_lo, w_hi) = limbs(w_t);
        trace[OFF_W_LO][row] = fu32(w_lo);
        trace[OFF_W_HI][row] = fu32(w_hi);

        // ── Block G: T1, T2 carry decomposition (per limb).
        //   T1_lo_full = h_lo + Σ1_lo + Ch_lo + K_lo + W_lo
        //   T1_hi_full = h_hi + Σ1_hi + Ch_hi + K_hi + W_hi + T1_lo_carry
        //   T2_lo_full = Σ0_lo + Maj_lo
        //   T2_hi_full = Σ0_hi + Maj_hi + T2_lo_carry
        let k_t = if block_row < NUM_ROUNDS { K[block_row] } else { 0 };
        let (h_lo, h_hi)   = limbs(h);
        let (k_lo, k_hi)   = limbs(k_t);

        let t1_lo_full: u64 = (h_lo as u64)
            + (s1_lo as u64) + (ch_lo as u64) + (k_lo as u64) + (w_lo as u64);
        let t1_lo_lo    = (t1_lo_full as u32) as u32;            // mod 2^32
        let t1_lo_carry = (t1_lo_full >> 32) as u32;             // ∈ [0, 4]
        let t1_hi_full: u64 = (h_hi as u64)
            + (s1_hi as u64) + (ch_hi as u64) + (k_hi as u64) + (w_hi as u64)
            + (t1_lo_carry as u64);
        let t1_hi_lo    = (t1_hi_full as u32) as u32;
        let t1_hi_carry = (t1_hi_full >> 32) as u32;             // ∈ [0, 4]

        trace[OFF_T1_LO_LO][row] = fu32(t1_lo_lo);
        trace[OFF_T1_LO_C0][row] = fu32(t1_lo_carry & 1);
        trace[OFF_T1_LO_C1][row] = fu32((t1_lo_carry >> 1) & 1);
        trace[OFF_T1_LO_C2][row] = fu32((t1_lo_carry >> 2) & 1);
        trace[OFF_T1_LO_CW][row] = fu32(t1_lo_carry);
        trace[OFF_T1_HI_LO][row] = fu32(t1_hi_lo);
        trace[OFF_T1_HI_C0][row] = fu32(t1_hi_carry & 1);
        trace[OFF_T1_HI_C1][row] = fu32((t1_hi_carry >> 1) & 1);
        trace[OFF_T1_HI_C2][row] = fu32((t1_hi_carry >> 2) & 1);
        trace[OFF_T1_HI_CW][row] = fu32(t1_hi_carry);

        let t2_lo_full: u64 = (s0_lo as u64) + (maj_lo as u64);
        let t2_lo_lo    = (t2_lo_full as u32) as u32;
        let t2_lo_carry = (t2_lo_full >> 32) as u32;             // ∈ [0, 1]
        let t2_hi_full: u64 = (s0_hi as u64) + (maj_hi as u64) + (t2_lo_carry as u64);
        let t2_hi_lo    = (t2_hi_full as u32) as u32;
        let t2_hi_carry = (t2_hi_full >> 32) as u32;             // ∈ [0, 1]

        trace[OFF_T2_LO_LO][row] = fu32(t2_lo_lo);
        trace[OFF_T2_LO_C0][row] = fu32(t2_lo_carry & 1);
        trace[OFF_T2_LO_CW][row] = fu32(t2_lo_carry);
        trace[OFF_T2_HI_LO][row] = fu32(t2_hi_lo);
        trace[OFF_T2_HI_C0][row] = fu32(t2_hi_carry & 1);
        trace[OFF_T2_HI_CW][row] = fu32(t2_hi_carry);

        // ── Block H: H-state.  block_row 0..80 hold incoming IV;
        //   block_row ≥ 81 hold the block-output digest.
        let hs = if block_row <= NUM_ROUNDS { iv } else { digest };
        for k in 0..8 {
            let (lo, hi) = limbs(hs[k]);
            trace[OFF_H0_LO + 2*k    ][row] = fu32(lo);
            trace[OFF_H0_LO + 2*k + 1][row] = fu32(hi);
        }

        // ── Block I: W window W_win[0..14] = (W[r-15], ..., W[r-1]).
        for k in 0..15 {
            let w_idx_signed = (block_row as isize) - 15 + (k as isize);
            let w_val = if (0..(NUM_ROUNDS as isize)).contains(&w_idx_signed) {
                w[w_idx_signed as usize]
            } else {
                0
            };
            let (lo, hi) = limbs(w_val);
            trace[OFF_WW0_LO + 2*k    ][row] = fu32(lo);
            trace[OFF_WW0_LO + 2*k + 1][row] = fu32(hi);
        }

        // ── Block J: bits of W_win[14] = W[r-1] ──
        let ww14: u64 = {
            let idx = (block_row as isize) - 1;
            if (0..(NUM_ROUNDS as isize)).contains(&idx) { w[idx as usize] } else { 0 }
        };
        for i in 0..64 {
            trace[OFF_BIT_WW14 + i][row] = fbit(ww14, i as u32);
        }

        // ── Block K: bits of W_win[1] = W[r-14] ──
        let ww1: u64 = {
            let idx = (block_row as isize) - 14;
            if (0..(NUM_ROUNDS as isize)).contains(&idx) { w[idx as usize] } else { 0 }
        };
        for i in 0..64 {
            trace[OFF_BIT_WW1 + i][row] = fbit(ww1, i as u32);
        }

        // ── Block L: σ0(W_win[1]) = ROTR^1 ⊕ ROTR^8 ⊕ SHR^7 ──
        let ss0_word = small_sigma0(ww1);
        for i in 0..64 {
            let p = bit(ww1, ((i + 1) % 64) as u32);
            let q = bit(ww1, ((i + 8) % 64) as u32);
            let r = if i + 7 < 64 { bit(ww1, (i + 7) as u32) } else { 0 };
            trace[OFF_SS0_T   + i][row] = fu64(p ^ q);
            trace[OFF_SS0_BIT + i][row] = fu64(p ^ q ^ r);
        }
        let (ss0_lo, ss0_hi) = limbs(ss0_word);
        trace[OFF_SS0_LO][row] = fu32(ss0_lo);
        trace[OFF_SS0_HI][row] = fu32(ss0_hi);

        // ── Block M: σ1(W_win[14]) = ROTR^19 ⊕ ROTR^61 ⊕ SHR^6 ──
        let ss1_word = small_sigma1(ww14);
        for i in 0..64 {
            let p = bit(ww14, ((i + 19) % 64) as u32);
            let q = bit(ww14, ((i + 61) % 64) as u32);
            let r = if i + 6 < 64 { bit(ww14, (i + 6) as u32) } else { 0 };
            trace[OFF_SS1_T   + i][row] = fu64(p ^ q);
            trace[OFF_SS1_BIT + i][row] = fu64(p ^ q ^ r);
        }
        let (ss1_lo, ss1_hi) = limbs(ss1_word);
        trace[OFF_SS1_LO][row] = fu32(ss1_lo);
        trace[OFF_SS1_HI][row] = fu32(ss1_hi);

        // ── Block N: schedule sum carry (per limb).
        let ww0_val: u64 = {
            let idx = (block_row as isize) - 15;
            if (0..(NUM_ROUNDS as isize)).contains(&idx) { w[idx as usize] } else { 0 }
        };
        let ww9_val: u64 = {
            let idx = (block_row as isize) - 6;
            if (0..(NUM_ROUNDS as isize)).contains(&idx) { w[idx as usize] } else { 0 }
        };
        let (ww0_lo, ww0_hi) = limbs(ww0_val);
        let (ww9_lo, ww9_hi) = limbs(ww9_val);
        let ws_lo_full: u64 = (ww0_lo as u64) + (ss0_lo as u64)
            + (ww9_lo as u64) + (ss1_lo as u64);
        let ws_lo_carry = (ws_lo_full >> 32) as u32;             // ∈ [0, 3]
        let ws_hi_full: u64 = (ww0_hi as u64) + (ss0_hi as u64)
            + (ww9_hi as u64) + (ss1_hi as u64) + (ws_lo_carry as u64);
        let ws_hi_carry = (ws_hi_full >> 32) as u32;             // ∈ [0, 3]

        trace[OFF_WS_LO_C0][row] = fu32(ws_lo_carry & 1);
        trace[OFF_WS_LO_C1][row] = fu32((ws_lo_carry >> 1) & 1);
        trace[OFF_WS_LO_CW][row] = fu32(ws_lo_carry);
        trace[OFF_WS_HI_C0][row] = fu32(ws_hi_carry & 1);
        trace[OFF_WS_HI_C1][row] = fu32((ws_hi_carry >> 1) & 1);
        trace[OFF_WS_HI_CW][row] = fu32(ws_hi_carry);

        // ── Block O: new_a, new_e per-limb carries (compression rows only).
        if block_row < NUM_ROUNDS {
            let (d_lo, d_hi) = limbs(d);
            let na_lo_full: u64 = (t1_lo_lo as u64) + (t2_lo_lo as u64);
            let na_lo_c = (na_lo_full >> 32) as u32;             // ∈ [0, 1]
            let na_hi_full: u64 = (t1_hi_lo as u64) + (t2_hi_lo as u64) + (na_lo_c as u64);
            let na_hi_c = (na_hi_full >> 32) as u32;             // ∈ [0, 1]
            let ne_lo_full: u64 = (d_lo as u64) + (t1_lo_lo as u64);
            let ne_lo_c = (ne_lo_full >> 32) as u32;             // ∈ [0, 1]
            let ne_hi_full: u64 = (d_hi as u64) + (t1_hi_lo as u64) + (ne_lo_c as u64);
            let ne_hi_c = (ne_hi_full >> 32) as u32;             // ∈ [0, 1]

            trace[OFF_NA_LO_C][row] = fu32(na_lo_c);
            trace[OFF_NA_HI_C][row] = fu32(na_hi_c);
            trace[OFF_NE_LO_C][row] = fu32(ne_lo_c);
            trace[OFF_NE_HI_C][row] = fu32(ne_hi_c);
        }

        // (No Block P — H-state finalisation carries are absorbed into
        //  the constraint evaluator's quadratic carry-implicit form;
        //  see `eval_sha512_constraints` for the H-state section.)
    }
}

// ═══════════════════════════════════════════════════════════════════
//  CONSTRAINT EVALUATOR
// ═══════════════════════════════════════════════════════════════════

/// Evaluate all `NUM_CONSTRAINTS` transition constraints at row `row`
/// for the given current and next row values.  Returns a vector of
/// length `NUM_CONSTRAINTS`; on a valid trace every entry is zero.
///
/// Mirrors `sha256_air::eval_sha256_constraints` block-for-block but
/// with the two-limb adaptation:
///
///   • Each "word" cell becomes (lo, hi) limb cells; bit-decomposition
///     packs lo from bits[0..32] and hi from bits[32..64].
///   • T1, T2, schedule, new_a, new_e carry decompositions run
///     separately on lo and hi limbs with cross-limb carry chaining.
///   • H-state finalisation uses the SHA-256-style implicit-carry trick
///     `delta · (delta − 2^32) = 0`, applied per limb with the lo
///     limb's carry folded into the hi-limb expression as
///     `delta_lo · 2^{-32}` (a constant-coefficient term, deg-2 overall).
///
/// Multi-block gating: `n_blocks` is the number of SHA-512 blocks the
/// trace encodes.  For row indices past `n_blocks · ROWS_PER_BLOCK`
/// (replicated last-row padding), all phase predicates are forced to
/// "idle" — every gated constraint then evaluates to zero on `nxt = cur`.
pub fn eval_sha512_constraints(
    cur: &[F], nxt: &[F], row: usize, n_blocks: usize,
) -> Vec<F> {
    let mut out: Vec<F> = Vec::with_capacity(NUM_CONSTRAINTS);

    // Phase predicates.
    let block_idx = row / ROWS_PER_BLOCK;
    let block_row = row % ROWS_PER_BLOCK;
    let past_last_block = block_idx >= n_blocks;

    let compression_active  = !past_last_block && block_row < NUM_ROUNDS;
    let finalisation_active = !past_last_block && block_row == NUM_ROUNDS;
    let _idle_active        =  past_last_block || block_row >= NUM_ROUNDS + 1;
    // Schedule recurrence fires when we're computing nxt[OFF_W] for
    // round t+1 ∈ [16, 79].  At cur block_row r ∈ [15, 78], the next
    // row r+1 holds W[r+1].  So range [15, 78].
    let schedule_active     = !past_last_block && (15..=78).contains(&block_row);

    // ── Block B: bit booleanity (8 words × 64 = 512 cons) ──────────
    for off in [OFF_BIT_A, OFF_BIT_B, OFF_BIT_C,
                OFF_BIT_E, OFF_BIT_F, OFF_BIT_G,
                OFF_BIT_WW14, OFF_BIT_WW1] {
        for i in 0..64 {
            let b = cur[off + i];
            out.push(b * (F::one() - b));
        }
    }

    // ── Bit→limb decomp (8 words × 2 limbs = 16 cons, deg 1) ──────
    //
    // pack_lo = Σ_{i=0..32} 2^i · bit_i
    // pack_hi = Σ_{i=0..32} 2^i · bit_{32+i}
    let pow_table: [F; 32] = core::array::from_fn(|i| pow2(i as u32));
    let pack_lo = |off: usize, c: &[F]| -> F {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * c[off + i]; }
        s
    };
    let pack_hi = |off: usize, c: &[F]| -> F {
        let mut s = fz();
        for i in 0..32 { s += pow_table[i] * c[off + 32 + i]; }
        s
    };

    // Working state words {a, b, c, e, f, g}: 12 cons.
    out.push(cur[A_a_LO] - pack_lo(OFF_BIT_A, cur));
    out.push(cur[A_a_HI] - pack_hi(OFF_BIT_A, cur));
    out.push(cur[A_b_LO] - pack_lo(OFF_BIT_B, cur));
    out.push(cur[A_b_HI] - pack_hi(OFF_BIT_B, cur));
    out.push(cur[A_c_LO] - pack_lo(OFF_BIT_C, cur));
    out.push(cur[A_c_HI] - pack_hi(OFF_BIT_C, cur));
    out.push(cur[A_e_LO] - pack_lo(OFF_BIT_E, cur));
    out.push(cur[A_e_HI] - pack_hi(OFF_BIT_E, cur));
    out.push(cur[A_f_LO] - pack_lo(OFF_BIT_F, cur));
    out.push(cur[A_f_HI] - pack_hi(OFF_BIT_F, cur));
    out.push(cur[A_g_LO] - pack_lo(OFF_BIT_G, cur));
    out.push(cur[A_g_HI] - pack_hi(OFF_BIT_G, cur));
    // W-window words: W_win[14] (= cur[OFF_WW0_LO + 28..30]) and
    // W_win[1]  (= cur[OFF_WW0_LO + 2..4]).  4 cons.
    out.push(cur[OFF_WW0_LO + 28] - pack_lo(OFF_BIT_WW14, cur));
    out.push(cur[OFF_WW0_LO + 29] - pack_hi(OFF_BIT_WW14, cur));
    out.push(cur[OFF_WW0_LO +  2] - pack_lo(OFF_BIT_WW1,  cur));
    out.push(cur[OFF_WW0_LO +  3] - pack_hi(OFF_BIT_WW1,  cur));

    // ── Block C0: Σ0(a) sub-block (130 cons) ─────────────────────
    //   Σ0(a) = ROTR^28(a) ⊕ ROTR^34(a) ⊕ ROTR^39(a)   (FIPS §4.1.3)
    for i in 0..64 {
        let p = cur[OFF_BIT_A + ((i + 28) % 64)];
        let q = cur[OFF_BIT_A + ((i + 34) % 64)];
        out.push(cur[OFF_S0_T + i] - xor_poly(p, q));
    }
    for i in 0..64 {
        let t0 = cur[OFF_S0_T + i];
        let r  = cur[OFF_BIT_A + ((i + 39) % 64)];
        out.push(cur[OFF_S0_BIT + i] - xor_poly(t0, r));
    }
    out.push(cur[OFF_S0_LO] - pack_lo(OFF_S0_BIT, cur));
    out.push(cur[OFF_S0_HI] - pack_hi(OFF_S0_BIT, cur));

    // ── Block C1: Σ1(e) sub-block (130 cons) ─────────────────────
    //   Σ1(e) = ROTR^14(e) ⊕ ROTR^18(e) ⊕ ROTR^41(e)
    for i in 0..64 {
        let p = cur[OFF_BIT_E + ((i + 14) % 64)];
        let q = cur[OFF_BIT_E + ((i + 18) % 64)];
        out.push(cur[OFF_S1_T + i] - xor_poly(p, q));
    }
    for i in 0..64 {
        let t0 = cur[OFF_S1_T + i];
        let r  = cur[OFF_BIT_E + ((i + 41) % 64)];
        out.push(cur[OFF_S1_BIT + i] - xor_poly(t0, r));
    }
    out.push(cur[OFF_S1_LO] - pack_lo(OFF_S1_BIT, cur));
    out.push(cur[OFF_S1_HI] - pack_hi(OFF_S1_BIT, cur));

    // ── Block L: σ0(W_win[1]) sub-block (130 cons) ───────────────
    //   σ0(x) = ROTR^1(x) ⊕ ROTR^8(x) ⊕ SHR^7(x)
    for i in 0..64 {
        let p = cur[OFF_BIT_WW1 + ((i + 1) % 64)];
        let q = cur[OFF_BIT_WW1 + ((i + 8) % 64)];
        out.push(cur[OFF_SS0_T + i] - xor_poly(p, q));
    }
    for i in 0..64 {
        let t0 = cur[OFF_SS0_T + i];
        let r  = if i + 7 < 64 { cur[OFF_BIT_WW1 + (i + 7)] } else { fz() };
        out.push(cur[OFF_SS0_BIT + i] - xor_poly(t0, r));
    }
    out.push(cur[OFF_SS0_LO] - pack_lo(OFF_SS0_BIT, cur));
    out.push(cur[OFF_SS0_HI] - pack_hi(OFF_SS0_BIT, cur));

    // ── Block M: σ1(W_win[14]) sub-block (130 cons) ──────────────
    //   σ1(x) = ROTR^19(x) ⊕ ROTR^61(x) ⊕ SHR^6(x)
    for i in 0..64 {
        let p = cur[OFF_BIT_WW14 + ((i + 19) % 64)];
        let q = cur[OFF_BIT_WW14 + ((i + 61) % 64)];
        out.push(cur[OFF_SS1_T + i] - xor_poly(p, q));
    }
    for i in 0..64 {
        let t0 = cur[OFF_SS1_T + i];
        let r  = if i + 6 < 64 { cur[OFF_BIT_WW14 + (i + 6)] } else { fz() };
        out.push(cur[OFF_SS1_BIT + i] - xor_poly(t0, r));
    }
    out.push(cur[OFF_SS1_LO] - pack_lo(OFF_SS1_BIT, cur));
    out.push(cur[OFF_SS1_HI] - pack_hi(OFF_SS1_BIT, cur));

    // ── Block D: Ch(e, f, g) (66 cons) ──────────────────────────
    //   Ch_i = e_i·f_i + g_i − e_i·g_i  (deg 2)
    for i in 0..64 {
        let ei = cur[OFF_BIT_E + i];
        let fi = cur[OFF_BIT_F + i];
        let gi = cur[OFF_BIT_G + i];
        out.push(cur[OFF_CH_BIT + i] - (ei * fi + gi - ei * gi));
    }
    out.push(cur[OFF_CH_LO] - pack_lo(OFF_CH_BIT, cur));
    out.push(cur[OFF_CH_HI] - pack_hi(OFF_CH_BIT, cur));

    // ── Block E: Maj(a, b, c) (322 cons) ────────────────────────
    //   ab_i = a_i·b_i, ac_i = a_i·c_i, bc_i = b_i·c_i  (deg 2)
    //   u_i  = ab_i ⊕ ac_i,    Maj_i = u_i ⊕ bc_i        (deg 2)
    for i in 0..64 {
        let ai = cur[OFF_BIT_A + i];
        let bi = cur[OFF_BIT_B + i];
        let ci = cur[OFF_BIT_C + i];
        out.push(cur[OFF_MAJ_AB + i] - ai * bi);
        out.push(cur[OFF_MAJ_AC + i] - ai * ci);
        out.push(cur[OFF_MAJ_BC + i] - bi * ci);
    }
    for i in 0..64 {
        let ab = cur[OFF_MAJ_AB + i];
        let ac = cur[OFF_MAJ_AC + i];
        out.push(cur[OFF_MAJ_U + i] - xor_poly(ab, ac));
    }
    for i in 0..64 {
        let u  = cur[OFF_MAJ_U + i];
        let bc = cur[OFF_MAJ_BC + i];
        out.push(cur[OFF_MAJ_BIT + i] - xor_poly(u, bc));
    }
    out.push(cur[OFF_MAJ_LO] - pack_lo(OFF_MAJ_BIT, cur));
    out.push(cur[OFF_MAJ_HI] - pack_hi(OFF_MAJ_BIT, cur));

    // ── Block G: T1, T2 carry decomp (10 + 6 = 16 cons) ─────────
    //
    // T1_lo_full = h_lo + Σ1_lo + Ch_lo + K_lo + W_lo  ≤ 5·(2^32-1) < 2^35
    //              = T1_lo_lo + 2^32 · T1_lo_CW,  T1_lo_CW ∈ [0, 4]
    // T1_hi_full = h_hi + Σ1_hi + Ch_hi + K_hi + W_hi + T1_lo_CW  < 2^35
    //              = T1_hi_lo + 2^32 · T1_hi_CW,  T1_hi_CW ∈ [0, 4]
    let k_t = if compression_active { K[block_row] } else { 0 };
    let (k_lo_u32, k_hi_u32) = limbs(k_t);
    let k_lo_f = fu32(k_lo_u32);
    let k_hi_f = fu32(k_hi_u32);

    // T1 lo (5 cons): sum identity, 3 booleans, carry pack.
    {
        let t1_lo_sum = cur[A_h_LO] + cur[OFF_S1_LO] + cur[OFF_CH_LO] + k_lo_f + cur[OFF_W_LO];
        out.push(cur[OFF_T1_LO_LO] + pow2(32) * cur[OFF_T1_LO_CW] - t1_lo_sum);
    }
    for off in [OFF_T1_LO_C0, OFF_T1_LO_C1, OFF_T1_LO_C2] {
        let b = cur[off];
        out.push(b * (F::one() - b));
    }
    out.push(cur[OFF_T1_LO_CW]
        - cur[OFF_T1_LO_C0]
        - fu64(2) * cur[OFF_T1_LO_C1]
        - fu64(4) * cur[OFF_T1_LO_C2]);

    // T1 hi (5 cons): with carry-in from lo.
    {
        let t1_hi_sum = cur[A_h_HI] + cur[OFF_S1_HI] + cur[OFF_CH_HI] + k_hi_f + cur[OFF_W_HI]
                      + cur[OFF_T1_LO_CW];
        out.push(cur[OFF_T1_HI_LO] + pow2(32) * cur[OFF_T1_HI_CW] - t1_hi_sum);
    }
    for off in [OFF_T1_HI_C0, OFF_T1_HI_C1, OFF_T1_HI_C2] {
        let b = cur[off];
        out.push(b * (F::one() - b));
    }
    out.push(cur[OFF_T1_HI_CW]
        - cur[OFF_T1_HI_C0]
        - fu64(2) * cur[OFF_T1_HI_C1]
        - fu64(4) * cur[OFF_T1_HI_C2]);

    // T2_lo_full = Σ0_lo + Maj_lo  < 2^33,  T2_lo_CW ∈ [0, 1]
    // T2_hi_full = Σ0_hi + Maj_hi + T2_lo_CW  < 2^33,  T2_hi_CW ∈ [0, 1]
    {
        let t2_lo_sum = cur[OFF_S0_LO] + cur[OFF_MAJ_LO];
        out.push(cur[OFF_T2_LO_LO] + pow2(32) * cur[OFF_T2_LO_CW] - t2_lo_sum);
    }
    {
        let b = cur[OFF_T2_LO_C0];
        out.push(b * (F::one() - b));
    }
    out.push(cur[OFF_T2_LO_CW] - cur[OFF_T2_LO_C0]);

    {
        let t2_hi_sum = cur[OFF_S0_HI] + cur[OFF_MAJ_HI] + cur[OFF_T2_LO_CW];
        out.push(cur[OFF_T2_HI_LO] + pow2(32) * cur[OFF_T2_HI_CW] - t2_hi_sum);
    }
    {
        let b = cur[OFF_T2_HI_C0];
        out.push(b * (F::one() - b));
    }
    out.push(cur[OFF_T2_HI_CW] - cur[OFF_T2_HI_C0]);

    // ── Working register shifts (12 cons, deg 1) ──────────────────
    //
    // Active on compression rows; outside compression, the working
    // state is held stable and the constraints fire safely on cur=nxt.
    out.push(if compression_active { nxt[A_b_LO] - cur[A_a_LO] } else { fz() });
    out.push(if compression_active { nxt[A_b_HI] - cur[A_a_HI] } else { fz() });
    out.push(if compression_active { nxt[A_c_LO] - cur[A_b_LO] } else { fz() });
    out.push(if compression_active { nxt[A_c_HI] - cur[A_b_HI] } else { fz() });
    out.push(if compression_active { nxt[A_d_LO] - cur[A_c_LO] } else { fz() });
    out.push(if compression_active { nxt[A_d_HI] - cur[A_c_HI] } else { fz() });
    out.push(if compression_active { nxt[A_f_LO] - cur[A_e_LO] } else { fz() });
    out.push(if compression_active { nxt[A_f_HI] - cur[A_e_HI] } else { fz() });
    out.push(if compression_active { nxt[A_g_LO] - cur[A_f_LO] } else { fz() });
    out.push(if compression_active { nxt[A_g_HI] - cur[A_f_HI] } else { fz() });
    out.push(if compression_active { nxt[A_h_LO] - cur[A_g_LO] } else { fz() });
    out.push(if compression_active { nxt[A_h_HI] - cur[A_g_HI] } else { fz() });

    // ── new_a, new_e per-limb carries (8 cons) ────────────────────
    //
    // Active on compression rows.
    //   new_a_lo:  T1_lo_lo + T2_lo_lo = nxt[A_a_LO] + 2^32 · NA_LO_C
    //   new_a_hi:  T1_hi_lo + T2_hi_lo + NA_LO_C = nxt[A_a_HI] + 2^32 · NA_HI_C
    //   new_e_lo:  d_lo + T1_lo_lo = nxt[A_e_LO] + 2^32 · NE_LO_C
    //   new_e_hi:  d_hi + T1_hi_lo + NE_LO_C = nxt[A_e_HI] + 2^32 · NE_HI_C
    if compression_active {
        // new_a lo.
        out.push(nxt[A_a_LO] + pow2(32) * cur[OFF_NA_LO_C]
                 - cur[OFF_T1_LO_LO] - cur[OFF_T2_LO_LO]);
        let na_lo = cur[OFF_NA_LO_C];
        out.push(na_lo * (F::one() - na_lo));
        // new_a hi.
        out.push(nxt[A_a_HI] + pow2(32) * cur[OFF_NA_HI_C]
                 - cur[OFF_T1_HI_LO] - cur[OFF_T2_HI_LO] - cur[OFF_NA_LO_C]);
        let na_hi = cur[OFF_NA_HI_C];
        out.push(na_hi * (F::one() - na_hi));
        // new_e lo.
        out.push(nxt[A_e_LO] + pow2(32) * cur[OFF_NE_LO_C]
                 - cur[A_d_LO] - cur[OFF_T1_LO_LO]);
        let ne_lo = cur[OFF_NE_LO_C];
        out.push(ne_lo * (F::one() - ne_lo));
        // new_e hi.
        out.push(nxt[A_e_HI] + pow2(32) * cur[OFF_NE_HI_C]
                 - cur[A_d_HI] - cur[OFF_T1_HI_LO] - cur[OFF_NE_LO_C]);
        let ne_hi = cur[OFF_NE_HI_C];
        out.push(ne_hi * (F::one() - ne_hi));
    } else {
        for _ in 0..8 { out.push(fz()); }
    }

    // ── H-state behaviour (16 cons, per-limb, deg 2) ─────────────
    //
    // Per H-word k:
    //   Hold rows (compression + idle): nxt[H_LO] − cur[H_LO] = 0
    //                                   nxt[H_HI] − cur[H_HI] = 0
    //   Finalisation row (block_row 80 → 81):
    //     delta_lo = cur[H_LO] + cur[A_LO] − nxt[H_LO]   ∈ {0, 2^32}
    //     ⇒ delta_lo · (delta_lo − 2^32) = 0
    //     carry_lo = delta_lo · 2^{-32} ∈ {0, 1}
    //     delta_hi = cur[H_HI] + cur[A_HI] + carry_lo − nxt[H_HI]
    //               ∈ {0, 2^32}
    //     ⇒ delta_hi · (delta_hi − 2^32) = 0
    //
    // Both forms reduce to deg-2 polynomials in trace cells
    // (carry_lo = constant · delta_lo), no carry columns needed.
    if finalisation_active {
        let pow2_32 = pow2(32);
        // 2^{-32} as a Goldilocks constant; computed once per call,
        // safe because pow2(32) is invertible (a power of the multi-
        // plicative generator's order doesn't divide |F^×|).
        let inv32 = pow2_32.inverse().expect("2^32 is invertible in Goldilocks");
        for k in 0..8 {
            let h_lo = cur[OFF_H0_LO + 2*k];
            let h_hi = cur[OFF_H0_LO + 2*k + 1];
            let a_lo = cur[A_a_LO + 2*k];
            let a_hi = cur[A_a_LO + 2*k + 1];
            let nxt_h_lo = nxt[OFF_H0_LO + 2*k];
            let nxt_h_hi = nxt[OFF_H0_LO + 2*k + 1];
            let delta_lo = h_lo + a_lo - nxt_h_lo;
            let carry_lo = delta_lo * inv32;
            let delta_hi = h_hi + a_hi + carry_lo - nxt_h_hi;
            out.push(delta_lo * (delta_lo - pow2_32));
            out.push(delta_hi * (delta_hi - pow2_32));
        }
    } else {
        for k in 0..8 {
            out.push(nxt[OFF_H0_LO + 2*k    ] - cur[OFF_H0_LO + 2*k    ]);
            out.push(nxt[OFF_H0_LO + 2*k + 1] - cur[OFF_H0_LO + 2*k + 1]);
        }
    }

    // ── W-window shifts (30 cons, deg 1) ──────────────────────────
    //
    //   nxt[W_win[k]_X] = cur[W_win[k+1]_X]    for k = 0..13, X ∈ {LO, HI}
    //   nxt[W_win[14]_X] = cur[OFF_W_X]                          (k = 14)
    //
    // Both directions: 14 + 1 = 15 shifts × 2 limbs = 30 cons.
    for k in 0..14 {
        out.push(nxt[OFF_WW0_LO + 2*k    ] - cur[OFF_WW0_LO + 2*(k+1)    ]);
        out.push(nxt[OFF_WW0_LO + 2*k + 1] - cur[OFF_WW0_LO + 2*(k+1) + 1]);
    }
    // Shift W_win[14] ← OFF_W (= W_win[15]).
    out.push(nxt[OFF_WW0_LO + 28] - cur[OFF_W_LO]);
    out.push(nxt[OFF_WW0_LO + 29] - cur[OFF_W_HI]);

    // ── Schedule recurrence (8 cons, gated to rows 15..78) ───────
    //
    //   sum = W_win[0] + σ0(W_win[1]) + W_win[9] + σ1(W_win[14])
    //   nxt[OFF_W_LO] = sum_lo mod 2^32, sum_lo_CW ∈ [0, 3]
    //   nxt[OFF_W_HI] = sum_hi mod 2^32, sum_hi_CW ∈ [0, 3]
    //   c0, c1 booleans; CW = c0 + 2 c1.
    if schedule_active {
        // Lo: 4 cons.
        let sum_lo = cur[OFF_WW0_LO + 0]
                   + cur[OFF_SS0_LO]
                   + cur[OFF_WW0_LO + 18]   // W_win[9] LO
                   + cur[OFF_SS1_LO];
        out.push(nxt[OFF_W_LO] + pow2(32) * cur[OFF_WS_LO_CW] - sum_lo);
        let c0 = cur[OFF_WS_LO_C0];
        let c1 = cur[OFF_WS_LO_C1];
        out.push(c0 * (F::one() - c0));
        out.push(c1 * (F::one() - c1));
        out.push(cur[OFF_WS_LO_CW] - c0 - fu64(2) * c1);
        // Hi: 4 cons (with carry-in).
        let sum_hi = cur[OFF_WW0_LO + 1]
                   + cur[OFF_SS0_HI]
                   + cur[OFF_WW0_LO + 19]   // W_win[9] HI
                   + cur[OFF_SS1_HI]
                   + cur[OFF_WS_LO_CW];
        out.push(nxt[OFF_W_HI] + pow2(32) * cur[OFF_WS_HI_CW] - sum_hi);
        let c0h = cur[OFF_WS_HI_C0];
        let c1h = cur[OFF_WS_HI_C1];
        out.push(c0h * (F::one() - c0h));
        out.push(c1h * (F::one() - c1h));
        out.push(cur[OFF_WS_HI_CW] - c0h - fu64(2) * c1h);
    } else {
        for _ in 0..8 { out.push(fz()); }
    }

    debug_assert_eq!(
        out.len(), NUM_CONSTRAINTS,
        "constraint count mismatch: emitted {} expected {}",
        out.len(), NUM_CONSTRAINTS
    );
    out
}

// ═══════════════════════════════════════════════════════════════════
//  Trace-self-check helper (used in tests to validate fill_block
//  produces internally-consistent cells before the constraint
//  evaluator lands).
// ═══════════════════════════════════════════════════════════════════

/// For tests: reconstruct the digest from the trace's H-state cells
/// at row `base + 81` (= H_k_LO + 2^32 · H_k_HI) for one block.
/// Returns the 8-word digest as u64.
pub fn read_digest_from_trace(trace: &[Vec<F>], base: usize) -> [u64; 8] {
    let row = base + NUM_ROUNDS + 1;     // 81
    core::array::from_fn(|k| {
        let lo_f = trace[OFF_H0_LO + 2*k    ][row];
        let hi_f = trace[OFF_H0_LO + 2*k + 1][row];
        // The trace cells are u32 values — read back as bigint mod p,
        // which equals the u32 value because u32 < p.
        let lo: u64 = field_to_u64(lo_f);
        let hi: u64 = field_to_u64(hi_f);
        lo | (hi << 32)
    })
}

/// Convert a Goldilocks element known to be < 2^32 back to u64 by
/// reading its canonical representative.  Trace cells representing
/// limb values fall in this range.
fn field_to_u64(x: F) -> u64 {
    use ark_ff::{BigInteger, PrimeField};
    let bi = x.into_bigint();
    bi.as_ref()[0]
}

// ═══════════════════════════════════════════════════════════════════
//  Tests — cross-check native impl against `sha2::Sha512`.
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha512};

    fn ref_sha512(msg: &[u8]) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(msg);
        let out = h.finalize();
        let mut a = [0u8; 64];
        a.copy_from_slice(&out);
        a
    }

    #[test]
    fn iv_matches_fips() {
        // Sanity: hashing the empty string under our padding should
        // match `sha2::Sha512` byte-for-byte.
        assert_eq!(sha512_native(b""), ref_sha512(b""));
    }

    #[test]
    fn one_block_messages() {
        // Messages whose padded length is exactly one 128-byte block.
        for msg in [b"".as_ref(), b"abc", b"hello world", &[0u8; 64], &[0xffu8; 100]] {
            assert_eq!(sha512_native(msg), ref_sha512(msg),
                "mismatch on len={}", msg.len());
        }
    }

    #[test]
    fn two_block_messages() {
        // Anything past 111 bytes spills into a second block.
        let m1 = vec![0xa5u8; 120];
        assert_eq!(sha512_native(&m1), ref_sha512(&m1));
        let m2 = vec![0x5au8; 200];
        assert_eq!(sha512_native(&m2), ref_sha512(&m2));
    }

    #[test]
    fn many_block_messages() {
        // Exercise the multi-block H-state chaining path used by the AIR.
        let m = (0..400).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        assert_eq!(sha512_native(&m), ref_sha512(&m));
        let m = (0..1024usize).map(|i| (i.wrapping_mul(31) % 257) as u8).collect::<Vec<_>>();
        assert_eq!(sha512_native(&m), ref_sha512(&m));
    }

    #[test]
    fn rfc6234_vector_abc() {
        // RFC 6234 §8.5: SHA-512("abc")
        let expected = hex::decode(
            "ddaf35a193617aba\
             cc417349ae204131\
             12e6fa4e89a97ea2\
             0a9eeee64b55d39a\
             2192992a274fc1a8\
             36ba3c23a3feebbd\
             454d4423643ce80e\
             2a9ac94fa54ca49f"
        ).unwrap();
        assert_eq!(&sha512_native(b"abc")[..], &expected[..]);
    }

    #[test]
    fn limb_roundtrip() {
        for x in [0u64, 1, 0xdeadbeef, 0xffff_ffff, 0x1_0000_0000,
                  0x1234_5678_9abc_def0, 0xffff_ffff_ffff_ffff] {
            let (lo, hi) = limbs(x);
            assert_eq!(from_limbs(lo, hi), x);
        }
    }

    #[test]
    fn sigma_functions_match_table() {
        // Smoke: verify our σ/Σ helpers roundtrip the FIPS test cases
        // implicitly (covered by the rfc6234 vector test above).
        // Standalone identity checks — sanity only.
        assert_eq!(big_sigma0(0), 0);
        assert_eq!(big_sigma1(0), 0);
        assert_eq!(small_sigma0(0), 0);
        assert_eq!(small_sigma1(0), 0);
        // ROTR is involutive after composing with its inverse.
        let x = 0x0123_4567_89ab_cdefu64;
        assert_eq!(rotr(rotr(x, 14), 64 - 14), x);
    }

    // ─────────────────────────────────────────────────────────────────
    //  AIR trace builder tests — verify cells land where expected and
    //  the digest reconstructed from H-state matches the native ref.
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn layout_offsets_are_consistent() {
        // Sanity: row width must equal the documented WIDTH constant.
        assert_eq!(WIDTH, 1510);
        assert_eq!(OFF_NE_HI_C, WIDTH - 1);
        // No two block-anchor offsets should collide.
        let anchors = [
            ("A_a_LO", A_a_LO), ("OFF_BIT_A", OFF_BIT_A),
            ("OFF_S0_T", OFF_S0_T), ("OFF_S0_LO", OFF_S0_LO),
            ("OFF_S1_T", OFF_S1_T), ("OFF_CH_BIT", OFF_CH_BIT),
            ("OFF_MAJ_AB", OFF_MAJ_AB), ("OFF_W_LO", OFF_W_LO),
            ("OFF_T1_LO_LO", OFF_T1_LO_LO), ("OFF_T2_LO_LO", OFF_T2_LO_LO),
            ("OFF_H0_LO", OFF_H0_LO), ("OFF_WW0_LO", OFF_WW0_LO),
            ("OFF_BIT_WW14", OFF_BIT_WW14), ("OFF_BIT_WW1", OFF_BIT_WW1),
            ("OFF_SS0_T", OFF_SS0_T), ("OFF_SS1_T", OFF_SS1_T),
            ("OFF_WS_LO_C0", OFF_WS_LO_C0), ("OFF_NA_LO_C", OFF_NA_LO_C),
        ];
        for (name, off) in anchors {
            assert!(off < WIDTH, "{} = {} ≥ WIDTH", name, off);
        }
    }

    #[test]
    fn single_block_trace_digest_matches_ref() {
        // Pad "abc" to one 128-byte block, build the trace, read the
        // digest out of the H-state cells at row 81, compare to the
        // native reference (which agrees with sha2::Sha512 by an
        // earlier test).
        let blocks = pad_message_to_blocks(b"abc");
        assert_eq!(blocks.len(), 1);
        let trace = build_sha512_trace(&blocks[0]);
        assert_eq!(trace.len(), WIDTH);
        assert_eq!(trace[0].len(), N_TRACE);
        let got = read_digest_from_trace(&trace, /* base = */ 0);
        let want = sha512_one_block(&blocks[0]);
        assert_eq!(got, want, "trace H-state digest != native digest");
    }

    #[test]
    fn multi_block_trace_digest_matches_ref() {
        // Two-block message (200 bytes pads into two blocks).
        let m = vec![0x5au8; 200];
        let (trace, n_blocks) = build_sha512_trace_multi(&m);
        assert_eq!(n_blocks, 2);
        // The last block's digest sits at row (n_blocks-1)·ROWS_PER_BLOCK + 81.
        let base = (n_blocks - 1) * ROWS_PER_BLOCK;
        let got = read_digest_from_trace(&trace, base);
        // Reference: native multi-block compression chained from IV.
        let mut h = IV;
        for block in pad_message_to_blocks(&m) {
            let post = compress_block_native(&block, h);
            for k in 0..8 { h[k] = h[k].wrapping_add(post[k]); }
        }
        assert_eq!(got, h);
    }

    #[test]
    fn trace_cells_are_valid_field_elements() {
        // Every trace cell ought to be reduced; a u32-valued limb
        // round-trips through field_to_u64 to its u32 value.
        let blocks = pad_message_to_blocks(b"hello stark world");
        let trace = build_sha512_trace(&blocks[0]);
        for col in [A_a_LO, A_h_HI, OFF_W_LO, OFF_W_HI,
                    OFF_S0_LO, OFF_S0_HI, OFF_T1_LO_LO, OFF_T1_HI_LO,
                    OFF_H0_LO, OFF_H0_LO + 15] {
            for r in 0..N_TRACE {
                let v = field_to_u64(trace[col][r]);
                assert!(v < (1u64 << 32),
                    "limb cell col={} row={} = {} ≥ 2^32", col, r, v);
            }
        }
    }

    #[test]
    fn trace_bit_cells_are_boolean() {
        // Bit cells should hold 0 or 1 after fill_block; this is the
        // pre-condition for the booleanity transition constraint.
        let blocks = pad_message_to_blocks(b"abc");
        let trace = build_sha512_trace(&blocks[0]);
        for off in [OFF_BIT_A, OFF_BIT_B, OFF_BIT_C,
                    OFF_BIT_E, OFF_BIT_F, OFF_BIT_G,
                    OFF_BIT_WW14, OFF_BIT_WW1,
                    OFF_S0_T, OFF_S0_BIT, OFF_S1_T, OFF_S1_BIT,
                    OFF_CH_BIT, OFF_MAJ_AB, OFF_MAJ_AC, OFF_MAJ_BC,
                    OFF_MAJ_U, OFF_MAJ_BIT,
                    OFF_SS0_T, OFF_SS0_BIT, OFF_SS1_T, OFF_SS1_BIT] {
            for i in 0..64 {
                for r in 0..N_TRACE {
                    let v = field_to_u64(trace[off + i][r]);
                    assert!(v <= 1, "non-boolean cell off={}+{} row={} val={}",
                        off, i, r, v);
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //  Constraint evaluator self-consistency tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_trace_satisfies_constraints(trace: &[Vec<F>], n_blocks: usize) {
        let h = trace[0].len();
        let mut nonzero_rows = Vec::new();
        for r in 0..h {
            let nxt_idx = (r + 1) % h;
            let cur: Vec<F> = (0..WIDTH).map(|c| trace[c][r]).collect();
            let nxt: Vec<F> = (0..WIDTH).map(|c| trace[c][nxt_idx]).collect();
            let cvals = eval_sha512_constraints(&cur, &nxt, r, n_blocks);
            assert_eq!(cvals.len(), NUM_CONSTRAINTS,
                "constraint vector length mismatch at row {}", r);
            for (i, v) in cvals.iter().enumerate() {
                if !v.is_zero() {
                    nonzero_rows.push((r, i, *v));
                }
            }
        }
        // Per the SHA-256 framework convention, the cyclic wrap row
        // (h-1) → 0 may not satisfy every constraint (digest at last
        // useful row vs IV/zero at row 0 across blocks).  We accept
        // failures only on the wrap row for the same reason; all
        // non-wrap rows must satisfy every constraint exactly.
        let wrap_row = h - 1;
        let problem: Vec<_> = nonzero_rows.iter()
            .filter(|(r, _, _)| *r != wrap_row)
            .collect();
        assert!(problem.is_empty(),
            "non-wrap-row constraint violations:\n{}",
            problem.iter().take(10).map(|(r, i, v)| {
                format!("  row {}, cons #{}: value = {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn empty_trace_satisfies_constraints() {
        // Single-block hash of the empty string.  All transition rows
        // (0..N_TRACE-2) should produce zero constraint vectors.
        let blocks = pad_message_to_blocks(b"");
        let trace = build_sha512_trace(&blocks[0]);
        assert_trace_satisfies_constraints(&trace, 1);
    }

    #[test]
    fn abc_trace_satisfies_constraints() {
        // Single-block hash of "abc" (RFC 6234 vector).
        let blocks = pad_message_to_blocks(b"abc");
        let trace = build_sha512_trace(&blocks[0]);
        assert_trace_satisfies_constraints(&trace, 1);
    }

    #[test]
    fn multi_block_trace_satisfies_constraints() {
        // Two-block message — exercises H-state chaining at the block
        // boundary (row 127 of block 0 → row 0 of block 1).
        let m = vec![0x5au8; 200];
        let (trace, n_blocks) = build_sha512_trace_multi(&m);
        assert_eq!(n_blocks, 2);
        assert_trace_satisfies_constraints(&trace, n_blocks);
    }

    #[test]
    fn tampered_message_fails_constraints() {
        // Build a valid trace, flip one bit of the working state at a
        // mid-compression row, expect constraint violations.
        let blocks = pad_message_to_blocks(b"abc");
        let mut trace = build_sha512_trace(&blocks[0]);
        // Flip a bit cell at a compression row.
        let target_col = OFF_BIT_A + 5;
        let target_row = 30;
        let original = trace[target_col][target_row];
        trace[target_col][target_row] = if original.is_zero() {
            F::one()
        } else {
            F::zero()
        };
        // Expect at least one non-zero constraint at the target row OR
        // an adjacent row (since shifts and packs both fire).
        let mut found_violation = false;
        for r in target_row.saturating_sub(1)..=target_row + 1 {
            if r >= trace[0].len() - 1 { break; }
            let cur: Vec<F> = (0..WIDTH).map(|c| trace[c][r]).collect();
            let nxt: Vec<F> = (0..WIDTH).map(|c| trace[c][r + 1]).collect();
            let cvals = eval_sha512_constraints(&cur, &nxt, r, 1);
            if cvals.iter().any(|v| !v.is_zero()) {
                found_violation = true;
                break;
            }
        }
        assert!(found_violation,
            "tampering with bit cell did not produce a constraint violation");
    }
}
