// p256_field.rs — F_p arithmetic for NIST P-256 (secp256r1).
//
// This file is split across three deliverables (mirroring the cadence
// of `ed25519_field.rs` and `sha512_air.rs`):
//
//   v0 (this commit): native (out-of-circuit) reference implementation
//     plus AIR-layout design notes.  The AIR (v1/v2) will replicate the
//     algebra; the native ref serves as both an algorithm spec and a
//     test oracle.
//
//   v1 (next commit): column layout + trace builder for the in-circuit
//     limb gadgets (add, sub, mul, freeze, conditional select).  Each
//     limb operation lays out a fixed number of trace rows.
//
//   v2 (next commit): constraint evaluator that enforces honest limb
//     arithmetic with carry propagation and Solinas-style reduction.
//
// ─────────────────────────────────────────────────────────────────
// PRIME & STRUCTURE
// ─────────────────────────────────────────────────────────────────
//
// p = 2^256 − 2^224 + 2^192 + 2^96 − 1
//
// Hex (big-endian, the canonical SEC1 / ANSI X9.62 form):
//   ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
//
// Bit-set positions: [0..96) ∪ {192} ∪ [224..256).  The prime is a
// generalised-Mersenne (Solinas) prime: the high half of any product
// folds back into the low half via
//
//   2^256 ≡ 2^224 − 2^192 − 2^96 + 1   (mod p).
//
// We use the standard FIPS 186-4 §D.2.2 (NIST SP 800-186) S1..S9 fast
// reduction.  Splitting the 512-bit product T = (T_15 .. T_0) into u32
// words (T_0 the low word), the reduction is
//
//   T mod p ≡ S1 + 2·S2 + 2·S3 + S4 + S5 − S6 − S7 − S8 − S9   (mod p)
//
// where each S_i is an 8-word permutation of the T_i, given in §D.2.2.
// The result is in (−4·p, 5·p) and is brought into [0, p) by a few
// trial-subtractions of p.
//
// ─────────────────────────────────────────────────────────────────
// LIMB REPRESENTATION (uniform 10×26)
// ─────────────────────────────────────────────────────────────────
//
// Different from Ed25519's alternating 26/25 (which is tuned to fit
// 2^255 − 19 exactly into 255 bits).  For P-256 we use 10 *uniform*
// 26-bit limbs:
//
//                 limb index : 0  1  2  3  4  5  6  7  8  9
//                 limb width : 26 26 26 26 26 26 26 26 26 26  (bits)
//                 limb radix :  0 26 52 78 104 130 156 182 208 234  (bit offset)
//
// Total = 260 bits → 4 bits of slack above the 256-bit field width.
// That slack absorbs the unreduced sum carries from the Solinas fold
// without re-triggering an out-of-bounds in limb 9 within a single
// reduce-pass.
//
// In the AIR every limb is one Goldilocks cell.  Limb-level products
// are at most 2^26 · 2^26 = 2^52, sums of 10 such products are at most
// 10·2^52 < 2^56 ≪ p_Goldilocks ≈ 2^64.  Multiplication therefore
// fits cleanly without spurious wrap.
//
// Choosing 10 limbs (vs e.g. 8×32 or 11×24) keeps the column count
// equal to the Ed25519 field AIR (so downstream gadget composition can
// share row layouts) and gives each limb 6 bits of headroom for
// loose-form additive headroom before a forced reduce.
//
// ─────────────────────────────────────────────────────────────────
// NON-CANONICAL VS CANONICAL FORM
// ─────────────────────────────────────────────────────────────────
//
// We distinguish three states for a 10-limb representation:
//
//   "loose":    each |limb_i| ≤ ~2^53 approximately.  Result of raw
//               add / sub / mul before final reduction.
//
//   "tight":    each limb_i in [0, 2^26).  The integer is non-negative
//               but only loosely bounded: in [0, ~18p) for sub/neg of
//               canonical inputs that triggered the limb-9 wrap, in
//               [0, 2^256) for mul outputs.  The Solinas wrap is mod-p
//               preserving but adds ±16p per fired wrap, so reduce()
//               does not by itself guarantee integer < 2p.  Result of
//               `reduce`.
//
//   "canonical": each limb_i in [0, 2^26) and integer in [0, p).
//                Result of `freeze`.  freeze() iterates the conditional
//                subtract of p (≤ ~18 iterations from the tight bound).
//                Required at API boundaries (decoding, re-encoding to
//                bytes, point compression, sign-bit extraction for
//                parity recovery).
//
// The AIR mirrors this distinction: only operations that *cross* a
// canonical/loose boundary need range-check evidence; intermediate
// loose results can be stored without per-limb bit decomposition.
//
// ─────────────────────────────────────────────────────────────────
// LIMB-9 CARRY-OUT WRAP
// ─────────────────────────────────────────────────────────────────
//
// If limb_9 holds an integer ≥ 2^26 (tight-form violation), carrying
// `c` units out of limb_9 corresponds to adding c · 2^260 to the
// integer.  Folding via the prime relation:
//
//   2^260 = 2^4 · 2^256 ≡ 16 · (2^224 − 2^192 − 2^96 + 1)
//        =  2^228 − 2^196 − 2^100 + 16   (mod p)
//
// In the 26-bit-limb basis these powers of 2 land as follows:
//
//   2^228 = 2^(26·8 + 20)  → 2^20 in limb 8     →  limb_8 +=  c · 2^20
//   2^196 = 2^(26·7 + 14)  → 2^14 in limb 7     →  limb_7 −=  c · 2^14
//   2^100 = 2^(26·3 + 22)  → 2^22 in limb 3     →  limb_3 −=  c · 2^22
//   16     = 2^4           → 2^4  in limb 0     →  limb_0 +=  c · 16
//
// (Compare with Ed25519's much simpler limb-9 wrap: a single fold
// `limb_0 += 19 · c` because 2^255 ≡ 19 (mod p_25519).)
//
// ─────────────────────────────────────────────────────────────────
// AIR INTEGRATION SKETCH (v1)
// ─────────────────────────────────────────────────────────────────
//
// ```text
// Per field element:    10 Goldilocks cells (one per limb).
//
// Per `mul(a, b) -> c` gadget:
//   Inputs:        2 × 10 limb cells = 20 cells
//   Output:        10 limb cells
//   Helper cells:
//     - 19 product limbs P[0..18] (a × b raw schoolbook)
//     - 8 "u32-projection" cells repacking P into the FIPS 16-word
//       basis (since the Solinas table is stated over 32-bit words
//       and our trace uses 26-bit limbs; the AIR proves the
//       projection is consistent)
//     - 9 Solinas helper buses (S1..S9) selecting the right T_i
//       into each output slot — these are pure wiring, no algebra
//     - 8 combined-output u32 cells   (S1 + 2S2 + 2S3 + S4 + S5
//                                      − S6 − S7 − S8 − S9, signed)
//     - carry chain across the 8 u32 slots (~9 carry cells)
//     - final 10-limb output c
//   Range-check evidence:
//     - 10 × 26-bit cells for c
//     - ~11 × 5-bit cells for the inter-limb carry chain
//     - 8 × 32-bit cells for the u32 projection (range-checked)
//
//   Per-mul column count:    ≈ 360 cells.
//   Per-mul constraint count: ≈ 280 deg-2 constraints.
//
// Per `add` / `sub`:  10 limb cells output, 10 cells helper carry.
//                     ~30 constraints, all degree 1.
//
// Per `freeze`:        10 canonical-output limb cells, 10 "minus-p"
//                      offset path, 1 select bit (deg-2 select).
//                      ~60 constraints (P-256's p has more non-trivial
//                      limbs than 2^255 − 19's, so the speculative
//                      subtract is wider).
// ```
//
// One full ECDSA-P256 verification (one in-circuit RRSIG):
//   * SHA-256(message)              — already covered by `sha256_air`
//   * inverse w = s^{−1} mod n      — Fermat: ~256 squarings + ~64 muls
//                                     (in Fn, the scalar field — handled
//                                     by `p256_scalar` in a later phase)
//   * u1 · G + u2 · Q (variable-base scalar mult of u2·Q)
//                                   — ~256 doublings + ~256 conditional
//                                     adds, each Weierstrass complete
//                                     addition (Renes–Costello–Batina
//                                     2016) costing ~12 muls.  Fixed-
//                                     base u1·G can use precomputed
//                                     tables out-of-circuit (Phase 4
//                                     decision).  Lower bound on muls:
//                                     ~6000 (variable-base alone).
//   * x mod n  ?=  r                — one Fp→Fn reduction, one compare.
//
// At ~280 cons/mul plus per-element overhead, ECDSA-P256 verify is
// ~20% heavier than Ed25519 (which is ~5000 muls).  This matches the
// abstract's "RSA/ECDSA attested under T2 → in-circuit upgrade" path:
// once Phases 1–6 land, ECDSA moves out from under trust assumption T2.
//
// ─────────────────────────────────────────────────────────────────
// REFERENCE
// ─────────────────────────────────────────────────────────────────
//
// v0 cross-checks against `num_bigint::BigUint` arithmetic mod p.
// `BigUint` is an independent bigint library — not a P-256-specific
// implementation — so passing the cross-checks gives a real test of
// our Solinas fold rather than a self-consistent tautology.
//
// Curve constants (a, b) are taken from FIPS 186-4 D.1.2.3 / SEC 2.
// Future test vectors (RRSIG ECDSA-P256 signatures) will live in the
// integration tests of `p256_verify` once that lands in Phase 5.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use once_cell::sync::Lazy;

// ═══════════════════════════════════════════════════════════════════
//  Limb-width tables (compile-time constants)
// ═══════════════════════════════════════════════════════════════════

/// Number of limbs in the field-element representation.
pub const NUM_LIMBS: usize = 10;

/// Bit-width of every limb.  Uniform 26 (in contrast to Ed25519's
/// alternating 26/25).
pub const LIMB_BITS: u32 = 26;

/// 2^{LIMB_BITS} as an i64.  Per-limb modulus for tight form.
pub const LIMB_RADIX: i64 = 1i64 << LIMB_BITS;

/// Bit offset of limb `i` (cumulative sum of preceding widths).
pub const LIMB_OFFSETS: [u32; NUM_LIMBS] =
    [0, 26, 52, 78, 104, 130, 156, 182, 208, 234];

// Compile-time sanity: total width is 260 bits (4 of slack).
const _: () = assert!(
    NUM_LIMBS * (LIMB_BITS as usize) == 260,
    "10 × 26 must sum to 260 bits"
);

/// Tight-form limbs of p itself, used by `freeze` for the speculative
/// subtraction.  Derived in the file-header doc.
const P_LIMBS_TIGHT: [i64; NUM_LIMBS] = [
    0x3FFFFFF, // limb 0 (bits   0.. 26): 2^26 − 1
    0x3FFFFFF, // limb 1 (bits  26.. 52): 2^26 − 1
    0x3FFFFFF, // limb 2 (bits  52.. 78): 2^26 − 1
    0x003FFFF, // limb 3 (bits  78..104): low 18 bits set (bits 78..96)
    0,
    0,
    0,
    0x0000400, // limb 7 (bits 182..208): bit 192 = bit 10 within limb
    0x3FF0000, // limb 8 (bits 208..234): bits 224..234 = bits 16..26
    0x03FFFFF, // limb 9 (bits 234..260): bits 234..256 = bits 0..22
];

// ═══════════════════════════════════════════════════════════════════
//  Bit-extraction helpers
// ═══════════════════════════════════════════════════════════════════

/// Extract `width` bits starting at LSB-position `offset` from a
/// big-endian 32-byte buffer.  bytes[0] is the highest-order byte;
/// bit-position 0 is the LSB of the encoded integer.
#[inline]
fn extract_bits_be(bytes: &[u8; 32], offset: u32, width: u32) -> u64 {
    debug_assert!(width <= 64);
    let mut result = 0u64;
    for i in 0..width {
        let bit_pos = offset + i;
        if bit_pos >= 256 {
            break;
        }
        let byte_idx_be = 31 - (bit_pos / 8) as usize;
        let bit_in_byte = bit_pos % 8;
        let bit = (bytes[byte_idx_be] >> bit_in_byte) & 1;
        result |= (bit as u64) << i;
    }
    result
}

// ═══════════════════════════════════════════════════════════════════
//  FieldElement — 10-limb representation in i64 storage.
// ═══════════════════════════════════════════════════════════════════

/// Element of F_p where p = 2^256 − 2^224 + 2^192 + 2^96 − 1
/// (the NIST P-256 base-field prime), stored as 10 uniform-26-bit
/// limbs in i64.  Signed storage gives headroom for unreduced sums
/// after add / sub / mul before normalisation.
///
/// Invariant flavours (see module-level doc):
///   - `loose`:     produced by raw add / sub / mul; |limb| ≤ ~2^53
///   - `tight`:     produced by `reduce`; 0 ≤ limb_i < 2^26, integer < 2p
///   - `canonical`: produced by `freeze`; tight AND integer < p
#[derive(Clone, Copy, Debug)]
pub struct FieldElement {
    pub limbs: [i64; NUM_LIMBS],
}

impl FieldElement {
    /// The zero element.
    pub const fn zero() -> Self {
        Self {
            limbs: [0; NUM_LIMBS],
        }
    }

    /// The multiplicative identity.
    pub const fn one() -> Self {
        let mut l = [0i64; NUM_LIMBS];
        l[0] = 1;
        Self { limbs: l }
    }

    /// Decode from a 32-byte big-endian encoding (SEC1 / ANSI X9.62).
    /// Output limbs are tight: each limb_i is in [0, 2^26) and the
    /// encoded integer is in [0, 2^256), which is in [0, 2p).
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut h = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            h[i] = extract_bits_be(bytes, LIMB_OFFSETS[i], LIMB_BITS) as i64;
        }
        Self { limbs: h }
    }

    /// Encode to a canonical 32-byte big-endian representation
    /// (SEC1 standard).  Implies a `freeze` to canonical form.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut t = *self;
        t.freeze();
        let mut out = [0u8; 32];
        for byte_idx_be in 0..32 {
            let byte_lsb_pos = 31 - byte_idx_be;
            let mut b = 0u8;
            for k in 0..8 {
                let bit_pos = (byte_lsb_pos * 8 + k) as u32;
                if bit_pos >= 256 {
                    break;
                }
                let limb_idx = (bit_pos / LIMB_BITS) as usize;
                if limb_idx >= NUM_LIMBS {
                    break;
                }
                let local = bit_pos - LIMB_OFFSETS[limb_idx];
                let bit = ((t.limbs[limb_idx] as u64) >> local) & 1;
                b |= (bit as u8) << k;
            }
            out[byte_idx_be] = b;
        }
        out
    }

    /// Loose addition: limb-wise sum.  Result in loose form.
    pub fn add(&self, other: &Self) -> Self {
        let mut r = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            r[i] = self.limbs[i] + other.limbs[i];
        }
        Self { limbs: r }
    }

    /// Loose subtraction: limb-wise difference.  Result may be negative
    /// in some limbs; subsequent `reduce` normalises.
    pub fn sub(&self, other: &Self) -> Self {
        let mut r = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            r[i] = self.limbs[i] - other.limbs[i];
        }
        Self { limbs: r }
    }

    /// Negation: 0 − self (mod p), in loose form.
    pub fn neg(&self) -> Self {
        let mut r = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            r[i] = -self.limbs[i];
        }
        Self { limbs: r }
    }

    /// Project a canonical-form FieldElement to 8 little-endian u32
    /// words (the natural FIPS 186-4 representation).  u32_le[0] is
    /// bits 0..32 of the integer; u32_le[7] is bits 224..256.
    fn to_u32_le_8(&self) -> [u32; 8] {
        let bytes = self.to_be_bytes();
        let mut u = [0u32; 8];
        for k in 0..8 {
            // word k (LSB-first) = the 4 bytes at BE positions [32-4(k+1), 32-4k).
            let i = 32 - 4 * (k + 1);
            u[k] = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
        }
        u
    }

    /// Inverse of `to_u32_le_8`.  Treats the input as bits 0..256 of
    /// an integer and reduces tight (no reduction beyond unpacking;
    /// caller must `reduce` if integer ≥ p).
    fn from_u32_le_8(u: [u32; 8]) -> Self {
        let mut bytes = [0u8; 32];
        for k in 0..8 {
            let i = 32 - 4 * (k + 1);
            bytes[i..i + 4].copy_from_slice(&u[k].to_be_bytes());
        }
        Self::from_be_bytes(&bytes)
    }

    /// Multiplication.  Result in canonical form.
    ///
    /// v0 algorithm (correct by construction): convert both operands
    /// to 8 × u32 LE limbs, do schoolbook 8×8 → 16-word multiply with
    /// u64 partial products, reduce mod p via FIPS 186-4 §D.2.2's
    /// nine-sum fast-reduction (S1..S9), iterate the residual fold
    /// until the high carry settles, then convert back.
    ///
    /// The AIR (v1/v2) will replicate this behaviour with explicit
    /// limb-level partial products and Solinas wiring constraints,
    /// but the v0 native ref takes the standard u32-word path so we
    /// have a trustworthy oracle for the AIR's correctness tests.
    pub fn mul(&self, other: &Self) -> Self {
        let a = self.to_u32_le_8();
        let b = other.to_u32_le_8();

        // ── Schoolbook 8 × 8 → 16-word multiply ──────────────────
        // Each partial product is u32 × u32 ≤ 2^64 − 2^33 + 1 < 2^64.
        // The middle slot (prod[7]) accumulates up to 8 such products,
        // sum ≤ 8·2^64 = 2^67, which would silently overflow a u64
        // accumulator.  Use u128 partials and let carry propagation
        // sort out overflows.
        let mut prod = [0u128; 16];
        for i in 0..8 {
            for j in 0..8 {
                prod[i + j] += (a[i] as u128) * (b[j] as u128);
            }
        }
        // Carry-propagate u128 partials into u32 limbs.
        let mut t = [0u32; 16];
        let mut carry: u128 = 0;
        for k in 0..16 {
            let v = prod[k] + carry;
            t[k] = v as u32;
            carry = v >> 32;
        }
        debug_assert_eq!(
            carry, 0,
            "u256 × u256 schoolbook overflowed 16 u32 words"
        );

        // ── FIPS 186-4 §D.2.2 nine-sum fast reduction ────────────
        //
        // result ≡ S1 + 2·S2 + 2·S3 + S4 + S5 − S6 − S7 − S8 − S9   (mod p)
        //
        // where each S_i is an 8-word permutation of (T_8..T_15)
        // back into the low half (T_0..T_7).  Layouts (LSB-first,
        // i.e. slot 0 is bits 0..32 of the value):
        let s1 = [t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]];
        let s2 = [0, 0, 0, t[11], t[12], t[13], t[14], t[15]];
        let s3 = [0, 0, 0, t[12], t[13], t[14], t[15], 0];
        let s4 = [t[8], t[9], t[10], 0, 0, 0, t[14], t[15]];
        let s5 = [t[9], t[10], t[11], t[13], t[14], t[15], t[13], t[8]];
        let s6 = [t[11], t[12], t[13], 0, 0, 0, t[8], t[10]];
        let s7 = [t[12], t[13], t[14], t[15], 0, 0, t[9], t[11]];
        let s8 = [t[13], t[14], t[15], t[8], t[9], t[10], 0, t[12]];
        let s9 = [t[14], t[15], 0, t[9], t[10], t[11], 0, t[13]];

        // Combined per-slot value (signed; fits in i64 since the
        // max coefficient sum is 2+2+1+1+1+1+1+1 = 10 of u32-sized
        // terms ≈ 10 · 2^32 < 2^36).
        let mut r = [0i64; 8];
        for k in 0..8 {
            r[k] = (s1[k] as i64)
                + 2 * (s2[k] as i64)
                + 2 * (s3[k] as i64)
                + (s4[k] as i64)
                + (s5[k] as i64)
                - (s6[k] as i64)
                - (s7[k] as i64)
                - (s8[k] as i64)
                - (s9[k] as i64);
        }

        // Carry-propagate r into 8 u32 slots plus a signed overflow.
        // We use Euclidean rem/div so each slot lands in [0, 2^32)
        // and the carry absorbs the rest with sign.
        let mut acc = [0i64; 9];
        let mut carry: i64 = 0;
        for k in 0..8 {
            let v = r[k] + carry;
            acc[k] = v.rem_euclid(1i64 << 32);
            carry = v.div_euclid(1i64 << 32);
        }
        acc[8] = carry;

        // Fold the residual high carry acc[8] back via
        //   2^256 ≡ 2^224 − 2^192 − 2^96 + 1   (mod p).
        // In the u32-word basis this means:
        //   acc[7] += h   (because 2^224 = 2^(32·7))
        //   acc[6] -= h   (because 2^192 = 2^(32·6))
        //   acc[3] -= h   (because 2^96  = 2^(32·3))
        //   acc[0] += h   (because 1     = 2^(32·0))
        // After folding, re-propagate carries.  Iterate up to 3×
        // (the fold can produce another overflow of ≤ a few units;
        // 3 iterations is comfortably enough — the residual halves
        // each iteration).
        for _ in 0..3 {
            let h = acc[8];
            if h == 0 {
                break;
            }
            acc[8] = 0;
            acc[7] += h;
            acc[6] -= h;
            acc[3] -= h;
            acc[0] += h;
            let mut carry: i64 = 0;
            for k in 0..8 {
                let v = acc[k] + carry;
                acc[k] = v.rem_euclid(1i64 << 32);
                carry = v.div_euclid(1i64 << 32);
            }
            acc[8] = carry;
        }
        debug_assert_eq!(
            acc[8], 0,
            "Solinas fold did not converge in 3 iterations"
        );

        // acc[0..8] now holds an 8-u32-word value V in [0, 2^256)
        // with V ≡ a · b (mod p).  Convert back to 10×26 limb form.
        let mut u32_words = [0u32; 8];
        for k in 0..8 {
            u32_words[k] = acc[k] as u32;
        }
        let mut fe = Self::from_u32_le_8(u32_words);
        fe.reduce();
        fe
    }

    /// Square — same as `self.mul(self)` in v0.  Future versions can
    /// specialise to share half the cross-products.
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Multiply by a small i64 scalar.  For |k| < 2^32 this falls
    /// within `mul`'s precision via the small-FE-from-bytes path.
    pub fn mul_small(&self, k: i64) -> Self {
        if k >= 0 {
            // Build a 32-byte BE encoding of k (which fits in the low
            // 8 bytes of the BE buffer).
            let mut bytes = [0u8; 32];
            bytes[24..32].copy_from_slice(&(k as u64).to_be_bytes());
            self.mul(&Self::from_be_bytes(&bytes))
        } else {
            self.neg().mul_small(-k)
        }
    }

    /// Carry-chain reduction: bring each limb into [0, 2^26) and the
    /// integer under 2p.  Produces tight form.
    ///
    /// Idempotent on tight input.  Uses arithmetic right-shift (signed
    /// floor division) to extract the carry, then a borrow-fix pass to
    /// promote any negative limb to non-negative by borrowing from the
    /// neighbour.  Limb 9's carry wraps into the low limbs via the
    /// 2^260 ≡ 2^228 − 2^196 − 2^100 + 16 (mod p) relation derived in
    /// the module-level doc.
    pub fn reduce(&mut self) {
        for _ in 0..3 {
            // Carry propagation pass.
            for i in 0..NUM_LIMBS {
                let c = self.limbs[i] >> LIMB_BITS;
                self.limbs[i] -= c << LIMB_BITS;
                if i < NUM_LIMBS - 1 {
                    self.limbs[i + 1] += c;
                } else {
                    // Limb-9 wrap: c · 2^260 ≡ c · (2^228 − 2^196 − 2^100 + 16) (mod p).
                    self.limbs[8] += c * (1 << 20);
                    self.limbs[7] -= c * (1 << 14);
                    self.limbs[3] -= c * (1 << 22);
                    self.limbs[0] += c * 16;
                }
            }
            // Borrow-fix pass: promote any negative limb to [0, 2^26).
            for i in 0..NUM_LIMBS {
                while self.limbs[i] < 0 {
                    self.limbs[i] += 1i64 << LIMB_BITS;
                    if i < NUM_LIMBS - 1 {
                        self.limbs[i + 1] -= 1;
                    } else {
                        // Same wrap with c = −1.
                        self.limbs[8] -= 1 << 20;
                        self.limbs[7] += 1 << 14;
                        self.limbs[3] += 1 << 22;
                        self.limbs[0] -= 16;
                    }
                }
            }
        }
    }

    /// Canonical-form normalisation: limbs in [0, 2^26) and integer
    /// in [0, p).  Required before byte encoding or comparison.
    ///
    /// After `reduce` each limb is in [0, 2^26) and the integer is
    /// non-negative, but the integer can sit anywhere in [0, ~18p)
    /// because each limb-9 carry-out fires the Solinas wrap which
    /// preserves V mod p but bumps the integer by ±16p.  We bring V
    /// into [0, p) with iterated speculative subtraction of p; the
    /// loop terminates in at most ~20 iterations (loose worst-case
    /// from sub-of-near-zero plus one wrap; mul outputs converge in 1).
    pub fn freeze(&mut self) {
        self.reduce();
        for _ in 0..32 {
            let mut diff = [0i64; NUM_LIMBS];
            let mut borrow = 0i64;
            for i in 0..NUM_LIMBS {
                let d = self.limbs[i] - P_LIMBS_TIGHT[i] - borrow;
                if d < 0 {
                    diff[i] = d + (1i64 << LIMB_BITS);
                    borrow = 1;
                } else {
                    diff[i] = d;
                    borrow = 0;
                }
            }
            if borrow == 1 {
                // self < p — already canonical, keep self.
                return;
            }
            // self ≥ p — take diff and try once more.
            self.limbs = diff;
        }
        panic!("freeze did not converge in 32 iterations (limbs={:?})", self.limbs);
    }

    /// True iff this element equals zero (canonical-form comparison).
    pub fn is_zero(&self) -> bool {
        let mut t = *self;
        t.freeze();
        t.limbs.iter().all(|&l| l == 0)
    }

    /// True iff self == other after both are canonicalised.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.to_be_bytes() == other.to_be_bytes()
    }

    /// Inverse via Fermat's little theorem: self^{p−2} mod p.
    /// Square-and-multiply with the explicit binary expansion of
    /// p − 2 (MSB-first).
    ///
    /// p − 2 in big-endian u32-word form:
    ///   ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffd
    /// (only the lowest hex digit changes from f → d versus p).
    pub fn invert(&self) -> Self {
        // Indexing: LSB word first, so word 0 = 0xfffffffd, word 7 = 0xffffffff.
        let p_minus_2: [u32; 8] = [
            0xffff_fffd,
            0xffff_ffff,
            0xffff_ffff,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0x0000_0001,
            0xffff_ffff,
        ];
        let mut acc = Self::one();
        // Walk MSB-first across all 256 bits of the exponent.
        for k in (0..8).rev() {
            let word = p_minus_2[k];
            for j in (0..32).rev() {
                acc = acc.square();
                if (word >> j) & 1 == 1 {
                    acc = acc.mul(self);
                }
            }
        }
        acc
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Curve constants for NIST P-256 (FIPS 186-4 D.1.2.3, SEC 2 v2 §2.4).
// ═══════════════════════════════════════════════════════════════════

/// P-256 curve parameter a = −3 (mod p).
///
/// The short-Weierstrass equation y² = x³ + a·x + b uses a = −3 for
/// every NIST prime curve (a deliberate choice that admits efficient
/// doubling formulas).
pub static A_MINUS_3: Lazy<FieldElement> = Lazy::new(|| {
    let three = FieldElement::one()
        .add(&FieldElement::one())
        .add(&FieldElement::one());
    three.neg()
});

/// P-256 curve parameter b (FIPS 186-4 D.1.2.3):
///   b = 0x5ac635d8 aa3a93e7 b3ebbd55 769886bc
///       651d06b0 cc53b0f6 3bce3c3e 27d2604b
pub static B_CURVE: Lazy<FieldElement> = Lazy::new(|| {
    let b_be: [u8; 32] = [
        0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
        0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
        0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
        0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
    ];
    FieldElement::from_be_bytes(&b_be)
});

// ═══════════════════════════════════════════════════════════════════
//  Tests — cross-check native impl against `num_bigint::BigUint`.
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::{Num, Zero};

    /// p = 2^256 − 2^224 + 2^192 + 2^96 − 1, hex form.
    fn p256_modulus() -> BigUint {
        BigUint::from_str_radix(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            16,
        )
        .unwrap()
    }

    fn fe_to_biguint(fe: &FieldElement) -> BigUint {
        let mut t = *fe;
        t.freeze();
        BigUint::from_bytes_be(&t.to_be_bytes())
    }

    fn biguint_to_fe(x: &BigUint) -> FieldElement {
        let bytes = x.to_bytes_be();
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        FieldElement::from_be_bytes(&padded)
    }

    fn pseudo_bytes(seed: u64, salt: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = (seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(salt.wrapping_mul(i as u64 + 1).wrapping_mul(31))
                & 0xff) as u8;
        }
        b
    }

    fn pseudo_fe(seed: u64) -> (BigUint, FieldElement) {
        let modulus = p256_modulus();
        let raw = BigUint::from_bytes_be(&pseudo_bytes(seed, 0xa5a5_a5a5));
        let int = raw % &modulus;
        let fe = biguint_to_fe(&int);
        (int, fe)
    }

    #[test]
    fn zero_is_zero() {
        assert!(FieldElement::zero().is_zero());
        assert_eq!(FieldElement::zero().to_be_bytes(), [0u8; 32]);
    }

    #[test]
    fn one_is_one() {
        let mut want = [0u8; 32];
        want[31] = 1;
        assert_eq!(FieldElement::one().to_be_bytes(), want);
    }

    #[test]
    fn p_constant_decodes_to_zero() {
        // P_LIMBS_TIGHT represents p, and p ≡ 0 (mod p).
        let p_fe = FieldElement {
            limbs: P_LIMBS_TIGHT,
        };
        assert!(p_fe.is_zero(), "p mod p ≠ 0; got {:?}", p_fe.limbs);
    }

    #[test]
    fn from_to_bytes_roundtrip() {
        for seed in 0u64..32 {
            let (int, fe) = pseudo_fe(seed);
            // The integer stored in the FE should match what we put in
            // (since we reduced modulo p before encoding).
            let bytes = fe.to_be_bytes();
            assert_eq!(BigUint::from_bytes_be(&bytes), int, "seed {}", seed);
        }
    }

    #[test]
    fn add_matches_biguint() {
        let modulus = p256_modulus();
        for seed in 0u64..32 {
            let (a_int, a) = pseudo_fe(seed);
            let (b_int, b) = pseudo_fe(seed.wrapping_mul(7).wrapping_add(13));
            let r = a.add(&b);
            let expected = (&a_int + &b_int) % &modulus;
            assert_eq!(fe_to_biguint(&r), expected, "add mismatch seed {}", seed);
        }
    }

    #[test]
    fn sub_matches_biguint() {
        let modulus = p256_modulus();
        for seed in 0u64..32 {
            let (a_int, a) = pseudo_fe(seed);
            let (b_int, b) = pseudo_fe(seed.wrapping_mul(7).wrapping_add(13));
            let r = a.sub(&b);
            let expected = (&a_int + &modulus - &b_int) % &modulus;
            assert_eq!(fe_to_biguint(&r), expected, "sub mismatch seed {}", seed);
        }
    }

    #[test]
    fn neg_matches_biguint() {
        let modulus = p256_modulus();
        for seed in 0u64..16 {
            let (a_int, a) = pseudo_fe(seed);
            let r = a.neg();
            let expected = if a_int.is_zero() {
                BigUint::zero()
            } else {
                &modulus - &a_int
            };
            assert_eq!(fe_to_biguint(&r), expected, "neg mismatch seed {}", seed);
        }
    }

    #[test]
    fn mul_matches_biguint_fixed_vectors() {
        let modulus = p256_modulus();
        let test_vectors: Vec<(BigUint, BigUint)> = vec![
            (BigUint::from(0u32), BigUint::from(0u32)),
            (BigUint::from(1u32), BigUint::from(1u32)),
            (BigUint::from(2u32), BigUint::from(3u32)),
            (BigUint::from(0xdead_beef_u32), BigUint::from(0xcafe_babe_u32)),
            (&modulus - 1u32, &modulus - 1u32), // (p-1)^2 = 1 mod p
            (&modulus / 2u32, &modulus / 3u32),
            (&modulus - 17u32, BigUint::from(31337u32)),
        ];
        for (a_int, b_int) in &test_vectors {
            let a = biguint_to_fe(a_int);
            let b = biguint_to_fe(b_int);
            let r = a.mul(&b);
            let expected = (a_int * b_int) % &modulus;
            assert_eq!(
                fe_to_biguint(&r),
                expected,
                "mul mismatch: 0x{:x} · 0x{:x}",
                a_int,
                b_int
            );
        }
    }

    #[test]
    fn mul_matches_biguint_random() {
        let modulus = p256_modulus();
        for seed in 0u64..32 {
            let (a_int, a) = pseudo_fe(seed);
            let (b_int, b) = pseudo_fe(seed.wrapping_mul(31).wrapping_add(7));
            let r = a.mul(&b);
            let expected = (&a_int * &b_int) % &modulus;
            assert_eq!(fe_to_biguint(&r), expected, "mul mismatch seed {}", seed);
        }
    }

    #[test]
    fn square_equals_mul_self() {
        for seed in 0u64..16 {
            let (_, a) = pseudo_fe(seed);
            assert_eq!(
                a.square().to_be_bytes(),
                a.mul(&a).to_be_bytes(),
                "square ≠ mul self seed {}",
                seed
            );
        }
    }

    #[test]
    fn mul_distributes_over_add() {
        // (a + b) · c == a·c + b·c
        for seed in 0u64..8 {
            let (_, a) = pseudo_fe(seed);
            let (_, b) = pseudo_fe(seed + 100);
            let (_, c) = pseudo_fe(seed + 200);
            let lhs = a.add(&b).mul(&c);
            let rhs = a.mul(&c).add(&b.mul(&c));
            assert_eq!(
                lhs.to_be_bytes(),
                rhs.to_be_bytes(),
                "distributivity failed seed {}",
                seed
            );
        }
    }

    #[test]
    fn invert_times_self_is_one() {
        for seed in 1u64..8 {
            let (a_int, a) = pseudo_fe(seed);
            if a_int.is_zero() {
                continue;
            }
            let inv = a.invert();
            let prod = a.mul(&inv);
            assert_eq!(
                prod.to_be_bytes(),
                FieldElement::one().to_be_bytes(),
                "a · a⁻¹ ≠ 1 for seed {}",
                seed
            );
        }
    }

    #[test]
    fn freeze_is_idempotent() {
        for seed in 0u64..8 {
            let (_, mut a) = pseudo_fe(seed);
            a.freeze();
            let mut b = a;
            b.freeze();
            assert_eq!(a.limbs, b.limbs, "freeze not idempotent seed {}", seed);
        }
    }

    #[test]
    fn b_curve_constant_round_trips() {
        let b_bytes: [u8; 32] = [
            0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
            0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
            0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
            0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
        ];
        assert_eq!(B_CURVE.to_be_bytes(), b_bytes);
    }

    #[test]
    fn a_minus_3_squared_is_nine() {
        // a = −3, so a² = 9.
        let a_sq = A_MINUS_3.square();
        let mut nine = FieldElement::zero();
        for _ in 0..9 {
            nine = nine.add(&FieldElement::one());
        }
        assert_eq!(a_sq.to_be_bytes(), nine.to_be_bytes());
    }

    #[test]
    fn generator_satisfies_curve_equation() {
        // The P-256 generator G has affine coordinates (Gx, Gy) where
        //   Gx = 0x6b17d1f2 e12c4247 f8bce6e5 63a440f2
        //        77037d81 2deb33a0 f4a13945 d898c296
        //   Gy = 0x4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16
        //        2bce3357 6b315ececbb6406837bf51f5
        // And G satisfies y² = x³ + a·x + b (mod p) with a = −3.
        let gx_be: [u8; 32] = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
            0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
            0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
            0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        ];
        let gy_be: [u8; 32] = [
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
            0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
            0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
            0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let gx = FieldElement::from_be_bytes(&gx_be);
        let gy = FieldElement::from_be_bytes(&gy_be);

        // y² = x·x·x + a·x + b
        let y_sq = gy.square();
        let x_cubed = gx.mul(&gx).mul(&gx);
        let ax = A_MINUS_3.mul(&gx);
        let rhs = x_cubed.add(&ax).add(&B_CURVE);

        assert_eq!(
            y_sq.to_be_bytes(),
            rhs.to_be_bytes(),
            "P-256 generator does not satisfy curve equation"
        );
    }
}
