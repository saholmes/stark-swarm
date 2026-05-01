// ed25519_scalar.rs — native Ed25519 scalar arithmetic mod L.
//
// L = 2^252 + 27742317777372353535851937790883648493 is the order of
// the prime-order subgroup of Edwards25519.  Ed25519 verification needs
// two scalar operations:
//
//   1. `is_canonical(s)`   — true iff a 32-byte LE buffer encodes a
//                            canonical scalar in [0, L).
//   2. `reduce_mod_l_wide` — reduce a 64-byte LE buffer (the SHA-512
//                            digest used for k = SHA-512(R || A || M))
//                            into the canonical residue in [0, L).
//
// Until this commit those two operations were delegated to
// `curve25519_dalek::scalar::Scalar`.  Implementing them natively here
// (a) removes a third-party crate from `ed25519_verify`'s call path
// and (b) gives us a known-correct algorithmic oracle that the in-AIR
// scalar-reduction gadget (Phase 5 v1) can be tested against
// step-for-step.
//
// ─────────────────────────────────────────────────────────────────
// REPRESENTATION
// ─────────────────────────────────────────────────────────────────
//
// Internally we manipulate 64-byte values as 8 × u64 little-endian
// limbs (a `U512`) and 32-byte values as 4 × u64 LE limbs (a `U256`).
// The reduction is the textbook "shift-and-subtract" long-division by
// L, from bit 511 down to bit 0 — slow but obviously correct.

#![allow(non_snake_case, dead_code)]

/// L in LE bytes: order of the Ed25519 prime subgroup.
/// 2^252 + 27742317777372353535851937790883648493.
pub const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// L as 4 × u64 little-endian limbs.
pub const L_LIMBS: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// A 512-bit unsigned integer as 8 × u64 LE limbs.
type U512 = [u64; 8];

/// A 256-bit unsigned integer as 4 × u64 LE limbs.
type U256 = [u64; 4];

#[inline]
fn u256_to_bytes(x: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * (i + 1)].copy_from_slice(&x[i].to_le_bytes());
    }
    out
}

#[inline]
fn u256_from_bytes(b: &[u8; 32]) -> U256 {
    [
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
        u64::from_le_bytes(b[16..24].try_into().unwrap()),
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
    ]
}

#[inline]
fn u512_from_bytes(b: &[u8; 64]) -> U512 {
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = u64::from_le_bytes(b[8 * i..8 * (i + 1)].try_into().unwrap());
    }
    out
}

/// Compare two 8-limb LE numbers; returns true iff `a >= b`.
#[inline]
fn ge_512(a: &U512, b: &U512) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] { return a[i] > b[i]; }
    }
    true
}

/// Compare two 4-limb LE numbers; returns true iff `a >= b`.
#[inline]
fn ge_256(a: &U256, b: &U256) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] { return a[i] > b[i]; }
    }
    true
}

/// Subtract `b` from `a` in place (assumes `a >= b`); 8-limb LE.
#[inline]
fn sub_512_in_place(a: &mut U512, b: &U512) {
    let mut borrow: u128 = 0;
    for i in 0..8 {
        let lhs = a[i] as u128;
        let rhs = (b[i] as u128) + borrow;
        if lhs >= rhs {
            a[i] = (lhs - rhs) as u64;
            borrow = 0;
        } else {
            a[i] = ((lhs + (1u128 << 64)) - rhs) as u64;
            borrow = 1;
        }
    }
    debug_assert_eq!(borrow, 0, "underflow in sub_512_in_place");
}

/// Right-shift an 8-limb LE number by 1 bit, in place.
#[inline]
fn shr1_512(a: &mut U512) {
    let mut carry: u64 = 0;
    for i in (0..8).rev() {
        let new_carry = a[i] & 1;
        a[i] = (a[i] >> 1) | (carry << 63);
        carry = new_carry;
    }
}

/// Left-shift an 8-limb LE number by 1 bit (overflow truncated).
#[inline]
fn shl1_512(a: &mut U512) {
    let mut carry: u64 = 0;
    for i in 0..8 {
        let new_carry = a[i] >> 63;
        a[i] = (a[i] << 1) | carry;
        carry = new_carry;
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════════

/// True iff the 32-byte LE buffer `s` encodes a canonical scalar
/// (integer value < L).
pub fn is_canonical(s: &[u8; 32]) -> bool {
    let lhs = u256_from_bytes(s);
    !ge_256(&lhs, &L_LIMBS)
}

/// Reduce a 64-byte LE buffer mod L, returning the canonical 32-byte
/// LE representation in [0, L).
///
/// Used for `k = SHA-512(R || A || M) mod L` in Ed25519 verify.  The
/// input is interpreted little-endian per RFC 8032 §5.1.7.
pub fn reduce_mod_l_wide(input: &[u8; 64]) -> [u8; 32] {
    // Walk through the 512 bits of the input MSB-first.  At each step,
    // shift the accumulated remainder left by one bit, OR in the next
    // input bit, and conditionally subtract L if the result is ≥ L.
    let mut x = u512_from_bytes(input);

    // Build an 8-limb representation of L (low 4 limbs from L_LIMBS,
    // high 4 limbs zero).  Then shift it left to align with bit 511 of
    // the input — but rather than aligning L itself, we use the
    // "shift-input-right-into-remainder" approach below.

    // Algorithm: long-division remainder via bit-by-bit processing.
    //
    //   r := 0     (8-limb)
    //   for i from 511 down to 0:
    //       r := r << 1
    //       r |= bit_i(x)
    //       if r >= L:
    //           r -= L
    //   return r   (now in [0, L))
    //
    // But shifting r and reading bits of x bit-by-bit is awkward.  An
    // equivalent and simpler formulation: align L · 2^{260} with the
    // top of x (since L is 253 bits and x is up to 512 bits, the
    // largest k with L · 2^k ≤ 2^512 is k = 259), then iterate.
    //
    // We use: l_shifted starts as L · 2^{259}, shrink by 1 bit per
    // iteration, conditionally subtract from x.

    // Build l_shifted = L (in 8 limbs).
    let mut l_shifted: U512 = [
        L_LIMBS[0], L_LIMBS[1], L_LIMBS[2], L_LIMBS[3],
        0, 0, 0, 0,
    ];

    // Shift L left by 259 bits to align with bit 511 of x.
    // L is 253 bits long → bit 252 set.  After << 259, top bit at 511.
    for _ in 0..259 {
        shl1_512(&mut l_shifted);
    }

    // 260 iterations: at each step, conditionally subtract l_shifted
    // from x and then shift l_shifted right by 1.
    for _ in 0..260 {
        if ge_512(&x, &l_shifted) {
            sub_512_in_place(&mut x, &l_shifted);
        }
        shr1_512(&mut l_shifted);
    }

    // x now < L.  The result lives in the low 4 limbs.
    debug_assert!(x[4] == 0 && x[5] == 0 && x[6] == 0 && x[7] == 0,
        "high limbs non-zero after reduction");
    let r: U256 = [x[0], x[1], x[2], x[3]];
    debug_assert!(!ge_256(&r, &L_LIMBS), "remainder ≥ L after reduction");
    u256_to_bytes(&r)
}

/// Convert a canonical 32-byte LE scalar to a `Vec<bool>` of 256 bits,
/// LSB first.  Matches the input format expected by
/// `EdwardsPoint::scalar_mul`.
pub fn scalar_bytes_to_bits_le(bytes: &[u8; 32]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(256);
    for &byte in bytes {
        for b in 0..8 {
            bits.push(((byte >> b) & 1) == 1);
        }
    }
    bits
}

// ═══════════════════════════════════════════════════════════════════
//  Tests — cross-check vs curve25519-dalek
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn l_constant_is_correct() {
        // L_BYTES should match dalek's BASEPOINT_ORDER bytes.
        // dalek doesn't expose BASEPOINT_ORDER directly in 4.x; we can
        // verify L by checking that (L - 1) · 1 == L - 1 mod L, i.e.,
        // L · 1 mod L == 0.  Use Scalar::from_bytes_mod_order to roundtrip.
        let l_minus_one = {
            let mut b = L_BYTES;
            b[0] -= 1;     // L - 1 in canonical form
            b
        };
        // L - 1 should be canonical (< L).
        assert!(is_canonical(&l_minus_one));
        // L itself should NOT be canonical.
        assert!(!is_canonical(&L_BYTES));
        // L + 1 (overflow byte 0) should NOT be canonical.
        let l_plus_one = {
            let mut b = L_BYTES;
            b[0] += 1;
            b
        };
        assert!(!is_canonical(&l_plus_one));
    }

    #[test]
    fn is_canonical_zero_and_one() {
        let zero = [0u8; 32];
        assert!(is_canonical(&zero));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(is_canonical(&one));
    }

    #[test]
    fn is_canonical_max_minus_one() {
        // Largest canonical scalar = L - 1.
        let mut l_minus_one = L_BYTES;
        l_minus_one[0] -= 1;
        assert!(is_canonical(&l_minus_one));
    }

    #[test]
    fn is_canonical_max_value() {
        // Maximum 256-bit value is NOT canonical (way above L).
        let max = [0xffu8; 32];
        assert!(!is_canonical(&max));
    }

    #[test]
    fn reduce_zero_is_zero() {
        let zero = [0u8; 64];
        assert_eq!(reduce_mod_l_wide(&zero), [0u8; 32]);
    }

    #[test]
    fn reduce_l_is_zero() {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&L_BYTES);
        assert_eq!(reduce_mod_l_wide(&buf), [0u8; 32]);
    }

    #[test]
    fn reduce_l_minus_one_is_l_minus_one() {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&L_BYTES);
        buf[0] -= 1;
        let mut want = L_BYTES;
        want[0] -= 1;
        assert_eq!(reduce_mod_l_wide(&buf), want);
    }

    #[test]
    fn reduce_matches_dalek_for_small_inputs() {
        // Various 64-byte inputs spanning the wide range.
        let inputs: Vec<[u8; 64]> = vec![
            { let mut b = [0u8; 64]; b[0] = 1; b },
            { let mut b = [0u8; 64]; b[0] = 0xff; b[1] = 0xff; b },
            { let mut b = [0u8; 64]; for i in 0..64 { b[i] = i as u8; } b },
            { let mut b = [0u8; 64]; for i in 0..64 { b[i] = (i.wrapping_mul(13) % 256) as u8; } b },
            { let mut b = [0u8; 64]; b[63] = 0x01; b },        // 2^504 — large
            [0xffu8; 64],                                      // maximum 64-byte value
        ];
        for input in inputs {
            let ours  = reduce_mod_l_wide(&input);
            let dalek = Scalar::from_bytes_mod_order_wide(&input).to_bytes();
            assert_eq!(ours, dalek,
                "reduce_mod_l_wide mismatch with dalek for input {:?}",
                &input[..8]);
        }
    }

    #[test]
    fn reduce_matches_dalek_for_random_inputs() {
        // Pseudorandom 64-byte inputs.  Deterministic seed for
        // reproducible failures.
        let mut state: u64 = 0xc0ffee_0123_4567;
        for _ in 0..32 {
            let mut input = [0u8; 64];
            for byte in input.iter_mut() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            let ours  = reduce_mod_l_wide(&input);
            let dalek = Scalar::from_bytes_mod_order_wide(&input).to_bytes();
            assert_eq!(ours, dalek,
                "reduce_mod_l_wide random mismatch with dalek");
        }
    }

    #[test]
    fn is_canonical_matches_dalek() {
        // Probe is_canonical at boundary values.  dalek's
        // `from_canonical_bytes` is the reference: it returns Some iff
        // bytes encode an integer in [0, L).
        let cases: Vec<[u8; 32]> = vec![
            [0u8; 32],
            { let mut b = [0u8; 32]; b[0] = 1; b },
            L_BYTES,
            { let mut b = L_BYTES; b[0] -= 1; b },             // L - 1: canonical
            { let mut b = L_BYTES; b[0] += 1; b },             // L + 1: not canonical
            [0xffu8; 32],
        ];
        for bytes in cases {
            let ours_says_canonical = is_canonical(&bytes);
            let dalek_ct = Scalar::from_canonical_bytes(bytes);
            let dalek_says_canonical = bool::from(dalek_ct.is_some());
            assert_eq!(ours_says_canonical, dalek_says_canonical,
                "is_canonical disagrees with dalek for bytes {:?}", bytes);
        }
    }

    #[test]
    fn scalar_bits_le_layout() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0b1010_1100;
        let bits = scalar_bytes_to_bits_le(&bytes);
        assert_eq!(bits.len(), 256);
        // Byte 0 = 0xac = 0b10101100 → LSB first: 0,0,1,1,0,1,0,1.
        assert_eq!(&bits[..8], &[false, false, true, true, false, true, false, true]);
    }
}
