// p256_ecdsa.rs — Native ECDSA-P256 signature verification.
//
// Out-of-circuit reference for the full ECDSA verify protocol, used
// as the test oracle for the eventual top-level ECDSA verify AIR
// (Phase 5).  Composes:
//
//   * `p256_field`   for F_p arithmetic (curve coordinates)
//   * `p256_scalar`  for F_n arithmetic (signature scalars)
//   * `p256_group`   for elliptic-curve point arithmetic
//
// SHA-256 is NOT included in this module — we accept a pre-computed
// 32-byte message digest as input to keep `deep_ali`'s public dep
// surface tight.  The eventual AIR-side composition will pipe the
// existing `sha256_air` output into this verifier as `e`.
//
// ─────────────────────────────────────────────────────────────────
// VERIFICATION ALGORITHM (FIPS 186-4 §6.4.2)
// ─────────────────────────────────────────────────────────────────
//
// Given:
//   * Message digest e ∈ {0, 1}^256  (typically SHA-256 of the message)
//   * Public key Q = (Qx, Qy), an affine P-256 point
//   * Signature (r, s), with r, s ∈ [1, n − 1]
//
// Verify:
//   1.  Reduce e mod n.
//   2.  w  = s^(−1)  mod n
//   3.  u₁ = e · w   mod n
//   4.  u₂ = r · w   mod n
//   5.  R  = u₁ · G + u₂ · Q
//   6.  If R = ∅, reject.
//   7.  Accept iff R.x mod n == r.
//
// Edge cases:
//   * r = 0 or r ≥ n: reject.
//   * s = 0 or s ≥ n: reject.
//   * Q = ∅ or Q not on curve: reject.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use num_bigint::BigUint;

use crate::p256_field::FieldElement;
use crate::p256_group::{AffinePoint, GENERATOR};
use crate::p256_scalar::{N_BIGUINT, ScalarElement};

/// An ECDSA-P256 signature: (r, s) ∈ F_n × F_n.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub r: ScalarElement,
    pub s: ScalarElement,
}

impl Signature {
    /// Construct from 32-byte big-endian (r, s) byte arrays.  Returns
    /// `None` if either component is 0 or ≥ n (per FIPS 186-4 §6.4.2).
    pub fn from_be_bytes(r_bytes: &[u8; 32], s_bytes: &[u8; 32]) -> Option<Self> {
        let r_int = BigUint::from_bytes_be(r_bytes);
        let s_int = BigUint::from_bytes_be(s_bytes);
        if r_int == BigUint::from(0u32) || r_int >= *N_BIGUINT {
            return None;
        }
        if s_int == BigUint::from(0u32) || s_int >= *N_BIGUINT {
            return None;
        }
        Some(Self {
            r: ScalarElement::from_be_bytes_unchecked(r_bytes),
            s: ScalarElement::from_be_bytes_unchecked(s_bytes),
        })
    }
}

/// A P-256 public key: an affine point on the curve, NOT the identity.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    pub point: AffinePoint,
}

impl PublicKey {
    /// Construct from 32-byte big-endian Qx, Qy.  Returns `None` if
    /// the point is not on the curve or is the identity.
    pub fn from_be_bytes(qx_bytes: &[u8; 32], qy_bytes: &[u8; 32]) -> Option<Self> {
        let qx = FieldElement::from_be_bytes(qx_bytes);
        let qy = FieldElement::from_be_bytes(qy_bytes);
        let point = AffinePoint::new(qx, qy);
        if point.infinity {
            return None;
        }
        if !point.is_on_curve() {
            return None;
        }
        Some(Self { point })
    }
}

/// Reduce a 32-byte big-endian message digest to an `F_n` element
/// (FIPS 186-4 §6.4.2 step 5: bit-truncate to ceil(log₂(n)) bits, then
/// reduce mod n; for SHA-256 + P-256 this is just "reduce mod n" since
/// the digest length matches log₂(n) ≈ 256).
pub fn reduce_digest_mod_n(digest_be: &[u8; 32]) -> ScalarElement {
    ScalarElement::from_be_bytes(digest_be) // ScalarElement::from_be_bytes already reduces mod n
}

/// Verify an ECDSA-P256 signature.  Returns `true` iff the signature
/// is valid for the given digest under the given public key.
pub fn verify(
    digest_be: &[u8; 32],
    public_key: &PublicKey,
    sig: &Signature,
) -> bool {
    // (1) Reduce the digest mod n.
    let e = reduce_digest_mod_n(digest_be);

    // (2) w = s^(−1) mod n.
    let w = sig.s.invert();

    // (3, 4) u_1 = e · w, u_2 = r · w  mod n.
    let u_1 = e.mul(&w);
    let u_2 = sig.r.mul(&w);

    // (5) R = u_1 · G + u_2 · Q.
    let g = *GENERATOR;
    let u1_g = g.scalar_mul(&u_1);
    let u2_q = public_key.point.scalar_mul(&u_2);
    let r_point = u1_g.add(&u2_q);

    // (6) Reject if R is the identity.
    if r_point.infinity {
        return false;
    }

    // (7) Accept iff R.x mod n == r.
    let rx_bytes = r_point.x.to_be_bytes();
    let rx_mod_n = ScalarElement::from_be_bytes(&rx_bytes);
    rx_mod_n.ct_eq(&sig.r)
}

// ═══════════════════════════════════════════════════════════════════
//  Tests — RFC 6979 deterministic-ECDSA-P256 vectors
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6979 §A.2.5 — P-256 + SHA-256, test message "sample".
    ///
    ///   private key x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    ///   public key Ux = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
    ///              Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
    ///   "sample"   SHA-256 = AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF
    ///   k         = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    ///   r         = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    ///   s         = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    fn rfc6979_sample_qx() -> [u8; 32] {
        [
            0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,
            0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
            0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
            0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
        ]
    }
    fn rfc6979_sample_qy() -> [u8; 32] {
        [
            0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,
            0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
            0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
            0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99,
        ]
    }
    fn rfc6979_sample_digest() -> [u8; 32] {
        [
            0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1,
            0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
            0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
            0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF,
        ]
    }
    fn rfc6979_sample_r() -> [u8; 32] {
        [
            0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD,
            0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
            0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
            0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
        ]
    }
    fn rfc6979_sample_s() -> [u8; 32] {
        [
            0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41,
            0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
            0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
            0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8,
        ]
    }

    #[test]
    fn rfc6979_sample_signature_verifies() {
        let pk = PublicKey::from_be_bytes(&rfc6979_sample_qx(), &rfc6979_sample_qy())
            .expect("RFC 6979 test public key must parse");
        let sig = Signature::from_be_bytes(&rfc6979_sample_r(), &rfc6979_sample_s())
            .expect("RFC 6979 test signature must parse");
        let ok = verify(&rfc6979_sample_digest(), &pk, &sig);
        assert!(ok, "RFC 6979 sample signature did not verify");
    }

    #[test]
    fn tampered_digest_rejects() {
        let pk = PublicKey::from_be_bytes(&rfc6979_sample_qx(), &rfc6979_sample_qy()).unwrap();
        let sig = Signature::from_be_bytes(&rfc6979_sample_r(), &rfc6979_sample_s()).unwrap();
        let mut bad_digest = rfc6979_sample_digest();
        bad_digest[0] ^= 1;
        let ok = verify(&bad_digest, &pk, &sig);
        assert!(!ok, "tampered digest should be rejected");
    }

    #[test]
    fn tampered_r_rejects() {
        let pk = PublicKey::from_be_bytes(&rfc6979_sample_qx(), &rfc6979_sample_qy()).unwrap();
        let mut r_bytes = rfc6979_sample_r();
        r_bytes[31] ^= 1;
        let sig = Signature::from_be_bytes(&r_bytes, &rfc6979_sample_s()).unwrap();
        let ok = verify(&rfc6979_sample_digest(), &pk, &sig);
        assert!(!ok, "tampered r should be rejected");
    }

    #[test]
    fn tampered_s_rejects() {
        let pk = PublicKey::from_be_bytes(&rfc6979_sample_qx(), &rfc6979_sample_qy()).unwrap();
        let mut s_bytes = rfc6979_sample_s();
        s_bytes[31] ^= 1;
        let sig = Signature::from_be_bytes(&rfc6979_sample_r(), &s_bytes).unwrap();
        let ok = verify(&rfc6979_sample_digest(), &pk, &sig);
        assert!(!ok, "tampered s should be rejected");
    }

    #[test]
    fn signature_zero_r_is_rejected_at_parse() {
        let zero = [0u8; 32];
        let sig = Signature::from_be_bytes(&zero, &rfc6979_sample_s());
        assert!(sig.is_none(), "r = 0 must be rejected at parse time");
    }

    #[test]
    fn signature_zero_s_is_rejected_at_parse() {
        let zero = [0u8; 32];
        let sig = Signature::from_be_bytes(&rfc6979_sample_r(), &zero);
        assert!(sig.is_none(), "s = 0 must be rejected at parse time");
    }

    #[test]
    fn public_key_off_curve_is_rejected() {
        let mut bad_qy = rfc6979_sample_qy();
        bad_qy[0] ^= 1;
        let pk = PublicKey::from_be_bytes(&rfc6979_sample_qx(), &bad_qy);
        assert!(pk.is_none(), "off-curve public key must be rejected");
    }
}
