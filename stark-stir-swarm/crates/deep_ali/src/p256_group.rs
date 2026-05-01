// p256_group.rs — Native P-256 elliptic-curve point arithmetic.
//
// Out-of-circuit reference for the curve-group operations needed by
// ECDSA-P256 verification.  Used as the test oracle for the eventual
// in-circuit `p256_group_air.rs` (Phase 3 v1+) which will encode
// complete addition formulas (Renes–Costello–Batina 2016) in
// projective coordinates.
//
// ─────────────────────────────────────────────────────────────────
// REPRESENTATION: AFFINE WITH EXPLICIT INFINITY FLAG
// ─────────────────────────────────────────────────────────────────
//
// We use affine coordinates (x, y) ∈ F_p × F_p plus a boolean
// `infinity` flag for the identity.  This is the simplest correct
// representation for native code: every operation can branch on the
// flag and on coordinate equality (which is fine out-of-circuit, but
// would be unsound in a constant-time AIR — hence the projective
// + complete-addition switch in Phase 3 v1).
//
// ─────────────────────────────────────────────────────────────────
// CURVE EQUATION
// ─────────────────────────────────────────────────────────────────
//
// P-256 (NIST secp256r1, FIPS 186-4 D.1.2.3):
//
//     y² = x³ + a · x + b   (mod p),    where  a = −3,  b = B_CURVE
//
// Generator G = (Gx, Gy), order n.  G has cofactor 1, i.e., the
// curve subgroup has prime order n exactly.
//
// ─────────────────────────────────────────────────────────────────
// AFFINE OPERATIONS (Hankerson–Menezes–Vanstone §3.1.2)
// ─────────────────────────────────────────────────────────────────
//
//   Identity:     ∅ + P = P + ∅ = P
//   Inverse:      −(x, y) = (x, −y)
//   Doubling:     (x, y) ≠ ∅, y ≠ 0:
//                   λ = (3x² + a) / (2y)
//                   x₃ = λ² − 2x
//                   y₃ = λ(x − x₃) − y
//                   (if y = 0:  result = ∅)
//   Addition:     P = (x₁, y₁), Q = (x₂, y₂), x₁ ≠ x₂:
//                   λ = (y₂ − y₁) / (x₂ − x₁)
//                   x₃ = λ² − x₁ − x₂
//                   y₃ = λ(x₁ − x₃) − y₁
//                 If x₁ = x₂:
//                   y₁ = y₂  →  doubling
//                   y₁ = −y₂ →  identity
//
// Scalar multiplication uses left-to-right binary double-and-add.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use once_cell::sync::Lazy;

use crate::p256_field::{A_MINUS_3, B_CURVE, FieldElement};
use crate::p256_scalar::ScalarElement;

// ═══════════════════════════════════════════════════════════════════
//  AffinePoint
// ═══════════════════════════════════════════════════════════════════

/// An affine point on P-256, or the identity (point at infinity).
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    pub x: FieldElement,
    pub y: FieldElement,
    /// True iff this point represents the group identity (point at infinity).
    pub infinity: bool,
}

impl AffinePoint {
    /// The identity element (point at infinity).
    pub const fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            infinity: true,
        }
    }

    /// Construct an affine point.  Does NOT validate that (x, y) lies on
    /// the curve; use `is_on_curve` to check.
    pub const fn new(x: FieldElement, y: FieldElement) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }

    /// True iff this point satisfies y² = x³ + a·x + b (mod p), or is
    /// the identity.
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        let y_sq = self.y.square();
        let x_cubed = self.x.mul(&self.x).mul(&self.x);
        let ax = A_MINUS_3.mul(&self.x);
        let rhs = x_cubed.add(&ax).add(&B_CURVE);
        y_sq.ct_eq(&rhs)
    }

    /// Negation: (x, y) ↦ (x, −y).  Identity ↦ identity.
    pub fn neg(&self) -> Self {
        if self.infinity {
            return *self;
        }
        Self {
            x: self.x,
            y: self.y.neg(),
            infinity: false,
        }
    }

    /// Equality (constant-time-ish — ct_eq on canonicalised limbs).
    pub fn eq(&self, other: &Self) -> bool {
        if self.infinity != other.infinity {
            return false;
        }
        if self.infinity {
            return true;
        }
        self.x.ct_eq(&other.x) && self.y.ct_eq(&other.y)
    }

    /// Doubling: 2 · P.
    pub fn double(&self) -> Self {
        if self.infinity {
            return Self::identity();
        }
        if self.y.is_zero() {
            // 2-torsion: y = 0 ⇒ doubling lands on identity.
            return Self::identity();
        }
        // λ = (3x² + a) / (2y) = (3x² − 3) / (2y)
        let three_x_sq = {
            let xx = self.x.square();
            xx.add(&xx).add(&xx) // 3 · x²
        };
        let numerator = three_x_sq.add(&A_MINUS_3); // 3x² − 3
        let two_y = self.y.add(&self.y);
        let lambda = numerator.mul(&two_y.invert());

        // x₃ = λ² − 2x
        let lambda_sq = lambda.square();
        let two_x = self.x.add(&self.x);
        let x3 = lambda_sq.sub(&two_x);

        // y₃ = λ(x − x₃) − y
        let x_minus_x3 = self.x.sub(&x3);
        let y3 = lambda.mul(&x_minus_x3).sub(&self.y);

        let mut x3 = x3;
        x3.freeze();
        let mut y3 = y3;
        y3.freeze();
        Self::new(x3, y3)
    }

    /// Addition: P + Q.
    pub fn add(&self, other: &Self) -> Self {
        if self.infinity {
            return *other;
        }
        if other.infinity {
            return *self;
        }
        // x₁ = x₂?  Then either doubling or inverses.
        if self.x.ct_eq(&other.x) {
            if self.y.ct_eq(&other.y) {
                return self.double();
            }
            // (x, y) + (x, −y) = identity.
            return Self::identity();
        }
        // λ = (y₂ − y₁) / (x₂ − x₁)
        let dy = other.y.sub(&self.y);
        let dx = other.x.sub(&self.x);
        let lambda = dy.mul(&dx.invert());
        // x₃ = λ² − x₁ − x₂
        let lambda_sq = lambda.square();
        let x3 = lambda_sq.sub(&self.x).sub(&other.x);
        // y₃ = λ(x₁ − x₃) − y₁
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        let mut x3 = x3;
        x3.freeze();
        let mut y3 = y3;
        y3.freeze();
        Self::new(x3, y3)
    }

    /// Scalar multiplication: k · P.  Left-to-right double-and-add
    /// over the canonical big-endian byte representation of k.  NOT
    /// constant-time (early-exit on identity).  Sufficient for the
    /// native test oracle; the AIR version uses a constant-time
    /// Montgomery ladder (Phase 4).
    pub fn scalar_mul(&self, k: &ScalarElement) -> Self {
        let bytes = k.to_be_bytes();
        let mut acc = Self::identity();
        let mut started = false;
        for &byte in &bytes {
            for bit in (0..8).rev() {
                if started {
                    acc = acc.double();
                }
                if (byte >> bit) & 1 == 1 {
                    if started {
                        acc = acc.add(self);
                    } else {
                        acc = *self;
                        started = true;
                    }
                }
            }
        }
        acc
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Generator G (FIPS 186-4 D.1.2.3)
// ═══════════════════════════════════════════════════════════════════

/// The standard P-256 generator, lazily decoded from FIPS 186-4 hex.
pub static GENERATOR: Lazy<AffinePoint> = Lazy::new(|| {
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
    AffinePoint::new(
        FieldElement::from_be_bytes(&gx_be),
        FieldElement::from_be_bytes(&gy_be),
    )
});

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_satisfies_curve_equation() {
        assert!(AffinePoint::identity().is_on_curve());
    }

    #[test]
    fn generator_satisfies_curve_equation() {
        assert!(GENERATOR.is_on_curve());
    }

    #[test]
    fn identity_plus_g_is_g() {
        let g = *GENERATOR;
        let r = AffinePoint::identity().add(&g);
        assert!(r.eq(&g));
    }

    #[test]
    fn g_plus_identity_is_g() {
        let g = *GENERATOR;
        let r = g.add(&AffinePoint::identity());
        assert!(r.eq(&g));
    }

    #[test]
    fn g_plus_neg_g_is_identity() {
        let g = *GENERATOR;
        let neg_g = g.neg();
        assert!(neg_g.is_on_curve(), "−G must be on curve");
        let r = g.add(&neg_g);
        assert!(r.infinity, "G + (−G) must be identity");
    }

    #[test]
    fn double_g_via_add_matches_double() {
        let g = *GENERATOR;
        let twoG_via_add = g.add(&g);
        let twoG_via_double = g.double();
        assert!(
            twoG_via_add.eq(&twoG_via_double),
            "G + G ≠ 2 · G"
        );
        assert!(twoG_via_double.is_on_curve());
    }

    #[test]
    fn three_g_consistent() {
        let g = *GENERATOR;
        let two_g = g.double();
        let three_g_via_add = two_g.add(&g);
        let three_g_via_other = g.add(&two_g);
        assert!(three_g_via_add.eq(&three_g_via_other));
        assert!(three_g_via_add.is_on_curve());
    }

    #[test]
    fn scalar_mul_zero_is_identity() {
        let g = *GENERATOR;
        let zero = ScalarElement::zero();
        let r = g.scalar_mul(&zero);
        assert!(r.infinity, "0 · G must be identity");
    }

    #[test]
    fn scalar_mul_one_is_self() {
        let g = *GENERATOR;
        let one = ScalarElement::one();
        let r = g.scalar_mul(&one);
        assert!(r.eq(&g), "1 · G ≠ G");
    }

    #[test]
    fn scalar_mul_two_matches_double() {
        let g = *GENERATOR;
        let two = {
            let mut t = ScalarElement::zero();
            t.limbs[0] = 2;
            t
        };
        let r = g.scalar_mul(&two);
        let twoG = g.double();
        assert!(r.eq(&twoG), "2 · G via scalar_mul ≠ 2 · G via double");
    }

    #[test]
    fn scalar_mul_n_minus_1_is_neg_g() {
        // (n − 1) · G = −G  (since n · G = identity).
        let g = *GENERATOR;
        let mut n_minus_1 = ScalarElement::one().neg();
        n_minus_1.freeze();
        let r = g.scalar_mul(&n_minus_1);
        assert!(
            r.eq(&g.neg()),
            "(n − 1) · G ≠ −G"
        );
    }

    #[test]
    fn scalar_mul_n_is_identity() {
        // n · G = identity (group order).
        let g = *GENERATOR;
        // Build n as a ScalarElement.  n itself reduces to 0 mod n,
        // so we compute (n − 1) · G + G instead, which equals n · G.
        let mut n_minus_1 = ScalarElement::one().neg();
        n_minus_1.freeze();
        let n_minus_1_g = g.scalar_mul(&n_minus_1);
        let n_g = n_minus_1_g.add(&g);
        assert!(n_g.infinity, "n · G ≠ identity");
    }

    #[test]
    fn two_g_is_on_curve_and_distinct_from_g() {
        let g = *GENERATOR;
        let two_g = g.double();
        assert!(two_g.is_on_curve(), "2G must be on curve");
        assert!(!two_g.infinity, "2G must not be identity");
        assert!(!two_g.eq(&g), "2G must differ from G");
    }

    #[test]
    fn scalar_mul_distributive() {
        // (k + 1) · G = k · G + G   for several small k.
        let g = *GENERATOR;
        for seed in 1u64..5 {
            let k = {
                let mut t = ScalarElement::zero();
                t.limbs[0] = seed as i64 * 17 + 3;
                t
            };
            let k_plus_1 = {
                let mut t = ScalarElement::zero();
                t.limbs[0] = seed as i64 * 17 + 4;
                t
            };
            let lhs = g.scalar_mul(&k_plus_1);
            let rhs = g.scalar_mul(&k).add(&g);
            assert!(lhs.eq(&rhs), "(k+1)G ≠ kG + G for k = {}", k.limbs[0]);
        }
    }
}
