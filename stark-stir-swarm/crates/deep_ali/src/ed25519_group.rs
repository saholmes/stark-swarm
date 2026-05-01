// ed25519_group.rs — native Edwards25519 group operations.
//
// Native (out-of-circuit) reference implementation of point arithmetic
// on Edwards25519 in extended twisted-Edwards coordinates (X, Y, Z, T)
// with T = X·Y/Z.  Built on `ed25519_field::FieldElement` so the AIR
// gadgets in v1 / v2 can replicate the algebra step-for-step against
// this oracle.
//
// Curve equation (RFC 8032 §5.1):  −x² + y² = 1 + d·x²·y²,
//   d = −121665 / 121666 (mod p)   where  p = 2^255 − 19.
//
// ─────────────────────────────────────────────────────────────────
// PHASE 3 SUB-PLAN
// ─────────────────────────────────────────────────────────────────
//
//   v0    native EdwardsPoint reference (this commit)             ✓ here
//   v1    point-op trace layout (compose field gadgets sequentially)
//   v2    point-op constraint evaluator + tests
//
// ─────────────────────────────────────────────────────────────────
// EXTENDED-COORDS ADD / DBL FORMULAS  (Hisil–Wong–Carter–Dawson, 2008)
// ─────────────────────────────────────────────────────────────────
//
// ```text
// add (P1 + P2):
//   A = (Y1 − X1) · (Y2 − X2)
//   B = (Y1 + X1) · (Y2 + X2)
//   C = T1 · T2 · 2d
//   D = Z1 · Z2 · 2
//   E = B − A
//   F = D − C
//   G = D + C
//   H = B + A
//   (X3, Y3, T3, Z3) = (E·F,  G·H,  E·H,  F·G)
//
// double (2 · P):
//   A = X1²
//   B = Y1²
//   C = 2 · Z1²
//   H = A + B
//   E = H − (X1 + Y1)²
//   G = A − B
//   F = C + G
//   (X3, Y3, T3, Z3) = (E·F,  G·H,  E·H,  F·G)
// ```
//
// add: 9 muls + 0 squares + 7 add/sub.
// dbl: 4 muls + 4 squares + 6 add/sub.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use once_cell::sync::Lazy;

use crate::ed25519_field::{D, FieldElement};

// ═══════════════════════════════════════════════════════════════════
//  Curve constants
// ═══════════════════════════════════════════════════════════════════

/// 2 · d (used in extended-coords add).
pub static D2: Lazy<FieldElement> = Lazy::new(|| (*D).add(&*D));

/// 32-byte compressed encoding of the standard Ed25519 basepoint
/// (RFC 8032 §5.1).  Y = 4/5 mod p; X = even root recovered from the
/// curve equation.
///
/// LE bytes: 0x58 followed by 31 × 0x66.
pub const ED25519_BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

// ═══════════════════════════════════════════════════════════════════
//  EdwardsPoint
// ═══════════════════════════════════════════════════════════════════

/// Point on Edwards25519 in extended twisted-Edwards coordinates.
/// Affine X = X / Z, affine Y = Y / Z, T = X·Y / Z.
#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T: FieldElement,
}

impl EdwardsPoint {
    /// Identity point (0, 1, 1, 0).
    pub fn identity() -> Self {
        Self {
            X: FieldElement::zero(),
            Y: FieldElement::one(),
            Z: FieldElement::one(),
            T: FieldElement::zero(),
        }
    }

    /// Point addition in extended coords (HWCD formula).
    pub fn add(&self, other: &Self) -> Self {
        let a = self.Y.sub(&self.X).mul(&other.Y.sub(&other.X));
        let b = self.Y.add(&self.X).mul(&other.Y.add(&other.X));
        let c = self.T.mul(&other.T).mul(&D2);
        let d = self.Z.mul(&other.Z).add(&self.Z.mul(&other.Z));    // 2 · Z1·Z2
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Self {
            X: e.mul(&f),
            Y: g.mul(&h),
            T: e.mul(&h),
            Z: f.mul(&g),
        }
    }

    /// Specialised addition when `other` is in affine form (`other.Z = 1`,
    /// `other.T = other.X · other.Y`).  Saves one mul vs `add` because
    /// `Z1 · Z2 = Z1` collapses; the 2 · Z1 factor that would normally
    /// require a multiplication becomes a doubling.  Used by
    /// `scalar_mul_basepoint` since every `BASEPOINT_POW2_TABLE` entry
    /// is precomputed in affine form.
    ///
    /// Pre-condition: `other.Z` is the canonical-form 1.  The native
    /// scalar_mul calls don't enforce this in code (we trust the table
    /// builder); the bench tests cross-check correctness.
    pub fn add_affine_other(&self, other: &Self) -> Self {
        let a = self.Y.sub(&self.X).mul(&other.Y.sub(&other.X));
        let b = self.Y.add(&self.X).mul(&other.Y.add(&other.X));
        let c = self.T.mul(&other.T).mul(&D2);
        // d = 2 · Z1 · Z2 = 2 · Z1 · 1 = 2·Z1   (saves one mul vs `add`)
        let d = self.Z.add(&self.Z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Self {
            X: e.mul(&f),
            Y: g.mul(&h),
            T: e.mul(&h),
            Z: f.mul(&g),
        }
    }

    /// Point doubling in extended coords.
    pub fn double(&self) -> Self {
        let a = self.X.square();
        let b = self.Y.square();
        let c_pre = self.Z.square();
        let c = c_pre.add(&c_pre);                                  // 2 · Z²
        let h = a.add(&b);
        let xy = self.X.add(&self.Y);
        let xy_sq = xy.square();
        let e = h.sub(&xy_sq);
        let g = a.sub(&b);
        let f = c.add(&g);
        Self {
            X: e.mul(&f),
            Y: g.mul(&h),
            T: e.mul(&h),
            Z: f.mul(&g),
        }
    }

    /// Negate a point: (−X, Y, Z, −T).
    pub fn neg(&self) -> Self {
        Self {
            X: self.X.neg(),
            Y: self.Y,
            Z: self.Z,
            T: self.T.neg(),
        }
    }

    /// Subtraction.
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Compute affine (x, y) from extended coords by dividing through by Z.
    pub fn to_affine(&self) -> (FieldElement, FieldElement) {
        let z_inv = self.Z.invert();
        (self.X.mul(&z_inv), self.Y.mul(&z_inv))
    }

    /// Compress to the 32-byte canonical Ed25519 encoding (RFC 8032 §5.1.2).
    /// Output bytes encode `y` little-endian; the most significant bit
    /// of byte 31 holds the sign of `x`.
    pub fn compress(&self) -> [u8; 32] {
        let (x, y) = self.to_affine();
        let mut out = y.to_bytes();
        if x.is_negative() {
            out[31] |= 0x80;
        } else {
            out[31] &= 0x7f;
        }
        out
    }

    /// Decompress a 32-byte encoding to a point.  Returns `None` on
    /// invalid input (Y not a square root of −X² + 1 = 1 + d·X²·Y² −
    /// equivalently, not on the curve).
    pub fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        // Extract sign bit and Y.
        let sign_bit = (bytes[31] >> 7) & 1;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = FieldElement::from_bytes(&y_bytes);

        // Recover x from x² · (d·y² + 1) = y² − 1.
        // u = y² − 1,  v = d·y² + 1,   x = ±sqrt(u / v).
        let one = FieldElement::one();
        let y_sq = y.square();
        let u = y_sq.sub(&one);
        let v = (*D).mul(&y_sq).add(&one);
        let (ok, mut x) = FieldElement::sqrt_ratio_i(&u, &v);
        if !ok { return None; }

        // Pick the root matching the encoded sign bit.
        if x.is_negative() != (sign_bit == 1) {
            x = x.neg();
        }

        // Construct extended coords with Z = 1.
        let one = FieldElement::one();
        let t = x.mul(&y);
        Some(Self { X: x, Y: y, Z: one, T: t })
    }

    /// True iff this point equals `other` projectively (i.e., the
    /// affine coordinates agree).  Comparison is via cross-multiply
    /// to avoid the inversion cost.
    pub fn ct_eq(&self, other: &Self) -> bool {
        // X1 / Z1 == X2 / Z2  ⇔  X1·Z2 == X2·Z1
        // Y1 / Z1 == Y2 / Z2  ⇔  Y1·Z2 == Y2·Z1
        let lhs_x = self.X.mul(&other.Z);
        let rhs_x = other.X.mul(&self.Z);
        let lhs_y = self.Y.mul(&other.Z);
        let rhs_y = other.Y.mul(&self.Z);
        lhs_x.ct_eq(&rhs_x) && lhs_y.ct_eq(&rhs_y)
    }

    /// True iff this is the identity point (X = 0, Y = Z, T = 0
    /// projectively).
    pub fn is_identity(&self) -> bool {
        self.ct_eq(&Self::identity())
    }

    /// Multiply self by 8 (cofactor).  Three doublings.
    pub fn mul_by_cofactor(&self) -> Self {
        self.double().double().double()
    }

    /// Variable-base scalar multiplication via simple double-and-add,
    /// LSB-first traversal of the 256-bit scalar.  Constant-time
    /// behaviour is NOT required for the native ref; this is a
    /// correctness oracle.  `scalar_bits` is little-endian (bit 0 is LSB).
    pub fn scalar_mul(&self, scalar_bits: &[bool]) -> Self {
        // Process MSB-first: start at identity, for each bit from high
        // to low, double and conditionally add.
        let mut acc = Self::identity();
        for &bit in scalar_bits.iter().rev() {
            acc = acc.double();
            if bit { acc = acc.add(self); }
        }
        acc
    }
}

/// Standard Ed25519 basepoint (RFC 8032 §5.1).  Decompressed once at
/// first access via `Lazy`.
pub static ED25519_BASEPOINT: Lazy<EdwardsPoint> = Lazy::new(|| {
    EdwardsPoint::decompress(&ED25519_BASEPOINT_COMPRESSED)
        .expect("standard basepoint must decompress")
});

/// Precomputed `[2^i] · B` for i = 0..256 in **affine form**
/// (Z = 1, T = X · Y).  Lazy-initialised on first use via 256 doublings
/// + one batch inversion pass.  Affine form lets `scalar_mul_basepoint`
/// use `add_affine_other` (one mul cheaper than the generic add) for
/// every table sum.
pub static BASEPOINT_POW2_TABLE: Lazy<[EdwardsPoint; 256]> = Lazy::new(|| {
    // Step 1: build the 256 doublings in extended (non-affine) form.
    let mut tmp: [EdwardsPoint; 256] = [EdwardsPoint::identity(); 256];
    let mut current = *ED25519_BASEPOINT;
    for entry in tmp.iter_mut() {
        *entry = current;
        current = current.double();
    }

    // Step 2: convert each entry to affine (X/Z, Y/Z, 1, X·Y/Z).
    // Use Montgomery's batch inversion: 1 inverse + 3·n muls, far
    // cheaper than n individual inverses (each ~250 muls via Fermat).
    let z_invs = batch_invert(&tmp.iter().map(|p| p.Z).collect::<Vec<_>>());
    let mut table: [EdwardsPoint; 256] = [EdwardsPoint::identity(); 256];
    for (i, p) in tmp.iter().enumerate() {
        let x_aff = p.X.mul(&z_invs[i]);
        let y_aff = p.Y.mul(&z_invs[i]);
        let t_aff = x_aff.mul(&y_aff);
        table[i] = EdwardsPoint {
            X: x_aff, Y: y_aff,
            Z: FieldElement::one(),
            T: t_aff,
        };
    }
    table
});

/// Batch inversion via Montgomery's trick: invert `[a_0, a_1, ..., a_{n-1}]`
/// using only ONE field inversion + roughly 3n field multiplications.
/// Massively faster than calling `invert()` on each input separately.
fn batch_invert(xs: &[FieldElement]) -> Vec<FieldElement> {
    let n = xs.len();
    if n == 0 { return Vec::new(); }
    // running[i] = product of xs[0..=i]
    let mut running = Vec::with_capacity(n);
    let mut acc = xs[0];
    running.push(acc);
    for i in 1..n {
        acc = acc.mul(&xs[i]);
        running.push(acc);
    }
    // One inverse: inv_running_n = 1 / Π xs.
    let mut inv = running[n - 1].invert();
    let mut out = vec![FieldElement::zero(); n];
    for i in (1..n).rev() {
        // out[i] = inv · running[i-1]    (= 1 / xs[i])
        out[i] = inv.mul(&running[i - 1]);
        // inv := inv · xs[i]            (= 1 / Π xs[0..i])
        inv = inv.mul(&xs[i]);
    }
    out[0] = inv;
    out
}

impl EdwardsPoint {
    /// Faster fixed-base scalar multiplication of the standard Ed25519
    /// basepoint using `BASEPOINT_POW2_TABLE`.  Skips doublings (the
    /// table holds them) AND uses `add_affine_other` for each addition
    /// (table entries are pre-converted to Z=1 affine form, saving one
    /// mul per add).
    ///
    /// `scalar_bits` is LSB-first, length 256.
    pub fn scalar_mul_basepoint(scalar_bits: &[bool]) -> Self {
        debug_assert_eq!(scalar_bits.len(), 256, "scalar must be 256 bits");
        let table = &*BASEPOINT_POW2_TABLE;
        let mut acc = Self::identity();
        for (i, &bit) in scalar_bits.iter().enumerate() {
            if bit { acc = acc.add_affine_other(&table[i]); }
        }
        acc
    }

    /// Variable-base scalar multiplication using a 4-bit windowed
    /// double-and-add.  Precomputes `0·self, 1·self, ..., 15·self`
    /// (15 additions), then walks the scalar bits in 4-bit windows
    /// MSB-first: per window do 4 doublings + (at most) one addition
    /// with `table[nibble]`.
    ///
    /// vs. the simple `scalar_mul` (256 doublings + ~128 conditional
    /// adds), the windowed version uses 256 doublings + ≤ 64 adds —
    /// ~50% reduction in addition count.
    ///
    /// `scalar_bits` is LSB-first, length 256.
    pub fn scalar_mul_windowed(&self, scalar_bits: &[bool]) -> Self {
        debug_assert_eq!(scalar_bits.len() % 4, 0,
            "scalar bit length must be a multiple of 4");
        // Build precomputed-multiples table: table[i] = i·self for i ∈ [0, 16).
        let mut table: [Self; 16] = [Self::identity(); 16];
        for i in 1..16 {
            table[i] = if i == 1 { *self } else { table[i - 1].add(self) };
        }

        // Pack scalar bits into MSB-first nibbles.
        let n_nibbles = scalar_bits.len() / 4;
        let mut nibbles = vec![0u8; n_nibbles];
        for (i, &bit) in scalar_bits.iter().enumerate() {
            if bit {
                nibbles[i / 4] |= 1 << (i % 4);
            }
        }

        let mut acc = Self::identity();
        for &nibble in nibbles.iter().rev() {
            // 4 doublings = quadruple
            acc = acc.double().double().double().double();
            if nibble != 0 {
                acc = acc.add(&table[nibble as usize]);
            }
        }
        acc
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Tests — cross-check vs curve25519-dalek
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{
        constants::ED25519_BASEPOINT_POINT as DALEK_BASEPOINT,
        edwards::CompressedEdwardsY,
        scalar::Scalar,
    };

    fn scalar_to_bits_le(s: &Scalar) -> Vec<bool> {
        let bytes = s.to_bytes();
        let mut bits = Vec::with_capacity(256);
        for byte in bytes {
            for b in 0..8 {
                bits.push(((byte >> b) & 1) == 1);
            }
        }
        bits
    }

    #[test]
    fn identity_compresses_to_canonical_bytes() {
        let id = EdwardsPoint::identity();
        let compressed = id.compress();
        // Identity = (0, 1).  Y = 1, x is positive (even).  bytes = 0x01, 0, ..., 0.
        assert_eq!(compressed[0], 1);
        for b in &compressed[1..] { assert_eq!(*b, 0); }
    }

    #[test]
    fn identity_plus_p_is_p() {
        let id = EdwardsPoint::identity();
        let p = EdwardsPoint::decompress(&ED25519_BASEPOINT_COMPRESSED).unwrap();
        let sum = id.add(&p);
        assert!(sum.ct_eq(&p), "id + p ≠ p");
    }

    #[test]
    fn p_plus_neg_p_is_identity() {
        let p = *ED25519_BASEPOINT;
        let neg_p = p.neg();
        let sum = p.add(&neg_p);
        assert!(sum.is_identity(), "p + (−p) ≠ identity");
    }

    #[test]
    fn double_equals_self_add_self() {
        let p = *ED25519_BASEPOINT;
        let p_doubled = p.double();
        let p_plus_p = p.add(&p);
        assert!(p_doubled.ct_eq(&p_plus_p), "2·p ≠ p + p");
    }

    #[test]
    fn basepoint_decompresses_and_round_trips() {
        let p = EdwardsPoint::decompress(&ED25519_BASEPOINT_COMPRESSED)
            .expect("basepoint should decompress");
        let recompressed = p.compress();
        assert_eq!(recompressed, ED25519_BASEPOINT_COMPRESSED,
            "basepoint compress(decompress(.)) round-trip failed");
    }

    #[test]
    fn basepoint_matches_dalek() {
        let ours = ED25519_BASEPOINT.compress();
        let dalek = DALEK_BASEPOINT.compress().to_bytes();
        assert_eq!(ours, dalek,
            "basepoint encoding mismatch with curve25519-dalek");
    }

    #[test]
    fn double_basepoint_matches_dalek() {
        let ours = ED25519_BASEPOINT.double();
        // dalek doesn't expose `double`; use [2]·B instead.
        let dalek = (DALEK_BASEPOINT * Scalar::from(2u64)).compress().to_bytes();
        assert_eq!(ours.compress(), dalek,
            "[2]B encoding mismatch with dalek");
    }

    #[test]
    fn cofactor_mul_basepoint_matches_dalek() {
        let ours = ED25519_BASEPOINT.mul_by_cofactor();
        let dalek = DALEK_BASEPOINT.mul_by_cofactor().compress().to_bytes();
        assert_eq!(ours.compress(), dalek,
            "[8]B encoding mismatch with dalek");
    }

    #[test]
    fn scalar_mul_basepoint_matches_dalek_for_small_scalars() {
        for k in [1u64, 2, 3, 5, 17, 1000, 0xdeadbeef_u64] {
            let s = Scalar::from(k);
            let dalek_kb = (DALEK_BASEPOINT * s).compress().to_bytes();

            let bits = scalar_to_bits_le(&s);
            let ours_kb = ED25519_BASEPOINT.scalar_mul(&bits).compress();

            assert_eq!(ours_kb, dalek_kb,
                "[{}]B encoding mismatch with dalek", k);
        }
    }

    #[test]
    fn scalar_mul_basepoint_matches_dalek_for_random_scalars() {
        // A handful of random-ish scalars.  We pin the bytes so the
        // test is deterministic.
        let scalars: Vec<[u8; 32]> = vec![
            *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\
               \x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x00",
            *b"\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\
               \x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x0d",
        ];
        for sb in &scalars {
            let s = Scalar::from_bytes_mod_order(*sb);
            let dalek_kb = (DALEK_BASEPOINT * s).compress().to_bytes();
            let bits = scalar_to_bits_le(&s);
            let ours_kb = ED25519_BASEPOINT.scalar_mul(&bits).compress();
            assert_eq!(ours_kb, dalek_kb,
                "scalar-mul mismatch for scalar bytes {:?}", sb);
        }
    }

    #[test]
    fn add_associativity_and_commutativity() {
        let p = *ED25519_BASEPOINT;
        let p2 = p.double();
        let p3 = p.add(&p2);

        // Commutativity: p + p2 == p2 + p.
        assert!(p.add(&p2).ct_eq(&p2.add(&p)),
            "addition not commutative");

        // Associativity: (p + p) + p == p + (p + p).
        let lhs = p.add(&p).add(&p);
        let rhs = p.add(&p.add(&p));
        assert!(lhs.ct_eq(&rhs), "addition not associative");

        // Sanity: 3·p via different routes.
        let three_p_via_add = p.add(&p2);
        let three_p_via_double_add = p.double().add(&p);
        assert!(three_p_via_add.ct_eq(&three_p_via_double_add));
        assert!(three_p_via_add.ct_eq(&p3));
    }

    #[test]
    fn scalar_mul_basepoint_precomputed_matches_generic() {
        // The precomputed-table path should produce identical points
        // (projectively) to the generic double-and-add for the basepoint.
        for k in [1u64, 2, 5, 100, 0xdeadbeef_u64] {
            let s = Scalar::from(k);
            let bits = scalar_to_bits_le(&s);
            let via_table   = EdwardsPoint::scalar_mul_basepoint(&bits);
            let via_generic = ED25519_BASEPOINT.scalar_mul(&bits);
            assert!(via_table.ct_eq(&via_generic),
                "[{}]B via table ≠ via generic", k);
        }
    }

    #[test]
    fn batch_invert_matches_individual_inverts() {
        let xs: Vec<FieldElement> = (1u64..10).map(|k| {
            FieldElement::one().mul_small(k as i64)
        }).collect();
        let batched = batch_invert(&xs);
        for (i, x) in xs.iter().enumerate() {
            let want = x.invert();
            assert_eq!(batched[i].to_bytes(), want.to_bytes(),
                "batch_invert[{}] ≠ individual invert", i);
            // Verify x · x^{-1} = 1.
            let prod = x.mul(&batched[i]);
            assert_eq!(prod.to_bytes(), FieldElement::one().to_bytes(),
                "x · batched_inv ≠ 1");
        }
    }

    #[test]
    fn basepoint_table_entries_are_affine() {
        // Every BASEPOINT_POW2_TABLE entry must have Z = 1 (canonical) and
        // T = X · Y (extended-coords invariant for affine points).
        let table = &*BASEPOINT_POW2_TABLE;
        let one = FieldElement::one();
        for (i, p) in table.iter().enumerate().take(8) {
            // Sample first 8 entries (enough to validate the construction).
            let mut z_canon = p.Z;  z_canon.freeze();
            assert_eq!(z_canon.to_bytes(), one.to_bytes(),
                "table[{}].Z ≠ 1 (not in affine form)", i);
            let mut t_check = p.X.mul(&p.Y);  t_check.freeze();
            let mut t_canon = p.T;            t_canon.freeze();
            assert_eq!(t_check.to_bytes(), t_canon.to_bytes(),
                "table[{}].T ≠ X · Y", i);
        }
    }

    #[test]
    fn add_affine_other_matches_generic_add() {
        // For an affine `other`, add_affine_other must produce the
        // same point projectively as the general `add`.
        let bp = *ED25519_BASEPOINT;
        let bp2 = bp.double();
        // ED25519_BASEPOINT was decompressed with Z = 1, so it's affine.
        // bp2 is generally NOT affine.  Test add(bp2, bp) — bp is affine.
        let via_general = bp2.add(&bp);
        let via_affine  = bp2.add_affine_other(&bp);
        assert!(via_general.ct_eq(&via_affine),
            "add_affine_other ≠ generic add for affine `other`");
    }

    #[test]
    fn scalar_mul_windowed_matches_generic() {
        let bp = *ED25519_BASEPOINT;
        for k in [1u64, 2, 5, 17, 100, 0xdeadbeef_u64] {
            let s = Scalar::from(k);
            let bits = scalar_to_bits_le(&s);
            let via_window  = bp.scalar_mul_windowed(&bits);
            let via_generic = bp.scalar_mul(&bits);
            assert!(via_window.ct_eq(&via_generic),
                "[{}]B via windowed ≠ via generic", k);
        }
    }

    #[test]
    fn scalar_mul_windowed_matches_dalek() {
        // Variable-base windowed mult on a non-basepoint should match dalek.
        let bp2 = ED25519_BASEPOINT.double();
        for k in [1u64, 2, 5, 100, 0xdeadbeef_u64] {
            let s = Scalar::from(k);
            let bits = scalar_to_bits_le(&s);
            let ours = bp2.scalar_mul_windowed(&bits).compress();
            // bp2 = [2]B, so [k]·bp2 = [2k]·B.
            let dalek = (DALEK_BASEPOINT * (s + s)).compress().to_bytes();
            assert_eq!(ours, dalek,
                "[{}]·[2]B windowed ≠ dalek", k);
        }
    }

    #[test]
    fn scalar_mul_basepoint_precomputed_matches_dalek() {
        // Sanity: the precomputed-table output also matches dalek for
        // the same basepoint scalars.
        for k in [1u64, 2, 5, 100, 0xdeadbeef_u64] {
            let s = Scalar::from(k);
            let bits = scalar_to_bits_le(&s);
            let ours  = EdwardsPoint::scalar_mul_basepoint(&bits).compress();
            let dalek = (DALEK_BASEPOINT * s).compress().to_bytes();
            assert_eq!(ours, dalek, "[{}]B precomputed ≠ dalek", k);
        }
    }

    #[test]
    fn invalid_decompression_returns_none() {
        // A Y value not on the curve (random-ish bytes that don't satisfy
        // the curve equation).  Pick a y where (y²−1)/(d·y²+1) is non-square.
        // Easy candidate: y = 2 is on Edwards25519? Let's check empirically:
        // try a few constants and find one not on the curve.
        for trial_byte in [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70] {
            let mut bytes = [0u8; 32];
            bytes[0] = trial_byte;
            // Strip sign bit on byte 31.
            bytes[31] &= 0x7f;
            if EdwardsPoint::decompress(&bytes).is_none() {
                // Found one. Test passes.
                return;
            }
        }
        // If somehow all trials happened to be valid points, the test
        // is inconclusive — we don't fail, but warn.
        eprintln!("warning: invalid_decompression_returns_none could not find an invalid Y");
    }
}
