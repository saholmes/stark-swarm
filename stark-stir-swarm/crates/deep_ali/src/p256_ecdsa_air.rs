// p256_ecdsa_air.rs — Top-level ECDSA-P256 verify AIR composition.
//
// Phase 5 v0: a simplified top-level verify gadget that composes the
// existing curve-level gadgets into the core of an ECDSA verification.
//
// Simplification: this demo takes the *pre-computed* scalars u_1 and
// u_2 (caller-supplied) rather than deriving them from the digest e
// and the inverse w = s⁻¹.  In a complete top-level AIR, u_1 and u_2
// would be produced by:
//   * one Fn-reduction gadget for e = digest mod n,
//   * one Fermat-style inversion for w = s^{n-2} mod n (~256
//     scalar-mul gadget instances),
//   * two scalar-mul gadgets for u_1 = e·w and u_2 = r·w.
// All of these compose from existing primitives (scalar_mul_gadget,
// scalar_freeze_gadget); the inversion is the bulk and is omitted
// here for tractable trace size.
//
// What this demo does:
//   1. Compute u_1·G  via a K-step scalar-mult chain (base = G).
//   2. Compute u_2·Q  via a K-step scalar-mult chain (base = Q).
//   3. Add the two results: R = u_1·G + u_2·Q.
//   4. Reduce R.x mod n via a scalar_mul_gadget with b = 1 (Fn).
//   5. Compare R.x_mod_n to r.
//
// For K = 2, the gadget uses ~360k cells / ~370k constraints — large
// but tractable, demonstrating that the top-level composition is
// mechanical given the validated underlying gadgets.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::{FieldElement, LIMB_BITS, NUM_LIMBS};
use crate::p256_field_air::ELEMENT_BIT_CELLS;
use crate::p256_group_air::{
    build_group_add_layout, eval_group_add_gadget, fill_group_add_gadget,
    group_add_gadget_constraints, GroupAddGadgetLayout,
};
use crate::p256_scalar::ScalarElement;
use crate::p256_scalar_air::{
    eval_scalar_eq_gadget, eval_scalar_mul_gadget, fill_scalar_mul_gadget,
    ScalarEqGadgetLayout, ScalarMulGadgetLayout, SCALAR_EQ_GADGET_CONSTRAINTS,
    SCALAR_MUL_GADGET_CONSTRAINTS,
};
use crate::p256_scalar_mul_air::{
    build_scalar_mul_chain_layout, eval_scalar_mul_chain_gadget,
    fill_scalar_mul_chain_gadget, scalar_mul_chain_gadget_constraints,
    ScalarMulChainGadgetLayout,
};

#[derive(Clone, Debug)]
pub struct EcdsaVerifyDemoLayout {
    /// Generator G coordinates (input cells, X:Y:1).
    pub g_x_base: usize,
    pub g_y_base: usize,
    pub g_z_base: usize,
    /// Public key Q coordinates.
    pub q_x_base: usize,
    pub q_y_base: usize,
    pub q_z_base: usize,
    /// u_1 scalar bits (MSB first).
    pub u1_bit_cells: Vec<usize>,
    /// u_2 scalar bits (MSB first).
    pub u2_bit_cells: Vec<usize>,
    /// Chain gadgets.
    pub u1_g_chain: ScalarMulChainGadgetLayout,
    pub u2_q_chain: ScalarMulChainGadgetLayout,
    /// Final point addition.
    pub final_add: GroupAddGadgetLayout,
    /// Cells for the constant scalar 1 (operand of the R.x mod n
    /// reduction).  The reduction is computed as R.x · 1 = q·n + c
    /// via a scalar_mul gadget; with b = 1 and the witness q chosen
    /// correctly, c = R.x mod n.
    pub scalar_one_base: usize,
    /// Scalar mul gadget that reduces R.x mod n.  Output cell base
    /// (`r_x_mod_n_layout.c_limbs_base`) holds R.x mod n.
    pub r_x_mod_n_layout: ScalarMulGadgetLayout,
    /// Cells where the caller places the signature's `r` scalar
    /// (10 limbs in canonical form).
    pub r_input_base: usize,
    /// Equality-check gadget that asserts R.x mod n == r.
    pub r_eq_layout: ScalarEqGadgetLayout,
}

/// Build the top-level layout.  K is the bit-length of u_1 and u_2.
pub fn build_ecdsa_verify_demo_layout(
    start: usize,
    g_x_base: usize,
    g_y_base: usize,
    g_z_base: usize,
    q_x_base: usize,
    q_y_base: usize,
    q_z_base: usize,
    k: usize,
) -> (EcdsaVerifyDemoLayout, usize) {
    let mut cursor = start;

    // Bit cells for u_1 and u_2.
    let u1_bit_cells: Vec<usize> = (0..k).map(|i| cursor + i).collect();
    cursor += k;
    let u2_bit_cells: Vec<usize> = (0..k).map(|i| cursor + i).collect();
    cursor += k;

    // u_1 · G chain.  Initial acc = G (first non-zero bit assumption).
    let (u1_g_chain, end1) = build_scalar_mul_chain_layout(
        cursor, g_x_base, g_y_base, g_z_base, g_x_base, g_y_base, g_z_base,
        u1_bit_cells.clone(),
    );
    cursor = end1;

    // u_2 · Q chain.  Initial acc = Q.
    let (u2_q_chain, end2) = build_scalar_mul_chain_layout(
        cursor, q_x_base, q_y_base, q_z_base, q_x_base, q_y_base, q_z_base,
        u2_bit_cells.clone(),
    );
    cursor = end2;

    // Final point addition: R = (u_1·G result) + (u_2·Q result).
    let u1g_x = u1_g_chain.steps.last().unwrap().select_x.c_limbs_base;
    let u1g_y = u1_g_chain.steps.last().unwrap().select_y.c_limbs_base;
    let u1g_z = u1_g_chain.steps.last().unwrap().select_z.c_limbs_base;
    let u2q_x = u2_q_chain.steps.last().unwrap().select_x.c_limbs_base;
    let u2q_y = u2_q_chain.steps.last().unwrap().select_y.c_limbs_base;
    let u2q_z = u2_q_chain.steps.last().unwrap().select_z.c_limbs_base;

    let (final_add, end3) = build_group_add_layout(
        cursor, u1g_x, u1g_y, u1g_z, u2q_x, u2q_y, u2q_z,
    );
    cursor = end3;

    // Allocate cells for the constant "1" operand (10 limbs, no bits
    // — the scalar_mul gadget doesn't range-check inputs, only its
    // own output and quotient).
    let scalar_one_base = cursor;
    cursor += NUM_LIMBS;

    // Scalar-mul gadget that computes R.x mod n.
    // Inputs: a = R.x (= final_add.result_x3_limbs_base), b = 1.
    // Output c = R.x mod n.
    use crate::p256_field_air::{MUL_CARRY_BITS, MUL_CARRY_POSITIONS};
    let bits_per_elem = NUM_LIMBS * (LIMB_BITS as usize);
    let r_x_mod_n_c_limbs = cursor;
    let r_x_mod_n_c_bits = r_x_mod_n_c_limbs + NUM_LIMBS;
    let r_x_mod_n_q_limbs = r_x_mod_n_c_bits + bits_per_elem;
    let r_x_mod_n_q_bits = r_x_mod_n_q_limbs + NUM_LIMBS;
    let r_x_mod_n_carry_bits = r_x_mod_n_q_bits + bits_per_elem;
    cursor = r_x_mod_n_carry_bits + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;
    let r_x_mod_n_layout = ScalarMulGadgetLayout {
        a_limbs_base: final_add.result_x3_limbs_base,
        b_limbs_base: scalar_one_base,
        c_limbs_base: r_x_mod_n_c_limbs,
        c_bits_base: r_x_mod_n_c_bits,
        q_limbs_base: r_x_mod_n_q_limbs,
        q_bits_base: r_x_mod_n_q_bits,
        carry_bits_base: r_x_mod_n_carry_bits,
    };

    // Allocate input cells for the signature `r` (10 limbs only).
    let r_input_base = cursor;
    cursor += NUM_LIMBS;

    // Equality-check gadget: a = R.x mod n, b = r.
    let r_eq_layout = ScalarEqGadgetLayout {
        a_limbs_base: r_x_mod_n_c_limbs,
        b_limbs_base: r_input_base,
    };

    (
        EcdsaVerifyDemoLayout {
            g_x_base,
            g_y_base,
            g_z_base,
            q_x_base,
            q_y_base,
            q_z_base,
            u1_bit_cells,
            u2_bit_cells,
            u1_g_chain,
            u2_q_chain,
            final_add,
            scalar_one_base,
            r_x_mod_n_layout,
            r_input_base,
            r_eq_layout,
        },
        cursor,
    )
}

pub fn ecdsa_verify_demo_constraints(layout: &EcdsaVerifyDemoLayout) -> usize {
    scalar_mul_chain_gadget_constraints(&layout.u1_g_chain)
        + scalar_mul_chain_gadget_constraints(&layout.u2_q_chain)
        + group_add_gadget_constraints(&layout.final_add)
        + SCALAR_MUL_GADGET_CONSTRAINTS
        + SCALAR_EQ_GADGET_CONSTRAINTS
}

/// Fill the demo layout for given inputs, including the signature
/// component `r` (caller-supplied scalar that should equal R.x mod n
/// for a valid signature).
pub fn fill_ecdsa_verify_demo(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &EcdsaVerifyDemoLayout,
    g_x: &FieldElement,
    g_y: &FieldElement,
    q_x: &FieldElement,
    q_y: &FieldElement,
    u1_bits: &[bool],
    u2_bits: &[bool],
    r: &ScalarElement,
) {
    use ark_ff::PrimeField;

    let z_one = {
        let mut t = FieldElement::zero();
        t.limbs[0] = 1;
        t
    };

    // Place G and Q at their input bases.
    place_proj(
        trace, row, layout.g_x_base, layout.g_y_base, layout.g_z_base, g_x, g_y, &z_one,
    );
    place_proj(
        trace, row, layout.q_x_base, layout.q_y_base, layout.q_z_base, q_x, q_y, &z_one,
    );

    // Place bit cells.
    for (i, &bit) in u1_bits.iter().enumerate() {
        trace[layout.u1_bit_cells[i]][row] = F::from(bit as u64);
    }
    for (i, &bit) in u2_bits.iter().enumerate() {
        trace[layout.u2_bit_cells[i]][row] = F::from(bit as u64);
    }

    // 1. u_1 · G chain.
    fill_scalar_mul_chain_gadget(
        trace, row, &layout.u1_g_chain, g_x, g_y, &z_one, g_x, g_y, &z_one, u1_bits,
    );

    // 2. u_2 · Q chain.
    fill_scalar_mul_chain_gadget(
        trace, row, &layout.u2_q_chain, q_x, q_y, &z_one, q_x, q_y, &z_one, u2_bits,
    );

    // 3. Read both chain results, fill final group_add.
    let read = |trace: &[Vec<F>], base: usize| -> FieldElement {
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };
    let u1g = layout.u1_g_chain.steps.last().unwrap();
    let u2q = layout.u2_q_chain.steps.last().unwrap();
    let r1_x = read(trace, u1g.select_x.c_limbs_base);
    let r1_y = read(trace, u1g.select_y.c_limbs_base);
    let r1_z = read(trace, u1g.select_z.c_limbs_base);
    let r2_x = read(trace, u2q.select_x.c_limbs_base);
    let r2_y = read(trace, u2q.select_y.c_limbs_base);
    let r2_z = read(trace, u2q.select_z.c_limbs_base);

    fill_group_add_gadget(
        trace, row, &layout.final_add,
        &r1_x, &r1_y, &r1_z, &r2_x, &r2_y, &r2_z,
    );

    // 4. Place constant 1 at scalar_one_base.
    trace[layout.scalar_one_base + 0][row] = F::from(1u64);
    for i in 1..NUM_LIMBS {
        trace[layout.scalar_one_base + i][row] = F::zero();
    }

    // 5. Read R.x and feed to scalar_mul gadget for R.x mod n.
    // R.x's limbs are in [0, 2^26) (range-checked by group_add).  We
    // re-interpret the same cells as a ScalarElement.
    let r_x = read(trace, layout.final_add.result_x3_limbs_base);
    let r_x_se = ScalarElement { limbs: r_x.limbs };
    let one_se = ScalarElement::one();
    fill_scalar_mul_gadget(
        trace, row, &layout.r_x_mod_n_layout, &r_x_se, &one_se,
    );

    // 6. Place the signature's `r` at r_input_base for the equality
    // check (gadget owns no cells; it just enforces a == b).
    let mut r_canonical = *r;
    r_canonical.freeze();
    for i in 0..NUM_LIMBS {
        trace[layout.r_input_base + i][row] = F::from(r_canonical.limbs[i] as u64);
    }
}

/// Emit all constraints.
pub fn eval_ecdsa_verify_demo(
    cur: &[F],
    layout: &EcdsaVerifyDemoLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(ecdsa_verify_demo_constraints(layout));
    out.extend(eval_scalar_mul_chain_gadget(cur, &layout.u1_g_chain));
    out.extend(eval_scalar_mul_chain_gadget(cur, &layout.u2_q_chain));
    out.extend(eval_group_add_gadget(cur, &layout.final_add));
    out.extend(eval_scalar_mul_gadget(cur, &layout.r_x_mod_n_layout));
    out.extend(eval_scalar_eq_gadget(cur, &layout.r_eq_layout));
    out
}

/// Place an affine point (x, y, z=1) at the given limb bases.
fn place_proj(
    trace: &mut [Vec<F>],
    row: usize,
    x_base: usize,
    y_base: usize,
    z_base: usize,
    x: &FieldElement,
    y: &FieldElement,
    z: &FieldElement,
) {
    for i in 0..NUM_LIMBS {
        trace[x_base + i][row] = F::from(x.limbs[i] as u64);
        trace[y_base + i][row] = F::from(y.limbs[i] as u64);
        trace[z_base + i][row] = F::from(z.limbs[i] as u64);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256_field::FieldElement;
    use crate::p256_group::{AffinePoint, GENERATOR};

    fn make_trace_row(width: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); 1]).collect()
    }

    fn read_fe(trace: &[Vec<F>], base: usize) -> FieldElement {
        use ark_ff::PrimeField;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][0];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    }

    fn canonicalise(fe: &FieldElement) -> FieldElement {
        let mut t = *fe;
        t.freeze();
        t
    }

    /// Compose u_1 · G + u_2 · Q for K = 2 with public key Q = 2·G.
    /// Tests the top-level gadget structure end-to-end.
    #[test]
    fn ecdsa_verify_demo_k2_constraints_satisfied() {
        // Layout offsets.
        let g_x = 0;
        let g_y = NUM_LIMBS;
        let g_z = 2 * NUM_LIMBS;
        let q_x = 3 * NUM_LIMBS;
        let q_y = 4 * NUM_LIMBS;
        let q_z = 5 * NUM_LIMBS;
        let start = 6 * NUM_LIMBS;
        let (layout, total) = build_ecdsa_verify_demo_layout(
            start, g_x, g_y, g_z, q_x, q_y, q_z, /* k = */ 2,
        );

        let mut trace = make_trace_row(total);
        let g = *GENERATOR;
        let q_point = g.double(); // Q = 2G

        // Bits for u_1 = (1,1)b, u_2 = (1,0)b — small concrete scalars.
        // u_1 chain start acc = G, base = G:  G → 3G → 7G.
        // u_2 chain start acc = Q (= 2G), base = Q (= 2G):  2G → 6G → 12G.
        // R = 7G + 12G = 19G.
        let u1_bits = [true, true];
        let u2_bits = [true, false];

        // First pass: fill with dummy r = 0 to have the gadget compute
        // R.x mod n.  Note the gadget reduces the *projective* X3 mod n,
        // not the affine x mod n; converting from projective to affine
        // requires a Z^{-1} inversion gadget that's the natural next
        // composition piece (Phase 5 v2).  For this demo we treat
        // R.x_mod_n as the gadget-output value and use it as the
        // "signature r" — tautological consistency, exercising the
        // equality-check gadget end-to-end.
        let zero_scalar = ScalarElement::zero();
        fill_ecdsa_verify_demo(
            &mut trace, 0, &layout, &g.x, &g.y, &q_point.x, &q_point.y, &u1_bits, &u2_bits,
            &zero_scalar,
        );

        // Read the gadget-computed R.x mod n.
        let r_x_mod_n_fe = read_fe(&trace, layout.r_x_mod_n_layout.c_limbs_base);
        // Overwrite r_input cells with the same value so the equality
        // check passes.
        for i in 0..NUM_LIMBS {
            trace[layout.r_input_base + i][0] = F::from(r_x_mod_n_fe.limbs[i] as u64);
        }

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_ecdsa_verify_demo(&cur, &layout);
        assert_eq!(cons.len(), ecdsa_verify_demo_constraints(&layout));
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(
            nonzero, 0,
            "ecdsa_verify_demo K=2: {} constraints failed",
            nonzero
        );

        // Verify R = 19G via cross-multiply.
        // u_1 chain bits (1,1) starting from G with base G → 7G.
        // u_2 chain bits (1,0) starting from 2G with base 2G:
        //   step 0 (bit=1): acc = 2·(2G) + 2G = 6G.
        //   step 1 (bit=0): acc = 2·6G = 12G.
        // R = 7G + 12G = 19G.
        let g = *GENERATOR;
        // Compute 19G via repeated doubling and addition.
        let two_g = g.double();
        let three_g = two_g.add(&g);
        let four_g = three_g.add(&g);
        let seven_g = four_g.add(&three_g);
        let twelve_g = seven_g.add(&four_g).add(&g);
        let nineteen_g = seven_g.add(&twelve_g);
        assert!(!nineteen_g.infinity);

        let r_x = read_fe(&trace, layout.final_add.result_x3_limbs_base);
        let r_y = read_fe(&trace, layout.final_add.result_y3_limbs_base);
        let r_z = read_fe(&trace, layout.final_add.result_z3_limbs_base);

        let lhs_x = canonicalise(&r_x);
        let rhs_x = canonicalise(&nineteen_g.x.mul(&r_z));
        assert!(lhs_x.ct_eq(&rhs_x), "R.x ≠ 19G.x · R.z");
        let lhs_y = canonicalise(&r_y);
        let rhs_y = canonicalise(&nineteen_g.y.mul(&r_z));
        assert!(lhs_y.ct_eq(&rhs_y), "R.y ≠ 19G.y · R.z");

        // Verify the R.x mod n reduction step.
        // The gadget reduced R.x (an Fp element) modulo n.  Compare
        // against the native scalar reduction of R.x's bytes.
        let r_x_mod_n_canonical = read_fe(&trace, layout.r_x_mod_n_layout.c_limbs_base);
        let r_x_mod_n_canonical = canonicalise(&r_x_mod_n_canonical);
        // Native: take r_x's canonical bytes, decode as ScalarElement
        // (which reduces mod n via from_be_bytes).
        let mut r_x_canonical = r_x;
        r_x_canonical.freeze();
        let r_x_bytes = r_x_canonical.to_be_bytes();
        let mut native_r_x_mod_n = ScalarElement::from_be_bytes(&r_x_bytes);
        native_r_x_mod_n.freeze();
        // The gadget output is FieldElement-shaped but the integer
        // value is the scalar.  Compare limb-by-limb.
        assert_eq!(
            r_x_mod_n_canonical.limbs, native_r_x_mod_n.limbs,
            "R.x mod n via gadget ≠ native reduction"
        );
    }

    /// K=4 scaling test.  Validates that the K-step chain composition
    /// scales beyond the K=2 demo: u_1·G with bits (1,1,1,1) starting
    /// from G should produce 31G, and u_2·Q (Q=2G) with bits
    /// (1,1,1,1) from Q produces 62G.  R = 31G + 62G = 93G.
    /// Trace total ≈ 690k cells, ≈710k constraints — exercises the
    /// gadget chain at 2× the K=2 size.
    #[test]
    fn ecdsa_verify_demo_k4_scales() {
        let g_x = 0;
        let g_y = NUM_LIMBS;
        let g_z = 2 * NUM_LIMBS;
        let q_x = 3 * NUM_LIMBS;
        let q_y = 4 * NUM_LIMBS;
        let q_z = 5 * NUM_LIMBS;
        let start = 6 * NUM_LIMBS;
        let (layout, total) = build_ecdsa_verify_demo_layout(
            start, g_x, g_y, g_z, q_x, q_y, q_z, /* k = */ 4,
        );

        let mut trace = make_trace_row(total);
        let g = *GENERATOR;
        let q_point = g.double();

        // u_1 chain bits (1,1,1,1): G → 3G → 7G → 15G → 31G.
        // u_2 chain bits (1,1,1,1) from Q=2G:
        //   step 0: 4G + 2G = 6G
        //   step 1: 12G + 2G = 14G
        //   step 2: 28G + 2G = 30G
        //   step 3: 60G + 2G = 62G
        // R = 31G + 62G = 93G.
        let u1_bits = [true, true, true, true];
        let u2_bits = [true, true, true, true];
        let zero_scalar = ScalarElement::zero();

        fill_ecdsa_verify_demo(
            &mut trace, 0, &layout, &g.x, &g.y, &q_point.x, &q_point.y,
            &u1_bits, &u2_bits, &zero_scalar,
        );

        // Make r_input match the gadget's R.x mod n output (tautological
        // equality — the affine-conversion semantics requires Z⁻¹ which
        // the next demo iteration adds).
        let r_x_mod_n_fe = read_fe(&trace, layout.r_x_mod_n_layout.c_limbs_base);
        for i in 0..NUM_LIMBS {
            trace[layout.r_input_base + i][0] = F::from(r_x_mod_n_fe.limbs[i] as u64);
        }

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_ecdsa_verify_demo(&cur, &layout);
        assert_eq!(cons.len(), ecdsa_verify_demo_constraints(&layout));
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(
            nonzero, 0,
            "ecdsa_verify_demo K=4: {} constraints failed",
            nonzero
        );

        // Verify R = 93G via projective cross-multiply.
        let two_g = g.double();
        let four_g = two_g.double();
        let eight_g = four_g.double();
        let sixteen_g = eight_g.double();
        let thirty_two_g = sixteen_g.double();
        let sixty_four_g = thirty_two_g.double();
        let thirty_one_g = sixteen_g.add(&eight_g).add(&four_g).add(&two_g).add(&g);
        let sixty_two_g = thirty_two_g.add(&sixteen_g).add(&eight_g).add(&four_g).add(&two_g);
        let ninety_three_g = thirty_one_g.add(&sixty_two_g);
        assert!(!ninety_three_g.infinity);

        // Sanity check: 93 = 31 + 62.  And 64 + 32 - 3 = 93. Use the latter:
        // 64G - G = 63G; 63G + 30G = 93G.  Or simpler: 32G + 64G - 3G = 93G.
        // Just trust 31G + 62G = 93G and compare.
        let r_x = read_fe(&trace, layout.final_add.result_x3_limbs_base);
        let r_y = read_fe(&trace, layout.final_add.result_y3_limbs_base);
        let r_z = read_fe(&trace, layout.final_add.result_z3_limbs_base);
        let lhs_x = canonicalise(&r_x);
        let rhs_x = canonicalise(&ninety_three_g.x.mul(&r_z));
        assert!(lhs_x.ct_eq(&rhs_x), "K=4 R.x ≠ 93G.x · R.z");
        let lhs_y = canonicalise(&r_y);
        let rhs_y = canonicalise(&ninety_three_g.y.mul(&r_z));
        assert!(lhs_y.ct_eq(&rhs_y), "K=4 R.y ≠ 93G.y · R.z");

        // Sanity that the trace is bigger than K=2.
        let (_l2, total2) = build_ecdsa_verify_demo_layout(
            start, g_x, g_y, g_z, q_x, q_y, q_z, /* k = */ 2,
        );
        assert!(total > total2 + 100_000,
            "K=4 trace must be substantially bigger than K=2 (by ~2x scalar-mult-step block)");
        // sixty_four_g unused; suppress warning.
        let _ = sixty_four_g;
    }
}
