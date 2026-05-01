// p256_scalar_mul_air.rs — In-circuit scalar multiplication step gadget
// for ECDSA-P256.
//
// Phase 4 v0: a single-step "double-and-conditional-add" gadget that
// processes one bit of the scalar.  Composes one group-double + one
// group-add + three cond-selects (X, Y, Z components of the
// projective output).
//
// One step:  acc' = bit ? (2·acc + base) : 2·acc
//
// Cell budget: 33,144 (double) + 41,352 (add) + 3·271 (selects)
//              = 75,309 cells per step.
// Constraint budget: 34,318 + 42,636 + 3·281
//              = 77,797 constraints per step.
//
// For a full 256-bit scalar mult, the natural design is a multi-row
// state machine where each row hosts one step gadget; row N's output
// (acc') wires into row N+1's input (acc).  This single-row gadget
// is the building block; multi-row composition is Phase 4 v1.
//
// ─────────────────────────────────────────────────────────────────
// LAYOUT
// ─────────────────────────────────────────────────────────────────
//
// Inputs (referenced by limb-base offsets, not owned by this gadget):
//   acc_x_base, acc_y_base, acc_z_base   : current accumulator (X:Y:Z)
//   base_x_base, base_y_base, base_z_base: base point (X:Y:Z)
//   bit_cell                              : 1-bit selector ∈ {0, 1}
//
// Owned (allocated by build_scalar_mul_step_layout):
//   double_layout: GroupDoubleGadgetLayout (computes 2·acc)
//   add_layout: GroupAddGadgetLayout (computes 2·acc + base)
//   select_x, select_y, select_z: SelectGadgetLayout (multiplexes
//     between double and add outputs by `bit_cell`)
//
// Outputs: select_*.c_limbs_base — the new accumulator (X':Y':Z').

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::FieldElement;
use crate::p256_field_air::{
    eval_select_gadget, fill_select_gadget, SelectGadgetLayout,
};
use crate::p256_group_air::{
    build_group_add_layout, build_group_double_layout, eval_group_add_gadget,
    eval_group_double_gadget, fill_group_add_gadget, fill_group_double_gadget,
    group_add_gadget_constraints, group_double_gadget_constraints,
    GroupAddGadgetLayout, GroupDoubleGadgetLayout,
};

#[derive(Clone, Debug)]
pub struct ScalarMulStepGadgetLayout {
    pub acc_x_base: usize,
    pub acc_y_base: usize,
    pub acc_z_base: usize,
    pub base_x_base: usize,
    pub base_y_base: usize,
    pub base_z_base: usize,
    pub bit_cell: usize,

    pub double_layout: GroupDoubleGadgetLayout,
    pub add_layout: GroupAddGadgetLayout,
    pub select_x: SelectGadgetLayout,
    pub select_y: SelectGadgetLayout,
    pub select_z: SelectGadgetLayout,
}

/// Build a scalar-mul-step layout starting at `start`.  The bit_cell
/// is provided by the caller (typically allocated from the surrounding
/// state-machine row).
pub fn build_scalar_mul_step_layout(
    start: usize,
    acc_x_base: usize,
    acc_y_base: usize,
    acc_z_base: usize,
    base_x_base: usize,
    base_y_base: usize,
    base_z_base: usize,
    bit_cell: usize,
) -> (ScalarMulStepGadgetLayout, usize) {
    use crate::p256_field::{LIMB_BITS, NUM_LIMBS};
    use crate::p256_field_air::ELEMENT_BIT_CELLS;

    let mut cursor = start;

    // 1. group_double: computes 2·acc.
    let (double_layout, end1) =
        build_group_double_layout(cursor, acc_x_base, acc_y_base, acc_z_base);
    cursor = end1;
    let two_acc_x = double_layout.result_x3_limbs_base;
    let two_acc_y = double_layout.result_y3_limbs_base;
    let two_acc_z = double_layout.result_z3_limbs_base;

    // 2. group_add: computes 2·acc + base.
    let (add_layout, end2) = build_group_add_layout(
        cursor, two_acc_x, two_acc_y, two_acc_z, base_x_base, base_y_base, base_z_base,
    );
    cursor = end2;
    let added_x = add_layout.result_x3_limbs_base;
    let added_y = add_layout.result_y3_limbs_base;
    let added_z = add_layout.result_z3_limbs_base;

    // 3. Three cond-selects.  c = bit ? added : two_acc.
    //    The select gadget computes c = sel·a + (1-sel)·b.  We want
    //    c = bit ? added : two_acc, so a = added (taken when sel=1),
    //    b = two_acc (taken when sel=0).
    let bits_per_elem = NUM_LIMBS * (LIMB_BITS as usize);

    let select_x_c_limbs = cursor;
    let select_x_c_bits = select_x_c_limbs + NUM_LIMBS;
    cursor = select_x_c_bits + bits_per_elem;
    let select_x = SelectGadgetLayout {
        a_limbs_base: added_x,
        b_limbs_base: two_acc_x,
        c_limbs_base: select_x_c_limbs,
        c_bits_base: select_x_c_bits,
        sel_cell: bit_cell,
    };

    let select_y_c_limbs = cursor;
    let select_y_c_bits = select_y_c_limbs + NUM_LIMBS;
    cursor = select_y_c_bits + bits_per_elem;
    let select_y = SelectGadgetLayout {
        a_limbs_base: added_y,
        b_limbs_base: two_acc_y,
        c_limbs_base: select_y_c_limbs,
        c_bits_base: select_y_c_bits,
        sel_cell: bit_cell,
    };

    let select_z_c_limbs = cursor;
    let select_z_c_bits = select_z_c_limbs + NUM_LIMBS;
    cursor = select_z_c_bits + bits_per_elem;
    let select_z = SelectGadgetLayout {
        a_limbs_base: added_z,
        b_limbs_base: two_acc_z,
        c_limbs_base: select_z_c_limbs,
        c_bits_base: select_z_c_bits,
        sel_cell: bit_cell,
    };

    let layout = ScalarMulStepGadgetLayout {
        acc_x_base,
        acc_y_base,
        acc_z_base,
        base_x_base,
        base_y_base,
        base_z_base,
        bit_cell,
        double_layout,
        add_layout,
        select_x,
        select_y,
        select_z,
    };
    (layout, cursor)
}

/// Total constraints emitted per scalar-mul-step gadget.
pub fn scalar_mul_step_gadget_constraints(layout: &ScalarMulStepGadgetLayout) -> usize {
    use crate::p256_field_air::SELECT_GADGET_CONSTRAINTS;
    group_double_gadget_constraints(&layout.double_layout)
        + group_add_gadget_constraints(&layout.add_layout)
        + 3 * SELECT_GADGET_CONSTRAINTS
}

/// Fill the scalar-mul-step gadget.
///
/// Inputs are projective: acc = (acc_x : acc_y : acc_z), base similarly.
/// `bit` is the scalar bit being processed.
pub fn fill_scalar_mul_step_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &ScalarMulStepGadgetLayout,
    acc_x: &FieldElement,
    acc_y: &FieldElement,
    acc_z: &FieldElement,
    base_x: &FieldElement,
    base_y: &FieldElement,
    base_z: &FieldElement,
    bit: bool,
) {
    use ark_ff::PrimeField;

    // 1. Fill group_double.
    fill_group_double_gadget(
        trace, row, &layout.double_layout, acc_x, acc_y, acc_z,
    );

    // Read 2·acc back from trace cells.
    let read = |trace: &[Vec<F>], base: usize| -> FieldElement {
        use crate::p256_field::NUM_LIMBS;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };
    let two_acc_x = read(trace, layout.double_layout.result_x3_limbs_base);
    let two_acc_y = read(trace, layout.double_layout.result_y3_limbs_base);
    let two_acc_z = read(trace, layout.double_layout.result_z3_limbs_base);

    // 2. Fill group_add (2·acc + base).
    fill_group_add_gadget(
        trace, row, &layout.add_layout,
        &two_acc_x, &two_acc_y, &two_acc_z, base_x, base_y, base_z,
    );
    let added_x = read(trace, layout.add_layout.result_x3_limbs_base);
    let added_y = read(trace, layout.add_layout.result_y3_limbs_base);
    let added_z = read(trace, layout.add_layout.result_z3_limbs_base);

    // 3. Three selects: c = bit ? added : two_acc.
    fill_select_gadget(trace, row, &layout.select_x, &added_x, &two_acc_x, bit);
    fill_select_gadget(trace, row, &layout.select_y, &added_y, &two_acc_y, bit);
    fill_select_gadget(trace, row, &layout.select_z, &added_z, &two_acc_z, bit);
}

/// Emit all transition constraints for a scalar-mul-step gadget.
pub fn eval_scalar_mul_step_gadget(
    cur: &[F],
    layout: &ScalarMulStepGadgetLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(scalar_mul_step_gadget_constraints(layout));
    out.extend(eval_group_double_gadget(cur, &layout.double_layout));
    out.extend(eval_group_add_gadget(cur, &layout.add_layout));
    out.extend(eval_select_gadget(cur, &layout.select_x));
    out.extend(eval_select_gadget(cur, &layout.select_y));
    out.extend(eval_select_gadget(cur, &layout.select_z));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  K-STEP SCALAR-MUL CHAIN GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Composes K step gadgets in sequence, with row-style state passing:
// step[k]'s output (the new accumulator) wires into step[k+1]'s acc
// input bases.  All K steps share the same `base` input (the point
// being multiplied).  Each step has its own `bit_cell` for the
// corresponding bit of the scalar.
//
// This is the single-row analog of a multi-row scalar-mult AIR — it
// processes K consecutive bits within one trace row.  The full
// 256-bit scalar mult is the K=256 instance, which would be ~19M
// cells per row (impractical in single-row form, hence the multi-
// row state machine for production).  K=2..8 single-row instances
// are useful for testing the chain composition pattern.
//
// Layout: K instances of ScalarMulStepGadgetLayout with their input
// acc bases threaded through.

#[derive(Clone, Debug)]
pub struct ScalarMulChainGadgetLayout {
    pub initial_acc_x_base: usize,
    pub initial_acc_y_base: usize,
    pub initial_acc_z_base: usize,
    pub base_x_base: usize,
    pub base_y_base: usize,
    pub base_z_base: usize,
    pub bit_cells: Vec<usize>,
    pub steps: Vec<ScalarMulStepGadgetLayout>,
}

/// Build a K-step chain.  `bit_cells` must have length K.
pub fn build_scalar_mul_chain_layout(
    start: usize,
    initial_acc_x_base: usize,
    initial_acc_y_base: usize,
    initial_acc_z_base: usize,
    base_x_base: usize,
    base_y_base: usize,
    base_z_base: usize,
    bit_cells: Vec<usize>,
) -> (ScalarMulChainGadgetLayout, usize) {
    let mut cursor = start;
    let mut steps = Vec::with_capacity(bit_cells.len());
    let mut acc_x = initial_acc_x_base;
    let mut acc_y = initial_acc_y_base;
    let mut acc_z = initial_acc_z_base;
    for &bit_cell in &bit_cells {
        let (step, end) = build_scalar_mul_step_layout(
            cursor, acc_x, acc_y, acc_z, base_x_base, base_y_base, base_z_base, bit_cell,
        );
        cursor = end;
        // Next step's acc inputs = this step's select outputs.
        acc_x = step.select_x.c_limbs_base;
        acc_y = step.select_y.c_limbs_base;
        acc_z = step.select_z.c_limbs_base;
        steps.push(step);
    }
    (
        ScalarMulChainGadgetLayout {
            initial_acc_x_base,
            initial_acc_y_base,
            initial_acc_z_base,
            base_x_base,
            base_y_base,
            base_z_base,
            bit_cells,
            steps,
        },
        cursor,
    )
}

pub fn scalar_mul_chain_gadget_constraints(
    layout: &ScalarMulChainGadgetLayout,
) -> usize {
    layout
        .steps
        .iter()
        .map(scalar_mul_step_gadget_constraints)
        .sum()
}

/// Fill the K-step chain.  `bits` must have length K, MSB-first
/// relative to the scalar bit order (bits[0] is processed first).
pub fn fill_scalar_mul_chain_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &ScalarMulChainGadgetLayout,
    initial_acc_x: &FieldElement,
    initial_acc_y: &FieldElement,
    initial_acc_z: &FieldElement,
    base_x: &FieldElement,
    base_y: &FieldElement,
    base_z: &FieldElement,
    bits: &[bool],
) {
    use ark_ff::PrimeField;
    use crate::p256_field::NUM_LIMBS;

    assert_eq!(bits.len(), layout.steps.len());

    let read = |trace: &[Vec<F>], base: usize| -> FieldElement {
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };

    let mut acc_x = *initial_acc_x;
    let mut acc_y = *initial_acc_y;
    let mut acc_z = *initial_acc_z;

    for (k, step) in layout.steps.iter().enumerate() {
        fill_scalar_mul_step_gadget(
            trace, row, step, &acc_x, &acc_y, &acc_z, base_x, base_y, base_z,
            bits[k],
        );
        // Read the step's output as next step's acc.
        acc_x = read(trace, step.select_x.c_limbs_base);
        acc_y = read(trace, step.select_y.c_limbs_base);
        acc_z = read(trace, step.select_z.c_limbs_base);
    }
}

pub fn eval_scalar_mul_chain_gadget(
    cur: &[F],
    layout: &ScalarMulChainGadgetLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(scalar_mul_chain_gadget_constraints(layout));
    for step in &layout.steps {
        out.extend(eval_scalar_mul_step_gadget(cur, step));
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256_field::{FieldElement, NUM_LIMBS};
    use crate::p256_group::{AffinePoint, GENERATOR};

    fn make_trace_row(width: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); 1]).collect()
    }

    fn standalone_step_layout() -> (ScalarMulStepGadgetLayout, usize) {
        let acc_x = 0;
        let acc_y = NUM_LIMBS;
        let acc_z = 2 * NUM_LIMBS;
        let base_x = 3 * NUM_LIMBS;
        let base_y = 4 * NUM_LIMBS;
        let base_z = 5 * NUM_LIMBS;
        let bit_cell = 6 * NUM_LIMBS;
        let start = bit_cell + 1;
        let (layout, end) = build_scalar_mul_step_layout(
            start, acc_x, acc_y, acc_z, base_x, base_y, base_z, bit_cell,
        );
        (layout, end)
    }

    fn place_proj(
        trace: &mut [Vec<F>],
        x_base: usize,
        y_base: usize,
        z_base: usize,
        p: &AffinePoint,
    ) {
        assert!(!p.infinity);
        for i in 0..NUM_LIMBS {
            trace[x_base + i][0] = F::from(p.x.limbs[i] as u64);
            trace[y_base + i][0] = F::from(p.y.limbs[i] as u64);
        }
        trace[z_base + 0][0] = F::from(1u64);
        for i in 1..NUM_LIMBS {
            trace[z_base + i][0] = F::zero();
        }
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

    #[test]
    fn scalar_mul_step_layout_consistency() {
        let (_layout, _total) = standalone_step_layout();
        // Sanity: total > 75k (per-step cell budget).
        assert!(_total > 70_000);
        assert!(_total < 80_000);
    }

    #[test]
    fn scalar_mul_step_bit_zero_doubles() {
        // bit = 0: result = 2·acc (base ignored).
        let (layout, total) = standalone_step_layout();
        let mut trace = make_trace_row(total);
        let g = *GENERATOR;
        let two_g = g.double();
        place_proj(&mut trace, layout.acc_x_base, layout.acc_y_base, layout.acc_z_base, &g);
        place_proj(&mut trace, layout.base_x_base, layout.base_y_base, layout.base_z_base, &g);
        trace[layout.bit_cell][0] = F::zero();

        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        fill_scalar_mul_step_gadget(
            &mut trace, 0, &layout, &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, false,
        );

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_mul_step_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(nonzero, 0, "bit=0: {} constraints failed", nonzero);

        // Verify result == 2G via cross-multiply.
        let x = read_fe(&trace, layout.select_x.c_limbs_base);
        let y = read_fe(&trace, layout.select_y.c_limbs_base);
        let z = read_fe(&trace, layout.select_z.c_limbs_base);
        let lhs_x = canonicalise(&x);
        let rhs_x = canonicalise(&two_g.x.mul(&z));
        assert!(lhs_x.ct_eq(&rhs_x), "bit=0 X' ≠ 2G.x · Z'");
        let lhs_y = canonicalise(&y);
        let rhs_y = canonicalise(&two_g.y.mul(&z));
        assert!(lhs_y.ct_eq(&rhs_y), "bit=0 Y' ≠ 2G.y · Z'");
    }

    #[test]
    fn scalar_mul_step_bit_one_doubles_and_adds() {
        // bit = 1: result = 2·acc + base.  With acc = G, base = G,
        // result = 2G + G = 3G.
        let (layout, total) = standalone_step_layout();
        let mut trace = make_trace_row(total);
        let g = *GENERATOR;
        let two_g = g.double();
        let three_g = two_g.add(&g);
        place_proj(&mut trace, layout.acc_x_base, layout.acc_y_base, layout.acc_z_base, &g);
        place_proj(&mut trace, layout.base_x_base, layout.base_y_base, layout.base_z_base, &g);
        trace[layout.bit_cell][0] = F::one();

        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        fill_scalar_mul_step_gadget(
            &mut trace, 0, &layout, &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, true,
        );

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_mul_step_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(nonzero, 0, "bit=1: {} constraints failed", nonzero);

        // Verify result == 3G via cross-multiply.
        let x = read_fe(&trace, layout.select_x.c_limbs_base);
        let y = read_fe(&trace, layout.select_y.c_limbs_base);
        let z = read_fe(&trace, layout.select_z.c_limbs_base);
        let lhs_x = canonicalise(&x);
        let rhs_x = canonicalise(&three_g.x.mul(&z));
        assert!(lhs_x.ct_eq(&rhs_x), "bit=1 X' ≠ 3G.x · Z'");
        let lhs_y = canonicalise(&y);
        let rhs_y = canonicalise(&three_g.y.mul(&z));
        assert!(lhs_y.ct_eq(&rhs_y), "bit=1 Y' ≠ 3G.y · Z'");
    }

    // ─────────────────────────────────────────────────────────────────
    //  Chain gadget tests (multi-step composition)
    // ─────────────────────────────────────────────────────────────────

    fn standalone_chain_layout(num_bits: usize) -> (ScalarMulChainGadgetLayout, usize) {
        let acc_x = 0;
        let acc_y = NUM_LIMBS;
        let acc_z = 2 * NUM_LIMBS;
        let base_x = 3 * NUM_LIMBS;
        let base_y = 4 * NUM_LIMBS;
        let base_z = 5 * NUM_LIMBS;
        let bit_cells_start = 6 * NUM_LIMBS;
        let bit_cells: Vec<usize> = (0..num_bits)
            .map(|i| bit_cells_start + i)
            .collect();
        let start = bit_cells_start + num_bits;
        let (layout, end) = build_scalar_mul_chain_layout(
            start, acc_x, acc_y, acc_z, base_x, base_y, base_z, bit_cells,
        );
        (layout, end)
    }

    #[test]
    fn scalar_mul_chain_2_steps_g_to_7g() {
        // Start acc = G, base = G, bits = (1, 1) MSB-first.
        // Step 0: bit=1 → acc = 2G + G = 3G.
        // Step 1: bit=1 → acc = 2·3G + G = 7G.
        let (layout, total) = standalone_chain_layout(2);
        let mut trace = make_trace_row(total);
        let g = *GENERATOR;
        place_proj(
            &mut trace,
            layout.initial_acc_x_base,
            layout.initial_acc_y_base,
            layout.initial_acc_z_base,
            &g,
        );
        place_proj(
            &mut trace,
            layout.base_x_base,
            layout.base_y_base,
            layout.base_z_base,
            &g,
        );
        for &cell in &layout.bit_cells {
            trace[cell][0] = F::one();
        }

        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        fill_scalar_mul_chain_gadget(
            &mut trace, 0, &layout, &g.x, &g.y, &z_one, &g.x, &g.y, &z_one,
            &[true, true],
        );

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_mul_chain_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(nonzero, 0, "chain (1,1): {} constraints failed", nonzero);

        // Verify result = 7G.  Compute native 7G via doubling/adding.
        let two_g = g.double();
        let three_g = two_g.add(&g);
        let six_g = three_g.double();
        let seven_g = six_g.add(&g);

        let final_step = layout.steps.last().unwrap();
        let x = read_fe(&trace, final_step.select_x.c_limbs_base);
        let y = read_fe(&trace, final_step.select_y.c_limbs_base);
        let z = read_fe(&trace, final_step.select_z.c_limbs_base);
        let lhs_x = canonicalise(&x);
        let rhs_x = canonicalise(&seven_g.x.mul(&z));
        assert!(lhs_x.ct_eq(&rhs_x), "chain(1,1) X' ≠ 7G.x · Z'");
        let lhs_y = canonicalise(&y);
        let rhs_y = canonicalise(&seven_g.y.mul(&z));
        assert!(lhs_y.ct_eq(&rhs_y), "chain(1,1) Y' ≠ 7G.y · Z'");
    }

    #[test]
    fn scalar_mul_chain_2_steps_bits_1_0_gives_6g() {
        // Start acc = G, bits = (1, 0) MSB-first.
        // Step 0: bit=1 → acc = 3G.
        // Step 1: bit=0 → acc = 6G.
        let (layout, total) = standalone_chain_layout(2);
        let mut trace = make_trace_row(total);
        let g = *GENERATOR;
        place_proj(
            &mut trace,
            layout.initial_acc_x_base,
            layout.initial_acc_y_base,
            layout.initial_acc_z_base,
            &g,
        );
        place_proj(
            &mut trace,
            layout.base_x_base,
            layout.base_y_base,
            layout.base_z_base,
            &g,
        );
        trace[layout.bit_cells[0]][0] = F::one();
        trace[layout.bit_cells[1]][0] = F::zero();

        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        fill_scalar_mul_chain_gadget(
            &mut trace, 0, &layout, &g.x, &g.y, &z_one, &g.x, &g.y, &z_one,
            &[true, false],
        );

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_mul_chain_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(nonzero, 0, "chain (1,0): {} constraints failed", nonzero);

        // Result = 6G.
        let two_g = g.double();
        let three_g = two_g.add(&g);
        let six_g = three_g.double();

        let final_step = layout.steps.last().unwrap();
        let x = read_fe(&trace, final_step.select_x.c_limbs_base);
        let y = read_fe(&trace, final_step.select_y.c_limbs_base);
        let z = read_fe(&trace, final_step.select_z.c_limbs_base);
        let lhs_x = canonicalise(&x);
        let rhs_x = canonicalise(&six_g.x.mul(&z));
        assert!(lhs_x.ct_eq(&rhs_x), "chain(1,0) X' ≠ 6G.x · Z'");
        let lhs_y = canonicalise(&y);
        let rhs_y = canonicalise(&six_g.y.mul(&z));
        assert!(lhs_y.ct_eq(&rhs_y), "chain(1,0) Y' ≠ 6G.y · Z'");
    }
}
