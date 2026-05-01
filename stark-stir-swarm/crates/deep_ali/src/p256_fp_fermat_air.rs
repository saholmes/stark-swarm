// p256_fp_fermat_air.rs — Fp Fermat-style square-and-multiply.
//
// Computes z_inv = z^{p−2} mod p, equivalent to z^{−1} (Fermat).
// Used by the projective→affine conversion in ECDSA-P256 verify:
// after `R = u_1·G + u_2·Q` produces a projective (X3 : Y3 : Z3), the
// affine x is X3 · Z3^{−1}, and that x is then reduced mod n for the
// equality check `x mod n == r`.
//
// Each step processes one bit of the exponent (p−2) MSB-first:
//
//     acc' = (bit ? acc² · z : acc²)        (mod p)
//
// Per-step gadgets:
//   * square: mul_gadget computing acc² mod p  (a = b = acc)
//   * mul:    mul_gadget computing acc² · z mod p  (a = acc², b = z)
//   * select: per-limb cond-select between acc²·z and acc²
//
// Per-step budget:
//   2 · 1188 (mul) + 271 (select) = 2647 cells
//   2 · 1207 (mul) + 281 (select) = 2695 constraints
//
// For full Fp inversion (~256 bits of p−2), total ~677k cells and
// ~690k constraints — same shape as Fn Fermat (`p256_fermat_air`).

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::{FieldElement, LIMB_BITS, NUM_LIMBS};
use crate::p256_field_air::{
    eval_mul_gadget, eval_select_gadget, fill_mul_gadget, fill_select_gadget,
    MulGadgetLayout, SelectGadgetLayout, MUL_GADGET_CONSTRAINTS,
    SELECT_GADGET_CONSTRAINTS,
};

#[derive(Clone, Debug)]
pub struct FpFermatStepGadgetLayout {
    pub acc_base: usize,
    pub base_base: usize,
    pub bit_cell: usize,
    pub square_layout: MulGadgetLayout,
    pub mul_layout: MulGadgetLayout,
    pub select_layout: SelectGadgetLayout,
}

fn alloc_mul_layout(
    cursor: &mut usize,
    a_limbs_base: usize,
    b_limbs_base: usize,
) -> MulGadgetLayout {
    use crate::p256_field_air::{
        ELEMENT_BIT_CELLS, MUL_CARRY_BITS, MUL_CARRY_POSITIONS,
    };
    let c_limbs_base = *cursor;
    let c_bits_base = c_limbs_base + NUM_LIMBS;
    let q_limbs_base = c_bits_base + ELEMENT_BIT_CELLS;
    let q_bits_base = q_limbs_base + NUM_LIMBS;
    let carry_bits_base = q_bits_base + ELEMENT_BIT_CELLS;
    *cursor = carry_bits_base + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;
    MulGadgetLayout {
        a_limbs_base,
        b_limbs_base,
        c_limbs_base,
        c_bits_base,
        q_limbs_base,
        q_bits_base,
        carry_bits_base,
    }
}

fn alloc_select_layout(
    cursor: &mut usize,
    a_limbs_base: usize,
    b_limbs_base: usize,
    sel_cell: usize,
) -> SelectGadgetLayout {
    use crate::p256_field_air::ELEMENT_BIT_CELLS;
    let c_limbs_base = *cursor;
    let c_bits_base = c_limbs_base + NUM_LIMBS;
    *cursor = c_bits_base + ELEMENT_BIT_CELLS;
    SelectGadgetLayout {
        a_limbs_base,
        b_limbs_base,
        c_limbs_base,
        c_bits_base,
        sel_cell,
    }
}

pub fn build_fp_fermat_step_layout(
    start: usize,
    acc_base: usize,
    base_base: usize,
    bit_cell: usize,
) -> (FpFermatStepGadgetLayout, usize) {
    let mut cursor = start;
    let square_layout = alloc_mul_layout(&mut cursor, acc_base, acc_base);
    let mul_layout = alloc_mul_layout(
        &mut cursor, square_layout.c_limbs_base, base_base,
    );
    let select_layout = alloc_select_layout(
        &mut cursor, mul_layout.c_limbs_base, square_layout.c_limbs_base, bit_cell,
    );
    (
        FpFermatStepGadgetLayout {
            acc_base,
            base_base,
            bit_cell,
            square_layout,
            mul_layout,
            select_layout,
        },
        cursor,
    )
}

pub fn fp_fermat_step_gadget_constraints(_layout: &FpFermatStepGadgetLayout) -> usize {
    2 * MUL_GADGET_CONSTRAINTS + SELECT_GADGET_CONSTRAINTS
}

pub fn fill_fp_fermat_step_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &FpFermatStepGadgetLayout,
    acc: &FieldElement,
    base: &FieldElement,
    bit: bool,
) {
    use ark_ff::PrimeField;

    fill_mul_gadget(trace, row, &layout.square_layout, acc, acc);
    let read = |trace: &[Vec<F>], cell_base: usize| -> FieldElement {
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[cell_base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };
    let squared = read(trace, layout.square_layout.c_limbs_base);
    fill_mul_gadget(trace, row, &layout.mul_layout, &squared, base);
    let mulled = read(trace, layout.mul_layout.c_limbs_base);
    fill_select_gadget(trace, row, &layout.select_layout, &mulled, &squared, bit);
}

pub fn eval_fp_fermat_step_gadget(
    cur: &[F],
    layout: &FpFermatStepGadgetLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(fp_fermat_step_gadget_constraints(layout));
    out.extend(eval_mul_gadget(cur, &layout.square_layout));
    out.extend(eval_mul_gadget(cur, &layout.mul_layout));
    out.extend(eval_select_gadget(cur, &layout.select_layout));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  K-step Fp Fermat chain
// ═══════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct FpFermatChainGadgetLayout {
    pub initial_acc_base: usize,
    pub base_base: usize,
    pub bit_cells: Vec<usize>,
    pub steps: Vec<FpFermatStepGadgetLayout>,
}

pub fn build_fp_fermat_chain_layout(
    start: usize,
    initial_acc_base: usize,
    base_base: usize,
    bit_cells: Vec<usize>,
) -> (FpFermatChainGadgetLayout, usize) {
    let mut cursor = start;
    let mut steps = Vec::with_capacity(bit_cells.len());
    let mut acc_base = initial_acc_base;
    for &bit_cell in &bit_cells {
        let (step, end) = build_fp_fermat_step_layout(cursor, acc_base, base_base, bit_cell);
        cursor = end;
        acc_base = step.select_layout.c_limbs_base;
        steps.push(step);
    }
    (
        FpFermatChainGadgetLayout {
            initial_acc_base,
            base_base,
            bit_cells,
            steps,
        },
        cursor,
    )
}

pub fn fp_fermat_chain_gadget_constraints(
    layout: &FpFermatChainGadgetLayout,
) -> usize {
    layout.steps.iter().map(fp_fermat_step_gadget_constraints).sum()
}

pub fn fill_fp_fermat_chain_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &FpFermatChainGadgetLayout,
    initial_acc: &FieldElement,
    base: &FieldElement,
    bits: &[bool],
) {
    use ark_ff::PrimeField;

    assert_eq!(bits.len(), layout.steps.len());
    let mut acc = *initial_acc;
    for (k, step) in layout.steps.iter().enumerate() {
        fill_fp_fermat_step_gadget(trace, row, step, &acc, base, bits[k]);
        let read = |trace: &[Vec<F>], cell_base: usize| -> FieldElement {
            let mut limbs = [0i64; NUM_LIMBS];
            for i in 0..NUM_LIMBS {
                let v = trace[cell_base + i][row];
                let bi = v.into_bigint();
                limbs[i] = bi.as_ref()[0] as i64;
            }
            FieldElement { limbs }
        };
        acc = read(trace, step.select_layout.c_limbs_base);
    }
}

pub fn eval_fp_fermat_chain_gadget(
    cur: &[F],
    layout: &FpFermatChainGadgetLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(fp_fermat_chain_gadget_constraints(layout));
    for step in &layout.steps {
        out.extend(eval_fp_fermat_step_gadget(cur, step));
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace_row(width: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); 1]).collect()
    }

    /// 2-step Fp Fermat chain computing s³ mod p starting from acc=1
    /// with bits (1, 1).  For s = 7, result = 343.
    #[test]
    fn fp_fermat_chain_2_steps_computes_pow_3() {
        let acc_base = 0;
        let base_base = NUM_LIMBS;
        let bits_start = 2 * NUM_LIMBS;
        let bit_cells = vec![bits_start, bits_start + 1];
        let start = bits_start + 2;
        let (layout, total) =
            build_fp_fermat_chain_layout(start, acc_base, base_base, bit_cells);

        let mut trace = make_trace_row(total);
        let one = FieldElement::one();
        let mut seven = FieldElement::zero();
        seven.limbs[0] = 7;
        for i in 0..NUM_LIMBS {
            trace[layout.initial_acc_base + i][0] = F::from(one.limbs[i] as u64);
            trace[layout.base_base + i][0] = F::from(seven.limbs[i] as u64);
        }
        for &cell in &layout.bit_cells {
            trace[cell][0] = F::one();
        }

        fill_fp_fermat_chain_gadget(
            &mut trace, 0, &layout, &one, &seven, &[true, true],
        );

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_fp_fermat_chain_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(
            nonzero, 0,
            "fp_fermat chain (1,1): {} constraints failed",
            nonzero
        );

        // Verify result = 7³ = 343 (mod p, but 343 < p so equality is exact).
        use ark_ff::PrimeField;
        let final_step = layout.steps.last().unwrap();
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[final_step.select_layout.c_limbs_base + i][0];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        let mut actual = FieldElement { limbs };
        actual.freeze();
        let mut expected = FieldElement::zero();
        expected.limbs[0] = 343;
        assert_eq!(actual.limbs, expected.limbs, "Fp 7³ ≠ 343");
    }

    /// Single Fp Fermat step (bit = 1) computing acc² · base.
    /// With acc = 3, base = 5: result = 9 · 5 = 45 mod p.
    #[test]
    fn fp_fermat_step_bit_one_squares_then_mults() {
        let acc_base = 0;
        let base_base = NUM_LIMBS;
        let bit_cell = 2 * NUM_LIMBS;
        let start = bit_cell + 1;
        let (layout, total) =
            build_fp_fermat_step_layout(start, acc_base, base_base, bit_cell);

        let mut trace = make_trace_row(total);
        let mut three = FieldElement::zero();
        three.limbs[0] = 3;
        let mut five = FieldElement::zero();
        five.limbs[0] = 5;
        for i in 0..NUM_LIMBS {
            trace[acc_base + i][0] = F::from(three.limbs[i] as u64);
            trace[base_base + i][0] = F::from(five.limbs[i] as u64);
        }
        trace[bit_cell][0] = F::one();

        fill_fp_fermat_step_gadget(&mut trace, 0, &layout, &three, &five, true);

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_fp_fermat_step_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(nonzero, 0, "Fp fermat step bit=1: {} constraints failed", nonzero);

        use ark_ff::PrimeField;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[layout.select_layout.c_limbs_base + i][0];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        let mut actual = FieldElement { limbs };
        actual.freeze();
        let mut expected = FieldElement::zero();
        expected.limbs[0] = 45;
        assert_eq!(actual.limbs, expected.limbs, "Fp 3² · 5 ≠ 45");
    }
}
