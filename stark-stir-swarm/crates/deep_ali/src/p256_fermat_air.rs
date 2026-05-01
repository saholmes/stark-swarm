// p256_fermat_air.rs — Fn Fermat inversion via square-and-multiply.
//
// Computes w = s^{n−2} mod n, equivalent to s^{−1} (Fermat).  Used by
// ECDSA verification to invert the signature scalar s.
//
// Each step processes one bit of the exponent (n−2) MSB-first:
//
//     acc' = (bit ? acc² · s : acc²)        (mod n)
//
// Per-step gadgets:
//   * square: scalar_mul_gadget computing acc² mod n  (a = b = acc)
//   * mul:    scalar_mul_gadget computing acc² · s mod n  (a = acc², b = s)
//   * select: per-limb cond-select between acc²·s and acc²
//
// Per-step budget:
//   2 · 1188 (mul) + 271 (select) = 2647 cells
//   2 · 1207 (mul) + 281 (select) = 2695 constraints
//
// For full inversion (~256 bits of n−2), total ~677k cells and
// ~690k constraints — modest compared to the scalar-mult chains
// (which are ~75k cells per step, ~19M total for K=256).
//
// This file delivers the per-step "Fermat step" gadget plus a K-step
// chain that demonstrates composition.  Used in tests with small K
// to validate; full Fermat is the K=256 instance.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::{LIMB_BITS, NUM_LIMBS};
use crate::p256_field_air::{
    eval_select_gadget, fill_select_gadget, SelectGadgetLayout,
    SELECT_GADGET_CONSTRAINTS,
};
use crate::p256_scalar::ScalarElement;
use crate::p256_scalar_air::{
    eval_scalar_mul_gadget, fill_scalar_mul_gadget, ScalarMulGadgetLayout,
    SCALAR_MUL_GADGET_CONSTRAINTS,
};

#[derive(Clone, Debug)]
pub struct FermatStepGadgetLayout {
    pub acc_base: usize,
    pub base_base: usize,
    pub bit_cell: usize,
    pub square_layout: ScalarMulGadgetLayout,
    pub mul_layout: ScalarMulGadgetLayout,
    pub select_layout: SelectGadgetLayout,
}

/// Allocate cells for a scalar_mul_gadget instance.
fn alloc_scalar_mul_layout(
    cursor: &mut usize,
    a_limbs_base: usize,
    b_limbs_base: usize,
) -> ScalarMulGadgetLayout {
    use crate::p256_field_air::{
        ELEMENT_BIT_CELLS, MUL_CARRY_BITS, MUL_CARRY_POSITIONS,
    };
    let c_limbs_base = *cursor;
    let c_bits_base = c_limbs_base + NUM_LIMBS;
    let q_limbs_base = c_bits_base + ELEMENT_BIT_CELLS;
    let q_bits_base = q_limbs_base + NUM_LIMBS;
    let carry_bits_base = q_bits_base + ELEMENT_BIT_CELLS;
    *cursor = carry_bits_base + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;
    ScalarMulGadgetLayout {
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

pub fn build_fermat_step_layout(
    start: usize,
    acc_base: usize,
    base_base: usize,
    bit_cell: usize,
) -> (FermatStepGadgetLayout, usize) {
    let mut cursor = start;
    let square_layout = alloc_scalar_mul_layout(&mut cursor, acc_base, acc_base);
    let mul_layout = alloc_scalar_mul_layout(
        &mut cursor, square_layout.c_limbs_base, base_base,
    );
    let select_layout = alloc_select_layout(
        &mut cursor, mul_layout.c_limbs_base, square_layout.c_limbs_base, bit_cell,
    );
    (
        FermatStepGadgetLayout {
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

pub fn fermat_step_gadget_constraints(_layout: &FermatStepGadgetLayout) -> usize {
    2 * SCALAR_MUL_GADGET_CONSTRAINTS + SELECT_GADGET_CONSTRAINTS
}

pub fn fill_fermat_step_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &FermatStepGadgetLayout,
    acc: &ScalarElement,
    base: &ScalarElement,
    bit: bool,
) {
    use ark_ff::PrimeField;
    use crate::p256_field::FieldElement;

    fill_scalar_mul_gadget(trace, row, &layout.square_layout, acc, acc);
    let read = |trace: &[Vec<F>], cell_base: usize| -> ScalarElement {
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[cell_base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        ScalarElement { limbs }
    };
    let squared = read(trace, layout.square_layout.c_limbs_base);
    fill_scalar_mul_gadget(trace, row, &layout.mul_layout, &squared, base);
    let mulled = read(trace, layout.mul_layout.c_limbs_base);

    // Select: c = bit ? mulled : squared.  Convert to FieldElement
    // wrapping for select fill (modulus-independent gadget).
    let mulled_fe = FieldElement { limbs: mulled.limbs };
    let squared_fe = FieldElement { limbs: squared.limbs };
    fill_select_gadget(trace, row, &layout.select_layout, &mulled_fe, &squared_fe, bit);
}

pub fn eval_fermat_step_gadget(cur: &[F], layout: &FermatStepGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(fermat_step_gadget_constraints(layout));
    out.extend(eval_scalar_mul_gadget(cur, &layout.square_layout));
    out.extend(eval_scalar_mul_gadget(cur, &layout.mul_layout));
    out.extend(eval_select_gadget(cur, &layout.select_layout));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  K-step Fermat chain
// ═══════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct FermatChainGadgetLayout {
    pub initial_acc_base: usize,
    pub base_base: usize,
    pub bit_cells: Vec<usize>,
    pub steps: Vec<FermatStepGadgetLayout>,
}

pub fn build_fermat_chain_layout(
    start: usize,
    initial_acc_base: usize,
    base_base: usize,
    bit_cells: Vec<usize>,
) -> (FermatChainGadgetLayout, usize) {
    let mut cursor = start;
    let mut steps = Vec::with_capacity(bit_cells.len());
    let mut acc_base = initial_acc_base;
    for &bit_cell in &bit_cells {
        let (step, end) = build_fermat_step_layout(cursor, acc_base, base_base, bit_cell);
        cursor = end;
        acc_base = step.select_layout.c_limbs_base;
        steps.push(step);
    }
    (
        FermatChainGadgetLayout {
            initial_acc_base,
            base_base,
            bit_cells,
            steps,
        },
        cursor,
    )
}

pub fn fermat_chain_gadget_constraints(layout: &FermatChainGadgetLayout) -> usize {
    layout.steps.iter().map(fermat_step_gadget_constraints).sum()
}

pub fn fill_fermat_chain_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &FermatChainGadgetLayout,
    initial_acc: &ScalarElement,
    base: &ScalarElement,
    bits: &[bool],
) {
    use ark_ff::PrimeField;

    assert_eq!(bits.len(), layout.steps.len());
    let mut acc = *initial_acc;
    for (k, step) in layout.steps.iter().enumerate() {
        fill_fermat_step_gadget(trace, row, step, &acc, base, bits[k]);
        // Read next-acc from the select output cells.
        let read = |trace: &[Vec<F>], cell_base: usize| -> ScalarElement {
            let mut limbs = [0i64; NUM_LIMBS];
            for i in 0..NUM_LIMBS {
                let v = trace[cell_base + i][row];
                let bi = v.into_bigint();
                limbs[i] = bi.as_ref()[0] as i64;
            }
            ScalarElement { limbs }
        };
        acc = read(trace, step.select_layout.c_limbs_base);
    }
}

pub fn eval_fermat_chain_gadget(
    cur: &[F],
    layout: &FermatChainGadgetLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(fermat_chain_gadget_constraints(layout));
    for step in &layout.steps {
        out.extend(eval_fermat_step_gadget(cur, step));
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

    fn standalone_step_layout() -> (FermatStepGadgetLayout, usize) {
        let acc_base = 0;
        let base_base = NUM_LIMBS;
        let bit_cell = 2 * NUM_LIMBS;
        let start = bit_cell + 1;
        build_fermat_step_layout(start, acc_base, base_base, bit_cell)
    }

    #[test]
    fn fermat_step_bit_zero_squares_only() {
        // bit = 0: result = acc² mod n (base ignored).
        let (layout, total) = standalone_step_layout();
        let mut trace = make_trace_row(total);
        let s = {
            let mut bytes = [0u8; 32];
            bytes[31] = 5; // s = 5
            ScalarElement::from_be_bytes(&bytes)
        };
        let three = {
            let mut t = ScalarElement::zero();
            t.limbs[0] = 3;
            t
        };
        for i in 0..NUM_LIMBS {
            trace[layout.acc_base + i][0] = F::from(three.limbs[i] as u64);
            trace[layout.base_base + i][0] = F::from(s.limbs[i] as u64);
        }
        trace[layout.bit_cell][0] = F::zero();

        fill_fermat_step_gadget(&mut trace, 0, &layout, &three, &s, false);

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_fermat_step_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(nonzero, 0, "fermat step bit=0: {} constraints failed", nonzero);

        // Result should be 3² = 9 mod n.
        use ark_ff::PrimeField;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[layout.select_layout.c_limbs_base + i][0];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        let result = ScalarElement { limbs };
        let mut expected = three.mul(&three);
        expected.freeze();
        let mut actual = result;
        actual.freeze();
        assert_eq!(actual.limbs, expected.limbs, "bit=0 result ≠ acc²");
    }

    #[test]
    fn fermat_step_bit_one_squares_then_mults() {
        // bit = 1: result = acc² · s mod n.  With acc = 3, s = 5:
        // 3² · 5 = 9 · 5 = 45.
        let (layout, total) = standalone_step_layout();
        let mut trace = make_trace_row(total);
        let s = {
            let mut t = ScalarElement::zero();
            t.limbs[0] = 5;
            t
        };
        let three = {
            let mut t = ScalarElement::zero();
            t.limbs[0] = 3;
            t
        };
        for i in 0..NUM_LIMBS {
            trace[layout.acc_base + i][0] = F::from(three.limbs[i] as u64);
            trace[layout.base_base + i][0] = F::from(s.limbs[i] as u64);
        }
        trace[layout.bit_cell][0] = F::one();

        fill_fermat_step_gadget(&mut trace, 0, &layout, &three, &s, true);

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_fermat_step_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(nonzero, 0, "fermat step bit=1: {} constraints failed", nonzero);

        // Result should be 9 · 5 = 45.
        use ark_ff::PrimeField;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[layout.select_layout.c_limbs_base + i][0];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        let result = ScalarElement { limbs };
        let mut expected = ScalarElement::zero();
        expected.limbs[0] = 45;
        let mut actual = result;
        actual.freeze();
        assert_eq!(actual.limbs, expected.limbs, "bit=1 result ≠ 45");
    }

    #[test]
    fn fermat_chain_2_steps_computes_pow_3() {
        // 2-step chain with bits (1, 1) starting from acc = 1:
        //   step 0: bit=1 → acc = 1² · s = s
        //   step 1: bit=1 → acc = s² · s = s³
        // For s = 7, result should be 343.
        let acc_base = 0;
        let base_base = NUM_LIMBS;
        let bits_start = 2 * NUM_LIMBS;
        let bit_cells = vec![bits_start, bits_start + 1];
        let start = bits_start + 2;
        let (layout, total) =
            build_fermat_chain_layout(start, acc_base, base_base, bit_cells);

        let mut trace = make_trace_row(total);
        let one = ScalarElement::one();
        let seven = {
            let mut t = ScalarElement::zero();
            t.limbs[0] = 7;
            t
        };
        for i in 0..NUM_LIMBS {
            trace[layout.initial_acc_base + i][0] = F::from(one.limbs[i] as u64);
            trace[layout.base_base + i][0] = F::from(seven.limbs[i] as u64);
        }
        for &cell in &layout.bit_cells {
            trace[cell][0] = F::one();
        }

        fill_fermat_chain_gadget(
            &mut trace, 0, &layout, &one, &seven, &[true, true],
        );

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_fermat_chain_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(
            nonzero, 0,
            "fermat chain (1,1): {} constraints failed",
            nonzero
        );

        // Verify result = 7³ = 343.
        use ark_ff::PrimeField;
        let final_step = layout.steps.last().unwrap();
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[final_step.select_layout.c_limbs_base + i][0];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        let result = ScalarElement { limbs };
        let mut actual = result;
        actual.freeze();
        let mut expected = ScalarElement::zero();
        expected.limbs[0] = 343;
        assert_eq!(actual.limbs, expected.limbs, "7³ ≠ 343");
    }
}
