// p256_ecdsa_double_multirow_air.rs — Double-chain multi-row ECDSA-P256 AIR.
//
// Phase 5 v4 (single-STARK ECDSA verify): each trace row hosts TWO
// scalar_mul_step gadgets in parallel — one for u_1·G, one for u_2·Q
// — at disjoint cell ranges within the row.  Transition constraints
// link both accumulators row-to-row independently.  This lets a
// single STARK proof cover the full scalar-mult portion of an
// ECDSA-P256 verify (the dominant 99.9% of the cost).  The final
// group-add + R.x mod n + equality is small (~0.1%) and is added
// either as a separate small proof or as additional rows in this
// trace (deferred — current iteration measures the dominant work).
//
// Per-row constraints ≈ 2 × 77{,}827 + 2 × 30 = 155{,}714.
// Per-row cells ≈ 2 × 75{,}637 = 151{,}274.
// At K=256: trace = 256 × 151k = 38.7M cells (310 MB);
//   LDE 32× = 9.9 GB row-major working set.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::Zero;
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::{FieldElement, NUM_LIMBS};
use crate::p256_scalar_mul_air::{
    build_scalar_mul_step_layout, eval_scalar_mul_step_gadget,
    fill_scalar_mul_step_gadget, scalar_mul_step_gadget_constraints,
    ScalarMulStepGadgetLayout,
};

/// Double-chain multi-row layout: two `scalar_mul_step` gadgets in
/// parallel per row, sharing the same trace.
#[derive(Clone, Debug)]
pub struct EcdsaDoubleMultirowLayout {
    pub step_a: ScalarMulStepGadgetLayout, // u_1·G chain
    pub step_b: ScalarMulStepGadgetLayout, // u_2·Q chain
    pub width: usize,
}

pub const DOUBLE_MULTIROW_TRANSITION_CONSTRAINTS: usize = 2 * 3 * NUM_LIMBS;

pub fn build_ecdsa_double_multirow_layout(start: usize) -> (EcdsaDoubleMultirowLayout, usize) {
    let mut cursor = start;

    // Chain A (u_1·G):
    let acc_a_x = cursor; cursor += NUM_LIMBS;
    let acc_a_y = cursor; cursor += NUM_LIMBS;
    let acc_a_z = cursor; cursor += NUM_LIMBS;
    let base_a_x = cursor; cursor += NUM_LIMBS;
    let base_a_y = cursor; cursor += NUM_LIMBS;
    let base_a_z = cursor; cursor += NUM_LIMBS;
    let bit_a = cursor; cursor += 1;
    let (step_a, end_a) = build_scalar_mul_step_layout(
        cursor, acc_a_x, acc_a_y, acc_a_z, base_a_x, base_a_y, base_a_z, bit_a,
    );
    cursor = end_a;

    // Chain B (u_2·Q):
    let acc_b_x = cursor; cursor += NUM_LIMBS;
    let acc_b_y = cursor; cursor += NUM_LIMBS;
    let acc_b_z = cursor; cursor += NUM_LIMBS;
    let base_b_x = cursor; cursor += NUM_LIMBS;
    let base_b_y = cursor; cursor += NUM_LIMBS;
    let base_b_z = cursor; cursor += NUM_LIMBS;
    let bit_b = cursor; cursor += 1;
    let (step_b, end_b) = build_scalar_mul_step_layout(
        cursor, acc_b_x, acc_b_y, acc_b_z, base_b_x, base_b_y, base_b_z, bit_b,
    );
    cursor = end_b;

    let layout = EcdsaDoubleMultirowLayout {
        step_a,
        step_b,
        width: cursor,
    };
    (layout, cursor)
}

pub fn ecdsa_double_multirow_local_constraints(layout: &EcdsaDoubleMultirowLayout) -> usize {
    scalar_mul_step_gadget_constraints(&layout.step_a)
        + scalar_mul_step_gadget_constraints(&layout.step_b)
}

pub fn ecdsa_double_multirow_constraints(layout: &EcdsaDoubleMultirowLayout) -> usize {
    ecdsa_double_multirow_local_constraints(layout)
        + DOUBLE_MULTIROW_TRANSITION_CONSTRAINTS
}

/// Fill the double-chain trace.  `n_trace >= max(k_a_steps, k_b_steps)`.
/// Both chains run with bit=0 padding past their respective k_steps.
#[allow(clippy::too_many_arguments)]
pub fn fill_ecdsa_double_multirow(
    trace: &mut [Vec<F>],
    layout: &EcdsaDoubleMultirowLayout,
    n_trace: usize,
    k_a_steps: usize,
    k_b_steps: usize,
    a_initial_x: &FieldElement,
    a_initial_y: &FieldElement,
    a_initial_z: &FieldElement,
    a_base_x: &FieldElement,
    a_base_y: &FieldElement,
    a_base_z: &FieldElement,
    a_bits: &[bool],
    b_initial_x: &FieldElement,
    b_initial_y: &FieldElement,
    b_initial_z: &FieldElement,
    b_base_x: &FieldElement,
    b_base_y: &FieldElement,
    b_base_z: &FieldElement,
    b_bits: &[bool],
) {
    use ark_ff::PrimeField;

    assert!(n_trace.is_power_of_two());
    assert!(n_trace >= k_a_steps && n_trace >= k_b_steps);
    assert_eq!(a_bits.len(), k_a_steps);
    assert_eq!(b_bits.len(), k_b_steps);

    let read = |trace: &[Vec<F>], base: usize, row: usize| -> FieldElement {
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };

    let place_fe = |trace: &mut [Vec<F>], base: usize, row: usize, fe: &FieldElement| {
        for i in 0..NUM_LIMBS {
            trace[base + i][row] = F::from(fe.limbs[i] as u64);
        }
    };

    let mut a_acc_x = *a_initial_x;
    let mut a_acc_y = *a_initial_y;
    let mut a_acc_z = *a_initial_z;
    let mut b_acc_x = *b_initial_x;
    let mut b_acc_y = *b_initial_y;
    let mut b_acc_z = *b_initial_z;

    for r in 0..n_trace {
        // Chain A inputs.
        place_fe(trace, layout.step_a.base_x_base, r, a_base_x);
        place_fe(trace, layout.step_a.base_y_base, r, a_base_y);
        place_fe(trace, layout.step_a.base_z_base, r, a_base_z);
        place_fe(trace, layout.step_a.acc_x_base, r, &a_acc_x);
        place_fe(trace, layout.step_a.acc_y_base, r, &a_acc_y);
        place_fe(trace, layout.step_a.acc_z_base, r, &a_acc_z);
        let a_bit = if r < k_a_steps { a_bits[r] } else { false };
        trace[layout.step_a.bit_cell][r] = F::from(a_bit as u64);
        fill_scalar_mul_step_gadget(
            trace, r, &layout.step_a, &a_acc_x, &a_acc_y, &a_acc_z,
            a_base_x, a_base_y, a_base_z, a_bit,
        );
        a_acc_x = read(trace, layout.step_a.select_x.c_limbs_base, r);
        a_acc_y = read(trace, layout.step_a.select_y.c_limbs_base, r);
        a_acc_z = read(trace, layout.step_a.select_z.c_limbs_base, r);

        // Chain B inputs.
        place_fe(trace, layout.step_b.base_x_base, r, b_base_x);
        place_fe(trace, layout.step_b.base_y_base, r, b_base_y);
        place_fe(trace, layout.step_b.base_z_base, r, b_base_z);
        place_fe(trace, layout.step_b.acc_x_base, r, &b_acc_x);
        place_fe(trace, layout.step_b.acc_y_base, r, &b_acc_y);
        place_fe(trace, layout.step_b.acc_z_base, r, &b_acc_z);
        let b_bit = if r < k_b_steps { b_bits[r] } else { false };
        trace[layout.step_b.bit_cell][r] = F::from(b_bit as u64);
        fill_scalar_mul_step_gadget(
            trace, r, &layout.step_b, &b_acc_x, &b_acc_y, &b_acc_z,
            b_base_x, b_base_y, b_base_z, b_bit,
        );
        b_acc_x = read(trace, layout.step_b.select_x.c_limbs_base, r);
        b_acc_y = read(trace, layout.step_b.select_y.c_limbs_base, r);
        b_acc_z = read(trace, layout.step_b.select_z.c_limbs_base, r);
    }
}

pub fn eval_ecdsa_double_multirow_per_row(
    cur: &[F],
    nxt: &[F],
    trace_row: usize,
    n_trace: usize,
    layout: &EcdsaDoubleMultirowLayout,
) -> Vec<F> {
    let total = ecdsa_double_multirow_constraints(layout);
    let mut out = Vec::with_capacity(total);

    // Local constraints: both step gadgets fire on cur.
    out.extend(eval_scalar_mul_step_gadget(cur, &layout.step_a));
    out.extend(eval_scalar_mul_step_gadget(cur, &layout.step_b));

    // Transition constraints: both chains independently.  Suppressed
    // (zeros) on the last row to respect FFT periodicity.
    if trace_row + 1 < n_trace {
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step_a.acc_x_base + i] - cur[layout.step_a.select_x.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step_a.acc_y_base + i] - cur[layout.step_a.select_y.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step_a.acc_z_base + i] - cur[layout.step_a.select_z.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step_b.acc_x_base + i] - cur[layout.step_b.select_x.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step_b.acc_y_base + i] - cur[layout.step_b.select_y.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step_b.acc_z_base + i] - cur[layout.step_b.select_z.c_limbs_base + i]);
        }
    } else {
        for _ in 0..DOUBLE_MULTIROW_TRANSITION_CONSTRAINTS {
            out.push(F::zero());
        }
    }

    debug_assert_eq!(out.len(), total);
    out
}

pub fn read_double_multirow_outputs(
    trace: &[Vec<F>],
    layout: &EcdsaDoubleMultirowLayout,
    k_a_steps: usize,
    k_b_steps: usize,
) -> ((FieldElement, FieldElement, FieldElement), (FieldElement, FieldElement, FieldElement)) {
    use ark_ff::PrimeField;
    let read_at = |base: usize, row: usize| -> FieldElement {
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };
    let row_a = k_a_steps - 1;
    let row_b = k_b_steps - 1;
    (
        (
            read_at(layout.step_a.select_x.c_limbs_base, row_a),
            read_at(layout.step_a.select_y.c_limbs_base, row_a),
            read_at(layout.step_a.select_z.c_limbs_base, row_a),
        ),
        (
            read_at(layout.step_b.select_x.c_limbs_base, row_b),
            read_at(layout.step_b.select_y.c_limbs_base, row_b),
            read_at(layout.step_b.select_z.c_limbs_base, row_b),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256_group::GENERATOR;

    fn make_trace(width: usize, n_rows: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); n_rows]).collect()
    }

    #[test]
    fn double_multirow_k4_all_zero() {
        let (layout, total_cells) = build_ecdsa_double_multirow_layout(0);
        let n_trace = 4;
        let k = 4;
        let mut trace = make_trace(total_cells, n_trace);

        let g = *GENERATOR;
        let q = g.double();
        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        let a_bits = vec![true, false, true, false];
        let b_bits = vec![false, true, true, false];

        fill_ecdsa_double_multirow(
            &mut trace, &layout, n_trace, k, k,
            &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &a_bits,
            &q.x, &q.y, &z_one, &q.x, &q.y, &z_one, &b_bits,
        );

        let mut total_failures = 0;
        for r in 0..n_trace {
            let cur: Vec<F> = (0..total_cells).map(|c| trace[c][r]).collect();
            let nxt_idx = (r + 1) % n_trace;
            let nxt: Vec<F> = (0..total_cells).map(|c| trace[c][nxt_idx]).collect();
            let cons = eval_ecdsa_double_multirow_per_row(
                &cur, &nxt, r, n_trace, &layout,
            );
            total_failures += cons.iter().filter(|v| !v.is_zero()).count();
        }
        assert_eq!(total_failures, 0,
            "double-multirow K=4 had {} non-zero", total_failures);
    }
}
