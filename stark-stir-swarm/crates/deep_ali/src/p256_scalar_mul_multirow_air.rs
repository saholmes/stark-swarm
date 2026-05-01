// p256_scalar_mul_multirow_air.rs — Multi-row scalar-mul AIR.
//
// Phase 5 v3: distributes a K-bit scalar mult across K rows (one
// scalar_mul_step per row) with transition constraints linking row k's
// accumulator output to row k+1's accumulator input.  This is the
// production layout for the ECDSA-P256 in-circuit verifier (versus the
// single-row chain in p256_scalar_mul_air.rs which packs all K steps
// into one trace row — useful for testing but suboptimal for STARK
// prove cost).
//
// ─────────────────────────────────────────────────────────────────
// LAYOUT
// ─────────────────────────────────────────────────────────────────
//
// Every row hosts one scalar_mul_step gadget with a fixed cell
// layout (the SAME `ScalarMulStepGadgetLayout` is used for every
// row — only the cell *values* differ).  Per row, the gadget has:
//
//   acc_x/y/z       : input accumulator cells (10 limbs × 3)
//   base_x/y/z      : base point cells        (10 limbs × 3)
//   bit_cell        : scalar bit for this step
//   double_layout   : 2·acc gadget
//   add_layout      : (2·acc) + base gadget
//   select_x/y/z    : bit ? added : doubled  (output cells)
//
// Local constraints (~78k per row) fire on `cur`.
//
// Transition constraints (3 × NUM_LIMBS per inter-row edge):
//   nxt[acc_x_base + i] - cur[select_x.c_limbs_base + i] = 0  (x)
//   nxt[acc_y_base + i] - cur[select_y.c_limbs_base + i] = 0  (y)
//   nxt[acc_z_base + i] - cur[select_z.c_limbs_base + i] = 0  (z)
//
// On row 0 the acc input is the initial accumulator (caller-set).
// On rows 0..k_steps-1 the bit_cell is the scalar's k-th bit.
// On rows k_steps..n_trace-1 the bit_cell = 0 (padding doubles;
//   the output of the chain at row k_steps - 1 is what the caller
//   reads downstream).
//
// On the LAST row (n_trace - 1) the transition is wrapped: nxt =
// row 0 (FFT periodicity).  Per the standard STARK convention, we
// suppress the transition on this last row by NOT emitting it.
// Implementations of the merge function fire transitions at rows
// 0..n_trace-2 only — the constraint vector returned by
// `eval_scalar_mul_multirow_per_row` matches this convention by
// returning ONLY local constraints on the last row.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::{FieldElement, NUM_LIMBS};
use crate::p256_scalar_mul_air::{
    build_scalar_mul_step_layout, eval_scalar_mul_step_gadget,
    fill_scalar_mul_step_gadget, scalar_mul_step_gadget_constraints,
    ScalarMulStepGadgetLayout,
};

/// Multi-row scalar-mul layout.  Every row has the same cell layout;
/// only cell *values* differ.  `step` describes that shared layout.
#[derive(Clone, Debug)]
pub struct ScalarMulMultirowLayout {
    /// Shared per-row step gadget layout.
    pub step: ScalarMulStepGadgetLayout,
    /// Total trace width (cells per row).
    pub width: usize,
}

/// Per-row local-constraint count.
pub fn scalar_mul_multirow_local_constraints(layout: &ScalarMulMultirowLayout) -> usize {
    scalar_mul_step_gadget_constraints(&layout.step)
}

/// Per-row transition constraints (when emitted) = 3 × NUM_LIMBS.
pub const SCALAR_MUL_MULTIROW_TRANSITION_CONSTRAINTS: usize = 3 * NUM_LIMBS;

/// Build a multi-row scalar-mul layout starting at `start`.  Cell
/// bases for `acc_x/y/z`, `base_x/y/z`, `bit_cell` are passed in;
/// the gadget allocates internal cells from `start` onward.
pub fn build_scalar_mul_multirow_layout(
    start: usize,
    acc_x_base: usize,
    acc_y_base: usize,
    acc_z_base: usize,
    base_x_base: usize,
    base_y_base: usize,
    base_z_base: usize,
    bit_cell: usize,
) -> (ScalarMulMultirowLayout, usize) {
    let (step, end) = build_scalar_mul_step_layout(
        start, acc_x_base, acc_y_base, acc_z_base, base_x_base, base_y_base, base_z_base, bit_cell,
    );
    let layout = ScalarMulMultirowLayout {
        step,
        width: end,
    };
    (layout, end)
}

/// Fill the multi-row trace.  `n_trace` must be a power of 2 and
/// `>= k_steps`.  Rows 0..k_steps-1 host the actual scalar bits
/// (bits[k]); rows k_steps..n_trace-1 are filled with bit=0 (which
/// keeps doubling — harmless padding).
pub fn fill_scalar_mul_multirow(
    trace: &mut [Vec<F>],
    layout: &ScalarMulMultirowLayout,
    n_trace: usize,
    k_steps: usize,
    initial_acc_x: &FieldElement,
    initial_acc_y: &FieldElement,
    initial_acc_z: &FieldElement,
    base_x: &FieldElement,
    base_y: &FieldElement,
    base_z: &FieldElement,
    bits: &[bool],
) {
    use ark_ff::PrimeField;

    assert!(n_trace.is_power_of_two());
    assert!(n_trace >= k_steps, "n_trace must hold at least k_steps rows");
    assert_eq!(bits.len(), k_steps);

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

    // ── Row 0: place initial accumulator and base; fill step. ──
    place_fe(trace, layout.step.acc_x_base, 0, initial_acc_x);
    place_fe(trace, layout.step.acc_y_base, 0, initial_acc_y);
    place_fe(trace, layout.step.acc_z_base, 0, initial_acc_z);

    let mut acc_x = *initial_acc_x;
    let mut acc_y = *initial_acc_y;
    let mut acc_z = *initial_acc_z;

    for r in 0..n_trace {
        // Place the base point at this row (constant across rows).
        place_fe(trace, layout.step.base_x_base, r, base_x);
        place_fe(trace, layout.step.base_y_base, r, base_y);
        place_fe(trace, layout.step.base_z_base, r, base_z);

        // Place acc input at this row (transitioned in from previous).
        place_fe(trace, layout.step.acc_x_base, r, &acc_x);
        place_fe(trace, layout.step.acc_y_base, r, &acc_y);
        place_fe(trace, layout.step.acc_z_base, r, &acc_z);

        // Bit value for this row.
        let bit = if r < k_steps { bits[r] } else { false };
        trace[layout.step.bit_cell][r] = F::from(bit as u64);

        // Fill the gadget at this row.
        fill_scalar_mul_step_gadget(
            trace, r, &layout.step, &acc_x, &acc_y, &acc_z, base_x, base_y, base_z, bit,
        );

        // Read this row's output as next row's input acc.
        acc_x = read(trace, layout.step.select_x.c_limbs_base, r);
        acc_y = read(trace, layout.step.select_y.c_limbs_base, r);
        acc_z = read(trace, layout.step.select_z.c_limbs_base, r);
    }
}

/// Read the chain output (the accumulator after `k_steps` real
/// steps) — caller uses this to chain into the next ECDSA gadget
/// (e.g., the final group-add of u_1·G + u_2·Q).
pub fn read_multirow_output(
    trace: &[Vec<F>],
    layout: &ScalarMulMultirowLayout,
    k_steps: usize,
) -> (FieldElement, FieldElement, FieldElement) {
    use ark_ff::PrimeField;
    assert!(k_steps >= 1);
    let row = k_steps - 1;
    let read = |base: usize| -> FieldElement {
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };
    (
        read(layout.step.select_x.c_limbs_base),
        read(layout.step.select_y.c_limbs_base),
        read(layout.step.select_z.c_limbs_base),
    )
}

/// Per-row constraint evaluator.  Emits all local step constraints
/// on `cur`, plus 3·NUM_LIMBS transition constraints linking
/// `cur[select.c_limbs_base]` to `nxt[acc_base]` for rows < n_trace - 1.
///
/// Returns a fixed-length vector: local constraints (always emitted)
/// followed by transition constraints (zero on the last row).
///
/// The merge function calls this once per LDE point and combines via
/// random coefficients.
pub fn eval_scalar_mul_multirow_per_row(
    cur: &[F],
    nxt: &[F],
    trace_row: usize,
    n_trace: usize,
    layout: &ScalarMulMultirowLayout,
) -> Vec<F> {
    let local_count = scalar_mul_multirow_local_constraints(layout);
    let mut out = Vec::with_capacity(
        local_count + SCALAR_MUL_MULTIROW_TRANSITION_CONSTRAINTS,
    );

    // ── Local: per-row step constraints (~78k). ──
    out.extend(eval_scalar_mul_step_gadget(cur, &layout.step));

    // ── Transition: nxt's acc inputs == cur's select outputs. ──
    // Fired on rows 0..n_trace-2; suppressed (zeros) on last row.
    if trace_row + 1 < n_trace {
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step.acc_x_base + i] - cur[layout.step.select_x.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step.acc_y_base + i] - cur[layout.step.select_y.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.step.acc_z_base + i] - cur[layout.step.select_z.c_limbs_base + i]);
        }
    } else {
        for _ in 0..SCALAR_MUL_MULTIROW_TRANSITION_CONSTRAINTS {
            out.push(F::zero());
        }
    }

    out
}

/// Total per-row constraint count (local + transition slots).
pub fn scalar_mul_multirow_constraints(layout: &ScalarMulMultirowLayout) -> usize {
    scalar_mul_multirow_local_constraints(layout)
        + SCALAR_MUL_MULTIROW_TRANSITION_CONSTRAINTS
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256_group::GENERATOR;

    fn make_trace(width: usize, n_rows: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); n_rows]).collect()
    }

    fn standalone_layout() -> (ScalarMulMultirowLayout, usize) {
        let acc_x = 0;
        let acc_y = NUM_LIMBS;
        let acc_z = 2 * NUM_LIMBS;
        let base_x = 3 * NUM_LIMBS;
        let base_y = 4 * NUM_LIMBS;
        let base_z = 5 * NUM_LIMBS;
        let bit_cell = 6 * NUM_LIMBS;
        let start = bit_cell + 1;
        build_scalar_mul_multirow_layout(
            start, acc_x, acc_y, acc_z, base_x, base_y, base_z, bit_cell,
        )
    }

    #[test]
    fn multirow_layout_matches_step_width() {
        let (layout, _total) = standalone_layout();
        let local = scalar_mul_multirow_local_constraints(&layout);
        let total = scalar_mul_multirow_constraints(&layout);
        assert_eq!(total, local + SCALAR_MUL_MULTIROW_TRANSITION_CONSTRAINTS);
        assert!(local > 70_000 && local < 80_000);
    }

    #[test]
    fn multirow_k4_all_zero() {
        // K=4, n_trace=4: minimal multi-row chain.
        let (layout, total_cells) = standalone_layout();
        let n_trace = 4;
        let k_steps = 4;
        let mut trace = make_trace(total_cells, n_trace);

        let g = *GENERATOR;
        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };

        let bits = vec![true, false, true, false];
        fill_scalar_mul_multirow(
            &mut trace, &layout, n_trace, k_steps,
            &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &bits,
        );

        // Eval all rows: locals + transitions (last row's transitions
        // are zeroed).
        let mut total_failures = 0;
        for r in 0..n_trace {
            let cur: Vec<F> = (0..total_cells).map(|c| trace[c][r]).collect();
            let nxt_idx = (r + 1) % n_trace;
            let nxt: Vec<F> = (0..total_cells).map(|c| trace[c][nxt_idx]).collect();
            let cons = eval_scalar_mul_multirow_per_row(
                &cur, &nxt, r, n_trace, &layout,
            );
            let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
            if nonzero > 0 {
                total_failures += nonzero;
            }
        }
        assert_eq!(total_failures, 0, "multi-row K=4 had {} non-zero", total_failures);
    }

    #[test]
    fn multirow_k4_n8_padding() {
        // K=4 active steps, n_trace=8 (4 padding rows with bit=0).
        let (layout, total_cells) = standalone_layout();
        let n_trace = 8;
        let k_steps = 4;
        let mut trace = make_trace(total_cells, n_trace);

        let g = *GENERATOR;
        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        let bits = vec![true, false, true, true];
        fill_scalar_mul_multirow(
            &mut trace, &layout, n_trace, k_steps,
            &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &bits,
        );

        let mut total_failures = 0;
        for r in 0..n_trace {
            let cur: Vec<F> = (0..total_cells).map(|c| trace[c][r]).collect();
            let nxt_idx = (r + 1) % n_trace;
            let nxt: Vec<F> = (0..total_cells).map(|c| trace[c][nxt_idx]).collect();
            let cons = eval_scalar_mul_multirow_per_row(
                &cur, &nxt, r, n_trace, &layout,
            );
            total_failures += cons.iter().filter(|v| !v.is_zero()).count();
        }
        assert_eq!(total_failures, 0,
            "multi-row K=4 + 4 padding had {} non-zero", total_failures);
    }
}
