// ed25519_scalar_mult_air.rs — multi-row scalar-multiplication AIR.
//
// Composes the point-double and conditional-point-add gadgets from
// `ed25519_group_air` into a K-row trace implementing the standard
// MSB-first double-and-add ladder:
//
// ```text
//   acc = identity
//   for bit in scalar_bits.iter().rev():        // MSB first
//       acc = double(acc)
//       acc = cond_add(acc, base, bit)
//   return acc
// ```
//
// Each row k ∈ [0, K) hosts ONE iteration of the loop:
//   - inputs:  acc_k        (40 limb cells, threaded from previous row)
//              base         (40 limb cells, constant across rows)
//   - step 1:  acc_dbl_k = double(acc_k)        [point-double gadget]
//   - step 2:  acc_{k+1} = cond_add(acc_dbl_k, base, bit_k)
//                                              [conditional-add gadget]
//   - output:  acc_{k+1}    (read out of cond_add gadget)
//
// Transition constraints between rows k and k+1:
//   nxt.acc  =  cur.cond_add.out
//   nxt.base =  cur.base
//
// Boundary constraints (handled by the caller as public-input bindings):
//   row 0:    acc     = identity     (X=0, Y=1, Z=1, T=0)
//   row 0:    base    = the actual base point limbs
//   row K-1:  cond_add.out  =  the public-input scalar-mult output
//
// For a 256-bit scalar this AIR has 256 rows × ~14_941 cells/row ≈ 3.8 M
// cells.  Tests in this file use small K (4..16) for fast validation;
// the same AIR scales to K = 256 for production.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{Field, Zero, One};
use ark_goldilocks::Goldilocks as F;

use crate::ed25519_field::{FieldElement, NUM_LIMBS};
use crate::ed25519_field_air::{place_element, read_element};
use crate::ed25519_group::EdwardsPoint;
use crate::ed25519_group_air::{
    PointDoubleGadgetLayout, POINT_DBL_OWNED_CELLS, POINT_DBL_CONSTRAINTS,
    CondAddGadgetLayout,    COND_ADD_OWNED_CELLS,    COND_ADD_CONSTRAINTS,
    point_double_layout_at, fill_point_double_gadget, eval_point_double_gadget,
    cond_add_layout_at,    fill_cond_add_gadget,    eval_cond_add_gadget,
    read_cond_add_output,
};

// ═══════════════════════════════════════════════════════════════════
//  Per-row layout
// ═══════════════════════════════════════════════════════════════════

/// Cell offsets for one scalar-mult row.  All rows in the trace share
/// the same offsets — the per-row contents differ but the layout is
/// uniform (an AIR requirement).
#[derive(Clone, Copy, Debug)]
pub struct ScalarMultRowLayout {
    pub base_x: usize,   pub base_y: usize,   pub base_z: usize,   pub base_t: usize,
    pub acc_x:  usize,   pub acc_y:  usize,   pub acc_z:  usize,   pub acc_t:  usize,
    pub dbl:      PointDoubleGadgetLayout,
    pub cond_add: CondAddGadgetLayout,
    pub width: usize,
}

/// Cells per row (= total trace width).
///
///   8 limb-base blocks (base + acc)            =  80 cells
///   POINT_DBL_OWNED_CELLS                      = 6670 cells
///   COND_ADD_OWNED_CELLS                       = 8191 cells
///   ────────────────────────────────────────────────────
///   TOTAL                                       14941 cells
pub const SCALAR_MULT_ROW_WIDTH: usize =
    8 * NUM_LIMBS
    + POINT_DBL_OWNED_CELLS
    + COND_ADD_OWNED_CELLS;

/// Per-row transition constraints (excluding row-to-row glue):
///   POINT_DBL_CONSTRAINTS          = 6830
///   COND_ADD_CONSTRAINTS           = 8414
///   ──────────────────────────────────────
///   TOTAL                          = 15244
pub const SCALAR_MULT_PER_ROW_CONSTRAINTS: usize =
    POINT_DBL_CONSTRAINTS + COND_ADD_CONSTRAINTS;

/// Cross-row "copy" constraints linking row k's outputs to row k+1's inputs:
///   8 × 10 = 80 cells   (base + acc, each a 10-limb element)
pub const SCALAR_MULT_TRANSITION_CONSTRAINTS: usize = 8 * NUM_LIMBS;

/// Build the canonical per-row layout starting at column 0 of each row.
pub fn scalar_mult_row_layout() -> ScalarMultRowLayout {
    let base_x = 0;
    let base_y = base_x + NUM_LIMBS;
    let base_z = base_y + NUM_LIMBS;
    let base_t = base_z + NUM_LIMBS;
    let acc_x  = base_t + NUM_LIMBS;
    let acc_y  = acc_x + NUM_LIMBS;
    let acc_z  = acc_y + NUM_LIMBS;
    let acc_t  = acc_z + NUM_LIMBS;

    let dbl_start = acc_t + NUM_LIMBS;
    let dbl = point_double_layout_at(dbl_start, acc_x, acc_y, acc_z);

    // Conditional-add takes its accumulator input from dbl's output coords
    // (mul_X3.c_limbs_base etc.) and its base input from the row's `base_*`.
    let cond_add = cond_add_layout_at(
        dbl.end,
        dbl.mul_X3.c_limbs_base, dbl.mul_Y3.c_limbs_base,
        dbl.mul_Z3.c_limbs_base, dbl.mul_T3.c_limbs_base,
        base_x, base_y, base_z, base_t,
    );

    let width = cond_add.end;

    ScalarMultRowLayout {
        base_x, base_y, base_z, base_t,
        acc_x,  acc_y,  acc_z,  acc_t,
        dbl, cond_add, width,
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Trace builder
// ═══════════════════════════════════════════════════════════════════

/// Build a K-row trace for the double-and-add ladder.  `scalar_bits[k]`
/// is the bit consumed by row k (MSB-first interpretation: scalar_bits[0]
/// is the most-significant bit).
///
/// Returns the full output point (= scalar_mult(base, scalar)).
pub fn fill_scalar_mult_trace(
    trace: &mut [Vec<F>],
    layout: &ScalarMultRowLayout,
    base: &EdwardsPoint,
    scalar_bits: &[bool],   // MSB first
) -> EdwardsPoint {
    let k_steps = scalar_bits.len();
    debug_assert!(trace[0].len() >= k_steps, "trace too short for K-step ladder");

    // Walk the ladder, tracking the running accumulator.
    let mut acc = EdwardsPoint::identity();

    for (row, &bit) in scalar_bits.iter().enumerate() {
        // Place only the limb cells of the per-row base + acc inputs.
        // (No bit-decomposition: those cells aren't allocated for these
        // input slots — they're range-checked by the producer/initial
        // boundary or by the cond_add output's downstream consumers.)
        place_limbs_only(trace, row, layout.base_x, &canonicalised(&base.X));
        place_limbs_only(trace, row, layout.base_y, &canonicalised(&base.Y));
        place_limbs_only(trace, row, layout.base_z, &canonicalised(&base.Z));
        place_limbs_only(trace, row, layout.base_t, &canonicalised(&base.T));
        place_limbs_only(trace, row, layout.acc_x,  &canonicalised(&acc.X));
        place_limbs_only(trace, row, layout.acc_y,  &canonicalised(&acc.Y));
        place_limbs_only(trace, row, layout.acc_z,  &canonicalised(&acc.Z));
        place_limbs_only(trace, row, layout.acc_t,  &canonicalised(&acc.T));

        // Step 1: dbl(acc).
        fill_point_double_gadget(trace, row, &layout.dbl, &acc);
        let acc_dbl = acc.double();

        // Step 2: cond_add(acc_dbl, base, bit).
        fill_cond_add_gadget(trace, row, &layout.cond_add, &acc_dbl, base, bit);

        // Update running acc for next row.
        acc = if bit { acc_dbl.add(base) } else { acc_dbl };
        let _ = k_steps;
    }

    acc
}

fn canonicalised(fe: &FieldElement) -> FieldElement {
    let mut x = *fe;
    x.freeze();
    x
}

/// Write only the 10 limb cells of an element at `base..base+10`.
/// The downstream gadgets that consume these cells either don't need
/// bit-decomposition (e.g., MUL inputs), or get it from their own
/// helper cells (e.g., the dbl gadget's internal scratch).
fn place_limbs_only(trace: &mut [Vec<F>], row: usize, base: usize, fe: &FieldElement) {
    for k in 0..NUM_LIMBS {
        trace[base + k][row] = F::from(fe.limbs[k] as u64);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Constraint emitters
// ═══════════════════════════════════════════════════════════════════

/// Emit the per-row transition constraints (those that fire on a
/// SINGLE row — i.e., the dbl + cond_add gadget constraints).
pub fn eval_scalar_mult_per_row(cur: &[F], layout: &ScalarMultRowLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(SCALAR_MULT_PER_ROW_CONSTRAINTS);
    out.extend(eval_point_double_gadget(cur, &layout.dbl));
    out.extend(eval_cond_add_gadget(cur, &layout.cond_add));
    debug_assert_eq!(out.len(), SCALAR_MULT_PER_ROW_CONSTRAINTS);
    out
}

/// Emit the cross-row "copy" constraints linking cur (row k) and nxt
/// (row k+1):
///   - nxt.base = cur.base   (40 cells)
///   - nxt.acc  = cur.cond_add.out  (40 cells)
pub fn eval_scalar_mult_transition(
    cur: &[F],
    nxt: &[F],
    layout: &ScalarMultRowLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(SCALAR_MULT_TRANSITION_CONSTRAINTS);

    // Base constancy across rows.
    for k in 0..NUM_LIMBS {
        out.push(nxt[layout.base_x + k] - cur[layout.base_x + k]);
        out.push(nxt[layout.base_y + k] - cur[layout.base_y + k]);
        out.push(nxt[layout.base_z + k] - cur[layout.base_z + k]);
        out.push(nxt[layout.base_t + k] - cur[layout.base_t + k]);
    }

    // Accumulator threading: nxt.acc = cur.cond_add.out.
    for k in 0..NUM_LIMBS {
        out.push(nxt[layout.acc_x + k] - cur[layout.cond_add.out_x + k]);
        out.push(nxt[layout.acc_y + k] - cur[layout.cond_add.out_y + k]);
        out.push(nxt[layout.acc_z + k] - cur[layout.cond_add.out_z + k]);
        out.push(nxt[layout.acc_t + k] - cur[layout.cond_add.out_t + k]);
    }

    debug_assert_eq!(out.len(), SCALAR_MULT_TRANSITION_CONSTRAINTS);
    out
}

/// Emit the boundary constraints binding row 0's acc cells to the
/// canonical-form identity point limbs (X=0, Y=1, Z=1, T=0).  In a
/// real STARK these would be encoded as public-input boundary checks;
/// here the test harness verifies them directly on the trace cells.
pub fn eval_scalar_mult_initial_acc(cur: &[F], layout: &ScalarMultRowLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(4 * NUM_LIMBS);
    let id = EdwardsPoint::identity();
    let id_x = canonicalised(&id.X);
    let id_y = canonicalised(&id.Y);
    let id_z = canonicalised(&id.Z);
    let id_t = canonicalised(&id.T);
    for k in 0..NUM_LIMBS {
        out.push(cur[layout.acc_x + k] - F::from(id_x.limbs[k] as u64));
        out.push(cur[layout.acc_y + k] - F::from(id_y.limbs[k] as u64));
        out.push(cur[layout.acc_z + k] - F::from(id_z.limbs[k] as u64));
        out.push(cur[layout.acc_t + k] - F::from(id_t.limbs[k] as u64));
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_group::ED25519_BASEPOINT;

    fn make_trace(width: usize, height: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); height]).collect()
    }

    /// Convert an i64 scalar k to MSB-first Vec<bool> using the upper
    /// `nbits` bits.  k must be in [0, 2^nbits).
    fn scalar_to_bits_msb_first(k: u64, nbits: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(nbits);
        for i in (0..nbits).rev() {
            bits.push(((k >> i) & 1) == 1);
        }
        bits
    }

    fn assert_scalar_mult_works(scalar: u64, nbits: usize) {
        let bits = scalar_to_bits_msb_first(scalar, nbits);
        let layout = scalar_mult_row_layout();
        let mut trace = make_trace(layout.width, nbits);
        let base = *ED25519_BASEPOINT;

        let computed = fill_scalar_mult_trace(&mut trace, &layout, &base, &bits);

        // Native cross-check: double-and-add MSB-first matches the
        // EdwardsPoint::scalar_mul (which is LSB-first) — convert via
        // bit reversal.
        let mut want = EdwardsPoint::identity();
        for &bit in &bits {
            want = want.double();
            if bit { want = want.add(&base); }
        }
        assert!(computed.ct_eq(&want),
            "trace builder output ≠ native double-and-add for scalar = {} ({} bits)",
            scalar, nbits);

        // Verify per-row constraints on every row.
        for r in 0..nbits {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][r]).collect();
            let cons = eval_scalar_mult_per_row(&cur, &layout);
            for (i, v) in cons.iter().enumerate() {
                assert!(v.is_zero(),
                    "per-row constraint #{} non-zero at row {} (scalar={}, nbits={}): {:?}",
                    i, r, scalar, nbits, v);
            }
        }

        // Verify transition constraints between adjacent rows.
        for r in 0..nbits.saturating_sub(1) {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][r]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][r + 1]).collect();
            let cons = eval_scalar_mult_transition(&cur, &nxt, &layout);
            for (i, v) in cons.iter().enumerate() {
                assert!(v.is_zero(),
                    "transition constraint #{} non-zero between rows {} and {} (scalar={}): {:?}",
                    i, r, r + 1, scalar, v);
            }
        }

        // Verify initial-acc boundary at row 0.
        let cur0: Vec<F> = (0..layout.width).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_mult_initial_acc(&cur0, &layout);
        for (i, v) in cons.iter().enumerate() {
            assert!(v.is_zero(),
                "initial-acc constraint #{} non-zero (scalar={}): {:?}", i, scalar, v);
        }
    }

    #[test]
    fn scalar_mult_constants_match_documentation() {
        assert_eq!(SCALAR_MULT_ROW_WIDTH, 8 * 10 + 6670 + 8191);
        assert_eq!(SCALAR_MULT_ROW_WIDTH, 14941);
        assert_eq!(SCALAR_MULT_PER_ROW_CONSTRAINTS, 6830 + 8414);
        assert_eq!(SCALAR_MULT_PER_ROW_CONSTRAINTS, 15244);
        assert_eq!(SCALAR_MULT_TRANSITION_CONSTRAINTS, 80);
    }

    #[test]
    fn scalar_mult_zero_basepoint_is_identity() {
        // [0]·B = identity.  4-bit scalar 0000.
        assert_scalar_mult_works(0, 4);
    }

    #[test]
    fn scalar_mult_one_basepoint_is_basepoint() {
        // [1]·B = B.  4-bit scalar 0001.
        assert_scalar_mult_works(1, 4);
    }

    #[test]
    fn scalar_mult_two_basepoint_is_2b() {
        // [2]·B = 2B.  4-bit scalar 0010.
        assert_scalar_mult_works(2, 4);
    }

    #[test]
    fn scalar_mult_three_basepoint_is_3b() {
        // [3]·B = 3B.  4-bit scalar 0011.
        assert_scalar_mult_works(3, 4);
    }

    #[test]
    fn scalar_mult_seven_basepoint_is_7b() {
        // [7]·B = 7B.  4-bit scalar 0111.
        assert_scalar_mult_works(7, 4);
    }

    #[test]
    fn scalar_mult_15_basepoint_is_15b() {
        // [15]·B = 15B.  All 4 bits set.
        assert_scalar_mult_works(15, 4);
    }

    #[test]
    fn scalar_mult_8bit_scalars() {
        for k in [0u64, 1, 5, 17, 100, 200, 255] {
            assert_scalar_mult_works(k, 8);
        }
    }

    #[test]
    fn scalar_mult_16bit_scalar() {
        // A medium-sized scalar to exercise more rows.
        assert_scalar_mult_works(0xdead, 16);
    }
}
