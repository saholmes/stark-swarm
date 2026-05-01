// p256_group_air.rs — AIR-level Weierstrass group operations on P-256.
//
// In-circuit counterpart to `p256_group.rs` (the native reference).
// This file delivers the *point-doubling* gadget: an AIR-side
// composition of the existing Fp gadgets (mul, add, sub) into one
// elliptic-curve doubling operation in projective coordinates.
//
// The design pattern shown here generalises directly to:
//   * point addition  (RCB-2016 Algorithm 4, ~14 mul + 20 add + 9 sub)
//   * scalar mult     (multi-row state machine: ~256 doublings + ~256
//                      conditional additions, with row-to-row state
//                      transitions)
//   * top-level ECDSA verify  (compose scalar mults of G and Q,
//                              add the two points, do x mod n == r)
//
// One group-doubling gadget already costs ~20k cells / ~20k
// constraints; full ECDSA verify is ~512 group ops + scalar
// reductions, so the eventual top-level AIR runs as a state machine
// over many rows (one row per group op).  Phase 4 v1 builds the
// state-machine wiring on top of this gadget.
//
// ─────────────────────────────────────────────────────────────────
// MAGNITUDE TRACKING — FREEZE INSERTION (Phase 3 v1.1)
// ─────────────────────────────────────────────────────────────────
//
// The RCB-2016 algorithm is correct under residue-class arithmetic,
// but our representation tracks the actual integer value of each
// cell (limbs in [0, 2^26), integer in [0, 2^260)).  Add and sub
// gadgets produce tight-but-non-canonical outputs (integer in
// [0, ~2p)), so chained add/sub operations cause integer values to
// grow beyond ~4p, after which the mul gadget's q-witness no longer
// fits in 10×26 limbs (q can reach ~36p > 2^256).
//
// Phase 3 v1.1 (this commit) addresses this by inserting a freeze
// gadget after every add and every sub, canonicalising each
// intermediate back into [0, p) before it feeds the next gadget.
// All 21 add+sub instances get a freeze immediately following.
//
// Cost: +21·591 = 12,411 constraints, +21·560 = 11,760 cells.
// Total per group-doubling gadget: ~33,144 cells, ~34,318 constraints.
//
// Optimisation opportunity (not implemented): only freeze before
// inputs that feed a mul or sub — values used only in adds can stay
// non-canonical.  This would save ~10 of the 21 freezes (~5,500
// constraints).  Not pursued here because the all-after-add/sub
// pattern is more uniform and easier to verify.
//
// ─────────────────────────────────────────────────────────────────
// COMPLETE PROJECTIVE DOUBLING (RCB-2016 Algorithm 6, a = −3)
// ─────────────────────────────────────────────────────────────────
//
// Renes–Costello–Batina, "Complete addition formulas for prime order
// elliptic curves," EUROCRYPT 2016.  For y² = x³ − 3x + b in
// projective coordinates (X : Y : Z), the doubling 2(X, Y, Z) is
// computed by:
//
//    1.  t₀ ← X²            [mul]      18.  Z₃ ← b · Z₃        [mul-by-b]
//    2.  t₁ ← Y²            [mul]      19.  Z₃ ← Z₃ − t₂       [sub]
//    3.  t₂ ← Z²            [mul]      20.  Z₃ ← Z₃ − t₀       [sub]
//    4.  t₃ ← X · Y         [mul]      21.  t₃ ← Z₃ + Z₃       [add]
//    5.  t₃ ← t₃ + t₃       [add]      22.  Z₃ ← Z₃ + t₃       [add]
//    6.  Z₃ ← X · Z         [mul]      23.  t₃ ← t₀ + t₀       [add]
//    7.  Z₃ ← Z₃ + Z₃       [add]      24.  t₀ ← t₃ + t₀       [add]
//    8.  Y₃ ← b · t₂        [mul-by-b] 25.  t₀ ← t₀ − t₂       [sub]
//    9.  Y₃ ← Y₃ − Z₃       [sub]      26.  t₀ ← t₀ · Z₃       [mul]
//   10.  X₃ ← Y₃ + Y₃       [add]      27.  Y₃ ← Y₃ + t₀       [add]
//   11.  Y₃ ← X₃ + Y₃       [add]      28.  t₀ ← Y · Z         [mul]
//   12.  X₃ ← t₁ − Y₃       [sub]      29.  t₀ ← t₀ + t₀       [add]
//   13.  Y₃ ← t₁ + Y₃       [add]      30.  Z₃ ← t₀ · Z₃       [mul]
//   14.  Y₃ ← X₃ · Y₃       [mul]      31.  X₃ ← X₃ − Z₃       [sub]
//   15.  X₃ ← X₃ · t₃       [mul]      32.  Z₃ ← t₀ · t₁       [mul]
//   16.  t₃ ← t₂ + t₂       [add]      33.  Z₃ ← Z₃ + Z₃       [add]
//   17.  t₂ ← t₂ + t₃       [add]      34.  Z₃ ← Z₃ + Z₃       [add]
//
// Counts: 12 mul (incl. 2 mul-by-b) + 15 add + 6 sub = 33 sub-gadgets.
//
// "mul-by-b" is implemented as a regular mul where one operand is the
// curve constant b (FieldElement::B_CURVE).  The mul gadget doesn't
// special-case constant operands; we just place b into the b-input
// cells of that mul instance.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::{B_CURVE, FieldElement, LIMB_BITS, NUM_LIMBS};
use crate::p256_field_air::{
    eval_add_gadget, eval_freeze_gadget, eval_mul_gadget, eval_sub_gadget,
    fill_add_gadget, fill_freeze_gadget, fill_mul_gadget, fill_sub_gadget,
    AddGadgetLayout, FreezeGadgetLayout, MulGadgetLayout, SubGadgetLayout,
    ADD_GADGET_OWNED_CELLS, ELEMENT_BIT_CELLS, ELEMENT_CELLS,
    FREEZE_GADGET_OWNED_CELLS, MUL_CARRY_BITS, MUL_CARRY_POSITIONS,
    MUL_GADGET_OWNED_CELLS, SUB_GADGET_OWNED_CELLS,
};

// ═══════════════════════════════════════════════════════════════════
//  Cell allocation helpers
// ═══════════════════════════════════════════════════════════════════
//
// These mirror the standalone-layout test helpers in
// `p256_field_air::tests`, but exposed at module level for use by
// composing AIRs.  Each helper takes a mutable cursor into the trace
// width, allocates the gadget's owned cells, and returns the layout
// with all bases populated.  The caller supplies the input bases.
// ═══════════════════════════════════════════════════════════════════

/// Allocate cells for one mul gadget instance.  Updates `cursor` to
/// the next free cell after the gadget's owned block.
fn alloc_mul_layout(
    cursor: &mut usize,
    a_limbs_base: usize,
    b_limbs_base: usize,
) -> MulGadgetLayout {
    let c_limbs_base = *cursor;
    let c_bits_base = c_limbs_base + NUM_LIMBS;
    let q_limbs_base = c_bits_base + ELEMENT_BIT_CELLS;
    let q_bits_base = q_limbs_base + NUM_LIMBS;
    let carry_bits_base = q_bits_base + ELEMENT_BIT_CELLS;
    *cursor = carry_bits_base + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;
    debug_assert_eq!(
        *cursor - c_limbs_base,
        MUL_GADGET_OWNED_CELLS,
        "alloc_mul_layout: cell count mismatch"
    );
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

/// Allocate cells for one add gadget instance.
fn alloc_add_layout(
    cursor: &mut usize,
    a_limbs_base: usize,
    b_limbs_base: usize,
) -> AddGadgetLayout {
    let c_limbs_base = *cursor;
    let c_bits_base = c_limbs_base + NUM_LIMBS;
    let carries_base = c_bits_base + ELEMENT_BIT_CELLS;
    *cursor = carries_base + NUM_LIMBS;
    debug_assert_eq!(
        *cursor - c_limbs_base,
        ADD_GADGET_OWNED_CELLS,
        "alloc_add_layout: cell count mismatch"
    );
    AddGadgetLayout {
        a_limbs_base,
        b_limbs_base,
        c_limbs_base,
        c_bits_base,
        carries_base,
    }
}

/// Allocate cells for one sub gadget instance.
fn alloc_sub_layout(
    cursor: &mut usize,
    a_limbs_base: usize,
    b_limbs_base: usize,
) -> SubGadgetLayout {
    let c_limbs_base = *cursor;
    let c_bits_base = c_limbs_base + NUM_LIMBS;
    let c_pos_base = c_bits_base + ELEMENT_BIT_CELLS;
    let c_neg_base = c_pos_base + NUM_LIMBS;
    *cursor = c_neg_base + NUM_LIMBS;
    debug_assert_eq!(
        *cursor - c_limbs_base,
        SUB_GADGET_OWNED_CELLS,
        "alloc_sub_layout: cell count mismatch"
    );
    SubGadgetLayout {
        a_limbs_base,
        b_limbs_base,
        c_limbs_base,
        c_bits_base,
        c_pos_base,
        c_neg_base,
    }
}

/// Allocate cells for one freeze gadget instance.
fn alloc_freeze_layout(
    cursor: &mut usize,
    a_limbs_base: usize,
) -> FreezeGadgetLayout {
    let diff_limbs_base = *cursor;
    let diff_bits_base = diff_limbs_base + NUM_LIMBS;
    let c_limbs_base = diff_bits_base + ELEMENT_BIT_CELLS;
    let c_bits_base = c_limbs_base + NUM_LIMBS;
    let c_pos_base = c_bits_base + ELEMENT_BIT_CELLS;
    let c_neg_base = c_pos_base + NUM_LIMBS;
    *cursor = c_neg_base + NUM_LIMBS;
    debug_assert_eq!(
        *cursor - diff_limbs_base,
        FREEZE_GADGET_OWNED_CELLS,
        "alloc_freeze_layout: cell count mismatch"
    );
    FreezeGadgetLayout {
        a_limbs_base,
        diff_limbs_base,
        diff_bits_base,
        c_limbs_base,
        c_bits_base,
        c_pos_base,
        c_neg_base,
    }
}

/// Place a tight-form FieldElement into a 270-cell block (10 limbs +
/// 260 bits) at `limbs_base`.  Used to seed the constant `b` operand.
fn place_field_element(trace: &mut [Vec<F>], row: usize, limbs_base: usize, fe: &FieldElement) {
    let bits_base = limbs_base + NUM_LIMBS;
    for i in 0..NUM_LIMBS {
        let limb = fe.limbs[i];
        debug_assert!(
            limb >= 0 && (limb as u64) < (1u64 << LIMB_BITS),
            "place_field_element: limb {} not tight: {}",
            i,
            limb
        );
        trace[limbs_base + i][row] = F::from(limb as u64);
        for b in 0..LIMB_BITS as usize {
            let bit = (limb >> b) & 1;
            trace[bits_base + i * (LIMB_BITS as usize) + b][row] = F::from(bit as u64);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  GROUP-DOUBLING GADGET
// ═══════════════════════════════════════════════════════════════════

/// Cell-offset descriptor for one group-doubling gadget instance.
///
/// Composes 33 sub-gadgets (12 mul + 15 add + 6 sub).  The layout is
/// built by [`build_group_double_layout`] which threads cell offsets
/// in the order specified by RCB-2016 Algorithm 6.
///
/// Inputs: P = (X, Y, Z) at `(x_base, y_base, z_base)`, each a
/// 10-limb tight-form FieldElement (the caller is responsible for
/// range-checking these upstream).  Plus one read-only block for the
/// curve constant b at `b_base`.
///
/// Output: (X₃, Y₃, Z₃) — the c-limb cells of the muls/adds/subs at
/// the final algorithm steps (lines 31, 27, 34).  Their bases are
/// returned via `result_*_limbs_base`.
#[derive(Clone, Debug)]
pub struct GroupDoubleGadgetLayout {
    pub x_base: usize,
    pub y_base: usize,
    pub z_base: usize,
    pub b_base: usize,
    /// 13 mul gadgets in algorithm order.  Mul outputs are already
    /// canonical (< p), so no freeze is needed after a mul.
    pub muls: Vec<MulGadgetLayout>,
    /// 15 add gadgets in algorithm order.
    pub adds: Vec<AddGadgetLayout>,
    /// 6 sub gadgets in algorithm order.
    pub subs: Vec<SubGadgetLayout>,
    /// 15 freeze gadgets, one after each add gadget.  Each
    /// canonicalises the corresponding add's output so that
    /// downstream gadgets see canonical (< p) inputs.
    pub freezes_after_adds: Vec<FreezeGadgetLayout>,
    /// 6 freeze gadgets, one after each sub gadget.
    pub freezes_after_subs: Vec<FreezeGadgetLayout>,
    /// Final X3 = output of freezes_after_subs[5] (step 31 + freeze).
    pub result_x3_limbs_base: usize,
    /// Final Y3 = output of freezes_after_adds[11] (step 27 + freeze).
    pub result_y3_limbs_base: usize,
    /// Final Z3 = output of freezes_after_adds[14] (step 34 + freeze).
    pub result_z3_limbs_base: usize,
}

/// Total cells owned by one group-doubling gadget instance, with
/// freeze gadgets inserted after each add and sub:
///   270 (b_base block) + 13 · 1188 + 15 · 280 + 6 · 290
///   + 21 · 560 (freezes after every add and sub)
///   = 33,144 cells.
pub const GROUP_DOUBLE_GADGET_OWNED_CELLS: usize =
    ELEMENT_CELLS
    + 13 * MUL_GADGET_OWNED_CELLS
    + 15 * ADD_GADGET_OWNED_CELLS
    + 6 * SUB_GADGET_OWNED_CELLS
    + 21 * FREEZE_GADGET_OWNED_CELLS;

/// Build a group-doubling layout starting at trace cell `start`.
/// `(x_base, y_base, z_base)` are the input point's limb bases (not
/// owned by this gadget).
///
/// After every add and every sub gadget, a freeze gadget is allocated
/// that takes the add/sub's c-cells as input and produces canonical
/// output.  Downstream references to the algorithm's intermediate
/// variables point at the freeze gadget's c-cells, NOT the add/sub's
/// — keeping all mul/sub inputs in canonical form.
pub fn build_group_double_layout(
    start: usize,
    x_base: usize,
    y_base: usize,
    z_base: usize,
) -> (GroupDoubleGadgetLayout, usize) {
    let mut cursor = start;

    // First, allocate a fresh element block to hold the curve constant b.
    // This is necessary because the mul-by-b operations need a b operand
    // at known trace cells.
    let b_base = cursor;
    cursor += ELEMENT_CELLS;

    let mut muls: Vec<MulGadgetLayout> = Vec::with_capacity(13);
    let mut adds: Vec<AddGadgetLayout> = Vec::with_capacity(15);
    let mut subs: Vec<SubGadgetLayout> = Vec::with_capacity(6);
    let mut freezes_after_adds: Vec<FreezeGadgetLayout> = Vec::with_capacity(15);
    let mut freezes_after_subs: Vec<FreezeGadgetLayout> = Vec::with_capacity(6);

    // Helper closures: allocate add/sub THEN freeze, return the freeze's
    // c_limbs_base as the canonical output base.
    macro_rules! push_add_freeze {
        ($a:expr, $b:expr) => {{
            let add_layout = alloc_add_layout(&mut cursor, $a, $b);
            let add_c = add_layout.c_limbs_base;
            adds.push(add_layout);
            let fz = alloc_freeze_layout(&mut cursor, add_c);
            let canonical = fz.c_limbs_base;
            freezes_after_adds.push(fz);
            canonical
        }};
    }
    macro_rules! push_sub_freeze {
        ($a:expr, $b:expr) => {{
            let sub_layout = alloc_sub_layout(&mut cursor, $a, $b);
            let sub_c = sub_layout.c_limbs_base;
            subs.push(sub_layout);
            let fz = alloc_freeze_layout(&mut cursor, sub_c);
            let canonical = fz.c_limbs_base;
            freezes_after_subs.push(fz);
            canonical
        }};
    }

    // Step 1: t0 = X · X
    muls.push(alloc_mul_layout(&mut cursor, x_base, x_base));
    let t0_v1 = muls[0].c_limbs_base;
    // Step 2: t1 = Y · Y
    muls.push(alloc_mul_layout(&mut cursor, y_base, y_base));
    let t1_v1 = muls[1].c_limbs_base;
    // Step 3: t2 = Z · Z
    muls.push(alloc_mul_layout(&mut cursor, z_base, z_base));
    let t2_v1 = muls[2].c_limbs_base;
    // Step 4: t3 = X · Y
    muls.push(alloc_mul_layout(&mut cursor, x_base, y_base));
    let t3_v1 = muls[3].c_limbs_base;
    // Step 5: t3 = t3 + t3 → freeze
    let t3_v2 = push_add_freeze!(t3_v1, t3_v1);
    // Step 6: Z3 = X · Z
    muls.push(alloc_mul_layout(&mut cursor, x_base, z_base));
    let z3_v1 = muls[4].c_limbs_base;
    // Step 7: Z3 = Z3 + Z3 → freeze
    let z3_v2 = push_add_freeze!(z3_v1, z3_v1);
    // Step 8: Y3 = b · t2
    muls.push(alloc_mul_layout(&mut cursor, b_base, t2_v1));
    let y3_v1 = muls[5].c_limbs_base;
    // Step 9: Y3 = Y3 - Z3 → freeze
    let y3_v2 = push_sub_freeze!(y3_v1, z3_v2);
    // Step 10: X3 = Y3 + Y3 → freeze
    let x3_v1 = push_add_freeze!(y3_v2, y3_v2);
    // Step 11: Y3 = X3 + Y3 → freeze
    let y3_v3 = push_add_freeze!(x3_v1, y3_v2);
    // Step 12: X3 = t1 - Y3 → freeze
    let x3_v2 = push_sub_freeze!(t1_v1, y3_v3);
    // Step 13: Y3 = t1 + Y3 → freeze
    let y3_v4 = push_add_freeze!(t1_v1, y3_v3);
    // Step 14: Y3 = X3 · Y3
    muls.push(alloc_mul_layout(&mut cursor, x3_v2, y3_v4));
    let y3_v5 = muls[6].c_limbs_base;
    // Step 15: X3 = X3 · t3
    muls.push(alloc_mul_layout(&mut cursor, x3_v2, t3_v2));
    let x3_v3 = muls[7].c_limbs_base;
    // Step 16: t3 = t2 + t2 → freeze
    let t3_v3 = push_add_freeze!(t2_v1, t2_v1);
    // Step 17: t2 = t2 + t3 → freeze
    let t2_v2 = push_add_freeze!(t2_v1, t3_v3);
    // Step 18: Z3 = b · Z3
    muls.push(alloc_mul_layout(&mut cursor, b_base, z3_v2));
    let z3_v3 = muls[8].c_limbs_base;
    // Step 19: Z3 = Z3 - t2 → freeze
    let z3_v4 = push_sub_freeze!(z3_v3, t2_v2);
    // Step 20: Z3 = Z3 - t0 → freeze
    let z3_v5 = push_sub_freeze!(z3_v4, t0_v1);
    // Step 21: t3 = Z3 + Z3 → freeze
    let t3_v4 = push_add_freeze!(z3_v5, z3_v5);
    // Step 22: Z3 = Z3 + t3 → freeze
    let z3_v6 = push_add_freeze!(z3_v5, t3_v4);
    // Step 23: t3 = t0 + t0 → freeze
    let t3_v5 = push_add_freeze!(t0_v1, t0_v1);
    // Step 24: t0 = t3 + t0 → freeze
    let t0_v2 = push_add_freeze!(t3_v5, t0_v1);
    // Step 25: t0 = t0 - t2 → freeze
    let t0_v3 = push_sub_freeze!(t0_v2, t2_v2);
    // Step 26: t0 = t0 · Z3
    muls.push(alloc_mul_layout(&mut cursor, t0_v3, z3_v6));
    let t0_v4 = muls[9].c_limbs_base;
    // Step 27: Y3 = Y3 + t0 → freeze (final Y3)
    let y3_final = push_add_freeze!(y3_v5, t0_v4);
    // Step 28: t0 = Y · Z
    muls.push(alloc_mul_layout(&mut cursor, y_base, z_base));
    let t0_v5 = muls[10].c_limbs_base;
    // Step 29: t0 = t0 + t0 → freeze
    let t0_v6 = push_add_freeze!(t0_v5, t0_v5);
    // Step 30: Z3 = t0 · Z3
    muls.push(alloc_mul_layout(&mut cursor, t0_v6, z3_v6));
    let z3_v7 = muls[11].c_limbs_base;
    // Step 31: X3 = X3 - Z3 → freeze (final X3)
    let x3_final = push_sub_freeze!(x3_v3, z3_v7);
    // Step 32: Z3 = t0 · t1
    muls.push(alloc_mul_layout(&mut cursor, t0_v6, t1_v1));
    let z3_v8 = muls[12].c_limbs_base;
    // Step 33: Z3 = Z3 + Z3 → freeze
    let z3_v9 = push_add_freeze!(z3_v8, z3_v8);
    // Step 34: Z3 = Z3 + Z3 → freeze (final Z3)
    let z3_final = push_add_freeze!(z3_v9, z3_v9);

    let layout = GroupDoubleGadgetLayout {
        x_base,
        y_base,
        z_base,
        b_base,
        muls,
        adds,
        subs,
        freezes_after_adds,
        freezes_after_subs,
        result_x3_limbs_base: x3_final,
        result_y3_limbs_base: y3_final,
        result_z3_limbs_base: z3_final,
    };

    (layout, cursor)
}

/// Total constraints emitted per group-doubling gadget instance with
/// freeze gadgets inserted: 13·1207 + 15·290 + 6·311 + 21·591 = 34,318.
pub fn group_double_gadget_constraints(layout: &GroupDoubleGadgetLayout) -> usize {
    use crate::p256_field_air::{
        ADD_GADGET_CONSTRAINTS, FREEZE_GADGET_CONSTRAINTS,
        MUL_GADGET_CONSTRAINTS, SUB_GADGET_CONSTRAINTS,
    };
    layout.muls.len() * MUL_GADGET_CONSTRAINTS
        + layout.adds.len() * ADD_GADGET_CONSTRAINTS
        + layout.subs.len() * SUB_GADGET_CONSTRAINTS
        + (layout.freezes_after_adds.len() + layout.freezes_after_subs.len())
            * FREEZE_GADGET_CONSTRAINTS
}

/// Fill all owned cells of a group-doubling gadget.
///
/// Strategy: each sub-gadget produces output cells whose values follow
/// the gadget's specific semantics (mul/sub produce canonical mod p;
/// add produces the integer sum, which can be non-canonical).  When
/// chaining, downstream gadgets must be fed the *actual cell values*
/// from upstream — not pre-canonicalised values — or the witness
/// computation in fill_mul_gadget will compute the wrong q.  We
/// therefore read each intermediate back from the trace after the
/// upstream gadget fills it.
pub fn fill_group_double_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &GroupDoubleGadgetLayout,
    fe_x: &FieldElement,
    fe_y: &FieldElement,
    fe_z: &FieldElement,
) {
    // Place the curve constant b at b_base.
    let b_canonical = {
        let mut t = *B_CURVE;
        t.freeze();
        t
    };
    place_field_element(trace, row, layout.b_base, &b_canonical);

    // Helper: read a 10-limb FieldElement back from the trace after a
    // gadget fill, so the next gadget gets the actual cell values.
    let read = |trace: &[Vec<F>], base: usize| -> FieldElement {
        use ark_ff::PrimeField;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };

    // Step 1: t0 = X · X
    fill_mul_gadget(trace, row, &layout.muls[0], fe_x, fe_x);
    let t0_v1 = read(trace, layout.muls[0].c_limbs_base);
    // Step 2: t1 = Y · Y
    fill_mul_gadget(trace, row, &layout.muls[1], fe_y, fe_y);
    let t1_v1 = read(trace, layout.muls[1].c_limbs_base);
    // Step 3: t2 = Z · Z
    fill_mul_gadget(trace, row, &layout.muls[2], fe_z, fe_z);
    let t2_v1 = read(trace, layout.muls[2].c_limbs_base);
    // Step 4: t3 = X · Y
    fill_mul_gadget(trace, row, &layout.muls[3], fe_x, fe_y);
    let t3_v1 = read(trace, layout.muls[3].c_limbs_base);

    // Local index counters for adds/subs/freezes (parallel to layout
    // ordering).  Each add or sub triggers a freeze immediately after.
    let mut ai = 0; // index into adds and freezes_after_adds
    let mut si = 0; // index into subs and freezes_after_subs

    // Helper: fill an add gadget then its freeze, returning the
    // canonical (frozen) FieldElement.
    let do_add_freeze = |trace: &mut [Vec<F>],
                         ai: &mut usize,
                         a: &FieldElement,
                         b: &FieldElement|
     -> FieldElement {
        fill_add_gadget(trace, row, &layout.adds[*ai], a, b);
        let raw = read(trace, layout.adds[*ai].c_limbs_base);
        fill_freeze_gadget(trace, row, &layout.freezes_after_adds[*ai], &raw);
        let canonical = read(trace, layout.freezes_after_adds[*ai].c_limbs_base);
        *ai += 1;
        canonical
    };
    let do_sub_freeze = |trace: &mut [Vec<F>],
                         si: &mut usize,
                         a: &FieldElement,
                         b: &FieldElement|
     -> FieldElement {
        fill_sub_gadget(trace, row, &layout.subs[*si], a, b);
        let raw = read(trace, layout.subs[*si].c_limbs_base);
        fill_freeze_gadget(trace, row, &layout.freezes_after_subs[*si], &raw);
        let canonical = read(trace, layout.freezes_after_subs[*si].c_limbs_base);
        *si += 1;
        canonical
    };

    // Step 5: t3 = t3 + t3 → freeze
    let t3_v2 = do_add_freeze(trace, &mut ai, &t3_v1, &t3_v1);

    // Step 6: Z3 = X · Z
    fill_mul_gadget(trace, row, &layout.muls[4], fe_x, fe_z);
    let z3_v1 = read(trace, layout.muls[4].c_limbs_base);

    // Step 7: Z3 = Z3 + Z3 → freeze
    let z3_v2 = do_add_freeze(trace, &mut ai, &z3_v1, &z3_v1);

    // Step 8: Y3 = b · t2
    fill_mul_gadget(trace, row, &layout.muls[5], &b_canonical, &t2_v1);
    let y3_v1 = read(trace, layout.muls[5].c_limbs_base);

    // Step 9: Y3 = Y3 - Z3 → freeze
    let y3_v2 = do_sub_freeze(trace, &mut si, &y3_v1, &z3_v2);
    // Step 10: X3 = Y3 + Y3 → freeze
    let x3_v1 = do_add_freeze(trace, &mut ai, &y3_v2, &y3_v2);
    // Step 11: Y3 = X3 + Y3 → freeze
    let y3_v3 = do_add_freeze(trace, &mut ai, &x3_v1, &y3_v2);
    // Step 12: X3 = t1 - Y3 → freeze
    let x3_v2 = do_sub_freeze(trace, &mut si, &t1_v1, &y3_v3);
    // Step 13: Y3 = t1 + Y3 → freeze
    let y3_v4 = do_add_freeze(trace, &mut ai, &t1_v1, &y3_v3);

    // Step 14: Y3 = X3 · Y3
    fill_mul_gadget(trace, row, &layout.muls[6], &x3_v2, &y3_v4);
    let y3_v5 = read(trace, layout.muls[6].c_limbs_base);

    // Step 15: X3 = X3 · t3
    fill_mul_gadget(trace, row, &layout.muls[7], &x3_v2, &t3_v2);
    let x3_v3 = read(trace, layout.muls[7].c_limbs_base);

    // Step 16: t3 = t2 + t2 → freeze
    let t3_v3 = do_add_freeze(trace, &mut ai, &t2_v1, &t2_v1);
    // Step 17: t2 = t2 + t3 → freeze
    let t2_v2 = do_add_freeze(trace, &mut ai, &t2_v1, &t3_v3);

    // Step 18: Z3 = b · Z3
    fill_mul_gadget(trace, row, &layout.muls[8], &b_canonical, &z3_v2);
    let z3_v3 = read(trace, layout.muls[8].c_limbs_base);

    // Step 19: Z3 = Z3 - t2 → freeze
    let z3_v4 = do_sub_freeze(trace, &mut si, &z3_v3, &t2_v2);
    // Step 20: Z3 = Z3 - t0 → freeze
    let z3_v5 = do_sub_freeze(trace, &mut si, &z3_v4, &t0_v1);
    // Step 21: t3 = Z3 + Z3 → freeze
    let t3_v4 = do_add_freeze(trace, &mut ai, &z3_v5, &z3_v5);
    // Step 22: Z3 = Z3 + t3 → freeze
    let z3_v6 = do_add_freeze(trace, &mut ai, &z3_v5, &t3_v4);
    // Step 23: t3 = t0 + t0 → freeze
    let t3_v5 = do_add_freeze(trace, &mut ai, &t0_v1, &t0_v1);
    // Step 24: t0 = t3 + t0 → freeze
    let t0_v2 = do_add_freeze(trace, &mut ai, &t3_v5, &t0_v1);
    // Step 25: t0 = t0 - t2 → freeze
    let t0_v3 = do_sub_freeze(trace, &mut si, &t0_v2, &t2_v2);

    // Step 26: t0 = t0 · Z3
    fill_mul_gadget(trace, row, &layout.muls[9], &t0_v3, &z3_v6);
    let t0_v4 = read(trace, layout.muls[9].c_limbs_base);

    // Step 27: Y3 = Y3 + t0 → freeze (final Y3)
    let _y3_final = do_add_freeze(trace, &mut ai, &y3_v5, &t0_v4);

    // Step 28: t0 = Y · Z
    fill_mul_gadget(trace, row, &layout.muls[10], fe_y, fe_z);
    let t0_v5 = read(trace, layout.muls[10].c_limbs_base);

    // Step 29: t0 = t0 + t0 → freeze
    let t0_v6 = do_add_freeze(trace, &mut ai, &t0_v5, &t0_v5);

    // Step 30: Z3 = t0 · Z3
    fill_mul_gadget(trace, row, &layout.muls[11], &t0_v6, &z3_v6);
    let z3_v7 = read(trace, layout.muls[11].c_limbs_base);

    // Step 31: X3 = X3 - Z3 → freeze (final X3)
    let _x3_final = do_sub_freeze(trace, &mut si, &x3_v3, &z3_v7);

    // Step 32: Z3 = t0 · t1
    fill_mul_gadget(trace, row, &layout.muls[12], &t0_v6, &t1_v1);
    let z3_v8 = read(trace, layout.muls[12].c_limbs_base);

    // Step 33: Z3 = Z3 + Z3 → freeze
    let z3_v9 = do_add_freeze(trace, &mut ai, &z3_v8, &z3_v8);
    // Step 34: Z3 = Z3 + Z3 → freeze (final Z3)
    let _z3_final = do_add_freeze(trace, &mut ai, &z3_v9, &z3_v9);

    debug_assert_eq!(ai, layout.adds.len(), "add fill count mismatch");
    debug_assert_eq!(si, layout.subs.len(), "sub fill count mismatch");
}

/// Convenience: ensure a FieldElement is in canonical (frozen) form.
fn canonicalise(fe: &FieldElement) -> FieldElement {
    let mut t = *fe;
    t.freeze();
    t
}

/// Emit all transition constraints for a group-doubling gadget by
/// concatenating the constraint vectors from each sub-gadget.
pub fn eval_group_double_gadget(
    cur: &[F],
    layout: &GroupDoubleGadgetLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(group_double_gadget_constraints(layout));
    for m in &layout.muls {
        out.extend(eval_mul_gadget(cur, m));
    }
    for a in &layout.adds {
        out.extend(eval_add_gadget(cur, a));
    }
    for s in &layout.subs {
        out.extend(eval_sub_gadget(cur, s));
    }
    for f in &layout.freezes_after_adds {
        out.extend(eval_freeze_gadget(cur, f));
    }
    for f in &layout.freezes_after_subs {
        out.extend(eval_freeze_gadget(cur, f));
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
//  GROUP-ADDITION GADGET (RCB-2016 Algorithm 4, a = −3)
// ═══════════════════════════════════════════════════════════════════
//
// Computes (X3, Y3, Z3) = (X1, Y1, Z1) + (X2, Y2, Z2) on P-256 in
// projective coordinates.  The 43-line RCB-2016 Algorithm 4 uses
// 14 muls + 20 adds + 9 subs.  As with group_double, every add/sub
// is followed by a freeze, so total sub-gadget count is 72:
//   14 muls + 20 (add+freeze) + 9 (sub+freeze) = 14 + 40 + 18 = 72.
//
// Cell budget: 270 (b block) + 14·1188 + 20·280 + 9·290 + 29·560
//              = 270 + 16,632 + 5,600 + 2,610 + 16,240 = 41,352 cells.
// Constraint budget: 14·1207 + 20·290 + 9·311 + 29·591
//              = 16,898 + 5,800 + 2,799 + 17,139 = 42,636 constraints.

#[derive(Clone, Debug)]
pub struct GroupAddGadgetLayout {
    pub p_x_base: usize,
    pub p_y_base: usize,
    pub p_z_base: usize,
    pub q_x_base: usize,
    pub q_y_base: usize,
    pub q_z_base: usize,
    pub b_base: usize,
    pub muls: Vec<MulGadgetLayout>,
    pub adds: Vec<AddGadgetLayout>,
    pub subs: Vec<SubGadgetLayout>,
    pub freezes_after_adds: Vec<FreezeGadgetLayout>,
    pub freezes_after_subs: Vec<FreezeGadgetLayout>,
    pub result_x3_limbs_base: usize,
    pub result_y3_limbs_base: usize,
    pub result_z3_limbs_base: usize,
}

/// Build a group-addition layout starting at trace cell `start`.
/// Inputs P = (p_x, p_y, p_z), Q = (q_x, q_y, q_z) are referenced by
/// limb-base offsets.
pub fn build_group_add_layout(
    start: usize,
    p_x_base: usize,
    p_y_base: usize,
    p_z_base: usize,
    q_x_base: usize,
    q_y_base: usize,
    q_z_base: usize,
) -> (GroupAddGadgetLayout, usize) {
    let mut cursor = start;

    // b constant block.
    let b_base = cursor;
    cursor += ELEMENT_CELLS;

    let mut muls: Vec<MulGadgetLayout> = Vec::with_capacity(14);
    let mut adds: Vec<AddGadgetLayout> = Vec::with_capacity(20);
    let mut subs: Vec<SubGadgetLayout> = Vec::with_capacity(9);
    let mut freezes_after_adds: Vec<FreezeGadgetLayout> = Vec::with_capacity(20);
    let mut freezes_after_subs: Vec<FreezeGadgetLayout> = Vec::with_capacity(9);

    macro_rules! push_add_freeze {
        ($a:expr, $b:expr) => {{
            let add_layout = alloc_add_layout(&mut cursor, $a, $b);
            let add_c = add_layout.c_limbs_base;
            adds.push(add_layout);
            let fz = alloc_freeze_layout(&mut cursor, add_c);
            let canonical = fz.c_limbs_base;
            freezes_after_adds.push(fz);
            canonical
        }};
    }
    macro_rules! push_sub_freeze {
        ($a:expr, $b:expr) => {{
            let sub_layout = alloc_sub_layout(&mut cursor, $a, $b);
            let sub_c = sub_layout.c_limbs_base;
            subs.push(sub_layout);
            let fz = alloc_freeze_layout(&mut cursor, sub_c);
            let canonical = fz.c_limbs_base;
            freezes_after_subs.push(fz);
            canonical
        }};
    }

    // Step 1: t0 = X1 · X2
    muls.push(alloc_mul_layout(&mut cursor, p_x_base, q_x_base));
    let t0_v1 = muls[0].c_limbs_base;
    // Step 2: t1 = Y1 · Y2
    muls.push(alloc_mul_layout(&mut cursor, p_y_base, q_y_base));
    let t1_v1 = muls[1].c_limbs_base;
    // Step 3: t2 = Z1 · Z2
    muls.push(alloc_mul_layout(&mut cursor, p_z_base, q_z_base));
    let t2_v1 = muls[2].c_limbs_base;
    // Step 4: t3 = X1 + Y1 → freeze
    let t3_v1 = push_add_freeze!(p_x_base, p_y_base);
    // Step 5: t4 = X2 + Y2 → freeze
    let t4_v1 = push_add_freeze!(q_x_base, q_y_base);
    // Step 6: t3 = t3 · t4
    muls.push(alloc_mul_layout(&mut cursor, t3_v1, t4_v1));
    let t3_v2 = muls[3].c_limbs_base;
    // Step 7: t4 = t0 + t1 → freeze
    let t4_v2 = push_add_freeze!(t0_v1, t1_v1);
    // Step 8: t3 = t3 - t4 → freeze
    let t3_v3 = push_sub_freeze!(t3_v2, t4_v2);
    // Step 9: t4 = Y1 + Z1 → freeze
    let t4_v3 = push_add_freeze!(p_y_base, p_z_base);
    // Step 10: X3 = Y2 + Z2 → freeze
    let x3_v1 = push_add_freeze!(q_y_base, q_z_base);
    // Step 11: t4 = t4 · X3
    muls.push(alloc_mul_layout(&mut cursor, t4_v3, x3_v1));
    let t4_v4 = muls[4].c_limbs_base;
    // Step 12: X3 = t1 + t2 → freeze
    let x3_v2 = push_add_freeze!(t1_v1, t2_v1);
    // Step 13: t4 = t4 - X3 → freeze
    let t4_v5 = push_sub_freeze!(t4_v4, x3_v2);
    // Step 14: X3 = X1 + Z1 → freeze
    let x3_v3 = push_add_freeze!(p_x_base, p_z_base);
    // Step 15: Y3 = X2 + Z2 → freeze
    let y3_v1 = push_add_freeze!(q_x_base, q_z_base);
    // Step 16: X3 = X3 · Y3
    muls.push(alloc_mul_layout(&mut cursor, x3_v3, y3_v1));
    let x3_v4 = muls[5].c_limbs_base;
    // Step 17: Y3 = t0 + t2 → freeze
    let y3_v2 = push_add_freeze!(t0_v1, t2_v1);
    // Step 18: Y3 = X3 - Y3 → freeze
    let y3_v3 = push_sub_freeze!(x3_v4, y3_v2);
    // Step 19: Z3 = b · t2
    muls.push(alloc_mul_layout(&mut cursor, b_base, t2_v1));
    let z3_v1 = muls[6].c_limbs_base;
    // Step 20: X3 = Y3 - Z3 → freeze
    let x3_v5 = push_sub_freeze!(y3_v3, z3_v1);
    // Step 21: Z3 = X3 + X3 → freeze
    let z3_v2 = push_add_freeze!(x3_v5, x3_v5);
    // Step 22: X3 = X3 + Z3 → freeze
    let x3_v6 = push_add_freeze!(x3_v5, z3_v2);
    // Step 23: Z3 = t1 - X3 → freeze
    let z3_v3 = push_sub_freeze!(t1_v1, x3_v6);
    // Step 24: X3 = t1 + X3 → freeze
    let x3_v7 = push_add_freeze!(t1_v1, x3_v6);
    // Step 25: Y3 = b · Y3
    muls.push(alloc_mul_layout(&mut cursor, b_base, y3_v3));
    let y3_v4 = muls[7].c_limbs_base;
    // Step 26: t1 = t2 + t2 → freeze
    let t1_v2 = push_add_freeze!(t2_v1, t2_v1);
    // Step 27: t2 = t1 + t2 → freeze
    let t2_v2 = push_add_freeze!(t1_v2, t2_v1);
    // Step 28: Y3 = Y3 - t2 → freeze
    let y3_v5 = push_sub_freeze!(y3_v4, t2_v2);
    // Step 29: Y3 = Y3 - t0 → freeze
    let y3_v6 = push_sub_freeze!(y3_v5, t0_v1);
    // Step 30: t1 = Y3 + Y3 → freeze
    let t1_v3 = push_add_freeze!(y3_v6, y3_v6);
    // Step 31: Y3 = t1 + Y3 → freeze
    let y3_v7 = push_add_freeze!(t1_v3, y3_v6);
    // Step 32: t1 = t0 + t0 → freeze
    let t1_v4 = push_add_freeze!(t0_v1, t0_v1);
    // Step 33: t0 = t1 + t0 → freeze
    let t0_v2 = push_add_freeze!(t1_v4, t0_v1);
    // Step 34: t0 = t0 - t2 → freeze
    let t0_v3 = push_sub_freeze!(t0_v2, t2_v2);
    // Step 35: t1 = t4 · Y3
    muls.push(alloc_mul_layout(&mut cursor, t4_v5, y3_v7));
    let t1_v5 = muls[8].c_limbs_base;
    // Step 36: t2 = t0 · Y3
    muls.push(alloc_mul_layout(&mut cursor, t0_v3, y3_v7));
    let t2_v3 = muls[9].c_limbs_base;
    // Step 37: Y3 = X3 · Z3
    muls.push(alloc_mul_layout(&mut cursor, x3_v7, z3_v3));
    let y3_v8 = muls[10].c_limbs_base;
    // Step 38: Y3 = Y3 + t2 → freeze (final Y3)
    let y3_final = push_add_freeze!(y3_v8, t2_v3);
    // Step 39: X3 = t3 · X3
    muls.push(alloc_mul_layout(&mut cursor, t3_v3, x3_v7));
    let x3_v8 = muls[11].c_limbs_base;
    // Step 40: X3 = X3 - t1 → freeze (final X3)
    let x3_final = push_sub_freeze!(x3_v8, t1_v5);
    // Step 41: Z3 = t4 · Z3
    muls.push(alloc_mul_layout(&mut cursor, t4_v5, z3_v3));
    let z3_v4 = muls[12].c_limbs_base;
    // Step 42: t1 = t3 · t0
    muls.push(alloc_mul_layout(&mut cursor, t3_v3, t0_v3));
    let t1_v6 = muls[13].c_limbs_base;
    // Step 43: Z3 = Z3 + t1 → freeze (final Z3)
    let z3_final = push_add_freeze!(z3_v4, t1_v6);

    let layout = GroupAddGadgetLayout {
        p_x_base,
        p_y_base,
        p_z_base,
        q_x_base,
        q_y_base,
        q_z_base,
        b_base,
        muls,
        adds,
        subs,
        freezes_after_adds,
        freezes_after_subs,
        result_x3_limbs_base: x3_final,
        result_y3_limbs_base: y3_final,
        result_z3_limbs_base: z3_final,
    };
    (layout, cursor)
}

/// Total constraints emitted per group-addition gadget instance.
pub fn group_add_gadget_constraints(layout: &GroupAddGadgetLayout) -> usize {
    use crate::p256_field_air::{
        ADD_GADGET_CONSTRAINTS, FREEZE_GADGET_CONSTRAINTS,
        MUL_GADGET_CONSTRAINTS, SUB_GADGET_CONSTRAINTS,
    };
    layout.muls.len() * MUL_GADGET_CONSTRAINTS
        + layout.adds.len() * ADD_GADGET_CONSTRAINTS
        + layout.subs.len() * SUB_GADGET_CONSTRAINTS
        + (layout.freezes_after_adds.len() + layout.freezes_after_subs.len())
            * FREEZE_GADGET_CONSTRAINTS
}

/// Fill the group-addition gadget's owned cells.
pub fn fill_group_add_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &GroupAddGadgetLayout,
    p_x: &FieldElement,
    p_y: &FieldElement,
    p_z: &FieldElement,
    q_x: &FieldElement,
    q_y: &FieldElement,
    q_z: &FieldElement,
) {
    // Place b constant.
    let b_canonical = {
        let mut t = *B_CURVE;
        t.freeze();
        t
    };
    place_field_element(trace, row, layout.b_base, &b_canonical);

    let read = |trace: &[Vec<F>], base: usize| -> FieldElement {
        use ark_ff::PrimeField;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };

    let mut ai = 0;
    let mut si = 0;

    let do_add_freeze = |trace: &mut [Vec<F>],
                         ai: &mut usize,
                         a: &FieldElement,
                         b: &FieldElement|
     -> FieldElement {
        fill_add_gadget(trace, row, &layout.adds[*ai], a, b);
        let raw = read(trace, layout.adds[*ai].c_limbs_base);
        fill_freeze_gadget(trace, row, &layout.freezes_after_adds[*ai], &raw);
        let canonical = read(trace, layout.freezes_after_adds[*ai].c_limbs_base);
        *ai += 1;
        canonical
    };
    let do_sub_freeze = |trace: &mut [Vec<F>],
                         si: &mut usize,
                         a: &FieldElement,
                         b: &FieldElement|
     -> FieldElement {
        fill_sub_gadget(trace, row, &layout.subs[*si], a, b);
        let raw = read(trace, layout.subs[*si].c_limbs_base);
        fill_freeze_gadget(trace, row, &layout.freezes_after_subs[*si], &raw);
        let canonical = read(trace, layout.freezes_after_subs[*si].c_limbs_base);
        *si += 1;
        canonical
    };

    // Step 1: t0 = X1 · X2
    fill_mul_gadget(trace, row, &layout.muls[0], p_x, q_x);
    let t0_v1 = read(trace, layout.muls[0].c_limbs_base);
    // Step 2: t1 = Y1 · Y2
    fill_mul_gadget(trace, row, &layout.muls[1], p_y, q_y);
    let t1_v1 = read(trace, layout.muls[1].c_limbs_base);
    // Step 3: t2 = Z1 · Z2
    fill_mul_gadget(trace, row, &layout.muls[2], p_z, q_z);
    let t2_v1 = read(trace, layout.muls[2].c_limbs_base);
    // Step 4: t3 = X1 + Y1 → freeze
    let t3_v1 = do_add_freeze(trace, &mut ai, p_x, p_y);
    // Step 5: t4 = X2 + Y2 → freeze
    let t4_v1 = do_add_freeze(trace, &mut ai, q_x, q_y);
    // Step 6: t3 = t3 · t4
    fill_mul_gadget(trace, row, &layout.muls[3], &t3_v1, &t4_v1);
    let t3_v2 = read(trace, layout.muls[3].c_limbs_base);
    // Step 7: t4 = t0 + t1 → freeze
    let t4_v2 = do_add_freeze(trace, &mut ai, &t0_v1, &t1_v1);
    // Step 8: t3 = t3 - t4 → freeze
    let t3_v3 = do_sub_freeze(trace, &mut si, &t3_v2, &t4_v2);
    // Step 9: t4 = Y1 + Z1 → freeze
    let t4_v3 = do_add_freeze(trace, &mut ai, p_y, p_z);
    // Step 10: X3 = Y2 + Z2 → freeze
    let x3_v1 = do_add_freeze(trace, &mut ai, q_y, q_z);
    // Step 11: t4 = t4 · X3
    fill_mul_gadget(trace, row, &layout.muls[4], &t4_v3, &x3_v1);
    let t4_v4 = read(trace, layout.muls[4].c_limbs_base);
    // Step 12: X3 = t1 + t2 → freeze
    let x3_v2 = do_add_freeze(trace, &mut ai, &t1_v1, &t2_v1);
    // Step 13: t4 = t4 - X3 → freeze
    let t4_v5 = do_sub_freeze(trace, &mut si, &t4_v4, &x3_v2);
    // Step 14: X3 = X1 + Z1 → freeze
    let x3_v3 = do_add_freeze(trace, &mut ai, p_x, p_z);
    // Step 15: Y3 = X2 + Z2 → freeze
    let y3_v1 = do_add_freeze(trace, &mut ai, q_x, q_z);
    // Step 16: X3 = X3 · Y3
    fill_mul_gadget(trace, row, &layout.muls[5], &x3_v3, &y3_v1);
    let x3_v4 = read(trace, layout.muls[5].c_limbs_base);
    // Step 17: Y3 = t0 + t2 → freeze
    let y3_v2 = do_add_freeze(trace, &mut ai, &t0_v1, &t2_v1);
    // Step 18: Y3 = X3 - Y3 → freeze
    let y3_v3 = do_sub_freeze(trace, &mut si, &x3_v4, &y3_v2);
    // Step 19: Z3 = b · t2
    fill_mul_gadget(trace, row, &layout.muls[6], &b_canonical, &t2_v1);
    let z3_v1 = read(trace, layout.muls[6].c_limbs_base);
    // Step 20: X3 = Y3 - Z3 → freeze
    let x3_v5 = do_sub_freeze(trace, &mut si, &y3_v3, &z3_v1);
    // Step 21: Z3 = X3 + X3 → freeze
    let z3_v2 = do_add_freeze(trace, &mut ai, &x3_v5, &x3_v5);
    // Step 22: X3 = X3 + Z3 → freeze
    let x3_v6 = do_add_freeze(trace, &mut ai, &x3_v5, &z3_v2);
    // Step 23: Z3 = t1 - X3 → freeze
    let z3_v3 = do_sub_freeze(trace, &mut si, &t1_v1, &x3_v6);
    // Step 24: X3 = t1 + X3 → freeze
    let x3_v7 = do_add_freeze(trace, &mut ai, &t1_v1, &x3_v6);
    // Step 25: Y3 = b · Y3
    fill_mul_gadget(trace, row, &layout.muls[7], &b_canonical, &y3_v3);
    let y3_v4 = read(trace, layout.muls[7].c_limbs_base);
    // Step 26: t1 = t2 + t2 → freeze
    let t1_v2 = do_add_freeze(trace, &mut ai, &t2_v1, &t2_v1);
    // Step 27: t2 = t1 + t2 → freeze
    let t2_v2 = do_add_freeze(trace, &mut ai, &t1_v2, &t2_v1);
    // Step 28: Y3 = Y3 - t2 → freeze
    let y3_v5 = do_sub_freeze(trace, &mut si, &y3_v4, &t2_v2);
    // Step 29: Y3 = Y3 - t0 → freeze
    let y3_v6 = do_sub_freeze(trace, &mut si, &y3_v5, &t0_v1);
    // Step 30: t1 = Y3 + Y3 → freeze
    let t1_v3 = do_add_freeze(trace, &mut ai, &y3_v6, &y3_v6);
    // Step 31: Y3 = t1 + Y3 → freeze
    let y3_v7 = do_add_freeze(trace, &mut ai, &t1_v3, &y3_v6);
    // Step 32: t1 = t0 + t0 → freeze
    let t1_v4 = do_add_freeze(trace, &mut ai, &t0_v1, &t0_v1);
    // Step 33: t0 = t1 + t0 → freeze
    let t0_v2 = do_add_freeze(trace, &mut ai, &t1_v4, &t0_v1);
    // Step 34: t0 = t0 - t2 → freeze
    let t0_v3 = do_sub_freeze(trace, &mut si, &t0_v2, &t2_v2);
    // Step 35: t1 = t4 · Y3
    fill_mul_gadget(trace, row, &layout.muls[8], &t4_v5, &y3_v7);
    let t1_v5 = read(trace, layout.muls[8].c_limbs_base);
    // Step 36: t2 = t0 · Y3
    fill_mul_gadget(trace, row, &layout.muls[9], &t0_v3, &y3_v7);
    let t2_v3 = read(trace, layout.muls[9].c_limbs_base);
    // Step 37: Y3 = X3 · Z3
    fill_mul_gadget(trace, row, &layout.muls[10], &x3_v7, &z3_v3);
    let y3_v8 = read(trace, layout.muls[10].c_limbs_base);
    // Step 38: Y3 = Y3 + t2 → freeze (final Y3)
    let _y3_final = do_add_freeze(trace, &mut ai, &y3_v8, &t2_v3);
    // Step 39: X3 = t3 · X3
    fill_mul_gadget(trace, row, &layout.muls[11], &t3_v3, &x3_v7);
    let x3_v8 = read(trace, layout.muls[11].c_limbs_base);
    // Step 40: X3 = X3 - t1 → freeze (final X3)
    let _x3_final = do_sub_freeze(trace, &mut si, &x3_v8, &t1_v5);
    // Step 41: Z3 = t4 · Z3
    fill_mul_gadget(trace, row, &layout.muls[12], &t4_v5, &z3_v3);
    let z3_v4 = read(trace, layout.muls[12].c_limbs_base);
    // Step 42: t1 = t3 · t0
    fill_mul_gadget(trace, row, &layout.muls[13], &t3_v3, &t0_v3);
    let t1_v6 = read(trace, layout.muls[13].c_limbs_base);
    // Step 43: Z3 = Z3 + t1 → freeze (final Z3)
    let _z3_final = do_add_freeze(trace, &mut ai, &z3_v4, &t1_v6);

    debug_assert_eq!(ai, layout.adds.len(), "group_add: add fill mismatch");
    debug_assert_eq!(si, layout.subs.len(), "group_add: sub fill mismatch");
}

/// Emit all transition constraints for a group-addition gadget.
pub fn eval_group_add_gadget(cur: &[F], layout: &GroupAddGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(group_add_gadget_constraints(layout));
    for m in &layout.muls {
        out.extend(eval_mul_gadget(cur, m));
    }
    for a in &layout.adds {
        out.extend(eval_add_gadget(cur, a));
    }
    for s in &layout.subs {
        out.extend(eval_sub_gadget(cur, s));
    }
    for f in &layout.freezes_after_adds {
        out.extend(eval_freeze_gadget(cur, f));
    }
    for f in &layout.freezes_after_subs {
        out.extend(eval_freeze_gadget(cur, f));
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256_group::{AffinePoint, GENERATOR};

    fn make_trace_row(width: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); 1]).collect()
    }

    /// Build a self-contained group-double layout: input (X, Y, Z) at
    /// the start, then all gadget-owned cells.  Returns the layout
    /// and total trace width.
    fn standalone_double_layout() -> (GroupDoubleGadgetLayout, usize) {
        let x_base = 0;
        let y_base = NUM_LIMBS;
        let z_base = 2 * NUM_LIMBS;
        let start = 3 * NUM_LIMBS;
        let (layout, end) = build_group_double_layout(start, x_base, y_base, z_base);
        (layout, end)
    }

    /// Place an input affine point as projective (X : Y : 1).
    fn place_projective_input(
        trace: &mut [Vec<F>],
        layout: &GroupDoubleGadgetLayout,
        p: &AffinePoint,
    ) {
        assert!(!p.infinity, "doubling identity not supported via this helper");
        for i in 0..NUM_LIMBS {
            trace[layout.x_base + i][0] = F::from(p.x.limbs[i] as u64);
            trace[layout.y_base + i][0] = F::from(p.y.limbs[i] as u64);
        }
        // Z = 1 (limbs[0] = 1, rest 0).
        trace[layout.z_base + 0][0] = F::from(1u64);
        for i in 1..NUM_LIMBS {
            trace[layout.z_base + i][0] = F::zero();
        }
    }

    #[test]
    fn group_double_layout_consistency() {
        use crate::p256_field_air::FREEZE_GADGET_OWNED_CELLS;
        let (layout, total) = standalone_double_layout();
        assert_eq!(layout.muls.len(), 13);
        assert_eq!(layout.adds.len(), 15);
        assert_eq!(layout.subs.len(), 6);
        assert_eq!(layout.freezes_after_adds.len(), 15);
        assert_eq!(layout.freezes_after_subs.len(), 6);
        let expected = 3 * NUM_LIMBS
            + ELEMENT_CELLS
            + 13 * MUL_GADGET_OWNED_CELLS
            + 15 * ADD_GADGET_OWNED_CELLS
            + 6 * SUB_GADGET_OWNED_CELLS
            + 21 * FREEZE_GADGET_OWNED_CELLS;
        assert_eq!(total, expected);
    }

    #[test]
    fn group_double_constraint_count() {
        use crate::p256_field_air::{
            ADD_GADGET_CONSTRAINTS, FREEZE_GADGET_CONSTRAINTS,
            MUL_GADGET_CONSTRAINTS, SUB_GADGET_CONSTRAINTS,
        };
        let (layout, _) = standalone_double_layout();
        let cons = group_double_gadget_constraints(&layout);
        let expected = 13 * MUL_GADGET_CONSTRAINTS
            + 15 * ADD_GADGET_CONSTRAINTS
            + 6 * SUB_GADGET_CONSTRAINTS
            + 21 * FREEZE_GADGET_CONSTRAINTS;
        assert_eq!(cons, expected);
    }

    #[test]
    fn group_double_generator_constraints_satisfied() {
        // Doubling the generator G should produce a valid trace where
        // every sub-gadget constraint evaluates to zero.
        let (layout, total) = standalone_double_layout();
        let mut trace = make_trace_row(total);

        let g = *GENERATOR;
        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        place_projective_input(&mut trace, &layout, &g);

        fill_group_double_gadget(&mut trace, 0, &layout, &g.x, &g.y, &z_one);

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_group_double_gadget(&cur, &layout);
        assert_eq!(cons.len(), group_double_gadget_constraints(&layout));
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(nonzero, 0, "group-double constraints had {} non-zero entries", nonzero);
    }

    #[test]
    fn group_double_result_matches_native() {
        // The (X3, Y3, Z3) read from the trace, after projective
        // normalisation (x = X3 / Z3², y = Y3 / Z3³), should match the
        // native affine doubling of G.
        //
        // We use a simpler check: compare via cross-multiplication to
        // avoid implementing Jacobian-to-affine inversion in the test.
        //
        // Specifically: the AIR gadget computes 2G in some projective
        // representation.  RCB-2016 Algorithm 6's output convention is
        // (X3 : Y3 : Z3) representing (X3/Z3, Y3/Z3) in the standard
        // projective "homogeneous" coordinates (NOT Jacobian).
        //
        // Native 2G has affine (x, y) = G.double().
        //
        // Equality: x = X3/Z3 and y = Y3/Z3, i.e., X3 = x · Z3 and
        // Y3 = y · Z3.
        let (layout, total) = standalone_double_layout();
        let mut trace = make_trace_row(total);
        let g = *GENERATOR;
        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        place_projective_input(&mut trace, &layout, &g);
        fill_group_double_gadget(&mut trace, 0, &layout, &g.x, &g.y, &z_one);

        // Read X3, Y3, Z3.
        let x3 = read_fe(&trace, layout.result_x3_limbs_base);
        let y3 = read_fe(&trace, layout.result_y3_limbs_base);
        let z3 = read_fe(&trace, layout.result_z3_limbs_base);

        let native_2g = g.double();
        assert!(!native_2g.infinity, "2G should not be identity");

        // Cross-multiply: X3 == native_x · Z3, Y3 == native_y · Z3.
        let lhs_x = canonicalise(&x3);
        let rhs_x = canonicalise(&native_2g.x.mul(&z3));
        assert!(
            lhs_x.ct_eq(&rhs_x),
            "X3 ≠ native_x · Z3"
        );
        let lhs_y = canonicalise(&y3);
        let rhs_y = canonicalise(&native_2g.y.mul(&z3));
        assert!(
            lhs_y.ct_eq(&rhs_y),
            "Y3 ≠ native_y · Z3"
        );
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

    // ─────────────────────────────────────────────────────────────────
    //  Group-addition gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_add_layout_3() -> (GroupAddGadgetLayout, usize) {
        // Inputs: P = (X1, Y1, Z1), Q = (X2, Y2, Z2), 6 elements at start.
        let p_x = 0;
        let p_y = NUM_LIMBS;
        let p_z = 2 * NUM_LIMBS;
        let q_x = 3 * NUM_LIMBS;
        let q_y = 4 * NUM_LIMBS;
        let q_z = 5 * NUM_LIMBS;
        let start = 6 * NUM_LIMBS;
        let (layout, end) = build_group_add_layout(start, p_x, p_y, p_z, q_x, q_y, q_z);
        (layout, end)
    }

    /// Place an affine point as projective (X : Y : 1) at the given limb bases.
    fn place_proj(
        trace: &mut [Vec<F>],
        x_base: usize,
        y_base: usize,
        z_base: usize,
        p: &AffinePoint,
    ) {
        assert!(!p.infinity, "place_proj: identity not supported");
        for i in 0..NUM_LIMBS {
            trace[x_base + i][0] = F::from(p.x.limbs[i] as u64);
            trace[y_base + i][0] = F::from(p.y.limbs[i] as u64);
        }
        trace[z_base + 0][0] = F::from(1u64);
        for i in 1..NUM_LIMBS {
            trace[z_base + i][0] = F::zero();
        }
    }

    #[test]
    fn group_add_layout_consistency() {
        use crate::p256_field_air::FREEZE_GADGET_OWNED_CELLS;
        let (layout, total) = standalone_add_layout_3();
        assert_eq!(layout.muls.len(), 14);
        assert_eq!(layout.adds.len(), 20);
        assert_eq!(layout.subs.len(), 9);
        assert_eq!(layout.freezes_after_adds.len(), 20);
        assert_eq!(layout.freezes_after_subs.len(), 9);
        let expected = 6 * NUM_LIMBS
            + ELEMENT_CELLS
            + 14 * MUL_GADGET_OWNED_CELLS
            + 20 * ADD_GADGET_OWNED_CELLS
            + 9 * SUB_GADGET_OWNED_CELLS
            + 29 * FREEZE_GADGET_OWNED_CELLS;
        assert_eq!(total, expected);
    }

    #[test]
    fn group_add_constraint_count() {
        use crate::p256_field_air::{
            ADD_GADGET_CONSTRAINTS, FREEZE_GADGET_CONSTRAINTS,
            MUL_GADGET_CONSTRAINTS, SUB_GADGET_CONSTRAINTS,
        };
        let (layout, _) = standalone_add_layout_3();
        let cons = group_add_gadget_constraints(&layout);
        let expected = 14 * MUL_GADGET_CONSTRAINTS
            + 20 * ADD_GADGET_CONSTRAINTS
            + 9 * SUB_GADGET_CONSTRAINTS
            + 29 * FREEZE_GADGET_CONSTRAINTS;
        assert_eq!(cons, expected);
    }

    /// Compute (G + 2G) in-circuit, verify all constraints satisfy AND
    /// the projective output matches native G + 2G = 3G.
    #[test]
    fn group_add_g_plus_2g_constraints_satisfied() {
        let (layout, total) = standalone_add_layout_3();
        let mut trace = make_trace_row(total);

        let g = *GENERATOR;
        let two_g = g.double();
        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };

        // P = G in projective (X : Y : 1).
        place_proj(&mut trace, layout.p_x_base, layout.p_y_base, layout.p_z_base, &g);
        // Q = 2G in projective (X : Y : 1).
        place_proj(&mut trace, layout.q_x_base, layout.q_y_base, layout.q_z_base, &two_g);

        fill_group_add_gadget(
            &mut trace, 0, &layout, &g.x, &g.y, &z_one, &two_g.x, &two_g.y, &z_one,
        );

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_group_add_gadget(&cur, &layout);
        assert_eq!(cons.len(), group_add_gadget_constraints(&layout));
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(
            nonzero, 0,
            "group_add G+2G: {} constraints failed",
            nonzero
        );
    }

    #[test]
    fn group_add_result_matches_native_3g() {
        let (layout, total) = standalone_add_layout_3();
        let mut trace = make_trace_row(total);
        let g = *GENERATOR;
        let two_g = g.double();
        let z_one = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 1;
            t
        };
        place_proj(&mut trace, layout.p_x_base, layout.p_y_base, layout.p_z_base, &g);
        place_proj(&mut trace, layout.q_x_base, layout.q_y_base, layout.q_z_base, &two_g);

        fill_group_add_gadget(
            &mut trace, 0, &layout, &g.x, &g.y, &z_one, &two_g.x, &two_g.y, &z_one,
        );

        let x3 = read_fe(&trace, layout.result_x3_limbs_base);
        let y3 = read_fe(&trace, layout.result_y3_limbs_base);
        let z3 = read_fe(&trace, layout.result_z3_limbs_base);

        // Expected: G + 2G = 3G.
        let three_g = g.add(&two_g);
        assert!(!three_g.infinity);

        // Cross-multiply check: X3 == 3G.x · Z3, Y3 == 3G.y · Z3.
        let lhs_x = canonicalise(&x3);
        let rhs_x = canonicalise(&three_g.x.mul(&z3));
        assert!(lhs_x.ct_eq(&rhs_x), "X3 ≠ 3G.x · Z3");
        let lhs_y = canonicalise(&y3);
        let rhs_y = canonicalise(&three_g.y.mul(&z3));
        assert!(lhs_y.ct_eq(&rhs_y), "Y3 ≠ 3G.y · Z3");
    }
}
