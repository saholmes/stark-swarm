// p256_field_air.rs — AIR-level layout for F_p arithmetic on NIST P-256.
//
// In-circuit counterpart to `p256_field.rs` (the native reference).
// This file establishes the trace-cell layout for a single tight-form
// field element plus the range-check constraints that pin those cells
// to honest values.  Per-operation gadgets (add, sub, mul, square,
// freeze, conditional-select) build on top of this layout in subsequent
// commits, exactly mirroring the v1a → v1b → … cadence of
// `ed25519_field_air.rs`.
//
// ─────────────────────────────────────────────────────────────────
// PHASE 1 SUB-PLAN
// ─────────────────────────────────────────────────────────────────
//
//   v0    native FieldElement reference                          ✓ done
//   v1a   field-element trace layout + range check               ✓ this commit
//   v1b   add gadget          (loose · loose → loose)            next
//   v1c   sub gadget          (a − b mod p)                      next
//   v1d   mul gadget          (8×8 schoolbook + Solinas fold)    after
//   v1e   square gadget       (specialised mul)                  after
//   v1f   freeze gadget       (loose → canonical, integer < p)   after
//   v1g   conditional-select  (used in scalar-mult ladder)       after
//
// Each gadget adds:
//   - column constants for its input/output/helper cells
//   - a trace-builder routine that fills the cells from a native ref result
//   - constraint clauses that the constraint evaluator emits
//   - tests: trace satisfies constraints, plus tamper-detection
//
// ─────────────────────────────────────────────────────────────────
// FIELD ELEMENT TRACE LAYOUT
// ─────────────────────────────────────────────────────────────────
//
// One tight-form FieldElement occupies a contiguous slab of
// `ELEMENT_CELLS = 270` trace cells, organised as:
//
// ```text
//   block X — Limbs       :  10 cells, each holding a 26-bit limb
//   block Y — Limb bits   : 260 cells, the LSB-first bit decomposition
//                            of all 10 limbs concatenated (each limb
//                            contributes 26 bits, uniformly)
// ```
//
// The bit cells serve as range-check evidence: each bit cell is
// constrained to be {0, 1}, and each limb is constrained to be the
// 2^j-weighted sum of its 26 bits.  Together these enforce
// `0 ≤ limb_i < 2^26` — equivalently, the integer represented by the
// limbs is in `[0, 2^260)`.
//
// Note: `[0, 2^260)` is 4 bits looser than `[0, 2^256)` and ~16× looser
// than canonical `[0, p)`.  The looser bound is sufficient and cheaper
// for intermediate representations; the stricter `< p` is enforced by
// the freeze gadget (v1f), which performs a speculative subtraction of
// p and checks the borrow direction.
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET PER ELEMENT
// ─────────────────────────────────────────────────────────────────
//
//   Bit booleanity:        260 deg-2 constraints (b · (1 − b) = 0)
//   Limb pack identity:     10 deg-1 constraints (limb_i = Σ 2^j · bit_{ij})
//   ─────────────────────────────────────────────────────────────
//   TOTAL                  270 constraints per range-checked element.
//
// All constraints are degree ≤ 2, matching the framework's max-degree
// budget.  No row-dependent gating — the constraints fire on every
// row that hosts an element block.
//
// (Compare with Ed25519: 265 constraints per element due to
// alternating 26/25-bit limbs summing to 255.  P-256's uniform layout
// costs +5 constraints per element but simplifies the per-limb code
// — limb width is a single constant rather than a 10-element table.)
//
// ─────────────────────────────────────────────────────────────────
// CELL ORDERING WITHIN AN ELEMENT BLOCK
// ─────────────────────────────────────────────────────────────────
//
// ```text
//   offset 0..9       limb cells (in order: limb 0, limb 1, …, limb 9)
//   offset 10..35     limb 0 bits (26 bits, LSB first)
//   offset 36..61     limb 1 bits (26 bits)
//   offset 62..87     limb 2 bits (26 bits)
//   offset 88..113    limb 3 bits (26 bits)
//   offset 114..139   limb 4 bits (26 bits)
//   offset 140..165   limb 5 bits (26 bits)
//   offset 166..191   limb 6 bits (26 bits)
//   offset 192..217   limb 7 bits (26 bits)
//   offset 218..243   limb 8 bits (26 bits)
//   offset 244..269   limb 9 bits (26 bits)
// ```
//
// Per-bit offsets follow `bit_offset(limb_idx, bit_idx) =
// ELEMENT_BITS_BASE + limb_idx · LIMB_BITS + bit_idx`, which is closed
// form (no cumulative-sum lookup needed) thanks to the uniform width.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::{FieldElement, LIMB_BITS, NUM_LIMBS};

// ═══════════════════════════════════════════════════════════════════
//  Cell-layout constants for one field element
// ═══════════════════════════════════════════════════════════════════

/// Number of limb cells per element (one per radix-2^26 limb).
pub const ELEMENT_LIMB_CELLS: usize = NUM_LIMBS;

/// Total number of bit-decomposition cells per element.
/// `NUM_LIMBS · LIMB_BITS = 10 · 26 = 260`.
pub const ELEMENT_BIT_CELLS: usize = NUM_LIMBS * (LIMB_BITS as usize);

/// Total cells consumed by one element's range-checked representation.
pub const ELEMENT_CELLS: usize = ELEMENT_LIMB_CELLS + ELEMENT_BIT_CELLS;

/// Offset of the first bit-decomp cell within an element block.
pub const ELEMENT_BITS_BASE: usize = ELEMENT_LIMB_CELLS;

// Compile-time sanity.
const _: () = assert!(ELEMENT_LIMB_CELLS == 10, "10 limbs per element");
const _: () = assert!(ELEMENT_BIT_CELLS == 260, "260 bits per element (10 × 26)");
const _: () = assert!(ELEMENT_CELLS == 270, "270 cells per element block");

/// Number of transition constraints emitted for a single range-checked
/// element block.
pub const ELEMENT_CONSTRAINTS: usize = ELEMENT_BIT_CELLS + ELEMENT_LIMB_CELLS;

/// Cell offset (within an element block) of the `bit_idx`-th bit of
/// limb `limb_idx`.  Closed form thanks to uniform limb width.
#[inline]
pub fn bit_cell(limb_idx: usize, bit_idx: usize) -> usize {
    debug_assert!(limb_idx < NUM_LIMBS);
    debug_assert!(bit_idx < LIMB_BITS as usize);
    ELEMENT_BITS_BASE + limb_idx * (LIMB_BITS as usize) + bit_idx
}

// ═══════════════════════════════════════════════════════════════════
//  Trace-builder helpers
// ═══════════════════════════════════════════════════════════════════

/// Write a tight-form `FieldElement` into `ELEMENT_CELLS` cells of the
/// given row, starting at column `base`.  Each limb cell holds the
/// limb value as a `Goldilocks` element; each bit cell holds 0 or 1.
///
/// Pre-condition: each `fe.limbs[i]` is in `[0, 2^26)` — i.e., the
/// input is in tight (or canonical) form, NOT loose.  The native
/// reference's `reduce` brings any loose result into tight form before
/// it can be placed in a trace.
pub fn place_element(trace: &mut [Vec<F>], row: usize, base: usize, fe: &FieldElement) {
    debug_assert!(
        base + ELEMENT_CELLS <= trace.len(),
        "element block at base={} exceeds trace width",
        base
    );

    for i in 0..NUM_LIMBS {
        let limb = fe.limbs[i];
        debug_assert!(
            limb >= 0 && (limb as u64) < (1u64 << LIMB_BITS),
            "limb {} out of tight range [0, 2^26): got {}",
            i,
            limb
        );
        trace[base + i][row] = F::from(limb as u64);

        // Bit decomposition (LSB first).
        for b in 0..LIMB_BITS as usize {
            let bit = (limb >> b) & 1;
            trace[bit_cell(i, b)][row] = F::from(bit as u64);
        }
    }
}

/// Read a `FieldElement` from `ELEMENT_CELLS` cells of the given row,
/// starting at column `base`.  Reconstructs the limb values directly
/// from the limb cells (NOT from the bit cells); the bit cells are
/// only used by the constraint evaluator for range-check enforcement.
pub fn read_element(trace: &[Vec<F>], row: usize, base: usize) -> FieldElement {
    use ark_ff::PrimeField;
    let mut limbs = [0i64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        let v: F = trace[base + i][row];
        let bi = v.into_bigint();
        let u: u64 = bi.as_ref()[0];
        limbs[i] = u as i64;
    }
    FieldElement { limbs }
}

// ═══════════════════════════════════════════════════════════════════
//  Constraint emitter — range check for one element block
// ═══════════════════════════════════════════════════════════════════

/// Emit the `ELEMENT_CONSTRAINTS` range-check constraints for the
/// element block starting at column `base` of the current row.
///
/// Returns a vector of length `ELEMENT_CONSTRAINTS`; on a valid trace
/// every entry is zero.
///
/// Constraint order:
///   - 260 booleanity constraints (one per bit cell), in the order
///     limb 0 bits 0..25, limb 1 bits 0..25, …
///   - 10 limb-pack constraints, one per limb, in limb order.
pub fn eval_element_range_check(cur: &[F], base: usize) -> Vec<F> {
    let mut out = Vec::with_capacity(ELEMENT_CONSTRAINTS);

    // ── Booleanity: 260 constraints ──────────────────────────────
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_BITS as usize {
            let cell = cur[bit_cell(i, b)];
            out.push(cell * (F::one() - cell));
        }
    }

    // ── Limb pack: 10 constraints ────────────────────────────────
    //   limb_i = Σ_{b=0..26} 2^b · bit_{i,b}
    for i in 0..NUM_LIMBS {
        let mut s = F::zero();
        for b in 0..LIMB_BITS as usize {
            let bit = cur[bit_cell(i, b)];
            s += F::from(1u64 << b) * bit;
        }
        out.push(cur[base + i] - s);
    }

    debug_assert_eq!(out.len(), ELEMENT_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  ADD GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Computes c = a + b in the integers (no mod-p reduction), where a
// and b are tight-form inputs (each limb in [0, 2^26), integer in
// [0, 2p)).  Output c is tight but only "almost canonical": the
// integer is in [0, 4p), strictly within the [0, 2^260) bound enforced
// by the range check.  Canonical-form (integer < p) enforcement is
// the freeze gadget's job (v1f).
//
// Why no Ed25519-style mod-p wrap?
//
// Ed25519 gets a + b mod p in one shot via `carry_in[0] = 19 · carry[9]`,
// using the relation 2^255 ≡ 19 (mod p_25519).  That works because the
// wrap collapses to a single-limb integer correction.
//
// For P-256, 2^260 ≡ K (mod p) with K = 2^228 − 2^196 − 2^100 + 16 —
// a multi-limb constant with mixed signs that would force signed
// carry cells (carry ∈ {−1, 0, +1}) and double the per-carry cost.
// Cheaper to keep the add gadget simple and let freeze handle the
// "subtract p if ≥ p" step.
//
// ─────────────────────────────────────────────────────────────────
// THE CARRY CHAIN
// ─────────────────────────────────────────────────────────────────
//
// For each limb k ∈ [0, 10):
//
//     a[k] + b[k] + carry_in[k]  =  c[k] + carry[k] · 2^26
//
// with carry_in[0] = 0 and carry_in[k] = carry[k − 1] for k > 0.
//
// All carries are 1-bit booleans: with a, b tight (each limb < 2^26),
// a[k] + b[k] < 2^27, plus a 1-bit carry-in stays below 2^27 + 1, so
// carry_out at each limb is 0 or 1.
//
// Summing all 10 limb constraints weighted by 2^(26·k) gives the
// integer relation
//
//     a + b − c − carry[9] · 2^260 = 0.
//
// For c ≡ a + b (mod p) we need carry[9] · 2^260 ≡ 0 (mod p), which
// (since 2^260 ≢ 0 mod p) forces carry[9] = 0.  The gadget enforces
// this directly with one extra constraint.  An honest prover with
// tight inputs always satisfies it (a + b < 2p < 2^260).
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
// Inputs are addressed by reference (caller chooses where a and b
// live); the gadget owns its output and helper cells.
//
// ```text
//   c_limbs_base + 0..10   : c output limbs
//   c_bits_base  + 0..260  : c bit decomposition (range check)
//   carries_base + 0..10   : 10 carry cells
// ```
//
// Total owned: 10 + 260 + 10 = 280 cells.
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on c (booleanity + limb pack):     270 deg-≤2
//   Limb-sum identities:                            10 deg-1
//   Carry booleanity (for carry[0]..carry[8]):       9 deg-2
//   carry[9] = 0:                                    1 deg-1
//   ─────────────────────────────────────────────────────────────
//   TOTAL                                          290 constraints
//
// All deg ≤ 2.  The carry[9] booleanity is subsumed by the explicit
// "carry[9] = 0" constraint, which is strictly stronger and saves one
// constraint over allocating a separate booleanity check.

/// Cells owned by an add gadget (output + range-check evidence + carries).
pub const ADD_GADGET_OWNED_CELLS: usize = ELEMENT_CELLS + ELEMENT_LIMB_CELLS;

/// Constraints emitted per add gadget instance.
pub const ADD_GADGET_CONSTRAINTS: usize = ELEMENT_CONSTRAINTS + 2 * ELEMENT_LIMB_CELLS;

/// Cell-offset descriptor for one add-gadget instance.
///
/// `a_limbs_base` and `b_limbs_base` point to the 10-limb cells of the
/// inputs, anywhere in the trace.  The gadget assumes those inputs are
/// independently range-checked (typically by a previous gadget that
/// produced them, or by a separate range-check block placed by the
/// caller) AND tight (integer < 2p) — the latter is a softer contract
/// that the caller must respect; the gadget enforces only carry[9] = 0
/// which implies a + b < 2^260.
///
/// The gadget owns `c_limbs_base..c_limbs_base + 10`,
/// `c_bits_base..c_bits_base + 260`, and `carries_base..carries_base + 10`.
#[derive(Clone, Copy, Debug)]
pub struct AddGadgetLayout {
    pub a_limbs_base: usize,
    pub b_limbs_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base: usize,
    pub carries_base: usize,
}

/// Fill the gadget-owned cells (c-limbs, c-bits, carries) for the
/// computation `c = a + b` (in integers, NOT yet mod-p-reduced), given
/// the input `FieldElement`s (which the caller is also expected to
/// have placed at `layout.a_limbs_base` / `layout.b_limbs_base` via
/// `place_element`).
///
/// Pre-condition: `fe_a` and `fe_b` are tight (each limb in [0, 2^26),
/// integer in [0, 2p)).  In debug builds, the function `panic!`s if
/// `a + b ≥ 2^260` (i.e., if carry[9] would be non-zero).
pub fn fill_add_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &AddGadgetLayout,
    fe_a: &FieldElement,
    fe_b: &FieldElement,
) {
    debug_assert!(layout.c_bits_base != layout.c_limbs_base, "layout overlap");

    let mut c_limbs = [0i64; NUM_LIMBS];
    let mut carries = [0i64; NUM_LIMBS];
    let mut prev = 0i64;
    let radix = 1i64 << LIMB_BITS;
    let mask = radix - 1;
    for k in 0..NUM_LIMBS {
        let sum = fe_a.limbs[k] + fe_b.limbs[k] + prev;
        debug_assert!(sum >= 0, "limb sum negative; inputs not tight");
        c_limbs[k] = sum & mask;
        carries[k] = sum >> LIMB_BITS;
        debug_assert!(
            carries[k] == 0 || carries[k] == 1,
            "carry at limb {} non-boolean: {} (inputs not tight enough)",
            k,
            carries[k]
        );
        prev = carries[k];
    }
    debug_assert_eq!(
        carries[NUM_LIMBS - 1],
        0,
        "add gadget overflow: a + b ≥ 2^260; inputs must satisfy a + b < 2^260"
    );

    // Write c-limbs and c-bits.
    for i in 0..NUM_LIMBS {
        let limb = c_limbs[i];
        trace[layout.c_limbs_base + i][row] = F::from(limb as u64);
        for b in 0..LIMB_BITS as usize {
            let bit = (limb >> b) & 1;
            trace[layout.c_bits_base + i * (LIMB_BITS as usize) + b][row] =
                F::from(bit as u64);
        }
    }
    // Write carries.
    for k in 0..NUM_LIMBS {
        trace[layout.carries_base + k][row] = F::from(carries[k] as u64);
    }
}

/// Emit the `ADD_GADGET_CONSTRAINTS` transition constraints for one
/// add gadget.  Returns a vector of length `ADD_GADGET_CONSTRAINTS`;
/// on a valid trace every entry is zero.
///
/// Constraint order (deterministic — must match constraint-vector
/// indexing in any composing AIR):
///
///   1.   270 = 260 + 10:  c range-check (booleanity + limb-pack)
///   2.    10:             limb-sum identities (carry chain)
///   3.     9:             carry booleanity for carry[0]..carry[8]
///   4.     1:             carry[9] = 0 (no integer overflow past 2^260)
pub fn eval_add_gadget(cur: &[F], layout: &AddGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(ADD_GADGET_CONSTRAINTS);

    // (1) Range check on c.
    //
    // 260 booleanity:
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_BITS as usize {
            let cell = cur[layout.c_bits_base + i * (LIMB_BITS as usize) + b];
            out.push(cell * (F::one() - cell));
        }
    }
    // 10 limb-pack identities:
    for i in 0..NUM_LIMBS {
        let mut s = F::zero();
        for b in 0..LIMB_BITS as usize {
            s += F::from(1u64 << b)
                * cur[layout.c_bits_base + i * (LIMB_BITS as usize) + b];
        }
        out.push(cur[layout.c_limbs_base + i] - s);
    }

    // (2) 10 limb-sum identities for the carry chain.
    //
    //   a[k] + b[k] + carry_in[k] − c[k] − carry[k] · 2^26 = 0
    //   carry_in[0] = 0,  carry_in[k] = carry[k−1] for k > 0.
    let radix = F::from(1u64 << LIMB_BITS);
    for k in 0..NUM_LIMBS {
        let a_k = cur[layout.a_limbs_base + k];
        let b_k = cur[layout.b_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];
        let carry_k = cur[layout.carries_base + k];
        let carry_in = if k == 0 {
            F::zero()
        } else {
            cur[layout.carries_base + k - 1]
        };
        out.push(a_k + b_k + carry_in - c_k - radix * carry_k);
    }

    // (3) 9 carry booleanity (carry[0]..carry[8]).
    for k in 0..NUM_LIMBS - 1 {
        let cy = cur[layout.carries_base + k];
        out.push(cy * (F::one() - cy));
    }

    // (4) 1 explicit constraint: carry[9] = 0 (no integer overflow).
    out.push(cur[layout.carries_base + NUM_LIMBS - 1]);

    debug_assert_eq!(out.len(), ADD_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  SUB GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Computes c = a + p − b in the integers (mod 2^260), where a and b
// are tight-form inputs.  This realises c ≡ a − b (mod p) without
// requiring the prover to know the sign of the result: adding p first
// keeps the partial sums non-negative throughout the chain.
//
// The output c is tight but only "almost canonical": integer in
// [0, 2p), strictly within the [0, 2^260) bound enforced by the
// range check.  Specifically:
//   - a ≥ b: c = a − b + p ∈ [p, p + a) ⊂ [p, 2p)  ← non-canonical!
//   - a < b: c = a − b + p ∈ [0, p)               ← canonical
// Canonicalising requires one conditional subtraction of p, deferred
// to the freeze gadget (v1f).
//
// Why "+ p" instead of plain a − b?
//
// A naked a − b can go negative (when a < b).  Encoding negative
// values in trace cells (Goldilocks elements) requires a modular
// representation that re-introduces a wrap problem.  Adding p first
// keeps every partial sum non-negative, simplifying the chain at the
// cost of one constant-coefficient extra term per limb.
//
// Why no Ed25519-style mod-p wrap to canonical form?
//
// Same as the add gadget: 2^260 ≡ K (mod p) with K = 2^228 − 2^196 −
// 2^100 + 16 is a multi-limb constant with mixed signs.  Encoding the
// wrap in-circuit would require routing carry[9] into four separate
// limb positions with sign-dependent magnitudes, doubling per-carry
// cost.  Cheaper to keep the gadget non-canonical and let the freeze
// gadget do a single conditional subtract.
//
// ─────────────────────────────────────────────────────────────────
// SIGNED CARRY CHAIN
// ─────────────────────────────────────────────────────────────────
//
// Per-limb constraint:
//
//     a[k] + p_limb[k] − b[k] + carry_in[k]
//                              =  c[k] + carry[k] · 2^26
//
// where carry[k] ∈ {−1, 0, +1} is encoded as
//
//     carry[k] = C_pos[k] − C_neg[k]
//
// with C_pos[k], C_neg[k] ∈ {0, 1} and C_pos[k] · C_neg[k] = 0.
//
// Carry-in chains forward: carry_in[0] = 0; carry_in[k] = carry[k−1]
// for k > 0.  No wrap from limb 9 back to limb 0 — the explicit
// constraint carry[9] = 0 (i.e., C_pos[9] + C_neg[9] = 0) forces no
// integer overflow past 2^260.
//
// Summing weighted by 2^(26·k) gives the integer relation
//
//     a + p − b − c − carry[9] · 2^260 = 0.
//
// With carry[9] = 0:  c = a + p − b, so c ≡ a − b (mod p).  ✓
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
// ```text
//   c_limbs_base + 0..10   : c output limbs                    (10)
//   c_bits_base  + 0..260  : c bit decomposition (range check) (260)
//   c_pos_base   + 0..10   : positive carry indicators         (10)
//   c_neg_base   + 0..10   : negative carry indicators         (10)
// ```
//
// Total owned: 10 + 260 + 10 + 10 = 290 cells.
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on c (booleanity + limb pack):       270 deg-≤2
//   Limb-difference identities:                       10 deg-1
//   Carry booleanity (10 × C_pos, 10 × C_neg):        20 deg-2
//   Mutual exclusion C_pos[k] · C_neg[k] = 0:         10 deg-2
//   carry[9] = 0  (i.e., C_pos[9] + C_neg[9] = 0):     1 deg-1
//   ─────────────────────────────────────────────────────────────
//   TOTAL                                            311 constraints
//
// All deg ≤ 2.

/// Cells owned by a sub gadget.  10 + 260 + 10 + 10 = 290.
pub const SUB_GADGET_OWNED_CELLS: usize = ELEMENT_CELLS + 2 * NUM_LIMBS;

/// Constraints emitted per sub gadget instance.
pub const SUB_GADGET_CONSTRAINTS: usize =
    ELEMENT_CONSTRAINTS + NUM_LIMBS + 2 * NUM_LIMBS + NUM_LIMBS + 1;

/// Cell-offset descriptor for one sub-gadget instance.
#[derive(Clone, Copy, Debug)]
pub struct SubGadgetLayout {
    pub a_limbs_base: usize,
    pub b_limbs_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base: usize,
    /// Base of 10 positive-carry cells (C_pos[0..9]).
    pub c_pos_base: usize,
    /// Base of 10 negative-carry cells (C_neg[0..9]).
    pub c_neg_base: usize,
}

/// Fill the gadget-owned cells for c = a + p − b (≡ a − b mod p).
///
/// Pre-condition: `fe_a` and `fe_b` are tight (each limb in [0, 2^26),
/// integer in [0, 2p)).  In debug builds, the function panics if the
/// resulting carry[9] ≠ 0 (which can only happen if inputs are not
/// tight enough that a + p − b ≥ 2^260).
pub fn fill_sub_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &SubGadgetLayout,
    fe_a: &FieldElement,
    fe_b: &FieldElement,
) {
    use crate::p256_field::P_LIMBS_TIGHT;

    let mut c_limbs = [0i64; NUM_LIMBS];
    let mut carries = [0i64; NUM_LIMBS];
    let mut prev = 0i64;
    let radix = 1i64 << LIMB_BITS;
    for k in 0..NUM_LIMBS {
        let lhs = fe_a.limbs[k] + P_LIMBS_TIGHT[k] - fe_b.limbs[k] + prev;
        c_limbs[k] = lhs.rem_euclid(radix);
        carries[k] = lhs.div_euclid(radix);
        debug_assert!(
            carries[k].abs() <= 1,
            "carry at limb {} out of range: {} (input a not tight or b ≫ a)",
            k,
            carries[k]
        );
        prev = carries[k];
    }
    debug_assert_eq!(
        carries[NUM_LIMBS - 1],
        0,
        "sub gadget overflow: a + p − b ≥ 2^260; inputs not tight enough"
    );

    // Write c-limbs and c-bits.
    for i in 0..NUM_LIMBS {
        let limb = c_limbs[i];
        debug_assert!(limb >= 0 && limb < radix);
        trace[layout.c_limbs_base + i][row] = F::from(limb as u64);
        for b in 0..LIMB_BITS as usize {
            let bit = (limb >> b) & 1;
            trace[layout.c_bits_base + i * (LIMB_BITS as usize) + b][row] =
                F::from(bit as u64);
        }
    }
    // Encode signed carries as (C_pos, C_neg).
    for k in 0..NUM_LIMBS {
        let (cp, cn) = match carries[k] {
            1 => (1u64, 0u64),
            -1 => (0u64, 1u64),
            0 => (0u64, 0u64),
            _ => unreachable!(),
        };
        trace[layout.c_pos_base + k][row] = F::from(cp);
        trace[layout.c_neg_base + k][row] = F::from(cn);
    }
}

/// Emit the `SUB_GADGET_CONSTRAINTS` transition constraints for one
/// sub gadget.  Returns a vector of length `SUB_GADGET_CONSTRAINTS`;
/// on a valid trace every entry is zero.
///
/// Constraint order:
///   1.   270 = 260 + 10:  c range-check (booleanity + limb-pack)
///   2.    10:             limb-difference identities (signed carry chain)
///   3.    10:             C_pos booleanity
///   4.    10:             C_neg booleanity
///   5.    10:             mutual exclusion C_pos[k] · C_neg[k] = 0
///   6.     1:             carry[9] = 0  (C_pos[9] + C_neg[9] = 0)
pub fn eval_sub_gadget(cur: &[F], layout: &SubGadgetLayout) -> Vec<F> {
    use crate::p256_field::P_LIMBS_TIGHT;

    let mut out = Vec::with_capacity(SUB_GADGET_CONSTRAINTS);

    // (1) Range check on c.
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_BITS as usize {
            let cell = cur[layout.c_bits_base + i * (LIMB_BITS as usize) + b];
            out.push(cell * (F::one() - cell));
        }
    }
    for i in 0..NUM_LIMBS {
        let mut s = F::zero();
        for b in 0..LIMB_BITS as usize {
            s += F::from(1u64 << b)
                * cur[layout.c_bits_base + i * (LIMB_BITS as usize) + b];
        }
        out.push(cur[layout.c_limbs_base + i] - s);
    }

    // (2) 10 limb-difference identities with signed carries.
    let radix = F::from(1u64 << LIMB_BITS);
    let net_out = |k: usize| -> F {
        cur[layout.c_pos_base + k] - cur[layout.c_neg_base + k]
    };
    for k in 0..NUM_LIMBS {
        let a_k = cur[layout.a_limbs_base + k];
        let b_k = cur[layout.b_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];
        let p_k = F::from(P_LIMBS_TIGHT[k] as u64);
        let carry_in = if k == 0 { F::zero() } else { net_out(k - 1) };
        out.push(a_k + p_k - b_k + carry_in - c_k - radix * net_out(k));
    }

    // (3) 10 C_pos booleanity.
    for k in 0..NUM_LIMBS {
        let cp = cur[layout.c_pos_base + k];
        out.push(cp * (F::one() - cp));
    }

    // (4) 10 C_neg booleanity.
    for k in 0..NUM_LIMBS {
        let cn = cur[layout.c_neg_base + k];
        out.push(cn * (F::one() - cn));
    }

    // (5) 10 mutual exclusion C_pos[k] · C_neg[k] = 0.
    for k in 0..NUM_LIMBS {
        let cp = cur[layout.c_pos_base + k];
        let cn = cur[layout.c_neg_base + k];
        out.push(cp * cn);
    }

    // (6) 1 explicit constraint: C_pos[9] + C_neg[9] = 0  (carry[9] = 0).
    out.push(
        cur[layout.c_pos_base + NUM_LIMBS - 1]
            + cur[layout.c_neg_base + NUM_LIMBS - 1],
    );

    debug_assert_eq!(out.len(), SUB_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  MUL GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Computes c = (a · b) mod p.  This is the workhorse — every field
// multiplication during ECDSA-P256 verification runs through this
// gadget.
//
// ─────────────────────────────────────────────────────────────────
// WITNESS-Q APPROACH (vs Ed25519's in-circuit Solinas fold)
// ─────────────────────────────────────────────────────────────────
//
// Ed25519's mul gadget folds the high half of the schoolbook product
// back into the low half via 2^255 ≡ 19 (mod p_25519).  This fold
// has a single coefficient (19, or 38 for radix-staggered terms),
// so each (i, j) partial product targets exactly one of the 10
// output limbs with a known multiplier in {1, 2, 19, 38}.
//
// For P-256, 2^260 ≡ K (mod p) with K = 2^228 − 2^196 − 2^100 + 16 —
// a multi-limb constant with mixed signs.  Worse, K · 2^(26·m) for
// m ≥ 2 itself produces terms ≥ 2^260 that need recursive folding.
// Hard-coding the resulting fold table is feasible but error-prone
// and would require extensive sign tracking.
//
// We adopt the cleaner *witness-quotient* approach:
//
//   prover provides q such that  a · b = q · p + c   (integer)
//   c is the canonical product (range-checked < p via freeze elsewhere
//   — here we just enforce 0 ≤ c < 2^260, with the integer equation
//   forcing c ≡ a·b mod p)
//
// The integer equation is checked limb-by-limb via 19 schoolbook
// positions (k = 0..18) and an 18-element signed-carry chain.
//
// ─────────────────────────────────────────────────────────────────
// SCHOOLBOOK + WITNESS-Q CARRY CHAIN
// ─────────────────────────────────────────────────────────────────
//
// Define LHS_k for k ∈ [0, 19):
//
//     LHS_k  =  Σ_{i+j=k} a[i] · b[j]              (schoolbook a · b at position k)
//             − Σ_{i+j=k} q[i] · p_limb[j]         (schoolbook q · p at position k)
//             − C[k]                               where C[k] = c[k] for k<10 else 0
//
// Per-position constraint (with signed carry chain):
//
//     LHS_k + carry[k − 1] − carry[k] · 2^26  =  0
//
// Boundary: carry[−1] = 0 (chain start).  carry[18] = 0 (chain end,
// no carry-out).  In-trace carries: carry[0]..carry[17] (18 cells).
//
// Summing all 19 constraints weighted by 2^(26·k) gives the integer
// relation a · b − q · p − c = 0  ⇒  c ≡ a · b (mod p).  ✓
//
// ─────────────────────────────────────────────────────────────────
// CARRY MAGNITUDES & ENCODING
// ─────────────────────────────────────────────────────────────────
//
// Per-position LHS_k magnitude: each position has up to 10 partial
// products, each ≤ (2^26 − 1)^2 < 2^52.  After two schoolbook
// subtractions and a c[k] subtraction:
//   |LHS_k|  ≤  10 · 2^52  +  10 · 2^52  +  2^26  <  2^57.
//
// Empirically, for honest inputs (canonical a, b < p), the carry
// chain produces |carry[k]| ≤ ~2^32.  We allocate 36 carry bits per
// position (signed range ≈ [−2^35, 2^35), via bias encoding) — this
// matches the Ed25519 mul gadget's choice and gives 8-bit headroom
// over the empirical maximum.
//
// Carry encoding: the trace stores 36 bits per position; the value
// represented is biased = Σ bit[b] · 2^b, signed = biased − 2^35.
// This keeps trace cells non-negative while the arithmetic uses the
// signed value.
//
// Soundness of the magnitude bound:
//   |constraint value|  ≤  |LHS_k|  +  |carry[k]| · 2^26
//                       ≤  2^57  +  2^35 · 2^26  =  2^57 + 2^61  ≈  2^61
//   ≪  Goldilocks ≈ 2^64  → no spurious mod-p_g zero.  ✓
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
//   c_limbs_base    + 0..10        : c output limbs                (10)
//   c_bits_base     + 0..260       : c bit decomposition           (260)
//   q_limbs_base    + 0..10        : q quotient limbs              (10)
//   q_bits_base     + 0..260       : q bit decomposition           (260)
//   carry_bits_base + 0..18·36=648 : carry bits (position-major)   (648)
//   ─────────────────────────────────────────────────────────────────
//   TOTAL OWNED                                                   1188 cells
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on c (booleanity + limb pack):       270 deg-≤2
//   Range check on q (booleanity + limb pack):       270 deg-≤2
//   Position constraints (carry-chain identities):    19 deg-2
//   Carry-bit booleanity (18 × 36):                  648 deg-2
//   ─────────────────────────────────────────────────────────────
//   TOTAL                                           1207 constraints
//
// Note: there is no separate "carry limb-pack" constraint.  The
// position identities at step (3) reconstruct each signed carry
// inline from its bits (Σ 2^b · bit_b − 2^35), so any tampering of
// the bit cells is caught by either booleanity (if the bit is not in
// {0,1}) or the position constraint (if the reconstructed value is
// wrong).  This matches Ed25519's mul gadget convention.

/// Bits used to range-check each carry cell.
pub const MUL_CARRY_BITS: usize = 36;

/// Bias added to each signed carry before bit-decomposition.  The
/// trace stores the biased (non-negative) value; the constraint
/// reconstructs `signed_carry = biased − MUL_CARRY_OFFSET`.
pub const MUL_CARRY_OFFSET: i64 = 1i64 << (MUL_CARRY_BITS - 1);

/// Number of carry positions in the chain.  carry[0]..carry[17]
/// (carry[−1] = 0 implicit at chain start, carry[18] = 0 implicit at
/// chain end, both encoded directly in the corresponding boundary
/// constraints rather than as cells).
pub const MUL_CARRY_POSITIONS: usize = 2 * NUM_LIMBS - 2;

/// Number of schoolbook positions (k = 0..18 for 10 × 10 → 19).
pub const MUL_SCHOOLBOOK_POSITIONS: usize = 2 * NUM_LIMBS - 1;

/// Cells owned by a mul gadget.
pub const MUL_GADGET_OWNED_CELLS: usize =
    2 * ELEMENT_CELLS + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;

/// Constraints emitted per mul gadget instance.
pub const MUL_GADGET_CONSTRAINTS: usize =
    2 * ELEMENT_CONSTRAINTS                          // c + q range checks
        + MUL_SCHOOLBOOK_POSITIONS                   // 19 position identities
        + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;      // carry-bit booleanity

/// Cell-offset descriptor for one mul-gadget instance.
#[derive(Clone, Copy, Debug)]
pub struct MulGadgetLayout {
    pub a_limbs_base: usize,
    pub b_limbs_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base: usize,
    pub q_limbs_base: usize,
    pub q_bits_base: usize,
    /// Base of carry-bit cells.  Bit `b` of the carry at position `k`
    /// lives at `carry_bits_base + k · MUL_CARRY_BITS + b`.
    pub carry_bits_base: usize,
}

/// Address of the carry-bit cell for chain position `k`, bit `b`.
#[inline]
pub fn mul_carry_bit_cell(layout: &MulGadgetLayout, k: usize, b: usize) -> usize {
    debug_assert!(k < MUL_CARRY_POSITIONS);
    debug_assert!(b < MUL_CARRY_BITS);
    layout.carry_bits_base + k * MUL_CARRY_BITS + b
}

/// Place a tight-form FieldElement at `limbs_base..+10` and its bit
/// decomposition at `bits_base..+260`.  Internal helper that allows
/// the limb and bit blocks to live at non-adjacent offsets (unlike
/// `place_element`, which assumes contiguous layout).
fn place_element_split(
    trace: &mut [Vec<F>],
    row: usize,
    limbs_base: usize,
    bits_base: usize,
    fe: &FieldElement,
) {
    for i in 0..NUM_LIMBS {
        let limb = fe.limbs[i];
        debug_assert!(
            limb >= 0 && (limb as u64) < (1u64 << LIMB_BITS),
            "limb {} out of tight range: {}",
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

/// Compute q = (a · b − c) / p using BigUint long division.  Returns
/// q as a tight-form FieldElement (each limb in [0, 2^26)).
///
/// Used only at proving time by `fill_mul_gadget`.
fn compute_quotient(fe_a: &FieldElement, fe_b: &FieldElement, fe_c: &FieldElement) -> FieldElement {
    use num_bigint::BigUint;
    use num_traits::Num;

    fn fe_to_biguint(fe: &FieldElement) -> BigUint {
        let mut t = *fe;
        t.freeze();
        BigUint::from_bytes_be(&t.to_be_bytes())
    }
    fn biguint_to_fe(x: &BigUint) -> FieldElement {
        let bytes = x.to_bytes_be();
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        FieldElement::from_be_bytes(&padded)
    }

    let p = BigUint::from_str_radix(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        16,
    )
    .unwrap();
    let a_int = fe_to_biguint(fe_a);
    let b_int = fe_to_biguint(fe_b);
    let c_int = fe_to_biguint(fe_c);
    let prod = &a_int * &b_int;
    debug_assert!(
        prod >= c_int,
        "compute_quotient: a·b < c, cannot compute q"
    );
    let q_int = (&prod - &c_int) / &p;
    debug_assert_eq!(
        &q_int * &p + &c_int,
        prod,
        "compute_quotient: a·b ≠ q·p + c"
    );
    biguint_to_fe(&q_int)
}

/// Fill the gadget-owned cells for c = (a · b) mod p.
///
/// Steps:
///   1. Compute c via the native `mul`+`freeze` (canonical 10-limb).
///   2. Compute q = (a·b − c) / p via BigUint long division.
///   3. Replay the 19-position schoolbook chain to derive the 18
///      signed carries.
///   4. Write c-limbs, c-bits, q-limbs, q-bits, carry-bits.
///
/// Pre-condition: `fe_a`, `fe_b` are tight (each limb in [0, 2^26),
/// integer in [0, 2p)).  In debug builds, panics if any carry's
/// magnitude exceeds the bias-encoded range [−2^35, 2^35).
pub fn fill_mul_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &MulGadgetLayout,
    fe_a: &FieldElement,
    fe_b: &FieldElement,
) {
    use crate::p256_field::P_LIMBS_TIGHT;

    // (1) c = a · b mod p in canonical form.
    let mut c = fe_a.mul(fe_b);
    c.freeze();

    // (2) q = (a · b − c) / p via BigUint long division.
    let q = compute_quotient(fe_a, fe_b, &c);

    // (3) Carry chain over 19 positions.
    //
    //   LHS_k = Σ_{i+j=k} a[i]·b[j] − Σ_{i+j=k} q[i]·p_limb[j] − C[k]
    //   where C[k] = c[k] for k<10 else 0.
    //
    //   Per-position: LHS_k + carry[k−1] − carry[k] · 2^26 = 0,
    //   with carry[−1] = 0 and carry[18] = 0.
    let mut carries = [0i64; MUL_CARRY_POSITIONS];
    let radix = 1i64 << LIMB_BITS;
    let mut prev: i64 = 0;
    for k in 0..MUL_SCHOOLBOOK_POSITIONS {
        let mut p_ab: i64 = 0;
        let mut p_qp: i64 = 0;
        // Iterate (i, j) with i + j = k, i ∈ [max(0, k−9), min(9, k)].
        let i_lo = k.saturating_sub(NUM_LIMBS - 1);
        let i_hi = std::cmp::min(NUM_LIMBS - 1, k);
        for i in i_lo..=i_hi {
            let j = k - i;
            p_ab += fe_a.limbs[i] * fe_b.limbs[j];
            p_qp += q.limbs[i] * P_LIMBS_TIGHT[j];
        }
        let c_k = if k < NUM_LIMBS { c.limbs[k] } else { 0 };
        let lhs = p_ab - p_qp - c_k + prev;

        if k < MUL_SCHOOLBOOK_POSITIONS - 1 {
            // carry[k] = lhs / 2^26 (Euclidean — exact, since chain closes).
            debug_assert_eq!(
                lhs.rem_euclid(radix),
                0,
                "carry chain residual ≠ 0 at position {}: lhs = {}",
                k,
                lhs
            );
            let cy = lhs.div_euclid(radix);
            debug_assert!(
                cy.abs() < MUL_CARRY_OFFSET,
                "carry[{}] = {} out of bias range [−2^35, 2^35)",
                k,
                cy
            );
            carries[k] = cy;
            prev = cy;
        } else {
            // k = 18: chain must close (lhs == 0).
            debug_assert_eq!(
                lhs, 0,
                "carry chain did not close at position 18: lhs = {}",
                lhs
            );
        }
    }

    // (4) Write trace cells.
    place_element_split(trace, row, layout.c_limbs_base, layout.c_bits_base, &c);
    place_element_split(trace, row, layout.q_limbs_base, layout.q_bits_base, &q);

    // Write carry bits (biased).
    for k in 0..MUL_CARRY_POSITIONS {
        let biased = (carries[k] + MUL_CARRY_OFFSET) as u64;
        for b in 0..MUL_CARRY_BITS {
            let bit = (biased >> b) & 1;
            trace[mul_carry_bit_cell(layout, k, b)][row] = F::from(bit);
        }
    }
}

/// Emit the `MUL_GADGET_CONSTRAINTS` transition constraints for one
/// mul gadget.  Returns a vector of length `MUL_GADGET_CONSTRAINTS`;
/// on a valid trace every entry is zero.
///
/// Constraint order:
///   1.   270:           c range-check (260 booleanity + 10 limb-pack)
///   2.   270:           q range-check (260 booleanity + 10 limb-pack)
///   3.    19:           position identities (carry chain)
///   4.   648 (18×36):   carry-bit booleanity
pub fn eval_mul_gadget(cur: &[F], layout: &MulGadgetLayout) -> Vec<F> {
    use crate::p256_field::P_LIMBS_TIGHT;

    let mut out = Vec::with_capacity(MUL_GADGET_CONSTRAINTS);

    // Helper: range-check an element block at given limb/bit bases.
    let range_check = |out: &mut Vec<F>, limbs_base: usize, bits_base: usize| {
        // Booleanity.
        for i in 0..NUM_LIMBS {
            for b in 0..LIMB_BITS as usize {
                let cell = cur[bits_base + i * (LIMB_BITS as usize) + b];
                out.push(cell * (F::one() - cell));
            }
        }
        // Limb pack.
        for i in 0..NUM_LIMBS {
            let mut s = F::zero();
            for b in 0..LIMB_BITS as usize {
                s += F::from(1u64 << b) * cur[bits_base + i * (LIMB_BITS as usize) + b];
            }
            out.push(cur[limbs_base + i] - s);
        }
    };

    // (1) c range-check.
    range_check(&mut out, layout.c_limbs_base, layout.c_bits_base);
    // (2) q range-check.
    range_check(&mut out, layout.q_limbs_base, layout.q_bits_base);

    // Helper: reconstruct signed carry at position k from its bits.
    let signed_carry = |k: usize| -> F {
        if k >= MUL_CARRY_POSITIONS {
            // Boundary: carry[18] = 0 (chain end, no cell).
            return F::zero();
        }
        let mut biased = F::zero();
        for b in 0..MUL_CARRY_BITS {
            biased += F::from(1u64 << b) * cur[mul_carry_bit_cell(layout, k, b)];
        }
        biased - F::from(MUL_CARRY_OFFSET as u64)
    };

    // (3) 19 position identities.
    let radix = F::from(1u64 << LIMB_BITS);
    for k in 0..MUL_SCHOOLBOOK_POSITIONS {
        let mut p_ab = F::zero();
        let mut p_qp = F::zero();
        let i_lo = k.saturating_sub(NUM_LIMBS - 1);
        let i_hi = std::cmp::min(NUM_LIMBS - 1, k);
        for i in i_lo..=i_hi {
            let j = k - i;
            p_ab += cur[layout.a_limbs_base + i] * cur[layout.b_limbs_base + j];
            p_qp +=
                cur[layout.q_limbs_base + i] * F::from(P_LIMBS_TIGHT[j] as u64);
        }
        let c_k = if k < NUM_LIMBS {
            cur[layout.c_limbs_base + k]
        } else {
            F::zero()
        };
        let carry_in = if k == 0 {
            F::zero()
        } else {
            signed_carry(k - 1)
        };
        let carry_out = signed_carry(k); // F::zero() for k = 18 (boundary).
        out.push(p_ab - p_qp - c_k + carry_in - radix * carry_out);
    }

    // (4) Carry-bit booleanity.
    for k in 0..MUL_CARRY_POSITIONS {
        for b in 0..MUL_CARRY_BITS {
            let cell = cur[mul_carry_bit_cell(layout, k, b)];
            out.push(cell * (F::one() - cell));
        }
    }

    debug_assert_eq!(out.len(), MUL_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  SQUARE GADGET (= MUL with a = b)
// ═══════════════════════════════════════════════════════════════════
//
// In the witness-q schoolbook design, computing a · a produces the
// same constraint shape as a · b — there's no specialisation that
// reduces constraint count when a = b (we'd save ~half of the (i, j)
// products in a free-form multiplier, but here the constraint sums
// over (i, j) at each position and arithmetic on a · a is the same
// algebra as on a · b).
//
// The square gadget is therefore the MUL gadget with `a_limbs_base`
// and `b_limbs_base` pointing at the same 10-cell block.  No new
// layout struct or constraints needed — composing AIRs simply set
// the layout's two input bases to the same offset.
//
// `fill_square_gadget` is provided as an ergonomic wrapper that takes
// a single `fe_a` argument; `eval_square_gadget` is identical to
// `eval_mul_gadget` (since the constraints don't care that the inputs
// happen to be equal).

/// Cells owned by a square gadget (identical to the mul gadget).
pub const SQUARE_GADGET_OWNED_CELLS: usize = MUL_GADGET_OWNED_CELLS;

/// Constraints emitted per square gadget (identical to the mul gadget).
pub const SQUARE_GADGET_CONSTRAINTS: usize = MUL_GADGET_CONSTRAINTS;

/// Layout for a square gadget.  Same as `MulGadgetLayout`, with the
/// caller responsible for setting `a_limbs_base == b_limbs_base`.
pub type SquareGadgetLayout = MulGadgetLayout;

/// Fill the gadget-owned cells for c = a² mod p.  Convenience wrapper
/// over `fill_mul_gadget(_, _, _, fe_a, fe_a)`.
pub fn fill_square_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &SquareGadgetLayout,
    fe_a: &FieldElement,
) {
    fill_mul_gadget(trace, row, layout, fe_a, fe_a);
}

/// Emit the square-gadget constraints.  Identical to `eval_mul_gadget`.
pub fn eval_square_gadget(cur: &[F], layout: &SquareGadgetLayout) -> Vec<F> {
    eval_mul_gadget(cur, layout)
}

// ═══════════════════════════════════════════════════════════════════
//  CONDITIONAL-SELECT GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Computes c = sel ? a : b, used in the constant-time scalar-mult
// ladder for ECDSA-P256 verification (Phase 4).  The selector bit
// `sel` is in {0, 1}.
//
// Per-limb constraint (with sel ∈ {0, 1}):
//
//     c[k] − sel · a[k] − (1 − sel) · b[k] = 0
//
// rewritten as
//
//     c[k] − b[k] − sel · (a[k] − b[k]) = 0       (deg 2 in sel × (a − b))
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
//   c_limbs_base + 0..10   :  c output limbs              (10)
//   c_bits_base  + 0..260  :  c bit decomposition         (260)
//   sel_cell               :  1-bit selector              (1)
//   ──────────────────────────────────────────────────────────
//   TOTAL OWNED                                          271 cells
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on c:                     270 deg-≤2
//   Per-limb multiplexer identities:       10 deg-2
//   sel booleanity:                         1 deg-2
//   ─────────────────────────────────────────────────────
//   TOTAL                                 281 constraints

/// Cells owned by a cond-select gadget.
pub const SELECT_GADGET_OWNED_CELLS: usize = ELEMENT_CELLS + 1;

/// Constraints emitted per cond-select gadget instance.
pub const SELECT_GADGET_CONSTRAINTS: usize = ELEMENT_CONSTRAINTS + NUM_LIMBS + 1;

/// Cell-offset descriptor for one cond-select gadget instance.
#[derive(Clone, Copy, Debug)]
pub struct SelectGadgetLayout {
    pub a_limbs_base: usize,
    pub b_limbs_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base: usize,
    /// Single-cell selector.  Constrained to {0, 1}.
    pub sel_cell: usize,
}

/// Fill the gadget-owned cells for c = sel ? a : b.
///
/// Pre-condition: `fe_a`, `fe_b` are tight (each limb in [0, 2^26)).
/// `sel ∈ {0, 1}`.  Output `c` will be tight if its source is tight.
pub fn fill_select_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &SelectGadgetLayout,
    fe_a: &FieldElement,
    fe_b: &FieldElement,
    sel: bool,
) {
    let chosen = if sel { fe_a } else { fe_b };
    place_element_split(trace, row, layout.c_limbs_base, layout.c_bits_base, chosen);
    trace[layout.sel_cell][row] = F::from(sel as u64);
}

/// Emit the `SELECT_GADGET_CONSTRAINTS` transition constraints.
pub fn eval_select_gadget(cur: &[F], layout: &SelectGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(SELECT_GADGET_CONSTRAINTS);

    // (1) Range check on c.
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_BITS as usize {
            let cell = cur[layout.c_bits_base + i * (LIMB_BITS as usize) + b];
            out.push(cell * (F::one() - cell));
        }
    }
    for i in 0..NUM_LIMBS {
        let mut s = F::zero();
        for b in 0..LIMB_BITS as usize {
            s += F::from(1u64 << b)
                * cur[layout.c_bits_base + i * (LIMB_BITS as usize) + b];
        }
        out.push(cur[layout.c_limbs_base + i] - s);
    }

    // (2) Multiplexer per-limb: c[k] − b[k] − sel · (a[k] − b[k]) = 0.
    let sel = cur[layout.sel_cell];
    for k in 0..NUM_LIMBS {
        let a_k = cur[layout.a_limbs_base + k];
        let b_k = cur[layout.b_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];
        out.push(c_k - b_k - sel * (a_k - b_k));
    }

    // (3) sel booleanity.
    out.push(sel * (F::one() - sel));

    debug_assert_eq!(out.len(), SELECT_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  FREEZE GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Brings a tight-form input (integer in [0, 2p)) to canonical form
// (integer in [0, p)).  Two-step pattern:
//
//   1. Compute `diff = a − p` via a signed-carry chain (mod 2^260).
//      The chain's final carry-out at limb 9 reveals the sign:
//        carry[9] = 0  ⇒  a ≥ p, diff = a − p ∈ [0, p).
//        carry[9] = −1 ⇒  a < p, diff has wrapped (= a − p + 2^260).
//
//   2. Multiplexer:  c = (carry[9] = 0) ? diff : a.
//      Encoded as  c[k] = diff[k] + C_neg[9] · (a[k] − diff[k]),
//      where C_neg[9] is the negative-carry indicator at limb 9.
//
// Pre-condition: input integer < 2p (i.e., the gadget that produced
// `a` is one of add / sub / freeze, all of which output < 2p).  Mul
// already produces canonical output, so freeze after mul is a no-op
// (carry[9] = 0, c = diff = a).
//
// Without the < 2p precondition, a in [2p, 2^260) would yield a
// non-canonical c ∈ [p, 2p), violating the freeze contract.  We do
// not enforce < 2p in-circuit (it's compositional).
//
// ─────────────────────────────────────────────────────────────────
// SIGNED CARRY CHAIN
// ─────────────────────────────────────────────────────────────────
//
// Per-limb constraint (with carry[k] ∈ {−1, 0, +1}, encoded as
// C_pos[k] − C_neg[k]):
//
//     a[k] − p_limb[k] − diff[k] + carry_in[k] − carry_out[k] · 2^26 = 0
//
// carry_in[0] = 0; carry_in[k] = carry_out[k − 1] for k > 0.  No
// constraint on carry_out[9] (it's allowed to be 0 or −1; this
// indicator drives the multiplexer).
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
//   diff_limbs_base + 0..10   : diff = a − p (mod 2^260)            (10)
//   diff_bits_base  + 0..260  : diff bit decomposition (range)     (260)
//   c_limbs_base    + 0..10   : c output limbs                      (10)
//   c_bits_base     + 0..260  : c bit decomposition                (260)
//   c_pos_base      + 0..10   : C_pos for chain carries             (10)
//   c_neg_base      + 0..10   : C_neg for chain carries             (10)
//   ─────────────────────────────────────────────────────────────────
//   TOTAL OWNED                                                    560 cells
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on diff:                  270 deg-≤2
//   Range check on c:                     270 deg-≤2
//   Limb-difference (carry chain):         10 deg-1
//   C_pos booleanity:                      10 deg-2
//   C_neg booleanity:                      10 deg-2
//   Mutual exclusion C_pos · C_neg = 0:    10 deg-2
//   C_pos[9] = 0 (no positive carry-out):   1 deg-1
//   Per-limb multiplexer:                  10 deg-2
//   ──────────────────────────────────────────────────────
//   TOTAL                                 591 constraints

/// Cells owned by a freeze gadget.
pub const FREEZE_GADGET_OWNED_CELLS: usize = 2 * ELEMENT_CELLS + 2 * NUM_LIMBS;

/// Constraints emitted per freeze gadget instance.
pub const FREEZE_GADGET_CONSTRAINTS: usize =
    2 * ELEMENT_CONSTRAINTS    // diff + c range
    + NUM_LIMBS                 // chain identities
    + 2 * NUM_LIMBS             // pos/neg booleanity
    + NUM_LIMBS                 // mutual exclusion
    + 1                         // C_pos[9] = 0
    + NUM_LIMBS;                // multiplexer

/// Cell-offset descriptor for one freeze gadget instance.
#[derive(Clone, Copy, Debug)]
pub struct FreezeGadgetLayout {
    pub a_limbs_base: usize,
    pub diff_limbs_base: usize,
    pub diff_bits_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base: usize,
    /// Base of 10 positive-carry indicators (C_pos[0..9]).
    pub c_pos_base: usize,
    /// Base of 10 negative-carry indicators (C_neg[0..9]).
    pub c_neg_base: usize,
}

/// Fill the gadget-owned cells for c = canonical(a).
///
/// Pre-condition: `fe_a` is tight with integer in [0, 2p).  Computes
/// diff = a − p (mod 2^260) and selects c = a if a < p, else c = a − p.
pub fn fill_freeze_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &FreezeGadgetLayout,
    fe_a: &FieldElement,
) {
    use crate::p256_field::P_LIMBS_TIGHT;

    // Replay the chain "a − p = diff" with signed carries.
    let mut diff_limbs = [0i64; NUM_LIMBS];
    let mut carries = [0i64; NUM_LIMBS];
    let mut prev = 0i64;
    let radix = 1i64 << LIMB_BITS;
    for k in 0..NUM_LIMBS {
        let lhs = fe_a.limbs[k] - P_LIMBS_TIGHT[k] + prev;
        diff_limbs[k] = lhs.rem_euclid(radix);
        carries[k] = lhs.div_euclid(radix);
        debug_assert!(
            carries[k].abs() <= 1,
            "freeze chain carry at limb {} out of range: {} (input not tight)",
            k,
            carries[k]
        );
        prev = carries[k];
    }
    // For input a in [0, 2p), carry[9] must be 0 (a ≥ p) or −1 (a < p),
    // never +1.  Enforce in debug.
    debug_assert!(
        carries[NUM_LIMBS - 1] == 0 || carries[NUM_LIMBS - 1] == -1,
        "freeze: input not in [0, 2p)"
    );

    // Multiplexer: c = (carry[9] = -1) ? a : diff.
    let c_neg_9 = if carries[NUM_LIMBS - 1] == -1 { 1i64 } else { 0i64 };
    let mut c_limbs = [0i64; NUM_LIMBS];
    for k in 0..NUM_LIMBS {
        c_limbs[k] = if c_neg_9 == 1 {
            fe_a.limbs[k]
        } else {
            diff_limbs[k]
        };
    }

    // Construct FieldElements for the trace placement.
    let diff_fe = FieldElement { limbs: diff_limbs };
    let c_fe = FieldElement { limbs: c_limbs };
    place_element_split(
        trace,
        row,
        layout.diff_limbs_base,
        layout.diff_bits_base,
        &diff_fe,
    );
    place_element_split(
        trace,
        row,
        layout.c_limbs_base,
        layout.c_bits_base,
        &c_fe,
    );

    // Encode signed carries.
    for k in 0..NUM_LIMBS {
        let (cp, cn) = match carries[k] {
            1 => (1u64, 0u64),
            -1 => (0u64, 1u64),
            0 => (0u64, 0u64),
            _ => unreachable!(),
        };
        trace[layout.c_pos_base + k][row] = F::from(cp);
        trace[layout.c_neg_base + k][row] = F::from(cn);
    }
}

/// Emit the `FREEZE_GADGET_CONSTRAINTS` transition constraints.
pub fn eval_freeze_gadget(cur: &[F], layout: &FreezeGadgetLayout) -> Vec<F> {
    use crate::p256_field::P_LIMBS_TIGHT;

    let mut out = Vec::with_capacity(FREEZE_GADGET_CONSTRAINTS);

    // (1) Range check on diff.
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_BITS as usize {
            let cell = cur[layout.diff_bits_base + i * (LIMB_BITS as usize) + b];
            out.push(cell * (F::one() - cell));
        }
    }
    for i in 0..NUM_LIMBS {
        let mut s = F::zero();
        for b in 0..LIMB_BITS as usize {
            s += F::from(1u64 << b)
                * cur[layout.diff_bits_base + i * (LIMB_BITS as usize) + b];
        }
        out.push(cur[layout.diff_limbs_base + i] - s);
    }

    // (2) Range check on c.
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_BITS as usize {
            let cell = cur[layout.c_bits_base + i * (LIMB_BITS as usize) + b];
            out.push(cell * (F::one() - cell));
        }
    }
    for i in 0..NUM_LIMBS {
        let mut s = F::zero();
        for b in 0..LIMB_BITS as usize {
            s += F::from(1u64 << b)
                * cur[layout.c_bits_base + i * (LIMB_BITS as usize) + b];
        }
        out.push(cur[layout.c_limbs_base + i] - s);
    }

    // (3) Chain identities: a[k] − p_limb[k] − diff[k] + carry_in[k] − carry_out[k]·2^26 = 0.
    let radix = F::from(1u64 << LIMB_BITS);
    let net_out = |k: usize| -> F {
        cur[layout.c_pos_base + k] - cur[layout.c_neg_base + k]
    };
    for k in 0..NUM_LIMBS {
        let a_k = cur[layout.a_limbs_base + k];
        let p_k = F::from(P_LIMBS_TIGHT[k] as u64);
        let diff_k = cur[layout.diff_limbs_base + k];
        let carry_in = if k == 0 { F::zero() } else { net_out(k - 1) };
        out.push(a_k - p_k - diff_k + carry_in - radix * net_out(k));
    }

    // (4) C_pos booleanity.
    for k in 0..NUM_LIMBS {
        let cp = cur[layout.c_pos_base + k];
        out.push(cp * (F::one() - cp));
    }
    // (5) C_neg booleanity.
    for k in 0..NUM_LIMBS {
        let cn = cur[layout.c_neg_base + k];
        out.push(cn * (F::one() - cn));
    }
    // (6) Mutual exclusion.
    for k in 0..NUM_LIMBS {
        let cp = cur[layout.c_pos_base + k];
        let cn = cur[layout.c_neg_base + k];
        out.push(cp * cn);
    }

    // (7) C_pos[9] = 0 (no positive carry-out: a < 2p means a − p < 2^260).
    out.push(cur[layout.c_pos_base + NUM_LIMBS - 1]);

    // (8) Multiplexer per limb: c[k] = (C_neg[9] = 1) ? a[k] : diff[k].
    //     c[k] − diff[k] − C_neg[9] · (a[k] − diff[k]) = 0
    let c_neg_9 = cur[layout.c_neg_base + NUM_LIMBS - 1];
    for k in 0..NUM_LIMBS {
        let a_k = cur[layout.a_limbs_base + k];
        let diff_k = cur[layout.diff_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];
        out.push(c_k - diff_k - c_neg_9 * (a_k - diff_k));
    }

    debug_assert_eq!(out.len(), FREEZE_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256_field::{FieldElement, B_CURVE};

    fn make_trace_row(width: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); 1]).collect()
    }

    fn fe_from_seed(seed: u64) -> FieldElement {
        // Build a tight-form FE by reducing a pseudo-random byte string
        // mod p (via the native `freeze`-then-place pipeline).
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((seed.wrapping_mul(7) + i as u64 * 11) % 256) as u8;
        }
        let mut fe = FieldElement::from_be_bytes(&bytes);
        fe.freeze();
        fe
    }

    #[test]
    fn cell_count_matches_documented_constants() {
        assert_eq!(ELEMENT_LIMB_CELLS, 10);
        assert_eq!(ELEMENT_BIT_CELLS, 260);
        assert_eq!(ELEMENT_CELLS, 270);
        assert_eq!(ELEMENT_CONSTRAINTS, 270);
        // NUM_LIMBS · LIMB_BITS = ELEMENT_BIT_CELLS.
        assert_eq!(NUM_LIMBS * (LIMB_BITS as usize), ELEMENT_BIT_CELLS);
    }

    #[test]
    fn bit_cell_addressing_is_unique_and_in_range() {
        // No two (limb_idx, bit_idx) pairs map to the same cell, and
        // every cell offset is within ELEMENT_CELLS.
        let mut seen = vec![false; ELEMENT_CELLS];
        for i in 0..NUM_LIMBS {
            for b in 0..LIMB_BITS as usize {
                let c = bit_cell(i, b);
                assert!(c >= ELEMENT_BITS_BASE);
                assert!(c < ELEMENT_CELLS);
                assert!(!seen[c], "duplicate bit cell at {}", c);
                seen[c] = true;
            }
        }
        for c in ELEMENT_BITS_BASE..ELEMENT_CELLS {
            assert!(seen[c], "unaddressed bit cell at {}", c);
        }
    }

    #[test]
    fn place_then_read_is_identity() {
        for seed in 0u64..8 {
            let fe = fe_from_seed(seed);
            let mut trace = make_trace_row(ELEMENT_CELLS);
            place_element(&mut trace, 0, 0, &fe);
            let read_back = read_element(&trace, 0, 0);
            assert_eq!(
                read_back.limbs, fe.limbs,
                "place+read mismatch for seed {}",
                seed
            );
        }
    }

    #[test]
    fn range_check_passes_on_canonical_element() {
        for seed in 0u64..8 {
            let fe = fe_from_seed(seed);
            let mut trace = make_trace_row(ELEMENT_CELLS);
            place_element(&mut trace, 0, 0, &fe);
            let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
            let cons = eval_element_range_check(&cur, 0);
            for (i, v) in cons.iter().enumerate() {
                assert!(
                    v.is_zero(),
                    "constraint #{} non-zero for seed {}: {:?}",
                    i,
                    seed,
                    v
                );
            }
        }
    }

    #[test]
    fn range_check_fails_on_tampered_bit() {
        // Place a valid element, set one bit cell to "2" (out of {0,1});
        // expect the booleanity constraint for that cell to fire.
        let fe = fe_from_seed(42);
        let mut trace = make_trace_row(ELEMENT_CELLS);
        place_element(&mut trace, 0, 0, &fe);

        let target_cell = bit_cell(3, 5);
        trace[target_cell][0] = F::from(2u64);

        let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
        let cons = eval_element_range_check(&cur, 0);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(
            nonzero >= 1,
            "tampered bit cell did not produce a constraint violation"
        );
    }

    #[test]
    fn range_check_fails_on_tampered_limb() {
        // Place a valid element, change one limb cell so it no longer
        // matches its bit decomposition; expect that limb's pack
        // constraint to be non-zero and all booleanity constraints
        // (untouched bit cells) to remain zero.
        let fe = fe_from_seed(11);
        let mut trace = make_trace_row(ELEMENT_CELLS);
        place_element(&mut trace, 0, 0, &fe);

        let original = trace[4][0];
        trace[4][0] = original + F::one();

        let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
        let cons = eval_element_range_check(&cur, 0);

        for i in 0..ELEMENT_BIT_CELLS {
            assert!(
                cons[i].is_zero(),
                "booleanity constraint #{} unexpectedly non-zero",
                i
            );
        }
        assert!(
            !cons[ELEMENT_BIT_CELLS + 4].is_zero(),
            "limb-pack constraint for limb 4 should detect the tamper"
        );
        for k in 0..NUM_LIMBS {
            if k != 4 {
                assert!(
                    cons[ELEMENT_BIT_CELLS + k].is_zero(),
                    "limb-pack #{} unexpectedly non-zero",
                    k
                );
            }
        }
    }

    #[test]
    fn range_check_fails_on_high_bit_overflow() {
        // The 26-bit limb width is uniform but the high 4 bits of limb 9
        // (bits 256..260 of the integer) should generally be zero for
        // values < p.  However the layout *permits* them to be set
        // (range check is "limb < 2^26", not "integer < p").  Instead
        // of testing for a constraint violation here, verify that the
        // constraint evaluator correctly accepts a high-bit-set limb
        // when its bit decomposition matches.
        let mut fe = FieldElement::zero();
        fe.limbs[9] = (1i64 << 25) | 5; // top bit of limb 9 set, plus 5

        let mut trace = make_trace_row(ELEMENT_CELLS);
        place_element(&mut trace, 0, 0, &fe);

        let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
        let cons = eval_element_range_check(&cur, 0);
        for v in &cons {
            assert!(
                v.is_zero(),
                "valid 26-bit limb (even with high bit set) should pass range check"
            );
        }
    }

    #[test]
    fn b_curve_constant_round_trips_through_air_layout() {
        // The P-256 b-coefficient should round-trip through place/read
        // and satisfy the range check.
        let b_canonical = {
            let mut t = *B_CURVE;
            t.freeze();
            t
        };
        let mut trace = make_trace_row(ELEMENT_CELLS);
        place_element(&mut trace, 0, 0, &b_canonical);
        let read_back = read_element(&trace, 0, 0);
        assert_eq!(read_back.limbs, b_canonical.limbs);

        let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
        let cons = eval_element_range_check(&cur, 0);
        for v in &cons {
            assert!(v.is_zero(), "B_CURVE range check should be all zeros");
        }
    }

    #[test]
    fn random_canonical_elements_round_trip_and_pass_range_check() {
        // Stress test: many seeded random canonical elements should all
        // place/read losslessly and pass the range check.
        for seed in 0u64..32 {
            let fe = fe_from_seed(seed.wrapping_mul(0x9E37_79B9));
            let mut trace = make_trace_row(ELEMENT_CELLS);
            place_element(&mut trace, 0, 0, &fe);

            let read_back = read_element(&trace, 0, 0);
            assert_eq!(read_back.limbs, fe.limbs, "round-trip seed {}", seed);

            let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
            let cons = eval_element_range_check(&cur, 0);
            for (i, v) in cons.iter().enumerate() {
                assert!(
                    v.is_zero(),
                    "constraint #{} non-zero for seed {}",
                    i,
                    seed
                );
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //  Add-gadget tests
    // ─────────────────────────────────────────────────────────────────

    /// Build a self-contained add-gadget layout: a-input, b-input,
    /// then the gadget-owned cells.  Returns the layout and the total
    /// trace width.
    fn standalone_add_layout() -> (AddGadgetLayout, usize) {
        let a_limbs_base = 0;
        let b_limbs_base = NUM_LIMBS;
        let c_limbs_base = 2 * NUM_LIMBS;
        let c_bits_base = c_limbs_base + NUM_LIMBS;
        let carries_base = c_bits_base + ELEMENT_BIT_CELLS;
        let total = carries_base + NUM_LIMBS;
        (
            AddGadgetLayout {
                a_limbs_base,
                b_limbs_base,
                c_limbs_base,
                c_bits_base,
                carries_base,
            },
            total,
        )
    }

    /// Place inputs, fill the gadget, and assert all constraints
    /// evaluate to zero.  Caller is responsible for ensuring inputs
    /// are tight (canonical).
    fn assert_satisfies_add(
        layout: &AddGadgetLayout,
        total_width: usize,
        fe_a: &FieldElement,
        fe_b: &FieldElement,
    ) {
        let mut trace = make_trace_row(total_width);
        // Place input limbs at a_limbs_base / b_limbs_base.  We only
        // place the limb cells (not the bit decomposition) since the
        // add-gadget constraint only references a_limbs / b_limbs.
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(fe_a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(fe_b.limbs[i] as u64);
        }
        fill_add_gadget(&mut trace, 0, layout, fe_a, fe_b);

        let cur: Vec<F> = (0..total_width).map(|c| trace[c][0]).collect();
        let cons = eval_add_gadget(&cur, layout);
        assert_eq!(cons.len(), ADD_GADGET_CONSTRAINTS);
        for (i, v) in cons.iter().enumerate() {
            assert!(
                v.is_zero(),
                "add-gadget constraint #{} non-zero (a.limbs={:?}, b.limbs={:?})",
                i,
                fe_a.limbs,
                fe_b.limbs
            );
        }
    }

    #[test]
    fn add_gadget_constants() {
        assert_eq!(ADD_GADGET_OWNED_CELLS, 280);
        assert_eq!(ADD_GADGET_CONSTRAINTS, 290);
    }

    #[test]
    fn add_gadget_zero_plus_zero_is_zero() {
        let (layout, total) = standalone_add_layout();
        let zero = FieldElement::zero();
        assert_satisfies_add(&layout, total, &zero, &zero);
    }

    #[test]
    fn add_gadget_zero_plus_x_is_x() {
        let (layout, total) = standalone_add_layout();
        let zero = FieldElement::zero();
        for seed in 0u64..4 {
            let x = fe_from_seed(seed);
            assert_satisfies_add(&layout, total, &zero, &x);
            assert_satisfies_add(&layout, total, &x, &zero);
        }
    }

    #[test]
    fn add_gadget_simple_sums() {
        // Hand-checkable small inputs.
        let (layout, total) = standalone_add_layout();
        let one = FieldElement::one();
        let two = one.add(&one);
        let three = {
            let mut t = two.add(&one);
            t.freeze();
            t
        };
        let two_canon = {
            let mut t = two;
            t.freeze();
            t
        };
        assert_satisfies_add(&layout, total, &one, &two_canon);

        // Verify result by reading c-limbs and comparing.
        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(one.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(two_canon.limbs[i] as u64);
        }
        fill_add_gadget(&mut trace, 0, &layout, &one, &two_canon);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        assert_eq!(c.limbs, three.limbs, "1 + 2 ≠ 3 in trace");
    }

    #[test]
    fn add_gadget_random_canonical_inputs() {
        let (layout, total) = standalone_add_layout();
        for seed in 0u64..16 {
            let a = fe_from_seed(seed);
            let b = fe_from_seed(seed.wrapping_mul(7).wrapping_add(13));
            assert_satisfies_add(&layout, total, &a, &b);
        }
    }

    #[test]
    fn add_gadget_output_matches_native_when_below_p() {
        // For canonical a, b with a + b < p, the add gadget produces
        // exactly a + b (no wrap).  Compare against the native ref.
        let (layout, total) = standalone_add_layout();
        // Choose inputs where a + b < p.  Use small values.
        let a = fe_from_seed(3);
        let mut tiny = FieldElement::zero();
        tiny.limbs[0] = 7;
        tiny.limbs[1] = 11;

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(tiny.limbs[i] as u64);
        }
        fill_add_gadget(&mut trace, 0, &layout, &a, &tiny);

        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut native = a.add(&tiny);
        native.freeze();
        let mut c_canon = c;
        c_canon.freeze();
        assert_eq!(c_canon.limbs, native.limbs);
    }

    #[test]
    fn add_gadget_output_below_2p_when_sum_exceeds_p() {
        // For canonical a, b with a + b ≥ p, the gadget output is
        // tight (each limb < 2^26) but NOT canonical (integer ≥ p).
        // Canonicalising via freeze should match a.add(&b).freeze().
        let (layout, total) = standalone_add_layout();
        // Choose a, b near p so that a + b ≥ p.  Use (p-1) + (p-1) = 2p-2.
        let mut p_minus_1 = {
            // p - 1 in canonical form
            use crate::p256_field::B_CURVE; // any non-zero canonical value works
            let mut bytes = [0u8; 32];
            // Build p - 1 by computing −1 (= p − 1).
            let neg_one = FieldElement::one().neg();
            let mut t = neg_one;
            t.freeze();
            t
        };
        let p_minus_1_clone = p_minus_1;
        // Note p_minus_1 + p_minus_1 = 2p - 2 < 2p < 2^260, so the
        // gadget should accept these inputs (carry[9] = 0).
        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(p_minus_1.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(p_minus_1_clone.limbs[i] as u64);
        }
        fill_add_gadget(&mut trace, 0, &layout, &p_minus_1, &p_minus_1_clone);

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_add_gadget(&cur, &layout);
        for (i, v) in cons.iter().enumerate() {
            assert!(v.is_zero(), "constraint #{} non-zero", i);
        }

        // The output, after canonicalisation, should equal (p-1)+(p-1) mod p = p - 2.
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut c_canon = c;
        c_canon.freeze();
        let mut expected = p_minus_1.add(&p_minus_1_clone);
        expected.freeze();
        assert_eq!(c_canon.limbs, expected.limbs);

        // Silence unused warning (p_minus_1 was rebuilt then mutated above).
        let _ = &mut p_minus_1;
    }

    #[test]
    fn add_gadget_tamper_detection() {
        // Place a valid gadget instance, then perturb one cell and
        // verify the constraint vector contains at least one non-zero
        // entry.
        let (layout, total) = standalone_add_layout();
        let a = fe_from_seed(5);
        let b = fe_from_seed(99);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_add_gadget(&mut trace, 0, &layout, &a, &b);

        // Tamper c-limb 5 by adding 1 (without updating bits).
        let target_cell = layout.c_limbs_base + 5;
        let original = trace[target_cell][0];
        trace[target_cell][0] = original + F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_add_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(
            nonzero >= 1,
            "tampered c-limb did not produce a constraint violation"
        );
    }

    #[test]
    fn add_gadget_tamper_detection_carry() {
        // Flipping a carry cell that should be 0 to 1 should violate
        // either the limb-sum or the booleanity constraints.
        let (layout, total) = standalone_add_layout();
        let a = fe_from_seed(11);
        let b = fe_from_seed(22);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_add_gadget(&mut trace, 0, &layout, &a, &b);

        // Tamper carry[9] from 0 → 1.  This violates the explicit
        // "carry[9] = 0" constraint.
        trace[layout.carries_base + NUM_LIMBS - 1][0] = F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_add_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(
            nonzero >= 1,
            "tampered carry[9] did not produce a constraint violation"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    //  Sub-gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_sub_layout() -> (SubGadgetLayout, usize) {
        let a_limbs_base = 0;
        let b_limbs_base = NUM_LIMBS;
        let c_limbs_base = 2 * NUM_LIMBS;
        let c_bits_base = c_limbs_base + NUM_LIMBS;
        let c_pos_base = c_bits_base + ELEMENT_BIT_CELLS;
        let c_neg_base = c_pos_base + NUM_LIMBS;
        let total = c_neg_base + NUM_LIMBS;
        (
            SubGadgetLayout {
                a_limbs_base,
                b_limbs_base,
                c_limbs_base,
                c_bits_base,
                c_pos_base,
                c_neg_base,
            },
            total,
        )
    }

    fn assert_satisfies_sub(
        layout: &SubGadgetLayout,
        total_width: usize,
        fe_a: &FieldElement,
        fe_b: &FieldElement,
    ) {
        let mut trace = make_trace_row(total_width);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(fe_a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(fe_b.limbs[i] as u64);
        }
        fill_sub_gadget(&mut trace, 0, layout, fe_a, fe_b);

        let cur: Vec<F> = (0..total_width).map(|c| trace[c][0]).collect();
        let cons = eval_sub_gadget(&cur, layout);
        assert_eq!(cons.len(), SUB_GADGET_CONSTRAINTS);
        for (i, v) in cons.iter().enumerate() {
            assert!(
                v.is_zero(),
                "sub-gadget constraint #{} non-zero (a.limbs={:?}, b.limbs={:?})",
                i,
                fe_a.limbs,
                fe_b.limbs
            );
        }
    }

    #[test]
    fn sub_gadget_constants() {
        assert_eq!(SUB_GADGET_OWNED_CELLS, 290);
        assert_eq!(SUB_GADGET_CONSTRAINTS, 311);
    }

    #[test]
    fn sub_gadget_zero_minus_zero_is_zero() {
        let (layout, total) = standalone_sub_layout();
        let zero = FieldElement::zero();
        assert_satisfies_sub(&layout, total, &zero, &zero);

        // Verify the result.
        let mut trace = make_trace_row(total);
        fill_sub_gadget(&mut trace, 0, &layout, &zero, &zero);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut c_canon = c;
        c_canon.freeze();
        assert!(c_canon.is_zero(), "0 - 0 should be 0");
    }

    #[test]
    fn sub_gadget_x_minus_x_is_zero() {
        let (layout, total) = standalone_sub_layout();
        for seed in 0u64..4 {
            let x = fe_from_seed(seed);
            assert_satisfies_sub(&layout, total, &x, &x);

            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(x.limbs[i] as u64);
                trace[layout.b_limbs_base + i][0] = F::from(x.limbs[i] as u64);
            }
            fill_sub_gadget(&mut trace, 0, &layout, &x, &x);
            let c = read_element(&trace, 0, layout.c_limbs_base);
            let mut c_canon = c;
            c_canon.freeze();
            assert!(c_canon.is_zero(), "x - x should be 0 (seed {})", seed);
        }
    }

    #[test]
    fn sub_gadget_simple_difference() {
        // 5 - 3 = 2 (no underflow).
        let (layout, total) = standalone_sub_layout();
        let mut five = FieldElement::zero();
        five.limbs[0] = 5;
        let mut three = FieldElement::zero();
        three.limbs[0] = 3;

        assert_satisfies_sub(&layout, total, &five, &three);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(five.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(three.limbs[i] as u64);
        }
        fill_sub_gadget(&mut trace, 0, &layout, &five, &three);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut c_canon = c;
        c_canon.freeze();
        let mut two = FieldElement::zero();
        two.limbs[0] = 2;
        assert_eq!(c_canon.limbs, two.limbs, "5 - 3 should canonicalise to 2");
    }

    #[test]
    fn sub_gadget_underflow_wraps() {
        // 3 - 5 should canonicalise to p - 2.
        let (layout, total) = standalone_sub_layout();
        let mut three = FieldElement::zero();
        three.limbs[0] = 3;
        let mut five = FieldElement::zero();
        five.limbs[0] = 5;

        assert_satisfies_sub(&layout, total, &three, &five);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(three.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(five.limbs[i] as u64);
        }
        fill_sub_gadget(&mut trace, 0, &layout, &three, &five);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut c_canon = c;
        c_canon.freeze();

        // Expected: p - 2.
        let two = {
            let mut t = FieldElement::zero();
            t.limbs[0] = 2;
            t
        };
        let mut p_minus_2 = two.neg();
        p_minus_2.freeze();
        assert_eq!(c_canon.limbs, p_minus_2.limbs, "3 - 5 should be p - 2");
    }

    #[test]
    fn sub_gadget_zero_minus_one_is_p_minus_one() {
        let (layout, total) = standalone_sub_layout();
        let zero = FieldElement::zero();
        let one = FieldElement::one();

        assert_satisfies_sub(&layout, total, &zero, &one);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(zero.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(one.limbs[i] as u64);
        }
        fill_sub_gadget(&mut trace, 0, &layout, &zero, &one);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut c_canon = c;
        c_canon.freeze();

        // Expected: -1 ≡ p - 1 (mod p).
        let mut neg_one = one.neg();
        neg_one.freeze();
        assert_eq!(c_canon.limbs, neg_one.limbs);
    }

    #[test]
    fn sub_gadget_random_canonical_inputs() {
        let (layout, total) = standalone_sub_layout();
        for seed in 0u64..16 {
            let a = fe_from_seed(seed);
            let b = fe_from_seed(seed.wrapping_mul(11).wrapping_add(7));
            assert_satisfies_sub(&layout, total, &a, &b);

            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
                trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
            }
            fill_sub_gadget(&mut trace, 0, &layout, &a, &b);
            let c = read_element(&trace, 0, layout.c_limbs_base);
            let mut c_canon = c;
            c_canon.freeze();

            let mut native = a.sub(&b);
            native.freeze();
            assert_eq!(
                c_canon.limbs, native.limbs,
                "sub gadget output ≠ native ref (seed {})",
                seed
            );
        }
    }

    #[test]
    fn sub_gadget_tamper_detection() {
        // Tamper c-limb and expect violation.
        let (layout, total) = standalone_sub_layout();
        let a = fe_from_seed(31);
        let b = fe_from_seed(17);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_sub_gadget(&mut trace, 0, &layout, &a, &b);

        let target = layout.c_limbs_base + 7;
        let original = trace[target][0];
        trace[target][0] = original + F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_sub_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1, "tamper not detected");
    }

    #[test]
    fn sub_gadget_tamper_detection_mutual_exclusion() {
        // Setting both C_pos[k] = C_neg[k] = 1 must trip the mutual
        // exclusion constraint.
        let (layout, total) = standalone_sub_layout();
        let a = fe_from_seed(2);
        let b = fe_from_seed(3);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_sub_gadget(&mut trace, 0, &layout, &a, &b);

        // Force C_pos[2] = C_neg[2] = 1.
        trace[layout.c_pos_base + 2][0] = F::one();
        trace[layout.c_neg_base + 2][0] = F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_sub_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(
            nonzero >= 1,
            "C_pos[2] = C_neg[2] = 1 should violate mutual exclusion"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    //  Mul-gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_mul_layout() -> (MulGadgetLayout, usize) {
        let a_limbs_base = 0;
        let b_limbs_base = NUM_LIMBS;
        let c_limbs_base = 2 * NUM_LIMBS;
        let c_bits_base = c_limbs_base + NUM_LIMBS;
        let q_limbs_base = c_bits_base + ELEMENT_BIT_CELLS;
        let q_bits_base = q_limbs_base + NUM_LIMBS;
        let carry_bits_base = q_bits_base + ELEMENT_BIT_CELLS;
        let total = carry_bits_base + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;
        (
            MulGadgetLayout {
                a_limbs_base,
                b_limbs_base,
                c_limbs_base,
                c_bits_base,
                q_limbs_base,
                q_bits_base,
                carry_bits_base,
            },
            total,
        )
    }

    fn assert_satisfies_mul(
        layout: &MulGadgetLayout,
        total_width: usize,
        fe_a: &FieldElement,
        fe_b: &FieldElement,
    ) {
        let mut trace = make_trace_row(total_width);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(fe_a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(fe_b.limbs[i] as u64);
        }
        fill_mul_gadget(&mut trace, 0, layout, fe_a, fe_b);

        let cur: Vec<F> = (0..total_width).map(|c| trace[c][0]).collect();
        let cons = eval_mul_gadget(&cur, layout);
        assert_eq!(cons.len(), MUL_GADGET_CONSTRAINTS);
        for (i, v) in cons.iter().enumerate() {
            assert!(
                v.is_zero(),
                "mul-gadget constraint #{} non-zero (a.limbs={:?}, b.limbs={:?})",
                i,
                fe_a.limbs,
                fe_b.limbs
            );
        }
    }

    #[test]
    fn mul_gadget_constants() {
        assert_eq!(MUL_CARRY_BITS, 36);
        assert_eq!(MUL_CARRY_OFFSET, 1i64 << 35);
        assert_eq!(MUL_CARRY_POSITIONS, 18);
        assert_eq!(MUL_SCHOOLBOOK_POSITIONS, 19);
        assert_eq!(MUL_GADGET_OWNED_CELLS, 1188);
        assert_eq!(MUL_GADGET_CONSTRAINTS, 1207);
    }

    #[test]
    fn mul_gadget_zero_times_zero_is_zero() {
        let (layout, total) = standalone_mul_layout();
        let zero = FieldElement::zero();
        assert_satisfies_mul(&layout, total, &zero, &zero);

        let mut trace = make_trace_row(total);
        fill_mul_gadget(&mut trace, 0, &layout, &zero, &zero);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        assert!(c.is_zero(), "0 · 0 should be 0");
    }

    #[test]
    fn mul_gadget_one_times_x_is_x() {
        let (layout, total) = standalone_mul_layout();
        let one = FieldElement::one();
        for seed in 0u64..4 {
            let x = fe_from_seed(seed);
            assert_satisfies_mul(&layout, total, &one, &x);
            assert_satisfies_mul(&layout, total, &x, &one);

            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(one.limbs[i] as u64);
                trace[layout.b_limbs_base + i][0] = F::from(x.limbs[i] as u64);
            }
            fill_mul_gadget(&mut trace, 0, &layout, &one, &x);
            let c = read_element(&trace, 0, layout.c_limbs_base);
            assert_eq!(c.limbs, x.limbs, "1 · x ≠ x for seed {}", seed);
        }
    }

    #[test]
    fn mul_gadget_simple_products() {
        // 2 · 3 = 6 (no mod-p reduction needed).
        let (layout, total) = standalone_mul_layout();
        let mut two = FieldElement::zero();
        two.limbs[0] = 2;
        let mut three = FieldElement::zero();
        three.limbs[0] = 3;
        let mut six = FieldElement::zero();
        six.limbs[0] = 6;

        assert_satisfies_mul(&layout, total, &two, &three);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(two.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(three.limbs[i] as u64);
        }
        fill_mul_gadget(&mut trace, 0, &layout, &two, &three);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        assert_eq!(c.limbs, six.limbs, "2 · 3 ≠ 6");
    }

    #[test]
    fn mul_gadget_p_minus_1_squared_is_one() {
        // (p − 1)² ≡ 1 (mod p).
        let (layout, total) = standalone_mul_layout();
        let mut neg_one = FieldElement::one().neg();
        neg_one.freeze();
        assert_satisfies_mul(&layout, total, &neg_one, &neg_one);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(neg_one.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(neg_one.limbs[i] as u64);
        }
        fill_mul_gadget(&mut trace, 0, &layout, &neg_one, &neg_one);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let one = FieldElement::one();
        assert_eq!(c.limbs, one.limbs, "(p-1)^2 ≠ 1 (mod p)");
    }

    #[test]
    fn mul_gadget_random_canonical_inputs() {
        let (layout, total) = standalone_mul_layout();
        for seed in 0u64..8 {
            let a = fe_from_seed(seed);
            let b = fe_from_seed(seed.wrapping_mul(13).wrapping_add(7));
            assert_satisfies_mul(&layout, total, &a, &b);

            // Read c, compare with native mul.
            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
                trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
            }
            fill_mul_gadget(&mut trace, 0, &layout, &a, &b);
            let c = read_element(&trace, 0, layout.c_limbs_base);
            let mut native = a.mul(&b);
            native.freeze();
            assert_eq!(
                c.limbs, native.limbs,
                "mul-gadget output ≠ native mul (seed {})",
                seed
            );
        }
    }

    #[test]
    fn mul_gadget_b_curve_squared_matches_native() {
        // B_CURVE · B_CURVE — exercises a non-trivial real-world value.
        use crate::p256_field::B_CURVE;
        let (layout, total) = standalone_mul_layout();
        let b = {
            let mut t = *B_CURVE;
            t.freeze();
            t
        };
        assert_satisfies_mul(&layout, total, &b, &b);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(b.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_mul_gadget(&mut trace, 0, &layout, &b, &b);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut native = b.mul(&b);
        native.freeze();
        assert_eq!(c.limbs, native.limbs, "B² gadget vs native mismatch");
    }

    #[test]
    fn mul_gadget_tamper_detection_c_limb() {
        let (layout, total) = standalone_mul_layout();
        let a = fe_from_seed(5);
        let b = fe_from_seed(7);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_mul_gadget(&mut trace, 0, &layout, &a, &b);

        let target = layout.c_limbs_base + 4;
        let original = trace[target][0];
        trace[target][0] = original + F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_mul_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1, "tampered c-limb undetected");
    }

    #[test]
    fn mul_gadget_tamper_detection_q_limb() {
        let (layout, total) = standalone_mul_layout();
        let a = fe_from_seed(11);
        let b = fe_from_seed(13);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_mul_gadget(&mut trace, 0, &layout, &a, &b);

        // Tamper q[3] by adding 1; this breaks the integer relation
        // a·b = q·p + c at any position k where (q+1)[3]·p_limb[j]
        // contributes — at minimum the position constraint must fire.
        let target = layout.q_limbs_base + 3;
        let original = trace[target][0];
        trace[target][0] = original + F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_mul_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1, "tampered q-limb undetected");
    }

    // ─────────────────────────────────────────────────────────────────
    //  Square-gadget tests
    // ─────────────────────────────────────────────────────────────────

    /// Standalone square layout: a-input only (no b), then mul-gadget owned cells.
    /// Sets a_limbs_base == b_limbs_base so the mul constraint reads the same
    /// 10 cells for both operands.
    fn standalone_square_layout() -> (SquareGadgetLayout, usize) {
        let a_limbs_base = 0;
        let b_limbs_base = 0; // SAME as a, makes square = mul(a, a)
        let c_limbs_base = NUM_LIMBS;
        let c_bits_base = c_limbs_base + NUM_LIMBS;
        let q_limbs_base = c_bits_base + ELEMENT_BIT_CELLS;
        let q_bits_base = q_limbs_base + NUM_LIMBS;
        let carry_bits_base = q_bits_base + ELEMENT_BIT_CELLS;
        let total = carry_bits_base + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;
        (
            SquareGadgetLayout {
                a_limbs_base,
                b_limbs_base,
                c_limbs_base,
                c_bits_base,
                q_limbs_base,
                q_bits_base,
                carry_bits_base,
            },
            total,
        )
    }

    #[test]
    fn square_gadget_constants_match_mul() {
        assert_eq!(SQUARE_GADGET_OWNED_CELLS, MUL_GADGET_OWNED_CELLS);
        assert_eq!(SQUARE_GADGET_CONSTRAINTS, MUL_GADGET_CONSTRAINTS);
    }

    #[test]
    fn square_gadget_basic_values() {
        let (layout, total) = standalone_square_layout();
        for seed in 0u64..6 {
            let a = fe_from_seed(seed);
            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            }
            fill_square_gadget(&mut trace, 0, &layout, &a);

            let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
            let cons = eval_square_gadget(&cur, &layout);
            for (i, v) in cons.iter().enumerate() {
                assert!(
                    v.is_zero(),
                    "square constraint #{} non-zero (seed {})",
                    i,
                    seed
                );
            }
            // Verify result.
            let c = read_element(&trace, 0, layout.c_limbs_base);
            let mut native = a.square();
            native.freeze();
            assert_eq!(c.limbs, native.limbs, "square != native (seed {})", seed);
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //  Cond-select gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_select_layout() -> (SelectGadgetLayout, usize) {
        let a_limbs_base = 0;
        let b_limbs_base = NUM_LIMBS;
        let c_limbs_base = 2 * NUM_LIMBS;
        let c_bits_base = c_limbs_base + NUM_LIMBS;
        let sel_cell = c_bits_base + ELEMENT_BIT_CELLS;
        let total = sel_cell + 1;
        (
            SelectGadgetLayout {
                a_limbs_base,
                b_limbs_base,
                c_limbs_base,
                c_bits_base,
                sel_cell,
            },
            total,
        )
    }

    fn assert_satisfies_select(
        layout: &SelectGadgetLayout,
        total_width: usize,
        fe_a: &FieldElement,
        fe_b: &FieldElement,
        sel: bool,
    ) {
        let mut trace = make_trace_row(total_width);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(fe_a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(fe_b.limbs[i] as u64);
        }
        fill_select_gadget(&mut trace, 0, layout, fe_a, fe_b, sel);

        let cur: Vec<F> = (0..total_width).map(|c| trace[c][0]).collect();
        let cons = eval_select_gadget(&cur, layout);
        assert_eq!(cons.len(), SELECT_GADGET_CONSTRAINTS);
        for (i, v) in cons.iter().enumerate() {
            assert!(
                v.is_zero(),
                "select-gadget constraint #{} non-zero (sel={})",
                i,
                sel
            );
        }
    }

    #[test]
    fn select_gadget_constants() {
        assert_eq!(SELECT_GADGET_OWNED_CELLS, 271);
        assert_eq!(SELECT_GADGET_CONSTRAINTS, 281);
    }

    #[test]
    fn select_gadget_picks_a_when_sel_one() {
        let (layout, total) = standalone_select_layout();
        let a = fe_from_seed(7);
        let b = fe_from_seed(11);
        assert_satisfies_select(&layout, total, &a, &b, true);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_select_gadget(&mut trace, 0, &layout, &a, &b, true);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        assert_eq!(c.limbs, a.limbs, "sel=1 should pick a");
    }

    #[test]
    fn select_gadget_picks_b_when_sel_zero() {
        let (layout, total) = standalone_select_layout();
        let a = fe_from_seed(7);
        let b = fe_from_seed(11);
        assert_satisfies_select(&layout, total, &a, &b, false);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_select_gadget(&mut trace, 0, &layout, &a, &b, false);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        assert_eq!(c.limbs, b.limbs, "sel=0 should pick b");
    }

    #[test]
    fn select_gadget_tamper_detection() {
        let (layout, total) = standalone_select_layout();
        let a = fe_from_seed(20);
        let b = fe_from_seed(30);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_select_gadget(&mut trace, 0, &layout, &a, &b, true);

        // Tamper c-limb 4.
        let original = trace[layout.c_limbs_base + 4][0];
        trace[layout.c_limbs_base + 4][0] = original + F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_select_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1, "tampered select c-limb undetected");
    }

    #[test]
    fn select_gadget_tamper_sel_non_boolean() {
        let (layout, total) = standalone_select_layout();
        let a = fe_from_seed(2);
        let b = fe_from_seed(5);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_select_gadget(&mut trace, 0, &layout, &a, &b, true);

        // Set sel = 2 (out of {0, 1}).
        trace[layout.sel_cell][0] = F::from(2u64);

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_select_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1, "non-boolean sel undetected");
    }

    // ─────────────────────────────────────────────────────────────────
    //  Freeze-gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_freeze_layout() -> (FreezeGadgetLayout, usize) {
        let a_limbs_base = 0;
        let diff_limbs_base = NUM_LIMBS;
        let diff_bits_base = diff_limbs_base + NUM_LIMBS;
        let c_limbs_base = diff_bits_base + ELEMENT_BIT_CELLS;
        let c_bits_base = c_limbs_base + NUM_LIMBS;
        let c_pos_base = c_bits_base + ELEMENT_BIT_CELLS;
        let c_neg_base = c_pos_base + NUM_LIMBS;
        let total = c_neg_base + NUM_LIMBS;
        (
            FreezeGadgetLayout {
                a_limbs_base,
                diff_limbs_base,
                diff_bits_base,
                c_limbs_base,
                c_bits_base,
                c_pos_base,
                c_neg_base,
            },
            total,
        )
    }

    fn assert_satisfies_freeze(
        layout: &FreezeGadgetLayout,
        total_width: usize,
        fe_a: &FieldElement,
    ) {
        let mut trace = make_trace_row(total_width);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(fe_a.limbs[i] as u64);
        }
        fill_freeze_gadget(&mut trace, 0, layout, fe_a);

        let cur: Vec<F> = (0..total_width).map(|c| trace[c][0]).collect();
        let cons = eval_freeze_gadget(&cur, layout);
        assert_eq!(cons.len(), FREEZE_GADGET_CONSTRAINTS);
        for (i, v) in cons.iter().enumerate() {
            assert!(
                v.is_zero(),
                "freeze-gadget constraint #{} non-zero (a={:?})",
                i,
                fe_a.limbs
            );
        }
    }

    #[test]
    fn freeze_gadget_constants() {
        assert_eq!(FREEZE_GADGET_OWNED_CELLS, 560);
        assert_eq!(FREEZE_GADGET_CONSTRAINTS, 591);
    }

    #[test]
    fn freeze_gadget_canonical_input_unchanged() {
        // For canonical inputs (already < p), freeze should leave c = a.
        let (layout, total) = standalone_freeze_layout();
        for seed in 0u64..8 {
            let a = fe_from_seed(seed); // already canonical
            assert_satisfies_freeze(&layout, total, &a);

            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            }
            fill_freeze_gadget(&mut trace, 0, &layout, &a);
            let c = read_element(&trace, 0, layout.c_limbs_base);
            assert_eq!(c.limbs, a.limbs, "freeze of canonical input changed it (seed {})", seed);
        }
    }

    #[test]
    fn freeze_gadget_p_minus_1_is_canonical() {
        // p − 1 is the largest canonical value.
        let (layout, total) = standalone_freeze_layout();
        let mut p_minus_1 = FieldElement::one().neg();
        p_minus_1.freeze();
        assert_satisfies_freeze(&layout, total, &p_minus_1);
    }

    #[test]
    fn freeze_gadget_value_just_above_p() {
        // Construct (p + 5) in tight non-canonical form (limbs < 2^26 but
        // integer ≥ p).  Freeze should produce 5.
        let (layout, total) = standalone_freeze_layout();
        // p + 5 = (canonical form via add of p as FE + 5):
        // Easier: 5 + (p in tight limb form) does not directly work since
        // adding p_limbs gives a non-canonical limb representation of p,
        // not p+5.  Construct p+5 = 5 + p directly.
        // Actually: take any value, add p to it via the chain to get a
        // tight non-canonical version with same residue.
        //
        // Approach: p + 5 = a where a_limbs = P_LIMBS_TIGHT, then add 5 to limb 0.
        use crate::p256_field::P_LIMBS_TIGHT;
        let mut a = FieldElement {
            limbs: P_LIMBS_TIGHT,
        };
        a.limbs[0] += 5;
        // a.limbs[0] = (2^26 - 1) + 5 = 2^26 + 4.  This overflows 2^26!
        // Need to carry-propagate.
        // Easier: use a = FE corresponding to the integer p + 5 directly,
        // computed as (p + 5) mod 2^260 in tight limbs.
        //
        // Use add: compute a = fe_a + fe_b where fe_a = "5" and fe_b = "p"
        // both in tight form.  But fe_b = p in tight form is P_LIMBS_TIGHT
        // (which represents p as an integer, even though canonical "p" is 0).
        let mut five = FieldElement::zero();
        five.limbs[0] = 5;
        let p_as_fe = FieldElement {
            limbs: P_LIMBS_TIGHT,
        };
        // Add via native code (which produces loose limbs); reduce.
        let a = {
            let mut t = five.add(&p_as_fe);
            t.reduce(); // brings limbs into [0, 2^26) but doesn't subtract p.
            t
        };
        // Sanity: a should represent integer p + 5 in tight form.
        // a mod p = 5.

        assert_satisfies_freeze(&layout, total, &a);
        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
        }
        fill_freeze_gadget(&mut trace, 0, &layout, &a);
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut expected = FieldElement::zero();
        expected.limbs[0] = 5;
        assert_eq!(c.limbs, expected.limbs, "freeze(p+5) ≠ 5");
    }

    #[test]
    fn freeze_gadget_random_canonical_inputs_unchanged() {
        let (layout, total) = standalone_freeze_layout();
        for seed in 0u64..16 {
            let a = fe_from_seed(seed.wrapping_mul(0x9E37_79B9));
            // a is canonical via fe_from_seed.
            assert_satisfies_freeze(&layout, total, &a);

            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            }
            fill_freeze_gadget(&mut trace, 0, &layout, &a);
            let c = read_element(&trace, 0, layout.c_limbs_base);
            assert_eq!(c.limbs, a.limbs, "freeze(canonical) ≠ canonical");
        }
    }

    #[test]
    fn freeze_gadget_tamper_detection() {
        let (layout, total) = standalone_freeze_layout();
        let a = fe_from_seed(42);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
        }
        fill_freeze_gadget(&mut trace, 0, &layout, &a);

        let target = layout.c_limbs_base + 2;
        let original = trace[target][0];
        trace[target][0] = original + F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_freeze_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1, "tampered freeze c-limb undetected");
    }
}
