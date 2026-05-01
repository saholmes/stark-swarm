// ed25519_field_air.rs — AIR-level layout for F_{2^255 - 19} arithmetic.
//
// This file is the in-circuit counterpart to `ed25519_field.rs` (the
// native reference).  It establishes the trace-cell layout for a single
// canonical-form field element, plus the range-check constraints that
// pin those cells to honest values.  Per-operation gadgets (add, sub,
// mul, square, freeze, conditional-select) build on top of this layout
// in subsequent commits.
//
// ─────────────────────────────────────────────────────────────────
// PHASE 2 SUB-PLAN
// ─────────────────────────────────────────────────────────────────
//
//   v0    native FieldElement reference                      ✓ done
//   v1a   field-element trace layout + range check           ✓ this commit
//   v1b   add gadget          (loose · loose → loose)        next
//   v1c   sub gadget          (a − b mod p)                  next
//   v1d   mul gadget          (10×10 schoolbook + 19-fold)   next
//   v1e   square gadget       (specialised mul)              after
//   v1f   freeze gadget       (loose → canonical)            after
//   v1g   conditional-select  (used in scalar-mult ladder)   after
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
// One canonical-form FieldElement occupies a contiguous slab of
// `ELEMENT_CELLS = 265` trace cells, organised as:
//
// ```text
//   block X — Limbs       :  10 cells, each holding a 25/26-bit limb
//   block Y — Limb bits   : 255 cells, the LSB-first bit decomposition
//                            of all 10 limbs concatenated (limb 0's 26
//                            bits, then limb 1's 25 bits, …)
// ```
//
// The bit cells serve as the range-check evidence: each bit cell is
// constrained to be {0, 1}, and each limb is constrained to be the
// 2^i-weighted sum of its bits.  Together these enforce
// `0 ≤ limb_i < 2^{LIMB_WIDTHS[i]}` — equivalently, the integer
// represented by the limbs is in `[0, 2^255)`.
//
// Note: `[0, 2^255)` is one bit looser than canonical `[0, p)`.  The
// difference (values in `[p, 2^255) = [2^255 − 19, 2^255)`, only 19
// values) is handled by the freeze gadget; for intermediate
// representations the looser bound is sufficient and cheaper.
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET PER ELEMENT
// ─────────────────────────────────────────────────────────────────
//
//   Bit booleanity:        255 deg-2 constraints (b · (1 − b) = 0)
//   Limb pack identity:     10 deg-1 constraints (limb_i = Σ 2^j · bit_{ij})
//   ─────────────────────────────────────────────────────────────
//   TOTAL                  265 constraints per range-checked element.
//
// All constraints are degree ≤ 2, matching the framework's max-degree
// budget.  No row-dependent gating — the constraints fire on every
// row that hosts an element block.
//
// ─────────────────────────────────────────────────────────────────
// CELL ORDERING WITHIN AN ELEMENT BLOCK
// ─────────────────────────────────────────────────────────────────
//
// ```text
//   offset 0..9       limb cells (in order: limb 0, limb 1, …, limb 9)
//   offset 10..35     limb 0 bits (26 bits, LSB first)
//   offset 36..60     limb 1 bits (25 bits)
//   offset 61..86     limb 2 bits (26 bits)
//   offset 87..111    limb 3 bits (25 bits)
//   offset 112..137   limb 4 bits (26 bits)
//   offset 138..162   limb 5 bits (25 bits)
//   offset 163..188   limb 6 bits (26 bits)
//   offset 189..213   limb 7 bits (25 bits)
//   offset 214..239   limb 8 bits (26 bits)
//   offset 240..264   limb 9 bits (25 bits)
// ```
//
// Per-bit offsets follow the cumulative-sum convention so that a
// bit-cell's offset is computable as
//   bit_offset(limb_idx, bit_idx) = ELEMENT_BITS_BASE
//                                 + Σ_{i<limb_idx} LIMB_WIDTHS[i]
//                                 + bit_idx

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{Field, Zero, One};
use ark_goldilocks::Goldilocks as F;

use crate::ed25519_field::{FieldElement, NUM_LIMBS, LIMB_WIDTHS};

// ═══════════════════════════════════════════════════════════════════
//  Cell-layout constants for one field element
// ═══════════════════════════════════════════════════════════════════

/// Number of limb cells per element (one per radix-2^{25.5} limb).
pub const ELEMENT_LIMB_CELLS: usize = NUM_LIMBS;

/// Total number of bit-decomposition cells per element (= 255).
pub const ELEMENT_BIT_CELLS: usize = 255;

/// Total cells consumed by one element's range-checked representation.
pub const ELEMENT_CELLS: usize = ELEMENT_LIMB_CELLS + ELEMENT_BIT_CELLS;

/// Offset of the first bit-decomp cell within an element block.
pub const ELEMENT_BITS_BASE: usize = ELEMENT_LIMB_CELLS;

// Compile-time sanity.
const _: () = assert!(ELEMENT_LIMB_CELLS == 10, "10 limbs per element");
const _: () = assert!(ELEMENT_BIT_CELLS  == 255, "255 bits per element");
const _: () = assert!(ELEMENT_CELLS      == 265, "265 cells per element block");

/// Number of transition constraints emitted for a single range-checked
/// element block.
pub const ELEMENT_CONSTRAINTS: usize = ELEMENT_BIT_CELLS + ELEMENT_LIMB_CELLS;

/// For limb index `limb_idx ∈ [0, 10)`, return the cumulative bit
/// offset of its first bit cell (relative to `ELEMENT_BITS_BASE`).
#[inline]
pub fn limb_bits_offset(limb_idx: usize) -> usize {
    debug_assert!(limb_idx < NUM_LIMBS);
    let mut acc = 0;
    for i in 0..limb_idx { acc += LIMB_WIDTHS[i] as usize; }
    acc
}

/// Cell offset (within an element block) of the `bit_idx`-th bit of
/// limb `limb_idx`.
#[inline]
pub fn bit_cell(limb_idx: usize, bit_idx: usize) -> usize {
    debug_assert!(limb_idx < NUM_LIMBS);
    debug_assert!(bit_idx < LIMB_WIDTHS[limb_idx] as usize);
    ELEMENT_BITS_BASE + limb_bits_offset(limb_idx) + bit_idx
}

// ═══════════════════════════════════════════════════════════════════
//  Trace-builder helpers
// ═══════════════════════════════════════════════════════════════════

/// Write a canonical-form `FieldElement` into `ELEMENT_CELLS` cells of
/// the given row, starting at column `base`.  Each limb cell holds
/// the limb value as a `Goldilocks` element; each bit cell holds 0 or
/// 1.  Pre-condition: `fe.limbs[i]` is in `[0, 2^{LIMB_WIDTHS[i]})` —
/// i.e., the input is in tight (or canonical) form, NOT loose.
pub fn place_element(trace: &mut [Vec<F>], row: usize, base: usize, fe: &FieldElement) {
    debug_assert!(base + ELEMENT_CELLS <= trace.len(),
        "element block at base={} exceeds trace width", base);

    for i in 0..NUM_LIMBS {
        let limb = fe.limbs[i];
        debug_assert!(
            limb >= 0 && (limb as u64) < (1u64 << LIMB_WIDTHS[i]),
            "limb {} out of tight range: got {}", i, limb
        );
        trace[base + i][row] = F::from(limb as u64);

        // Bit decomposition (LSB first).
        for b in 0..LIMB_WIDTHS[i] as usize {
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
    use ark_ff::{BigInteger, PrimeField};
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
///   - 255 booleanity constraints (one per bit cell), in the order
///     limb 0 bits 0..25, limb 1 bits 0..24, …
///   - 10 limb-pack constraints, one per limb, in limb order.
pub fn eval_element_range_check(cur: &[F], base: usize) -> Vec<F> {
    let mut out = Vec::with_capacity(ELEMENT_CONSTRAINTS);

    // ── Booleanity: 255 constraints ──────────────────────────────
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_WIDTHS[i] as usize {
            let cell = cur[bit_cell(i, b)];
            out.push(cell * (F::one() - cell));
        }
    }

    // ── Limb pack: 10 constraints ────────────────────────────────
    //   limb_i = Σ_{b=0..w_i} 2^b · bit_{i,b}
    for i in 0..NUM_LIMBS {
        let mut s = F::zero();
        for b in 0..LIMB_WIDTHS[i] as usize {
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
// Computes c = (a + b) mod p, where a and b are canonical-form
// inputs (each limb in [0, 2^{w_k})).  Output c is range-checked to
// be in [0, 2^255) — a "tight" form that is *almost* canonical: it
// admits 19 extra values in [p, 2^255) that cannot be reached by
// honest a + b mod p, so soundness holds.  (Strict canonical-form
// enforcement is the freeze gadget's job — see v1f.)
//
// ─────────────────────────────────────────────────────────────────
// THE CARRY CHAIN
// ─────────────────────────────────────────────────────────────────
//
// For each limb k ∈ [0, 10):
//
//     a[k] + b[k] + carry_in[k]  =  c[k] + carry[k] · 2^{w_k}
//
// where carry_in[0] = 19 · carry[9]  (the wrap from 2^255 ≡ 19 mod p)
//       carry_in[k] = carry[k - 1]   for k > 0.
//
// All carries are 1-bit booleans: with a, b canonical (each limb < 2^{w_k}),
// a[k] + b[k] < 2^{w_k+1}, plus a 1-bit carry-in plus 19 (only at k=0)
// stays well below 2^{w_k+1} + 19 < 2^{w_k} · 2.  So carry_out at each
// limb is 0 or 1.
//
// Summing all 10 limb constraints weighted by 2^{LIMB_OFFSETS[k]} gives
// the integer relation
//
//     a + b - c - carry[9] · p = 0
//
// (because the "carry[9] · 2^{w_9}" term at limb 9 contributes
// 2^{255} · carry[9] on the RHS, while "19 · carry[9]" at limb 0
// contributes 19 · carry[9] on the LHS, and 2^{255} - 19 = p).
//
// So c = a + b - carry[9] · p.  With c range-checked to [0, 2^255)
// and carry[9] ∈ {0, 1}:
//
//     a + b < p   ⇒  c = a + b,           carry[9] = 0
//     a + b ≥ p   ⇒  c = a + b - p ∈ [0, p),  carry[9] = 1
//
// In both cases c ≡ (a + b) (mod p).  No 2-bit carries needed.
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
// Inputs are addressed by reference (caller chooses where a and b live);
// the gadget owns its output and helper cells (c-limbs, c-bits, carries).
//
// Owned cells (relative to `c_limbs_base`):
//
// ```text
//   c_limbs_base + 0..10  : c output limbs
//   c_bits_base  + 0..255 : c bit decomposition (range check)
//   carries_base + 0..10  : 10 carry cells
// ```
//
// Total owned: 10 + 255 + 10 = 275 cells.
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on c (bit booleanity + limb pack):     265 deg-≤2
//   Limb-sum identities (per-limb carry chain):         10 deg-1
//   Carry booleanity:                                   10 deg-2
//   ──────────────────────────────────────────────────────────────
//   TOTAL                                              285 constraints
//
// All deg ≤ 2.  No phase gating — the gadget fires once per row that
// hosts an add operation.

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
/// caller).
///
/// The gadget owns `c_limbs_base..c_limbs_base + 10`,
/// `c_bits_base..c_bits_base + 255`, and `carries_base..carries_base + 10`.
#[derive(Clone, Copy, Debug)]
pub struct AddGadgetLayout {
    pub a_limbs_base: usize,
    pub b_limbs_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base:  usize,
    pub carries_base: usize,
}

/// Fill the gadget-owned cells (c-limbs, c-bits, carries) for the
/// computation `c = (a + b) mod p`, given the input `FieldElement`s
/// (which the caller is also expected to have placed at
/// `layout.a_limbs_base` / `layout.b_limbs_base` via `place_element`).
pub fn fill_add_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &AddGadgetLayout,
    fe_a: &FieldElement,
    fe_b: &FieldElement,
) {
    debug_assert!(layout.c_bits_base != layout.c_limbs_base, "layout overlap");

    // Compute c = (a + b) mod p in canonical form, plus the carries.
    // We replicate the carry chain explicitly so the trace cells match
    // exactly what the constraints expect.
    let mut c_limbs = [0i64; NUM_LIMBS];
    let mut carries = [0i64; NUM_LIMBS];

    // First pass: compute carry[9] (the wrap bit) by simulating the
    // chain WITHOUT the wrap, then resolving it.
    //
    // The integer relation a + b = c + carry[9] · p tells us:
    //   carry[9] = 1  iff  a + b ≥ p
    //   carry[9] = 0  otherwise
    //
    // Cheapest way: compute (a + b) mod p via the native ref, freeze
    // it, then derive each carry by replaying the chain.
    let sum_mod_p = {
        let mut s = fe_a.add(fe_b);
        s.freeze();
        s
    };
    for i in 0..NUM_LIMBS { c_limbs[i] = sum_mod_p.limbs[i]; }

    // Determine carry[9] from a + b vs p.  Equivalently: 2^{255} · carry[9]
    // = a + b - c, so carry[9] = (a + b - c)_at_bit_255.
    // Easiest: run the chain forward starting from carry_in[0] = 19·carry[9]
    // for each candidate, pick the one where carry[9] matches.
    //
    // Try carry[9] = 0 first.  If chain produces carry[9] = 0, accept;
    // otherwise carry[9] = 1.
    for &candidate in &[0i64, 1i64] {
        let mut prev = 19 * candidate;
        let mut chain_ok = true;
        for k in 0..NUM_LIMBS {
            let w = LIMB_WIDTHS[k];
            let sum = fe_a.limbs[k] + fe_b.limbs[k] + prev;
            let c_k = c_limbs[k];
            let diff = sum - c_k;
            // diff should equal carry[k] · 2^{w}  with carry[k] ∈ {0, 1}.
            let radix = 1i64 << w;
            if diff == 0 {
                carries[k] = 0;
                prev = 0;
            } else if diff == radix {
                carries[k] = 1;
                prev = 1;
            } else {
                chain_ok = false;
                break;
            }
        }
        if chain_ok && carries[NUM_LIMBS - 1] == candidate {
            // Found the consistent carry chain.
            break;
        }
        // Reset and try next candidate.
        carries = [0i64; NUM_LIMBS];
    }

    // Sanity: chain consistency.
    debug_assert!(
        carries.iter().all(|&c| c == 0 || c == 1),
        "carry chain produced non-boolean values: {:?}", carries
    );

    // Write c-limbs, c-bits, carries into the trace.
    for i in 0..NUM_LIMBS {
        let limb = c_limbs[i];
        trace[layout.c_limbs_base + i][row] = F::from(limb as u64);
        // Bit decomposition.
        let mut bit_offset_within = 0usize;
        for kk in 0..i { bit_offset_within += LIMB_WIDTHS[kk] as usize; }
        for b in 0..LIMB_WIDTHS[i] as usize {
            let bit = (limb >> b) & 1;
            trace[layout.c_bits_base + bit_offset_within + b][row]
                = F::from(bit as u64);
        }
    }
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
///   1.   255 + 10 = 265:  c range-check (booleanity + limb-pack)
///   2.   10:              limb-sum identities (carry chain)
///   3.   10:              carry booleanity
pub fn eval_add_gadget(cur: &[F], layout: &AddGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(ADD_GADGET_CONSTRAINTS);

    // (1) Range check on c.  We re-use the helper but it expects the
    // c-limbs and c-bits to be at consecutive offsets (limb_block then
    // bit_block).  The add-gadget layout HAS them at non-adjacent
    // offsets (`c_limbs_base` and `c_bits_base`), so we inline the
    // check rather than calling eval_element_range_check.
    //
    // 255 booleanity:
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_WIDTHS[i] as usize {
            let cell = cur[layout.c_bits_base + bit_off_within + b];
            out.push(cell * (F::one() - cell));
        }
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }
    // 10 limb-pack identities:
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        let mut s = F::zero();
        for b in 0..LIMB_WIDTHS[i] as usize {
            s += F::from(1u64 << b)
                * cur[layout.c_bits_base + bit_off_within + b];
        }
        out.push(cur[layout.c_limbs_base + i] - s);
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }

    // (2) 10 limb-sum identities for the carry chain.
    //
    //   a[k] + b[k] + carry_in[k] - c[k] - carry[k] · 2^{w_k} = 0
    //   carry_in[0] = 19 · carry[9],  carry_in[k] = carry[k-1].
    for k in 0..NUM_LIMBS {
        let w = LIMB_WIDTHS[k];
        let radix = F::from(1u64 << w);
        let a_k = cur[layout.a_limbs_base + k];
        let b_k = cur[layout.b_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];
        let carry_k = cur[layout.carries_base + k];
        let carry_in = if k == 0 {
            F::from(19u64) * cur[layout.carries_base + NUM_LIMBS - 1]
        } else {
            cur[layout.carries_base + k - 1]
        };
        out.push(a_k + b_k + carry_in - c_k - radix * carry_k);
    }

    // (3) 10 carry booleanity.
    for k in 0..NUM_LIMBS {
        let cy = cur[layout.carries_base + k];
        out.push(cy * (F::one() - cy));
    }

    debug_assert_eq!(out.len(), ADD_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  SUB GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Computes c = (a - b) mod p, where a and b are canonical-form
// inputs.  Single row, gadget-owned output cells with range check,
// plus signed carry cells (positive and negative indicators per limb)
// to handle both directions of overflow.
//
// ─────────────────────────────────────────────────────────────────
// SIGNED CARRY CHAIN
// ─────────────────────────────────────────────────────────────────
//
// Per-limb constraint:
//
//     a[k] - b[k] - net_in[k] - c[k] + net_out[k] · 2^{w_k} = 0
//
// where net_out[k] ∈ {-1, 0, 1} is encoded as
//
//     net_out[k] = C_pos[k] - C_neg[k]
//
// with C_pos[k], C_neg[k] ∈ {0, 1} and C_pos[k] · C_neg[k] = 0
// (mutual exclusion — at most one of {pos, neg} can be 1).
//
// Carry-in from the previous limb:
//     net_in[0] = 19 · net_out[9]    (the wrap, since 2^255 ≡ 19 mod p)
//     net_in[k] = net_out[k - 1]      for k > 0
//
// Summing weighted by 2^{LIMB_OFFSETS[k]} gives the integer relation
//
//     a - b - c - net_out[9] · p = 0
//
// because the carry-chain telescopes (OFF[k+1] = OFF[k] + w[k]) and
// the wrap term 19 · net_out[9] at limb 0 vs 2^255 · net_out[9] at
// limb 9 differ by exactly p.  So
//
//     c = a - b - net_out[9] · p
//
// With c range-checked to [0, 2^255) and net_out[9] ∈ {-1, 0, 1}:
//   a ≥ b: net_out[9] = 0  →  c = a - b ∈ [0, p) ✓
//   a < b:  net_out[9] = -1 →  c = a - b + p ∈ [0, p) ✓
//   net_out[9] = +1 forces c = a - b - p < 0, which fails the range
//   check — so the prover is constrained to honest carry choices.
//
// Why NOT a single-bit carry: in the add gadget, sums are inherently
// non-negative (a, b ≥ 0), so carry_out ∈ {0, 1}.  In sub, the
// chain a[k] - b[k] - net_in[k] can go in either direction at each
// limb, so net_out ∈ {-1, 0, 1} is needed.  An earlier (broken) v0
// of this gadget assumed carry ∈ {0, 1} only; that fails when
// (a + s·p)[k] overflows 2^{w_k} (e.g., when both a[k] and the implicit
// p_limbs[k] term are large).
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
//   c_limbs_base + 0..10  :  c output limbs                    (10)
//   c_bits_base  + 0..255 :  c bit decomposition               (255)
//   c_pos_base   + 0..10  :  positive carry indicators         (10)
//   c_neg_base   + 0..10  :  negative carry indicators         (10)
//   ──────────────────────────────────────────────────────────────
//   TOTAL OWNED                                                285 cells
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on c (booleanity + limb-pack):       265 deg-≤2
//   Limb-difference identities:                       10 deg-1
//   Carry booleanity (10 × 2):                        20 deg-2
//   Mutual exclusion C_pos · C_neg = 0:               10 deg-2
//   ──────────────────────────────────────────────────────────────
//   TOTAL                                            305 constraints

/// Cells owned by a sub gadget.  10 + 255 + 10 + 10 = 285.
pub const SUB_GADGET_OWNED_CELLS: usize = ELEMENT_CELLS + 2 * NUM_LIMBS;

/// Constraints emitted per sub gadget instance.
pub const SUB_GADGET_CONSTRAINTS: usize =
    ELEMENT_CONSTRAINTS + NUM_LIMBS + 2 * NUM_LIMBS + NUM_LIMBS;

#[derive(Clone, Copy, Debug)]
pub struct SubGadgetLayout {
    pub a_limbs_base: usize,
    pub b_limbs_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base:  usize,
    /// Base of 10 positive-carry cells (C_pos[0..9]).
    pub c_pos_base:   usize,
    /// Base of 10 negative-carry cells (C_neg[0..9]).
    pub c_neg_base:   usize,
}

/// Fill the gadget-owned cells for c = (a - b) mod p.
pub fn fill_sub_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &SubGadgetLayout,
    fe_a: &FieldElement,
    fe_b: &FieldElement,
) {
    // Compute canonical c via the native ref.
    let mut c = fe_a.sub(fe_b);
    c.freeze();
    let c_limbs = c.limbs;

    // Replay the chain to derive the signed carries.
    //
    //   v[k] = a[k] - b[k] - net_in[k]
    //   c[k] = v[k] - net_out[k] · 2^{w_k}
    //
    // We choose net_out[9] ∈ {-1, 0, 1} so the wrap closes; per-limb
    // carries fall out from the chain.
    let mut net_out = [0i64; NUM_LIMBS];

    // Try each candidate for net_out[9] ∈ {-1, 0, 1}.
    //
    // Per-limb constraint: a[k] - b[k] - net_in[k] - c[k] + net_out[k] · radix = 0
    //   ⇒ net_out[k] · radix = c[k] - (a[k] - b[k] - net_in[k]) = -(v - c[k]) = -diff.
    // So diff =  radix → net_out[k] = -1
    //    diff = -radix → net_out[k] = +1
    //    diff =  0     → net_out[k] =  0
    for &top in &[0i64, 1i64, -1i64] {
        let mut chain_ok = true;
        let mut prev: i64 = 19 * top;   // net_in[0]
        for k in 0..NUM_LIMBS {
            let w = LIMB_WIDTHS[k];
            let radix = 1i64 << w;
            let v = fe_a.limbs[k] - fe_b.limbs[k] - prev;
            let c_k = c_limbs[k];
            let diff = v - c_k;
            if diff == 0 {
                net_out[k] = 0;
                prev = 0;
            } else if diff == -radix {
                net_out[k] = 1;
                prev = 1;
            } else if diff == radix {
                net_out[k] = -1;
                prev = -1;
            } else {
                chain_ok = false;
                break;
            }
        }
        if chain_ok && net_out[NUM_LIMBS - 1] == top {
            break;
        }
        net_out = [0i64; NUM_LIMBS];
    }

    debug_assert!(
        net_out.iter().all(|&v| v == -1 || v == 0 || v == 1),
        "signed carries out of range: {:?}", net_out
    );

    // Write c-limbs and c-bits.
    for i in 0..NUM_LIMBS {
        let limb = c_limbs[i];
        trace[layout.c_limbs_base + i][row] = F::from(limb as u64);
        let mut bit_off_within = 0usize;
        for kk in 0..i { bit_off_within += LIMB_WIDTHS[kk] as usize; }
        for b in 0..LIMB_WIDTHS[i] as usize {
            let bit = (limb >> b) & 1;
            trace[layout.c_bits_base + bit_off_within + b][row]
                = F::from(bit as u64);
        }
    }

    // Encode net_out[k] = C_pos[k] - C_neg[k] with mutual exclusion.
    for k in 0..NUM_LIMBS {
        let (c_pos, c_neg) = match net_out[k] {
            1  => (1u64, 0u64),
            -1 => (0u64, 1u64),
            _  => (0u64, 0u64),
        };
        trace[layout.c_pos_base + k][row] = F::from(c_pos);
        trace[layout.c_neg_base + k][row] = F::from(c_neg);
    }
}

/// Emit the `SUB_GADGET_CONSTRAINTS` transition constraints.
pub fn eval_sub_gadget(cur: &[F], layout: &SubGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(SUB_GADGET_CONSTRAINTS);

    // (1) Range check on c (255 booleanity + 10 limb-pack = 265).
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_WIDTHS[i] as usize {
            let cell = cur[layout.c_bits_base + bit_off_within + b];
            out.push(cell * (F::one() - cell));
        }
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        let mut sum_bits = F::zero();
        for b in 0..LIMB_WIDTHS[i] as usize {
            sum_bits += F::from(1u64 << b)
                * cur[layout.c_bits_base + bit_off_within + b];
        }
        out.push(cur[layout.c_limbs_base + i] - sum_bits);
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }

    // (2) 10 limb-difference identities with signed carries.
    //   a[k] - b[k] - net_in[k] - c[k] + net_out[k] · 2^{w_k} = 0
    //   net_in[0] = 19 · net_out[9],  net_in[k] = net_out[k-1] for k>0.
    let net_out = |k: usize| -> F {
        cur[layout.c_pos_base + k] - cur[layout.c_neg_base + k]
    };
    for k in 0..NUM_LIMBS {
        let w = LIMB_WIDTHS[k];
        let radix = F::from(1u64 << w);
        let a_k = cur[layout.a_limbs_base + k];
        let b_k = cur[layout.b_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];

        let net_in = if k == 0 {
            F::from(19u64) * net_out(NUM_LIMBS - 1)
        } else {
            net_out(k - 1)
        };
        out.push(a_k - b_k - net_in - c_k + radix * net_out(k));
    }

    // (3) 20 carry booleanity (10 × C_pos, 10 × C_neg).
    for k in 0..NUM_LIMBS {
        let cp = cur[layout.c_pos_base + k];
        out.push(cp * (F::one() - cp));
    }
    for k in 0..NUM_LIMBS {
        let cn = cur[layout.c_neg_base + k];
        out.push(cn * (F::one() - cn));
    }

    // (4) 10 mutual-exclusion: C_pos[k] · C_neg[k] = 0.
    for k in 0..NUM_LIMBS {
        let cp = cur[layout.c_pos_base + k];
        let cn = cur[layout.c_neg_base + k];
        out.push(cp * cn);
    }

    debug_assert_eq!(out.len(), SUB_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  MUL GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Computes c = (a · b) mod p, where a and b are canonical-form
// inputs.  Single row.  This is the workhorse of Ed25519 verification
// — every field multiplication during scalar multiplication runs one
// of these gadgets.
//
// ─────────────────────────────────────────────────────────────────
// SCHOOLBOOK + 19-FOLD
// ─────────────────────────────────────────────────────────────────
//
// In radix-2^{25.5}, a × b decomposes into 10 × 10 = 100 partial
// products.  Each partial product a[i] · b[j] lives at "natural"
// position OFF[i] + OFF[j] in the integer.  After mod-p reduction
// (using 2^255 ≡ 19), every partial product folds onto exactly one
// of the 10 output limbs c[0..9] with a known multiplicative factor:
//
// ```text
//   if i + j < 10:    target = i + j,    factor = 1   if not (i odd AND j odd)
//                                       = 2   if both odd  (radix stagger)
//   if i + j ≥ 10:    target = i + j - 10, factor = 19   if not both odd
//                                         = 38  if both odd  (= 2 · 19)
// ```
//
// So the per-limb partial sum is
//
//     T[k] = Σ_{(i,j) targeting k} factor(i,j) · a[i] · b[j]
//
// At each limb T[k] can be very loose (≤ ~2^59), so we apply a single
// carry-chain pass to fold T[k] into the canonical c[k] ∈ [0, 2^{w_k})
// plus a per-limb carry that propagates to limb k + 1.  The carry
// from limb 9 wraps back to limb 0 with factor 19 (the same wrap as
// in the add gadget).
//
// ─────────────────────────────────────────────────────────────────
// CARRY MAGNITUDES
// ─────────────────────────────────────────────────────────────────
//
// Worst-case T[k] (for limb 0, which absorbs the most 38-factor terms):
//   ≤ 10 · 38 · (2^26)^2 ≈ 2^59
// Plus carry_in[0] = 19 · carry[9] ≤ 19 · 2^32 ≈ 2^36.5.
// Sum ≤ 2^59.  Carry[k] = (T[k] + carry_in[k]) / 2^{w_k} ≤ 2^59 / 2^25
//   ≈ 2^34.
//
// We use 36 carry bits per limb (16-bit headroom for safety against
// edge cases — e.g., the carry-in from limb 8 stacking with limb 9's
// wrap).  Carry cells are reconstructed inline from their bits via
// the limb-sum constraint, so no dedicated "packed carry" cell is
// needed — just 36 booleanised bit cells per limb.
//
// Soundness check:  the per-limb constraint magnitude
//   |T[k] + carry_in[k] - c[k] - carry[k] · 2^{w_k}|
// must be ≤ Goldilocks/2 ≈ 2^63 to avoid spurious modular
// satisfaction.  T[k] ≤ 2^59, carry_in ≤ 2^36, c[k] ≤ 2^26,
// carry · 2^25 ≤ 2^36 · 2^26 = 2^62.  Total ≤ 2^62.5 < 2^63.  ✓
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
//   c_limbs_base    + 0..10       :  c output limbs                   (10)
//   c_bits_base     + 0..255      :  c bit decomposition              (255)
//   carry_bits_base + 0..36 · 10  :  carry bits, limb-major (k, b)    (360)
//   ──────────────────────────────────────────────────────────────────────
//   TOTAL OWNED                                                       625 cells
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on c (booleanity + limb-pack):       265 deg-≤2
//   Limb-sum identities (10 · ~10 deg-2 products):    10 deg-2
//   Carry-bit booleanity (10 × 36):                  360 deg-2
//   ──────────────────────────────────────────────────────────────
//   TOTAL                                            635 constraints

/// Number of bits used for each carry cell's range check.  Carries
/// are stored BIASED (signed value + offset) so the bit cells stay
/// non-negative.  With MUL_CARRY_BITS = 36, the encoded value lives
/// in [0, 2^36) and the represented signed carry lies in [-2^35, 2^35).
pub const MUL_CARRY_BITS: usize = 36;

/// Bias added to each signed carry before bit-decomposition.
/// Equal to 2^{MUL_CARRY_BITS - 1}.
pub const MUL_CARRY_OFFSET: u64 = 1u64 << (MUL_CARRY_BITS - 1);

/// Cells owned by a mul gadget.  10 + 255 + 36·10 = 625.
pub const MUL_GADGET_OWNED_CELLS: usize =
    ELEMENT_CELLS + MUL_CARRY_BITS * NUM_LIMBS;

/// Constraints emitted per mul gadget instance.
pub const MUL_GADGET_CONSTRAINTS: usize =
    ELEMENT_CONSTRAINTS + NUM_LIMBS + MUL_CARRY_BITS * NUM_LIMBS;

#[derive(Clone, Copy, Debug)]
pub struct MulGadgetLayout {
    pub a_limbs_base:    usize,
    pub b_limbs_base:    usize,
    pub c_limbs_base:    usize,
    pub c_bits_base:     usize,
    /// Base of carry-bit cells.  Bit `b` of the carry at limb `k` lives at
    /// cell `carry_bits_base + k · MUL_CARRY_BITS + b`.
    pub carry_bits_base: usize,
}

/// For a target limb `k`, return the list of `(i, j, factor)` triples
/// such that limb `k` receives `factor · a[i] · b[j]` after schoolbook
/// + 19-fold folding.
fn mul_partial_products_for_limb(k: usize) -> Vec<(usize, usize, i64)> {
    let mut out = Vec::new();
    for i in 0..NUM_LIMBS {
        for j in 0..NUM_LIMBS {
            let s = i + j;
            let both_odd = (i & 1) == 1 && (j & 1) == 1;
            if s == k {
                let factor = if both_odd { 2 } else { 1 };
                out.push((i, j, factor));
            } else if s == k + NUM_LIMBS {
                let factor = if both_odd { 38 } else { 19 };
                out.push((i, j, factor));
            }
        }
    }
    out
}

/// Address of the carry-bit cell for limb `k`, bit `b`.
#[inline]
pub fn mul_carry_bit_cell(layout: &MulGadgetLayout, k: usize, b: usize) -> usize {
    debug_assert!(k < NUM_LIMBS);
    debug_assert!(b < MUL_CARRY_BITS);
    layout.carry_bits_base + k * MUL_CARRY_BITS + b
}

/// Fill the gadget-owned cells for c = (a · b) mod p.
pub fn fill_mul_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &MulGadgetLayout,
    fe_a: &FieldElement,
    fe_b: &FieldElement,
) {
    // Compute canonical c via the native ref.
    let mut c = fe_a.mul(fe_b);
    c.freeze();
    let c_limbs = c.limbs;

    // Compute T[k] for each output limb (folded schoolbook).
    let mut t_limbs = [0i128; NUM_LIMBS];   // i128 for headroom
    for k in 0..NUM_LIMBS {
        for (i, j, factor) in mul_partial_products_for_limb(k) {
            t_limbs[k] += (factor as i128)
                * (fe_a.limbs[i] as i128)
                * (fe_b.limbs[j] as i128);
        }
    }

    // Replay the carry chain.  Per limb:
    //   T[k] + carry_in[k] = c[k] + carry[k] · 2^{w_k}
    //   carry_in[0] = 19 · carry[9],  carry_in[k] = carry[k-1].
    //
    // The chain is cyclic via the wrap.  For honest a, b, c, the
    // chain has a unique solution.  Strategy:
    //   1. Compute T_total = sum T[k] · 2^{OFF[k]}  (in i128 — fits since
    //      sum T < 20 · 2^{255} and we work modulo 2^{128} per piece).
    //   Actually that approach overflows i128.  Use a different strategy:
    //   guess carry[9] ∈ [0, ~32], and check chain consistency.
    //
    // Bound on carry[9]: from the sum identity, carry[9] = (sum T - c) / p.
    // sum T ≤ 20 · 2^{255}, c < p ≈ 2^{255}, so carry[9] ≤ 20.  We try
    // each candidate ∈ [0, 32) and pick the one that closes the chain.
    // Limb 0 of the chain gives the congruence
    //   T[0] + 19 · carry[9] ≡ c[0]  (mod 2^{w_0})
    // which determines  carry[9] ≡ (c[0] − T[0]) · 19^{-1}  (mod 2^{26}).
    // The actual carry[9] is in some bounded range (|carry[9]| ≤ ~2^{35}
    // by per-limb-carry bound), so we narrow to a small set of
    // candidates differing by 2^{26}.
    const INV19_MOD_2POW26: i128 = 7064091;
    let radix0: i128 = 1i128 << 26;
    let target_mod = (c_limbs[0] as i128 - t_limbs[0])
        .rem_euclid(radix0);
    let base_carry9 = (target_mod * INV19_MOD_2POW26).rem_euclid(radix0);
    // Bring `base_carry9` into the symmetric range [-2^{25}, 2^{25}).
    let base_carry9 = if base_carry9 >= (1i128 << 25) {
        base_carry9 - radix0
    } else {
        base_carry9
    };

    let mut carries = [0i128; NUM_LIMBS];
    let mut found = false;
    // Per-limb carry bound is ~2^{35.5}, so |carry[9]| < 2^{36} is loose
    // enough.  carry[9] = base + k · 2^{26}, with k in a small range.
    'outer: for k_offset in -1024i128..1024i128 {
        let top_carry_guess = base_carry9 + k_offset * radix0;
        let mut prev: i128 = 19 * top_carry_guess;
        let mut tentative = [0i128; NUM_LIMBS];
        let mut chain_ok = true;
        for k in 0..NUM_LIMBS {
            let w = LIMB_WIDTHS[k];
            let radix = 1i128 << w;
            let total = t_limbs[k] + prev;
            let c_k = c_limbs[k] as i128;
            let diff = total - c_k;
            if diff.rem_euclid(radix) != 0 {
                chain_ok = false;
                break;
            }
            tentative[k] = diff.div_euclid(radix);
            prev = tentative[k];
        }
        if chain_ok && tentative[NUM_LIMBS - 1] == top_carry_guess {
            carries = tentative;
            found = true;
            break 'outer;
        }
    }
    debug_assert!(found,
        "mul-gadget carry chain failed to close for canonical inputs:\n\
         a.limbs = {:?}\n\
         b.limbs = {:?}\n\
         c.limbs = {:?}\n\
         t_limbs = {:?}\n\
         base_carry9 = {}",
        fe_a.limbs, fe_b.limbs, c_limbs, t_limbs, base_carry9);

    // Sanity bound — biased carry must fit in [0, 2^MUL_CARRY_BITS).
    let half_range: i128 = 1i128 << (MUL_CARRY_BITS - 1);
    for k in 0..NUM_LIMBS {
        debug_assert!(
            carries[k] >= -half_range && carries[k] < half_range,
            "carry[{}] = {} out of biased range ±2^{}",
            k, carries[k], MUL_CARRY_BITS - 1
        );
    }

    // Write c-limbs and c-bits.
    for i in 0..NUM_LIMBS {
        let limb = c_limbs[i];
        trace[layout.c_limbs_base + i][row] = F::from(limb as u64);
        let mut bit_off_within = 0usize;
        for kk in 0..i { bit_off_within += LIMB_WIDTHS[kk] as usize; }
        for b in 0..LIMB_WIDTHS[i] as usize {
            let bit = (limb >> b) & 1;
            trace[layout.c_bits_base + bit_off_within + b][row]
                = F::from(bit as u64);
        }
    }

    // Write carry bits (biased).  cy_biased = carry + 2^{35} ∈ [0, 2^36).
    for k in 0..NUM_LIMBS {
        let cy_biased = (carries[k] + half_range) as u64;
        for b in 0..MUL_CARRY_BITS {
            let bit = (cy_biased >> b) & 1;
            trace[mul_carry_bit_cell(layout, k, b)][row]
                = F::from(bit);
        }
    }
}

/// Emit the `MUL_GADGET_CONSTRAINTS` transition constraints.
pub fn eval_mul_gadget(cur: &[F], layout: &MulGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(MUL_GADGET_CONSTRAINTS);

    // (1) Range check on c.
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_WIDTHS[i] as usize {
            let cell = cur[layout.c_bits_base + bit_off_within + b];
            out.push(cell * (F::one() - cell));
        }
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        let mut sum_bits = F::zero();
        for b in 0..LIMB_WIDTHS[i] as usize {
            sum_bits += F::from(1u64 << b)
                * cur[layout.c_bits_base + bit_off_within + b];
        }
        out.push(cur[layout.c_limbs_base + i] - sum_bits);
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }

    // Helper: assemble the SIGNED carry[k] inline from its bit cells.
    // The 36-bit cell decodes to a biased value; subtract MUL_CARRY_OFFSET
    // to recover the signed carry.
    let pack_carry_signed = |k: usize| -> F {
        let mut s = F::zero();
        for b in 0..MUL_CARRY_BITS {
            s += F::from(1u64 << b)
                * cur[layout.carry_bits_base + k * MUL_CARRY_BITS + b];
        }
        s - F::from(MUL_CARRY_OFFSET)
    };

    // (2) 10 limb-sum identities.
    //
    //   T[k] + carry_in[k] - c[k] - carry[k] · 2^{w_k} = 0
    //   T[k] = Σ_{(i,j,f)} f · a[i] · b[j]
    //   Carries are SIGNED (in [-2^35, 2^35)) — the chain admits
    //   negative carries when the integer product crosses the 2^255
    //   wrap "from above" (LOW < c).
    for k in 0..NUM_LIMBS {
        let w = LIMB_WIDTHS[k];
        let radix = F::from(1u64 << w);
        let c_k = cur[layout.c_limbs_base + k];

        // T[k] (deg-2 sum of partial products).
        let mut t_k = F::zero();
        for (i, j, factor) in mul_partial_products_for_limb(k) {
            let a_i = cur[layout.a_limbs_base + i];
            let b_j = cur[layout.b_limbs_base + j];
            t_k += F::from(factor as u64) * a_i * b_j;
        }

        let carry_in = if k == 0 {
            F::from(19u64) * pack_carry_signed(NUM_LIMBS - 1)
        } else {
            pack_carry_signed(k - 1)
        };
        let carry_k = pack_carry_signed(k);
        out.push(t_k + carry_in - c_k - radix * carry_k);
    }

    // (3) Carry-bit booleanity (10 · 36 = 360 cells).
    for k in 0..NUM_LIMBS {
        for b in 0..MUL_CARRY_BITS {
            let cell = cur[layout.carry_bits_base + k * MUL_CARRY_BITS + b];
            out.push(cell * (F::one() - cell));
        }
    }

    debug_assert_eq!(out.len(), MUL_GADGET_CONSTRAINTS);
    out
}

/// Limb-form encoding of p = 2^255 − 19, used by gadgets that subtract
/// or compare against p.  Computed from the limb-width table.
fn p_limbs() -> [i64; NUM_LIMBS] {
    [
        (1i64 << 26) - 19,
        (1i64 << 25) - 1,
        (1i64 << 26) - 1,
        (1i64 << 25) - 1,
        (1i64 << 26) - 1,
        (1i64 << 25) - 1,
        (1i64 << 26) - 1,
        (1i64 << 25) - 1,
        (1i64 << 26) - 1,
        (1i64 << 25) - 1,
    ]
}

// ═══════════════════════════════════════════════════════════════════
//  FREEZE GADGET — canonical-form enforcement
// ═══════════════════════════════════════════════════════════════════
//
// Takes a "tight" input (range-checked into [0, 2^255), produced by
// add / sub / mul) and produces a STRICTLY canonical output  c ∈ [0, p).
//
// Why this gadget exists: our other gadgets range-check their outputs
// into [0, 2^255) but admit 19 non-canonical values in [p, 2^255).
// For boundary operations — most importantly, byte encoding (sign
// extraction during point compression) — we need the strict form.
//
// ─────────────────────────────────────────────────────────────────
// THE TWO CONSTRAINTS THAT MAKE IT CANONICAL
// ─────────────────────────────────────────────────────────────────
//
// 1. Conditional subtract:  input = c + s · p,   s ∈ {0, 1}.
//    Per-limb borrow chain (single-bit borrows; no signed carries
//    because p > 0 is fixed):
//      input[k] − s · p_limbs[k] − borrow_in[k]
//                 = c[k] − borrow_out[k] · 2^{w_k}
//    with borrow_in[0] = 0,  borrow_in[k] = borrow_out[k − 1],  and
//    borrow_out[9] forced to 0 (any prover with input ≥ p chooses
//    s = 1 to avoid an under-flow at the top).
//
// 2. Strict-canonical witness: cells for  g = c + 19,  range-checked
//    into [0, 2^255).  Since g_int < 2^255 ⇔ c_int < 2^255 − 19 = p,
//    this rules out the 19 non-canonical residues even when the
//    prover lies about s.  Per-limb chain for g = c + 19:
//      c[0] + 19 + g_carry_in[0]    = g[0] + g_carry_out[0] · 2^{w_0}
//      c[k] + g_carry_in[k]         = g[k] + g_carry_out[k] · 2^{w_k}
//    with g_carry_in[0] = 0,  g_carry_in[k] = g_carry_out[k−1],  and
//    g_carry_out[9] forced to 0.
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
//   c_limbs_base      + 0..10   :  canonical c                (10)
//   c_bits_base       + 0..255  :  c bit decomposition        (255)
//   g_limbs_base      + 0..10   :  g = c + 19                 (10)
//   g_bits_base       + 0..255  :  g bit decomposition        (255)
//   s_cell                       :  conditional-subtract bit  (1)
//   sub_borrows_base  + 0..9    :  borrow_out[0..8] for sub   (9)
//   add_carries_base  + 0..9    :  carry_out[0..8] for add 19 (9)
//   ──────────────────────────────────────────────────────────────────
//   TOTAL OWNED                                              559 cells
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   Range check on c       (booleanity + limb-pack):    265 deg-≤2
//   Range check on g       (booleanity + limb-pack):    265 deg-≤2
//   Conditional sub chain  (10 limb-diff identities):    10 deg-1
//   Sub borrow booleanity:                                9 deg-2
//   s booleanity:                                         1 deg-2
//   Add-19 chain           (10 limb-sum identities):     10 deg-1
//   Add-19 carry booleanity:                              9 deg-2
//   ──────────────────────────────────────────────────────────────
//   TOTAL                                               569 constraints

pub const FREEZE_GADGET_OWNED_CELLS: usize =
    2 * ELEMENT_CELLS + 1 + 2 * (NUM_LIMBS - 1);

pub const FREEZE_GADGET_CONSTRAINTS: usize =
    2 * ELEMENT_CONSTRAINTS                  // 530 (c + g range checks)
    + NUM_LIMBS                              // 10  (sub limb-diff)
    + (NUM_LIMBS - 1)                        // 9   (sub borrow booleanity)
    + 1                                      // 1   (s booleanity)
    + NUM_LIMBS                              // 10  (add limb-sum)
    + (NUM_LIMBS - 1);                       // 9   (add carry booleanity)

#[derive(Clone, Copy, Debug)]
pub struct FreezeGadgetLayout {
    pub input_limbs_base: usize,
    pub c_limbs_base:     usize,
    pub c_bits_base:      usize,
    pub g_limbs_base:     usize,
    pub g_bits_base:      usize,
    pub s_cell:           usize,
    /// 9 cells for borrow_out[0..8] of the conditional-subtract chain.
    pub sub_borrows_base: usize,
    /// 9 cells for carry_out[0..8] of the c + 19 chain.
    pub add_carries_base: usize,
}

/// Fill the gadget cells given the (range-checked, possibly non-canonical)
/// input.
pub fn fill_freeze_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &FreezeGadgetLayout,
    fe_input: &FieldElement,
) {
    // (1) Compute canonical c via the native ref.
    let mut c = *fe_input;
    c.freeze();
    let c_limbs = c.limbs;

    // (2) Determine s and the sub-chain borrows.
    //     s = 1 iff input >= p  (i.e., subtraction was needed).
    let p_l = p_limbs();
    let mut s_chosen: i64 = 0;
    let mut sub_borrows = [0i64; NUM_LIMBS - 1];
    'outer: for &candidate in &[0i64, 1i64] {
        let mut prev: i64 = 0;
        let mut tentative = [0i64; NUM_LIMBS - 1];
        for k in 0..NUM_LIMBS {
            let w = LIMB_WIDTHS[k];
            let radix = 1i64 << w;
            let v = fe_input.limbs[k] - candidate * p_l[k] - prev;
            let c_k = c_limbs[k];
            let diff = v - c_k;
            if k < NUM_LIMBS - 1 {
                if diff == 0 {
                    tentative[k] = 0;
                    prev = 0;
                } else if diff == -radix {
                    tentative[k] = 1;
                    prev = 1;
                } else {
                    continue 'outer;
                }
            } else {
                // Last limb: borrow_out[9] forced to 0.
                if diff != 0 { continue 'outer; }
            }
        }
        s_chosen = candidate;
        sub_borrows = tentative;
        break;
    }

    debug_assert!(s_chosen == 0 || s_chosen == 1);
    debug_assert!(sub_borrows.iter().all(|&b| b == 0 || b == 1));

    // (3) Compute g = c + 19 and the add-chain carries.
    let mut g_limbs = [0i64; NUM_LIMBS];
    let mut add_carries = [0i64; NUM_LIMBS - 1];
    {
        let mut prev: i64 = 0;
        for k in 0..NUM_LIMBS {
            let w = LIMB_WIDTHS[k];
            let radix = 1i64 << w;
            let extra = if k == 0 { 19 } else { 0 };
            let v = c_limbs[k] + extra + prev;
            let cell = v % radix;
            let cy = v / radix;
            g_limbs[k] = cell;
            if k < NUM_LIMBS - 1 {
                add_carries[k] = cy;
                prev = cy;
            } else {
                debug_assert_eq!(cy, 0,
                    "c + 19 overflowed limb 9 — input >= p violation");
            }
        }
    }

    // (4) Write all cells.
    for i in 0..NUM_LIMBS {
        let limb = c_limbs[i];
        trace[layout.c_limbs_base + i][row] = F::from(limb as u64);
        let mut bit_off_within = 0usize;
        for kk in 0..i { bit_off_within += LIMB_WIDTHS[kk] as usize; }
        for b in 0..LIMB_WIDTHS[i] as usize {
            let bit = (limb >> b) & 1;
            trace[layout.c_bits_base + bit_off_within + b][row]
                = F::from(bit as u64);
        }
    }
    for i in 0..NUM_LIMBS {
        let limb = g_limbs[i];
        trace[layout.g_limbs_base + i][row] = F::from(limb as u64);
        let mut bit_off_within = 0usize;
        for kk in 0..i { bit_off_within += LIMB_WIDTHS[kk] as usize; }
        for b in 0..LIMB_WIDTHS[i] as usize {
            let bit = (limb >> b) & 1;
            trace[layout.g_bits_base + bit_off_within + b][row]
                = F::from(bit as u64);
        }
    }
    trace[layout.s_cell][row] = F::from(s_chosen as u64);
    for k in 0..(NUM_LIMBS - 1) {
        trace[layout.sub_borrows_base + k][row] = F::from(sub_borrows[k] as u64);
        trace[layout.add_carries_base + k][row] = F::from(add_carries[k] as u64);
    }
}

/// Emit the `FREEZE_GADGET_CONSTRAINTS` constraints.
pub fn eval_freeze_gadget(cur: &[F], layout: &FreezeGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(FREEZE_GADGET_CONSTRAINTS);

    // (A) Range check on c (booleanity + limb-pack = 265 cons).
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_WIDTHS[i] as usize {
            let cell = cur[layout.c_bits_base + bit_off_within + b];
            out.push(cell * (F::one() - cell));
        }
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        let mut sum_bits = F::zero();
        for b in 0..LIMB_WIDTHS[i] as usize {
            sum_bits += F::from(1u64 << b)
                * cur[layout.c_bits_base + bit_off_within + b];
        }
        out.push(cur[layout.c_limbs_base + i] - sum_bits);
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }

    // (B) Range check on g (265 cons).
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        for b in 0..LIMB_WIDTHS[i] as usize {
            let cell = cur[layout.g_bits_base + bit_off_within + b];
            out.push(cell * (F::one() - cell));
        }
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }
    let mut bit_off_within = 0usize;
    for i in 0..NUM_LIMBS {
        let mut sum_bits = F::zero();
        for b in 0..LIMB_WIDTHS[i] as usize {
            sum_bits += F::from(1u64 << b)
                * cur[layout.g_bits_base + bit_off_within + b];
        }
        out.push(cur[layout.g_limbs_base + i] - sum_bits);
        bit_off_within += LIMB_WIDTHS[i] as usize;
    }

    // (C) Conditional-sub chain: input − s · p_limbs = c (limb-wise borrow).
    //   input[k] − s · p_limbs[k] − borrow_in[k] − c[k] + borrow_out[k] · 2^{w_k} = 0
    //   borrow_in[0] = 0,  borrow_in[k] = borrow_out[k−1],  borrow_out[9] = 0.
    let p_l = p_limbs();
    let s = cur[layout.s_cell];
    for k in 0..NUM_LIMBS {
        let w = LIMB_WIDTHS[k];
        let radix = F::from(1u64 << w);
        let inp_k = cur[layout.input_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];
        let p_k = F::from(p_l[k] as u64);

        let borrow_in = if k == 0 {
            F::zero()
        } else {
            cur[layout.sub_borrows_base + k - 1]
        };
        let borrow_out_term = if k < NUM_LIMBS - 1 {
            radix * cur[layout.sub_borrows_base + k]
        } else {
            F::zero()
        };
        out.push(inp_k - s * p_k - borrow_in - c_k + borrow_out_term);
    }

    // (D) Sub-borrow booleanity (9 cons).
    for k in 0..(NUM_LIMBS - 1) {
        let bo = cur[layout.sub_borrows_base + k];
        out.push(bo * (F::one() - bo));
    }

    // (E) s booleanity (1 con).
    out.push(s * (F::one() - s));

    // (F) Add-19 chain: g = c + 19 (limb-wise carry).
    //   c[k] + (19 if k=0 else 0) + carry_in[k] − g[k] − carry_out[k] · 2^{w_k} = 0
    //   carry_in[0] = 0, carry_in[k] = carry_out[k−1], carry_out[9] = 0.
    for k in 0..NUM_LIMBS {
        let w = LIMB_WIDTHS[k];
        let radix = F::from(1u64 << w);
        let c_k = cur[layout.c_limbs_base + k];
        let g_k = cur[layout.g_limbs_base + k];
        let extra = if k == 0 { F::from(19u64) } else { F::zero() };
        let carry_in = if k == 0 {
            F::zero()
        } else {
            cur[layout.add_carries_base + k - 1]
        };
        let carry_out_term = if k < NUM_LIMBS - 1 {
            radix * cur[layout.add_carries_base + k]
        } else {
            F::zero()
        };
        out.push(c_k + extra + carry_in - g_k - carry_out_term);
    }

    // (G) Add-carry booleanity (9 cons).
    for k in 0..(NUM_LIMBS - 1) {
        let cy = cur[layout.add_carries_base + k];
        out.push(cy * (F::one() - cy));
    }

    debug_assert_eq!(out.len(), FREEZE_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  CONDITIONAL SELECT GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Computes  c = if bit then b else a,  selecting between two
// canonical-form field elements based on a single boolean cell.
// Used by the scalar-mult ladder (constant-time conditional point
// addition).
//
// ─────────────────────────────────────────────────────────────────
// CELL LAYOUT
// ─────────────────────────────────────────────────────────────────
//
//   bit_cell          :  selector bit                         (1 cell)
//   c_limbs_base + 0..10  :  output limbs                     (10 cells)
//   ──────────────────────────────────────────────────────────────────
//   TOTAL OWNED                                              11 cells
//
// Inputs `a` and `b` are referenced by base; the gadget assumes
// they are range-checked by their producer (e.g., previous ops).
// Output `c` does NOT need an independent range check: by the
// per-limb constraint c[k] = a[k] + bit · (b[k] − a[k]),  c is forced
// to equal exactly one of {a, b}, both of which are already
// range-checked.
//
// ─────────────────────────────────────────────────────────────────
// CONSTRAINT BUDGET
// ─────────────────────────────────────────────────────────────────
//
//   1 booleanity:                                   bit · (1 − bit) = 0
//   10 per-limb selects (each deg-2):
//     c[k] − a[k] − bit · (b[k] − a[k]) = 0
//   ──────────────────────────────────────────────────────
//   TOTAL                                          11 constraints

pub const SELECT_GADGET_OWNED_CELLS: usize = 1 + NUM_LIMBS;
pub const SELECT_GADGET_CONSTRAINTS: usize = 1 + NUM_LIMBS;

#[derive(Clone, Copy, Debug)]
pub struct SelectGadgetLayout {
    pub a_limbs_base: usize,
    pub b_limbs_base: usize,
    pub bit_cell:     usize,
    pub c_limbs_base: usize,
}

/// Fill the gadget-owned cells (bit + c-limbs) with the appropriate
/// selection based on `bit`.  When `bit` is true, c = b; else c = a.
pub fn fill_select_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &SelectGadgetLayout,
    fe_a: &FieldElement,
    fe_b: &FieldElement,
    bit: bool,
) {
    trace[layout.bit_cell][row] = F::from(bit as u64);
    let chosen = if bit { fe_b } else { fe_a };
    for k in 0..NUM_LIMBS {
        trace[layout.c_limbs_base + k][row] = F::from(chosen.limbs[k] as u64);
    }
}

/// Emit the `SELECT_GADGET_CONSTRAINTS` transition constraints.
pub fn eval_select_gadget(cur: &[F], layout: &SelectGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(SELECT_GADGET_CONSTRAINTS);

    let bit = cur[layout.bit_cell];
    out.push(bit * (F::one() - bit));

    for k in 0..NUM_LIMBS {
        let a_k = cur[layout.a_limbs_base + k];
        let b_k = cur[layout.b_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];
        // c = a + bit · (b − a)
        out.push(c_k - a_k - bit * (b_k - a_k));
    }

    debug_assert_eq!(out.len(), SELECT_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  SQUARE GADGET
// ═══════════════════════════════════════════════════════════════════
//
// Computes c = a² mod p.  In v1 this is a thin wrapper over the MUL
// gadget called with both operands equal to `a` — same cell layout,
// same constraints, same trace builder.  Future versions can specialise
// to share half the cross products (i, j) with (j, i) where i ≠ j,
// roughly halving the partial-product count.

pub const SQUARE_GADGET_OWNED_CELLS:  usize = MUL_GADGET_OWNED_CELLS;
pub const SQUARE_GADGET_CONSTRAINTS: usize = MUL_GADGET_CONSTRAINTS;

pub type SquareGadgetLayout = MulGadgetLayout;

#[inline]
pub fn fill_square_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &SquareGadgetLayout,
    fe_a: &FieldElement,
) {
    fill_mul_gadget(trace, row, layout, fe_a, fe_a);
}

#[inline]
pub fn eval_square_gadget(cur: &[F], layout: &SquareGadgetLayout) -> Vec<F> {
    eval_mul_gadget(cur, layout)
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_field::FieldElement;

    fn make_trace_row(width: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); 1]).collect()
    }

    fn fe_from_seed(seed: u64) -> FieldElement {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((seed.wrapping_mul(7) + i as u64 * 11) % 256) as u8;
        }
        bytes[31] &= 0x7f;
        FieldElement::from_bytes(&bytes)
    }

    #[test]
    fn cell_count_matches_documented_constants() {
        assert_eq!(ELEMENT_LIMB_CELLS, 10);
        assert_eq!(ELEMENT_BIT_CELLS, 255);
        assert_eq!(ELEMENT_CELLS, 265);
        assert_eq!(ELEMENT_CONSTRAINTS, 265);
        // limb_bits_offset(10) = total bit count.
        let mut total = 0;
        for i in 0..NUM_LIMBS { total += LIMB_WIDTHS[i] as usize; }
        assert_eq!(total, ELEMENT_BIT_CELLS);
    }

    #[test]
    fn bit_cell_addressing_is_unique_and_in_range() {
        // No two (limb_idx, bit_idx) pairs map to the same cell, and
        // every cell offset is within ELEMENT_CELLS.
        let mut seen = vec![false; ELEMENT_CELLS];
        for i in 0..NUM_LIMBS {
            for b in 0..LIMB_WIDTHS[i] as usize {
                let c = bit_cell(i, b);
                assert!(c >= ELEMENT_BITS_BASE);
                assert!(c < ELEMENT_CELLS);
                assert!(!seen[c], "duplicate bit cell at {}", c);
                seen[c] = true;
            }
        }
        // All bit cells (offsets ELEMENT_BITS_BASE..ELEMENT_CELLS) are seen.
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
            assert_eq!(read_back.limbs, fe.limbs,
                "place+read mismatch for seed {}", seed);
        }
    }

    #[test]
    fn range_check_passes_on_canonical_element() {
        for seed in 0u64..8 {
            let fe = fe_from_seed(seed);
            let mut trace = make_trace_row(ELEMENT_CELLS);
            place_element(&mut trace, 0, 0, &fe);
            // Read row 0 as a flat `cur` slice.
            let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
            let cons = eval_element_range_check(&cur, 0);
            for (i, v) in cons.iter().enumerate() {
                assert!(v.is_zero(),
                    "constraint #{} non-zero for seed {}: {:?}", i, seed, v);
            }
        }
    }

    #[test]
    fn range_check_fails_on_tampered_bit() {
        // Place a valid element, flip one bit cell, and expect the
        // constraint vector to contain at least one non-zero entry.
        let fe = fe_from_seed(42);
        let mut trace = make_trace_row(ELEMENT_CELLS);
        place_element(&mut trace, 0, 0, &fe);

        // Flip a bit cell to "2" (deliberately out-of-range) — this
        // should violate the booleanity constraint.
        let target_cell = bit_cell(3, 5);
        trace[target_cell][0] = F::from(2u64);

        let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
        let cons = eval_element_range_check(&cur, 0);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1,
            "tampered bit cell did not produce a constraint violation");
    }

    #[test]
    fn range_check_fails_on_tampered_limb() {
        // Place a valid element, change one limb cell so it no longer
        // matches its bit decomposition; expect the limb-pack
        // constraint for that limb to be non-zero.
        let fe = fe_from_seed(11);
        let mut trace = make_trace_row(ELEMENT_CELLS);
        place_element(&mut trace, 0, 0, &fe);

        // Add 1 to limb 4 without updating its bits.
        let original = trace[4][0];
        trace[4][0] = original + F::one();

        let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
        let cons = eval_element_range_check(&cur, 0);

        // Booleanity (first 255) should all be zero — we didn't touch
        // the bit cells.  Limb pack #4 (offset 255 + 4 = 259) should
        // be non-zero.
        for i in 0..ELEMENT_BIT_CELLS {
            assert!(cons[i].is_zero(),
                "booleanity constraint #{} unexpectedly non-zero", i);
        }
        assert!(!cons[ELEMENT_BIT_CELLS + 4].is_zero(),
            "limb-pack constraint for limb 4 should detect the tamper");
        // Other limb-pack constraints unchanged.
        for k in 0..NUM_LIMBS {
            if k != 4 {
                assert!(cons[ELEMENT_BIT_CELLS + k].is_zero(),
                    "limb-pack #{} unexpectedly non-zero", k);
            }
        }
    }

    #[test]
    fn d_constant_round_trips_through_air_layout() {
        // The Ed25519 d constant should round-trip cleanly through
        // place / read.
        use crate::ed25519_field::D;
        let d = *D;
        let mut trace = make_trace_row(ELEMENT_CELLS);
        place_element(&mut trace, 0, 0, &d);
        let read_back = read_element(&trace, 0, 0);
        assert_eq!(read_back.limbs, d.limbs);

        let cur: Vec<F> = (0..ELEMENT_CELLS).map(|c| trace[c][0]).collect();
        let cons = eval_element_range_check(&cur, 0);
        for v in &cons {
            assert!(v.is_zero(), "d-constant range check should be all zeros");
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //  Add-gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_satisfies_add(layout: &AddGadgetLayout, total_width: usize, fe_a: &FieldElement, fe_b: &FieldElement) {
        let mut trace = make_trace_row(total_width);
        place_element(&mut trace, 0, layout.a_limbs_base, fe_a);
        place_element(&mut trace, 0, layout.b_limbs_base, fe_b);
        fill_add_gadget(&mut trace, 0, layout, fe_a, fe_b);

        // Verify the c output equals (a + b) mod p (via native ref).
        let c = read_element(&trace, 0, layout.c_limbs_base);
        let expected = fe_a.add(fe_b);
        let mut expected_canonical = expected;
        expected_canonical.freeze();
        assert_eq!(
            c.to_bytes(), expected_canonical.to_bytes(),
            "add gadget output ≠ (a + b) mod p"
        );

        // Verify all gadget constraints zero.
        let cur: Vec<F> = (0..total_width).map(|col| trace[col][0]).collect();
        let cons = eval_add_gadget(&cur, layout);
        for (i, v) in cons.iter().enumerate() {
            assert!(v.is_zero(),
                "add-gadget constraint #{} non-zero: {:?}", i, v);
        }
    }

    /// Helper: a self-contained "add-gadget block" layout that places
    /// a, b, and the gadget's owned cells in a single contiguous slab.
    fn standalone_add_layout() -> (AddGadgetLayout, usize) {
        // Slab layout:
        //   [0,         265):  a element block (limb + bits)
        //   [265,       530):  b element block
        //   [530, 530 + ADD_GADGET_OWNED_CELLS): gadget-owned cells
        let a_base = 0;
        let b_base = ELEMENT_CELLS;
        let owned_base = 2 * ELEMENT_CELLS;
        let layout = AddGadgetLayout {
            a_limbs_base: a_base,
            b_limbs_base: b_base,
            c_limbs_base: owned_base,
            c_bits_base:  owned_base + ELEMENT_LIMB_CELLS,
            carries_base: owned_base + ELEMENT_CELLS,
        };
        let total = owned_base + ADD_GADGET_OWNED_CELLS;
        (layout, total)
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
        let z = FieldElement::zero();
        let x = fe_from_seed(7);
        assert_satisfies_add(&layout, total, &z, &x);
        assert_satisfies_add(&layout, total, &x, &z);
    }

    #[test]
    fn add_gadget_simple_sums() {
        let (layout, total) = standalone_add_layout();
        for (sa, sb) in [(1u64, 2u64), (3u64, 5u64), (0xdeadbeef_u64, 0xcafebabe_u64)] {
            let mut a_bytes = [0u8; 32];
            a_bytes[..8].copy_from_slice(&sa.to_le_bytes());
            let mut b_bytes = [0u8; 32];
            b_bytes[..8].copy_from_slice(&sb.to_le_bytes());
            let a = FieldElement::from_bytes(&a_bytes);
            let b = FieldElement::from_bytes(&b_bytes);
            assert_satisfies_add(&layout, total, &a, &b);
        }
    }

    #[test]
    fn add_gadget_random_canonical_inputs() {
        let (layout, total) = standalone_add_layout();
        for seed in 0u64..20 {
            let a = fe_from_seed(seed.wrapping_mul(13));
            let b = fe_from_seed(seed.wrapping_mul(17) + 7);
            assert_satisfies_add(&layout, total, &a, &b);
        }
    }

    #[test]
    fn add_gadget_overflow_wraps_correctly() {
        // a, b each = p - 1 (the largest canonical value).  a + b = 2p - 2,
        // which mod p is p - 2.  Forces carry[9] = 1 (the wrap path).
        let (layout, total) = standalone_add_layout();
        let mut p_minus_1_bytes = [0u8; 32];
        for b in p_minus_1_bytes.iter_mut() { *b = 0xff; }
        p_minus_1_bytes[0] = 0xec;     // p = 2^255 - 19, so p - 1 = ...ec at byte 0.
        p_minus_1_bytes[31] = 0x7f;    // bit 255 cleared.
        let p_minus_1 = FieldElement::from_bytes(&p_minus_1_bytes);
        assert_satisfies_add(&layout, total, &p_minus_1, &p_minus_1);
    }

    #[test]
    fn add_gadget_tamper_detection() {
        // Build a valid trace, flip one carry bit, expect constraint violation.
        let (layout, total) = standalone_add_layout();
        let a = fe_from_seed(123);
        let b = fe_from_seed(456);
        let mut trace = make_trace_row(total);
        place_element(&mut trace, 0, layout.a_limbs_base, &a);
        place_element(&mut trace, 0, layout.b_limbs_base, &b);
        fill_add_gadget(&mut trace, 0, &layout, &a, &b);

        // Flip carry[3].
        let target = layout.carries_base + 3;
        trace[target][0] = if trace[target][0].is_zero() { F::one() } else { F::zero() };

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_add_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1,
            "tampering with a carry cell did not produce a constraint violation");
    }

    // ─────────────────────────────────────────────────────────────────
    //  Sub-gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_sub_layout() -> (SubGadgetLayout, usize) {
        let a_base = 0;
        let b_base = ELEMENT_CELLS;
        let owned_base = 2 * ELEMENT_CELLS;
        let layout = SubGadgetLayout {
            a_limbs_base: a_base,
            b_limbs_base: b_base,
            c_limbs_base: owned_base,
            c_bits_base:  owned_base + ELEMENT_LIMB_CELLS,
            c_pos_base:   owned_base + ELEMENT_CELLS,
            c_neg_base:   owned_base + ELEMENT_CELLS + NUM_LIMBS,
        };
        let total = owned_base + SUB_GADGET_OWNED_CELLS;
        (layout, total)
    }

    fn assert_satisfies_sub(layout: &SubGadgetLayout, total_width: usize, fe_a: &FieldElement, fe_b: &FieldElement) {
        let mut trace = make_trace_row(total_width);
        place_element(&mut trace, 0, layout.a_limbs_base, fe_a);
        place_element(&mut trace, 0, layout.b_limbs_base, fe_b);
        fill_sub_gadget(&mut trace, 0, layout, fe_a, fe_b);

        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut expected = fe_a.sub(fe_b);
        expected.freeze();
        assert_eq!(c.to_bytes(), expected.to_bytes(),
            "sub gadget output ≠ (a - b) mod p");

        let cur: Vec<F> = (0..total_width).map(|col| trace[col][0]).collect();
        let cons = eval_sub_gadget(&cur, layout);
        for (i, v) in cons.iter().enumerate() {
            assert!(v.is_zero(),
                "sub-gadget constraint #{} non-zero: {:?}", i, v);
        }
    }

    #[test]
    fn sub_gadget_zero_minus_zero_is_zero() {
        let (layout, total) = standalone_sub_layout();
        let zero = FieldElement::zero();
        assert_satisfies_sub(&layout, total, &zero, &zero);
    }

    #[test]
    fn sub_gadget_x_minus_x_is_zero() {
        let (layout, total) = standalone_sub_layout();
        let x = fe_from_seed(99);
        assert_satisfies_sub(&layout, total, &x, &x);
    }

    #[test]
    fn sub_gadget_simple_difference() {
        let (layout, total) = standalone_sub_layout();
        let mut a_bytes = [0u8; 32]; a_bytes[0] = 100;
        let mut b_bytes = [0u8; 32]; b_bytes[0] = 30;
        let a = FieldElement::from_bytes(&a_bytes);
        let b = FieldElement::from_bytes(&b_bytes);
        assert_satisfies_sub(&layout, total, &a, &b);   // 100 - 30 = 70 (s=0)
    }

    #[test]
    fn sub_gadget_underflow_wraps() {
        let (layout, total) = standalone_sub_layout();
        let mut a_bytes = [0u8; 32]; a_bytes[0] = 30;
        let mut b_bytes = [0u8; 32]; b_bytes[0] = 100;
        let a = FieldElement::from_bytes(&a_bytes);
        let b = FieldElement::from_bytes(&b_bytes);
        // 30 - 100 = -70 ≡ p - 70 (mod p), wrap path with s = 1.
        assert_satisfies_sub(&layout, total, &a, &b);
    }

    #[test]
    fn sub_gadget_random_canonical_inputs() {
        let (layout, total) = standalone_sub_layout();
        for seed in 0u64..20 {
            let a = fe_from_seed(seed.wrapping_mul(13));
            let b = fe_from_seed(seed.wrapping_mul(17) + 7);
            assert_satisfies_sub(&layout, total, &a, &b);
            // Also test the reverse direction.
            assert_satisfies_sub(&layout, total, &b, &a);
        }
    }

    #[test]
    fn sub_gadget_zero_minus_one_is_p_minus_one() {
        let (layout, total) = standalone_sub_layout();
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        assert_satisfies_sub(&layout, total, &zero, &one);
    }

    #[test]
    fn sub_gadget_tamper_detection() {
        let (layout, total) = standalone_sub_layout();
        let a = fe_from_seed(321);
        let b = fe_from_seed(654);
        let mut trace = make_trace_row(total);
        place_element(&mut trace, 0, layout.a_limbs_base, &a);
        place_element(&mut trace, 0, layout.b_limbs_base, &b);
        fill_sub_gadget(&mut trace, 0, &layout, &a, &b);

        // Flip the top-limb negative-carry indicator (which carries the
        // mod-p wrap information).
        let target = layout.c_neg_base + (NUM_LIMBS - 1);
        trace[target][0] = if trace[target][0].is_zero() { F::one() } else { F::zero() };

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_sub_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1,
            "flipping the top carry indicator should produce a constraint violation");
    }

    // ─────────────────────────────────────────────────────────────────
    //  Mul-gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_mul_layout() -> (MulGadgetLayout, usize) {
        let a_base = 0;
        let b_base = ELEMENT_CELLS;
        let owned_base = 2 * ELEMENT_CELLS;
        let layout = MulGadgetLayout {
            a_limbs_base:    a_base,
            b_limbs_base:    b_base,
            c_limbs_base:    owned_base,
            c_bits_base:     owned_base + ELEMENT_LIMB_CELLS,
            carry_bits_base: owned_base + ELEMENT_CELLS,
        };
        let total = owned_base + MUL_GADGET_OWNED_CELLS;
        (layout, total)
    }

    fn assert_satisfies_mul(layout: &MulGadgetLayout, total_width: usize, fe_a: &FieldElement, fe_b: &FieldElement) {
        let mut trace = make_trace_row(total_width);
        place_element(&mut trace, 0, layout.a_limbs_base, fe_a);
        place_element(&mut trace, 0, layout.b_limbs_base, fe_b);
        fill_mul_gadget(&mut trace, 0, layout, fe_a, fe_b);

        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut expected = fe_a.mul(fe_b);
        expected.freeze();
        assert_eq!(c.to_bytes(), expected.to_bytes(),
            "mul gadget output ≠ (a · b) mod p");

        let cur: Vec<F> = (0..total_width).map(|col| trace[col][0]).collect();
        let cons = eval_mul_gadget(&cur, layout);
        for (i, v) in cons.iter().enumerate() {
            assert!(v.is_zero(),
                "mul-gadget constraint #{} non-zero: {:?}", i, v);
        }
    }

    #[test]
    fn mul_gadget_constants() {
        // Sanity on the documented sizes.
        assert_eq!(MUL_CARRY_BITS, 36);
        assert_eq!(MUL_GADGET_OWNED_CELLS, 265 + 36 * 10);
        assert_eq!(MUL_GADGET_CONSTRAINTS, 265 + 10 + 36 * 10);
    }

    #[test]
    fn mul_partial_products_table_is_complete() {
        // Every (i, j) ∈ [0, 10)² must appear in exactly one limb's
        // partial-product list.
        let mut seen = std::collections::HashSet::new();
        for k in 0..NUM_LIMBS {
            for (i, j, _f) in mul_partial_products_for_limb(k) {
                assert!(seen.insert((i, j)),
                    "duplicate (i, j) = ({}, {}) at limb {}", i, j, k);
            }
        }
        assert_eq!(seen.len(), NUM_LIMBS * NUM_LIMBS,
            "missing some (i, j) pairs");
    }

    #[test]
    fn mul_gadget_zero_times_zero_is_zero() {
        let (layout, total) = standalone_mul_layout();
        let zero = FieldElement::zero();
        assert_satisfies_mul(&layout, total, &zero, &zero);
    }

    #[test]
    fn mul_gadget_one_times_x_is_x() {
        let (layout, total) = standalone_mul_layout();
        let one = FieldElement::one();
        let x = fe_from_seed(7);
        assert_satisfies_mul(&layout, total, &one, &x);
        assert_satisfies_mul(&layout, total, &x, &one);
    }

    #[test]
    fn mul_gadget_zero_times_x_is_zero() {
        let (layout, total) = standalone_mul_layout();
        let zero = FieldElement::zero();
        let x = fe_from_seed(11);
        assert_satisfies_mul(&layout, total, &zero, &x);
    }

    #[test]
    fn mul_gadget_simple_products() {
        let (layout, total) = standalone_mul_layout();
        for (sa, sb) in [(2u64, 3u64), (7, 11), (0xdead_u64, 0xbeef_u64), (0x10000000_u64, 0x20000000_u64)] {
            let mut a_bytes = [0u8; 32];
            a_bytes[..8].copy_from_slice(&sa.to_le_bytes());
            let mut b_bytes = [0u8; 32];
            b_bytes[..8].copy_from_slice(&sb.to_le_bytes());
            let a = FieldElement::from_bytes(&a_bytes);
            let b = FieldElement::from_bytes(&b_bytes);
            assert_satisfies_mul(&layout, total, &a, &b);
        }
    }

    #[test]
    fn mul_gadget_random_canonical_inputs() {
        let (layout, total) = standalone_mul_layout();
        for seed in 0u64..15 {
            let a = fe_from_seed(seed.wrapping_mul(31) + 5);
            let b = fe_from_seed(seed.wrapping_mul(41) + 9);
            assert_satisfies_mul(&layout, total, &a, &b);
        }
    }

    #[test]
    fn mul_gadget_d_times_121666_eq_minus_121665() {
        // The defining identity for the Ed25519 d constant.
        use crate::ed25519_field::D;
        let (layout, total) = standalone_mul_layout();
        let d = *D;
        let one = FieldElement::one();
        let small = one.mul_small(121666);
        assert_satisfies_mul(&layout, total, &d, &small);
    }

    #[test]
    fn mul_gadget_self_squared_matches_square() {
        let (layout, total) = standalone_mul_layout();
        for seed in 0u64..6 {
            let a = fe_from_seed(seed * 71 + 3);
            assert_satisfies_mul(&layout, total, &a, &a);
        }
    }

    #[test]
    fn mul_gadget_p_minus_1_squared() {
        // (p - 1)² mod p = 1.  Worst-case carries.
        let (layout, total) = standalone_mul_layout();
        let mut p_minus_1_bytes = [0u8; 32];
        for byte in p_minus_1_bytes.iter_mut() { *byte = 0xff; }
        p_minus_1_bytes[0]  = 0xec;
        p_minus_1_bytes[31] = 0x7f;
        let p_minus_1 = FieldElement::from_bytes(&p_minus_1_bytes);
        assert_satisfies_mul(&layout, total, &p_minus_1, &p_minus_1);
    }

    #[test]
    fn mul_gadget_tamper_detection() {
        let (layout, total) = standalone_mul_layout();
        let a = fe_from_seed(135);
        let b = fe_from_seed(246);
        let mut trace = make_trace_row(total);
        place_element(&mut trace, 0, layout.a_limbs_base, &a);
        place_element(&mut trace, 0, layout.b_limbs_base, &b);
        fill_mul_gadget(&mut trace, 0, &layout, &a, &b);

        // Flip a carry bit at limb 4, bit 5.
        let target = mul_carry_bit_cell(&layout, 4, 5);
        trace[target][0] = if trace[target][0].is_zero() { F::one() } else { F::zero() };

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_mul_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1,
            "flipping a carry bit should produce a constraint violation");
    }

    // ─────────────────────────────────────────────────────────────────
    //  Select-gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_select_layout() -> (SelectGadgetLayout, usize) {
        let a_base = 0;
        let b_base = ELEMENT_CELLS;
        let owned_base = 2 * ELEMENT_CELLS;
        let layout = SelectGadgetLayout {
            a_limbs_base: a_base,
            b_limbs_base: b_base,
            bit_cell:     owned_base,
            c_limbs_base: owned_base + 1,
        };
        let total = owned_base + SELECT_GADGET_OWNED_CELLS;
        (layout, total)
    }

    fn assert_satisfies_select(layout: &SelectGadgetLayout, total_width: usize, fe_a: &FieldElement, fe_b: &FieldElement, bit: bool) {
        let mut trace = make_trace_row(total_width);
        place_element(&mut trace, 0, layout.a_limbs_base, fe_a);
        place_element(&mut trace, 0, layout.b_limbs_base, fe_b);
        fill_select_gadget(&mut trace, 0, layout, fe_a, fe_b, bit);

        let c = read_element(&trace, 0, layout.c_limbs_base);
        let expected = if bit { fe_b } else { fe_a };
        assert_eq!(c.limbs, expected.limbs,
            "select output ≠ chosen input (bit={})", bit);

        let cur: Vec<F> = (0..total_width).map(|col| trace[col][0]).collect();
        let cons = eval_select_gadget(&cur, layout);
        for (i, v) in cons.iter().enumerate() {
            assert!(v.is_zero(),
                "select-gadget constraint #{} non-zero: {:?}", i, v);
        }
    }

    #[test]
    fn select_gadget_constants() {
        assert_eq!(SELECT_GADGET_OWNED_CELLS, 11);
        assert_eq!(SELECT_GADGET_CONSTRAINTS, 11);
    }

    #[test]
    fn select_gadget_picks_a_when_bit_zero() {
        let (layout, total) = standalone_select_layout();
        let a = fe_from_seed(11);
        let b = fe_from_seed(22);
        assert_satisfies_select(&layout, total, &a, &b, false);
    }

    #[test]
    fn select_gadget_picks_b_when_bit_one() {
        let (layout, total) = standalone_select_layout();
        let a = fe_from_seed(11);
        let b = fe_from_seed(22);
        assert_satisfies_select(&layout, total, &a, &b, true);
    }

    #[test]
    fn select_gadget_random_pairs() {
        let (layout, total) = standalone_select_layout();
        for seed in 0u64..10 {
            let a = fe_from_seed(seed * 13 + 1);
            let b = fe_from_seed(seed * 17 + 5);
            assert_satisfies_select(&layout, total, &a, &b, false);
            assert_satisfies_select(&layout, total, &a, &b, true);
        }
    }

    #[test]
    fn select_gadget_tamper_swaps_output() {
        // Fill with bit = 0 (output should = a), then flip the bit cell
        // to 1, expect violation (since c is still a, not b).
        let (layout, total) = standalone_select_layout();
        let a = fe_from_seed(33);
        let b = fe_from_seed(77);
        let mut trace = make_trace_row(total);
        place_element(&mut trace, 0, layout.a_limbs_base, &a);
        place_element(&mut trace, 0, layout.b_limbs_base, &b);
        fill_select_gadget(&mut trace, 0, &layout, &a, &b, false);

        // Flip the bit cell.
        trace[layout.bit_cell][0] = F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_select_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1,
            "tampering with bit cell did not produce a violation");
    }

    #[test]
    fn select_gadget_non_boolean_bit_fails() {
        let (layout, total) = standalone_select_layout();
        let a = fe_from_seed(33);
        let b = fe_from_seed(77);
        let mut trace = make_trace_row(total);
        place_element(&mut trace, 0, layout.a_limbs_base, &a);
        place_element(&mut trace, 0, layout.b_limbs_base, &b);
        fill_select_gadget(&mut trace, 0, &layout, &a, &b, false);

        // Set bit cell to 2 (out of {0, 1}); booleanity must catch.
        trace[layout.bit_cell][0] = F::from(2u64);

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_select_gadget(&cur, &layout);
        // The booleanity constraint (#0) should be non-zero.
        assert!(!cons[0].is_zero(),
            "non-boolean bit not caught by booleanity constraint");
    }

    // ─────────────────────────────────────────────────────────────────
    //  Square-gadget tests (alias of mul)
    // ─────────────────────────────────────────────────────────────────

    fn standalone_square_layout() -> (SquareGadgetLayout, usize) {
        // Same shape as a mul layout, but b is unused (filled with the
        // same a).
        let a_base = 0;
        let b_base = ELEMENT_CELLS;
        let owned_base = 2 * ELEMENT_CELLS;
        let layout = SquareGadgetLayout {
            a_limbs_base:    a_base,
            b_limbs_base:    b_base,
            c_limbs_base:    owned_base,
            c_bits_base:     owned_base + ELEMENT_LIMB_CELLS,
            carry_bits_base: owned_base + ELEMENT_CELLS,
        };
        let total = owned_base + SQUARE_GADGET_OWNED_CELLS;
        (layout, total)
    }

    // ─────────────────────────────────────────────────────────────────
    //  Freeze-gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_freeze_layout() -> (FreezeGadgetLayout, usize) {
        // Slab: input element (just limbs), then gadget-owned cells.
        let input_limbs_base = 0;
        let owned_base = NUM_LIMBS;
        let layout = FreezeGadgetLayout {
            input_limbs_base,
            c_limbs_base:     owned_base,
            c_bits_base:      owned_base + ELEMENT_LIMB_CELLS,
            g_limbs_base:     owned_base + ELEMENT_CELLS,
            g_bits_base:      owned_base + ELEMENT_CELLS + ELEMENT_LIMB_CELLS,
            s_cell:           owned_base + 2 * ELEMENT_CELLS,
            sub_borrows_base: owned_base + 2 * ELEMENT_CELLS + 1,
            add_carries_base: owned_base + 2 * ELEMENT_CELLS + 1 + (NUM_LIMBS - 1),
        };
        let total = owned_base + FREEZE_GADGET_OWNED_CELLS;
        (layout, total)
    }

    fn assert_satisfies_freeze(layout: &FreezeGadgetLayout, total_width: usize, fe_input: &FieldElement) {
        let mut trace = make_trace_row(total_width);
        // Place input limbs.
        for k in 0..NUM_LIMBS {
            trace[layout.input_limbs_base + k][0] = F::from(fe_input.limbs[k] as u64);
        }
        fill_freeze_gadget(&mut trace, 0, layout, fe_input);

        let c = read_element(&trace, 0, layout.c_limbs_base);
        let mut expected = *fe_input;
        expected.freeze();
        assert_eq!(c.limbs, expected.limbs,
            "freeze gadget output ≠ canonical input");

        let cur: Vec<F> = (0..total_width).map(|col| trace[col][0]).collect();
        let cons = eval_freeze_gadget(&cur, layout);
        for (i, v) in cons.iter().enumerate() {
            assert!(v.is_zero(),
                "freeze-gadget constraint #{} non-zero: {:?}", i, v);
        }
    }

    #[test]
    fn freeze_gadget_constants() {
        // 2 × 265 + 1 + 9 + 9 = 549; but we have 10 + 255 + 10 + 255 + 1 + 9 + 9 = 549? wait
        // ELEMENT_CELLS = 265; 2*265 + 1 + 9 + 9 = 549. Actually wait 559 was the earlier number.
        // Recompute: 2 × ELEMENT_CELLS = 530; + 1 (s) + 9 (sub) + 9 (add) = 549.
        assert_eq!(FREEZE_GADGET_OWNED_CELLS, 2 * ELEMENT_CELLS + 1 + 2 * (NUM_LIMBS - 1));
        assert_eq!(FREEZE_GADGET_OWNED_CELLS, 549);
        assert_eq!(FREEZE_GADGET_CONSTRAINTS, 569);
    }

    #[test]
    fn freeze_gadget_canonical_is_idempotent() {
        let (layout, total) = standalone_freeze_layout();
        for seed in 0u64..8 {
            let a = fe_from_seed(seed * 11 + 3);
            // a is already canonical (fe_from_seed produces canonical output).
            assert_satisfies_freeze(&layout, total, &a);
        }
    }

    #[test]
    fn freeze_gadget_zero_freezes_to_zero() {
        let (layout, total) = standalone_freeze_layout();
        let zero = FieldElement::zero();
        assert_satisfies_freeze(&layout, total, &zero);
    }

    #[test]
    fn freeze_gadget_p_minus_1_freezes_to_p_minus_1() {
        // p - 1 IS canonical (since canonical is < p).
        let (layout, total) = standalone_freeze_layout();
        let mut p_minus_1_bytes = [0u8; 32];
        for byte in p_minus_1_bytes.iter_mut() { *byte = 0xff; }
        p_minus_1_bytes[0]  = 0xec;
        p_minus_1_bytes[31] = 0x7f;
        let p_minus_1 = FieldElement::from_bytes(&p_minus_1_bytes);
        assert_satisfies_freeze(&layout, total, &p_minus_1);
    }

    #[test]
    fn freeze_gadget_non_canonical_input_freezes_correctly() {
        // Construct a NON-canonical input (limbs in tight form but
        // integer ≥ p).  E.g., input = p + 5 (= 2^255 - 14).
        // Limbs: [2^26 - 14, 2^25 - 1, 2^26 - 1, 2^25 - 1, ..., 2^25 - 1].
        let (layout, total) = standalone_freeze_layout();
        let mut limbs = [0i64; NUM_LIMBS];
        limbs[0] = (1i64 << 26) - 14;     // = p_limbs[0] + 5
        for k in 1..NUM_LIMBS {
            limbs[k] = (1i64 << LIMB_WIDTHS[k]) - 1;
        }
        let non_canonical = FieldElement { limbs };
        // Sanity: non_canonical's integer value should be p + 5.
        assert_satisfies_freeze(&layout, total, &non_canonical);
    }

    #[test]
    fn freeze_gadget_random_inputs() {
        let (layout, total) = standalone_freeze_layout();
        for seed in 0u64..15 {
            let a = fe_from_seed(seed * 23 + 11);
            assert_satisfies_freeze(&layout, total, &a);
        }
    }

    #[test]
    fn freeze_gadget_tamper_detection() {
        let (layout, total) = standalone_freeze_layout();
        let a = fe_from_seed(99);
        let mut trace = make_trace_row(total);
        for k in 0..NUM_LIMBS {
            trace[layout.input_limbs_base + k][0] = F::from(a.limbs[k] as u64);
        }
        fill_freeze_gadget(&mut trace, 0, &layout, &a);

        // Flip s.
        let target = layout.s_cell;
        trace[target][0] = if trace[target][0].is_zero() { F::one() } else { F::zero() };

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_freeze_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1,
            "tampering with s did not produce a constraint violation");
    }

    #[test]
    fn square_gadget_self_squared_matches_native() {
        let (layout, total) = standalone_square_layout();
        for seed in 0u64..5 {
            let a = fe_from_seed(seed * 19 + 4);
            // Place a in BOTH a and b slots (the square gadget uses the
            // mul layout but reads `a` for both operands).
            let mut trace = make_trace_row(total);
            place_element(&mut trace, 0, layout.a_limbs_base, &a);
            place_element(&mut trace, 0, layout.b_limbs_base, &a);
            fill_square_gadget(&mut trace, 0, &layout, &a);

            let c = read_element(&trace, 0, layout.c_limbs_base);
            let mut expected = a.square();
            expected.freeze();
            assert_eq!(c.to_bytes(), expected.to_bytes(),
                "square gadget output ≠ a² mod p");

            let cur: Vec<F> = (0..total).map(|col| trace[col][0]).collect();
            let cons = eval_square_gadget(&cur, &layout);
            for (i, v) in cons.iter().enumerate() {
                assert!(v.is_zero(),
                    "square-gadget constraint #{} non-zero: {:?}", i, v);
            }
        }
    }
}
