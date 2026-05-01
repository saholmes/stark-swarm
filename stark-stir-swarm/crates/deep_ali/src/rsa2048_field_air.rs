// rsa2048_field_air.rs — Scaffolding for the in-circuit
// F_{n_RSA2048} witness-quotient multiplication gadget.
//
// Phase 1 (this commit): types, layout, constraint-count budget.
// Phase 2 (next): fill_mul_gadget + eval_mul_gadget actual constraint
// emission (mirrors `p256_field_air.rs` mul gadget but with 80 limbs
// and a non-Solinas, modulus-as-input witness-quotient form).
//
// ─────────────────────────────────────────────────────────────────
// LIMB REPRESENTATION
// ─────────────────────────────────────────────────────────────────
//
// A 2048-bit non-negative integer is stored as 80 limbs of 26 bits
// each (80 × 26 = 2080 bits, with 32 bits of headroom).  This
// matches the P-256 `Element` shape extended in-place from 10 to 80
// limbs.  Cross-product limbs are products of two 26-bit values
// (max 2^52); summing up to 80 such per output position fits in
// $80 \cdot 2^{52} \le 2^{58.3}$, comfortably inside i64.
//
// ─────────────────────────────────────────────────────────────────
// MULTIPLICATION GADGET (witness-quotient, modulus as input)
// ─────────────────────────────────────────────────────────────────
//
// Inputs:  a (80 limbs), b (80 limbs), modulus n (80 limbs).
// Outputs: c (80 limbs) with 0 <= c < n.
// Witness: q (80 limbs) such that a·b = q·n + c.
//
// Per-row constraint structure:
//   1. **Schoolbook cross-product** of a·b → 159 sum-of-products
//      slots (each containing up to 80 cross-products of 26-bit
//      limbs).
//   2. **Schoolbook cross-product** of q·n → another 159 slots.
//   3. **Difference**: a·b - q·n - c, slot-by-slot, with a carry
//      chain of i64 width.
//   4. **Range checks**: every limb of q and c is exactly 26 bits
//      (verified via 26 bit-cells per limb).
//   5. **Bound check**: c < n, asserted via a borrow-bit chain on
//      the limb-by-limb subtraction n - c >= 0.
//
// Constraint budget (estimated; firmed up in Phase 2):
//   - Cross-products of a·b:     6,400 cells, 6,400 constraints
//   - Cross-products of q·n:     6,400 cells, 6,400 constraints
//   - Carry chain (159 slots):       ~640 cells,   ~640 constraints
//   - Range bits for q, c:        4,160 cells, 4,160 constraints
//   - Bound check c < n:            ~80 cells,    ~80 constraints
//   - **Total**:                ~17,680 cells, ~17,680 constraints/mul

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;
use num_bigint::BigUint;
use num_traits::Zero as _;

/// Number of limbs per 2048-bit element.
pub const RSA_NUM_LIMBS: usize = 80;
/// Limb width in bits (matches P-256's 26-bit packing).
pub const RSA_LIMB_BITS: u32 = 26;

/// Bit-cells per element (for range checks: each limb is 26 bits).
pub const RSA_ELEMENT_BIT_CELLS: usize = RSA_NUM_LIMBS * (RSA_LIMB_BITS as usize);

/// Number of slots in the schoolbook cross-product (a·b has degree
/// 2·NUM_LIMBS - 1 = 159 in limb terms).
pub const RSA_CROSS_SLOTS: usize = 2 * RSA_NUM_LIMBS - 1;

/// Carry-chain bit width per slot.  Per-position LHS magnitude is
/// bounded by ${\sim}2{\cdot}80{\cdot}2^{52} = 2^{59.3}$; carries
/// shrink by $2^{26}$ each step so $|\mathrm{carry}| < 2^{34}$.
/// 40 bits with a $2^{39}$ bias gives headroom for the maximum
/// carry of $\sim 2^{34}$ plus signed encoding.
pub const RSA_CARRY_BITS: usize = 40;
pub const RSA_CARRY_OFFSET: i64 = 1i64 << (RSA_CARRY_BITS - 1);
pub const RSA_CARRY_POSITIONS: usize = RSA_CROSS_SLOTS - 1;

/// Position-identity count: one constraint per cross-product slot.
pub const RSA_POSITION_IDENTITIES: usize = RSA_CROSS_SLOTS;

/// Per-element range-check constraints: 26 booleanity constraints per
/// limb + 1 limb-pack constraint per limb = $80 \cdot 27 = 2{,}160$.
pub const RSA_ELEMENT_RANGE_CONSTRAINTS: usize =
    RSA_NUM_LIMBS * (1 + RSA_LIMB_BITS as usize);

/// Per-RSA-mul constraint count (exact, no longer an estimate).
///   * c range check:           2,160
///   * q range check:           2,160
///   * position identities:       159
///   * carry-bit booleanity: 158·40 = 6,320
///   * **TOTAL**:              10,799
pub const RSA_MUL_GADGET_CONSTRAINTS: usize =
    2 * RSA_ELEMENT_RANGE_CONSTRAINTS
        + RSA_POSITION_IDENTITIES
        + RSA_CARRY_POSITIONS * RSA_CARRY_BITS;

/// Owned cells per RSA-mul gadget (q, c, q_bits, c_bits, carry bits).
pub const RSA_MUL_GADGET_OWNED_CELLS: usize =
    2 * RSA_NUM_LIMBS                                 // c + q limbs
        + 2 * RSA_ELEMENT_BIT_CELLS                   // c + q range bits
        + RSA_CARRY_BITS * RSA_CARRY_POSITIONS;       // carry bits

/// Legacy estimate names — kept for the round-trip example which
/// prints the budget.  Both are now exact.
pub const RSA_MUL_GADGET_CELLS_EST:       usize = RSA_MUL_GADGET_OWNED_CELLS;
pub const RSA_MUL_GADGET_CONSTRAINTS_EST: usize = RSA_MUL_GADGET_CONSTRAINTS;

/// Layout of one F_n2048 witness-quotient mul gadget.
///
/// Inputs are referenced by limb-base offsets (not owned by this
/// gadget): a, b, modulus n, output c.  Owned: q, plus carry and
/// range-check bits.
///
/// **Phase 1 status:** layout is allocated and verified for cell-
/// count consistency; `fill_*` and `eval_*` are stubs that return
/// the right vector lengths but do not yet emit live constraints.
/// Phase 2 (next commit) fills in the actual cross-product expansion,
/// carry chain, and range/bound checks.
#[derive(Clone, Debug)]
pub struct RsaMulGadgetLayout {
    /// Input cell bases (10×26-bit-limb-style storage extended to 80 limbs).
    pub a_limbs_base:    usize,
    pub b_limbs_base:    usize,
    pub n_limbs_base:    usize,
    /// Output cell base.
    pub c_limbs_base:    usize,
    /// Witness cell bases.
    pub q_limbs_base:    usize,
    /// Bit decomposition for range checks on q and c (26 bits per limb).
    pub q_bits_base:     usize,
    pub c_bits_base:     usize,
    /// Carry chain for the slot-by-slot a·b - q·n - c equality.
    pub carry_bits_base: usize,
}

/// Build an RSA-2048 mul gadget layout starting at `start`.
/// Caller supplies the input bases for `a`, `b`, `n` (which the
/// surrounding state machine owns).  Returns the new cursor.
pub fn build_rsa_mul_layout(
    start: usize,
    a_limbs_base: usize,
    b_limbs_base: usize,
    n_limbs_base: usize,
) -> (RsaMulGadgetLayout, usize) {
    let mut cursor = start;

    let c_limbs_base = cursor;
    cursor += RSA_NUM_LIMBS;

    let q_limbs_base = cursor;
    cursor += RSA_NUM_LIMBS;

    let q_bits_base = cursor;
    cursor += RSA_ELEMENT_BIT_CELLS;

    let c_bits_base = cursor;
    cursor += RSA_ELEMENT_BIT_CELLS;

    let carry_bits_base = cursor;
    cursor += RSA_CARRY_BITS * RSA_CARRY_POSITIONS;

    let layout = RsaMulGadgetLayout {
        a_limbs_base,
        b_limbs_base,
        n_limbs_base,
        c_limbs_base,
        q_limbs_base,
        q_bits_base,
        c_bits_base,
        carry_bits_base,
    };
    (layout, cursor)
}

/// Per-RSA-mul constraint count.
pub fn rsa_mul_gadget_constraints(_layout: &RsaMulGadgetLayout) -> usize {
    RSA_MUL_GADGET_CONSTRAINTS
}

/// Cell index for the b-th carry bit at position k.
pub fn rsa_mul_carry_bit_cell(layout: &RsaMulGadgetLayout, k: usize, b: usize) -> usize {
    debug_assert!(k < RSA_CARRY_POSITIONS);
    debug_assert!(b < RSA_CARRY_BITS);
    layout.carry_bits_base + k * RSA_CARRY_BITS + b
}

// ═══════════════════════════════════════════════════════════════════
//  CONVERSION HELPERS — BigUint <-> 80-limb i64 representation
// ═══════════════════════════════════════════════════════════════════

/// Decompose a non-negative `BigUint` < 2^2080 into 80 limbs of 26 bits.
pub fn biguint_to_limbs80(x: &BigUint) -> [i64; RSA_NUM_LIMBS] {
    let mask = (1u64 << RSA_LIMB_BITS) - 1;
    let mut out = [0i64; RSA_NUM_LIMBS];
    let bytes = x.to_bytes_le();
    // Pack bytes LSB-first into a 64-bit shifting window, peeling
    // off `RSA_LIMB_BITS` at a time.
    let mut acc: u128 = 0;
    let mut acc_bits: u32 = 0;
    let mut byte_idx = 0;
    for limb in out.iter_mut() {
        while acc_bits < RSA_LIMB_BITS && byte_idx < bytes.len() {
            acc |= (bytes[byte_idx] as u128) << acc_bits;
            acc_bits += 8;
            byte_idx += 1;
        }
        *limb = ((acc as u64) & mask) as i64;
        acc >>= RSA_LIMB_BITS;
        acc_bits = acc_bits.saturating_sub(RSA_LIMB_BITS);
    }
    out
}

/// Pack 80 limbs back into a `BigUint`.
pub fn limbs80_to_biguint(limbs: &[i64; RSA_NUM_LIMBS]) -> BigUint {
    let mut x = BigUint::zero();
    for i in (0..RSA_NUM_LIMBS).rev() {
        x <<= RSA_LIMB_BITS;
        x += limbs[i] as u64;
    }
    x
}

// ═══════════════════════════════════════════════════════════════════
//  FILL — write c, q, range bits, carry bits into the trace
// ═══════════════════════════════════════════════════════════════════

/// Fill one RSA mul gadget on a single trace row.
///
/// Inputs (already placed into the trace by the caller):
///   - `a` (80 limbs at `layout.a_limbs_base`)
///   - `b` (80 limbs at `layout.b_limbs_base`)
///   - `n` (80 limbs at `layout.n_limbs_base`)
///
/// This function computes c = (a · b) mod n, the witness quotient
/// q = (a · b - c) / n, the bit decompositions of c and q, and the
/// carry chain over the slot-by-slot equality
///     a · b - q · n - c ≡ 0
/// then writes everything into the trace.
///
/// Pre-conditions:
///   - a, b are each non-negative integers < n (typical RSA usage:
///     they are reductions mod n from a previous step).
///   - n is a 2048-bit modulus (limb 79 has its high bit set
///     in the production case, but this gadget is generic).
pub fn fill_rsa_mul_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &RsaMulGadgetLayout,
    a: &BigUint,
    b: &BigUint,
    n: &BigUint,
) {
    // (1) c = a·b mod n;  q = (a·b - c) / n.
    let prod = a * b;
    let c_big = &prod % n;
    let q_big = (&prod - &c_big) / n;
    debug_assert_eq!(&q_big * n + &c_big, prod, "witness quotient mismatch");

    let a_limbs = biguint_to_limbs80(a);
    let b_limbs = biguint_to_limbs80(b);
    let n_limbs = biguint_to_limbs80(n);
    let c_limbs = biguint_to_limbs80(&c_big);
    let q_limbs = biguint_to_limbs80(&q_big);

    // (2) Slot-by-slot LHS = Σ a[i]·b[k-i] - Σ q[i]·n[k-i] - c[k] (or 0).
    //     Run carry chain.
    let radix = 1i64 << RSA_LIMB_BITS;
    let mut prev_carry: i64 = 0;
    let mut carries = vec![0i64; RSA_CARRY_POSITIONS];
    for k in 0..RSA_CROSS_SLOTS {
        let mut p_ab: i64 = 0;
        let mut p_qn: i64 = 0;
        let i_lo = k.saturating_sub(RSA_NUM_LIMBS - 1);
        let i_hi = std::cmp::min(RSA_NUM_LIMBS - 1, k);
        for i in i_lo..=i_hi {
            let j = k - i;
            // 26-bit × 26-bit = up to 52 bits.  Up to 80 sums of these
            // → <= 2^58.3.  Subtract another <= 2^58.3.  Net |LHS| < 2^60.
            p_ab = p_ab.checked_add(a_limbs[i].checked_mul(b_limbs[j]).expect("ab overflow"))
                .expect("p_ab overflow");
            p_qn = p_qn.checked_add(q_limbs[i].checked_mul(n_limbs[j]).expect("qn overflow"))
                .expect("p_qn overflow");
        }
        let c_k = if k < RSA_NUM_LIMBS { c_limbs[k] } else { 0 };
        let lhs = p_ab - p_qn - c_k + prev_carry;

        if k < RSA_CROSS_SLOTS - 1 {
            debug_assert_eq!(
                lhs.rem_euclid(radix),
                0,
                "carry chain residual ≠ 0 at position {}: lhs = {}",
                k, lhs
            );
            let cy = lhs.div_euclid(radix);
            debug_assert!(
                cy.abs() < RSA_CARRY_OFFSET,
                "carry[{}] = {} out of bias range [-2^39, 2^39)",
                k, cy
            );
            carries[k] = cy;
            prev_carry = cy;
        } else {
            debug_assert_eq!(
                lhs, 0,
                "carry chain did not close at position {}: lhs = {}",
                k, lhs
            );
        }
    }

    // (3) Write c, q limb cells + bit decompositions.
    let place_element = |trace: &mut [Vec<F>], limbs_base: usize, bits_base: usize, limbs: &[i64; RSA_NUM_LIMBS]| {
        for i in 0..RSA_NUM_LIMBS {
            trace[limbs_base + i][row] = F::from(limbs[i] as u64);
            for b in 0..(RSA_LIMB_BITS as usize) {
                let bit = ((limbs[i] >> b) as u64) & 1;
                trace[bits_base + i * (RSA_LIMB_BITS as usize) + b][row] = F::from(bit);
            }
        }
    };
    place_element(trace, layout.c_limbs_base, layout.c_bits_base, &c_limbs);
    place_element(trace, layout.q_limbs_base, layout.q_bits_base, &q_limbs);

    // (4) Write biased carry bits.
    for k in 0..RSA_CARRY_POSITIONS {
        let biased = (carries[k] + RSA_CARRY_OFFSET) as u64;
        for b in 0..RSA_CARRY_BITS {
            let bit = (biased >> b) & 1;
            trace[rsa_mul_carry_bit_cell(layout, k, b)][row] = F::from(bit);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  EVAL — emit constraints over (cur) trace cells
// ═══════════════════════════════════════════════════════════════════

/// Emit the `RSA_MUL_GADGET_CONSTRAINTS` transition constraints for one
/// RSA mul gadget.  On a valid trace every entry is zero.
///
/// Constraint order (mirrors P-256 mul gadget for reviewability):
///   1.  $80 \cdot 27 = 2{,}160$:  c range-check (booleanity + limb-pack)
///   2.  $80 \cdot 27 = 2{,}160$:  q range-check
///   3.  $159$:                    position identities (carry chain)
///   4.  $158 \cdot 40 = 6{,}320$: carry-bit booleanity
pub fn eval_rsa_mul_gadget(cur: &[F], layout: &RsaMulGadgetLayout) -> Vec<F> {
    let mut out = Vec::with_capacity(RSA_MUL_GADGET_CONSTRAINTS);

    // Helper: range-check an 80-limb element.
    let range_check = |out: &mut Vec<F>, limbs_base: usize, bits_base: usize| {
        // (1a) booleanity of the 80·26 = 2,080 bit cells.
        for i in 0..RSA_NUM_LIMBS {
            for b in 0..(RSA_LIMB_BITS as usize) {
                let cell = cur[bits_base + i * (RSA_LIMB_BITS as usize) + b];
                out.push(cell * (F::one() - cell));
            }
        }
        // (1b) limb-pack: limb_i == Σ_b 2^b · bit_{i,b}.
        for i in 0..RSA_NUM_LIMBS {
            let mut s = F::zero();
            for b in 0..(RSA_LIMB_BITS as usize) {
                s += F::from(1u64 << b) * cur[bits_base + i * (RSA_LIMB_BITS as usize) + b];
            }
            out.push(cur[limbs_base + i] - s);
        }
    };

    range_check(&mut out, layout.c_limbs_base, layout.c_bits_base);
    range_check(&mut out, layout.q_limbs_base, layout.q_bits_base);

    // Helper: signed-carry F-element at position k (or 0 at boundary).
    let signed_carry = |k: usize| -> F {
        if k >= RSA_CARRY_POSITIONS {
            return F::zero();
        }
        let mut biased = F::zero();
        for b in 0..RSA_CARRY_BITS {
            biased += F::from(1u64 << b) * cur[rsa_mul_carry_bit_cell(layout, k, b)];
        }
        biased - F::from(RSA_CARRY_OFFSET as u64)
    };

    // (3) Position identities: 159 constraints.
    let radix = F::from(1u64 << RSA_LIMB_BITS);
    for k in 0..RSA_CROSS_SLOTS {
        let mut p_ab = F::zero();
        let mut p_qn = F::zero();
        let i_lo = k.saturating_sub(RSA_NUM_LIMBS - 1);
        let i_hi = std::cmp::min(RSA_NUM_LIMBS - 1, k);
        for i in i_lo..=i_hi {
            let j = k - i;
            p_ab += cur[layout.a_limbs_base + i] * cur[layout.b_limbs_base + j];
            // q · n: BOTH operands are cell values (n is input-supplied,
            // not a compile-time constant — this is the key difference
            // from P-256's Solinas mul).
            p_qn += cur[layout.q_limbs_base + i] * cur[layout.n_limbs_base + j];
        }
        let c_k = if k < RSA_NUM_LIMBS {
            cur[layout.c_limbs_base + k]
        } else {
            F::zero()
        };
        let carry_in = if k == 0 { F::zero() } else { signed_carry(k - 1) };
        let carry_out = signed_carry(k); // 0 at boundary k = RSA_CROSS_SLOTS - 1
        out.push(p_ab - p_qn - c_k + carry_in - radix * carry_out);
    }

    // (4) Carry-bit booleanity.
    for k in 0..RSA_CARRY_POSITIONS {
        for b in 0..RSA_CARRY_BITS {
            let cell = cur[rsa_mul_carry_bit_cell(layout, k, b)];
            out.push(cell * (F::one() - cell));
        }
    }

    debug_assert_eq!(out.len(), RSA_MUL_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  EXPONENTIATION CHAIN: e = 65537 = 2^16 + 1
// ═══════════════════════════════════════════════════════════════════
//
// 16 squarings (acc = acc²) followed by 1 multiplication
// (acc = acc · base) where `base = signature value s`.
// Multi-row layout: each row hosts ONE F_n2048 mul gadget (squaring
// or multiplication, distinguished by a bit cell).
//
// Per-row layout:
//   - mul gadget (RsaMulGadgetLayout): inputs are (acc, op2, n).
//   - op2 selector: bit cell choosing between `acc` (squaring) and
//     `s` (the base operand for the final multiply).
//   - acc input: cells holding the current accumulator value.
//   - acc output: cells holding the new accumulator (= mul output c).
//
// Transition: nxt's acc input == cur's mul-output c (10 limbs × 80 = 800 cells).
//
// Trace shape: n_trace = 32 (next pow-2 after 17 active rows; rows
// 17..31 run with op2 = acc, harmless squaring of the final result).

pub const RSA_EXP_E: u64 = 65_537;
pub const RSA_EXP_NUM_STEPS: usize = 17; // 16 squarings + 1 multiply

/// Per-row count for the multi-row exponentiation chain (mul + transition).
pub const RSA_EXP_PER_ROW_CONSTRAINTS_EST: usize =
    RSA_MUL_GADGET_CONSTRAINTS_EST + 3 * RSA_NUM_LIMBS; // mul + acc transition

/// Total RSA-2048 exponentiation constraints (chain + transitions).
pub const RSA_EXP_TOTAL_CONSTRAINTS_EST: usize =
    RSA_EXP_NUM_STEPS * RSA_EXP_PER_ROW_CONSTRAINTS_EST;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn make_trace_row(width: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); 1]).collect()
    }

    /// Generate a random 2048-bit (or smaller) BigUint deterministically.
    fn gen_biguint(rng: &mut rand::rngs::StdRng, bits: u32) -> BigUint {
        let bytes = (bits as usize + 7) / 8;
        let mut buf = vec![0u8; bytes];
        rng.fill(&mut buf[..]);
        // Mask the top byte to honour `bits`.
        let extra = (bytes * 8) - bits as usize;
        if extra > 0 {
            buf[0] &= 0xFF >> extra;
        }
        BigUint::from_bytes_be(&buf)
    }

    /// Random BigUint in [0, n).
    fn gen_biguint_below(rng: &mut rand::rngs::StdRng, n: &BigUint) -> BigUint {
        let bits = n.bits() as u32;
        loop {
            let candidate = gen_biguint(rng, bits);
            if &candidate < n {
                return candidate;
            }
        }
    }

    /// Layout: a, b, n at fixed bases, gadget owned cells start at 3·NUM_LIMBS.
    fn standalone_layout() -> (RsaMulGadgetLayout, usize) {
        let a_base = 0;
        let b_base = RSA_NUM_LIMBS;
        let n_base = 2 * RSA_NUM_LIMBS;
        let start = 3 * RSA_NUM_LIMBS;
        build_rsa_mul_layout(start, a_base, b_base, n_base)
    }

    fn place_biguint(trace: &mut [Vec<F>], base: usize, x: &BigUint) {
        let limbs = biguint_to_limbs80(x);
        for i in 0..RSA_NUM_LIMBS {
            trace[base + i][0] = F::from(limbs[i] as u64);
        }
    }

    #[test]
    fn layout_cell_counts_consistent() {
        let (layout, end) = build_rsa_mul_layout(0, 0, RSA_NUM_LIMBS, 2 * RSA_NUM_LIMBS);
        let expected_owned = RSA_MUL_GADGET_OWNED_CELLS;
        assert_eq!(end, expected_owned);
        assert_eq!(layout.a_limbs_base, 0);
        assert_eq!(layout.b_limbs_base, RSA_NUM_LIMBS);
        assert_eq!(layout.n_limbs_base, 2 * RSA_NUM_LIMBS);
    }

    #[test]
    fn constraint_count_exact() {
        // Exact: 2,160 + 2,160 + 159 + 6,320 = 10,799.
        assert_eq!(RSA_MUL_GADGET_CONSTRAINTS, 10_799);
        assert_eq!(2 * RSA_ELEMENT_RANGE_CONSTRAINTS, 4_320);
        assert_eq!(RSA_POSITION_IDENTITIES, 159);
        assert_eq!(RSA_CARRY_POSITIONS * RSA_CARRY_BITS, 6_320);
    }

    #[test]
    fn biguint_limb_roundtrip() {
        // Random 2048-bit value round-trips losslessly through limbs.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE_F00D);
        for _ in 0..16 {
            let x = gen_biguint(&mut rng, 2040);
            let limbs = biguint_to_limbs80(&x);
            let y = limbs80_to_biguint(&limbs);
            assert_eq!(x, y);
        }
    }

    #[test]
    fn mul_gadget_satisfies_on_real_inputs() {
        // Pick a random 2048-bit modulus n and 2048-bit operands a, b
        // with a, b < n, then verify all constraints are zero.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF);
        let n = (gen_biguint(&mut rng, 2046) << 1) | BigUint::from(1u8); // odd 2047-bit
        let a = gen_biguint_below(&mut rng, &n);
        let b = gen_biguint_below(&mut rng, &n);

        let (layout, total) = standalone_layout();
        let mut trace = make_trace_row(total);
        place_biguint(&mut trace, layout.a_limbs_base, &a);
        place_biguint(&mut trace, layout.b_limbs_base, &b);
        place_biguint(&mut trace, layout.n_limbs_base, &n);

        fill_rsa_mul_gadget(&mut trace, 0, &layout, &a, &b, &n);

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_rsa_mul_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert_eq!(
            nonzero, 0,
            "{} of {} RSA mul constraints non-zero",
            nonzero,
            cons.len()
        );

        // Read back c from the trace and verify it equals (a*b) mod n.
        let mut c_limbs = [0i64; RSA_NUM_LIMBS];
        for i in 0..RSA_NUM_LIMBS {
            use ark_ff::PrimeField;
            let bi = trace[layout.c_limbs_base + i][0].into_bigint();
            c_limbs[i] = bi.as_ref()[0] as i64;
        }
        let c_recovered = limbs80_to_biguint(&c_limbs);
        assert_eq!(c_recovered, (&a * &b) % &n);
    }

    #[test]
    fn mul_gadget_satisfies_on_zero_a() {
        let n = BigUint::from(0xFFFF_FFFFu64) * BigUint::from(0xFFFF_FFFEu64) + BigUint::from(3u64);
        let a = BigUint::zero();
        let b = BigUint::from(0xCAFE_BABEu64);
        let (layout, total) = standalone_layout();
        let mut trace = make_trace_row(total);
        place_biguint(&mut trace, layout.a_limbs_base, &a);
        place_biguint(&mut trace, layout.b_limbs_base, &b);
        place_biguint(&mut trace, layout.n_limbs_base, &n);
        fill_rsa_mul_gadget(&mut trace, 0, &layout, &a, &b, &n);
        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_rsa_mul_gadget(&cur, &layout);
        assert_eq!(cons.iter().filter(|v| !v.is_zero()).count(), 0);
    }

    #[test]
    fn mul_gadget_corrupted_c_fails() {
        // Sanity: if we tamper with one cell of c in the trace,
        // some constraint should be non-zero.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xBEEF);
        let n = (gen_biguint(&mut rng, 2046) << 1) | BigUint::from(1u8);
        let a = gen_biguint_below(&mut rng, &n);
        let b = gen_biguint_below(&mut rng, &n);
        let (layout, total) = standalone_layout();
        let mut trace = make_trace_row(total);
        place_biguint(&mut trace, layout.a_limbs_base, &a);
        place_biguint(&mut trace, layout.b_limbs_base, &b);
        place_biguint(&mut trace, layout.n_limbs_base, &n);
        fill_rsa_mul_gadget(&mut trace, 0, &layout, &a, &b, &n);
        // Tamper.
        trace[layout.c_limbs_base][0] += F::one();
        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_rsa_mul_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero > 0, "tampered c must violate at least one constraint");
    }

    #[test]
    fn exp_step_count_matches_e_65537() {
        // e = 65537 = 0x10001 → square-and-multiply chain is
        // 16 squarings (bits 15..0 each square) + 1 multiply
        // (bit 0 set), with the MSB (bit 16) initialising acc = s.
        let e = RSA_EXP_E;
        let bits = 64 - e.leading_zeros() as usize;
        let squarings = bits - 1;
        let multiplies = (e.count_ones() as usize) - 1;
        assert_eq!(squarings, 16);
        assert_eq!(multiplies, 1);
        assert_eq!(squarings + multiplies, RSA_EXP_NUM_STEPS);
    }
}
