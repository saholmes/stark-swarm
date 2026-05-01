// p256_scalar_air.rs — AIR-level layout for F_n arithmetic on NIST P-256.
//
// In-circuit counterpart to `p256_scalar.rs` (the native reference).
// This module supplies the scalar-field gadgets needed for ECDSA-P256
// verification:
//
//   * scalar_mul     — c = a · b (mod n)             [the workhorse]
//   * scalar_freeze  — bring tight input to canonical [for output normalisation]
//
// Modulus-INDEPENDENT gadgets are reused from `p256_field_air`:
//
//   * Element layout + range check  (same 10×26 cell shape)
//   * Add gadget                    (no mod-reduction; just sum + range check)
//   * Cond-select gadget            (just multiplexer + sel booleanity)
//
// Modulus-SPECIFIC gadgets are mirrored here with N_LIMBS_TIGHT
// substituted for P_LIMBS_TIGHT and N_BIGUINT for the Fp BigUint.
//
// ─────────────────────────────────────────────────────────────────
// SHARED LAYOUT WITH FIELD AIR
// ─────────────────────────────────────────────────────────────────
//
// Both F_p and F_n use the same uniform 10×26-bit limb layout, so a
// scalar element block has the same `ELEMENT_CELLS = 270` size and
// the same `ELEMENT_CONSTRAINTS = 270` range-check budget as a base-
// field element.  Composing AIRs (e.g. the top-level ECDSA verify
// AIR) can therefore mix scalar and base-field elements freely
// without per-row layout divergence.
//
// ─────────────────────────────────────────────────────────────────
// MUL GADGET BUDGET (parallel to p256_field_air::MUL_GADGET_*)
// ─────────────────────────────────────────────────────────────────
//
// Identical structure: 10×10 schoolbook + 18-element signed-carry
// chain + witness quotient q over the 19 schoolbook positions, with
// n substituted for p.  Same cell budget (1188) and constraint
// budget (1207).
//
// Why share constants?  Because the witness-q approach is
// parameterised purely by the modulus's tight-form limbs; the
// soundness magnitude analysis, carry-bit budget, and constraint
// count are all independent of which prime the modulus is.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;

use crate::p256_field::{LIMB_BITS, NUM_LIMBS};
use crate::p256_field_air::{
    MUL_CARRY_BITS, MUL_CARRY_OFFSET, MUL_CARRY_POSITIONS,
    MUL_GADGET_CONSTRAINTS, MUL_GADGET_OWNED_CELLS, MUL_SCHOOLBOOK_POSITIONS,
};
use crate::p256_scalar::{N_BIGUINT, N_LIMBS_TIGHT, ScalarElement};

// ═══════════════════════════════════════════════════════════════════
//  SCALAR-MUL GADGET (= MUL GADGET with modulus = n)
// ═══════════════════════════════════════════════════════════════════

/// Cells owned by a scalar-mul gadget.  Identical to the base-field
/// mul gadget's count.
pub const SCALAR_MUL_GADGET_OWNED_CELLS: usize = MUL_GADGET_OWNED_CELLS;

/// Constraints emitted per scalar-mul gadget.  Identical structure.
pub const SCALAR_MUL_GADGET_CONSTRAINTS: usize = MUL_GADGET_CONSTRAINTS;

/// Cell-offset descriptor for one scalar-mul-gadget instance.
///
/// Field semantics are identical to `p256_field_air::MulGadgetLayout`.
/// We use a separate struct (rather than a type alias) to make scalar
/// vs base-field operations type-distinct in the top-level verify AIR.
#[derive(Clone, Copy, Debug)]
pub struct ScalarMulGadgetLayout {
    pub a_limbs_base: usize,
    pub b_limbs_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base: usize,
    pub q_limbs_base: usize,
    pub q_bits_base: usize,
    pub carry_bits_base: usize,
}

#[inline]
pub fn scalar_mul_carry_bit_cell(
    layout: &ScalarMulGadgetLayout,
    k: usize,
    b: usize,
) -> usize {
    debug_assert!(k < MUL_CARRY_POSITIONS);
    debug_assert!(b < MUL_CARRY_BITS);
    layout.carry_bits_base + k * MUL_CARRY_BITS + b
}

/// Place a tight-form ScalarElement at given limb / bit bases.
fn place_scalar_split(
    trace: &mut [Vec<F>],
    row: usize,
    limbs_base: usize,
    bits_base: usize,
    fe: &ScalarElement,
) {
    for i in 0..NUM_LIMBS {
        let limb = fe.limbs[i];
        debug_assert!(
            limb >= 0 && (limb as u64) < (1u64 << LIMB_BITS),
            "scalar limb {} out of tight range: {}",
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

/// Read a `ScalarElement` from the trace.
pub fn read_scalar(trace: &[Vec<F>], row: usize, base: usize) -> ScalarElement {
    use ark_ff::PrimeField;
    let mut limbs = [0i64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        let v: F = trace[base + i][row];
        let bi = v.into_bigint();
        let u: u64 = bi.as_ref()[0];
        limbs[i] = u as i64;
    }
    ScalarElement { limbs }
}

/// Compute q = (a · b − c) / n via BigUint long division.
///
/// Used at proving time only.  Uses RAW limbs-to-BigUint conversion
/// (no freeze) so q is consistent with the actual cell-value integers,
/// which may be non-canonical when inputs come from upstream gadgets.
fn compute_scalar_quotient(
    fe_a: &ScalarElement,
    fe_b: &ScalarElement,
    fe_c: &ScalarElement,
) -> ScalarElement {
    use num_bigint::BigUint;
    use num_traits::Zero;

    fn se_to_biguint_raw(fe: &ScalarElement) -> BigUint {
        let mut acc = BigUint::zero();
        for i in 0..NUM_LIMBS {
            debug_assert!(fe.limbs[i] >= 0, "raw: negative limb");
            let term = BigUint::from(fe.limbs[i] as u64) << (LIMB_BITS as usize * i);
            acc += term;
        }
        acc
    }
    let a_int = se_to_biguint_raw(fe_a);
    let b_int = se_to_biguint_raw(fe_b);
    let c_int = se_to_biguint_raw(fe_c);
    let prod = &a_int * &b_int;
    debug_assert!(
        prod >= c_int,
        "compute_scalar_quotient: a·b < c, cannot compute q"
    );
    let q_int = (&prod - &c_int) / &*N_BIGUINT;
    debug_assert_eq!(
        &q_int * &*N_BIGUINT + &c_int,
        prod,
        "compute_scalar_quotient: a·b ≠ q·n + c"
    );
    let q_bytes = q_int.to_bytes_be();
    let mut padded = [0u8; 32];
    padded[32 - q_bytes.len()..].copy_from_slice(&q_bytes);
    ScalarElement::from_be_bytes_unchecked(&padded)
}

/// Fill the gadget-owned cells for c = (a · b) mod n.
pub fn fill_scalar_mul_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &ScalarMulGadgetLayout,
    fe_a: &ScalarElement,
    fe_b: &ScalarElement,
) {
    // (1) c = a · b mod n in canonical form.
    let mut c = fe_a.mul(fe_b);
    c.freeze();
    // (2) q = (a · b − c) / n.
    let q = compute_scalar_quotient(fe_a, fe_b, &c);

    // (3) Carry chain over 19 positions.
    let n_limbs = &*N_LIMBS_TIGHT;
    let mut carries = [0i64; MUL_CARRY_POSITIONS];
    let radix = 1i64 << LIMB_BITS;
    let mut prev: i64 = 0;
    for k in 0..MUL_SCHOOLBOOK_POSITIONS {
        let mut p_ab: i64 = 0;
        let mut p_qn: i64 = 0;
        let i_lo = k.saturating_sub(NUM_LIMBS - 1);
        let i_hi = std::cmp::min(NUM_LIMBS - 1, k);
        for i in i_lo..=i_hi {
            let j = k - i;
            p_ab += fe_a.limbs[i] * fe_b.limbs[j];
            p_qn += q.limbs[i] * n_limbs[j];
        }
        let c_k = if k < NUM_LIMBS { c.limbs[k] } else { 0 };
        let lhs = p_ab - p_qn - c_k + prev;
        if k < MUL_SCHOOLBOOK_POSITIONS - 1 {
            debug_assert_eq!(
                lhs.rem_euclid(radix),
                0,
                "scalar mul carry chain residual ≠ 0 at position {}",
                k
            );
            let cy = lhs.div_euclid(radix);
            debug_assert!(
                cy.abs() < MUL_CARRY_OFFSET,
                "scalar carry[{}] = {} out of bias range",
                k,
                cy
            );
            carries[k] = cy;
            prev = cy;
        } else {
            debug_assert_eq!(
                lhs, 0,
                "scalar mul chain did not close at position 18"
            );
        }
    }

    // (4) Write trace cells.
    place_scalar_split(trace, row, layout.c_limbs_base, layout.c_bits_base, &c);
    place_scalar_split(trace, row, layout.q_limbs_base, layout.q_bits_base, &q);
    for k in 0..MUL_CARRY_POSITIONS {
        let biased = (carries[k] + MUL_CARRY_OFFSET) as u64;
        for b in 0..MUL_CARRY_BITS {
            let bit = (biased >> b) & 1;
            trace[scalar_mul_carry_bit_cell(layout, k, b)][row] = F::from(bit);
        }
    }
}

/// Emit the `SCALAR_MUL_GADGET_CONSTRAINTS` transition constraints.
pub fn eval_scalar_mul_gadget(
    cur: &[F],
    layout: &ScalarMulGadgetLayout,
) -> Vec<F> {
    let n_limbs = &*N_LIMBS_TIGHT;
    let mut out = Vec::with_capacity(SCALAR_MUL_GADGET_CONSTRAINTS);

    // Range-check helper.
    let range_check = |out: &mut Vec<F>, limbs_base: usize, bits_base: usize| {
        for i in 0..NUM_LIMBS {
            for b in 0..LIMB_BITS as usize {
                let cell = cur[bits_base + i * (LIMB_BITS as usize) + b];
                out.push(cell * (F::one() - cell));
            }
        }
        for i in 0..NUM_LIMBS {
            let mut s = F::zero();
            for b in 0..LIMB_BITS as usize {
                s += F::from(1u64 << b)
                    * cur[bits_base + i * (LIMB_BITS as usize) + b];
            }
            out.push(cur[limbs_base + i] - s);
        }
    };
    range_check(&mut out, layout.c_limbs_base, layout.c_bits_base);
    range_check(&mut out, layout.q_limbs_base, layout.q_bits_base);

    let signed_carry = |k: usize| -> F {
        if k >= MUL_CARRY_POSITIONS {
            return F::zero();
        }
        let mut biased = F::zero();
        for b in 0..MUL_CARRY_BITS {
            biased += F::from(1u64 << b)
                * cur[scalar_mul_carry_bit_cell(layout, k, b)];
        }
        biased - F::from(MUL_CARRY_OFFSET as u64)
    };

    // Position identities.
    let radix = F::from(1u64 << LIMB_BITS);
    for k in 0..MUL_SCHOOLBOOK_POSITIONS {
        let mut p_ab = F::zero();
        let mut p_qn = F::zero();
        let i_lo = k.saturating_sub(NUM_LIMBS - 1);
        let i_hi = std::cmp::min(NUM_LIMBS - 1, k);
        for i in i_lo..=i_hi {
            let j = k - i;
            p_ab += cur[layout.a_limbs_base + i] * cur[layout.b_limbs_base + j];
            p_qn += cur[layout.q_limbs_base + i] * F::from(n_limbs[j] as u64);
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
        let carry_out = signed_carry(k);
        out.push(p_ab - p_qn - c_k + carry_in - radix * carry_out);
    }

    // Carry-bit booleanity.
    for k in 0..MUL_CARRY_POSITIONS {
        for b in 0..MUL_CARRY_BITS {
            let cell = cur[scalar_mul_carry_bit_cell(layout, k, b)];
            out.push(cell * (F::one() - cell));
        }
    }

    debug_assert_eq!(out.len(), SCALAR_MUL_GADGET_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  SCALAR-FREEZE GADGET (= FREEZE GADGET with modulus = n)
// ═══════════════════════════════════════════════════════════════════
//
// Brings a tight-form F_n input (integer in [0, 2n)) to canonical
// form (integer in [0, n)).  Identical structure to the Fp freeze
// gadget (`p256_field_air::FreezeGadgetLayout`) with `N_LIMBS_TIGHT`
// substituted for `P_LIMBS_TIGHT`.
//
// Used at the end of ECDSA verification to canonicalise the result
// of `R.x mod n` before equality comparison with the signature `r`.
//
// Same cell budget (560) and constraint budget (591) as Fp freeze.

/// Cells owned by a scalar-freeze gadget.
pub const SCALAR_FREEZE_GADGET_OWNED_CELLS: usize =
    crate::p256_field_air::FREEZE_GADGET_OWNED_CELLS;

/// Constraints emitted per scalar-freeze gadget.
pub const SCALAR_FREEZE_GADGET_CONSTRAINTS: usize =
    crate::p256_field_air::FREEZE_GADGET_CONSTRAINTS;

/// Cell-offset descriptor for one scalar-freeze-gadget instance.
/// Same shape as `p256_field_air::FreezeGadgetLayout`.
#[derive(Clone, Copy, Debug)]
pub struct ScalarFreezeGadgetLayout {
    pub a_limbs_base: usize,
    pub diff_limbs_base: usize,
    pub diff_bits_base: usize,
    pub c_limbs_base: usize,
    pub c_bits_base: usize,
    pub c_pos_base: usize,
    pub c_neg_base: usize,
}

/// Fill the gadget-owned cells for c = canonical-form(a) (mod n).
pub fn fill_scalar_freeze_gadget(
    trace: &mut [Vec<F>],
    row: usize,
    layout: &ScalarFreezeGadgetLayout,
    fe_a: &ScalarElement,
) {
    let n_limbs = &*N_LIMBS_TIGHT;
    let mut diff_limbs = [0i64; NUM_LIMBS];
    let mut carries = [0i64; NUM_LIMBS];
    let mut prev = 0i64;
    let radix = 1i64 << LIMB_BITS;
    for k in 0..NUM_LIMBS {
        let lhs = fe_a.limbs[k] - n_limbs[k] + prev;
        diff_limbs[k] = lhs.rem_euclid(radix);
        carries[k] = lhs.div_euclid(radix);
        debug_assert!(
            carries[k].abs() <= 1,
            "scalar freeze chain carry at limb {} out of range",
            k
        );
        prev = carries[k];
    }
    debug_assert!(
        carries[NUM_LIMBS - 1] == 0 || carries[NUM_LIMBS - 1] == -1,
        "scalar freeze: input not in [0, 2n)"
    );

    // Multiplexer: c = (carry[9] = -1) ? a : diff.
    let c_neg_9 = if carries[NUM_LIMBS - 1] == -1 {
        1i64
    } else {
        0i64
    };
    let mut c_limbs = [0i64; NUM_LIMBS];
    for k in 0..NUM_LIMBS {
        c_limbs[k] = if c_neg_9 == 1 {
            fe_a.limbs[k]
        } else {
            diff_limbs[k]
        };
    }

    // Write trace.
    let diff_se = ScalarElement { limbs: diff_limbs };
    let c_se = ScalarElement { limbs: c_limbs };
    place_scalar_split(
        trace,
        row,
        layout.diff_limbs_base,
        layout.diff_bits_base,
        &diff_se,
    );
    place_scalar_split(trace, row, layout.c_limbs_base, layout.c_bits_base, &c_se);

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

/// Emit the scalar-freeze gadget constraints.
pub fn eval_scalar_freeze_gadget(
    cur: &[F],
    layout: &ScalarFreezeGadgetLayout,
) -> Vec<F> {
    let n_limbs = &*N_LIMBS_TIGHT;
    let mut out = Vec::with_capacity(SCALAR_FREEZE_GADGET_CONSTRAINTS);

    // Range check on diff.
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

    // Range check on c.
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

    // Chain identities: a[k] − n_limb[k] − diff[k] + carry_in[k] − carry_out[k] · 2^26 = 0.
    let radix = F::from(1u64 << LIMB_BITS);
    let net_out = |k: usize| -> F {
        cur[layout.c_pos_base + k] - cur[layout.c_neg_base + k]
    };
    for k in 0..NUM_LIMBS {
        let a_k = cur[layout.a_limbs_base + k];
        let n_k = F::from(n_limbs[k] as u64);
        let diff_k = cur[layout.diff_limbs_base + k];
        let carry_in = if k == 0 { F::zero() } else { net_out(k - 1) };
        out.push(a_k - n_k - diff_k + carry_in - radix * net_out(k));
    }

    // C_pos / C_neg booleanity.
    for k in 0..NUM_LIMBS {
        let cp = cur[layout.c_pos_base + k];
        out.push(cp * (F::one() - cp));
    }
    for k in 0..NUM_LIMBS {
        let cn = cur[layout.c_neg_base + k];
        out.push(cn * (F::one() - cn));
    }

    // Mutual exclusion.
    for k in 0..NUM_LIMBS {
        let cp = cur[layout.c_pos_base + k];
        let cn = cur[layout.c_neg_base + k];
        out.push(cp * cn);
    }

    // C_pos[9] = 0.
    out.push(cur[layout.c_pos_base + NUM_LIMBS - 1]);

    // Multiplexer per limb: c[k] − diff[k] − C_neg[9] · (a[k] − diff[k]) = 0.
    let c_neg_9 = cur[layout.c_neg_base + NUM_LIMBS - 1];
    for k in 0..NUM_LIMBS {
        let a_k = cur[layout.a_limbs_base + k];
        let diff_k = cur[layout.diff_limbs_base + k];
        let c_k = cur[layout.c_limbs_base + k];
        out.push(c_k - diff_k - c_neg_9 * (a_k - diff_k));
    }

    debug_assert_eq!(out.len(), SCALAR_FREEZE_GADGET_CONSTRAINTS);
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

    fn pseudo_scalar(seed: u64) -> ScalarElement {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(i as u64 * 31)
                & 0xff) as u8;
        }
        ScalarElement::from_be_bytes(&bytes) // reduces mod n
    }

    fn standalone_scalar_mul_layout() -> (ScalarMulGadgetLayout, usize) {
        let a_limbs_base = 0;
        let b_limbs_base = NUM_LIMBS;
        let c_limbs_base = 2 * NUM_LIMBS;
        let c_bits_base = c_limbs_base + NUM_LIMBS;
        let bits_per_elem = NUM_LIMBS * (LIMB_BITS as usize);
        let q_limbs_base = c_bits_base + bits_per_elem;
        let q_bits_base = q_limbs_base + NUM_LIMBS;
        let carry_bits_base = q_bits_base + bits_per_elem;
        let total = carry_bits_base + MUL_CARRY_POSITIONS * MUL_CARRY_BITS;
        (
            ScalarMulGadgetLayout {
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

    fn assert_satisfies_scalar_mul(
        layout: &ScalarMulGadgetLayout,
        total_width: usize,
        fe_a: &ScalarElement,
        fe_b: &ScalarElement,
    ) {
        let mut trace = make_trace_row(total_width);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(fe_a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(fe_b.limbs[i] as u64);
        }
        fill_scalar_mul_gadget(&mut trace, 0, layout, fe_a, fe_b);

        let cur: Vec<F> = (0..total_width).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_mul_gadget(&cur, layout);
        assert_eq!(cons.len(), SCALAR_MUL_GADGET_CONSTRAINTS);
        for (i, v) in cons.iter().enumerate() {
            assert!(
                v.is_zero(),
                "scalar-mul-gadget constraint #{} non-zero (a={:?}, b={:?})",
                i,
                fe_a.limbs,
                fe_b.limbs
            );
        }
    }

    #[test]
    fn scalar_mul_gadget_constants_match_field_mul() {
        // The scalar mul gadget shares the field mul gadget's cell
        // and constraint budgets — only the modulus differs.
        assert_eq!(SCALAR_MUL_GADGET_OWNED_CELLS, MUL_GADGET_OWNED_CELLS);
        assert_eq!(SCALAR_MUL_GADGET_CONSTRAINTS, MUL_GADGET_CONSTRAINTS);
    }

    #[test]
    fn scalar_mul_zero_times_zero_is_zero() {
        let (layout, total) = standalone_scalar_mul_layout();
        let zero = ScalarElement::zero();
        assert_satisfies_scalar_mul(&layout, total, &zero, &zero);

        let mut trace = make_trace_row(total);
        fill_scalar_mul_gadget(&mut trace, 0, &layout, &zero, &zero);
        let c = read_scalar(&trace, 0, layout.c_limbs_base);
        assert!(c.is_zero(), "0·0 should be 0");
    }

    #[test]
    fn scalar_mul_one_times_x_is_x() {
        let (layout, total) = standalone_scalar_mul_layout();
        let one = ScalarElement::one();
        for seed in 0u64..4 {
            let x = pseudo_scalar(seed);
            assert_satisfies_scalar_mul(&layout, total, &one, &x);

            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(one.limbs[i] as u64);
                trace[layout.b_limbs_base + i][0] = F::from(x.limbs[i] as u64);
            }
            fill_scalar_mul_gadget(&mut trace, 0, &layout, &one, &x);
            let c = read_scalar(&trace, 0, layout.c_limbs_base);
            assert_eq!(c.limbs, x.limbs, "1·x ≠ x (seed {})", seed);
        }
    }

    #[test]
    fn scalar_mul_simple_products() {
        let (layout, total) = standalone_scalar_mul_layout();
        let mut two = ScalarElement::zero();
        two.limbs[0] = 2;
        let mut three = ScalarElement::zero();
        three.limbs[0] = 3;
        let mut six = ScalarElement::zero();
        six.limbs[0] = 6;
        assert_satisfies_scalar_mul(&layout, total, &two, &three);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(two.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(three.limbs[i] as u64);
        }
        fill_scalar_mul_gadget(&mut trace, 0, &layout, &two, &three);
        let c = read_scalar(&trace, 0, layout.c_limbs_base);
        assert_eq!(c.limbs, six.limbs);
    }

    #[test]
    fn scalar_mul_n_minus_1_squared_is_one() {
        let (layout, total) = standalone_scalar_mul_layout();
        let mut neg_one = ScalarElement::one().neg();
        neg_one.freeze();
        assert_satisfies_scalar_mul(&layout, total, &neg_one, &neg_one);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(neg_one.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(neg_one.limbs[i] as u64);
        }
        fill_scalar_mul_gadget(&mut trace, 0, &layout, &neg_one, &neg_one);
        let c = read_scalar(&trace, 0, layout.c_limbs_base);
        let one = ScalarElement::one();
        assert_eq!(c.limbs, one.limbs, "(n-1)² ≠ 1 (mod n)");
    }

    #[test]
    fn scalar_mul_random_inputs_match_native() {
        let (layout, total) = standalone_scalar_mul_layout();
        for seed in 0u64..6 {
            let a = pseudo_scalar(seed);
            let b = pseudo_scalar(seed.wrapping_mul(13).wrapping_add(7));
            assert_satisfies_scalar_mul(&layout, total, &a, &b);

            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
                trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
            }
            fill_scalar_mul_gadget(&mut trace, 0, &layout, &a, &b);
            let c = read_scalar(&trace, 0, layout.c_limbs_base);
            let mut native = a.mul(&b);
            native.freeze();
            assert_eq!(
                c.limbs, native.limbs,
                "scalar mul gadget ≠ native (seed {})",
                seed
            );
        }
    }

    #[test]
    fn scalar_mul_tamper_detection() {
        let (layout, total) = standalone_scalar_mul_layout();
        let a = pseudo_scalar(5);
        let b = pseudo_scalar(7);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            trace[layout.b_limbs_base + i][0] = F::from(b.limbs[i] as u64);
        }
        fill_scalar_mul_gadget(&mut trace, 0, &layout, &a, &b);

        let target = layout.c_limbs_base + 4;
        let original = trace[target][0];
        trace[target][0] = original + F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_mul_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1, "scalar mul tamper undetected");
    }

    // ─────────────────────────────────────────────────────────────────
    //  Scalar-freeze gadget tests
    // ─────────────────────────────────────────────────────────────────

    fn standalone_scalar_freeze_layout() -> (ScalarFreezeGadgetLayout, usize) {
        let bits_per_elem = NUM_LIMBS * (LIMB_BITS as usize);
        let a_limbs_base = 0;
        let diff_limbs_base = NUM_LIMBS;
        let diff_bits_base = diff_limbs_base + NUM_LIMBS;
        let c_limbs_base = diff_bits_base + bits_per_elem;
        let c_bits_base = c_limbs_base + NUM_LIMBS;
        let c_pos_base = c_bits_base + bits_per_elem;
        let c_neg_base = c_pos_base + NUM_LIMBS;
        let total = c_neg_base + NUM_LIMBS;
        (
            ScalarFreezeGadgetLayout {
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

    fn assert_satisfies_scalar_freeze(
        layout: &ScalarFreezeGadgetLayout,
        total_width: usize,
        fe_a: &ScalarElement,
    ) {
        let mut trace = make_trace_row(total_width);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(fe_a.limbs[i] as u64);
        }
        fill_scalar_freeze_gadget(&mut trace, 0, layout, fe_a);

        let cur: Vec<F> = (0..total_width).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_freeze_gadget(&cur, layout);
        assert_eq!(cons.len(), SCALAR_FREEZE_GADGET_CONSTRAINTS);
        for (i, v) in cons.iter().enumerate() {
            assert!(
                v.is_zero(),
                "scalar-freeze constraint #{} non-zero (a={:?})",
                i,
                fe_a.limbs
            );
        }
    }

    #[test]
    fn scalar_freeze_constants_match_field_freeze() {
        // Same shape and budget as Fp freeze.
        use crate::p256_field_air::{FREEZE_GADGET_CONSTRAINTS, FREEZE_GADGET_OWNED_CELLS};
        assert_eq!(SCALAR_FREEZE_GADGET_OWNED_CELLS, FREEZE_GADGET_OWNED_CELLS);
        assert_eq!(SCALAR_FREEZE_GADGET_CONSTRAINTS, FREEZE_GADGET_CONSTRAINTS);
    }

    #[test]
    fn scalar_freeze_canonical_input_unchanged() {
        let (layout, total) = standalone_scalar_freeze_layout();
        for seed in 0u64..6 {
            let a = pseudo_scalar(seed);
            assert_satisfies_scalar_freeze(&layout, total, &a);

            let mut trace = make_trace_row(total);
            for i in 0..NUM_LIMBS {
                trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
            }
            fill_scalar_freeze_gadget(&mut trace, 0, &layout, &a);
            let c = read_scalar(&trace, 0, layout.c_limbs_base);
            assert_eq!(
                c.limbs, a.limbs,
                "freeze of canonical input changed it (seed {})",
                seed
            );
        }
    }

    #[test]
    fn scalar_freeze_n_minus_1_is_canonical() {
        let (layout, total) = standalone_scalar_freeze_layout();
        let mut n_minus_1 = ScalarElement::one().neg();
        n_minus_1.freeze();
        assert_satisfies_scalar_freeze(&layout, total, &n_minus_1);
    }

    #[test]
    fn scalar_freeze_value_just_above_n_canonicalises() {
        // Construct n + 5 in tight non-canonical form, freeze should
        // produce 5.
        let (layout, total) = standalone_scalar_freeze_layout();
        let mut five = ScalarElement::zero();
        five.limbs[0] = 5;
        let n_as_se = ScalarElement {
            limbs: *N_LIMBS_TIGHT,
        };
        let mut a = five.add(&n_as_se);
        a.reduce(); // brings limbs into [0, 2^26) without subtracting n
        assert_satisfies_scalar_freeze(&layout, total, &a);

        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
        }
        fill_scalar_freeze_gadget(&mut trace, 0, &layout, &a);
        let c = read_scalar(&trace, 0, layout.c_limbs_base);
        let mut expected = ScalarElement::zero();
        expected.limbs[0] = 5;
        assert_eq!(c.limbs, expected.limbs, "freeze(n+5) ≠ 5");
    }

    #[test]
    fn scalar_freeze_tamper_detection() {
        let (layout, total) = standalone_scalar_freeze_layout();
        let a = pseudo_scalar(42);
        let mut trace = make_trace_row(total);
        for i in 0..NUM_LIMBS {
            trace[layout.a_limbs_base + i][0] = F::from(a.limbs[i] as u64);
        }
        fill_scalar_freeze_gadget(&mut trace, 0, &layout, &a);

        let target = layout.c_limbs_base + 2;
        let original = trace[target][0];
        trace[target][0] = original + F::one();

        let cur: Vec<F> = (0..total).map(|c| trace[c][0]).collect();
        let cons = eval_scalar_freeze_gadget(&cur, &layout);
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1, "tampered scalar freeze c-limb undetected");
    }
}

