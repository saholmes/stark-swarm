// rsa2048_exp_air.rs — Phase 3: multi-row RSA-2048 exponentiation
// chain for e = 65537.
//
// Each trace row hosts ONE F_n2048 multiplication gadget (from
// `rsa2048_field_air`).  The schedule is hardcoded for e=65537:
//
//     acc[0]   = s                     // boundary: initial acc = signature value
//     acc[k+1] = acc[k]^2  mod n       // 16 squarings (rows 0..15)
//     acc[17]  = acc[16] · s mod n     // final multiply (row 16)
//
// 17 active rows; trace is padded to n_trace = 32 with bit=0
// squarings beyond row 16 (harmless — extra rows compute
// $s^{65537 \cdot 2^k}$ but are not read).
//
// Per-row cell layout (input bases referenced; gadget cells owned):
//   - `acc[80]`     : current accumulator (input cells)
//   - `s[80]`       : signature value (input cells, constant across rows)
//   - `n[80]`       : modulus            (input cells, constant across rows)
//   - `phase`       : 1 cell, $\in \{0,1\}$
//   - `op2[80]`     : selected second operand = phase·s + (1-phase)·acc
//   - mul gadget    : 10,640 cells, computes `acc · op2 mod n` → `c`
//
// Per-row constraints:
//   - `phase ∈ {0,1}`        : 1 booleanity
//   - 80× select identities  : op2[i] - (phase·s[i] + (1-phase)·acc[i]) = 0
//   - mul gadget             : 10,799 (from `eval_rsa_mul_gadget`)
//   - acc transition         : nxt.acc[i] = cur.mul.c[i]    (80, fires when row+1 < n_trace)
//   - s constant transition  : nxt.s[i]   = cur.s[i]        (80, fires when row+1 < n_trace)
//   - n constant transition  : nxt.n[i]   = cur.n[i]        (80, fires when row+1 < n_trace)
//
// Total per-row constraints (when transitions fire):
//   1 + 80 + 10,799 + 240 = 11,120
//
// Soundness boundary (Phase 3 v0):
//   - Caller sets the trace cells consistently with the e=65537
//     schedule (phase=0 for rows 0..15, phase=1 for row 16, phase=0
//     for padding rows 17..31).
//   - Output at row 16's mul-gadget c cells is the claimed s^65537.
//   - A v1 layout (Phase 4) will add boundary constraints that
//     fix the phase schedule per row, eliminating the trust in
//     prover-supplied phase values.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;
use num_bigint::BigUint;

use crate::rsa2048_field_air::{
    biguint_to_limbs80, build_rsa_mul_layout, eval_rsa_mul_gadget,
    fill_rsa_mul_gadget, limbs80_to_biguint, rsa_mul_gadget_constraints,
    RsaMulGadgetLayout, RSA_MUL_GADGET_CONSTRAINTS, RSA_NUM_LIMBS,
};

/// Multi-row exponentiation chain layout.
#[derive(Clone, Debug)]
pub struct RsaExpMultirowLayout {
    /// Input columns (replicated across rows).
    pub acc_base:    usize,        // 80 cells
    pub s_base:      usize,        // 80 cells (signature value)
    pub n_base:      usize,        // 80 cells (modulus)
    /// Phase cell (1 = multiply, 0 = squaring).
    pub phase_cell:  usize,
    /// Selected operand: op2[i] = phase·s[i] + (1-phase)·acc[i].
    pub op2_base:    usize,        // 80 cells
    /// PKCS#1 v1.5 encoded message EM = pkcs1_pad(SHA-256(message), k=256),
    /// in 80×26-bit limbs (constant across all rows).  Phase 4 v2: the
    /// row-16 chain output is bound to these cells via boundary constraint,
    /// closing the SHA-256+padding native gap from Phase 3 v1.
    pub em_base:     usize,        // 80 cells
    /// Per-row mul gadget computing acc · op2 mod n.
    pub mul:         RsaMulGadgetLayout,
    /// Total cells per row.
    pub width:       usize,
}

/// Trace row at which the chain's final s^e mod n value is read.
pub const RSA_EXP_OUTPUT_ROW: usize = 16;

/// Per-row transition slots (acc + s + n + em).
pub const RSA_EXP_TRANSITION_CONSTRAINTS: usize = 4 * RSA_NUM_LIMBS;

/// Per-row local constraints
/// (phase booleanity + 80 select + mul + 80 em-output binding slots).
pub const RSA_EXP_LOCAL_CONSTRAINTS: usize =
    1 + RSA_NUM_LIMBS + RSA_MUL_GADGET_CONSTRAINTS + RSA_NUM_LIMBS;

/// Total per-row constraint count (local + transition slots).
pub const RSA_EXP_PER_ROW_CONSTRAINTS: usize =
    RSA_EXP_LOCAL_CONSTRAINTS + RSA_EXP_TRANSITION_CONSTRAINTS;

/// Build the RSA exponentiation chain layout starting at `start`.
///
/// Cell ordering (consecutive blocks):
///   [acc 80] [s 80] [n 80] [phase 1] [op2 80] [mul-gadget cells]
///
/// The mul gadget's a_limbs_base = acc_base, b_limbs_base = op2_base,
/// n_limbs_base = n_base.
pub fn build_rsa_exp_multirow_layout(start: usize) -> (RsaExpMultirowLayout, usize) {
    let mut cursor = start;

    let acc_base = cursor; cursor += RSA_NUM_LIMBS;
    let s_base   = cursor; cursor += RSA_NUM_LIMBS;
    let n_base   = cursor; cursor += RSA_NUM_LIMBS;
    let phase_cell = cursor; cursor += 1;
    let op2_base = cursor; cursor += RSA_NUM_LIMBS;
    let em_base  = cursor; cursor += RSA_NUM_LIMBS;

    let (mul, end) = build_rsa_mul_layout(cursor, acc_base, op2_base, n_base);
    cursor = end;

    let layout = RsaExpMultirowLayout {
        acc_base,
        s_base,
        n_base,
        phase_cell,
        op2_base,
        em_base,
        mul,
        width: cursor,
    };
    (layout, cursor)
}

pub fn rsa_exp_multirow_constraints(_layout: &RsaExpMultirowLayout) -> usize {
    RSA_EXP_PER_ROW_CONSTRAINTS
}

/// Phase schedule for e = 65537 (= 2^16 + 1):
///   - Rows 0..14: squaring (phase=0).
///   - Row 15: squaring producing acc = s^(2^16).
///   - Row 16: multiply (phase=1) producing acc = s^(2^16+1) = s^65537.
///   - Rows 17..n_trace-1: padding, squaring (phase=0).
fn phase_for_row_e65537(row: usize) -> bool {
    row == 16
}

/// Number of active rows for e = 65537.
pub const RSA_EXP_E65537_ACTIVE_ROWS: usize = 17;

/// Fill the trace for an RSA-2048 exponentiation `s^65537 mod n`.
///
/// * `trace[c][r]` is the trace cell at column `c`, row `r`.
/// * `n_trace` must be a power of 2 and ≥ `RSA_EXP_E65537_ACTIVE_ROWS`.
/// * `em` is the PKCS#1 v1.5 encoded message expected to equal
///   $s^{65537} \bmod n$ (the boundary constraint at row 16 enforces
///   `c_limbs == em_limbs`).  Caller computes em natively from the
///   message digest.
pub fn fill_rsa_exp_multirow(
    trace: &mut [Vec<F>],
    layout: &RsaExpMultirowLayout,
    n_trace: usize,
    n: &BigUint,
    s: &BigUint,
    em: &BigUint,
) {
    assert!(n_trace.is_power_of_two());
    assert!(n_trace >= RSA_EXP_E65537_ACTIVE_ROWS);

    let s_limbs = biguint_to_limbs80(s);
    let n_limbs = biguint_to_limbs80(n);
    let em_limbs = biguint_to_limbs80(em);

    // Initial acc = s.
    let mut acc_big = s.clone();

    for r in 0..n_trace {
        // Place s, n, em on every row.
        for i in 0..RSA_NUM_LIMBS {
            trace[layout.s_base + i][r]  = F::from(s_limbs[i] as u64);
            trace[layout.n_base + i][r]  = F::from(n_limbs[i] as u64);
            trace[layout.em_base + i][r] = F::from(em_limbs[i] as u64);
        }
        // Place acc[r].
        let acc_limbs = biguint_to_limbs80(&acc_big);
        for i in 0..RSA_NUM_LIMBS {
            trace[layout.acc_base + i][r] = F::from(acc_limbs[i] as u64);
        }
        // Phase decides op2:
        //   phase = 1 → op2 = s (multiply)
        //   phase = 0 → op2 = acc (squaring)
        let phase = phase_for_row_e65537(r);
        trace[layout.phase_cell][r] = F::from(phase as u64);

        let op2_big: BigUint = if phase { s.clone() } else { acc_big.clone() };
        let op2_limbs = biguint_to_limbs80(&op2_big);
        for i in 0..RSA_NUM_LIMBS {
            trace[layout.op2_base + i][r] = F::from(op2_limbs[i] as u64);
        }

        // Fill the mul gadget: c = acc · op2 mod n.
        fill_rsa_mul_gadget(trace, r, &layout.mul, &acc_big, &op2_big, n);

        // Read the gadget's c output to advance acc.
        let mut c_limbs = [0i64; RSA_NUM_LIMBS];
        for i in 0..RSA_NUM_LIMBS {
            use ark_ff::PrimeField;
            let bi = trace[layout.mul.c_limbs_base + i][r].into_bigint();
            c_limbs[i] = bi.as_ref()[0] as i64;
        }
        acc_big = limbs80_to_biguint(&c_limbs);
    }
}

/// Evaluate per-row constraints for the RSA exponentiation chain.
///
/// Returns a vector of length `RSA_EXP_PER_ROW_CONSTRAINTS`.  On a
/// valid trace every entry is zero.  Transition slots are zeroed at
/// the boundary row (row + 1 == n_trace) to respect FFT periodicity.
pub fn eval_rsa_exp_multirow_per_row(
    cur: &[F],
    nxt: &[F],
    trace_row: usize,
    n_trace: usize,
    layout: &RsaExpMultirowLayout,
) -> Vec<F> {
    let mut out = Vec::with_capacity(RSA_EXP_PER_ROW_CONSTRAINTS);

    // (1) phase ∈ {0, 1}.
    let phase = cur[layout.phase_cell];
    out.push(phase * (F::one() - phase));

    // (2) Select: op2[i] - (phase·s[i] + (1-phase)·acc[i]) = 0.
    for i in 0..RSA_NUM_LIMBS {
        let s_i  = cur[layout.s_base + i];
        let a_i  = cur[layout.acc_base + i];
        let op_i = cur[layout.op2_base + i];
        // phase·s + (1-phase)·acc = phase·(s - acc) + acc
        let target = phase * (s_i - a_i) + a_i;
        out.push(op_i - target);
    }

    // (3) Mul gadget constraints.
    out.extend(eval_rsa_mul_gadget(cur, &layout.mul));

    // (4) Boundary constraint at the chain output row: row-16 mul.c
    //     equals the verifier-supplied EM (Phase 4 v2 — closes the
    //     SHA-256+padding native gap).  Slot is always emitted; the
    //     value is zero on rows other than RSA_EXP_OUTPUT_ROW.
    if trace_row == RSA_EXP_OUTPUT_ROW {
        for i in 0..RSA_NUM_LIMBS {
            out.push(cur[layout.mul.c_limbs_base + i] - cur[layout.em_base + i]);
        }
    } else {
        for _ in 0..RSA_NUM_LIMBS {
            out.push(F::zero());
        }
    }

    // (5) Transitions: acc/s/n/em constant or chained where applicable.
    if trace_row + 1 < n_trace {
        // acc transition: nxt.acc[i] = cur.mul.c[i]
        for i in 0..RSA_NUM_LIMBS {
            out.push(nxt[layout.acc_base + i] - cur[layout.mul.c_limbs_base + i]);
        }
        // s constant: nxt.s[i] = cur.s[i]
        for i in 0..RSA_NUM_LIMBS {
            out.push(nxt[layout.s_base + i] - cur[layout.s_base + i]);
        }
        // n constant: nxt.n[i] = cur.n[i]
        for i in 0..RSA_NUM_LIMBS {
            out.push(nxt[layout.n_base + i] - cur[layout.n_base + i]);
        }
        // em constant: nxt.em[i] = cur.em[i]
        for i in 0..RSA_NUM_LIMBS {
            out.push(nxt[layout.em_base + i] - cur[layout.em_base + i]);
        }
    } else {
        for _ in 0..RSA_EXP_TRANSITION_CONSTRAINTS {
            out.push(F::zero());
        }
    }

    debug_assert_eq!(out.len(), RSA_EXP_PER_ROW_CONSTRAINTS);
    out
}

/// Read the chain's output (s^65537 mod n) from row 16 of the trace.
pub fn read_exp_output(
    trace: &[Vec<F>],
    layout: &RsaExpMultirowLayout,
) -> BigUint {
    use ark_ff::PrimeField;
    let row = 16;
    let mut limbs = [0i64; RSA_NUM_LIMBS];
    for i in 0..RSA_NUM_LIMBS {
        let bi = trace[layout.mul.c_limbs_base + i][row].into_bigint();
        limbs[i] = bi.as_ref()[0] as i64;
    }
    limbs80_to_biguint(&limbs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn make_trace(width: usize, n_rows: usize) -> Vec<Vec<F>> {
        (0..width).map(|_| vec![F::zero(); n_rows]).collect()
    }

    fn gen_biguint(rng: &mut rand::rngs::StdRng, bits: u32) -> BigUint {
        let bytes = (bits as usize + 7) / 8;
        let mut buf = vec![0u8; bytes];
        rng.fill(&mut buf[..]);
        let extra = (bytes * 8) - bits as usize;
        if extra > 0 {
            buf[0] &= 0xFF >> extra;
        }
        BigUint::from_bytes_be(&buf)
    }

    fn gen_biguint_below(rng: &mut rand::rngs::StdRng, n: &BigUint) -> BigUint {
        let bits = n.bits() as u32;
        loop {
            let candidate = gen_biguint(rng, bits);
            if &candidate < n {
                return candidate;
            }
        }
    }

    #[test]
    fn exp_layout_consistency() {
        let (layout, end) = build_rsa_exp_multirow_layout(0);
        assert_eq!(layout.width, end);
        assert!(layout.width >= RSA_NUM_LIMBS * 4 + 1);
        assert_eq!(rsa_exp_multirow_constraints(&layout), RSA_EXP_PER_ROW_CONSTRAINTS);
    }

    #[test]
    fn exp_chain_computes_s_to_65537() {
        // Random 2048-bit modulus + signature value; run the chain
        // with em = the expected s^65537 mod n; assert all constraints
        // satisfy (including the row-16 boundary tying chain output to em).
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF);
        let n = (gen_biguint(&mut rng, 2046) << 1) | BigUint::from(1u8);
        let s = gen_biguint_below(&mut rng, &n);
        let em = s.modpow(&BigUint::from(65_537u32), &n);

        let n_trace = 32;
        let (layout, total_cells) = build_rsa_exp_multirow_layout(0);
        let mut trace = make_trace(total_cells, n_trace);

        fill_rsa_exp_multirow(&mut trace, &layout, n_trace, &n, &s, &em);

        let mut total_failures = 0;
        for r in 0..n_trace {
            let cur: Vec<F> = (0..total_cells).map(|c| trace[c][r]).collect();
            let nxt_idx = (r + 1) % n_trace;
            let nxt: Vec<F> = (0..total_cells).map(|c| trace[c][nxt_idx]).collect();
            let cons = eval_rsa_exp_multirow_per_row(&cur, &nxt, r, n_trace, &layout);
            let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
            total_failures += nonzero;
        }
        assert_eq!(total_failures, 0,
            "RSA exp chain had {} non-zero constraints across {} rows",
            total_failures, n_trace);

        let expected = s.modpow(&BigUint::from(65_537u32), &n);
        let actual = read_exp_output(&trace, &layout);
        assert_eq!(actual, expected);
    }

    #[test]
    fn exp_chain_wrong_em_violates_boundary() {
        // If we lie about em (give the prover an em that does NOT
        // equal s^65537 mod n), the row-16 boundary constraint must fire.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE_F00D);
        let n = (gen_biguint(&mut rng, 2046) << 1) | BigUint::from(1u8);
        let s = gen_biguint_below(&mut rng, &n);
        let real_em = s.modpow(&BigUint::from(65_537u32), &n);
        let bogus_em = (&real_em + BigUint::from(1u8)) % &n; // != real_em mod n

        let n_trace = 32;
        let (layout, total_cells) = build_rsa_exp_multirow_layout(0);
        let mut trace = make_trace(total_cells, n_trace);
        fill_rsa_exp_multirow(&mut trace, &layout, n_trace, &n, &s, &bogus_em);

        // Eval row 16 specifically — the boundary slot should fire non-zero.
        let cur: Vec<F> = (0..total_cells)
            .map(|c| trace[c][RSA_EXP_OUTPUT_ROW]).collect();
        let nxt: Vec<F> = (0..total_cells)
            .map(|c| trace[c][RSA_EXP_OUTPUT_ROW + 1]).collect();
        let cons = eval_rsa_exp_multirow_per_row(
            &cur, &nxt, RSA_EXP_OUTPUT_ROW, n_trace, &layout,
        );
        let nonzero = cons.iter().filter(|v| !v.is_zero()).count();
        assert!(nonzero >= 1,
            "bogus em must violate at least one boundary constraint, got {}",
            nonzero);
    }
}
