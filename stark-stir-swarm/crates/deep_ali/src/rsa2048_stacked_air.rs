// rsa2048_stacked_air.rs — N-record RSA-2048 stacked AIR.
//
// Stacks $N$ independent RSA exponentiation chains side-by-side
// in a single wide trace, yielding a SINGLE outer FRI proof that
// attests to all $N$ signatures simultaneously.  Achieves the
// lightest-footprint consumer artefact (one ${\sim}138$~KiB proof
// regardless of $N$) without requiring full STARK-of-STARK
// recursion --- the prover does $N{\times}$ the per-record work
// in one trace instead of producing $N$ separate proofs.
//
// Trade-off vs the per-record + outer-rollup architecture:
//   * Same consumer footprint (one FRI proof + ML-DSA signature).
//   * Cryptographically sound (no swarm-trust assumption).
//   * Prover work $O(N)$ in one sequential AIR (cannot trivially
//     parallelise across records on a swarm of provers --- a real
//     trade-off vs the recursive-STARK architecture which would
//     allow per-record parallelism + recursive aggregation).
//
// This is the "stacked AIR" pattern; it's not formally a recursive
// STARK but achieves the same edge-consumer property: one proof,
// constant verify time, no per-record artefacts.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{One, Zero};
use ark_goldilocks::Goldilocks as F;
use num_bigint::BigUint;

use crate::rsa2048_exp_air::{
    build_rsa_exp_multirow_layout, eval_rsa_exp_multirow_per_row,
    fill_rsa_exp_multirow, rsa_exp_multirow_constraints,
    RsaExpMultirowLayout, RSA_EXP_PER_ROW_CONSTRAINTS,
};

/// Stacked layout: one `RsaExpMultirowLayout` per record, at
/// disjoint column ranges within a single wide trace.
#[derive(Clone, Debug)]
pub struct RsaStackedLayout {
    pub records: Vec<RsaExpMultirowLayout>,
    pub width:   usize,
}

/// Build a stacked layout for `n_records` RSA-2048 chains.
pub fn build_rsa_stacked_layout(n_records: usize) -> RsaStackedLayout {
    let mut cursor = 0;
    let mut records = Vec::with_capacity(n_records);
    for _ in 0..n_records {
        let (layout, end) = build_rsa_exp_multirow_layout(cursor);
        cursor = end;
        records.push(layout);
    }
    RsaStackedLayout { records, width: cursor }
}

/// Per-row constraint count: $N \cdot$ (per-record constraints).
pub fn rsa_stacked_constraints(layout: &RsaStackedLayout) -> usize {
    layout.records.len() * RSA_EXP_PER_ROW_CONSTRAINTS
}

/// Per-record input bundle.
#[derive(Clone, Debug)]
pub struct RsaStackedRecord {
    pub n:  BigUint,
    pub s:  BigUint,
    pub em: BigUint,
}

/// Fill the stacked trace.
pub fn fill_rsa_stacked(
    trace: &mut [Vec<F>],
    layout: &RsaStackedLayout,
    n_trace: usize,
    records: &[RsaStackedRecord],
) {
    assert_eq!(records.len(), layout.records.len());
    for (rec_layout, rec) in layout.records.iter().zip(records.iter()) {
        fill_rsa_exp_multirow(trace, rec_layout, n_trace, &rec.n, &rec.s, &rec.em);
    }
}

/// Per-row constraint evaluator: evaluates all N records' per-row
/// constraints concatenated.  No inter-record constraints (records
/// share only the trace's row index).
pub fn eval_rsa_stacked_per_row(
    cur: &[F],
    nxt: &[F],
    trace_row: usize,
    n_trace: usize,
    layout: &RsaStackedLayout,
) -> Vec<F> {
    let total = rsa_stacked_constraints(layout);
    let mut out = Vec::with_capacity(total);
    for rec_layout in &layout.records {
        out.extend(eval_rsa_exp_multirow_per_row(
            cur, nxt, trace_row, n_trace, rec_layout,
        ));
    }
    debug_assert_eq!(out.len(), total);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

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
    fn stacked_rsa_n3_all_zero() {
        // N=3 stacked RSA records, each with random (n, s); em derived
        // from s^65537 mod n.  All constraints satisfy.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD);
        let mut records = Vec::new();
        for _ in 0..3 {
            let n = (gen_biguint(&mut rng, 2046) << 1) | BigUint::from(1u8);
            let s = gen_biguint_below(&mut rng, &n);
            let em = s.modpow(&BigUint::from(65_537u32), &n);
            records.push(RsaStackedRecord { n, s, em });
        }

        let layout = build_rsa_stacked_layout(3);
        let n_trace = 32;
        let mut trace: Vec<Vec<F>> = (0..layout.width)
            .map(|_| vec![F::zero(); n_trace]).collect();
        fill_rsa_stacked(&mut trace, &layout, n_trace, &records);

        let mut total_failures = 0;
        for r in 0..n_trace {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][r]).collect();
            let nxt_idx = (r + 1) % n_trace;
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][nxt_idx]).collect();
            let cons = eval_rsa_stacked_per_row(&cur, &nxt, r, n_trace, &layout);
            total_failures += cons.iter().filter(|v| !v.is_zero()).count();
        }
        assert_eq!(total_failures, 0,
            "stacked-RSA N=3 had {} non-zero constraints", total_failures);
    }
}
