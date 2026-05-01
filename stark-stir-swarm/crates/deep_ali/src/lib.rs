// lib.rs — replacement DEEP-ALI merge

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_variables)]
#![allow(unused_macros)]
use ark_ff::{Field, Zero};
use ark_goldilocks::Goldilocks as F;

pub mod trace_import;

use ark_poly::{
    EvaluationDomain,
    GeneralEvaluationDomain,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

const PARALLEL_MIN_ELEMS: usize = 1 << 12;

#[inline]
fn enable_parallel(len: usize) -> bool {
    #[cfg(feature = "parallel")]
    {
        len >= PARALLEL_MIN_ELEMS && rayon::current_num_threads() > 1
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = len;
        false
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Soundness budget
// ═══════════════════════════════════════════════════════════════════

/// Soundness breakdown for the full DEEP-ALI + FRI pipeline.
///
/// The total security level (in bits) is the minimum across all
/// contributing terms.  When `r` changes due to a more conservative
/// proximity gap bound, `fri_bits` changes, and the bottleneck may
/// shift from FRI to ALI or vice versa.
#[derive(Clone, Debug)]
pub struct SoundnessBudget {
    /// ALI reduction error: ≤ (num_constraints * max_degree * (width + 1)) / |F_ext|
    /// In bits: -log2(ε_ALI).
    pub ali_bits: f64,

    /// FRI proximity testing: depends on r, eps_eff, PoW bits.
    pub fri_bits: f64,

    /// Proof-of-work grinding bits (0 if not used).
    pub pow_bits: f64,

    /// Total: min(ali_bits, fri_bits + pow_bits).
    pub total_bits: f64,
}

impl SoundnessBudget {
    /// Compute the soundness budget from protocol parameters.
    ///
    /// `ext_field_log_size`: log2(|F_ext|), e.g. 192 for Fp3, 384 for Fp6.
    /// `num_constraints`:    number of transition constraints in the AIR.
    /// `max_constraint_deg`: maximum degree of any single constraint.
    /// `trace_width`:        number of trace columns (w).
    /// `fri_bits`:           bits of security from FRI queries (r * bits_per_query).
    /// `pow_bits`:           bits from proof-of-work grinding.
    pub fn compute(
        ext_field_log_size: f64,
        num_constraints: usize,
        max_constraint_deg: usize,
        trace_width: usize,
        fri_bits: f64,
        pow_bits: f64,
    ) -> Self {
        // ALI reduction error bound:
        //   ε_ALI ≤ num_constraints * max_degree * (width + 1) / |F_ext|
        //
        // This is the probability that the random combination of
        // unsatisfied constraint quotients lands in the RS code.
        // The (width + 1) factor accounts for the DEEP sampling
        // adding one evaluation point per trace column plus one
        // for the composition column.
        let numerator_log2 = (num_constraints as f64
            * max_constraint_deg as f64
            * (trace_width + 1) as f64)
            .log2();
        let ali_bits = ext_field_log_size - numerator_log2;

        let total_bits = ali_bits.min(fri_bits + pow_bits);

        SoundnessBudget {
            ali_bits,
            fri_bits,
            pow_bits,
            total_bits,
        }
    }

    pub fn is_secure(&self, target_bits: f64) -> bool {
        self.total_bits >= target_bits
    }

    /// Identify which component is the bottleneck.
    pub fn bottleneck(&self) -> &'static str {
        if self.ali_bits <= self.fri_bits + self.pow_bits {
            "ALI reduction"
        } else {
            "FRI queries"
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Proximity gap bounds
// ═══════════════════════════════════════════════════════════════════

/// Which proximity gap lower bound to use for FRI soundness.
///
/// When you move to a more conservative bound, `eps_eff_per_query`
/// decreases and `r` must increase to maintain the target security.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProximityGapBound {
    /// Standard DEEP bound: δ ≥ 1 − √ρ  (Ben-Sasson et al., DEEP-FRI).
    /// Gives the best (largest) per-query soundness.
    Johnson,

    /// One-and-a-half Johnson: δ ≥ 1 − ρ^{1/3}.
    /// More conservative; used when the full Johnson analysis
    /// is not applicable (e.g., non-standard field/code parameters).
    OneAndHalfJohnson,

    /// Double Johnson: δ ≥ 1 − ρ^{1/4}.
    /// Most conservative; the original DEEP-FRI bound before
    /// the improved proximity gap analysis.
    DoubleJohnson,

    /// Custom bound: provide δ directly.
    Custom(f64),
}

impl ProximityGapBound {
    /// Compute the proximity gap δ for a given rate ρ = deg/domain_size.
    pub fn delta(&self, rho: f64) -> f64 {
        match self {
            ProximityGapBound::Johnson => 1.0 - rho.sqrt(),
            ProximityGapBound::OneAndHalfJohnson => 1.0 - rho.cbrt(),
            ProximityGapBound::DoubleJohnson => 1.0 - rho.powf(0.25),
            ProximityGapBound::Custom(d) => *d,
        }
    }

    /// Per-query soundness: probability of rejecting a word at distance ≥ δ.
    ///
    /// For FRI with rate ρ and proximity gap δ, each query rejects
    /// with probability ≥ 1 - (1 - δ) = δ when the codeword is δ-far.
    /// The per-query error is at most max(√ρ, 1 - δ) for the standard
    /// bound.  We use the conservative formula:
    ///   ε_per_query = 1 − δ   (upper bound on non-rejection probability)
    pub fn per_query_error(&self, rho: f64) -> f64 {
        1.0 - self.delta(rho)
    }

    /// Bits of soundness per FRI query.
    pub fn bits_per_query(&self, rho: f64) -> f64 {
        let err = self.per_query_error(rho);
        if err >= 1.0 {
            return 0.0;
        }
        -(err.log2())
    }

    /// Number of queries needed for `target_bits` of FRI soundness.
    pub fn queries_for_target(&self, rho: f64, target_bits: f64) -> usize {
        let bpq = self.bits_per_query(rho);
        if bpq <= 0.0 {
            return usize::MAX;
        }
        (target_bits / bpq).ceil() as usize
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Polynomial division by Z_H(X) = X^m − 1
// ═══════════════════════════════════════════════════════════════════

/// Exact polynomial division of `dividend` by Z_H(X) = X^m − 1.
fn poly_div_zh(dividend: &[F], m: usize) -> Vec<F> {
    let n = dividend.len();
    if n <= m {
        #[cfg(debug_assertions)]
        for (i, &c) in dividend.iter().enumerate() {
            debug_assert!(
                c.is_zero(),
                "poly_div_zh: Φ̃ has degree < m={} but coeff[{}] is nonzero — \
                 constraints are not satisfied on the trace domain",
                m, i,
            );
        }
        return vec![F::zero()];
    }

    let q_len = n - m;
    let mut q = vec![F::zero(); q_len];

    for k in (m..n).rev() {
        let qk = if k < q_len { q[k] } else { F::zero() };
        q[k - m] = dividend[k] + qk;
    }

    #[cfg(debug_assertions)]
    {
        for k in 0..m.min(n) {
            let qk = if k < q_len { q[k] } else { F::zero() };
            let remainder = dividend[k] + qk;
            debug_assert!(
                remainder.is_zero(),
                "poly_div_zh: nonzero remainder at coeff index {} \
                 (remainder = {:?}) — constraints not satisfied on H",
                k, remainder,
            );
        }
    }

    q
}

// ═══════════════════════════════════════════════════════════════════
//  DEEP-ALI constraint merge — GENERALIZED
// ═══════════════════════════════════════════════════════════════════

/// Metadata about the composition for downstream soundness accounting.
#[derive(Clone, Debug)]
pub struct CompositionInfo {
    /// Degree of Φ̃(X) before dividing by Z_H.
    pub phi_degree_bound: usize,
    /// Degree of c(X) = Φ̃/Z_H.
    pub quotient_degree_bound: usize,
    /// Rate ρ = quotient_degree_bound / n.
    pub rate: f64,
    /// Number of constraints that were combined.
    pub num_constraints: usize,
    /// Maximum individual constraint degree.
    pub max_constraint_degree: usize,
    /// Trace width (number of columns).
    pub trace_width: usize,
}

/// Evaluate all transition constraints for a given AIR on the full
/// FRI domain, returning one evaluation vector per constraint.
///
/// Each returned vector has length `n` (the FRI domain size).
/// Constraint evaluations are zero on the trace subdomain H when
/// the execution trace is valid.
///
/// # Arguments
///
/// * `trace_evals_on_lde` — trace columns, each LDE-evaluated on the
///   n-point FRI domain.  `trace_evals_on_lde[col][i]` is column `col`
///   evaluated at ω^i.
///
/// * `air` — which AIR workload to evaluate.
///
/// * `n_trace` — number of rows in the execution trace (= n / blowup).
///   Constraints are meaningful on rows 0..n_trace−2 of H.
///
/// * `blowup` — LDE blowup factor (n / n_trace).
fn evaluate_all_constraints_on_lde(
    trace_evals_on_lde: &[Vec<F>],
    air: crate::air_workloads::AirType,
    n: usize,
    n_trace: usize,
    blowup: usize,
) -> Vec<Vec<F>> {
    let w = air.width();
    let k = air.num_constraints();
    assert_eq!(trace_evals_on_lde.len(), w);
    for col in trace_evals_on_lde {
        assert_eq!(col.len(), n);
    }

    let mut constraint_evals = vec![vec![F::zero(); n]; k];

    // The LDE domain is D = {ω^0, ω^1, ..., ω^{n-1}}.
    // The trace subdomain is H = {ω^{blowup·0}, ω^{blowup·1}, ..., ω^{blowup·(n_trace-1)}}.
    // The "next row" for H-row j is H-row (j+1) mod n_trace,
    // which corresponds to LDE index (j+1)*blowup mod n.
    //
    // For the constraint polynomial, we evaluate at EVERY LDE point:
    //   C(ω^i) using cur = trace(ω^i) and nxt = trace(ω^{i + blowup} mod n).
    //
    // This produces a polynomial that vanishes on H (rows 0..n_trace-2)
    // when constraints are satisfied.

    for i in 0..n {
        let cur: Vec<F> = (0..w).map(|c| trace_evals_on_lde[c][i]).collect();
        let nxt_idx = (i + blowup) % n;
        let nxt: Vec<F> = (0..w).map(|c| trace_evals_on_lde[c][nxt_idx]).collect();

        // Determine the trace-domain row index for round-constant lookup
        // (relevant for Poseidon).  LDE index i corresponds to trace row
        // i / blowup when i is a multiple of blowup.  For non-H points
        // we use i / blowup as a reasonable approximation (the round
        // constants are deterministic from the row index).
        let trace_row = i / blowup;

        let cvals = crate::air_workloads::evaluate_constraints(
            air, &cur, &nxt, trace_row,
        );

        for j in 0..k {
            constraint_evals[j][i] = cvals[j];
        }
    }

    constraint_evals
}

/// Generalized DEEP-ALI merge for arbitrary multi-constraint AIRs.
///
/// Computes the composition quotient c(X) = Φ̃(X) / Z_H(X) where
///   Φ̃(X) = Σ_{j=0}^{k-1} λ_j · C_j(trace(X))
/// and λ_j are the verifier's random combination coefficients.
///
/// # Arguments
///
/// * `trace_evals_on_lde` — all trace columns, LDE-evaluated on the
///   n-point FRI domain.
/// * `combination_coeffs` — random base-field coefficients λ_j, one per
///   constraint.  In a real protocol these come from the Fiat–Shamir
///   transcript AFTER the prover commits to the trace.
/// * `air` — which AIR workload.
/// * `omega` — generator of the FRI domain.
/// * `n_trace` — trace domain size.
/// * `blowup` — LDE blowup factor.
///
/// # Returns
///
/// `(Vec<F>, CompositionInfo)`:  evaluations of c(X) on the FRI domain,
/// plus metadata for soundness accounting.
pub fn deep_ali_merge_general(
    trace_evals_on_lde: &[Vec<F>],
    combination_coeffs: &[F],
    air: crate::air_workloads::AirType,
    omega: F,
    n_trace: usize,
    blowup: usize,
) -> (Vec<F>, CompositionInfo) {
    let w = air.width();
    let k = air.num_constraints();
    let n = n_trace * blowup;

    assert_eq!(trace_evals_on_lde.len(), w, "trace width mismatch");
    assert_eq!(
        combination_coeffs.len(), k,
        "need one combination coefficient per constraint, got {} for {} constraints",
        combination_coeffs.len(), k
    );
    for col in trace_evals_on_lde {
        assert_eq!(col.len(), n, "trace column length mismatch");
    }

    // ── Step 1: Evaluate all constraints on the LDE domain ──
    let constraint_evals = evaluate_all_constraints_on_lde(
        trace_evals_on_lde, air, n, n_trace, blowup,
    );

    // ── Step 2: Random linear combination ──
    //   Φ̃(ω^i) = Σ_j λ_j · C_j(ω^i)
    let mut phi_eval = vec![F::zero(); n];

    if enable_parallel(n) {
        #[cfg(feature = "parallel")]
        {
            phi_eval.par_iter_mut().enumerate().for_each(|(i, phi_i)| {
                let mut acc = F::zero();
                for j in 0..k {
                    acc += combination_coeffs[j] * constraint_evals[j][i];
                }
                *phi_i = acc;
            });
        }
    }

    // Sequential fallback (also used when parallel is disabled)
    #[cfg(not(feature = "parallel"))]
    {
        for i in 0..n {
            let mut acc = F::zero();
            for j in 0..k {
                acc += combination_coeffs[j] * constraint_evals[j][i];
            }
            phi_eval[i] = acc;
        }
    }

    // ── Step 3: IFFT → coefficient representation ──
    let domain =
        GeneralEvaluationDomain::<F>::new(n).expect("power-of-two domain");
    let phi_coeffs = domain.ifft(&phi_eval);

    // ── Step 4: Divide by Z_H(X) = X^{n_trace} − 1 ──
    let c_coeffs = poly_div_zh(&phi_coeffs, n_trace);

    // ── Step 5: FFT back to evaluations ──
    let mut padded = c_coeffs.clone();
    padded.resize(n, F::zero());
    let c_eval = domain.fft(&padded);

    // ── Composition metadata ──
    let max_deg = air.max_constraint_degree();
    // Φ̃ has degree ≤ max_deg * (n_trace - 1)  (transition constraints
    // applied to polynomials of degree n_trace - 1).
    // After dividing by Z_H (degree n_trace), the quotient has degree
    // ≤ max_deg * (n_trace - 1) - n_trace = (max_deg - 1) * n_trace - max_deg.
    // In practice, the effective bound is:
    let phi_degree_bound = max_deg * n_trace;
    let quotient_degree_bound = if phi_degree_bound > n_trace {
        phi_degree_bound - n_trace
    } else {
        0
    };
    let rate = quotient_degree_bound as f64 / n as f64;

    let info = CompositionInfo {
        phi_degree_bound,
        quotient_degree_bound,
        rate,
        num_constraints: k,
        max_constraint_degree: max_deg,
        trace_width: w,
    };

    (c_eval, info)
}

// ═══════════════════════════════════════════════════════════════════
//  SHA-256 multi-block merge (parameterised by n_blocks)
// ═══════════════════════════════════════════════════════════════════

/// DEEP-ALI merge for the SHA-256 AIR with arbitrary `n_blocks`.
///
/// Mirrors `deep_ali_merge_general` but routes constraint evaluation
/// through `sha256_air::eval_sha256_constraints(cur, nxt, row, n_blocks)`
/// instead of the registry dispatcher (which fixes `n_blocks = 1`).
///
/// `swarm-dns::prove_ds_ksk_binding` invokes this directly so that
/// multi-block DNSKEYs (RSA-2048, ECDSA-P256, multi-block Ed25519
/// concatenations) can be proved with a single STARK rather than
/// composing per-block proofs at the API layer.
pub fn deep_ali_merge_sha256(
    trace_evals_on_lde: &[Vec<F>],
    combination_coeffs: &[F],
    omega: F,
    n_trace: usize,
    blowup: usize,
    n_blocks: usize,
) -> (Vec<F>, CompositionInfo) {
    use crate::sha256_air::{WIDTH as SHA_W, NUM_CONSTRAINTS as SHA_K};

    let _ = omega;
    let n = n_trace * blowup;

    assert_eq!(trace_evals_on_lde.len(), SHA_W, "trace width mismatch");
    assert_eq!(
        combination_coeffs.len(), SHA_K,
        "need one combination coefficient per constraint, got {} for {} constraints",
        combination_coeffs.len(), SHA_K
    );
    for col in trace_evals_on_lde {
        assert_eq!(col.len(), n, "trace column length mismatch");
    }

    // ── Step 1: evaluate constraints on the LDE domain ──
    let mut constraint_evals = vec![vec![F::zero(); n]; SHA_K];
    for i in 0..n {
        let cur: Vec<F> = (0..SHA_W).map(|c| trace_evals_on_lde[c][i]).collect();
        let nxt_idx = (i + blowup) % n;
        let nxt: Vec<F> = (0..SHA_W).map(|c| trace_evals_on_lde[c][nxt_idx]).collect();
        let trace_row = i / blowup;
        let cvals = crate::sha256_air::eval_sha256_constraints(
            &cur, &nxt, trace_row, n_blocks,
        );
        for j in 0..SHA_K {
            constraint_evals[j][i] = cvals[j];
        }
    }

    // ── Step 2: random linear combination Φ̃(ω^i) ──
    let mut phi_eval = vec![F::zero(); n];
    if enable_parallel(n) {
        #[cfg(feature = "parallel")]
        {
            phi_eval.par_iter_mut().enumerate().for_each(|(i, phi_i)| {
                let mut acc = F::zero();
                for j in 0..SHA_K {
                    acc += combination_coeffs[j] * constraint_evals[j][i];
                }
                *phi_i = acc;
            });
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        for i in 0..n {
            let mut acc = F::zero();
            for j in 0..SHA_K {
                acc += combination_coeffs[j] * constraint_evals[j][i];
            }
            phi_eval[i] = acc;
        }
    }

    // ── Step 3: IFFT → coefficients ──
    let domain =
        GeneralEvaluationDomain::<F>::new(n).expect("power-of-two domain");
    let phi_coeffs = domain.ifft(&phi_eval);

    // ── Step 4: divide by Z_H(X) = X^{n_trace} − 1 ──
    let c_coeffs = poly_div_zh(&phi_coeffs, n_trace);

    // ── Step 5: FFT back to evaluations ──
    let mut padded = c_coeffs.clone();
    padded.resize(n, F::zero());
    let c_eval = domain.fft(&padded);

    // ── Composition metadata (max_deg = 2 globally) ──
    let max_deg = 2usize;
    let phi_degree_bound = max_deg * n_trace;
    let quotient_degree_bound = if phi_degree_bound > n_trace {
        phi_degree_bound - n_trace
    } else { 0 };
    let info = CompositionInfo {
        phi_degree_bound,
        quotient_degree_bound,
        rate: quotient_degree_bound as f64 / n as f64,
        num_constraints: SHA_K,
        max_constraint_degree: max_deg,
        trace_width: SHA_W,
    };

    (c_eval, info)
}

// ═══════════════════════════════════════════════════════════════════
//  SHA-512 multi-block merge (parameterised by n_blocks)
// ═══════════════════════════════════════════════════════════════════

/// DEEP-ALI merge for the SHA-512 AIR with arbitrary `n_blocks`.
///
/// Twin of `deep_ali_merge_sha256` for the SHA-512 AIR (1510 cols,
/// 1526 transition constraints).  Routes constraint evaluation through
/// `sha512_air::eval_sha512_constraints(cur, nxt, row, n_blocks)`.
///
/// Used by `swarm-dns::prove_zsk_ksk_binding` (planned) for the
/// in-circuit SHA-512 stage of Ed25519 verification (RFC 8032 §5.1.7),
/// where the input to the hash is `R || A || M` and the output digest
/// is reduced mod L to form the verification scalar k.
pub fn deep_ali_merge_sha512(
    trace_evals_on_lde: &[Vec<F>],
    combination_coeffs: &[F],
    omega: F,
    n_trace: usize,
    blowup: usize,
    n_blocks: usize,
) -> (Vec<F>, CompositionInfo) {
    use crate::sha512_air::{WIDTH as SHA_W, NUM_CONSTRAINTS as SHA_K};

    let _ = omega;
    let n = n_trace * blowup;

    assert_eq!(trace_evals_on_lde.len(), SHA_W, "trace width mismatch");
    assert_eq!(
        combination_coeffs.len(), SHA_K,
        "need one combination coefficient per constraint, got {} for {} constraints",
        combination_coeffs.len(), SHA_K
    );
    for col in trace_evals_on_lde {
        assert_eq!(col.len(), n, "trace column length mismatch");
    }

    // ── Step 1: evaluate constraints on the LDE domain ──
    let mut constraint_evals = vec![vec![F::zero(); n]; SHA_K];
    for i in 0..n {
        let cur: Vec<F> = (0..SHA_W).map(|c| trace_evals_on_lde[c][i]).collect();
        let nxt_idx = (i + blowup) % n;
        let nxt: Vec<F> = (0..SHA_W).map(|c| trace_evals_on_lde[c][nxt_idx]).collect();
        let trace_row = i / blowup;
        let cvals = crate::sha512_air::eval_sha512_constraints(
            &cur, &nxt, trace_row, n_blocks,
        );
        for j in 0..SHA_K {
            constraint_evals[j][i] = cvals[j];
        }
    }

    // ── Step 2: random linear combination Φ̃(ω^i) ──
    let mut phi_eval = vec![F::zero(); n];
    if enable_parallel(n) {
        #[cfg(feature = "parallel")]
        {
            phi_eval.par_iter_mut().enumerate().for_each(|(i, phi_i)| {
                let mut acc = F::zero();
                for j in 0..SHA_K {
                    acc += combination_coeffs[j] * constraint_evals[j][i];
                }
                *phi_i = acc;
            });
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        for i in 0..n {
            let mut acc = F::zero();
            for j in 0..SHA_K {
                acc += combination_coeffs[j] * constraint_evals[j][i];
            }
            phi_eval[i] = acc;
        }
    }

    // ── Step 3: IFFT → coefficients ──
    let domain =
        GeneralEvaluationDomain::<F>::new(n).expect("power-of-two domain");
    let phi_coeffs = domain.ifft(&phi_eval);

    // ── Step 4: divide by Z_H(X) = X^{n_trace} − 1 ──
    let c_coeffs = poly_div_zh(&phi_coeffs, n_trace);

    // ── Step 5: FFT back to evaluations ──
    let mut padded = c_coeffs.clone();
    padded.resize(n, F::zero());
    let c_eval = domain.fft(&padded);

    // ── Composition metadata (max_deg = 2 globally) ──
    let max_deg = 2usize;
    let phi_degree_bound = max_deg * n_trace;
    let quotient_degree_bound = if phi_degree_bound > n_trace {
        phi_degree_bound - n_trace
    } else { 0 };
    let info = CompositionInfo {
        phi_degree_bound,
        quotient_degree_bound,
        rate: quotient_degree_bound as f64 / n as f64,
        num_constraints: SHA_K,
        max_constraint_degree: max_deg,
        trace_width: SHA_W,
    };

    (c_eval, info)
}

// ═══════════════════════════════════════════════════════════════════
//  Ed25519 verify AIR — parametric merge (Phase 6 v2 wiring)
// ═══════════════════════════════════════════════════════════════════

/// Sequential (no-rayon) fallback for `deep_ali_merge_ed25519_verify`.
/// Used when the `parallel` feature is off OR when n is below the
/// `enable_parallel` threshold.  Mirrors the parallel path's fused
/// Step 1+2 so behaviour matches.
fn sequential_step1_step2(
    trace_evals_on_lde: &[Vec<F>],
    combination_coeffs: &[F],
    layout: &crate::ed25519_verify_air::VerifyAirLayoutV16,
    n: usize,
    w: usize,
    blowup: usize,
    k: usize,
) -> Vec<F> {
    let mut phi = vec![F::zero(); n];
    for i in 0..n {
        let cur: Vec<F> = (0..w).map(|c| trace_evals_on_lde[c][i]).collect();
        let nxt_idx = (i + blowup) % n;
        let nxt: Vec<F> = (0..w).map(|c| trace_evals_on_lde[c][nxt_idx]).collect();
        let trace_row = i / blowup;
        let cvals = crate::ed25519_verify_air::eval_verify_air_v16_per_row(
            &cur, &nxt, trace_row, layout,
        );
        debug_assert_eq!(cvals.len(), k);
        let mut acc = F::zero();
        for j in 0..k {
            acc += combination_coeffs[j] * cvals[j];
        }
        phi[i] = acc;
    }
    phi
}

/// DEEP-ALI merge for the parametric Ed25519 verify AIR (v16
/// composition in `crate::ed25519_verify_air`).
///
/// Mirrors `deep_ali_merge_sha256` / `deep_ali_merge_general` but
/// routes constraint evaluation through
/// `eval_verify_air_v16_per_row(cur, nxt, row, layout)`, which
/// requires the per-call `&VerifyAirLayoutV16` (the layout carries
/// the per-call public-input scalar bits, R/A coords, k_scalar, and
/// row/column offsets, none of which the static `AirType` registry
/// can express).
///
/// Production callers (K=256) invoke this directly from
/// `swarm-dns::prove_zsk_ksk_binding_v2`; the registry path
/// (`AirType::Ed25519ZskKsk`, K=8 stub) routes through
/// `deep_ali_merge_general` and produces an identical c-polynomial
/// when the stub layout is passed here.
pub fn deep_ali_merge_ed25519_verify(
    trace_evals_on_lde: &[Vec<F>],
    combination_coeffs: &[F],
    layout: &crate::ed25519_verify_air::VerifyAirLayoutV16,
    omega: F,
    n_trace: usize,
    blowup: usize,
) -> (Vec<F>, CompositionInfo) {
    use crate::ed25519_verify_air::{
        eval_verify_air_v16_per_row, verify_v16_per_row_constraints,
    };

    let _ = omega;
    let n = n_trace * blowup;
    let w = layout.width;
    let k = verify_v16_per_row_constraints(layout.k_scalar);

    assert_eq!(trace_evals_on_lde.len(), w, "trace width mismatch");
    assert_eq!(
        combination_coeffs.len(), k,
        "need one combination coefficient per constraint, got {} for {} constraints",
        combination_coeffs.len(), k,
    );
    for col in trace_evals_on_lde {
        assert_eq!(col.len(), n, "trace column length mismatch");
    }

    // ── Step 1+2 fused: evaluate constraints + linear combination,
    //    in parallel over LDE points.
    //
    // Allocator-aware design:
    //
    //   1. **Transpose the LDE once at the start** to a row-major
    //      buffer `lde_rm[i] = [F; w]`.  This is an O(n·w) one-time
    //      cost (~32K × 40K ≈ 0.5 s of data movement at 20 GB/s) but
    //      converts the inner loop's column-major scattered reads
    //      into contiguous slice borrows.  No per-iteration
    //      allocation; cache-friendly.
    //
    //   2. **Pass &[F] slice borrows** for cur and nxt into the
    //      per-row evaluator instead of Vec<F>.  Eliminates 2·n large
    //      heap allocations (~64K × 320 KB = 20 GiB of allocator
    //      churn at K=256) that were serialising threads on the
    //      global allocator lock.
    //
    // Memory footprint: O(n·w) for the row-major transpose
    //                   PLUS O(n·w) original column-major LDE
    //                   = 2× the LDE size (~20 GB at K=256).
    // Wall-clock: should saturate all rayon threads (one allocation
    //             per thread for the cvals output Vec).
    let lde_row_major: Vec<Vec<F>> = if enable_parallel(n) {
        #[cfg(feature = "parallel")]
        {
            (0..n).into_par_iter().map(|i| {
                (0..w).map(|c| trace_evals_on_lde[c][i]).collect::<Vec<F>>()
            }).collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            (0..n).map(|i| {
                (0..w).map(|c| trace_evals_on_lde[c][i]).collect::<Vec<F>>()
            }).collect()
        }
    } else {
        (0..n).map(|i| {
            (0..w).map(|c| trace_evals_on_lde[c][i]).collect::<Vec<F>>()
        }).collect()
    };

    let phi_eval: Vec<F>;
    if enable_parallel(n) {
        #[cfg(feature = "parallel")]
        {
            phi_eval = (0..n).into_par_iter().map(|i| {
                let cur: &[F] = &lde_row_major[i];
                let nxt_idx = (i + blowup) % n;
                let nxt: &[F] = &lde_row_major[nxt_idx];
                let trace_row = i / blowup;
                let cvals = eval_verify_air_v16_per_row(cur, nxt, trace_row, layout);
                debug_assert_eq!(cvals.len(), k);
                let mut acc = F::zero();
                for j in 0..k {
                    acc += combination_coeffs[j] * cvals[j];
                }
                acc
            }).collect();
        }
        #[cfg(not(feature = "parallel"))]
        {
            phi_eval = sequential_step1_step2(
                trace_evals_on_lde, combination_coeffs, layout,
                n, w, blowup, k,
            );
        }
    } else {
        phi_eval = sequential_step1_step2(
            trace_evals_on_lde, combination_coeffs, layout,
            n, w, blowup, k,
        );
    }
    drop(lde_row_major);    // release the transpose ASAP

    // ── Step 3: IFFT → coefficients ──
    let domain =
        GeneralEvaluationDomain::<F>::new(n).expect("power-of-two domain");
    let phi_coeffs = domain.ifft(&phi_eval);

    // ── Step 4: divide by Z_H(X) = X^{n_trace} − 1 ──
    let c_coeffs = poly_div_zh(&phi_coeffs, n_trace);

    // ── Step 5: FFT back to evaluations ──
    let mut padded = c_coeffs.clone();
    padded.resize(n, F::zero());
    let c_eval = domain.fft(&padded);

    // ── Composition metadata (max_deg = 2 globally) ──
    let max_deg = 2usize;
    let phi_degree_bound = max_deg * n_trace;
    let quotient_degree_bound = if phi_degree_bound > n_trace {
        phi_degree_bound - n_trace
    } else { 0 };
    let info = CompositionInfo {
        phi_degree_bound,
        quotient_degree_bound,
        rate: quotient_degree_bound as f64 / n as f64,
        num_constraints: k,
        max_constraint_degree: max_deg,
        trace_width: w,
    };

    (c_eval, info)
}

// ═══════════════════════════════════════════════════════════════════
//  Legacy single-constraint merge (Fibonacci: Φ̃ = a·s + e − t)
// ═══════════════════════════════════════════════════════════════════

/// Base-field DEEP-ALI merge for the single-constraint Fibonacci AIR.
///
/// Computes c(X) = Φ̃(X) / Z_H(X) where Φ̃(X) = a(X)·s(X) + e(X) − t(X),
/// returning evaluations of c on the FRI domain.
///
/// This is the entry point used by the benchmark harness.
pub fn deep_ali_merge_evals(
    a_eval: &[F],
    s_eval: &[F],
    e_eval: &[F],
    t_eval: &[F],
    omega: F,
    n_trace: usize,
) -> Vec<F> {
    let n = a_eval.len();
    assert!(n > 1 && n.is_power_of_two());
    assert!(n_trace > 0 && n_trace < n);
    assert_eq!(n % n_trace, 0);
    assert_eq!(s_eval.len(), n);
    assert_eq!(e_eval.len(), n);
    assert_eq!(t_eval.len(), n);

    // Φ̃(ω^i) = a(ω^i)·s(ω^i) + e(ω^i) − t(ω^i)
    let mut phi_eval = vec![F::zero(); n];
    for i in 0..n {
        phi_eval[i] = a_eval[i] * s_eval[i] + e_eval[i] - t_eval[i];
    }

    // IFFT → coefficients → divide by Z_H → FFT back
    let domain =
        GeneralEvaluationDomain::<F>::new(n).expect("power-of-two domain");
    let phi_coeffs = domain.ifft(&phi_eval);
    let c_coeffs = poly_div_zh(&phi_coeffs, n_trace);

    let mut padded = c_coeffs;
    padded.resize(n, F::zero());
    domain.fft(&padded)
}

/// Legacy blinded merge (backward-compatible wrapper).
pub fn deep_ali_merge_evals_blinded(
    a_eval: &[F],
    s_eval: &[F],
    e_eval: &[F],
    t_eval: &[F],
    r_eval_opt: Option<&[F]>,
    beta: F,
    omega: F,
    n_trace: usize,
) -> Vec<F> {
    let n = a_eval.len();
    assert!(n > 1);
    assert!(n.is_power_of_two());
    assert!(n_trace > 0 && n_trace < n);
    assert!(n % n_trace == 0);
    assert_eq!(s_eval.len(), n);
    assert_eq!(e_eval.len(), n);
    assert_eq!(t_eval.len(), n);
    if let Some(r_eval) = r_eval_opt {
        assert_eq!(r_eval.len(), n);
    }

    let mut phi_eval = vec![F::zero(); n];
    for i in 0..n {
        let base = a_eval[i] * s_eval[i] + e_eval[i] - t_eval[i];
        phi_eval[i] = if let Some(r) = r_eval_opt {
            base + beta * r[i]
        } else {
            base
        };
    }

    let domain = GeneralEvaluationDomain::<F>::new(n).expect("power-of-two domain");
    let phi_coeffs = domain.ifft(&phi_eval);
    let c_coeffs = poly_div_zh(&phi_coeffs, n_trace);
    let mut padded = c_coeffs;
    padded.resize(n, F::zero());
    domain.fft(&padded)
}

pub mod fri;
pub mod streaming;
pub mod deep_tower;
pub mod deep;
pub mod cubic_ext;
pub mod tower_field;
pub mod sextic_ext;
pub mod octic_ext;
pub mod air_workloads;
pub mod sha256_air;
pub mod sha512_air;
pub mod ed25519_field;
pub mod ed25519_field_air;
pub mod ed25519_group;
pub mod ed25519_group_air;
pub mod ed25519_scalar;
pub mod ed25519_scalar_air;
pub mod ed25519_scalar_mult_air;
pub mod ed25519_verify;
pub mod ed25519_verify_air;
pub mod ed25519_air;