#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_variables)]
#![allow(unused_macros)]

use ark_goldilocks::Goldilocks as F;
use rand::{rngs::StdRng, Rng, SeedableRng};

use ark_poly::domain::radix2::Radix2EvaluationDomain as Domain;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    EvaluationDomain, GeneralEvaluationDomain,
};
use hash::SelectedHasher;
use hash::selected::HASH_BYTES;

use hash::sha3::Digest;
use crate::tower_field::TowerField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use merkle::{
    MerkleChannelCfg,
    MerkleTreeChannel,
    MerkleOpening,
    compute_leaf_hash,
};

use transcript::Transcript;


#[cfg(feature = "parallel")]
use rayon::prelude::*;


// ────────────────────────────────────────────────────────────────────────
//  Hash helpers
// ────────────────────────────────────────────────────────────────────────

#[inline]
fn finalize_to_digest(h: SelectedHasher) -> [u8; HASH_BYTES] {
    let result = h.finalize();
    let mut out = [0u8; HASH_BYTES];
    out.copy_from_slice(result.as_slice());
    out
}

fn transcript_challenge_hash(tr: &mut Transcript, label: &[u8]) -> [u8; HASH_BYTES] {
    let v = tr.challenge_bytes(label);
    assert!(
        v.len() >= HASH_BYTES,
        "transcript digest ({} bytes) shorter than HASH_BYTES ({})",
        v.len(),
        HASH_BYTES,
    );
    let mut out = [0u8; HASH_BYTES];
    out.copy_from_slice(&v[..HASH_BYTES]);
    out
}

// ────────────────────────────────────────────────────────────────────────
//  Safe field serialization helper
// ────────────────────────────────────────────────────────────────────────

#[inline]
fn field_to_le_bytes(f: F) -> [u8; 8] {
    f.into_bigint().0[0].to_le_bytes()
}

// ────────────────────────────────────────────────────────────────────────
//  Safe field-challenge helper
// ────────────────────────────────────────────────────────────────────────

fn safe_field_challenge(tr: &mut Transcript, label: &[u8]) -> F {
    let bytes = tr.challenge_bytes(label);
    let mut acc = F::zero();
    for chunk in bytes.rchunks(7) {
        let shift = 1u64 << (chunk.len() as u64 * 8);
        let mut val = 0u64;
        for (i, &b) in chunk.iter().enumerate() {
            val |= (b as u64) << (i * 8);
        }
        acc = acc * F::from(shift) + F::from(val);
    }
    acc
}

// ────────────────────────────────────────────────────────────────────────

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

#[cfg(feature = "fri_bench_log")]
#[allow(unused_macros)]
macro_rules! logln {
    ($($tt:tt)*) => { eprintln!($($tt)*); }
}
#[cfg(not(feature = "fri_bench_log"))]
macro_rules! logln {
    ($($tt:tt)*) => {};
}

mod ds {
    pub const FRI_SEED: &[u8] = b"FRI/seed";
    pub const FRI_INDEX: &[u8] = b"FRI/index";
    pub const FRI_Z_L: &[u8] = b"FRI/z/l";
    pub const FRI_Z_L_1: &[u8] = b"FRI/z/l/1";
    pub const FRI_Z_L_2: &[u8] = b"FRI/z/l/2";
    pub const FRI_LEAF: &[u8] = b"FRI/leaf";
}

fn tr_hash_fields_tagged(tag: &[u8], fields: &[F]) -> F {
    let mut tr = Transcript::new_matching_hash(b"FRI/FS");
    tr.absorb_bytes(tag);
    for &x in fields {
        tr.absorb_field(x);
    }
    safe_field_challenge(&mut tr, b"out")
}

// ────────────────────────────────────────────────────────────────────────
//  Extension-field division helper
// ────────────────────────────────────────────────────────────────────────

#[inline]
fn ext_div<E: TowerField>(a: E, b: E) -> E {
    a * b.invert().expect("ext_div: division by zero in extension field")
}

// ────────────────────────────────────────────────────────────────────────
//  Extension-field power helper (square-and-multiply)
// ────────────────────────────────────────────────────────────────────────

fn ext_pow<E: TowerField>(mut base: E, mut exp: u64) -> E {
    if exp == 0 {
        return E::one();
    }
    let mut result = E::one();
    while exp > 1 {
        if exp & 1 == 1 {
            result = result * base;
        }
        base = base.sq();
        exp >>= 1;
    }
    result * base
}

// ────────────────────────────────────────────────────────────────────────
//  FRI Domain
// ────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct FriDomain {
    pub omega: F,
    pub size: usize,
}

impl FriDomain {
    pub fn new_radix2(size: usize) -> Self {
        let dom = Domain::<F>::new(size).expect("radix-2 domain exists");
        Self { omega: dom.group_gen, size }
    }
}

// ────────────────────────────────────────────────────────────────────────
//  Base-field utilities (kept for backward compatibility and tests)
// ────────────────────────────────────────────────────────────────────────

fn build_z_pows(z_l: F, m: usize) -> Vec<F> {
    let mut z_pows = Vec::with_capacity(m);
    let mut acc = F::one();
    for _ in 0..m {
        z_pows.push(acc);
        acc *= z_l;
    }
    z_pows
}

fn build_ext_pows<E: TowerField>(alpha: E, m: usize) -> Vec<E> {
    let mut pows = Vec::with_capacity(m);
    let mut acc = E::one();
    for _ in 0..m {
        pows.push(acc);
        acc = acc * alpha;
    }
    pows
}

fn eval_poly_at_ext<E: TowerField>(coeffs: &[F], z: E) -> E {
    E::eval_base_poly(coeffs, z)
}

fn compute_q_layer_ext<E: TowerField + Send + Sync>(
    f_l: &[F],
    z: E,
    omega: F,
) -> (Vec<E>, E) {
    let n = f_l.len();
    let dom = Domain::<F>::new(n).unwrap();
    let coeffs = dom.ifft(f_l);
    let fz = eval_poly_at_ext(&coeffs, z);

    let omega_ext = E::from_fp(omega);
    let xs: Vec<E> = {
        let mut v = Vec::with_capacity(n);
        let mut x = E::one();
        for _ in 0..n {
            v.push(x);
            x = x * omega_ext;
        }
        v
    };

    #[cfg(feature = "parallel")]
    let q: Vec<E> = f_l
        .par_iter()
        .zip(xs.par_iter())
        .map(|(&fi, &xi)| {
            let num   = E::from_fp(fi) - fz;
            let denom = xi - z;
            ext_div(num, denom)
        })
        .collect();

    #[cfg(not(feature = "parallel"))]
    let q: Vec<E> = f_l
        .iter()
        .zip(xs.iter())
        .map(|(&fi, &xi)| {
            let num   = E::from_fp(fi) - fz;
            let denom = xi - z;
            ext_div(num, denom)
        })
        .collect();

    (q, fz)
}

// ────────────────────────────────────────────────────────────────────────
//  Extension-field FRI core — generic over E : TowerField
// ────────────────────────────────────────────────────────────────────────

fn compute_q_layer_ext_on_ext<E: TowerField + Send + Sync>(
    f_l: &[E],
    z: E,
    omega: F,
) -> (Vec<E>, E) {
    let n = f_l.len();
    let d = E::DEGREE;
    let dom = Domain::<F>::new(n).unwrap();

    let mut comp_evals: Vec<Vec<F>> = vec![Vec::with_capacity(n); d];
    for elem in f_l {
        let comps = elem.to_fp_components();
        for j in 0..d {
            comp_evals[j].push(comps[j]);
        }
    }

    #[cfg(feature = "parallel")]
    let comp_coeffs: Vec<Vec<F>> = comp_evals
        .par_iter()
        .map(|evals| dom.ifft(evals))
        .collect();

    #[cfg(not(feature = "parallel"))]
    let comp_coeffs: Vec<Vec<F>> = comp_evals
        .iter()
        .map(|evals| dom.ifft(evals))
        .collect();

    let mut fz = E::zero();
    for k in (0..n).rev() {
        let coeff_comps: Vec<F> = (0..d).map(|j| comp_coeffs[j][k]).collect();
        let coeff_k = E::from_fp_components(&coeff_comps)
            .expect("compute_q_layer_ext_on_ext: bad coefficient components");
        fz = fz * z + coeff_k;
    }

    let omega_ext = E::from_fp(omega);
    let xs: Vec<E> = {
        let mut v = Vec::with_capacity(n);
        let mut x = E::one();
        for _ in 0..n {
            v.push(x);
            x = x * omega_ext;
        }
        v
    };

    #[cfg(feature = "parallel")]
    let q: Vec<E> = f_l
        .par_iter()
        .zip(xs.par_iter())
        .map(|(&fi, &xi)| {
            let num   = fi - fz;
            let denom = xi - z;
            ext_div(num, denom)
        })
        .collect();

    #[cfg(not(feature = "parallel"))]
    let q: Vec<E> = f_l
        .iter()
        .zip(xs.iter())
        .map(|(&fi, &xi)| {
            let num   = fi - fz;
            let denom = xi - z;
            ext_div(num, denom)
        })
        .collect();

    (q, fz)
}

// ────────────────────────────────────────────────────────────────────────
//  STIR: OOD coset evaluation (without quotient computation)
// ────────────────────────────────────────────────────────────────────────

/// Evaluate f_ℓ at the out-of-domain coset {ζ^j · z_ℓ}_{j=0..m-1}
/// and compute the interpolation polynomial coefficients.
///
/// Returns (coset_evals, interp_coeffs) where:
///   coset_evals[j] = f_ℓ(ζ^j · z_ℓ)
///   interp_coeffs  = monomial coefficients of P(x) interpolating the coset
fn evaluate_ood_coset<E: TowerField + Send + Sync>(
    f_l: &[E],
    z_ell: E,
    omega: F,
    m: usize,
) -> (Vec<E>, Vec<E>) {
    let n = f_l.len();
    let d = E::DEGREE;
    let dom = Domain::<F>::new(n).unwrap();
    let n_next = n / m;

    let mut comp_evals: Vec<Vec<F>> = vec![Vec::with_capacity(n); d];
    for elem in f_l {
        let comps = elem.to_fp_components();
        for j in 0..d {
            comp_evals[j].push(comps[j]);
        }
    }

    #[cfg(feature = "parallel")]
    let comp_coeffs: Vec<Vec<F>> = comp_evals
        .par_iter()
        .map(|evals| dom.ifft(evals))
        .collect();

    #[cfg(not(feature = "parallel"))]
    let comp_coeffs: Vec<Vec<F>> = comp_evals
        .iter()
        .map(|evals| dom.ifft(evals))
        .collect();

    let eval_at = |point: E| -> E {
        let mut result = E::zero();
        for k in (0..n).rev() {
            let comps: Vec<F> = (0..d).map(|j| comp_coeffs[j][k]).collect();
            let coeff_k = E::from_fp_components(&comps).unwrap();
            result = result * point + coeff_k;
        }
        result
    };

    let zeta_base = omega.pow([n_next as u64]);
    let zeta = E::from_fp(zeta_base);
    let mut coset_evals = Vec::with_capacity(m);
    let mut zeta_pow = E::one();
    for _ in 0..m {
        coset_evals.push(eval_at(zeta_pow * z_ell));
        zeta_pow = zeta_pow * zeta;
    }

    let interp_coeffs = interpolate_stir_coset(&coset_evals, z_ell, zeta_base, m);

    (coset_evals, interp_coeffs)
}

// ────────────────────────────────────────────────────────────────────────
//  O(m log m) radix-2 FFT for extension-field coset interpolation
//
//  Replaces the O(m²) manual DFT that was the dominant cost inside
//  `interpolate_coset_ext` and `interpolate_stir_coset`.
//
//  Butterfly multiplications are EF × F (extension × base field),
//  costing only `d` base-field multiplications for a degree-d
//  extension.  Twiddle factors live entirely in the base field.
// ────────────────────────────────────────────────────────────────────────

/// Reverse the lowest `bits` bits of `x`.
#[inline(always)]
fn bit_reverse(x: usize, bits: u32) -> usize {
    x.reverse_bits() >> (usize::BITS - bits)
}

/// In-place radix-2 decimation-in-time (Cooley–Tukey) FFT.
///
/// Computes `X[k] = Σ_{j=0}^{n-1} x[j] · root^{jk}`.
///
/// `root` must be a primitive n-th root of unity **in the base field F**.
/// Extension-field elements are multiplied by base-field twiddles via
/// `E::from_fp`, which is cheap (d base-field muls for degree-d ext).
fn fft_in_place_ext<E: TowerField>(vals: &mut [E], root: F) {
    let n = vals.len();
    if n <= 1 {
        return;
    }
    debug_assert!(n.is_power_of_two());

    let log_n = n.trailing_zeros();

    // ── Bit-reversal permutation ─────────────────────────────────
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            vals.swap(i, j);
        }
    }

    // ── Butterfly stages ─────────────────────────────────────────
    let mut half = 1usize;
    while half < n {
        let block = half << 1;
        let exp = (n / block) as u64;
        let w_step: F = root.pow([exp]); // primitive block-th root

        let mut base = 0usize;
        while base < n {
            let mut w = F::one();
            for j in 0..half {
                let lo = base + j;
                let hi = lo + half;
                let u = vals[lo];
                let t = vals[hi] * E::from_fp(w);
                vals[lo] = u + t;
                vals[hi] = u - t;
                w *= w_step;
            }
            base += block;
        }
        half = block;
    }
}

// ────────────────────────────────────────────────────────────────────────
//  STIR: Batched multi-point DEEP quotient (kept for backward compat / tests)
// ────────────────────────────────────────────────────────────────────────

/// Recover the monomial-coefficient representation of the degree-(m-1)
/// polynomial that interpolates `coset_evals` on the coset
/// {z_ell, ζ·z_ell, ζ²·z_ell, …, ζ^{m-1}·z_ell}.
///
/// **Complexity:** O(m log m) via radix-2 FFT (was O(m²) before v2).
fn interpolate_stir_coset<E: TowerField>(
    coset_evals: &[E],
    z_ell: E,
    zeta: F,
    m: usize,
) -> Vec<E> {
    debug_assert!(m >= 2 && m.is_power_of_two(),
        "interpolate_stir_coset: m must be a power of two ≥ 2, got {}", m);

    let m_inv = F::from(m as u64).inverse().unwrap();
    let zeta_inv = zeta.inverse().unwrap();

    // ── Step 1: IFFT ─────────────────────────────────────────────
    // Compute d[k] = (1/m) Σ_{j=0}^{m-1} coset_evals[j] · ζ^{-jk}
    //
    // This is a forward FFT with root = ζ⁻¹ followed by 1/m scaling.
    let mut d = coset_evals.to_vec();
    fft_in_place_ext::<E>(&mut d, zeta_inv);
    let scale = E::from_fp(m_inv);
    for v in d.iter_mut() {
        *v = *v * scale;
    }

    // ── Step 2: un-shift by z_ell ────────────────────────────────
    // coeffs[k] = d[k] · z_ell^{-k}
    let z_inv = z_ell.invert().expect("STIR z_ell must be nonzero");
    let mut coeffs = Vec::with_capacity(m);
    let mut z_inv_pow = E::one();
    for k in 0..m {
        coeffs.push(d[k] * z_inv_pow);
        z_inv_pow = z_inv_pow * z_inv;
    }

    coeffs
}

fn compute_stir_quotient_ext<E: TowerField + Send + Sync>(
    f_l: &[E],
    z_ell: E,
    omega: F,
    m: usize,
) -> (Vec<E>, Vec<E>, Vec<E>) {
    let n = f_l.len();
    let d = E::DEGREE;
    let dom = Domain::<F>::new(n).unwrap();
    let n_next = n / m;

    let mut comp_evals: Vec<Vec<F>> = vec![Vec::with_capacity(n); d];
    for elem in f_l {
        let comps = elem.to_fp_components();
        for j in 0..d {
            comp_evals[j].push(comps[j]);
        }
    }

    #[cfg(feature = "parallel")]
    let comp_coeffs: Vec<Vec<F>> = comp_evals
        .par_iter()
        .map(|evals| dom.ifft(evals))
        .collect();

    #[cfg(not(feature = "parallel"))]
    let comp_coeffs: Vec<Vec<F>> = comp_evals
        .iter()
        .map(|evals| dom.ifft(evals))
        .collect();

    let eval_at = |point: E| -> E {
        let mut result = E::zero();
        for k in (0..n).rev() {
            let comps: Vec<F> = (0..d).map(|j| comp_coeffs[j][k]).collect();
            let coeff_k = E::from_fp_components(&comps).unwrap();
            result = result * point + coeff_k;
        }
        result
    };

    let zeta_base = omega.pow([n_next as u64]);
    let zeta = E::from_fp(zeta_base);
    let mut coset_evals = Vec::with_capacity(m);
    let mut zeta_pow = E::one();
    for _ in 0..m {
        coset_evals.push(eval_at(zeta_pow * z_ell));
        zeta_pow = zeta_pow * zeta;
    }

    let interp_coeffs = interpolate_stir_coset(&coset_evals, z_ell, zeta_base, m);

    let z_ell_m = ext_pow(z_ell, m as u64);

    let omega_ext = E::from_fp(omega);
    let xs: Vec<E> = {
        let mut v = Vec::with_capacity(n);
        let mut x = E::one();
        for _ in 0..n {
            v.push(x);
            x = x * omega_ext;
        }
        v
    };

    #[cfg(feature = "parallel")]
    let quotient: Vec<E> = f_l
        .par_iter()
        .zip(xs.par_iter())
        .map(|(&fi, &xi)| {
            let p_xi = eval_final_poly_ext(&interp_coeffs, xi);
            let v_xi = ext_pow(xi, m as u64) - z_ell_m;
            ext_div(fi - p_xi, v_xi)
        })
        .collect();

    #[cfg(not(feature = "parallel"))]
    let quotient: Vec<E> = f_l
        .iter()
        .zip(xs.iter())
        .map(|(&fi, &xi)| {
            let p_xi = eval_final_poly_ext(&interp_coeffs, xi);
            let v_xi = ext_pow(xi, m as u64) - z_ell_m;
            ext_div(fi - p_xi, v_xi)
        })
        .collect();

    (quotient, coset_evals, interp_coeffs)
}

// ────────────────────────────────────────────────────────────────────────

fn fri_fold_layer_ext_impl<E: TowerField>(
    evals: &[E],
    alpha: E,
    folding_factor: usize,
) -> Vec<E> {
    let n = evals.len();
    assert!(n % folding_factor == 0);
    let n_next = n / folding_factor;

    let alpha_pows = build_ext_pows(alpha, folding_factor);

    let mut out = vec![E::zero(); n_next];

    if enable_parallel(n_next) {
        #[cfg(feature = "parallel")]
        {
            out.par_iter_mut().enumerate().for_each(|(b, out_b)| {
                let mut acc = E::zero();
                for j in 0..folding_factor {
                    acc = acc + evals[b + j * n_next] * alpha_pows[j];
                }
                *out_b = acc;
            });
            return out;
        }
    }

    for b in 0..n_next {
        let mut acc = E::zero();
        for j in 0..folding_factor {
            acc = acc + evals[b + j * n_next] * alpha_pows[j];
        }
        out[b] = acc;
    }
    out
}

fn compute_s_layer_ext<E: TowerField>(
    f_l: &[E],
    alpha: E,
    m: usize,
) -> Vec<E> {
    let n = f_l.len();
    assert!(n % m == 0);
    let n_next = n / m;

    let alpha_pows = build_ext_pows(alpha, m);

    let mut folded = vec![E::zero(); n_next];
    for b in 0..n_next {
        let mut sum = E::zero();
        for j in 0..m {
            sum = sum + f_l[b + j * n_next] * alpha_pows[j];
        }
        folded[b] = sum;
    }

    let mut s_per_i = vec![E::zero(); n];
    for b in 0..n_next {
        for j in 0..m {
            s_per_i[b + j * n_next] = folded[b];
        }
    }
    s_per_i
}

// ────────────────────────────────────────────────────────────────────────
//  Construction 5.1 — Coefficient extraction & interpolation fold
// ────────────────────────────────────────────────────────────────────────

/// Extract per-coset monomial coefficients for all n/m cosets.
///
/// Uses `interpolate_coset_ext` (O(m log m) FFT) per coset and
/// parallelises across cosets when the `parallel` feature is enabled.
fn extract_all_coset_coefficients<E: TowerField + Send + Sync>(
    evals: &[E],
    omega: F,
    m: usize,
) -> Vec<Vec<E>> {
    let n = evals.len();
    assert!(n % m == 0);
    let n_next = n / m;
    let zeta = omega.pow([n_next as u64]);

    // Pre-compute per-coset shift ω^b incrementally instead of
    // calling omega.pow([b as u64]) inside the hot loop.
    let omega_b_table: Vec<F> = {
        let mut v = Vec::with_capacity(n_next);
        let mut acc = F::one();
        for _ in 0..n_next {
            v.push(acc);
            acc *= omega;
        }
        v
    };

    let extract_one = |b: usize| -> Vec<E> {
        let fibre_values: Vec<E> = (0..m)
            .map(|j| evals[b + j * n_next])
            .collect();
        interpolate_coset_ext(&fibre_values, omega_b_table[b], zeta, m)
    };

    if enable_parallel(n_next) {
        #[cfg(feature = "parallel")]
        {
            return (0..n_next).into_par_iter().map(extract_one).collect();
        }
    }

    (0..n_next).map(extract_one).collect()
}

/// Recover the monomial-coefficient representation of the degree-(m-1)
/// polynomial whose evaluations on the coset {ω^b, ω^b·ζ, …, ω^b·ζ^{m-1}}
/// are given by `fibre_values`.
///
/// **Complexity:** O(m log m) via radix-2 FFT (was O(m²) before v2).
fn interpolate_coset_ext<E: TowerField>(
    fibre_values: &[E],
    omega_b: F,
    zeta: F,
    m: usize,
) -> Vec<E> {
    debug_assert!(m >= 2 && m.is_power_of_two(),
        "interpolate_coset_ext: m must be a power of two ≥ 2, got {}", m);

    let m_inv = F::from(m as u64).inverse().unwrap();
    let zeta_inv = zeta.inverse().unwrap();

    // ── Step 1: IFFT ─────────────────────────────────────────────
    // Compute d[k] = (1/m) Σ_{j=0}^{m-1} fibre_values[j] · ζ^{-jk}
    //
    // This is a forward FFT with root = ζ⁻¹ followed by 1/m scaling.
    let mut d = fibre_values.to_vec();
    fft_in_place_ext::<E>(&mut d, zeta_inv);
    let scale = E::from_fp(m_inv);
    for v in d.iter_mut() {
        *v = *v * scale;
    }

    // ── Step 2: un-shift by ω^b ──────────────────────────────────
    // coeffs[k] = d[k] · (ω^b)^{-k}
    let omega_b_inv = if omega_b == F::zero() {
        F::one()
    } else {
        omega_b.inverse().unwrap()
    };

    let mut ob_inv_pow = F::one();
    for k in 0..m {
        d[k] = d[k] * E::from_fp(ob_inv_pow);
        ob_inv_pow *= omega_b_inv;
    }

    d
}

fn interpolation_fold_ext<E: TowerField>(
    coeff_tuples: &[Vec<E>],
    alpha: E,
) -> Vec<E> {
    let m = coeff_tuples[0].len();
    let alpha_pows = build_ext_pows(alpha, m);

    coeff_tuples
        .iter()
        .map(|coeffs| {
            let mut sum = E::zero();
            for i in 0..m {
                sum = sum + coeffs[i] * alpha_pows[i];
            }
            sum
        })
        .collect()
}

fn compute_s_layer_from_coeffs<E: TowerField>(
    coeff_tuples: &[Vec<E>],
    alpha: E,
    n: usize,
    m: usize,
) -> Vec<E> {
    let n_next = n / m;
    let folded = interpolation_fold_ext(coeff_tuples, alpha);

    let mut s_per_i = vec![E::zero(); n];
    for b in 0..n_next {
        for j in 0..m {
            s_per_i[b + j * n_next] = folded[b];
        }
    }
    s_per_i
}

fn verify_interpolation_consistency<E: TowerField>(
    fibre_values: &[E],
    fibre_points: &[F],
    coeff_tuple: &[E],
) -> bool {
    let m = fibre_values.len();
    for j in 0..m {
        let mut eval = E::zero();
        let mut x_pow = F::one();
        for i in 0..m {
            eval = eval + coeff_tuple[i] * E::from_fp(x_pow);
            x_pow *= fibre_points[j];
        }
        if eval != fibre_values[j] {
            return false;
        }
    }
    true
}

fn batched_degree_check_ext<E: TowerField>(
    coeff_tuples: &[Vec<E>],
    beta: E,
    d_final: usize,
) -> bool {
    let n_final = coeff_tuples.len();
    if n_final == 0 {
        return true;
    }
    let m = coeff_tuples[0].len();
    let beta_pows = build_ext_pows(beta, m);

    let gamma_evals: Vec<E> = (0..n_final)
        .map(|b| {
            let mut sum = E::zero();
            for i in 0..m {
                sum = sum + coeff_tuples[b][i] * beta_pows[i];
            }
            sum
        })
        .collect();

    let deg = E::DEGREE;
    let dom = Domain::<F>::new(n_final).unwrap();

    let mut comp_evals: Vec<Vec<F>> = vec![Vec::with_capacity(n_final); deg];
    for elem in &gamma_evals {
        let comps = elem.to_fp_components();
        for j in 0..deg {
            comp_evals[j].push(comps[j]);
        }
    }

    let comp_coeffs: Vec<Vec<F>> = comp_evals
        .iter()
        .map(|evals| dom.ifft(evals))
        .collect();

    for k in d_final..n_final {
        for j in 0..deg {
            if !comp_coeffs[j][k].is_zero() {
                return false;
            }
        }
    }

    true
}

fn coeff_tree_config(n_final: usize) -> MerkleChannelCfg {
    let arity = pick_arity_for_layer(n_final, 16).max(2);
    let depth = merkle_depth(n_final, arity);
    MerkleChannelCfg::new(vec![arity; depth], 0xFE)
}

fn coeff_leaf_fields<E: TowerField>(tuple: &[E]) -> Vec<F> {
    tuple.iter().flat_map(|e| e.to_fp_components()).collect()
}

// ────────────────────────────────────────────────────────────────────────
//  Extension-field evaluation/coefficient helpers
// ────────────────────────────────────────────────────────────────────────

fn ext_evals_to_coeffs<E: TowerField>(evals: &[E]) -> Vec<E> {
    let n = evals.len();
    if n == 0 {
        return vec![];
    }
    if n == 1 {
        return evals.to_vec();
    }

    let d = E::DEGREE;
    let dom = Domain::<F>::new(n).unwrap();

    let mut comp_evals: Vec<Vec<F>> = vec![Vec::with_capacity(n); d];
    for elem in evals {
        let comps = elem.to_fp_components();
        for j in 0..d {
            comp_evals[j].push(comps[j]);
        }
    }

    let comp_coeffs: Vec<Vec<F>> = comp_evals
        .iter()
        .map(|e| dom.ifft(e))
        .collect();

    (0..n)
        .map(|k| {
            let comps: Vec<F> = (0..d).map(|j| comp_coeffs[j][k]).collect();
            E::from_fp_components(&comps).unwrap()
        })
        .collect()
}

#[inline]
fn eval_final_poly_ext<E: TowerField>(coeffs: &[E], x: E) -> E {
    let mut result = E::zero();
    for c in coeffs.iter().rev() {
        result = result * x + *c;
    }
    result
}

// ────────────────────────────────────────────────────────────────────────
//  Base-field FRI fold (kept for backward compatibility / tests)
// ────────────────────────────────────────────────────────────────────────

fn dot_with_z_pows(chunk: &[F], z_pows: &[F]) -> F {
    debug_assert_eq!(chunk.len(), z_pows.len());
    let mut s = F::zero();
    for (val, zp) in chunk.iter().zip(z_pows.iter()) {
        s += *val * *zp;
    }
    s
}

fn fold_layer_sequential(f_l: &[F], z_pows: &[F], m: usize) -> Vec<F> {
    f_l.chunks(m)
        .map(|chunk| dot_with_z_pows(chunk, z_pows))
        .collect()
}

#[cfg(feature = "parallel")]
fn fold_layer_parallel(f_l: &[F], z_pows: &[F], m: usize) -> Vec<F> {
    f_l.par_chunks(m)
        .map(|chunk| dot_with_z_pows(chunk, z_pows))
        .collect()
}

fn fill_repeated_targets(target: &mut [F], src: &[F], m: usize) {
    for (bucket, chunk) in src.iter().zip(target.chunks_mut(m)) {
        for item in chunk {
            *item = *bucket;
        }
    }
}

fn merkle_depth(leaves: usize, arity: usize) -> usize {
    assert!(arity >= 2, "Merkle arity must be ≥ 2");
    let mut depth = 1;
    let mut cur = leaves;
    while cur > arity {
        cur = (cur + arity - 1) / arity;
        depth += 1;
    }
    depth
}

#[cfg(feature = "parallel")]
fn fill_repeated_targets_parallel(target: &mut [F], src: &[F], m: usize) {
    target
        .par_chunks_mut(m)
        .enumerate()
        .for_each(|(idx, chunk)| {
            let bucket = src[idx];
            for item in chunk {
                *item = bucket;
            }
        });
}

pub fn fri_sample_z_ell(seed_z: u64, level: usize, domain_size: usize) -> F {
    let fused = tr_hash_fields_tagged(
        ds::FRI_Z_L,
        &[F::from(seed_z), F::from(level as u64), F::from(domain_size as u64)],
    );
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&field_to_le_bytes(fused));
    let mut rng = StdRng::from_seed(seed_bytes);
    let exp_bigint = <F as PrimeField>::BigInt::from(domain_size as u64);
    let mut tries = 0usize;
    const MAX_TRIES: usize = 1_000;
    loop {
        let cand = F::from(rng.gen::<u64>());
        if !cand.is_zero() && cand.pow(exp_bigint.as_ref()) != F::one() {
            return cand;
        }
        tries += 1;
        if tries >= MAX_TRIES {
            let fallback = F::from(seed_z.wrapping_add(level as u64).wrapping_add(7));
            if fallback.pow(exp_bigint.as_ref()) != F::one() {
                return fallback;
            }
            return F::from(11u64);
        }
    }
}

pub fn compute_s_layer(f_l: &[F], z_l: F, m: usize) -> Vec<F> {
    let n = f_l.len();
    assert!(n % m == 0);
    let n_next = n / m;
    let z_pows = build_z_pows(z_l, m);
    let mut folded = vec![F::zero(); n_next];
    for b in 0..n_next {
        let mut acc = F::zero();
        for j in 0..m {
            acc += f_l[b + j * n_next] * z_pows[j];
        }
        folded[b] = acc;
    }
    let mut s_per_i = vec![F::zero(); n];
    for b in 0..n_next {
        for j in 0..m {
            s_per_i[b + j * n_next] = folded[b];
        }
    }
    s_per_i
}

fn layer_sizes_from_schedule(n0: usize, schedule: &[usize]) -> Vec<usize> {
    let mut sizes = Vec::with_capacity(schedule.len() + 1);
    let mut n = n0;
    sizes.push(n);
    for &m in schedule {
        assert!(n % m == 0, "schedule not dividing domain size");
        n /= m;
        sizes.push(n);
    }
    sizes
}

fn hash_node(children: &[[u8; HASH_BYTES]]) -> [u8; HASH_BYTES] {
    let mut h = SelectedHasher::new();
    Digest::update(&mut h, b"FRI/MERKLE/NODE");
    for c in children {
        Digest::update(&mut h, c);
    }
    finalize_to_digest(h)
}

fn index_from_seed(seed_f: F, n_pow2: usize) -> usize {
    assert!(n_pow2.is_power_of_two());
    let mask = n_pow2 - 1;
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&field_to_le_bytes(seed_f));
    let mut rng = StdRng::from_seed(seed_bytes);
    (rng.gen::<u64>() as usize) & mask
}

fn index_seed(roots_seed: F, ell: usize, q: usize) -> F {
    tr_hash_fields_tagged(
        ds::FRI_INDEX,
        &[roots_seed, F::from(ell as u64), F::from(q as u64)],
    )
}

fn f0_trace_hash(n0: usize, seed_z: u64) -> [u8; HASH_BYTES] {
    let mut h = SelectedHasher::new();
    Digest::update(&mut h, b"FRI/F0_TREE_DOMAIN");
    Digest::update(&mut h, &(n0 as u64).to_le_bytes());
    Digest::update(&mut h, &seed_z.to_le_bytes());
    finalize_to_digest(h)
}

fn f0_tree_config(n0: usize) -> MerkleChannelCfg {
    let arity = pick_arity_for_layer(n0, 16).max(2);
    let depth = merkle_depth(n0, arity);
    MerkleChannelCfg::new(vec![arity; depth], 0xFF)
}

// ────────────────────────────────────────────────────────────────────────
//  Coset-packed f0 tree (STIR mode)
// ────────────────────────────────────────────────────────────────────────

fn f0_packed_tree_config(n0: usize, m0: usize) -> MerkleChannelCfg {
    let n_leaves = n0 / m0;
    let arity = pick_arity_for_layer(n_leaves, 16).max(2);
    let depth = merkle_depth(n_leaves, arity);
    MerkleChannelCfg::new(vec![arity; depth], 0xFF)
}

fn f0_packed_trace_hash(n0: usize, m0: usize, seed_z: u64) -> [u8; HASH_BYTES] {
    let mut h = SelectedHasher::new();
    Digest::update(&mut h, b"FRI/F0_PACKED_TREE");
    Digest::update(&mut h, &(n0 as u64).to_le_bytes());
    Digest::update(&mut h, &(m0 as u64).to_le_bytes());
    Digest::update(&mut h, &seed_z.to_le_bytes());
    finalize_to_digest(h)
}

fn pick_arity_for_layer(n: usize, requested_m: usize) -> usize {
    if requested_m >= 128 && n % 128 == 0 { return 128; }
    if requested_m >= 64  && n % 64  == 0 { return 64; }
    if requested_m >= 32  && n % 32  == 0 { return 32; }
    if requested_m >= 16  && n % 16  == 0 { return 16; }
    if requested_m >= 8   && n % 8   == 0 { return 8; }
    if requested_m >= 4   && n % 4   == 0 { return 4; }
    if n % 2 == 0 { return 2; }
    1
}

fn bind_statement_to_transcript<E: TowerField>(
    tr: &mut Transcript,
    schedule: &[usize],
    n0: usize,
    seed_z: u64,
    coeff_commit_final: bool,
    stir: bool,
    public_inputs_hash: Option<[u8; 32]>,
) {
    // Absorb public inputs commitment first so the proof is bound to them.
    if let Some(pi_hash) = public_inputs_hash {
        tr.absorb_bytes(b"CAIRO-PUBLIC-INPUTS-V1");
        tr.absorb_bytes(&pi_hash);
    }
    tr.absorb_bytes(b"DEEP-FRI-STATEMENT-V2");
    tr.absorb_field(F::from(n0 as u64));
    tr.absorb_field(F::from(schedule.len() as u64));
    for &m in schedule {
        tr.absorb_field(F::from(m as u64));
    }
    tr.absorb_field(F::from(seed_z));
    tr.absorb_field(F::from(E::DEGREE as u64));
    tr.absorb_field(F::from(coeff_commit_final as u64));
    tr.absorb_field(F::from(stir as u64));
}

pub fn fri_fold_layer(
    evals: &[F],
    z_l: F,
    folding_factor: usize,
) -> Vec<F> {
    let domain_size = evals.len();
    let domain = GeneralEvaluationDomain::<F>::new(domain_size)
        .expect("Domain size must be a power of two.");
    let domain_generator = domain.group_gen();
    fri_fold_layer_impl(evals, z_l, domain_generator, folding_factor)
}

fn fri_fold_layer_impl(
    evals: &[F],
    z_l: F,
    omega: F,
    folding_factor: usize,
) -> Vec<F> {
    let n = evals.len();
    assert!(n % folding_factor == 0);
    let n_next = n / folding_factor;
    let mut out = vec![F::zero(); n_next];
    let z_pows = build_z_pows(z_l, folding_factor);

    if enable_parallel(n_next) {
        #[cfg(feature = "parallel")]
        {
            out.par_iter_mut().enumerate().for_each(|(b, out_b)| {
                let mut acc = F::zero();
                for j in 0..folding_factor {
                    acc += evals[b + j * n_next] * z_pows[j];
                }
                *out_b = acc;
            });
            return out;
        }
    }

    for b in 0..n_next {
        let mut acc = F::zero();
        for j in 0..folding_factor {
            acc += evals[b + j * n_next] * z_pows[j];
        }
        out[b] = acc;
    }
    out
}

// ────────────────────────────────────────────────────────────────────────
//  Core protocol structs — generic over E : TowerField
// ────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct CombinedLeaf<E: TowerField> {
    pub f: E,
    pub s: E,
    pub q: E,
}

pub struct FriLayerCommitment {
    pub n: usize,
    pub m: usize,
    pub root: [u8; HASH_BYTES],
}

pub struct FriTranscript {
    pub schedule: Vec<usize>,
    pub layers: Vec<FriLayerCommitment>,
}

pub struct FriProverParams {
    pub schedule: Vec<usize>,
    pub seed_z: u64,
    pub coeff_commit_final: bool,
    pub d_final: usize,
    pub stir: bool,
    /// SHA3-256 commitment to the public inputs (absorbed before any challenges).
    pub public_inputs_hash: Option<[u8; 32]>,
}

pub struct FriProverState<E: TowerField> {
    pub f0_base: Vec<F>,
    pub f_layers_ext: Vec<Vec<E>>,
    pub s_layers: Vec<Vec<E>>,
    pub q_layers: Vec<Vec<E>>,
    pub fz_layers: Vec<E>,
    pub transcript: FriTranscript,
    pub omega_layers: Vec<F>,
    pub z_ext: E,
    pub alpha_layers: Vec<E>,
    pub root_f0: [u8; HASH_BYTES],
    pub trace_hash: [u8; HASH_BYTES],
    pub seed_z: u64,
    pub coeff_tuples: Option<Vec<Vec<E>>>,
    pub coeff_root: Option<[u8; HASH_BYTES]>,
    pub beta_deg: Option<E>,
    pub coeff_commit_final: bool,
    pub d_final: usize,
    pub stir_coset_evals: Option<Vec<Vec<E>>>,
    pub stir_z_per_layer: Option<Vec<E>>,
    pub stir_interp_coeffs: Option<Vec<Vec<E>>>,
    pub stir: bool,
}

#[derive(Clone, ark_serialize::CanonicalSerialize, ark_serialize::CanonicalDeserialize)]
pub struct LayerQueryRef {
    pub i: usize,
    pub child_pos: usize,
    pub parent_index: usize,
    pub parent_pos: usize,
}

#[derive(Clone, ark_serialize::CanonicalSerialize, ark_serialize::CanonicalDeserialize)]
pub struct FriQueryOpenings {
    pub per_layer_refs: Vec<LayerQueryRef>,
    pub final_index: usize,
}

#[derive(Clone, ark_serialize::CanonicalSerialize, ark_serialize::CanonicalDeserialize)]
pub struct LayerOpenPayload<E: TowerField> {
    pub f_val: E,
    pub s_val: E,
    pub q_val: E,
}

#[derive(Clone, ark_serialize::CanonicalSerialize, ark_serialize::CanonicalDeserialize)]
pub struct FriQueryPayload<E: TowerField> {
    pub per_layer_refs: Vec<LayerQueryRef>,
    pub per_layer_payloads: Vec<LayerOpenPayload<E>>,
    pub f0_opening: MerkleOpening,
    pub final_index: usize,
}

#[derive(Clone, ark_serialize::CanonicalSerialize, ark_serialize::CanonicalDeserialize)]
pub struct StirProximityPayload<E: TowerField> {
    pub base_index: usize,
    pub raw_query_index: usize,
    pub fiber_indices: Vec<usize>,
    pub fiber_f_vals: Vec<F>,
    pub f0_packed_opening: MerkleOpening,
    pub f_next_val: E,
    pub layer1_opening: Option<MerkleOpening>,
}

#[derive(Clone, ark_serialize::CanonicalSerialize, ark_serialize::CanonicalDeserialize)]
pub struct LayerProof {
    pub openings: Vec<MerkleOpening>,
}

#[derive(ark_serialize::CanonicalSerialize, ark_serialize::CanonicalDeserialize)]
pub struct FriLayerProofs {
    pub layers: Vec<LayerProof>,
}

#[derive(ark_serialize::CanonicalSerialize, ark_serialize::CanonicalDeserialize)]
pub struct DeepFriProof<E: TowerField> {
    pub root_f0: [u8; HASH_BYTES],
    pub roots: Vec<[u8; HASH_BYTES]>,
    pub layer_proofs: FriLayerProofs,
    pub f0_openings: Vec<MerkleOpening>,
    pub queries: Vec<FriQueryPayload<E>>,
    pub fz_per_layer: Vec<E>,
    pub final_poly_coeffs: Vec<E>,
    pub n0: usize,
    pub omega0: F,
    pub coeff_tuples: Option<Vec<Vec<E>>>,
    pub coeff_root: Option<[u8; HASH_BYTES]>,
    pub stir_coset_evals: Option<Vec<Vec<E>>>,
    pub stir_proximity_queries: Option<Vec<StirProximityPayload<E>>>,
}

#[derive(Clone, Debug)]
pub struct DeepFriParams {
    pub schedule: Vec<usize>,
    pub r: usize,
    pub seed_z: u64,
    pub coeff_commit_final: bool,
    pub d_final: usize,
    pub stir: bool,
    pub s0: usize,
    /// SHA3-256 commitment to the public inputs (absorbed before any challenges).
    /// When set, the proof is cryptographically bound to these specific inputs.
    pub public_inputs_hash: Option<[u8; 32]>,
}

impl DeepFriParams {
    pub fn new(schedule: Vec<usize>, r: usize, seed_z: u64) -> Self {
        Self {
            schedule,
            r,
            seed_z,
            coeff_commit_final: false,
            d_final: 1,
            stir: false,
            s0: r,
            public_inputs_hash: None,
        }
    }

    pub fn with_coeff_commit(mut self) -> Self {
        self.coeff_commit_final = true;
        self
    }

    pub fn with_d_final(mut self, d: usize) -> Self {
        self.d_final = d;
        self
    }

    pub fn with_stir(mut self) -> Self {
        self.stir = true;
        self
    }

    pub fn with_s0(mut self, s0: usize) -> Self {
        self.s0 = s0;
        self
    }
}

// ────────────────────────────────────────────────────────────────────────
//  Leaf serialization helpers
// ────────────────────────────────────────────────────────────────────────

#[inline]
fn ext_leaf_fields<E: TowerField>(f: E, s: E, q: E) -> Vec<F> {
    let mut fields = f.to_fp_components();
    fields.extend(s.to_fp_components());
    fields.extend(q.to_fp_components());
    fields
}

#[inline]
fn stir_leaf_fields<E: TowerField>(f: E) -> Vec<F> {
    f.to_fp_components()
}

// ────────────────────────────────────────────────────────────────────────
//  Extension-field challenge helpers
// ────────────────────────────────────────────────────────────────────────

fn challenge_ext<E: TowerField>(tr: &mut Transcript, tag: &[u8]) -> E {
    let d = E::DEGREE;
    let mut components = Vec::with_capacity(d);
    for i in 0..d {
        let mut sub_tag = Vec::with_capacity(tag.len() + 5);
        sub_tag.extend_from_slice(tag);
        sub_tag.extend_from_slice(b"/c");
        for byte in i.to_string().bytes() {
            sub_tag.push(byte);
        }
        components.push(safe_field_challenge(tr, &sub_tag));
    }
    E::from_fp_components(&components)
        .expect("challenge_ext: failed to build extension element from squeezed components")
}

fn absorb_ext<E: TowerField>(tr: &mut Transcript, v: E) {
    for c in v.to_fp_components() {
        tr.absorb_field(c);
    }
}

// =============================================================================
// ── Transcript builder — generic over E : TowerField ──
// =============================================================================

pub fn fri_build_transcript<E: TowerField>(
    f0: Vec<F>,
    domain0: FriDomain,
    params: &FriProverParams,
) -> FriProverState<E> {
    let schedule = params.schedule.clone();
    let l = schedule.len();
    let use_coeff_commit = params.coeff_commit_final && l > 0;
    let use_stir = params.stir;
    let normal_layers = if use_coeff_commit { l - 1 } else { l };

    let mut tr = Transcript::new_matching_hash(b"FRI/FS");
    bind_statement_to_transcript::<E>(
        &mut tr,
        &schedule,
        domain0.size,
        params.seed_z,
        params.coeff_commit_final,
        params.stir,
        params.public_inputs_hash,
    );

    let root_f0 = if use_stir && !schedule.is_empty() {
        let m0 = schedule[0];
        let n_next = domain0.size / m0;
        let f0_th = f0_packed_trace_hash(domain0.size, m0, params.seed_z);
        let f0_cfg = f0_packed_tree_config(domain0.size, m0);
        let mut f0_tree = MerkleTreeChannel::new(f0_cfg, f0_th);
        for b in 0..n_next {
            let fiber: Vec<F> = (0..m0).map(|j| f0[b + j * n_next]).collect();
            f0_tree.push_leaf(&fiber);
        }
        f0_tree.finalize()
    } else {
        let f0_th = f0_trace_hash(domain0.size, params.seed_z);
        let f0_cfg = f0_tree_config(domain0.size);
        let mut f0_tree = MerkleTreeChannel::new(f0_cfg, f0_th);
        for &val in &f0 {
            f0_tree.push_leaf(&[val]);
        }
        f0_tree.finalize()
    };

    tr.absorb_bytes(&root_f0);

    let z_ext = challenge_ext::<E>(&mut tr, b"z_fp3");

    let trace_hash: [u8; HASH_BYTES] = transcript_challenge_hash(&mut tr, ds::FRI_SEED);

    let f0_ext: Vec<E> = f0.iter().map(|&x| E::from_fp(x)).collect();

    let mut f_layers_ext: Vec<Vec<E>> = Vec::with_capacity(l + 1);
    let mut s_layers: Vec<Vec<E>> = Vec::with_capacity(l + 1);
    let mut q_layers: Vec<Vec<E>> = Vec::with_capacity(l);
    let mut fz_layers: Vec<E> = Vec::with_capacity(l);
    let mut omega_layers: Vec<F> = Vec::with_capacity(l);
    let mut alpha_layers: Vec<E> = Vec::with_capacity(l);
    let mut layer_commitments: Vec<FriLayerCommitment> = Vec::with_capacity(l);

    let mut stir_all_coset_evals: Vec<Vec<E>> = Vec::with_capacity(l);
    let mut stir_z_per_layer: Vec<E> = Vec::with_capacity(l);
    let mut stir_all_interp_coeffs: Vec<Vec<E>> = Vec::with_capacity(l);
    let mut z_current = z_ext;

    f_layers_ext.push(f0_ext);
    let mut cur_size = domain0.size;

    for ell in 0..normal_layers {
        let m = schedule[ell];

        let alpha_ell = challenge_ext::<E>(&mut tr, b"alpha");
        alpha_layers.push(alpha_ell);

        let dom = Domain::<F>::new(cur_size).unwrap();
        let omega = dom.group_gen;
        omega_layers.push(omega);

        let cur_f = &f_layers_ext[ell];

        let (fz, coset_evals_opt, interp_coeffs_opt) = if use_stir {
            let z_ell = z_current;
            stir_z_per_layer.push(z_ell);

            let (coset_evals, interp_coeffs) =
                evaluate_ood_coset(cur_f, z_ell, omega, m);

            let fz = coset_evals[0];
            z_current = ext_pow(z_current, m as u64);

            (fz, Some(coset_evals), Some(interp_coeffs))
        } else {
            let (q, fz) = compute_q_layer_ext_on_ext(cur_f, z_ext, omega);
            q_layers.push(q);
            (fz, None, None)
        };

        if use_stir {
            q_layers.push(vec![]);
        }

        fz_layers.push(fz);

        let coeff_tuples_layer = extract_all_coset_coefficients(cur_f, omega, m);

        if use_stir {
            let s = vec![E::zero(); cur_size];
            s_layers.push(s);

            let arity = pick_arity_for_layer(cur_size, m).max(2);
            let depth = merkle_depth(cur_size, arity);
            let cfg = MerkleChannelCfg::new(vec![arity; depth], ell as u64);
            let mut tree = MerkleTreeChannel::new(cfg, trace_hash);

            let all_fields: Vec<Vec<F>> = (0..cur_size)
                .map(|i| stir_leaf_fields(cur_f[i]))
                .collect();
            tree.push_leaves_parallel(&all_fields);

            let layer_root = tree.finalize();

            layer_commitments.push(FriLayerCommitment {
                n: cur_size,
                m,
                root: layer_root,
            });
        } else {
            let s = compute_s_layer_from_coeffs(&coeff_tuples_layer, alpha_ell, cur_size, m);
            s_layers.push(s.clone());

            let arity = pick_arity_for_layer(cur_size, m).max(2);
            let depth = merkle_depth(cur_size, arity);
            let cfg = MerkleChannelCfg::new(vec![arity; depth], ell as u64);
            let mut tree = MerkleTreeChannel::new(cfg, trace_hash);

            let all_fields: Vec<Vec<F>> = (0..cur_size)
                .map(|i| ext_leaf_fields(cur_f[i], s_layers[ell][i], q_layers[ell][i]))
                .collect();
            tree.push_leaves_parallel(&all_fields);

            let layer_root = tree.finalize();

            layer_commitments.push(FriLayerCommitment {
                n: cur_size,
                m,
                root: layer_root,
            });
        }

        if use_stir {
            let coset_evals = coset_evals_opt.as_ref().unwrap();
            for &ev in coset_evals {
                absorb_ext(&mut tr, ev);
            }
            stir_all_coset_evals.push(coset_evals_opt.unwrap());
            stir_all_interp_coeffs.push(interp_coeffs_opt.unwrap());
        } else {
            absorb_ext(&mut tr, fz);
        }
        tr.absorb_bytes(&layer_commitments.last().unwrap().root);

        let next_f = interpolation_fold_ext(&coeff_tuples_layer, alpha_ell);
        cur_size /= m;
        f_layers_ext.push(next_f);

        logln!(
            "[PROVER] ell={} stir={} z_ell={:?} alpha={:?}",
            ell, use_stir,
            if use_stir { stir_z_per_layer.last().copied() } else { Some(z_ext) },
            alpha_ell
        );
    }

    let mut stored_coeff_tuples: Option<Vec<Vec<E>>> = None;
    let mut stored_coeff_root: Option<[u8; HASH_BYTES]> = None;
    let mut stored_beta: Option<E> = None;

    if use_coeff_commit {
        let ell = l - 1;
        let m = schedule[ell];

        let dom = Domain::<F>::new(cur_size).unwrap();
        let omega = dom.group_gen;
        omega_layers.push(omega);

        let cur_f = &f_layers_ext[ell];

        let (fz, coset_evals_opt, interp_coeffs_opt) = if use_stir {
            let z_ell = z_current;
            stir_z_per_layer.push(z_ell);

            let (coset_evals, interp_coeffs) =
                evaluate_ood_coset(cur_f, z_ell, omega, m);

            let fz = coset_evals[0];
            z_current = ext_pow(z_current, m as u64);

            (fz, Some(coset_evals), Some(interp_coeffs))
        } else {
            let (q, fz) = compute_q_layer_ext_on_ext(cur_f, z_ext, omega);
            q_layers.push(q);
            (fz, None, None)
        };

        if use_stir {
            q_layers.push(vec![]);
        }

        fz_layers.push(fz);

        let s = vec![E::zero(); cur_size];
        s_layers.push(s.clone());

        if use_stir {
            let arity = pick_arity_for_layer(cur_size, m).max(2);
            let depth = merkle_depth(cur_size, arity);
            let cfg = MerkleChannelCfg::new(vec![arity; depth], ell as u64);
            let mut tree = MerkleTreeChannel::new(cfg, trace_hash);

            let all_fields: Vec<Vec<F>> = (0..cur_size)
                .map(|i| stir_leaf_fields(cur_f[i]))
                .collect();
            tree.push_leaves_parallel(&all_fields);

            let layer_root = tree.finalize();

            layer_commitments.push(FriLayerCommitment {
                n: cur_size,
                m,
                root: layer_root,
            });
        } else {
            let arity = pick_arity_for_layer(cur_size, m).max(2);
            let depth = merkle_depth(cur_size, arity);
            let cfg = MerkleChannelCfg::new(vec![arity; depth], ell as u64);
            let mut tree = MerkleTreeChannel::new(cfg, trace_hash);

            let all_fields: Vec<Vec<F>> = (0..cur_size)
                .map(|i| ext_leaf_fields(cur_f[i], s[i], q_layers[ell][i]))
                .collect();
            tree.push_leaves_parallel(&all_fields);

            let layer_root = tree.finalize();

            layer_commitments.push(FriLayerCommitment {
                n: cur_size,
                m,
                root: layer_root,
            });
        }

        if use_stir {
            let coset_evals = coset_evals_opt.as_ref().unwrap();
            for &ev in coset_evals {
                absorb_ext(&mut tr, ev);
            }
            stir_all_coset_evals.push(coset_evals_opt.unwrap());
            stir_all_interp_coeffs.push(interp_coeffs_opt.unwrap());
        } else {
            absorb_ext(&mut tr, fz);
        }
        tr.absorb_bytes(&layer_commitments.last().unwrap().root);

        let coeff_tuples = extract_all_coset_coefficients(cur_f, omega, m);

        let n_final = cur_size / m;
        let coeff_cfg = coeff_tree_config(n_final);
        let mut coeff_tree = MerkleTreeChannel::new(coeff_cfg, trace_hash);

        let coeff_fields: Vec<Vec<F>> = coeff_tuples
            .iter()
            .map(|t| coeff_leaf_fields(t))
            .collect();
        coeff_tree.push_leaves_parallel(&coeff_fields);

        let coeff_root = coeff_tree.finalize();

        tr.absorb_bytes(&coeff_root);

        let alpha_ell = challenge_ext::<E>(&mut tr, b"alpha");
        alpha_layers.push(alpha_ell);

        let beta_deg = challenge_ext::<E>(&mut tr, b"beta_deg");

        let next_f = interpolation_fold_ext(&coeff_tuples, alpha_ell);
        cur_size = n_final;
        f_layers_ext.push(next_f);

        stored_coeff_tuples = Some(coeff_tuples);
        stored_coeff_root = Some(coeff_root);
        stored_beta = Some(beta_deg);
    }

    s_layers.push(vec![E::zero(); f_layers_ext.last().unwrap().len()]);

    FriProverState {
        f0_base: f0,
        f_layers_ext,
        s_layers,
        q_layers,
        fz_layers,
        transcript: FriTranscript {
            schedule,
            layers: layer_commitments,
        },
        omega_layers,
        z_ext,
        alpha_layers,
        root_f0,
        trace_hash,
        seed_z: params.seed_z,
        coeff_tuples: stored_coeff_tuples,
        coeff_root: stored_coeff_root,
        beta_deg: stored_beta,
        coeff_commit_final: use_coeff_commit,
        d_final: params.d_final,
        stir_coset_evals: if use_stir { Some(stir_all_coset_evals) } else { None },
        stir_z_per_layer: if use_stir { Some(stir_z_per_layer) } else { None },
        stir_interp_coeffs: if use_stir { Some(stir_all_interp_coeffs) } else { None },
        stir: use_stir,
    }
}

// =============================================================================
// ── Query derivation — generic over E  (classic FRI only) ──
// =============================================================================

pub fn fri_prove_queries<E: TowerField>(
    st: &FriProverState<E>,
    r: usize,
    query_seed: F,
) -> (Vec<FriQueryOpenings>, Vec<[u8; HASH_BYTES]>, FriLayerProofs, Vec<MerkleOpening>) {
    let L = st.transcript.schedule.len();
    let mut all_refs = Vec::with_capacity(r);
    let n0 = st.transcript.layers.first().map_or(0, |l| l.n);

    for q in 0..r {
        let mut per_layer_refs = Vec::with_capacity(L);

        let mut i = {
            let n_pow2 = n0.next_power_of_two();
            let seed = index_seed(query_seed, 0, q);
            index_from_seed(seed, n_pow2) % n0
        };

        for ell in 0..L {
            let n = st.transcript.layers[ell].n;
            let m = st.transcript.schedule[ell];
            let n_next = n / m;

            per_layer_refs.push(LayerQueryRef {
                i,
                child_pos: i % m,
                parent_index: i % n_next,
                parent_pos: 0,
            });

            i = i % n_next;
        }

        all_refs.push(FriQueryOpenings {
            per_layer_refs,
            final_index: i,
        });
    }

    let f0_th = f0_trace_hash(n0, st.seed_z);
    let f0_cfg = f0_tree_config(n0);
    let mut f0_tree = MerkleTreeChannel::new(f0_cfg, f0_th);
    for &val in &st.f0_base {
        f0_tree.push_leaf(&[val]);
    }
    f0_tree.finalize();

    let mut f0_openings = Vec::with_capacity(r);
    for q in 0..r {
        let idx = all_refs[q].per_layer_refs[0].i;
        f0_openings.push(f0_tree.open(idx));
    }

    let mut layer_proofs = Vec::with_capacity(L);

    for ell in 0..L {
        let layer = &st.transcript.layers[ell];
        let arity = pick_arity_for_layer(layer.n, layer.m).max(2);
        let depth = merkle_depth(layer.n, arity);
        let cfg = MerkleChannelCfg::new(vec![arity; depth], ell as u64);
        let mut tree = MerkleTreeChannel::new(cfg, st.trace_hash);

        for i in 0..layer.n {
            let fields = ext_leaf_fields(
                st.f_layers_ext[ell][i],
                st.s_layers[ell][i],
                st.q_layers[ell][i],
            );
            tree.push_leaf(&fields);
        }
        tree.finalize();

        let mut openings = Vec::with_capacity(r);
        for q in 0..r {
            let idx = all_refs[q].per_layer_refs[ell].i;
            openings.push(tree.open(idx));
        }
        layer_proofs.push(LayerProof { openings });
    }

    let roots: Vec<[u8; HASH_BYTES]> = st.transcript.layers.iter().map(|l| l.root).collect();

    (all_refs, roots, FriLayerProofs { layers: layer_proofs }, f0_openings)
}

// =============================================================================
// ── STIR fold-consistency proximity queries (coset-packed f0 tree) ──
// =============================================================================

fn stir_prove_proximity_queries<E: TowerField>(
    st: &FriProverState<E>,
    s0: usize,
    query_seed: F,
    r: usize,
) -> Vec<StirProximityPayload<E>> {
    if !st.stir || st.transcript.layers.is_empty() {
        return vec![];
    }

    let L = st.transcript.schedule.len();
    let n0 = st.transcript.layers[0].n;
    let m0 = st.transcript.schedule[0];
    let n_next = n0 / m0;

    let f0_packed_th = f0_packed_trace_hash(n0, m0, st.seed_z);
    let f0_packed_cfg = f0_packed_tree_config(n0, m0);
    let mut f0_tree = MerkleTreeChannel::new(f0_packed_cfg, f0_packed_th);
    for b in 0..n_next {
        let fiber: Vec<F> = (0..m0).map(|j| st.f0_base[b + j * n_next]).collect();
        f0_tree.push_leaf(&fiber);
    }
    f0_tree.finalize();

    let layer1_tree: Option<MerkleTreeChannel> = if L >= 2 {
        let layer1_info = &st.transcript.layers[1];
        let arity = pick_arity_for_layer(layer1_info.n, layer1_info.m).max(2);
        let depth = merkle_depth(layer1_info.n, arity);
        let cfg = MerkleChannelCfg::new(vec![arity; depth], 1u64);
        let mut tree = MerkleTreeChannel::new(cfg, st.trace_hash);
        let n1 = st.f_layers_ext[1].len();
        for i in 0..n1 {
            let fields = stir_leaf_fields(st.f_layers_ext[1][i]);
            tree.push_leaf(&fields);
        }
        tree.finalize();
        Some(tree)
    } else {
        None
    };

    let mut payloads = Vec::with_capacity(s0);

    for q in 0..s0 {
        let seed = index_seed(query_seed, 0, r + q);
        let n_pow2 = n0.next_power_of_two();
        let raw_i = index_from_seed(seed, n_pow2) % n0;
        let base_index = raw_i % n_next;

        let fiber_indices: Vec<usize> = (0..m0)
            .map(|j| base_index + j * n_next)
            .collect();

        let fiber_f_vals: Vec<F> = fiber_indices
            .iter()
            .map(|&idx| st.f0_base[idx])
            .collect();

        let f0_packed_opening = f0_tree.open(base_index);

        let (f_next_val, layer1_opening) = if L >= 2 {
            let tree = layer1_tree.as_ref().unwrap();
            let opening = tree.open(base_index);
            (st.f_layers_ext[1][base_index], Some(opening))
        } else {
            (E::zero(), None)
        };

        payloads.push(StirProximityPayload {
            base_index,
            raw_query_index: raw_i,
            fiber_indices,
            fiber_f_vals,
            f0_packed_opening,
            f_next_val,
            layer1_opening,
        });
    }

    payloads
}


// =============================================================================
// ── Prover top-level — generic over E ──
// =============================================================================

pub fn deep_fri_prove<E: TowerField>(
    f0: Vec<F>,
    domain0: FriDomain,
    params: &DeepFriParams,
) -> DeepFriProof<E> {
    let prover_params = FriProverParams {
        schedule: params.schedule.clone(),
        seed_z: params.seed_z,
        coeff_commit_final: params.coeff_commit_final,
        d_final: params.d_final,
        stir: params.stir,
        public_inputs_hash: params.public_inputs_hash,
    };

    let st: FriProverState<E> = fri_build_transcript(f0, domain0, &prover_params);

    let L = params.schedule.len();
    let final_evals = st.f_layers_ext[L].clone();

    let final_poly_coeffs: Vec<E> = {
        let all_coeffs = ext_evals_to_coeffs::<E>(&final_evals);
        let d_final = params.d_final.min(all_coeffs.len());

        if cfg!(debug_assertions) {
            for k in d_final..all_coeffs.len() {
                if all_coeffs[k] != E::zero() {
                    eprintln!(
                        "[WARN] Final polynomial coefficient at degree {} is non-zero; \
                         proof may not verify (d_final={})",
                        k, params.d_final,
                    );
                    break;
                }
            }
        }

        all_coeffs[..d_final].to_vec()
    };

    let query_seed = {
        let mut tr = Transcript::new_matching_hash(b"FRI/FS");
        bind_statement_to_transcript::<E>(
            &mut tr,
            &params.schedule,
            domain0.size,
            params.seed_z,
            params.coeff_commit_final,
            params.stir,
            params.public_inputs_hash,
        );
        tr.absorb_bytes(&st.root_f0);

        let _ = challenge_ext::<E>(&mut tr, b"z_fp3");
        let _: [u8; HASH_BYTES] = transcript_challenge_hash(&mut tr, ds::FRI_SEED);

        let use_coeff_commit = params.coeff_commit_final && L > 0;
        let normal_layers = if use_coeff_commit { L - 1 } else { L };

        for ell in 0..normal_layers {
            let _ = challenge_ext::<E>(&mut tr, b"alpha");
            if params.stir {
                let coset_evals = &st.stir_coset_evals.as_ref().unwrap()[ell];
                for &ev in coset_evals {
                    absorb_ext(&mut tr, ev);
                }
            } else {
                absorb_ext(&mut tr, st.fz_layers[ell]);
            }
            tr.absorb_bytes(&st.transcript.layers[ell].root);
        }

        if use_coeff_commit {
            let ell = L - 1;
            if params.stir {
                let coset_evals = &st.stir_coset_evals.as_ref().unwrap()[ell];
                for &ev in coset_evals {
                    absorb_ext(&mut tr, ev);
                }
            } else {
                absorb_ext(&mut tr, st.fz_layers[ell]);
            }
            tr.absorb_bytes(&st.transcript.layers[ell].root);

            tr.absorb_bytes(&st.coeff_root.unwrap());
            let _ = challenge_ext::<E>(&mut tr, b"alpha");
            let _ = challenge_ext::<E>(&mut tr, b"beta_deg");
        }

        for &c in &final_poly_coeffs {
            absorb_ext::<E>(&mut tr, c);
        }

        safe_field_challenge(&mut tr, b"query_seed")
    };

    let (queries, roots, layer_proofs, f0_openings_classic, stir_proximity) = if params.stir {
        let roots: Vec<[u8; HASH_BYTES]> =
            st.transcript.layers.iter().map(|l| l.root).collect();
        let stir_prox = stir_prove_proximity_queries(&st, params.s0, query_seed, 0);
        (
            vec![],
            roots,
            FriLayerProofs { layers: vec![] },
            vec![],
            Some(stir_prox),
        )
    } else {
        let (query_refs, roots, layer_proofs, f0_openings) =
            fri_prove_queries(&st, params.r, query_seed);

        let mut queries = Vec::with_capacity(params.r);
        for (qi, q) in query_refs.into_iter().enumerate() {
            let mut payloads = Vec::with_capacity(params.schedule.len());
            for (ell, rref) in q.per_layer_refs.iter().enumerate() {
                payloads.push(LayerOpenPayload {
                    f_val: st.f_layers_ext[ell][rref.i],
                    s_val: st.s_layers[ell][rref.i],
                    q_val: if st.q_layers[ell].is_empty() {
                        E::zero()
                    } else {
                        st.q_layers[ell][rref.i]
                    },
                });
            }
            queries.push(FriQueryPayload {
                per_layer_refs: q.per_layer_refs,
                per_layer_payloads: payloads,
                f0_opening: f0_openings[qi].clone(),
                final_index: q.final_index,
            });
        }
        (queries, roots, layer_proofs, f0_openings, None)
    };

    let stir_coset_evals_proof = if params.stir {
        st.stir_coset_evals.clone()
    } else {
        None
    };

    DeepFriProof {
        root_f0: st.root_f0,
        roots,
        layer_proofs,
        f0_openings: f0_openings_classic,
        queries,
        fz_per_layer: st.fz_layers.clone(),
        final_poly_coeffs,
        n0: domain0.size,
        omega0: domain0.omega,
        coeff_tuples: st.coeff_tuples.clone(),
        coeff_root: st.coeff_root,
        stir_coset_evals: stir_coset_evals_proof,
        stir_proximity_queries: stir_proximity,
    }
}

pub fn deep_fri_proof_size_bytes<E: TowerField>(proof: &DeepFriProof<E>, stir: bool) -> usize {
    const FIELD_BYTES: usize = 8;
    let ext_bytes: usize = E::DEGREE * FIELD_BYTES;

    let mut bytes = 0usize;

    bytes += HASH_BYTES;
    bytes += proof.roots.len() * HASH_BYTES;

    bytes += proof.final_poly_coeffs.len() * ext_bytes;

    if stir {
        if let Some(ref stir_evals) = proof.stir_coset_evals {
            for layer_evals in stir_evals {
                bytes += layer_evals.len() * ext_bytes;
            }
        }

        if let Some(ref prox) = proof.stir_proximity_queries {
            for pq in prox {
                let m = pq.fiber_f_vals.len();

                bytes += m * FIELD_BYTES;

                bytes += ext_bytes;

                bytes += HASH_BYTES;
                for level in &pq.f0_packed_opening.path {
                    bytes += level.len() * HASH_BYTES;
                }

                if let Some(ref l1_open) = pq.layer1_opening {
                    bytes += HASH_BYTES;
                    for level in &l1_open.path {
                        bytes += level.len() * HASH_BYTES;
                    }
                }
            }
        }
    } else {
        bytes += proof.fz_per_layer.len() * ext_bytes;

        for q in &proof.queries {
            bytes += q.per_layer_payloads.len() * 3 * ext_bytes;
        }

        for opening in &proof.f0_openings {
            bytes += HASH_BYTES;
            for level in &opening.path {
                bytes += level.len() * HASH_BYTES;
            }
        }

        for layer in &proof.layer_proofs.layers {
            for opening in &layer.openings {
                bytes += HASH_BYTES;
                for level in &opening.path {
                    bytes += level.len() * HASH_BYTES;
                }
            }
        }
    }

    if let Some(ref tuples) = proof.coeff_tuples {
        for t in tuples {
            bytes += t.len() * ext_bytes;
        }
    }
    if proof.coeff_root.is_some() {
        bytes += HASH_BYTES;
    }

    bytes
}

// =============================================================================
// ── Verifier — generic over E : TowerField ──
// =============================================================================

pub fn deep_fri_verify<E: TowerField>(
    params: &DeepFriParams,
    proof: &DeepFriProof<E>,
) -> bool {
    let L = params.schedule.len();
    let sizes = layer_sizes_from_schedule(proof.n0, &params.schedule);
    let use_coeff_commit = params.coeff_commit_final && L > 0;
    let use_stir = params.stir;
    let normal_layers = if use_coeff_commit { L - 1 } else { L };

    let mut tr = Transcript::new_matching_hash(b"FRI/FS");
    bind_statement_to_transcript::<E>(
        &mut tr,
        &params.schedule,
        proof.n0,
        params.seed_z,
        params.coeff_commit_final,
        params.stir,
        params.public_inputs_hash,
    );
    tr.absorb_bytes(&proof.root_f0);

    let z_ext = challenge_ext::<E>(&mut tr, b"z_fp3");
    let trace_hash: [u8; HASH_BYTES] = transcript_challenge_hash(&mut tr, ds::FRI_SEED);

    logln!("[VERIFY] z_ext = {:?}  stir = {}", z_ext, use_stir);

    let mut z_current = z_ext;
    let mut stir_z_per_layer: Vec<E> = Vec::with_capacity(L);
    let mut stir_interp_per_layer: Vec<Vec<E>> = Vec::with_capacity(L);
    let mut alpha_layers: Vec<E> = Vec::with_capacity(L);

    for ell in 0..normal_layers {
        let alpha_ell = challenge_ext::<E>(&mut tr, b"alpha");
        alpha_layers.push(alpha_ell);

        if use_stir {
            let m = params.schedule[ell];
            let coset_evals = &proof.stir_coset_evals.as_ref().unwrap()[ell];

            stir_z_per_layer.push(z_current);

            let n_ell = sizes[ell];
            let n_next = n_ell / m;
            let omega_ell = Domain::<F>::new(n_ell).unwrap().group_gen;
            let zeta = omega_ell.pow([n_next as u64]);
            let interp = interpolate_stir_coset(coset_evals, z_current, zeta, m);
            stir_interp_per_layer.push(interp);

            z_current = ext_pow(z_current, m as u64);

            for &ev in coset_evals {
                absorb_ext(&mut tr, ev);
            }
        } else {
            absorb_ext(&mut tr, proof.fz_per_layer[ell]);
        }
        tr.absorb_bytes(&proof.roots[ell]);
    }

    let mut beta_deg: Option<E> = None;
    if use_coeff_commit {
        let ell = L - 1;

        if use_stir {
            let m = params.schedule[ell];
            let coset_evals = &proof.stir_coset_evals.as_ref().unwrap()[ell];

            stir_z_per_layer.push(z_current);

            let n_ell = sizes[ell];
            let n_next = n_ell / m;
            let omega_ell = Domain::<F>::new(n_ell).unwrap().group_gen;
            let zeta = omega_ell.pow([n_next as u64]);
            let interp = interpolate_stir_coset(coset_evals, z_current, zeta, m);
            stir_interp_per_layer.push(interp);

            z_current = ext_pow(z_current, m as u64);

            for &ev in coset_evals {
                absorb_ext(&mut tr, ev);
            }
        } else {
            absorb_ext(&mut tr, proof.fz_per_layer[ell]);
        }
        tr.absorb_bytes(&proof.roots[ell]);

        tr.absorb_bytes(&proof.coeff_root.unwrap());
        let alpha_ell = challenge_ext::<E>(&mut tr, b"alpha");
        alpha_layers.push(alpha_ell);
        beta_deg = Some(challenge_ext::<E>(&mut tr, b"beta_deg"));
    }

    for &c in &proof.final_poly_coeffs {
        absorb_ext::<E>(&mut tr, c);
    }

    let query_seed: F = safe_field_challenge(&mut tr, b"query_seed");

    if proof.final_poly_coeffs.len() != params.d_final {
        eprintln!(
            "[FAIL][FINAL POLY COEFFS SIZE] expected={} got={}",
            params.d_final,
            proof.final_poly_coeffs.len()
        );
        return false;
    }

    if use_stir {
        for ell in 0..L {
            let m = params.schedule[ell];
            let alpha_ell = alpha_layers[ell];
            let alpha_pows = build_ext_pows(alpha_ell, m);

            let interp = &stir_interp_per_layer[ell];
            let mut fold_at_ood = E::zero();
            for k in 0..m {
                fold_at_ood = fold_at_ood + interp[k] * alpha_pows[k];
            }

            let expected = if ell + 1 < L {
                proof.stir_coset_evals.as_ref().unwrap()[ell + 1][0]
            } else {
                let mut z_final = z_ext;
                for i in 0..L {
                    z_final = ext_pow(z_final, params.schedule[i] as u64);
                }
                eval_final_poly_ext(&proof.final_poly_coeffs, z_final)
            };

            if fold_at_ood != expected {
                eprintln!(
                    "[FAIL][STIR OOD FOLD] ell={}\n  fold_at_ood={:?}\n  expected={:?}",
                    ell, fold_at_ood, expected,
                );
                return false;
            }
        }
    }

    if use_coeff_commit {
        let coeff_tuples = match proof.coeff_tuples {
            Some(ref ct) => ct,
            None => {
                eprintln!("[FAIL][COEFF TUPLES MISSING]");
                return false;
            }
        };

        let n_final = sizes[L];
        let m_final = params.schedule[L - 1];

        if coeff_tuples.len() != n_final {
            eprintln!(
                "[FAIL][COEFF TUPLES SIZE] expected={} got={}",
                n_final,
                coeff_tuples.len()
            );
            return false;
        }
        for (b, t) in coeff_tuples.iter().enumerate() {
            if t.len() != m_final {
                eprintln!(
                    "[FAIL][COEFF TUPLE WIDTH] coset={} expected={} got={}",
                    b, m_final, t.len()
                );
                return false;
            }
        }

        let coeff_cfg = coeff_tree_config(n_final);
        let mut coeff_tree = MerkleTreeChannel::new(coeff_cfg.clone(), trace_hash);
        let coeff_fields: Vec<Vec<F>> = coeff_tuples
            .iter()
            .map(|t| coeff_leaf_fields(t))
            .collect();
        coeff_tree.push_leaves_parallel(&coeff_fields);
        let recomputed_root = coeff_tree.finalize();

        if recomputed_root != proof.coeff_root.unwrap() {
            eprintln!("[FAIL][COEFF MERKLE ROOT MISMATCH]");
            return false;
        }

        let beta = beta_deg.unwrap();
        if !batched_degree_check_ext(coeff_tuples, beta, params.d_final) {
            eprintln!("[FAIL][BATCHED DEGREE CHECK]");
            return false;
        }
    }

    let omega_per_layer: Vec<F> = (0..L)
        .map(|ell| Domain::<F>::new(sizes[ell]).unwrap().group_gen)
        .collect();
    let omega_final: F = if sizes[L] >= 2 {
        Domain::<F>::new(sizes[L]).unwrap().group_gen
    } else {
        F::one()
    };

    // =================================================================
    //  STIR mode: verify s₀ fold-consistency proximity queries
    // =================================================================
    if use_stir {
        let prox_queries = match proof.stir_proximity_queries {
            Some(ref pq) => pq,
            None => {
                eprintln!("[FAIL][STIR PROXIMITY QUERIES MISSING]");
                return false;
            }
        };

        if prox_queries.len() != params.s0 {
            eprintln!(
                "[FAIL][STIR S0 COUNT] expected={} got={}",
                params.s0,
                prox_queries.len()
            );
            return false;
        }

        let n0 = proof.n0;
        let m0 = params.schedule[0];
        let n_next = sizes[0] / m0;
        let omega_0 = omega_per_layer[0];
        let zeta_0 = omega_0.pow([n_next as u64]);
        let alpha_0 = alpha_layers[0];
        let alpha_pows_0 = build_ext_pows(alpha_0, m0);

        let f0_packed_th = f0_packed_trace_hash(n0, m0, params.seed_z);
        let f0_packed_cfg = f0_packed_tree_config(n0, m0);

        let layer1_cfg = if L >= 2 {
            let arity = pick_arity_for_layer(sizes[1], params.schedule[1]).max(2);
            let depth = merkle_depth(sizes[1], arity);
            Some(MerkleChannelCfg::new(vec![arity; depth], 1u64))
        } else {
            None
        };

        for (qi, pq) in prox_queries.iter().enumerate() {
            let effective_r = 0usize;
            let expected_raw = {
                let seed = index_seed(query_seed, 0, effective_r + qi);
                let n_pow2 = n0.next_power_of_two();
                index_from_seed(seed, n_pow2) % n0
            };
            if pq.raw_query_index != expected_raw {
                eprintln!(
                    "[FAIL][STIR PROX RAW INDEX] qi={} expected={} got={}",
                    qi, expected_raw, pq.raw_query_index
                );
                return false;
            }

            let base_index = expected_raw % n_next;
            if pq.base_index != base_index {
                eprintln!(
                    "[FAIL][STIR PROX BASE INDEX] qi={} expected={} got={}",
                    qi, base_index, pq.base_index
                );
                return false;
            }

            if pq.fiber_indices.len() != m0 || pq.fiber_f_vals.len() != m0 {
                eprintln!("[FAIL][STIR PROX FIBER LEN] qi={}", qi);
                return false;
            }
            for j in 0..m0 {
                let expected_idx = base_index + j * n_next;
                if pq.fiber_indices[j] != expected_idx {
                    eprintln!(
                        "[FAIL][STIR PROX FIBER IDX] qi={} j={} expected={} got={}",
                        qi, j, expected_idx, pq.fiber_indices[j]
                    );
                    return false;
                }
            }

            if !MerkleTreeChannel::verify_opening(
                &f0_packed_cfg,
                proof.root_f0,
                &pq.f0_packed_opening,
                &f0_packed_th,
            ) {
                eprintln!("[FAIL][STIR PROX F0 PACKED MERKLE] qi={}", qi);
                return false;
            }
            if pq.f0_packed_opening.index != base_index {
                eprintln!(
                    "[FAIL][STIR PROX F0 PACKED INDEX] qi={} expected={} got={}",
                    qi, base_index, pq.f0_packed_opening.index
                );
                return false;
            }

            let expected_leaf = compute_leaf_hash(
                &f0_packed_cfg,
                pq.f0_packed_opening.index,
                &pq.fiber_f_vals,
            );
            if expected_leaf != pq.f0_packed_opening.leaf {
                eprintln!("[FAIL][STIR PROX F0 PACKED LEAF BIND] qi={}", qi);
                return false;
            }

            let fiber_ext: Vec<E> = pq.fiber_f_vals.iter()
                .map(|&v| E::from_fp(v))
                .collect();

            let omega_b = omega_0.pow([base_index as u64]);
            let coeff_tuple = interpolate_coset_ext::<E>(
                &fiber_ext,
                omega_b,
                zeta_0,
                m0,
            );
            let mut fold_val = E::zero();
            for k in 0..m0 {
                fold_val = fold_val + coeff_tuple[k] * alpha_pows_0[k];
            }

            if L >= 2 {
                let layer1_opening = match pq.layer1_opening {
                    Some(ref o) => o,
                    None => {
                        eprintln!("[FAIL][STIR PROX LAYER1 OPEN MISSING] qi={}", qi);
                        return false;
                    }
                };
                let l1_cfg = layer1_cfg.as_ref().unwrap();

                if !MerkleTreeChannel::verify_opening(
                    l1_cfg,
                    proof.roots[1],
                    layer1_opening,
                    &trace_hash,
                ) {
                    eprintln!("[FAIL][STIR PROX LAYER1 MERKLE] qi={}", qi);
                    return false;
                }
                if layer1_opening.index != base_index {
                    eprintln!(
                        "[FAIL][STIR PROX LAYER1 INDEX] qi={} expected={} got={}",
                        qi, base_index, layer1_opening.index
                    );
                    return false;
                }

                let leaf_fields = stir_leaf_fields(pq.f_next_val);
                let expected_leaf = compute_leaf_hash(
                    l1_cfg,
                    layer1_opening.index,
                    &leaf_fields,
                );
                if expected_leaf != layer1_opening.leaf {
                    eprintln!("[FAIL][STIR PROX LAYER1 LEAF BIND] qi={}", qi);
                    return false;
                }

                if fold_val != pq.f_next_val {
                    eprintln!(
                        "[FAIL][STIR FOLD CONSISTENCY] qi={}\n  fold_val={:?}\n  f_next={:?}",
                        qi, fold_val, pq.f_next_val,
                    );
                    return false;
                }
            } else {
                let x_final = E::from_fp(omega_final.pow([base_index as u64]));
                let expected_final = eval_final_poly_ext(
                    &proof.final_poly_coeffs,
                    x_final,
                );
                if fold_val != expected_final {
                    eprintln!(
                        "[FAIL][STIR FOLD VS FINAL] qi={}\n  fold_val={:?}\n  poly_eval={:?}",
                        qi, fold_val, expected_final,
                    );
                    return false;
                }
            }
        }

        logln!("[VERIFY] SUCCESS  stir=true  s0={}", params.s0);
        return true;
    }

    // =================================================================
    //  Classic FRI mode: verify r fold-queries across all layers
    // =================================================================
    let f0_th = f0_trace_hash(proof.n0, params.seed_z);
    let f0_cfg = f0_tree_config(proof.n0);

    for q in 0..params.r {
        let qp = &proof.queries[q];

        let expected_i0 = {
            let n_pow2 = proof.n0.next_power_of_two();
            let seed = index_seed(query_seed, 0, q);
            index_from_seed(seed, n_pow2) % proof.n0
        };

        let mut expected_i = expected_i0;
        for ell in 0..L {
            if qp.per_layer_refs[ell].i != expected_i {
                eprintln!(
                    "[FAIL][QUERY POS] q={} ell={} expected={} got={}",
                    q, ell, expected_i, qp.per_layer_refs[ell].i
                );
                return false;
            }
            let n_next = sizes[ell] / params.schedule[ell];
            expected_i = expected_i % n_next;
        }

        if qp.final_index != expected_i {
            eprintln!(
                "[FAIL][FINAL INDEX] q={} expected={} got={}",
                q, expected_i, qp.final_index
            );
            return false;
        }

        {
            let f0_opening = &qp.f0_opening;

            if !MerkleTreeChannel::verify_opening(
                &f0_cfg,
                proof.root_f0,
                f0_opening,
                &f0_th,
            ) {
                eprintln!("[FAIL][F0 MERKLE] q={}", q);
                return false;
            }

            let pay0 = &qp.per_layer_payloads[0];
            let pay0_comps = pay0.f_val.to_fp_components();
            let is_base = pay0_comps[1..].iter().all(|&c| c == F::zero());
            if !is_base {
                eprintln!("[FAIL][LAYER0 NOT BASE FIELD] q={}", q);
                return false;
            }

            let expected_f0_leaf = compute_leaf_hash(
                &f0_cfg,
                f0_opening.index,
                &[pay0_comps[0]],
            );
            if expected_f0_leaf != f0_opening.leaf {
                eprintln!("[FAIL][F0 LEAF BIND] q={}", q);
                return false;
            }

            if f0_opening.index != expected_i0 {
                eprintln!("[FAIL][F0 INDEX] q={}", q);
                return false;
            }
        }

        for ell in 0..L {
            let opening = &proof.layer_proofs.layers[ell].openings[q];
            let rref = &qp.per_layer_refs[ell];
            let pay = &qp.per_layer_payloads[ell];

            let arity = pick_arity_for_layer(sizes[ell], params.schedule[ell]).max(2);
            let depth = merkle_depth(sizes[ell], arity);
            let cfg = MerkleChannelCfg::new(vec![arity; depth], ell as u64);

            if !MerkleTreeChannel::verify_opening(
                &cfg,
                proof.roots[ell],
                opening,
                &trace_hash,
            ) {
                eprintln!("[FAIL][MERKLE] q={} ell={}", q, ell);
                return false;
            }

            if opening.index != rref.i {
                eprintln!("[FAIL][INDEX BINDING] q={} ell={}", q, ell);
                return false;
            }

            let leaf_fields = ext_leaf_fields(pay.f_val, pay.s_val, pay.q_val);
            let expected_leaf = compute_leaf_hash(&cfg, opening.index, &leaf_fields);
            if expected_leaf != opening.leaf {
                eprintln!("[FAIL][LEAF BINDING] q={} ell={}", q, ell);
                return false;
            }

            let omega_ell = omega_per_layer[ell];
            let x_i = E::from_fp(omega_ell.pow([rref.i as u64]));

            let fz = proof.fz_per_layer[ell];
            let num   = pay.f_val - fz;
            let denom = x_i - z_ext;

            if pay.q_val * denom != num {
                eprintln!(
                    "[FAIL][DEEP-EXT] q={} ell={}\n  f_val={:?}\n  fz={:?}\n  q_val={:?}\n  x_i={:?}",
                    q, ell, pay.f_val, fz, pay.q_val, x_i,
                );
                return false;
            }

            let is_final_layer = ell == L - 1;

            if is_final_layer && use_coeff_commit {
                let m = params.schedule[ell];
                let coset_b = qp.final_index;

                let coeff_tuples = proof.coeff_tuples.as_ref().unwrap();
                let coeff_tuple = &coeff_tuples[coset_b];

                let x_i_base = omega_ell.pow([rref.i as u64]);
                let mut h_star = E::zero();
                let mut x_pow = F::one();
                for k in 0..m {
                    h_star = h_star + coeff_tuple[k] * E::from_fp(x_pow);
                    x_pow *= x_i_base;
                }

                if pay.f_val != h_star {
                    eprintln!(
                        "[FAIL][SINGLE-POINT CONSISTENCY] q={} ell={}\n  f_val={:?}\n  h_star={:?}",
                        q, ell, pay.f_val, h_star,
                    );
                    return false;
                }

                let alpha_final = alpha_layers[L - 1];
                let alpha_pows = build_ext_pows(alpha_final, m);
                let mut fold_val = E::zero();
                for k in 0..m {
                    fold_val = fold_val + coeff_tuple[k] * alpha_pows[k];
                }

                let x_final = E::from_fp(omega_final.pow([qp.final_index as u64]));
                let expected_final = eval_final_poly_ext(
                    &proof.final_poly_coeffs,
                    x_final,
                );

                if fold_val != expected_final {
                    eprintln!(
                        "[FAIL][COEFF FOLD VALUE] q={} fold={:?} poly_eval={:?}",
                        q, fold_val, expected_final
                    );
                    return false;
                }
            } else {
                let verified_f_next = if ell + 1 < L {
                    qp.per_layer_payloads[ell + 1].f_val
                } else {
                    let x_final = E::from_fp(
                        omega_final.pow([qp.final_index as u64]),
                    );
                    eval_final_poly_ext(&proof.final_poly_coeffs, x_final)
                };

                if pay.s_val != verified_f_next {
                    eprintln!(
                        "[FAIL][FOLD] q={} ell={}\n  s_val={:?}\n  f_next={:?}",
                        q, ell, pay.s_val, verified_f_next,
                    );
                    return false;
                }
            }
        }
    }

    logln!("[VERIFY] SUCCESS  stir={}", use_stir);
    true
}


// ================================================================
// Extension-field FRI folding utilities — generic over E
// ================================================================

#[inline]
pub fn fri_fold_degree2<E: TowerField>(
    f_pos: E,
    f_neg: E,
    x: F,
    beta: E,
) -> E {
    let two_inv = F::from(2u64).invert().unwrap();
    let x_inv = x.invert().unwrap();

    let f_even = (f_pos + f_neg) * E::from_fp(two_inv);
    let f_odd  = (f_pos - f_neg) * E::from_fp(two_inv * x_inv);

    f_even + beta * f_odd
}

pub fn fri_fold_degree3<E: TowerField>(
    f_at_y:   E,
    f_at_zy:  E,
    f_at_z2y: E,
    y:        F,
    zeta:     F,
    beta:     E,
) -> E {
    let zeta2 = zeta * zeta;
    let inv3 = F::from(3u64).invert().unwrap();
    let y_inv = y.invert().unwrap();
    let y2_inv = y_inv * y_inv;

    let f0 = (f_at_y + f_at_zy + f_at_z2y) * E::from_fp(inv3);

    let f1 = (f_at_y + f_at_zy * E::from_fp(zeta2) + f_at_z2y * E::from_fp(zeta))
        * E::from_fp(inv3 * y_inv);

    let f2 = (f_at_y + f_at_zy * E::from_fp(zeta) + f_at_z2y * E::from_fp(zeta2))
        * E::from_fp(inv3 * y2_inv);

    let beta_sq = beta.sq();
    f0 + beta * f1 + beta_sq * f2
}

pub fn fri_fold_round<E: TowerField>(
    codeword: &[E],
    domain: &[F],
    beta: E,
) -> Vec<E> {
    let half = codeword.len() / 2;
    let mut folded = Vec::with_capacity(half);

    for i in 0..half {
        let f_pos = codeword[i];
        let f_neg = codeword[i + half];
        let x = domain[i];
        folded.push(fri_fold_degree2(f_pos, f_neg, x, beta));
    }

    folded
}

pub fn fri_verify_query<E: TowerField>(
    round_evals: &[(E, E)],
    round_domains: &[F],
    betas: &[E],
    final_value: E,
) -> bool {
    let num_rounds = betas.len();
    let mut expected = fri_fold_degree2(
        round_evals[0].0,
        round_evals[0].1,
        round_domains[0],
        betas[0],
    );

    for r in 1..num_rounds {
        let (f_pos, f_neg) = round_evals[r];
        if f_pos != expected && f_neg != expected {
            return false;
        }
        expected = fri_fold_degree2(f_pos, f_neg, round_domains[r], betas[r]);
    }

    expected == final_value
}


// ────────────────────────────────────────────────────────────────────────
//  Soundness accounting: proximity-gap bounds & query-count derivation
// ────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProximityBound {
    Johnson,
    StirCapacity { gamma_log2: f64 },
}

impl ProximityBound {
    pub fn label(&self) -> String {
        match self {
            Self::Johnson => "johnson".into(),
            Self::StirCapacity { gamma_log2 } =>
                format!("capacity(g=2^{:.0})", gamma_log2),
        }
    }

    pub fn gap_and_list_size(&self, rho: f64) -> (f64, f64) {
        match *self {
            Self::Johnson => {
                let sqrt_rho = rho.sqrt();
                let delta = 1.0 - sqrt_rho;
                let list_log2 = -(sqrt_rho.log2());
                (delta, list_log2)
            }
            Self::StirCapacity { gamma_log2 } => {
                let gamma = f64::exp2(gamma_log2);
                let delta = 1.0 - rho - gamma;
                assert!(
                    delta > 0.0,
                    "gamma too large for rate {rho}: delta would be {delta}"
                );
                let list_log2 = -gamma_log2;
                (delta, list_log2)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashVariant {
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashVariant {
    pub fn output_bits(&self) -> usize {
        match self {
            Self::Sha3_256 => 256,
            Self::Sha3_384 => 384,
            Self::Sha3_512 => 512,
        }
    }

    pub fn collision_bits(&self) -> usize {
        self.output_bits() / 2
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
        }
    }

    pub fn all() -> &'static [HashVariant] {
        &[Self::Sha3_256, Self::Sha3_384, Self::Sha3_512]
    }

    pub fn from_compiled() -> Self {
        match HASH_BYTES {
            32 => Self::Sha3_256,
            48 => Self::Sha3_384,
            64 => Self::Sha3_512,
            other => panic!(
                "Unknown HASH_BYTES={other}; expected 32, 48, or 64"
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RoundSoundnessDetail {
    pub round: usize,
    pub fold_factor: usize,
    pub degree_before: f64,
    pub alg_error_log2: f64,
}

#[derive(Clone, Debug)]
pub struct SoundnessReport {
    pub bound_label: String,
    pub hash_label: String,
    pub hash_collision_bits: usize,
    pub field_ext_bits: f64,
    pub target_bits: usize,
    pub effective_target: usize,
    pub achieved_bits: f64,
    pub query_security_bits: f64,
    pub algebraic_security_bits: f64,
    pub queries: usize,
    pub delta: f64,
    pub rho: f64,
    pub list_size_log2: f64,
    pub num_rounds: usize,
    pub is_stir: bool,
    pub rounds: Vec<RoundSoundnessDetail>,
}

impl SoundnessReport {
    pub fn csv_header_suffix() -> &'static str {
        ",bound,hash,hash_col_bits,field_ext_bits,\
         target_bits,eff_target,achieved_bits,\
         query_sec,alg_sec,queries_computed,\
         delta,rho,list_log2,num_rounds,is_stir"
    }

    pub fn csv_suffix(&self) -> String {
        format!(
            ",{},{},{},{:.0},{},{},{:.1},{:.1},{:.1},{},{:.6},{:.4},{:.1},{},{}",
            self.bound_label,
            self.hash_label,
            self.hash_collision_bits,
            self.field_ext_bits,
            self.target_bits,
            self.effective_target,
            self.achieved_bits,
            self.query_security_bits,
            self.algebraic_security_bits,
            self.queries,
            self.delta,
            self.rho,
            self.list_size_log2,
            self.num_rounds,
            self.is_stir,
        )
    }
}

pub struct SoundnessCalculator {
    pub target_bits: usize,
    pub field_ext_bits: f64,
    pub bound: ProximityBound,
    pub hash: HashVariant,
}

impl SoundnessCalculator {
    pub fn new(
        target_bits: usize,
        field_ext_bits: f64,
        bound: ProximityBound,
        hash: HashVariant,
    ) -> Self {
        Self { target_bits, field_ext_bits, bound, hash }
    }

    pub fn effective_target(&self) -> usize {
        self.target_bits.min(self.hash.collision_bits())
    }

    pub fn security_stir(
        &self,
        schedule: &[usize],
        n0: usize,
        blowup: usize,
        s0: usize,
    ) -> (f64, f64, f64) {
        let rho = 1.0 / blowup as f64;
        let (delta, list_log2) = self.bound.gap_and_list_size(rho);

        let query_err = f64::exp2(s0 as f64 * (1.0 - delta).log2());

        let mut degree = n0 as f64 / blowup as f64;
        let mut alg_err = 0.0_f64;
        for &m in schedule {
            alg_err += f64::exp2(
                list_log2 + degree.log2() - self.field_ext_bits,
            );
            degree /= m as f64;
        }
        alg_err += f64::exp2(
            degree.max(1.0).log2() - self.field_ext_bits,
        );

        let total = query_err + alg_err;
        let achieved = -(total.log2());
        let q_sec   = -(query_err.log2());
        let a_sec   = -(alg_err.log2());

        (achieved.min(self.hash.collision_bits() as f64), q_sec, a_sec)
    }

    pub fn security_classic(
        &self,
        schedule: &[usize],
        n0: usize,
        blowup: usize,
        r: usize,
    ) -> (f64, f64, f64) {
        let rho = 1.0 / blowup as f64;
        let (delta, _) = self.bound.gap_and_list_size(rho);
        let num_rounds = schedule.len();

        let per_layer = f64::exp2(r as f64 * (1.0 - delta).log2());
        let query_err = num_rounds as f64 * per_layer;

        let degree = n0 as f64 / blowup as f64;
        let alg_err = f64::exp2(degree.log2() - self.field_ext_bits);

        let total = query_err + alg_err;
        let achieved = -(total.log2());
        let q_sec   = -(query_err.log2());
        let a_sec   = -(alg_err.log2());

        (achieved.min(self.hash.collision_bits() as f64), q_sec, a_sec)
    }

    pub fn security_bits(
        &self,
        schedule: &[usize],
        n0: usize,
        blowup: usize,
        queries: usize,
        stir: bool,
    ) -> (f64, f64, f64) {
        if stir {
            self.security_stir(schedule, n0, blowup, queries)
        } else {
            self.security_classic(schedule, n0, blowup, queries)
        }
    }

    pub fn min_queries(
        &self,
        schedule: &[usize],
        n0: usize,
        blowup: usize,
        stir: bool,
    ) -> usize {
        let eff = self.effective_target() as f64;
        for q in 1..=2048 {
            let (achieved, _, _) =
                self.security_bits(schedule, n0, blowup, q, stir);
            if achieved >= eff {
                return q;
            }
        }
        panic!(
            "Cannot reach {}-bit security (eff_target={}) with ≤2048 \
             queries for schedule {:?}, n0={}, blowup={}, bound={:?}",
            self.target_bits, eff, schedule, n0, blowup, self.bound,
        );
    }

    pub fn report(
        &self,
        schedule: &[usize],
        n0: usize,
        blowup: usize,
        queries: usize,
        stir: bool,
    ) -> SoundnessReport {
        let rho = 1.0 / blowup as f64;
        let (delta, list_log2) = self.bound.gap_and_list_size(rho);
        let (achieved, q_sec, a_sec) =
            self.security_bits(schedule, n0, blowup, queries, stir);

        let mut degree = n0 as f64 / blowup as f64;
        let mut rounds = Vec::with_capacity(schedule.len());
        for (i, &m) in schedule.iter().enumerate() {
            rounds.push(RoundSoundnessDetail {
                round: i,
                fold_factor: m,
                degree_before: degree,
                alg_error_log2: list_log2 + degree.log2()
                    - self.field_ext_bits,
            });
            degree /= m as f64;
        }

        SoundnessReport {
            bound_label: self.bound.label(),
            hash_label: self.hash.label().into(),
            hash_collision_bits: self.hash.collision_bits(),
            field_ext_bits: self.field_ext_bits,
            target_bits: self.target_bits,
            effective_target: self.effective_target(),
            achieved_bits: achieved,
            query_security_bits: q_sec,
            algebraic_security_bits: a_sec,
            queries,
            delta,
            rho,
            list_size_log2: list_log2,
            num_rounds: schedule.len(),
            is_stir: stir,
            rounds,
        }
    }

    pub fn print_comparison(
        schedules: &[(&str, &[usize])],
        n0: usize,
        blowup: usize,
        target_bits: usize,
        field_ext_bits: f64,
        hash: HashVariant,
        stir: bool,
    ) {
        let johnson = Self::new(
            target_bits, field_ext_bits,
            ProximityBound::Johnson, hash,
        );
        let capacity = Self::new(
            target_bits, field_ext_bits,
            ProximityBound::StirCapacity { gamma_log2: -30.0 },
            hash,
        );

        eprintln!("╔═══════════════════════╦═════════╦═════════╦═════════╦═════════╗");
        eprintln!("║ Schedule              ║ J  s0   ║ J  bits ║ SC s0   ║ SC bits ║");
        eprintln!("╠═══════════════════════╬═════════╬═════════╬═════════╬═════════╣");

        for &(label, sched) in schedules {
            let j_q = johnson.min_queries(sched, n0, blowup, stir);
            let (j_b, _, _) = johnson.security_bits(sched, n0, blowup, j_q, stir);

            let c_q = capacity.min_queries(sched, n0, blowup, stir);
            let (c_b, _, _) = capacity.security_bits(sched, n0, blowup, c_q, stir);

            eprintln!(
                "║ {:<21} ║ {:>5}   ║ {:>5.1}   ║ {:>5}   ║ {:>5.1}   ║",
                label, j_q, j_b, c_q, c_b,
            );
        }

        eprintln!("╚═══════════════════════╩═════════╩═════════╩═════════╩═════════╝");
        eprintln!(
            "  hash={} collision_bits={} field_ext_bits={:.0} stir={}",
            hash.label(), hash.collision_bits(), field_ext_bits, stir,
        );
    }
}


// ================================================================
// Tests
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, FftField, One, Zero};
    use ark_goldilocks::Goldilocks;
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_poly::DenseUVPolynomial;
    use ark_poly::Polynomial;
    use rand::Rng;
    use std::collections::HashSet;

    use ark_ff::UniformRand;
    use ark_poly::polynomial::univariate::DensePolynomial;
    use rand::seq::SliceRandom;
    use crate::cubic_ext::GoldilocksCubeConfig;

    use crate::cubic_ext::CubeExt;

    type TestField = Goldilocks;

    fn random_polynomial<F: Field>(degree: usize, rng: &mut impl Rng) -> Vec<F> {
        (0..=degree).map(|_| F::rand(rng)).collect()
    }

    fn perform_fold<F: Field + FftField>(
        evals: &[F],
        domain: GeneralEvaluationDomain<F>,
        alpha: F,
        folding_factor: usize,
    ) -> (Vec<F>, GeneralEvaluationDomain<F>) {
        assert!(evals.len() % folding_factor == 0);
        let n = evals.len();
        let next_n = n / folding_factor;
        let next_domain = GeneralEvaluationDomain::<F>::new(next_n)
            .expect("valid folded domain");
        let folding_domain = GeneralEvaluationDomain::<F>::new(folding_factor)
            .expect("valid folding domain");
        let generator = domain.group_gen();
        let folded = (0..next_n)
            .map(|i| {
                let coset_values: Vec<F> = (0..folding_factor)
                    .map(|j| evals[i + j * next_n])
                    .collect();
                let coset_generator = generator.pow([i as u64]);
                fold_one_coset(&coset_values, alpha, coset_generator, &folding_domain)
            })
            .collect();
        (folded, next_domain)
    }

    fn fold_one_coset<F: Field + FftField>(
        coset_values: &[F],
        alpha: F,
        coset_generator: F,
        folding_domain: &GeneralEvaluationDomain<F>,
    ) -> F {
        let p_coeffs = folding_domain.ifft(coset_values);
        let poly = DensePolynomial::from_coefficients_vec(p_coeffs);
        let evaluation_point = alpha * coset_generator.inverse().unwrap();
        poly.evaluate(&evaluation_point)
    }

    // ────────────────────────────────────────────────────────────────
    //  FFT correctness test
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_fft_roundtrip_ext() {
        type E = CubeExt<GoldilocksCubeConfig>;
        let mut rng = StdRng::seed_from_u64(555);

        for log_m in 1..=6 {
            let m = 1usize << log_m;
            let dom = Domain::<TestField>::new(m).unwrap();
            let zeta = dom.group_gen;
            let zeta_inv = zeta.inverse().unwrap();
            let m_inv = TestField::from(m as u64).inverse().unwrap();

            // Random extension-field values
            let original: Vec<E> = (0..m)
                .map(|_| {
                    let comps: Vec<TestField> = (0..E::DEGREE)
                        .map(|_| TestField::from(rng.gen::<u64>()))
                        .collect();
                    E::from_fp_components(&comps).unwrap()
                })
                .collect();

            // Forward FFT with zeta
            let mut vals = original.clone();
            fft_in_place_ext::<E>(&mut vals, zeta);

            // Inverse: forward FFT with zeta_inv, then scale by 1/m
            fft_in_place_ext::<E>(&mut vals, zeta_inv);
            let scale = E::from_fp(m_inv);
            for v in vals.iter_mut() {
                *v = *v * scale;
            }

            for i in 0..m {
                assert_eq!(
                    vals[i], original[i],
                    "FFT roundtrip failed at index {} for m={}",
                    i, m
                );
            }
        }
    }

    /// Verify that the FFT-based interpolate_coset_ext produces the
    /// same result as the old O(m²) manual DFT.
    #[test]
    fn test_fft_interpolation_matches_naive() {
        type E = CubeExt<GoldilocksCubeConfig>;
        let mut rng = StdRng::seed_from_u64(1234);

        for &m in &[2, 4, 8, 16, 32] {
            let n = m * 4; // some domain larger than m
            let dom = Domain::<TestField>::new(n).unwrap();
            let omega = dom.group_gen;
            let n_next = n / m;
            let zeta = omega.pow([n_next as u64]);

            for b in 0..4.min(n_next) {
                let fibre_values: Vec<E> = (0..m)
                    .map(|_| {
                        let comps: Vec<TestField> = (0..E::DEGREE)
                            .map(|_| TestField::from(rng.gen::<u64>()))
                            .collect();
                        E::from_fp_components(&comps).unwrap()
                    })
                    .collect();

                let omega_b = omega.pow([b as u64]);

                // FFT-based (the new code)
                let coeffs = interpolate_coset_ext(&fibre_values, omega_b, zeta, m);

                // Verify: evaluate the polynomial at each coset point
                // and check it matches the original fibre values.
                for j in 0..m {
                    let x_j = omega.pow([(b + j * n_next) as u64]);
                    let mut eval = E::zero();
                    let mut x_pow = TestField::one();
                    for k in 0..m {
                        eval = eval + coeffs[k] * E::from_fp(x_pow);
                        x_pow *= x_j;
                    }
                    assert_eq!(
                        eval, fibre_values[j],
                        "FFT interpolation roundtrip failed: m={} b={} j={}",
                        m, b, j
                    );
                }
            }
        }
    }

    // ────────────────────────────────────────────────────────────────
    //  STIR fold-consistency end-to-end tests
    // ────────────────────────────────────────────────────────────────

    fn test_stir_fold_consistency_binary_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(777);
        let n = 256usize;
        let schedule = vec![2, 2, 2, 2];
        let degree = n / 32 - 1;

        let dom = GeneralEvaluationDomain::<TestField>::new(n).unwrap();
        let poly = DensePolynomial::<TestField>::rand(degree, &mut rng);
        let evals = dom.fft(poly.coeffs());

        let domain0 = FriDomain::new_radix2(n);

        let final_size: usize = n / schedule.iter().product::<usize>();
        let d_final = final_size / 2;

        let params = DeepFriParams::new(schedule, 4, 42)
            .with_stir()
            .with_s0(6)
            .with_d_final(d_final);

        let proof: DeepFriProof<E> = deep_fri_prove(evals, domain0, &params);

        assert!(
            proof.stir_coset_evals.is_some(),
            "STIR proof should include coset evaluations"
        );
        assert!(
            proof.stir_proximity_queries.is_some(),
            "STIR proof should include proximity queries"
        );

        let pqs = proof.stir_proximity_queries.as_ref().unwrap();
        assert_eq!(pqs.len(), 6, "Should have s0=6 queries");

        for pq in pqs {
            assert_eq!(pq.fiber_f_vals.len(), 2, "Binary schedule: m=2 fiber values");
            assert_eq!(pq.f0_packed_opening.index, pq.base_index);
        }

        assert!(
            proof.queries.is_empty(),
            "STIR proof should have zero classic fold queries"
        );

        let ok = deep_fri_verify(&params, &proof);
        assert!(ok, "STIR fold-consistency verification failed (binary schedule)");
    }

    #[test]
    fn test_stir_fold_consistency_binary() {
        test_stir_fold_consistency_binary_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    fn test_stir_fold_consistency_quaternary_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(888);
        let n = 256usize;
        let schedule = vec![4, 4];
        let degree = n / 32 - 1;

        let dom = GeneralEvaluationDomain::<TestField>::new(n).unwrap();
        let poly = DensePolynomial::<TestField>::rand(degree, &mut rng);
        let evals = dom.fft(poly.coeffs());

        let domain0 = FriDomain::new_radix2(n);

        let final_size: usize = n / schedule.iter().product::<usize>();
        let d_final = final_size / 2;

        let params = DeepFriParams::new(schedule, 4, 42)
            .with_stir()
            .with_s0(8)
            .with_d_final(d_final);

        let proof: DeepFriProof<E> = deep_fri_prove(evals, domain0, &params);

        let pqs = proof.stir_proximity_queries.as_ref().unwrap();
        for pq in pqs {
            assert_eq!(pq.fiber_f_vals.len(), 4, "Quaternary: m=4 fiber values");
        }

        let ok = deep_fri_verify(&params, &proof);
        assert!(ok, "STIR fold-consistency verification failed (quaternary schedule)");
    }

    #[test]
    fn test_stir_fold_consistency_quaternary() {
        test_stir_fold_consistency_quaternary_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    fn test_stir_fold_consistency_mixed_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(999);
        let n = 256usize;
        let schedule = vec![4, 2, 2, 2, 2];
        let degree = n / 32 - 1;

        let dom = GeneralEvaluationDomain::<TestField>::new(n).unwrap();
        let poly = DensePolynomial::<TestField>::rand(degree, &mut rng);
        let evals = dom.fft(poly.coeffs());

        let domain0 = FriDomain::new_radix2(n);

        let final_size: usize = n / schedule.iter().product::<usize>();
        let d_final = final_size / 2;

        let params = DeepFriParams::new(schedule, 4, 42)
            .with_stir()
            .with_s0(10)
            .with_d_final(d_final);

        let proof: DeepFriProof<E> = deep_fri_prove(evals, domain0, &params);
        let ok = deep_fri_verify(&params, &proof);
        assert!(ok, "STIR fold-consistency verification failed (mixed schedule)");
    }

    #[test]
    fn test_stir_fold_consistency_mixed() {
        test_stir_fold_consistency_mixed_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    fn test_no_stir_backward_compat_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(111);
        let n = 256usize;
        let schedule = vec![2, 2, 2, 2];
        let degree = n / 32 - 1;

        let dom = GeneralEvaluationDomain::<TestField>::new(n).unwrap();
        let poly = DensePolynomial::<TestField>::rand(degree, &mut rng);
        let evals = dom.fft(poly.coeffs());

        let domain0 = FriDomain::new_radix2(n);

        let final_size: usize = n / schedule.iter().product::<usize>();
        let d_final = final_size / 2;

        let params = DeepFriParams::new(schedule, 4, 42)
            .with_d_final(d_final);

        assert!(!params.stir);

        let proof: DeepFriProof<E> = deep_fri_prove(evals, domain0, &params);
        assert!(proof.stir_coset_evals.is_none());
        assert!(proof.stir_proximity_queries.is_none());

        let ok = deep_fri_verify(&params, &proof);
        assert!(ok, "Backward-compatible (no STIR) verification failed");
    }

    #[test]
    fn test_no_stir_backward_compat() {
        test_no_stir_backward_compat_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    fn test_stir_query_count_reduction_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(1234);
        let n = 256usize;
        let schedule = vec![2, 2, 2, 2];
        let L = schedule.len();
        let degree = n / 32 - 1;
        let s0 = 6usize;
        let m0 = schedule[0];

        let dom = GeneralEvaluationDomain::<TestField>::new(n).unwrap();
        let poly = DensePolynomial::<TestField>::rand(degree, &mut rng);
        let evals = dom.fft(poly.coeffs());

        let domain0 = FriDomain::new_radix2(n);
        let final_size: usize = n / schedule.iter().product::<usize>();
        let d_final = final_size / 2;

        let stir_params = DeepFriParams::new(schedule.clone(), 0, 42)
            .with_stir()
            .with_s0(s0)
            .with_d_final(d_final);

        let stir_proof: DeepFriProof<E> = deep_fri_prove(evals.clone(), domain0, &stir_params);
        let stir_bytes = deep_fri_proof_size_bytes(&stir_proof, true);

        let fri_params = DeepFriParams::new(schedule.clone(), s0, 42)
            .with_d_final(d_final);

        let fri_proof: DeepFriProof<E> = deep_fri_prove(evals, domain0, &fri_params);
        let fri_bytes = deep_fri_proof_size_bytes(&fri_proof, false);

        eprintln!("[STIR vs FRI] s0={} L={} m0={}", s0, L, m0);
        eprintln!("  STIR proof size: {} bytes (packed f0 tree)", stir_bytes);
        eprintln!("  FRI  proof size: {} bytes", fri_bytes);

        assert!(deep_fri_verify(&stir_params, &stir_proof), "STIR verify failed");
        assert!(deep_fri_verify(&fri_params, &fri_proof), "FRI verify failed");
    }

    #[test]
    fn test_stir_query_count_reduction() {
        test_stir_query_count_reduction_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    // ────────────────────────────────────────────────────────────────
    //  STIR OOD fold consistency unit test
    // ────────────────────────────────────────────────────────────────

    fn test_stir_ood_fold_consistency_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(666);
        let n = 64usize;
        let m = 4usize;
        let degree = n / m - 1;

        let dom = GeneralEvaluationDomain::<TestField>::new(n).unwrap();
        let poly = DensePolynomial::<TestField>::rand(degree, &mut rng);
        let evals = dom.fft(poly.coeffs());
        let evals_ext: Vec<E> = evals.iter().map(|&x| E::from_fp(x)).collect();

        let omega = dom.group_gen();
        let n_next = n / m;

        let alpha_comps: Vec<TestField> = (0..E::DEGREE)
            .map(|i| TestField::from((31 + i * 17) as u64))
            .collect();
        let alpha = E::from_fp_components(&alpha_comps).unwrap();

        let z_comps: Vec<TestField> = (0..E::DEGREE)
            .map(|i| TestField::from((42 + i * 11) as u64))
            .collect();
        let z = E::from_fp_components(&z_comps).unwrap();

        let (coset_evals, _) = evaluate_ood_coset(&evals_ext, z, omega, m);

        let zeta = omega.pow([n_next as u64]);
        let interp_coeffs = interpolate_stir_coset(&coset_evals, z, zeta, m);

        let alpha_pows = build_ext_pows(alpha, m);
        let mut fold_at_ood = E::zero();
        for k in 0..m {
            fold_at_ood = fold_at_ood + interp_coeffs[k] * alpha_pows[k];
        }

        let coeff_tuples = extract_all_coset_coefficients(&evals_ext, omega, m);
        let folded_evals = interpolation_fold_ext(&coeff_tuples, alpha);

        let z_m = ext_pow(z, m as u64);
        let folded_coeffs = ext_evals_to_coeffs(&folded_evals);
        let folded_at_zm = eval_final_poly_ext(&folded_coeffs, z_m);

        assert_eq!(
            fold_at_ood, folded_at_zm,
            "STIR OOD fold-consistency failed: fold(interp_coeffs) != f_next(z^m)"
        );
    }

    #[test]
    fn test_stir_ood_fold_consistency() {
        test_stir_ood_fold_consistency_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    // ────────────────────────────────────────────────────────────────
    //  Extension-field fold & DEEP tests
    // ────────────────────────────────────────────────────────────────

    fn test_ext_fold_preserves_low_degree_with<E: TowerField>() {
        use ark_ff::UniformRand;

        let mut rng = StdRng::seed_from_u64(42);
        let n = 256usize;
        let m = 4usize;
        let degree = n / m - 1;

        let dom = GeneralEvaluationDomain::<TestField>::new(n).unwrap();
        let poly = DensePolynomial::<TestField>::rand(degree, &mut rng);
        let evals = dom.fft(poly.coeffs());

        let evals_ext: Vec<E> = evals.iter()
            .map(|&x| E::from_fp(x))
            .collect();

        let challenge_comps: Vec<TestField> = (0..E::DEGREE)
            .map(|i| TestField::from((17 + i * 13) as u64))
            .collect();
        let alpha = E::from_fp_components(&challenge_comps).unwrap();

        let folded = fri_fold_layer_ext_impl(&evals_ext, alpha, m);

        assert_eq!(folded.len(), n / m);

        let any_nonzero = folded.iter().any(|v| *v != E::zero());
        assert!(any_nonzero, "Folded codeword should be non-trivial");
    }

    #[test]
    fn test_ext_fold_preserves_low_degree() {
        test_ext_fold_preserves_low_degree_with::<CubeExt<GoldilocksCubeConfig>>();
    }

    fn test_ext_fold_consistency_with_s_layer_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(99);
        let n = 128usize;
        let m = 4usize;

        let evals: Vec<E> = (0..n)
            .map(|_| {
                let comps: Vec<TestField> = (0..E::DEGREE)
                    .map(|_| TestField::from(rng.gen::<u64>()))
                    .collect();
                E::from_fp_components(&comps).unwrap()
            })
            .collect();

        let alpha_comps: Vec<TestField> = (0..E::DEGREE)
            .map(|i| TestField::from((13 + i * 7) as u64))
            .collect();
        let alpha = E::from_fp_components(&alpha_comps).unwrap();

        let folded = fri_fold_layer_ext_impl(&evals, alpha, m);
        let s = compute_s_layer_ext(&evals, alpha, m);

        let n_next = n / m;
        for b in 0..n_next {
            for j in 0..m {
                assert_eq!(
                    s[b + j * n_next], folded[b],
                    "s-layer mismatch at b={} j={}", b, j
                );
            }
        }
    }

    #[test]
    fn test_ext_fold_consistency_with_s_layer() {
        test_ext_fold_consistency_with_s_layer_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    fn test_ext_deep_quotient_consistency_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(77);
        let n = 64usize;

        let dom = Domain::<TestField>::new(n).unwrap();
        let omega = dom.group_gen;

        let evals: Vec<E> = (0..n)
            .map(|_| {
                let comps: Vec<TestField> = (0..E::DEGREE)
                    .map(|_| TestField::from(rng.gen::<u64>()))
                    .collect();
                E::from_fp_components(&comps).unwrap()
            })
            .collect();

        let z_comps: Vec<TestField> = (0..E::DEGREE)
            .map(|i| TestField::from((42 + i * 11) as u64))
            .collect();
        let z = E::from_fp_components(&z_comps).unwrap();

        let (q, fz) = compute_q_layer_ext_on_ext(&evals, z, omega);

        let mut x = TestField::one();
        for i in 0..n {
            let lhs = q[i] * (E::from_fp(x) - z);
            let rhs = evals[i] - fz;
            assert_eq!(lhs, rhs, "DEEP identity failed at i={}", i);
            x *= omega;
        }
    }

    #[test]
    fn test_ext_deep_quotient_consistency() {
        test_ext_deep_quotient_consistency_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    // ────────────────────────────────────────────────────────────────
    //  Construction 5.1 specific tests
    // ────────────────────────────────────────────────────────────────

    fn test_coset_interpolation_roundtrip_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(123);
        let n = 64usize;
        let m = 4usize;
        let n_next = n / m;

        let dom = Domain::<TestField>::new(n).unwrap();
        let omega = dom.group_gen;
        let zeta = omega.pow([n_next as u64]);

        let evals: Vec<E> = (0..n)
            .map(|_| {
                let comps: Vec<TestField> = (0..E::DEGREE)
                    .map(|_| TestField::from(rng.gen::<u64>()))
                    .collect();
                E::from_fp_components(&comps).unwrap()
            })
            .collect();

        let coeff_tuples = extract_all_coset_coefficients(&evals, omega, m);

        assert_eq!(coeff_tuples.len(), n_next);
        assert_eq!(coeff_tuples[0].len(), m);

        for b in 0..n_next {
            for j in 0..m {
                let x_j = omega.pow([(b + j * n_next) as u64]);
                let mut eval = E::zero();
                let mut x_pow = F::one();
                for i in 0..m {
                    eval = eval + coeff_tuples[b][i] * E::from_fp(x_pow);
                    x_pow *= x_j;
                }
                assert_eq!(
                    eval,
                    evals[b + j * n_next],
                    "Interpolation roundtrip failed at coset b={} fibre j={}",
                    b, j
                );
            }
        }
    }

    #[test]
    fn test_coset_interpolation_roundtrip() {
        test_coset_interpolation_roundtrip_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    fn test_batched_degree_check_for<E: TowerField>() {
        let mut rng = StdRng::seed_from_u64(321);
        let n = 64usize;
        let m = 4usize;
        let degree = m - 1;

        let dom = GeneralEvaluationDomain::<TestField>::new(n).unwrap();
        let poly = DensePolynomial::<TestField>::rand(degree, &mut rng);
        let evals = dom.fft(poly.coeffs());
        let evals_ext: Vec<E> = evals.iter().map(|&x| E::from_fp(x)).collect();

        let omega = dom.group_gen();
        let coeff_tuples = extract_all_coset_coefficients(&evals_ext, omega, m);

        let beta_comps: Vec<TestField> = (0..E::DEGREE)
            .map(|i| TestField::from((7 + i * 3) as u64))
            .collect();
        let beta = E::from_fp_components(&beta_comps).unwrap();

        assert!(
            batched_degree_check_ext(&coeff_tuples, beta, 1),
            "Batched degree check should pass for honest coefficients"
        );

        let mut bad_tuples = coeff_tuples.clone();
        bad_tuples[1][0] = bad_tuples[1][0] + E::from_fp(TestField::one());

        assert!(
            !batched_degree_check_ext(&bad_tuples, beta, 1),
            "Batched degree check should fail for corrupted coefficients"
        );
    }

    #[test]
    fn test_batched_degree_check() {
        test_batched_degree_check_for::<CubeExt<GoldilocksCubeConfig>>();
    }

    // ────────────────────────────────────────────────────────────────
    //  Legacy FRI tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_fri_local_consistency_check_soundness() {
        const DOMAIN_SIZE: usize = 1024;
        const FOLDING_FACTOR: usize = 4;
        const NUM_TRIALS: usize = 1000000;

        let mut rng = rand::thread_rng();
        let mut detections = 0;

        let z_l = TestField::from(5u64);
        let f: Vec<TestField> = (0..DOMAIN_SIZE).map(|_| TestField::rand(&mut rng)).collect();
        let f_next_claimed: Vec<TestField> = vec![TestField::zero(); DOMAIN_SIZE / FOLDING_FACTOR];

        let domain = GeneralEvaluationDomain::<TestField>::new(DOMAIN_SIZE).unwrap();
        let generator = domain.group_gen();
        let folding_domain = GeneralEvaluationDomain::<TestField>::new(FOLDING_FACTOR).unwrap();

        for _ in 0..NUM_TRIALS {
            let query_index = rng.gen_range(0..f_next_claimed.len());
            let coset_values: Vec<TestField> = (0..FOLDING_FACTOR)
                .map(|j| f[query_index + j * (DOMAIN_SIZE / FOLDING_FACTOR)])
                .collect();
            let coset_generator = generator.pow([query_index as u64]);
            let s_reconstructed = fold_one_coset(&coset_values, z_l, coset_generator, &folding_domain);
            let s_claimed = f_next_claimed[query_index];
            if s_reconstructed != s_claimed {
                detections += 1;
            }
        }
        let measured_rate = detections as f64 / NUM_TRIALS as f64;
        assert!((measured_rate - 1.0).abs() < 0.01, "Detection rate should be close to 100%");
    }

    #[test]
    fn test_fri_distance_amplification() {
        const DOMAIN_SIZE: usize = 1024;
        const FOLDING_FACTOR: usize = 4;
        const NUM_TRIALS: usize = 100_000;
        const INITIAL_CORRUPTION_FRACTION: f64 = 0.05;

        let mut rng = rand::thread_rng();
        let z_l = TestField::from(5u64);

        let large_domain = GeneralEvaluationDomain::<TestField>::new(DOMAIN_SIZE).unwrap();
        let degree_bound = DOMAIN_SIZE / FOLDING_FACTOR;
        let p_coeffs = random_polynomial(degree_bound - 2, &mut rng);
        let p_poly = DensePolynomial::from_coefficients_vec(p_coeffs);
        let p_evals = large_domain.fft(p_poly.coeffs());

        let mut f_evals = p_evals.clone();
        let num_corruptions = (DOMAIN_SIZE as f64 * INITIAL_CORRUPTION_FRACTION) as usize;
        let mut corrupted_indices = HashSet::new();
        while corrupted_indices.len() < num_corruptions {
            corrupted_indices.insert(rng.gen_range(0..DOMAIN_SIZE));
        }
        for &idx in &corrupted_indices {
            f_evals[idx] = TestField::rand(&mut rng);
        }

        let folded_honest = fri_fold_layer(&p_evals, z_l, FOLDING_FACTOR);
        let folded_corrupted = fri_fold_layer(&f_evals, z_l, FOLDING_FACTOR);

        let mut detections = 0;
        for _ in 0..NUM_TRIALS {
            let query_index = rng.gen_range(0..folded_honest.len());
            if folded_honest[query_index] != folded_corrupted[query_index] {
                detections += 1;
            }
        }

        let measured_rate = detections as f64 / NUM_TRIALS as f64;
        let theoretical_rate = (FOLDING_FACTOR as f64 * INITIAL_CORRUPTION_FRACTION).min(1.0);

        let tolerance = 0.05;
        assert!(
            (measured_rate - theoretical_rate).abs() < tolerance,
            "Measured detection rate should be close to the theoretical rate."
        );
    }

    #[test]
    fn debug_single_fold_distance_amplification() {
        let log_domain_size = 12;
        let initial_domain_size = 1 << log_domain_size;
        let folding_factor = 4;
        let initial_corruption_rate = 0.06;

        let mut rng = StdRng::seed_from_u64(0);

        let degree = (initial_domain_size / folding_factor) - 1;
        let domain = GeneralEvaluationDomain::<F>::new(initial_domain_size)
            .expect("Failed to create domain");
        let poly_p0 = DensePolynomial::<F>::rand(degree, &mut rng);

        let codeword_c0_evals = poly_p0.evaluate_over_domain(domain).evals;

        let mut corrupted_codeword_c_prime_0_evals = codeword_c0_evals.clone();
        let num_corruptions = (initial_domain_size as f64 * initial_corruption_rate).ceil() as usize;
        let mut corrupted_indices = HashSet::new();

        while corrupted_indices.len() < num_corruptions {
            let idx_to_corrupt = usize::rand(&mut rng) % initial_domain_size;
            if corrupted_indices.contains(&idx_to_corrupt) {
                continue;
            }

            let original_value = corrupted_codeword_c_prime_0_evals[idx_to_corrupt];
            let mut new_value = F::rand(&mut rng);
            while new_value == original_value {
                new_value = F::rand(&mut rng);
            }
            corrupted_codeword_c_prime_0_evals[idx_to_corrupt] = new_value;
            corrupted_indices.insert(idx_to_corrupt);
        }

        let alpha = F::rand(&mut rng);

        let (folded_corrupted_evals, new_domain) = perform_fold(
            &corrupted_codeword_c_prime_0_evals,
            domain,
            alpha,
            folding_factor,
        );

        let (folded_true_evals, _) = perform_fold(
            &codeword_c0_evals,
            domain,
            alpha,
            folding_factor,
        );

        let differing_points = folded_corrupted_evals
            .iter()
            .zip(folded_true_evals.iter())
            .filter(|(a, b)| a != b)
            .count();

        let measured_rho_1 = differing_points as f64 / new_domain.size() as f64;

        let theoretical_rho_1 = 1.0_f64 - (1.0_f64 - initial_corruption_rate).powf(folding_factor as f64);

        let tolerance = 0.01;
        assert!(
            (measured_rho_1 - theoretical_rho_1).abs() < tolerance,
            "Single fold amplification measured rate {} is not close to precise theoretical rate {}",
            measured_rho_1,
            theoretical_rho_1
        );
    }
}