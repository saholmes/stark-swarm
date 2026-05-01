//! Multi-row ECDSA-P256 scalar-mul STARK prove demonstration.
//!
//! This is the production layout for in-circuit ECDSA-P256: each
//! trace row hosts ONE scalar_mul_step gadget, with transition
//! constraints linking row k's accumulator output to row k+1's
//! input.  Row width ≈ 75k cells; row count = K (the scalar bit
//! length).  At K=256 this is the canonical full ECDSA-P256
//! scalar-mult AIR.
//!
//! Compared to the single-row layout (`p256_ecdsa_stark_prove`)
//! this distributes ~78k constraints per LDE point across K=256
//! rows (n0 = K · 32 = 8192) — same total work as 64 LDE points ×
//! 20M constraints, but the per-LDE-point evaluator is 256× smaller,
//! and the row-major transpose makes cur/nxt access cache-friendly.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example p256_multirow_stark_prove

use std::time::Instant;

use ark_ff::Zero;
use ark_goldilocks::Goldilocks as F;

use deep_ali::{
    deep_ali_merge_scalar_mul_multirow,
    fri::{deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    p256_field::{FieldElement, NUM_LIMBS},
    p256_group::GENERATOR,
    p256_scalar_mul_multirow_air::{
        build_scalar_mul_multirow_layout, fill_scalar_mul_multirow,
        scalar_mul_multirow_constraints,
    },
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};

type Ext = SexticExt;
const BLOWUP: usize = 32;
const NUM_QUERIES: usize = 54;
const SEED_Z: u64 = 0xDEEF_BAAD;

fn make_schedule_stir(n0: usize) -> Vec<usize> {
    assert!(n0.is_power_of_two());
    let log_n0 = n0.trailing_zeros() as usize;
    let log_arity = 3usize;
    let full_folds = log_n0 / log_arity;
    let remainder_log = log_n0 % log_arity;
    let mut s = vec![8usize; full_folds];
    if remainder_log > 0 {
        s.push(1usize << remainder_log);
    }
    s
}

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

/// Run a STARK prove + verify on the multi-row scalar-mul chain.
fn run_multirow_prove(k_steps: usize, n_trace: usize) {
    assert!(n_trace.is_power_of_two() && n_trace >= k_steps);

    println!(
        "─── ECDSA-P256 multi-row scalar-mul K_steps={} n_trace={} ───",
        k_steps, n_trace
    );

    // Cell layout (one row's worth):
    let acc_x = 0;
    let acc_y = NUM_LIMBS;
    let acc_z = 2 * NUM_LIMBS;
    let base_x = 3 * NUM_LIMBS;
    let base_y = 4 * NUM_LIMBS;
    let base_z = 5 * NUM_LIMBS;
    let bit_cell = 6 * NUM_LIMBS;
    let start = bit_cell + 1;
    let (layout, total_cells) = build_scalar_mul_multirow_layout(
        start, acc_x, acc_y, acc_z, base_x, base_y, base_z, bit_cell,
    );
    let total_constraints = scalar_mul_multirow_constraints(&layout);

    println!("    Cells per row:        {}", total_cells);
    println!("    Constraints per row:  {}", total_constraints);
    println!("    Trace rows (n_trace): {}", n_trace);
    println!("    LDE rows (n0):        {}", n_trace * BLOWUP);
    println!(
        "    Total cells:          {} ({} MB)",
        total_cells * n_trace,
        total_cells * n_trace * 8 / 1_048_576
    );
    println!(
        "    Total constraint evals (n0 × per-row): {}",
        n_trace * BLOWUP * total_constraints
    );

    // ── Allocate trace ──
    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); n_trace])
        .collect();

    let g = *GENERATOR;
    let z_one = {
        let mut t = FieldElement::zero();
        t.limbs[0] = 1;
        t
    };
    // Use synthetic scalar bits (alternating pattern).
    let bits: Vec<bool> = (0..k_steps).map(|i| i % 2 == 0).collect();

    let t_fill = Instant::now();
    fill_scalar_mul_multirow(
        &mut trace, &layout, n_trace, k_steps,
        &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &bits,
    );
    let fill_dur = t_fill.elapsed();
    println!("    [fill]      {:>10.2?}", fill_dur);

    // ── LDE ──
    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);

    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP)
        .expect("LDE failed");
    let lde_dur = t_lde.elapsed();
    println!("    [LDE]       {:>10.2?}", lde_dur);

    // ── Composition (multi-row merge) ──
    let coeffs = comb_coeffs(total_constraints);
    let t_merge = Instant::now();
    let (c_eval, info) = deep_ali_merge_scalar_mul_multirow(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let merge_dur = t_merge.elapsed();
    println!("    [merge]     {:>10.2?}", merge_dur);
    println!(
        "      phi_deg_bound={}  quotient_deg_bound={}  rate={:.3}",
        info.phi_degree_bound, info.quotient_degree_bound, info.rate
    );

    // ── DeepFRI Prove ──
    let pk_hash_32 = [0u8; 32];
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0),
        r: NUM_QUERIES,
        seed_z: SEED_Z,
        coeff_commit_final: true,
        d_final: 1,
        stir: true,
        s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_32),
    };

    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_dur = t_prove.elapsed();
    println!("    [prove]     {:>10.2?}", prove_dur);

    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_dur = t_verify.elapsed();
    println!(
        "    [verify]    {:>10.2?}   {}",
        verify_dur,
        if ok { "ok ✓" } else { "FAIL ✗" }
    );

    let total_dur = fill_dur + lde_dur + merge_dur + prove_dur + verify_dur;
    println!("    TOTAL:      {:>10.2?}", total_dur);
    println!();
}

fn main() {
    println!("=== ECDSA-P256 multi-row scalar-mul STARK prove ===");
    println!();
    println!("Layout: one scalar_mul_step per row, transition constraints");
    println!("link row k's output acc to row k+1's input acc.  This is the");
    println!("production layout for in-circuit ECDSA-P256.");
    println!();

    // Sweep: small → full K=256.
    for k in [4usize, 8, 16, 32, 64, 128, 256] {
        let n_trace = k.next_power_of_two().max(2);
        run_multirow_prove(k, n_trace);
    }

    println!("Done.");
}
