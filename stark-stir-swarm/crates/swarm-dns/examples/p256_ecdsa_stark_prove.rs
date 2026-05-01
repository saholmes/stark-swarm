//! End-to-end ECDSA-P256 STARK prove demonstration.
//!
//! Bridges the K-step ECDSA verify demo (single-row gadget composition)
//! through the deep-ALI prove pipeline (`deep_ali_merge_ecdsa_demo` +
//! `deep_fri_prove`).  Reports actual measured prove + verify wall time
//! on the K=2 / K=4 / K=8 demo traces.
//!
//! Soundness note (multi-row layout, Phase 5 v3):
//!   The demo composes all gadgets into a single trace row with
//!   `n_trace` copies (so the constraints satisfy at every row of
//!   the trace domain H).  This proves a trivially-satisfying trace,
//!   but it does exercise every stage of the prover (LDE, composition,
//!   FRI/STIR commit, query, verify) and so gives the actual measured
//!   STARK prove time at the corresponding constraint count.  A
//!   production multi-row layout (where row k hosts step k of the
//!   scalar-mul chain) reuses the same per-row gadget evaluator and
//!   is a deferred engineering item — not a soundness gap of the
//!   gadgets themselves.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example p256_ecdsa_stark_prove

use std::time::Instant;

use ark_ff::Zero;
use ark_goldilocks::Goldilocks as F;

use deep_ali::{
    deep_ali_merge_ecdsa_demo,
    fri::{deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    p256_ecdsa_air::{
        build_ecdsa_verify_demo_layout, ecdsa_verify_demo_constraints,
        fill_ecdsa_verify_demo,
    },
    p256_field::NUM_LIMBS,
    p256_group::GENERATOR,
    p256_scalar::ScalarElement,
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

/// Run a STARK prove + verify on the K-step ECDSA demo trace.
fn run_ecdsa_prove(k: usize, n_trace: usize) {
    assert!(n_trace.is_power_of_two() && n_trace >= 2);

    println!("─── ECDSA-P256 K={} STARK prove (n_trace={}) ───", k, n_trace);

    // ── Layout ──
    let g_x = 0;
    let g_y = NUM_LIMBS;
    let g_z = 2 * NUM_LIMBS;
    let q_x = 3 * NUM_LIMBS;
    let q_y = 4 * NUM_LIMBS;
    let q_z = 5 * NUM_LIMBS;
    let start = 6 * NUM_LIMBS;
    let (layout, total_cells) = build_ecdsa_verify_demo_layout(
        start, g_x, g_y, g_z, q_x, q_y, q_z, k,
    );
    let total_constraints = ecdsa_verify_demo_constraints(&layout);

    println!("    Trace cells:         {}", total_cells);
    println!("    Total constraints:   {}", total_constraints);
    println!("    Trace rows (n_trace):{}", n_trace);
    println!("    LDE rows (n0):       {}", n_trace * BLOWUP);

    // ── Build the trace (single-row demo, replicated to n_trace rows) ──
    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); n_trace])
        .collect();

    let g = *GENERATOR;
    let q_point = g.double();
    let u1_bits: Vec<bool> = (0..k).map(|i| i % 2 == 0).collect();
    let u2_bits: Vec<bool> = (0..k).map(|i| i % 3 == 0).collect();
    let zero_scalar = ScalarElement::zero();

    let t_fill = Instant::now();
    fill_ecdsa_verify_demo(
        &mut trace, 0, &layout,
        &g.x, &g.y, &q_point.x, &q_point.y,
        &u1_bits, &u2_bits, &zero_scalar,
    );

    // Set r_input = R.x mod n so equality fires consistently.
    {
        let r_x_mod_n_base = layout.r_x_mod_n_layout.c_limbs_base;
        for i in 0..NUM_LIMBS {
            let v = trace[r_x_mod_n_base + i][0];
            trace[layout.r_input_base + i][0] = v;
        }
    }

    // Replicate row 0 to all n_trace rows so constraints fire to zero
    // at every row of the trace domain H.
    for c in 0..total_cells {
        let v = trace[c][0];
        for r in 1..n_trace {
            trace[c][r] = v;
        }
    }
    let fill_dur = t_fill.elapsed();
    println!("    [fill]      {:>8.2?}", fill_dur);

    // ── LDE the trace ──
    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);

    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP)
        .expect("LDE failed");
    let lde_dur = t_lde.elapsed();
    println!("    [LDE]       {:>8.2?}", lde_dur);

    // ── Composition ──
    let coeffs = comb_coeffs(total_constraints);
    let t_merge = Instant::now();
    let (c_eval, info) = deep_ali_merge_ecdsa_demo(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let merge_dur = t_merge.elapsed();
    println!("    [merge]     {:>8.2?}", merge_dur);
    println!(
        "      phi_deg_bound={}  quotient_deg_bound={}  constraints={}",
        info.phi_degree_bound, info.quotient_degree_bound, info.num_constraints
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
    println!("    [prove]     {:>8.2?}", prove_dur);

    // ── Verify ──
    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_dur = t_verify.elapsed();
    println!("    [verify]    {:>8.2?}   {}", verify_dur,
        if ok { "ok ✓" } else { "FAIL ✗" });

    let total_dur = fill_dur + lde_dur + merge_dur + prove_dur + verify_dur;
    println!("    TOTAL:      {:>8.2?}", total_dur);
    println!();
}

fn main() {
    println!("=== ECDSA-P256 STARK prove pipeline ===");
    println!();
    println!("Bridges the K-step ECDSA verify demo through deep-ALI");
    println!("(deep_ali_merge_ecdsa_demo) + DeepFRI prove + verify.");
    println!();
    println!("Note: trace replicates row 0 across all n_trace rows.");
    println!("The proof is sound for the gadget composition; multi-row");
    println!("layout (one chain step per row) is deferred (Phase 5 v3).");
    println!();

    // Sweep K with n_trace=2 (single replicated trace row → all constraints
    // satisfy at every row of H). Reports: fill, LDE, merge, prove, verify.
    for k in [2usize, 4, 8, 16, 32, 64] {
        run_ecdsa_prove(k, 2);
    }

    // K=4 at larger n_trace=4 (LDE doubles, constraint count fixed).
    run_ecdsa_prove(4, 4);

    println!("Done.");
}
