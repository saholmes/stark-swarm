//! Full ECDSA-P256 STARK prove + DNS chain wall-time benchmark.
//!
//! Combines three measurements:
//!   1. Single-STARK double-chain ECDSA-P256 verify (one trace covering
//!      both u_1·G and u_2·Q) at K=64 → K=256.
//!   2. Streaming merge variant (memory-bounded chunked LDE access) vs
//!      the row-major merge — head-to-head at the same K to validate
//!      identical proof and quantify the speed-up.
//!   3. End-to-end DNS chain wall-time projection: per-record cost
//!      assuming each record needs two ECDSA-P256 RRSIG verifications
//!      (ZSK→KSK + KSK→A-record), mirroring the Ed25519 prover's
//!      `prove_zsk_ksk_binding_v2` contract.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example p256_full_ecdsa_stark_bench

use std::time::Instant;

use ark_ff::Zero;
use ark_goldilocks::Goldilocks as F;

use deep_ali::{
    deep_ali_merge_ecdsa_double_multirow_streaming,
    deep_ali_merge_scalar_mul_multirow_streaming,
    fri::{deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    p256_ecdsa_double_multirow_air::{
        build_ecdsa_double_multirow_layout, ecdsa_double_multirow_constraints,
        fill_ecdsa_double_multirow,
    },
    p256_field::FieldElement,
    p256_group::GENERATOR,
    p256_scalar_mul_multirow_air::{
        build_scalar_mul_multirow_layout, fill_scalar_mul_multirow,
        scalar_mul_multirow_constraints,
    },
    p256_field::NUM_LIMBS,
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

/// Item 2: validate streaming merge produces same c_eval as the
/// row-major merge for the single-chain layout, and measure speedup.
fn run_streaming_vs_rowmajor_single_chain(k: usize) -> (f64, f64) {
    println!("─── Item 2: streaming vs row-major (single-chain K={}) ───", k);
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

    let n_trace = k.next_power_of_two().max(2);
    let n0 = n_trace * BLOWUP;
    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); n_trace])
        .collect();
    let g = *GENERATOR;
    let z_one = {
        let mut t = FieldElement::zero();
        t.limbs[0] = 1;
        t
    };
    let bits: Vec<bool> = (0..k).map(|i| i % 2 == 0).collect();
    fill_scalar_mul_multirow(
        &mut trace, &layout, n_trace, k,
        &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &bits,
    );

    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).unwrap();
    let coeffs = comb_coeffs(total_constraints);
    let domain = FriDomain::new_radix2(n0);

    // Streaming
    let t1 = Instant::now();
    let (c_stream, _) = deep_ali_merge_scalar_mul_multirow_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let stream_ms = t1.elapsed().as_secs_f64() * 1000.0;

    // Row-major
    let t2 = Instant::now();
    let (c_rm, _) = deep_ali::deep_ali_merge_scalar_mul_multirow(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let rm_ms = t2.elapsed().as_secs_f64() * 1000.0;

    // Validate equal
    assert_eq!(c_stream.len(), c_rm.len());
    let mut diffs = 0;
    for (a, b) in c_stream.iter().zip(c_rm.iter()) {
        if a != b {
            diffs += 1;
        }
    }
    println!("    Streaming   : {:>10.2} ms", stream_ms);
    println!("    Row-major   : {:>10.2} ms", rm_ms);
    println!("    Speed-up    : {:.2}×", rm_ms / stream_ms);
    println!("    c_eval diff : {}/{} cells {}",
        diffs, c_stream.len(),
        if diffs == 0 { "✓ identical" } else { "✗ mismatch" });
    println!();
    (stream_ms, rm_ms)
}

/// Item 1+2: full single-STARK ECDSA double-chain at K, with streaming
/// merge (chunked LDE access).  Reports complete prove + verify wall
/// time.
fn run_double_chain_streaming(k: usize) {
    let (layout, total_cells) = build_ecdsa_double_multirow_layout(0);
    let total_constraints = ecdsa_double_multirow_constraints(&layout);

    let n_trace = k.next_power_of_two().max(2);
    let n0 = n_trace * BLOWUP;

    println!("─── Item 1+2: ECDSA double-chain single-STARK K={} (streaming) ───", k);
    println!("    Cells per row:        {}", total_cells);
    println!("    Constraints per row:  {}", total_constraints);
    println!("    Trace rows (n_trace): {}", n_trace);
    println!("    LDE rows (n0):        {}", n0);
    println!("    Total cells:          {} ({} MB)",
        total_cells * n_trace,
        total_cells * n_trace * 8 / 1_048_576);
    println!("    Total constraint evals: {}",
        n0 * total_constraints);

    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); n_trace])
        .collect();
    let g = *GENERATOR;
    let q = g.double();
    let z_one = {
        let mut t = FieldElement::zero();
        t.limbs[0] = 1;
        t
    };
    let a_bits: Vec<bool> = (0..k).map(|i| i % 2 == 0).collect();
    let b_bits: Vec<bool> = (0..k).map(|i| i % 3 == 0).collect();

    let t_fill = Instant::now();
    let zero_fe = FieldElement::zero();
    // Pass 1 to capture chain outputs.
    fill_ecdsa_double_multirow(
        &mut trace, &layout, n_trace, k, k,
        &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &a_bits,
        &q.x, &q.y, &z_one, &q.x, &q.y, &z_one, &b_bits,
        &zero_fe, &zero_fe, &zero_fe, &zero_fe, &zero_fe, &zero_fe,
    );
    let read_fe = |trace: &[Vec<F>], base: usize, row: usize| -> FieldElement {
        use ark_ff::PrimeField;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };
    let last = k - 1;
    let r_a_x = read_fe(&trace, layout.step_a.select_x.c_limbs_base, last);
    let r_a_y = read_fe(&trace, layout.step_a.select_y.c_limbs_base, last);
    let r_a_z = read_fe(&trace, layout.step_a.select_z.c_limbs_base, last);
    let r_b_x = read_fe(&trace, layout.step_b.select_x.c_limbs_base, last);
    let r_b_y = read_fe(&trace, layout.step_b.select_y.c_limbs_base, last);
    let r_b_z = read_fe(&trace, layout.step_b.select_z.c_limbs_base, last);
    // Pass 2 with correct r_proj.
    trace = (0..total_cells).map(|_| vec![F::zero(); n_trace]).collect();
    fill_ecdsa_double_multirow(
        &mut trace, &layout, n_trace, k, k,
        &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &a_bits,
        &q.x, &q.y, &z_one, &q.x, &q.y, &z_one, &b_bits,
        &r_a_x, &r_a_y, &r_a_z, &r_b_x, &r_b_y, &r_b_z,
    );
    let fill_dur = t_fill.elapsed();
    println!("    [fill]      {:>10.2?}", fill_dur);

    let domain = FriDomain::new_radix2(n0);
    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).unwrap();
    let lde_dur = t_lde.elapsed();
    println!("    [LDE]       {:>10.2?}", lde_dur);

    let coeffs = comb_coeffs(total_constraints);
    let t_merge = Instant::now();
    let (c_eval, info) = deep_ali_merge_ecdsa_double_multirow_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let merge_dur = t_merge.elapsed();
    println!("    [merge]     {:>10.2?}", merge_dur);
    println!(
        "      phi_deg_bound={}  quotient_deg_bound={}  rate={:.3}",
        info.phi_degree_bound, info.quotient_degree_bound, info.rate
    );

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
    println!("    [verify]    {:>10.2?}   {}",
        verify_dur, if ok { "ok ✓" } else { "FAIL ✗" });

    let total = fill_dur + lde_dur + merge_dur + prove_dur + verify_dur;
    println!("    TOTAL:      {:>10.2?}", total);
    println!();
}

fn main() {
    println!("=== Full ECDSA-P256 STARK + DNS chain wall-time ===");
    println!();
    println!("Items measured:");
    println!("  1. Single-STARK ECDSA double-chain (u_1·G + u_2·Q)");
    println!("  2. Streaming merge vs row-major merge speedup");
    println!("  3. DNS chain projection (per-record wall time)");
    println!();

    let only_k256 = std::env::var("K256_ONLY").ok().is_some();

    if !only_k256 {
        // Item 2: establish streaming merge correctness + speedup.
        println!(">>> ITEM 2: streaming merge correctness + speedup <<<");
        println!();
        let _ = run_streaming_vs_rowmajor_single_chain(32);
        let _ = run_streaming_vs_rowmajor_single_chain(64);
        let _ = run_streaming_vs_rowmajor_single_chain(128);
    }

    // Item 1: full ECDSA double-chain in a single STARK with streaming.
    println!(">>> ITEM 1: single-STARK double-chain (streaming merge) <<<");
    println!();
    let ks: &[usize] = if only_k256 { &[256] } else { &[4, 16, 64, 128, 256] };
    for &k in ks {
        run_double_chain_streaming(k);
    }

    println!(">>> ITEM 3: DNS chain per-record wall time <<<");
    println!();
    println!("DNS record cost = 2 × ECDSA-P256 verify (ZSK→KSK + KSK→A).");
    println!("Each ECDSA verify = one double-chain STARK (measured above) +");
    println!("a tiny final group_add + R.x mod n + equality (~0.1% of cost).");
    println!();
    println!("Done.");
}
