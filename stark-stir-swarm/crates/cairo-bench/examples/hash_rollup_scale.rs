//! Measurement binary: run HashRollup STARK prove + verify at large
//! trace sizes to anchor the scaling extrapolation in
//! `docs/scaling-analysis.md`.
//!
//! Each row of HashRollup absorbs one u64 leaf, and a DNS record
//! contributes 4 leaves, so trace_rows ≈ 4 × records_per_shard.
//!
//! Usage:
//!   cargo run --release -p cairo-bench --example hash_rollup_scale -- 16 18 20
//!
//! Output: one CSV-style line per trace size with prove_ms, verify_ms,
//! proof_size_bytes, peak_rss_mb (best-effort).

use std::time::Instant;

use ark_goldilocks::Goldilocks as F;
use ark_ff::PrimeField;

use deep_ali::{
    air_workloads::{build_hash_rollup_trace, AirType},
    deep_ali_merge_general,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};

use api::convert::serialize_proof;

type Ext = SexticExt;

const BLOWUP: usize = 32;     // paper Table III: 1/ρ₀ = 32 calibration
const NUM_QUERIES: usize = 54;        // Level 1 / q=2^40
const SEED_Z: u64 = 0xDEEF_BAAD;

fn make_schedule(n0: usize) -> Vec<usize> {
    vec![2usize; n0.trailing_zeros() as usize]
}

fn combination_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

#[cfg(target_os = "macos")]
fn peak_rss_mb() -> u64 {
    // mach_task_basic_info → resident_size_max
    use std::mem::MaybeUninit;
    extern "C" {
        fn task_info(target_task: u32, flavor: u32, info: *mut u8, info_count: *mut u32) -> i32;
        fn mach_task_self() -> u32;
    }
    const MACH_TASK_BASIC_INFO: u32 = 20;
    let mut info: [u64; 16] = [0; 16];
    let mut count: u32 = (info.len() as u32);
    let rc = unsafe {
        task_info(mach_task_self(), MACH_TASK_BASIC_INFO, info.as_mut_ptr() as *mut u8, &mut count)
    };
    if rc != 0 {
        return 0;
    }
    // Index of resident_size_max in mach_task_basic_info: bytes
    // Layout (mach_task_basic_info, 64-bit): virtual_size, resident_size, resident_size_max, user_time, system_time, policy, suspend_count
    info[2] / (1024 * 1024)
}

#[cfg(not(target_os = "macos"))]
fn peak_rss_mb() -> u64 { 0 }

fn run_one(log_n_trace: u32) {
    let n_trace = 1usize << log_n_trace;
    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);

    // Build a deterministic leaf sequence.
    let leaves: Vec<u64> = (0..n_trace as u64)
        .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1))
        .collect();

    let t_setup = Instant::now();
    let trace = build_hash_rollup_trace(n_trace, &leaves);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).expect("LDE failed");
    let coeffs = combination_coeffs(AirType::HashRollup.num_constraints());
    let (c_eval, _) = deep_ali_merge_general(
        &lde, &coeffs, AirType::HashRollup, domain.omega, n_trace, BLOWUP,
    );
    let setup_ms = t_setup.elapsed().as_secs_f64() * 1e3;

    let params = DeepFriParams {
        schedule: make_schedule(n0),
        r: NUM_QUERIES,
        seed_z: SEED_Z,
        coeff_commit_final: true,
        d_final: 1,
        stir: false,
        s0: NUM_QUERIES,
        public_inputs_hash: None,
    };

    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1e3;

    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1e3;
    assert!(ok, "verify failed at log2(n_trace) = {log_n_trace}");

    let in_mem_bytes = deep_fri_proof_size_bytes::<Ext>(&proof, false);
    let serialized   = serialize_proof(&proof);
    let json_bytes    = serialized.to_json_size();
    let bincode_bytes = serialized.to_bincode_compact().len();
    let rss_mb = peak_rss_mb();

    let _ = std::convert::identity::<F>(F::from(0u64));
    println!(
        "{},{},{},{},{},{:.0},{:.1},{:.1},{:.1},{:.1},{:.1},{}",
        log_n_trace,
        n_trace,
        n0,
        n_trace / 4,
        NUM_QUERIES,
        setup_ms,
        prove_ms,
        verify_ms,
        in_mem_bytes as f64 / 1024.0,        // KiB — in-memory struct (existing reporter)
        json_bytes   as f64 / 1024.0,        // KiB — JSON-hex (current ethSTARK-split format)
        bincode_bytes as f64 / 1024.0,       // KiB — bincode binary-native (paper-style)
        rss_mb,
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let logs: Vec<u32> = if args.is_empty() {
        vec![14, 16, 18, 20]
    } else {
        args.iter().map(|s| s.parse().expect("log2(n_trace) must be u32")).collect()
    };

    eprintln!(
        "[hash_rollup_scale] rayon threads = {}",
        rayon::current_num_threads()
    );

    println!("log2_n,n_trace,n0,records,r,setup_ms,prove_ms,verify_ms,in_mem_kib,json_kib,bincode_kib,rss_mb_peak");
    for &log_n in &logs {
        run_one(log_n);
    }
}
