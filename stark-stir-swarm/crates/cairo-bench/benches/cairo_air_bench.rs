//! Criterion benchmarks for all Cairo AIR workloads on the STARK prover.
//!
//! Each benchmark runs the full pipeline:
//!   1. Build execution trace for the AIR
//!   2. LDE-evaluate all trace columns
//!   3. Compute the DEEP-ALI composition polynomial
//!   4. Run the FRI prover
//!   5. Run the FRI verifier
//!
//! AIRs tested (matching the Cairo AIR taxonomy):
//!   - Fibonacci      (w=2,  1 constraint)
//!   - PoseidonChain  (w=16, 16 constraints)  — Cairo hash step
//!   - RegisterMachine(w=8,  8 constraints)   — generic register CPU
//!   - CairoSimple    (w=8,  4 constraints)   — Cairo CPU columns
//!
//! Trace sizes (rows): 256, 1024, 4096
//! LDE blowup: 4   (rate ρ = 1/4)
//! FRI queries: 40  (≈100-bit security with Fp6 at blowup 4)
//! Schedule: binary fold [2,2,...,2] until domain collapses to 1

use criterion::{
    criterion_group, criterion_main, measurement::WallTime,
    BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use ark_goldilocks::Goldilocks as F;

use deep_ali::{
    air_workloads::{build_execution_trace, AirType},
    deep_ali_merge_general,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};

use cairo_bench::BenchRecord;

// ─────────────────────────────────────────────────────────────────────────────
//  Protocol constants
// ─────────────────────────────────────────────────────────────────────────────

type Ext = SexticExt; // Fp6 — gives ~192-bit extension-field security

const BLOWUP: usize = 32;    // paper Table III: 1/ρ₀ = 32 calibration
const NUM_QUERIES: usize = 40;
const SEED_Z: u64 = 0xDEEF_BAAD;

// Trace row counts to benchmark (power of 2).
// Add 16384 to the list for heavy benchmarks (takes several minutes per AIR).
const TRACE_SIZES: &[usize] = &[256, 1024, 4096];

// ─────────────────────────────────────────────────────────────────────────────
//  Protocol helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_schedule(n0: usize) -> Vec<usize> {
    assert!(n0.is_power_of_two(), "n0 must be a power of 2");
    vec![2usize; n0.trailing_zeros() as usize]
}

fn make_params(n0: usize) -> DeepFriParams {
    DeepFriParams {
        schedule: make_schedule(n0),
        r: NUM_QUERIES,
        seed_z: SEED_Z,
        coeff_commit_final: true,
        d_final: 1,
        stir: false,
        s0: NUM_QUERIES,
        public_inputs_hash: None,
    }
}

/// Fixed (non-random) combination coefficients — fine for benchmarks.
/// In a real protocol these come from the Fiat-Shamir transcript.
fn combination_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Core pipeline: trace → proof → verify
// ─────────────────────────────────────────────────────────────────────────────

/// Run prove + verify for `air` at trace length `n_trace`.
/// Returns (proof_bytes, prove_ms, verify_us).
fn run_pipeline(air: AirType, n_trace: usize) -> (usize, f64, f64) {
    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);
    let params = make_params(n0);

    let trace = build_execution_trace(air, n_trace);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).expect("LDE failed");

    let coeffs = combination_coeffs(air.num_constraints());
    let (c_eval, _info) =
        deep_ali_merge_general(&lde, &coeffs, air, domain.omega, n_trace, BLOWUP);

    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1e3;

    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_us = t_verify.elapsed().as_secs_f64() * 1e6;

    assert!(ok, "proof verification failed for {} n_trace={}", air.label(), n_trace);

    (deep_fri_proof_size_bytes::<Ext>(&proof, false), prove_ms, verify_us)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Criterion prove benchmarks
// ─────────────────────────────────────────────────────────────────────────────

fn bench_prove(c: &mut Criterion) {
    let mut group: BenchmarkGroup<WallTime> = c.benchmark_group("cairo_air/prove");
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    for &air in AirType::all() {
        for &n_trace in TRACE_SIZES {
            let n0 = n_trace * BLOWUP;
            let domain = FriDomain::new_radix2(n0);
            let params = make_params(n0);
            let coeffs = combination_coeffs(air.num_constraints());

            // Pre-build everything except the prove call so we measure only proving.
            let trace = build_execution_trace(air, n_trace);
            let lde = lde_trace_columns(&trace, n_trace, BLOWUP).expect("LDE failed");
            let (c_eval, _) =
                deep_ali_merge_general(&lde, &coeffs, air, domain.omega, n_trace, BLOWUP);

            let id = BenchmarkId::new(air.label(), n_trace);
            group.throughput(Throughput::Elements(n_trace as u64));

            group.bench_with_input(id, &n_trace, |b, _| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let f = c_eval.clone();
                        let t = Instant::now();
                        let _proof = deep_fri_prove::<Ext>(f, domain, &params);
                        total += t.elapsed();
                    }
                    total
                });
            });
        }
    }

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Criterion verify benchmarks
// ─────────────────────────────────────────────────────────────────────────────

fn bench_verify(c: &mut Criterion) {
    let mut group: BenchmarkGroup<WallTime> = c.benchmark_group("cairo_air/verify");
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(8));
    group.sample_size(20);

    for &air in AirType::all() {
        for &n_trace in TRACE_SIZES {
            let n0 = n_trace * BLOWUP;
            let domain = FriDomain::new_radix2(n0);
            let params = make_params(n0);
            let coeffs = combination_coeffs(air.num_constraints());

            let trace = build_execution_trace(air, n_trace);
            let lde = lde_trace_columns(&trace, n_trace, BLOWUP).expect("LDE failed");
            let (c_eval, _) =
                deep_ali_merge_general(&lde, &coeffs, air, domain.omega, n_trace, BLOWUP);
            let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);

            let id = BenchmarkId::new(air.label(), n_trace);
            group.throughput(Throughput::Elements(n_trace as u64));

            group.bench_with_input(id, &n_trace, |b, _| {
                b.iter(|| {
                    assert!(deep_fri_verify::<Ext>(&params, &proof));
                });
            });
        }
    }

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Full-pipeline summary (not Criterion — wall-clock one-shot)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_summary(c: &mut Criterion) {
    let mut group = c.benchmark_group("cairo_air/summary");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let csv_path = "cairo_air_bench.csv";
    let file = File::create(csv_path).expect("cannot create cairo_air_bench.csv");
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{}", BenchRecord::header()).unwrap();
    println!("\n{}", BenchRecord::header());

    for &air in AirType::all() {
        for &n_trace in TRACE_SIZES {
            let (proof_bytes, prove_ms, verify_us) = run_pipeline(air, n_trace);
            let rec = BenchRecord {
                air_label:   air.label().to_string(),
                n_trace,
                blowup:      BLOWUP,
                n_queries:   NUM_QUERIES,
                proof_bytes,
                prove_ms,
                verify_us,
                throughput:  (n_trace as f64) / (prove_ms / 1e3),
            };
            rec.print_row();
            writeln!(writer, "{}", rec.to_csv()).unwrap();
        }
    }

    writer.flush().unwrap();
    eprintln!("\n[cairo-bench] results written to {csv_path}");

    // A dummy one-shot bench so Criterion doesn't complain about an empty group.
    group.bench_function("noop", |b| b.iter(|| {}));
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Optional: Cairo VM real-trace benchmark
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "cairo-vm-trace")]
fn bench_cairo_vm(c: &mut Criterion) {
    use cairo_bench::run_cairo_program;
    use deep_ali::trace_import::lde_trace_columns;

    let mut group = c.benchmark_group("cairo_air/cairo_vm");
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(5);

    // Paths to pre-compiled Cairo JSON programs.
    // Build them with: cairo-compile cairo/<name>.cairo --output <name>.json
    let programs: &[(&str, &str)] = &[
        ("fibonacci", "crates/cairo-bench/cairo/fibonacci.json"),
        ("cpu_trace", "crates/cairo-bench/cairo/cpu_trace.json"),
    ];

    for (name, path) in programs {
        let real_trace = match run_cairo_program(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[cairo-vm] skipping {name}: {e}");
                continue;
            }
        };

        let n_trace = real_trace[0].len();
        if !n_trace.is_power_of_two() || n_trace < 8 {
            eprintln!("[cairo-vm] {name}: trace length {n_trace} is not a usable power of 2");
            continue;
        }

        let n0 = n_trace * BLOWUP;
        let domain = FriDomain::new_radix2(n0);
        let params = make_params(n0);

        let lde = lde_trace_columns(&real_trace, n_trace, BLOWUP).expect("LDE failed");
        let coeffs = combination_coeffs(real_trace.len());
        let air = AirType::CairoSimple; // closest AIR for pc/ap/fp columns
        let (c_eval, _) =
            deep_ali_merge_general(&lde, &coeffs, air, domain.omega, n_trace, BLOWUP);

        group.throughput(Throughput::Elements(n_trace as u64));
        let id = BenchmarkId::new("cairo_vm", format!("{name}_{n_trace}"));
        group.bench_with_input(id, &n_trace, |b, _| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let f = c_eval.clone();
                    let t = Instant::now();
                    let _proof = deep_fri_prove::<Ext>(f, domain, &params);
                    total += t.elapsed();
                }
                total
            });
        });
    }

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Criterion entry point
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(feature = "cairo-vm-trace"))]
criterion_group!(cairo_benches, bench_summary, bench_prove, bench_verify);

#[cfg(feature = "cairo-vm-trace")]
criterion_group!(cairo_benches, bench_summary, bench_prove, bench_verify, bench_cairo_vm);

criterion_main!(cairo_benches);
