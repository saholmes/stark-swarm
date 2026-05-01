use rayon;
use ark_ff::UniformRand;
use ark_goldilocks::Goldilocks as F;
use criterion::{
    criterion_group, criterion_main, measurement::WallTime,
    BenchmarkGroup, Criterion, Throughput,
};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use deep_ali::trace_import::real_trace_inputs;
use deep_ali::air_workloads::{AirType, build_execution_trace};
use deep_ali::trace_import::trace_inputs_from_air;

use deep_ali::{
    deep_ali_merge_evals,
    fri::{
        deep_fri_prove,
        deep_fri_proof_size_bytes,
        deep_fri_verify,
        FriDomain,
        DeepFriParams,
    },
};

use deep_ali::sextic_ext::SexticExt;
use deep_ali::tower_field::TowerField;

type Ext = SexticExt;

// ═══════════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════════

/// Blowup (inverse rate).  ρ = 1 / BLOWUP.
///
///   BLOWUP =  4  →  ρ = 1/4
///   BLOWUP = 32  →  ρ = 1/32
const BLOWUP: usize = 32;

/// Number of FRI queries.
///
/// Johnson bound: δ = 1 − √ρ.
///
///   ρ = 1/32  →  δ = 1 − 1/√32 ≈ 0.8232
///   bits-per-query = −log₂(1 − δ) = −log₂(1/√32) = ½·log₂(32) = 2.5
///
/// For 128-bit security:  r ≥ ⌈128 / 2.5⌉ = 52.
/// We use 54 for a small margin.
///
/// (Comparison: blowup=4 gives only 1 bit/query, requiring r=128.)
const R_QUERIES: usize = 54;

/// Set to `false` for classic FRI, `true` for STIR mode.
const USE_STIR: bool = true;

// ═══════════════════════════════════════════════════════════════════
//  CSV record
// ═══════════════════════════════════════════════════════════════════

#[derive(Default, Clone)]
struct CsvRow {
    air_type: String,
    air_width: usize,
    air_constraints: usize,
    label: String,
    schedule: String,
    k: usize,
    proof_bytes: usize,
    prove_s: f64,
    verify_ms: f64,
    prove_elems_per_s: f64,
    delta_size_pct: f64,
    delta_prove_pct: f64,
    delta_verify_pct: f64,
    delta_throughput_pct: f64,
}

impl CsvRow {
    fn header() -> &'static str {
        "csv,air_type,air_w,air_constraints,\
         label,k,schedule,\
         proof_bytes,prove_s,verify_ms,prove_elems_per_s,\
         delta_size_pct,delta_prove_pct,delta_verify_pct,delta_throughput_pct"
    }
    fn to_line(&self) -> String {
        format!(
            "csv,{},{},{},{},{},{},{},{:.6},{:.3},{:.6},{:.2},{:.2},{:.2},{:.2}\n",
            self.air_type,
            self.air_width,
            self.air_constraints,
            self.label,
            self.k,
            self.schedule,
            self.proof_bytes,
            self.prove_s,
            self.verify_ms,
            self.prove_elems_per_s,
            self.delta_size_pct,
            self.delta_prove_pct,
            self.delta_verify_pct,
            self.delta_throughput_pct,
        )
    }
    fn print_stdout(&self) {
        print!("{}", self.to_line());
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Schedule helpers
// ═══════════════════════════════════════════════════════════════════

fn schedule_str(s: &[usize]) -> String {
    format!(
        "[{}]",
        s.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
    )
}

fn log2_pow2(x: usize) -> usize {
    assert!(x.is_power_of_two());
    x.trailing_zeros() as usize
}

fn k_min_for_schedule(schedule: &[usize]) -> usize {
    schedule.iter().map(|&m| log2_pow2(m)).sum()
}

fn divides_chain(n0: usize, schedule: &[usize]) -> bool {
    let mut n = n0;
    for &m in schedule {
        if n % m != 0 {
            return false;
        }
        n /= m;
    }
    true
}

fn ks_for_schedule(schedule: &[usize], k_lo: usize, k_hi: usize) -> Vec<usize> {
    let k_min = k_min_for_schedule(schedule);
    (k_lo.max(k_min)..=k_hi)
        .filter(|&k| divides_chain(1usize << k, schedule))
        .collect()
}

fn normalize_fri_schedule(n0: usize, mut schedule: Vec<usize>) -> Vec<usize> {
    let mut n = n0;
    for &m in &schedule {
        assert!(n % m == 0, "schedule does not divide domain");
        n /= m;
    }
    if n > 1 {
        assert!(n.is_power_of_two(), "final layer must be power of two");
        schedule.push(n);
    }
    schedule
}

// ═══════════════════════════════════════════════════════════════════
//  Main benchmark
// ═══════════════════════════════════════════════════════════════════

fn bench_e2e_mf_fri(c: &mut Criterion) {
    eprintln!(
        "[RAYON CHECK] current_num_threads = {}",
        rayon::current_num_threads()
    );
    eprintln!(
        "[CONFIG] BLOWUP={} R_QUERIES={} USE_STIR={} rho=1/{} \
         delta≈{:.4} bits/query≈{:.2}",
        BLOWUP,
        R_QUERIES,
        USE_STIR,
        BLOWUP,
        1.0 - (1.0 / BLOWUP as f64).sqrt(),
        -((1.0 / BLOWUP as f64).sqrt().log2()),
    );

    let mut g: BenchmarkGroup<WallTime> = c.benchmark_group("e2e_mf_fri");
    g.warm_up_time(Duration::from_secs(5));
    g.measurement_time(Duration::from_secs(20));
    g.sample_size(10);

    let seed_z: u64 = 0xDEEF_BAAD;

    // With BLOWUP=32, n_trace = n0/32 = 2^(k-5).
    // k_lo=15 → n_trace = 2^10 = 1024  (smallest practical trace)
    // k_lo=11 with blowup=32 would give n_trace=64, far too small.
    let k_lo = 20usize;
    let k_hi = 20usize;

    let presets: &[(&str, &[usize])] = &[
        ("2power16",       &[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]),
        ("16by16times5",   &[16,16,16,16,16]), 
        ("64by32by16by16", &[64,32,16,16]),
        //("16by16by16",     &[16,16,16]),
        //("32by16by8",      &[32,16,8]),
        //("64by32by16",     &[64,32,16]),
        //("16by16by8",      &[16,16,8]),
    ];

    let air_types = AirType::all();

    let file = File::create("benchmarkdata.csv").unwrap();
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{}", CsvRow::header()).unwrap();
    println!("{}", CsvRow::header());

    let mut paper_baseline: HashMap<(String, usize), CsvRow> = HashMap::new();
    let mut rng_seed = 1337u64;

    for &air in air_types {
        eprintln!(
            "\n╔══════════════════════════════════════════════════╗"
        );
        eprintln!(
            "║  AIR: {:20}  w={:<3}  constraints={:<3}  ║",
            air.label(),
            air.width(),
            air.num_constraints(),
        );
        eprintln!(
            "╚══════════════════════════════════════════════════╝"
        );

        for &(label, schedule) in presets {
            let ks = ks_for_schedule(schedule, k_lo, k_hi);

            eprintln!(
                "\n[PRESET] air={} label={} schedule={} configs={}",
                air.label(),
                label,
                schedule_str(schedule),
                ks.len()
            );

            for &k in &ks {
                let run_start = Instant::now();

                let n0 = 1usize << k;
                let n_trace = n0 / BLOWUP;
                g.throughput(Throughput::Elements(n0 as u64));

                let normalized_schedule =
                    normalize_fri_schedule(n0, schedule.to_vec());

                eprintln!(
                    "[START] air={} label={} schedule={} k={} (n0={}, n_trace={}, blowup={})",
                    air.label(),
                    label,
                    schedule_str(&normalized_schedule),
                    k,
                    n0,
                    n_trace,
                    BLOWUP,
                );

                rng_seed = rng_seed.wrapping_mul(1103515245).wrapping_add(12345);
                let mut _rng = StdRng::seed_from_u64(rng_seed);

                // ── Trace generation ──
                let trace = match air {
                    AirType::Fibonacci => {
                        real_trace_inputs(n0, BLOWUP)
                    }
                    _ => {
                        let trace_cols = build_execution_trace(air, n_trace);
                        trace_inputs_from_air(trace_cols, n0, BLOWUP)
                    }
                };

                let a_eval = trace.a_eval;
                let s_eval = trace.s_eval;
                let e_eval = trace.e_eval;
                let t_eval = trace.t_eval;

                let domain0 = FriDomain::new_radix2(n0);

                // ── DEEP-ALI merge ──
                let f0_ali = deep_ali_merge_evals(
                    &a_eval,
                    &s_eval,
                    &e_eval,
                    &t_eval,
                    domain0.omega,
                    n_trace,
                );

                // ── FRI params ──
                let params = DeepFriParams {
                    schedule: normalized_schedule.clone(),
                    r: if USE_STIR { 0 } else { R_QUERIES },
                    seed_z,
                    coeff_commit_final: true,
                    d_final: 1,
                    stir: USE_STIR,
                    s0: if USE_STIR { R_QUERIES } else { 0 },
                };

                // ── Prove ──
                let t0 = Instant::now();
                let proof = deep_fri_prove::<Ext>(
                    f0_ali.clone(), domain0, &params,
                );
                let prove_s = t0.elapsed().as_secs_f64();

                // ── Verify ──
                let t1 = Instant::now();
                assert!(deep_fri_verify::<Ext>(&params, &proof));
                let verify_ms = t1.elapsed().as_secs_f64() * 1e3;

                let proof_bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);

                let mut row = CsvRow {
                    air_type: air.label().to_string(),
                    air_width: air.width(),
                    air_constraints: air.num_constraints(),
                    label: label.to_string(),
                    schedule: schedule_str(&normalized_schedule),
                    k,
                    proof_bytes,
                    prove_s,
                    verify_ms,
                    prove_elems_per_s: n0 as f64 / prove_s,
                    delta_size_pct: 0.0,
                    delta_prove_pct: 0.0,
                    delta_verify_pct: 0.0,
                    delta_throughput_pct: 0.0,
                };

                let baseline_key = (air.label().to_string(), k);
                if label == "2power16" {
                    paper_baseline.insert(baseline_key, row.clone());
                } else if let Some(base) =
                    paper_baseline.get(&(air.label().to_string(), k))
                {
                    row.delta_size_pct =
                        100.0 * (row.proof_bytes as f64 - base.proof_bytes as f64)
                            / base.proof_bytes as f64;
                    row.delta_prove_pct =
                        100.0 * (row.prove_s - base.prove_s) / base.prove_s;
                    row.delta_verify_pct =
                        100.0 * (row.verify_ms - base.verify_ms) / base.verify_ms;
                    row.delta_throughput_pct =
                        100.0
                            * (row.prove_elems_per_s - base.prove_elems_per_s)
                            / base.prove_elems_per_s;
                }

                row.print_stdout();
                std::io::stdout().flush().unwrap();
                writer.write_all(row.to_line().as_bytes()).unwrap();
                writer.flush().unwrap();

                eprintln!(
                    "[DONE ] air={} label={} k={} prove={:.2}s verify={:.2}ms \
                     proof={} bytes  [Fp{}]  [stir={}]  [blowup={}]",
                    air.label(),
                    label,
                    k,
                    prove_s,
                    verify_ms,
                    proof_bytes,
                    Ext::DEGREE,
                    USE_STIR,
                    BLOWUP,
                );

                let run_secs = run_start.elapsed().as_secs_f64();
                eprintln!(
                    "[ETA ] air={} label={} schedule={} elapsed={:.2}s",
                    air.label(),
                    label,
                    schedule_str(&normalized_schedule),
                    run_secs
                );
            }
        }
    }

    g.finish();
}

criterion_group!(e2e, bench_e2e_mf_fri);
criterion_main!(e2e);