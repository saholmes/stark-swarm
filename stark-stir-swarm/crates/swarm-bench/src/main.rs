//! Scaling-bench harness for the STIR DNS swarm.
//!
//! Spawns one `swarm-ctrl` and N `swarm-worker` processes, runs a single
//! zone-proving job, parses the resulting `zone_bundle.json`, and reports
//! per-N timings. Sweeps N over `--workers 1,2,4,8` style lists.
//!
//! Two scaling modes:
//!   * **weak**  (default) — records scale with N: each worker proves
//!     `--records-per-worker` records. Wall-clock should stay roughly
//!     flat as N grows; demonstrates linear horizontal scaling.
//!   * **strong** — total records fixed via `--total-records`; bigger N
//!     means smaller per-worker shard. Wall-clock drops with N.
//!
//! Run after `cargo build --release`:
//!     cargo run --release -p swarm-bench -- --workers 1,2,4,8

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(name = "swarm-bench", about = "STIR DNS swarm scaling bench")]
struct Args {
    /// Comma-separated worker counts to sweep.
    #[arg(long, default_value = "1,2,4")]
    workers: String,

    /// Weak-scaling: records each worker proves. Total = N × this.
    #[arg(long, default_value_t = 1024)]
    records_per_worker: usize,

    /// Strong-scaling: fix total records (split across N). Overrides --records-per-worker.
    #[arg(long)]
    total_records: Option<usize>,

    /// LDT mode for both inner shards and outer rollup.
    #[arg(long, default_value = "stir")]
    ldt: String,

    /// NIST PQ level for the controller's authority key.
    #[arg(long, default_value_t = 1)]
    nist_level: u8,

    /// Heartbeat interval (seconds). Bench keeps it short.
    #[arg(long, default_value_t = 2)]
    heartbeat_secs: u32,

    /// Directory containing the swarm-ctrl + swarm-worker binaries.
    /// Defaults to `./target/release` relative to the workspace root.
    #[arg(long)]
    binary_dir: Option<PathBuf>,

    /// Base TCP port for ctrl. Each run uses base_port + run_index.
    #[arg(long, default_value_t = 7900)]
    base_port: u16,

    /// Per-run scratch directory root. Each run uses bench_dir/run-N/.
    #[arg(long, default_value = "./bench-runs")]
    bench_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ZoneBundle {
    nist_level:        u8,
    ml_dsa_scheme:     String,
    record_count:      usize,
    shard_count:       usize,
    ldt:               String,
    outer_n_trace:     usize,
    outer_proof_bytes: usize,
    inner_workers:     Vec<InnerWorkerRecord>,
    timings_ms:        Timings,
}

#[derive(Debug, Deserialize)]
struct InnerWorkerRecord {
    worker_id:       u32,
    shard_id:        u32,
    record_count:    u64,
    proof_bytes_len: u64,
    prove_ms:        f64,
}

#[derive(Debug, Deserialize)]
struct Timings {
    wait_workers_ms:        f64,
    assign_to_last_done_ms: f64,
    outer_rollup_ms:        f64,
    sign_ms:                f64,
    total_ms:               f64,
}

#[derive(Debug)]
struct Row {
    n_workers:     usize,
    total_records: usize,
    max_inner_ms:  f64,
    sum_inner_ms:  f64,
    outer_ms:      f64,
    sign_ms:       f64,
    inner_proof_kb: usize,
    outer_proof_kb: usize,
    bundle_total_proof_kb: usize,
    wall_clock_s:  f64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let workers: Vec<usize> = args.workers.split(',')
        .map(|s| s.trim().parse::<usize>().unwrap_or(0))
        .filter(|&n| n > 0)
        .collect();
    if workers.is_empty() {
        return Err(anyhow!("--workers parsed to empty list"));
    }

    let bin_dir = args.binary_dir.clone().unwrap_or_else(|| PathBuf::from("./target/release"));
    let ctrl_bin   = bin_dir.join("swarm-ctrl");
    let worker_bin = bin_dir.join("swarm-worker");
    if !ctrl_bin.exists()   { return Err(anyhow!("swarm-ctrl binary not found at {}", ctrl_bin.display())); }
    if !worker_bin.exists() { return Err(anyhow!("swarm-worker binary not found at {}", worker_bin.display())); }

    std::fs::create_dir_all(&args.bench_dir)
        .with_context(|| format!("create bench dir {}", args.bench_dir.display()))?;

    println!("\n┌─ STIR DNS Swarm Bench ─────────────────────────────────────");
    println!("│  ctrl bin   : {}", ctrl_bin.display());
    println!("│  worker bin : {}", worker_bin.display());
    println!("│  ldt        : {}", args.ldt);
    println!("│  nist level : L{}", args.nist_level);
    println!("│  scaling    : {}",
             if args.total_records.is_some() { "strong (fixed total)" } else { "weak  (per-worker)" });
    println!("│  workers    : {:?}", workers);
    if let Some(t) = args.total_records {
        println!("│  total recs : {t}");
    } else {
        println!("│  recs/worker: {}", args.records_per_worker);
    }
    println!("└────────────────────────────────────────────────────────────\n");

    let mut rows: Vec<Row> = Vec::new();
    for (idx, &n) in workers.iter().enumerate() {
        let port = args.base_port + idx as u16;
        let total = args.total_records.unwrap_or(args.records_per_worker * n);
        let run_dir = args.bench_dir.join(format!("run-{n:03}-port-{port}"));
        let _ = std::fs::remove_dir_all(&run_dir);
        std::fs::create_dir_all(&run_dir)?;

        println!("── run N={n}  port={port}  total_records={total}  state={}", run_dir.display());

        match run_one(&ctrl_bin, &worker_bin, &args, n, total, port, &run_dir) {
            Ok(row) => {
                println!("   ✓  inner max={:.0} ms  outer={:.1} ms  total job={:.0} ms  wall={:.1} s",
                    row.max_inner_ms, row.outer_ms, row.max_inner_ms + row.outer_ms, row.wall_clock_s);
                rows.push(row);
            }
            Err(e) => {
                println!("   ✗  FAILED: {e:?}");
            }
        }
        // Pause between runs to let kernel reclaim ports.
        std::thread::sleep(Duration::from_millis(500));
    }

    print_summary(&rows);
    Ok(())
}

fn run_one(
    ctrl_bin:   &PathBuf,
    worker_bin: &PathBuf,
    args:       &Args,
    n_workers:  usize,
    total_records: usize,
    port:       u16,
    run_dir:    &PathBuf,
) -> Result<Row> {
    let bind = format!("127.0.0.1:{port}");
    let ctrl_log_path   = run_dir.join("ctrl.log");
    let ctrl_log = std::fs::File::create(&ctrl_log_path)
        .with_context(|| format!("create {}", ctrl_log_path.display()))?;
    let ctrl_log_err = ctrl_log.try_clone()?;

    let bundle_path = run_dir.join("zone_bundle.json");
    let fp_path     = run_dir.join("fingerprint.hex");

    let started = Instant::now();
    let mut ctrl_child = Command::new(ctrl_bin)
        .args([
            "--bind", &bind,
            "--state-dir", &run_dir.display().to_string(),
            "--heartbeat-secs", &args.heartbeat_secs.to_string(),
            "--wait-workers", &n_workers.to_string(),
            "--zone-records", &total_records.to_string(),
            "--zone-ldt", &args.ldt,
            "--nist-level", &args.nist_level.to_string(),
            "--exit-on-complete",
        ])
        .stdout(Stdio::from(ctrl_log))
        .stderr(Stdio::from(ctrl_log_err))
        .spawn()
        .with_context(|| "spawn swarm-ctrl")?;

    let kill_guard = ChildKillGuard(Some(&mut ctrl_child as *mut Child));

    // Wait for ctrl to publish its fingerprint (signals "listening").
    let deadline = Instant::now() + Duration::from_secs(15);
    while !fp_path.exists() {
        if Instant::now() > deadline {
            drop(kill_guard);
            return Err(anyhow!("ctrl did not write fingerprint within 15s — see {}", ctrl_log_path.display()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Spawn N workers.
    let mut worker_children: Vec<(Child, std::path::PathBuf)> = Vec::with_capacity(n_workers);
    for w in 1..=n_workers {
        let log_path = run_dir.join(format!("worker-{w:03}.log"));
        let log = std::fs::File::create(&log_path)
            .with_context(|| format!("create {}", log_path.display()))?;
        let log_err = log.try_clone()?;
        let label = format!("edge-{w:03}");
        let child = Command::new(worker_bin)
            .args([
                "--ctrl", &bind,
                "--ctrl-fingerprint-file", &fp_path.display().to_string(),
                "--label", &label,
                "--nist-level", &args.nist_level.to_string(),
            ])
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .with_context(|| format!("spawn worker {w}"))?;
        worker_children.push((child, log_path));
    }

    // Wait for ctrl to exit (it has --exit-on-complete).
    let ctrl_status = ctrl_child.wait().with_context(|| "wait ctrl")?;
    let wall_clock_s = started.elapsed().as_secs_f64();

    // Reap any leftover workers (they will exit when ctrl drops the connection,
    // but on macOS they sometimes linger briefly).
    for (c, _) in worker_children.iter_mut() {
        let _ = c.kill();
        let _ = c.wait();
    }

    // ChildKillGuard would kill ctrl on drop, but ctrl already exited.
    // Keep it dropped so it doesn't try double-kill.
    std::mem::forget(kill_guard);

    if !ctrl_status.success() && ctrl_status.code() != Some(0) {
        return Err(anyhow!("ctrl exited with status {ctrl_status:?} — see {}", ctrl_log_path.display()));
    }

    // Parse bundle.
    let json = std::fs::read_to_string(&bundle_path)
        .with_context(|| format!("read {}", bundle_path.display()))?;
    let bundle: ZoneBundle = serde_json::from_str(&json)
        .with_context(|| format!("parse {}", bundle_path.display()))?;

    let max_inner_ms: f64 = bundle.inner_workers.iter().map(|r| r.prove_ms).fold(0.0, f64::max);
    let sum_inner_ms: f64 = bundle.inner_workers.iter().map(|r| r.prove_ms).sum();
    let inner_proof_kb: usize = bundle.inner_workers.iter()
        .map(|r| r.proof_bytes_len as usize / 1024).max().unwrap_or(0);
    let bundle_total_proof_kb = bundle.inner_workers.iter()
        .map(|r| r.proof_bytes_len as usize)
        .sum::<usize>() / 1024
        + bundle.outer_proof_bytes / 1024;

    Ok(Row {
        n_workers,
        total_records,
        max_inner_ms,
        sum_inner_ms,
        outer_ms: bundle.timings_ms.outer_rollup_ms,
        sign_ms:  bundle.timings_ms.sign_ms,
        inner_proof_kb,
        outer_proof_kb: bundle.outer_proof_bytes / 1024,
        bundle_total_proof_kb,
        wall_clock_s,
    })
}

/// Drop guard that kills a child process if the surrounding stack unwinds.
/// Held by raw pointer so we can `mem::forget` it after a successful run
/// without interfering with the actual `Child` value still alive in scope.
struct ChildKillGuard(Option<*mut Child>);

impl Drop for ChildKillGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0 {
            unsafe {
                let _ = (*p).kill();
                let _ = (*p).wait();
            }
        }
    }
}

fn print_summary(rows: &[Row]) {
    if rows.is_empty() { return; }
    println!("\n┌─ Scaling summary ────────────────────────────────────────────────────────────────────");
    println!("│ {:>3} │ {:>10} │ {:>10} │ {:>10} │ {:>9} │ {:>10} │ {:>11} │ {:>10}",
             "N", "total_recs", "max_inner",
             "sum_inner", "outer_ms",
             "sig_ms", "inner_KiB", "wall_s");
    println!("├─────┼────────────┼────────────┼────────────┼───────────┼────────────┼─────────────┼────────────");
    for r in rows {
        println!("│ {:>3} │ {:>10} │ {:>9.0}ms │ {:>9.0}ms │ {:>9.1} │ {:>10.2} │ {:>11} │ {:>10.2}",
                 r.n_workers, r.total_records,
                 r.max_inner_ms, r.sum_inner_ms,
                 r.outer_ms, r.sign_ms,
                 r.inner_proof_kb, r.wall_clock_s);
    }
    println!("└──────────────────────────────────────────────────────────────────────────────────────");

    if rows.len() >= 2 {
        let baseline_max = rows[0].max_inner_ms;
        let baseline_sum = rows[0].sum_inner_ms;
        println!("\n  Strong-scaling reference: max_inner @ N={} = {:.1} ms",
                 rows[0].n_workers, baseline_max);
        println!("  Speedup (sum_inner / max_inner) per N — ideal = N");
        println!("  ┌─────┬────────────┬─────────────┬──────────┬──────────");
        println!("  │   N │  total_recs│  max_inner  │  sum/max │ work/N (= constant ⇒ linear)");
        println!("  ├─────┼────────────┼─────────────┼──────────┼──────────");
        for r in rows {
            let speedup = if r.max_inner_ms > 0.0 { r.sum_inner_ms / r.max_inner_ms } else { 0.0 };
            let normalised = r.sum_inner_ms / (r.n_workers as f64);
            println!("  │ {:>3} │ {:>10} │  {:>9.0}ms │  {:>5.2}× │  {:.0} ms",
                     r.n_workers, r.total_records, r.max_inner_ms, speedup, normalised);
        }
        println!("  └─────┴────────────┴─────────────┴──────────┴──────────");
        println!("  · `sum/max` near N ⇒ workers are running in genuine parallel");
        println!("  · `work/N` flat across rows ⇒ weak-scaling efficiency near 100%");
        println!("  · baseline_sum = {:.0} ms (single-worker total compute)", baseline_sum);
    }
}
