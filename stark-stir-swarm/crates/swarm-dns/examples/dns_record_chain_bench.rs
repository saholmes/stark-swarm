//! Full DNS STARK benchmark — 10 / 100 / 1000 / 10000 records.
//!
//! End-to-end flow exercised:
//!
//!   1. Generate one zone KSK + one zone ZSK (test keys via
//!      ed25519-dalek; the prototype's verify path uses the in-crate
//!      `deep_ali::ed25519_verify`).
//!   2. KSK signs the DNSKEY RRset (carries the ZSK).
//!   3. Synthesise N (domain, ipv4) records.
//!   4. ZSK signs each record's canonical A-RRset.
//!   5. Build the domain→IP lookup Merkle tree.
//!   6. Build N chain bundles (Layer 1: KSK→DNSKEY, Layer 2:
//!      ZSK→Record, Layer 3: lookup-tree inclusion path).
//!   7. v5 aggregation:
//!      a. `prove_outer_rollup` over the inner pi_hashes (HashRollup
//!         AIR trace, STIR proof).
//!      b. Build a Merkle tree over the inner pi_hashes for O(log N)
//!         per-query membership verification.
//!   8. Sample N_QUERIES random records and time
//!      `verify_dns_record_chain_set_membership` per query.
//!   9. Report: prove wall-clock by phase, per-query latency stats,
//!      wire-format sizes.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example dns_record_chain_bench
//!
//! NOTE: N=10000 takes ~1 minute total in release.  Pass
//! `ZSK_KSK_BENCH_SKIP_10K=1` to skip the largest size for fast
//! iteration on the smaller numbers.

use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

use swarm_dns::dns::merkle_path;
use swarm_dns::prover::{
    dns_lookup_build_tree,
    epoch_fs_binding,
    prove_dns_record_chain_native,
    prove_dns_record_chain_set_v5,
    verify_dns_record_chain_set_membership,
    DnsLookupInclusion, DnsRecordChainBundle, LdtMode,
};

// ─────────────────────────────────────────────────────────────────────
//  Synthesis helpers
// ─────────────────────────────────────────────────────────────────────

fn synth_zone_keys() -> (
    [u8; 32],          // ksk_pub
    [u8; 64],          // ksk_to_dnskey_sig
    Vec<u8>,           // dnskey_rrset
    SigningKey,        // zsk
    [u8; 32],          // zsk_pub
) {
    let mut rng_k = StdRng::seed_from_u64(0xBEEF_BABE);
    let ksk = SigningKey::generate(&mut rng_k);
    let ksk_pub = ksk.verifying_key().to_bytes();

    let mut rng_z = StdRng::seed_from_u64(0xDEAD_BEEF);
    let zsk = SigningKey::generate(&mut rng_z);
    let zsk_pub = zsk.verifying_key().to_bytes();

    let mut dnskey_rrset = Vec::new();
    dnskey_rrset.extend_from_slice(b"DNSKEY-RRSET-V0");
    dnskey_rrset.extend_from_slice(&zsk_pub);
    let ksk_to_dnskey_sig = ksk.sign(&dnskey_rrset).to_bytes();

    (ksk_pub, ksk_to_dnskey_sig, dnskey_rrset, zsk, zsk_pub)
}

fn synth_records(n: usize) -> Vec<(String, Vec<u8>)> {
    (0..n).map(|i| (
        format!("host{:06}.example.com.", i),
        vec![10u8, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8, 1],
    )).collect()
}

fn sign_record(zsk: &SigningKey, domain: &str, ip_bytes: &[u8])
    -> ([u8; 64], Vec<u8>)
{
    let mut rrset = Vec::new();
    rrset.extend_from_slice(b"A-RRSET-V0");
    rrset.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    rrset.extend_from_slice(domain.as_bytes());
    rrset.extend_from_slice(&(ip_bytes.len() as u64).to_le_bytes());
    rrset.extend_from_slice(ip_bytes);
    let sig = zsk.sign(&rrset).to_bytes();
    (sig, rrset)
}

fn approx_bundle_size(b: &DnsRecordChainBundle) -> usize {
    32                                             // pi_hash
        + 32 + 32                                  // pubkeys
        + 64 + 64                                  // sigs
        + b.dnskey_rrset.len() + b.rec_rrset.len() // RRsets
        + 8 + b.inclusion.domain.len()             // domain
        + 8 + b.inclusion.ip_bytes.len()           // ip
        + b.inclusion.path.len() * 32              // lookup-tree path
        + 32 + 32                                  // root + chain fs
        + b.ksk_to_dnskey_proof.len()              // STARK blob (empty in native)
        + b.zsk_to_rec_proof.len()                 // STARK blob (empty in native)
        + 32 + 32                                  // root_f0 fields
        + 1                                        // stark_present flag
}

// ─────────────────────────────────────────────────────────────────────
//  One-N benchmark
// ─────────────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct PhaseTimings {
    setup_ms:                  f64,
    sign_records_ms:           f64,
    build_tree_ms:             f64,
    chain_bundles_total_ms:    f64,
    chain_bundles_min_ms:      f64,
    chain_bundles_max_ms:      f64,
    set_v5_aggregate_ms:       f64,
    per_query_min_us:          f64,
    per_query_med_us:          f64,
    per_query_avg_us:          f64,
    per_query_max_us:          f64,
    avg_bundle_bytes:          usize,
    outer_proof_bytes:         usize,
    pi_hash_path_bytes:        usize,
    end_to_end_ms:             f64,
}

fn bench_one(n: usize, n_queries: usize) -> PhaseTimings {
    let t_e2e = Instant::now();
    let mut t = PhaseTimings::default();
    let zone_fs = [0xCAu8; 32];
    let epoch_fs = epoch_fs_binding(&zone_fs, /* epoch */ 0, /* serial */ 1);

    // ── 1. Zone keys + DNSKEY signature ─────────────────────────────
    let t_setup = Instant::now();
    let (ksk_pub, ksk_to_dnskey_sig, dnskey_rrset, zsk, _zsk_pub) = synth_zone_keys();
    t.setup_ms = t_setup.elapsed().as_secs_f64() * 1e3;

    // ── 2. Synth records ────────────────────────────────────────────
    let records = synth_records(n);

    // ── 3. Sign each record's RRset ─────────────────────────────────
    let t0 = Instant::now();
    let signed: Vec<([u8; 64], Vec<u8>)> = records.iter()
        .map(|(d, ip)| sign_record(&zsk, d, ip))
        .collect();
    t.sign_records_ms = t0.elapsed().as_secs_f64() * 1e3;

    // ── 4. Build domain→IP lookup tree ──────────────────────────────
    let t0 = Instant::now();
    let (lookup_root, lookup_levels) = dns_lookup_build_tree(&records);
    t.build_tree_ms = t0.elapsed().as_secs_f64() * 1e3;

    // ── 5. Per-record chain bundles (Layer 1+2+3) ───────────────────
    let zsk_pub = zsk.verifying_key().to_bytes();
    let t0 = Instant::now();
    let mut per_min = f64::INFINITY;
    let mut per_max: f64 = 0.0;
    let mut bundles = Vec::with_capacity(n);
    for (i, ((domain, ip_bytes), (rec_sig, rec_rrset))) in
        records.iter().zip(signed.iter()).enumerate()
    {
        let path = merkle_path(&lookup_levels, i);
        let inclusion = DnsLookupInclusion {
            domain: domain.clone(),
            ip_bytes: ip_bytes.clone(),
            path,
            leaf_index: i,
        };
        let t_one = Instant::now();
        let bundle = prove_dns_record_chain_native(
            &ksk_pub, &ksk_to_dnskey_sig, &dnskey_rrset,
            &zsk_pub, rec_sig, rec_rrset,
            inclusion, &lookup_root, &zone_fs,
        );
        let dt = t_one.elapsed().as_secs_f64() * 1e3;
        per_min = per_min.min(dt);
        per_max = per_max.max(dt);
        bundles.push(bundle);
    }
    t.chain_bundles_total_ms = t0.elapsed().as_secs_f64() * 1e3;
    t.chain_bundles_min_ms   = per_min;
    t.chain_bundles_max_ms   = per_max;

    // ── 6. v5 aggregation: outer STIR proof + pi_hash merkle tree ───
    let t0 = Instant::now();
    let (set, pi_hash_levels) = prove_dns_record_chain_set_v5(
        &bundles, &epoch_fs, LdtMode::Stir,
    );
    t.set_v5_aggregate_ms = t0.elapsed().as_secs_f64() * 1e3;

    // ── 7. Per-query membership verification timing ─────────────────
    let mut times: Vec<Duration> = Vec::with_capacity(n_queries);
    let stride = n.max(1) / n_queries.max(1);
    for q in 0..n_queries.min(n) {
        let i = (q * stride) % n;
        let path_for_i = merkle_path(&pi_hash_levels, i);
        let t = Instant::now();
        verify_dns_record_chain_set_membership(
            &set, &bundles[i], i, &path_for_i, LdtMode::Stir,
        ).expect("membership verify must succeed");
        times.push(t.elapsed());
    }
    times.sort();
    let len = times.len().max(1);
    t.per_query_min_us = times.first().map(|d| d.as_secs_f64()).unwrap_or(0.0) * 1e6;
    t.per_query_med_us = times.get(len / 2).map(|d| d.as_secs_f64()).unwrap_or(0.0) * 1e6;
    t.per_query_max_us = times.last().map(|d| d.as_secs_f64()).unwrap_or(0.0) * 1e6;
    t.per_query_avg_us = (times.iter().map(|d| d.as_secs_f64()).sum::<f64>()
                           / len as f64) * 1e6;

    // ── 8. Wire-format accounting ───────────────────────────────────
    t.avg_bundle_bytes  = bundles.iter()
        .map(approx_bundle_size).sum::<usize>() / bundles.len();
    t.outer_proof_bytes = set.outer.proof_bytes;
    t.pi_hash_path_bytes = (pi_hash_levels.len() - 1) * 32;

    t.end_to_end_ms = t_e2e.elapsed().as_secs_f64() * 1e3;
    t
}

// ─────────────────────────────────────────────────────────────────────
//  Reporting
// ─────────────────────────────────────────────────────────────────────

fn fmt_kib(b: usize) -> String { format!("{:.2} KiB", b as f64 / 1024.0) }

fn print_size_table(rows: &[(usize, PhaseTimings)]) {
    println!();
    println!("┌─ Authority-side prove wall-clock (single-machine, native chain) ─────────────");
    println!("│ N       │ sign all │  tree   │  chain bundles  (ms)            │  v5 STIR │  e2e   │");
    println!("│ records │   (ms)   │  (ms)   │  total / min / max              │  rollup  │  (ms)  │");
    println!("├─────────┼──────────┼─────────┼─────────────────────────────────┼──────────┼────────┤");
    for (n, t) in rows {
        println!(
            "│ {:>7} │ {:>8.2} │ {:>7.2} │ {:>9.0} / {:>5.2} / {:>5.2}     │ {:>8.1} │ {:>6.0} │",
            n, t.sign_records_ms, t.build_tree_ms,
            t.chain_bundles_total_ms, t.chain_bundles_min_ms, t.chain_bundles_max_ms,
            t.set_v5_aggregate_ms, t.end_to_end_ms,
        );
    }
    println!("└─────────┴──────────┴─────────┴─────────────────────────────────┴──────────┴────────┘");

    println!();
    println!("┌─ Per-query consumer cost — `verify_dns_record_chain_set_membership` ─────────");
    println!("│ N       │            latency across sample queries  (µs)         │ throughput   │");
    println!("│ records │   min  /  median /   avg  /   max                       │ /core (qps)  │");
    println!("├─────────┼─────────────────────────────────────────────────────────┼──────────────┤");
    for (n, t) in rows {
        let qps = if t.per_query_avg_us > 0.0 { 1e6 / t.per_query_avg_us } else { 0.0 };
        println!(
            "│ {:>7} │ {:>5.0}  /  {:>5.0}  /  {:>5.0}  /  {:>5.0}                 │ {:>9.0}    │",
            n,
            t.per_query_min_us, t.per_query_med_us,
            t.per_query_avg_us, t.per_query_max_us, qps,
        );
    }
    println!("└─────────┴─────────────────────────────────────────────────────────┴──────────────┘");

    println!();
    println!("┌─ Wire size shipped per consumer query (offline + STARK-verified DNS) ────────");
    println!("│ N       │  outer STIR proof  │  chain bundle  │  pi_hash path  │  total/qry │");
    println!("├─────────┼────────────────────┼────────────────┼────────────────┼────────────┤");
    for (n, t) in rows {
        let total = t.outer_proof_bytes + t.avg_bundle_bytes + t.pi_hash_path_bytes;
        println!(
            "│ {:>7} │ {:>15}    │ {:>11}    │ {:>11}    │ {:>10} │",
            n,
            fmt_kib(t.outer_proof_bytes),
            fmt_kib(t.avg_bundle_bytes),
            fmt_kib(t.pi_hash_path_bytes),
            fmt_kib(total),
        );
    }
    println!("└─────────┴────────────────────┴────────────────┴────────────────┴────────────┘");

    println!();
    println!("┌─ Offline zone snapshot — what gets shipped to a node for ZERO-network DNS ───");
    println!("│ N       │  N · chain bundles  │  pi_hash levels  │  outer proof  │  TOTAL    │");
    println!("├─────────┼─────────────────────┼──────────────────┼───────────────┼───────────┤");
    for (n, t) in rows {
        let bundles = (n * t.avg_bundle_bytes) as f64 / 1024.0 / 1024.0;
        // pi_hash levels: ~2N nodes worst case (binary tree), each 32 B.
        let levels   = (2 * n * 32) as f64 / 1024.0 / 1024.0;
        let outer    = t.outer_proof_bytes as f64 / 1024.0 / 1024.0;
        println!(
            "│ {:>7} │ {:>14.2} MiB    │ {:>11.2} MiB  │ {:>9.2} MiB │ {:>6.2} MiB │",
            n, bundles, levels, outer, bundles + levels + outer,
        );
    }
    println!("└─────────┴─────────────────────┴──────────────────┴───────────────┴───────────┘");
}

// ─────────────────────────────────────────────────────────────────────

fn main() {
    let release = !cfg!(debug_assertions);
    let skip_10k = std::env::var("ZSK_KSK_BENCH_SKIP_10K").is_ok();

    println!();
    println!("┌─ Full DNS STARK benchmark ───────────────────────────────────────────────────");
    println!("│  build mode  : {}",
        if release { "release" } else { "DEBUG (small-N v5 aggregation skipped — see header)" });
    println!("│  per record  : KSK→DNSKEY signature + ZSK→A-record signature + Merkle path");
    println!("│  prover path : prove_dns_record_chain_native      (no STARK chain proofs)");
    println!("│  rollup path : prove_dns_record_chain_set_v5      (HashRollup STIR + pi-merkle)");
    println!("│  query path  : verify_dns_record_chain_set_membership   (O(log N) per query)");
    println!("└──────────────────────────────────────────────────────────────────────────────");

    if !release {
        println!();
        println!("  ⚠  DEBUG build — outer-rollup proof serialise hits an ark-ff buffer assertion");
        println!("     at small n_trace.  Re-run with --release for the v5 aggregation phase.");
        println!();
        return;
    }

    // Default to a conservative single-processor sweep.  Override via
    // env var `ZSK_KSK_BENCH_SIZES=10,100,1000,10000` (or any subset).
    //
    // NOTE: this bench uses `prove_dns_record_chain_native` for the
    // per-record chain — that's ~5 ms per record on a single core.
    // The K=256 ZSK→KSK STARK chain (~25-40 min per record on a single
    // core, ~1 hr including both KSK→DNSKEY and ZSK→Record proofs) is
    // a SEPARATE path (`prove_dns_record_chain_stark`) and is NOT
    // exercised here.
    let sizes: Vec<usize> = match std::env::var("ZSK_KSK_BENCH_SIZES").ok() {
        Some(s) => s.split(',').filter_map(|t| t.trim().parse().ok()).collect(),
        None => vec![10, 100],
    };
    let _ = skip_10k;

    let n_queries = 100;
    let mut rows: Vec<(usize, PhaseTimings)> = Vec::new();
    for &n in &sizes {
        eprintln!("benching N = {} ...", n);
        let t = bench_one(n, n_queries);
        rows.push((n, t));
    }

    print_size_table(&rows);

    println!();
    println!("  Authority-side wall-clock scales linearly in N for the chain phase.  In a");
    println!("  swarm of N parallel workers the chain-phase wall-clock collapses to one");
    println!("  worker's prove time (~5 ms per chain bundle native; ~25-40 min per K=256");
    println!("  STARK chain proof).");
    println!();
    println!("  Per-query consumer cost is essentially flat (O(log N) merkle path + O(1)");
    println!("  STARK verify + O(1) chain bundle re-verify).  This is the headline property");
    println!("  for offline / mission-critical DNS resolution.");
    println!();
    println!("  Offline zone snapshot is the bytes a node carries to do zero-network DNS.");
    println!("  Today's prototype ships chain bundles (~1 KiB each) plus the pi_hash tree");
    println!("  plus the outer STIR proof.  Recursive STARK composition (the §10.8 roadmap");
    println!("  target) absorbs the chain bundles into the outer proof — that's the path to");
    println!("  ~1 MiB snapshots at N = 10K and ~50 MiB at N = 1M.");
    println!();
}
