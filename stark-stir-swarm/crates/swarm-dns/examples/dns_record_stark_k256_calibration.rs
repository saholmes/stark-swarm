//! K=256 wall-clock calibration — ONE complete DNS record chain proof.
//!
//! Generates a single (KSK, ZSK, A-record) tuple with real Ed25519
//! keys, signs the DNSKEY RRset and the A-record RRset, builds the
//! lookup tree, then runs the full STARK chain proof:
//!
//!   prove_dns_record_chain_stark(..., k_scalar = 256, ldt = STIR)
//!
//! which composes two K=256 ZSK→KSK STARK proofs (one for the
//! KSK→DNSKEY signature, one for the ZSK→Record signature) plus the
//! Layer-3 Merkle-inclusion check.  Per-phase wall-clock is reported
//! so we can validate the ~25-40 min/STARK extrapolation from the
//! K=8 stub's 315 s measurement.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example dns_record_stark_k256_calibration
//!
//! ⚠  Resource notes:
//!   * Wall-clock: 30-90 min PER STARK in current debug build; release
//!     mode + a modern laptop expects ~25-40 min per STARK, so a full
//!     chain bundle is ~1-1.5 hours single-core.
//!   * Memory: K=256 trace is 1024 rows × ~40,800 cells.  After LDE
//!     blowup × 32 the prover holds ~10 GB of field elements in RAM.
//!     Need ≥ 16 GB free for comfort.
//!   * To run only the FIRST STARK (KSK→DNSKEY) for a half-time
//!     calibration, set `K256_CALIB_ONE_STARK=1`.
//!
//! Per-thread heap allocator (mimalloc):
//!   macOS `libsystem_malloc` serialises threads on a global lock for
//!   medium-sized allocations (~600 KB) — exactly the per-LDE-point
//!   `cvals` Vec<F> shape produced by `eval_verify_air_v16_per_row` at
//!   K=256.  This example overrides the global allocator with mimalloc
//!   (per-thread heaps) to remove that contention.  Expected speedup
//!   over libsystem_malloc on K=256 prove: 1.5-3×.

// Override global allocator BEFORE any use statements that bring in
// alloc-using code.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

use swarm_dns::dns::merkle_path;
use swarm_dns::prover::{
    dns_lookup_build_tree,
    prove_dns_record_chain_stark,
    prove_zsk_ksk_binding_v2,
    verify_dns_record_chain_stark,
    DnsLookupInclusion, LdtMode,
};

fn main() {
    let release = !cfg!(debug_assertions);
    let one_stark_only = std::env::var("K256_CALIB_ONE_STARK").is_ok();

    println!();
    println!("┌─ K=256 Ed25519 STARK chain calibration ──────────────────────────────────────");
    println!("│  build mode  : {}",
        if release { "release" } else { "DEBUG (very slow — please re-run with --release)" });
    println!("│  AIR         : v16 verify_air (full RFC 8032 §5.1.7 cofactored, K=256)");
    println!("│  trace       : ~40,800 cells × 1024 rows");
    println!("│  ldt         : STIR");
    println!("│  scope       : {}",
        if one_stark_only { "ONE STARK proof (KSK→DNSKEY only)" }
        else              { "FULL chain — two K=256 STARK proofs + Merkle path" });
    println!("└──────────────────────────────────────────────────────────────────────────────");
    println!();

    if !release {
        println!("  ⚠  DEBUG build detected — abort.  K=256 in debug is impractically slow");
        println!("     (estimated 4-12 hours per STARK).  Re-run with `--release`.");
        return;
    }

    // ─── Synth zone keys + DNSKEY signature ──────────────────────────
    println!("[setup] generating zone keys and signing DNSKEY RRset...");
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

    // ─── Synth one A-record + ZSK signature ──────────────────────────
    let domain = "google.com.".to_string();
    let ip_bytes = vec![142u8, 251, 46, 142];
    let mut rec_rrset = Vec::new();
    rec_rrset.extend_from_slice(b"A-RRSET-V0");
    rec_rrset.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    rec_rrset.extend_from_slice(domain.as_bytes());
    rec_rrset.extend_from_slice(&(ip_bytes.len() as u64).to_le_bytes());
    rec_rrset.extend_from_slice(&ip_bytes);
    let zsk_to_rec_sig = zsk.sign(&rec_rrset).to_bytes();

    // ─── Lookup tree (just one record, padded to a power of 2) ───────
    let records = vec![
        ("filler.example.com.".to_string(), vec![0u8, 0, 0, 1]),
        (domain.clone(),                    ip_bytes.clone()),
    ];
    let (lookup_root, levels) = dns_lookup_build_tree(&records);
    let leaf_index = 1;
    let path = merkle_path(&levels, leaf_index);
    let inclusion = DnsLookupInclusion {
        domain:   domain.clone(),
        ip_bytes: ip_bytes.clone(),
        path,
        leaf_index,
    };

    let zone_fs = [0xCAu8; 32];

    println!("[setup] OK.  KSK and ZSK signatures verified natively before STARK.");
    println!();

    // ─── Calibration: one STARK only (env-gated) or both STARKs ─────
    let t_total = Instant::now();
    if one_stark_only {
        println!("[stark 1/1] proving KSK→DNSKEY at K=256...  (~25-40 min expected)");
        let t_one = Instant::now();
        let out = prove_zsk_ksk_binding_v2(
            &ksk_pub, &ksk_to_dnskey_sig, &dnskey_rrset,
            &zone_fs, &lookup_root,
            /* k_scalar */ 256, LdtMode::Stir,
        );
        let one_ms = t_one.elapsed().as_secs_f64() * 1e3;
        println!();
        println!("┌─ STARK 1 (KSK→DNSKEY) result ───────────────────────────────────────");
        println!("│  prove (worker)      : {:>10.0} ms  ({:>6.2} min)",
            out.prove_ms,        out.prove_ms        / 60_000.0);
        println!("│  self-verify         : {:>10.0} ms  ({:>6.2} min)",
            out.local_verify_ms, out.local_verify_ms / 60_000.0);
        println!("│  end-to-end          : {:>10.0} ms  ({:>6.2} min)",
            one_ms, one_ms / 60_000.0);
        println!("│  proof size          : {:>10} B   ({:>6.2} MiB)",
            out.proof_bytes,
            out.proof_bytes as f64 / 1024.0 / 1024.0);
        println!("│  pi_hash[..16]       : {}", &hex::encode(out.pi_hash)[..16]);
        println!("└──────────────────────────────────────────────────────────────────────");
        println!();
        println!("  Extrapolation: full chain bundle = 2 sequential STARKs of this size,");
        println!("  so end-to-end for one DNS record ≈ {:.1} min in this run.",
            (one_ms * 2.0) / 60_000.0);
    } else {
        println!("[stark 1/2 + 2/2] proving full chain at K=256...  (~50-80 min expected)");
        let t_chain = Instant::now();
        let bundle = prove_dns_record_chain_stark(
            &ksk_pub, &ksk_to_dnskey_sig, &dnskey_rrset,
            &zsk_pub, &zsk_to_rec_sig,    &rec_rrset,
            inclusion, &lookup_root, &zone_fs,
            /* k_scalar */ 256, LdtMode::Stir,
        );
        let chain_ms = t_chain.elapsed().as_secs_f64() * 1e3;

        println!();
        println!("┌─ Full chain bundle (KSK→DNSKEY + ZSK→Record) ───────────────────────");
        println!("│  total prove         : {:>10.0} ms  ({:>6.2} min)",
            bundle.prove_ms,        bundle.prove_ms        / 60_000.0);
        println!("│  worker self-verify  : {:>10.0} ms  ({:>6.2} min)",
            bundle.local_verify_ms, bundle.local_verify_ms / 60_000.0);
        println!("│  end-to-end          : {:>10.0} ms  ({:>6.2} min)",
            chain_ms, chain_ms / 60_000.0);
        println!("│  KSK→DNSKEY proof    : {:>10} B   ({:>6.2} MiB)",
            bundle.ksk_to_dnskey_proof.len(),
            bundle.ksk_to_dnskey_proof.len() as f64 / 1024.0 / 1024.0);
        println!("│  ZSK→Record proof    : {:>10} B   ({:>6.2} MiB)",
            bundle.zsk_to_rec_proof.len(),
            bundle.zsk_to_rec_proof.len()    as f64 / 1024.0 / 1024.0);
        println!("│  pi_hash[..16]       : {}", &hex::encode(bundle.pi_hash)[..16]);
        println!("└──────────────────────────────────────────────────────────────────────");
        println!();

        // Verifier-side timing.
        println!("[verify] running consumer-side verify_dns_record_chain_stark...");
        let t_v = Instant::now();
        // n_trace for the inner ZSK→KSK proofs at K=256 — derived from
        // the v16 layout's height for k_scalar = 256.
        let inner_n_trace = 1024;
        let res = verify_dns_record_chain_stark(&bundle, inner_n_trace, LdtMode::Stir);
        let verify_ms = t_v.elapsed().as_secs_f64() * 1e3;
        println!();
        println!("┌─ Consumer-side full verify (incl. both STARK FRI verifies) ─────────");
        println!("│  result              : {:?}", res);
        println!("│  wall-clock          : {:>10.0} ms  ({:>6.2} s)",
            verify_ms, verify_ms / 1_000.0);
        println!("└──────────────────────────────────────────────────────────────────────");
    }

    let total_ms = t_total.elapsed().as_secs_f64() * 1e3;
    println!();
    println!("[done] total run wall-clock: {:.0} ms ({:.2} min)",
        total_ms, total_ms / 60_000.0);
}
