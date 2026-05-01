//! DNS Megazone Rollup Demo — 5 inner shards × N records → 1 outer rollup.
//!
//! Models a "Mega Enterprise / multi-cloud" tier deployment from
//! `docs/scaling-analysis.md`: 5 shards × 2 M records ≈ 10 M total records,
//! proven in ~5.5 min wall-clock with 5-way parallelism (or 27 min sequential).
//!
//! Usage:
//!   cargo run --release -p cairo-bench --example dns_megazone_demo \
//!       -- [--shards N] [--records-per-shard N] [--quick|--medium|--full]
//!
//! Default: --quick (4 K records/shard, ~2 s total) so the demo is
//! always runnable for validation.  Use --full for the actual 10 M
//! deployment scenario (≈ 27 min sequential on a 16 GB box).
//!
//! Modes:
//!   --quick    1 024 records/shard  (n_trace = 2¹², ~1 s total)
//!   --medium  65 536 records/shard  (n_trace = 2¹⁸, ~35 s total)
//!   --full   2 097 152 records/shard (n_trace = 2²³, ~27 min total)
//!
//! The demo proves all shards sequentially (rayon already parallelizes
//! within each STARK), then aggregates inner pi_hashes into one outer
//! rollup STARK, verifies all proofs, and demonstrates an inclusion
//! proof for one specific DNS record.

use std::time::Instant;

use ark_ff::{PrimeField, Zero};
use ark_goldilocks::Goldilocks as F;

use deep_ali::{
    air_workloads::{build_hash_rollup_trace, pack_hash_to_leaves, AirType},
    deep_ali_merge_general,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};

use swarm_dns::dns::{merkle_build, merkle_path, merkle_root, merkle_verify, DnsRecord};
use swarm_dns::dns_authority::{level_hash, pk_binding_hash, AuthorityKeypair, NistLevel};

type Ext = SexticExt;
const BLOWUP: usize = 32;     // paper Table III: 1/ρ₀ = 32 calibration
const NUM_QUERIES: usize = 54; // NIST L1 / q = 2^40
const SEED_Z: u64 = 0xDEEF_BAAD;

// ─────────────────────────────────────────────────────────────────────────────
//  CLI parsing (no external deps)
// ─────────────────────────────────────────────────────────────────────────────

/// Low-degree-test mode for the rollup proofs. STIR is the default; FRI
/// arity-2 is kept for comparison benchmarks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ldt { Stir, Fri }

impl Ldt {
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "stir" => Ok(Self::Stir),
            "fri"  => Ok(Self::Fri),
            other  => Err(format!("invalid --ldt '{other}' (expected stir or fri)")),
        }
    }
    fn label(self) -> &'static str {
        match self { Self::Stir => "STIR", Self::Fri => "FRI (arity-2)" }
    }
    fn short(self) -> &'static str {
        match self { Self::Stir => "STIR", Self::Fri => "FRI" }
    }
    fn is_stir(self) -> bool { matches!(self, Self::Stir) }
}

struct Args {
    shards: usize,
    records_per_shard: usize,
    nist_level: NistLevel,
    ldt: Ldt,
}

impl Args {
    fn parse() -> Self {
        let mut a = Args {
            shards: 5,
            records_per_shard: 1024, // --quick default
            nist_level: NistLevel::L1,
            ldt: Ldt::Stir,
        };
        let mut iter = std::env::args().skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--quick"  => a.records_per_shard = 1024,
                "--medium" => a.records_per_shard = 65_536,
                "--full"   => a.records_per_shard = 2_097_152,
                "--shards" => a.shards = iter.next().unwrap().parse().unwrap(),
                "--records-per-shard" => a.records_per_shard = iter.next().unwrap().parse().unwrap(),
                "--nist-level" => {
                    let v = iter.next().expect("--nist-level requires 1, 3, or 5");
                    a.nist_level = NistLevel::parse(&v).unwrap_or_else(|e| {
                        eprintln!("{e}");
                        std::process::exit(2);
                    });
                }
                "--ldt" => {
                    let v = iter.next().expect("--ldt requires stir or fri");
                    a.ldt = Ldt::parse(&v).unwrap_or_else(|e| {
                        eprintln!("{e}");
                        std::process::exit(2);
                    });
                }
                "--help" | "-h" => {
                    eprintln!("usage: dns_megazone_demo [--shards N] [--records-per-shard N] [--quick|--medium|--full] [--nist-level 1|3|5] [--ldt stir|fri]");
                    std::process::exit(0);
                }
                other => {
                    eprintln!("unknown arg: {other}");
                    std::process::exit(2);
                }
            }
        }
        a
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Synthetic zone generator
// ─────────────────────────────────────────────────────────────────────────────

fn make_record(i: u64) -> DnsRecord {
    // Mix record types to make the zone realistic.
    match i % 4 {
        0 => DnsRecord::a(
            &format!("host-{i:08x}.example.com"), 300,
            [10, ((i >> 16) & 0xff) as u8, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8],
        ),
        1 => DnsRecord::aaaa(
            &format!("v6-{i:08x}.example.com"), 300,
            {
                let mut b = [0u8; 16];
                b[0..8].copy_from_slice(&i.to_be_bytes());
                b[8..16].copy_from_slice(&(i ^ 0xCAFE_BABE_DEAD_BEEF).to_be_bytes());
                b
            },
        ),
        2 => DnsRecord::txt(
            &format!("txt-{i:08x}.example.com"), 60,
            &format!("v=auth1;rec={i}"),
        ),
        _ => DnsRecord::mx(
            &format!("mail-{i:08x}.example.com"), 300, (i % 1000) as u16,
            &format!("mx{}.example.com", i & 0xff),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Rollup pipeline
// ─────────────────────────────────────────────────────────────────────────────

fn next_pow2(x: usize) -> usize { x.next_power_of_two().max(8) }

fn build_trace_bytes(leaves: &[u64], n_trace: usize) -> Vec<Vec<F>> {
    build_hash_rollup_trace(n_trace, leaves)
}

/// LDT folding schedule. Mirrors `default_schedule` in
/// `crates/api/src/routes/prove.rs`:
///   * STIR: arity-8 + residual to land at size 1
///   * FRI : arity-2 binary fold (the only proven-secure FRI arity)
fn make_schedule(n0: usize, ldt: Ldt) -> Vec<usize> {
    assert!(n0.is_power_of_two(), "n0 must be a power of 2");
    let log_n0 = n0.trailing_zeros() as usize;
    if !ldt.is_stir() {
        return vec![2usize; log_n0];
    }
    let log_arity = 3usize; // log2(8)
    let full_folds = log_n0 / log_arity;
    let remainder_log = log_n0 % log_arity;
    let mut schedule = vec![8usize; full_folds];
    if remainder_log > 0 {
        schedule.push(1usize << remainder_log);
    }
    schedule
}

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

#[derive(Debug)]
struct ShardOutput {
    pi_hash:   [u8; 32],
    proof_size: usize,
    prove_ms:  f64,
    verify_ms: f64,
    merkle_root: [u8; 32],
    merkle_levels: Vec<Vec<[u8; 32]>>,  // kept for inclusion proof demo
}

/// Hash records → Merkle tree → HashRollup STARK trace → prove → verify.
/// Returns the shard's pi_hash (32-byte commitment ready for the outer rollup),
/// timings, and the Merkle tree (so we can demo inclusion proofs).
fn prove_shard(
    label:    &str,
    salt:     &[u8; 16],
    records:  &[DnsRecord],
    pk_hash:  &[u8; 32],
    ldt:      Ldt,
) -> ShardOutput {
    let total = records.len();
    println!("  [{label}] records = {total}");

    // 1. Per-record salted, doubly-hashed leaves
    let t_hash = Instant::now();
    let leaf_hashes: Vec<[u8; 32]> = records.iter().map(|r| r.leaf_hash(salt)).collect();
    println!("        record hashing: {:.2} s", t_hash.elapsed().as_secs_f64());

    // 2. Off-chain Merkle tree → root committed in pi_hash
    let t_merkle = Instant::now();
    let levels = merkle_build(&leaf_hashes);
    let root   = merkle_root(&levels);
    println!("        merkle tree:    {:.2} s   root={}…",
             t_merkle.elapsed().as_secs_f64(), &hex::encode(root)[..16]);

    // 3. Build STARK trace: stream all packed-h2 leaves through HashRollup
    //    Trace length must be ≥ 4 × records, padded to next power of 2.
    let active_leaves: Vec<u64> = leaf_hashes.iter().flat_map(|h| pack_hash_to_leaves(h)).collect();
    let n_trace = next_pow2(active_leaves.len());
    let mut leaves: Vec<u64> = active_leaves;
    leaves.resize(n_trace, 0);

    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);

    let t_setup = Instant::now();
    let trace = build_trace_bytes(&leaves, n_trace);
    let lde   = lde_trace_columns(&trace, n_trace, BLOWUP).expect("LDE failed");
    let coeffs = comb_coeffs(AirType::HashRollup.num_constraints());
    let (c_eval, _) = deep_ali_merge_general(
        &lde, &coeffs, AirType::HashRollup, domain.omega, n_trace, BLOWUP,
    );
    println!("        trace + DEEP-ALI: {:.2} s   n_trace=2^{}",
             t_setup.elapsed().as_secs_f64(), n_trace.trailing_zeros());

    let params = DeepFriParams {
        schedule: make_schedule(n0, ldt),
        r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1,
        stir: ldt.is_stir(), s0: NUM_QUERIES,
        public_inputs_hash: Some(*pk_hash),
    };

    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1e3;
    println!("        {} prove:       {:.2} s", ldt.short(), prove_ms / 1e3);

    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1e3;
    assert!(ok, "shard {label} verify failed");
    let proof_bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    println!("        {} verify:      {:.2} ms   proof={} KiB", ldt.short(), verify_ms, proof_bytes/1024);

    // The shard's "pi_hash" for the outer rollup is what binds this proof.
    // We synthesize a deterministic 32-byte commitment from the Merkle root
    // + the proof's f0 commitment + record count + the authority pk_hash
    // (a domain-separated hash).  Including pk_hash here means an attacker
    // cannot detach this shard's pi_hash from the authority that proved it.
    let mut h = sha3::Sha3_256::new();
    use sha3::Digest;
    Digest::update(&mut h, b"DNS-SHARD-PIHASH-V1");
    Digest::update(&mut h, salt);
    Digest::update(&mut h, &(records.len() as u64).to_le_bytes());
    Digest::update(&mut h, root);
    Digest::update(&mut h, proof.root_f0);     // binds the LDT proof
    Digest::update(&mut h, pk_hash);           // binds the authority public key
    let pi_hash: [u8; 32] = Digest::finalize(h).into();

    ShardOutput {
        pi_hash, proof_size: proof_bytes, prove_ms, verify_ms,
        merkle_root: root,
        merkle_levels: levels,
    }
}

/// Aggregate N inner pi_hashes into one outer rollup STARK.
fn prove_outer_rollup(
    pi_hashes: &[[u8; 32]],
    pk_hash: &[u8; 32],
    ldt: Ldt,
) -> (f64, f64, usize, [u8; 32]) {
    let mut leaves: Vec<u64> = Vec::with_capacity(pi_hashes.len() * 4);
    for h in pi_hashes {
        leaves.extend_from_slice(&pack_hash_to_leaves(h));
    }
    let n_trace = next_pow2(leaves.len());
    leaves.resize(n_trace, 0);

    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);

    let trace = build_trace_bytes(&leaves, n_trace);
    let lde   = lde_trace_columns(&trace, n_trace, BLOWUP).expect("outer LDE failed");
    let coeffs = comb_coeffs(AirType::HashRollup.num_constraints());
    let (c_eval, _) = deep_ali_merge_general(
        &lde, &coeffs, AirType::HashRollup, domain.omega, n_trace, BLOWUP,
    );

    let params = DeepFriParams {
        schedule: make_schedule(n0, ldt),
        r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1,
        stir: ldt.is_stir(), s0: NUM_QUERIES,
        public_inputs_hash: Some(*pk_hash),
    };

    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1e3;

    let t_verify = Instant::now();
    assert!(deep_fri_verify::<Ext>(&params, &proof));
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1e3;

    let proof_bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);

    println!("\n  outer rollup [{}]:  n_trace=2^{}  prove={:.2} s  verify={:.2} ms  proof={} KiB",
             ldt.short(), n_trace.trailing_zeros(), prove_ms/1e3, verify_ms, proof_bytes/1024);

    (prove_ms, verify_ms, proof_bytes, proof.root_f0)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();
    let total_records = args.shards * args.records_per_shard;

    println!("=================================================================");
    println!("  DNS Megazone Rollup Demo");
    println!("=================================================================");
    println!("  shards               = {}", args.shards);
    println!("  records / shard      = {}", args.records_per_shard);
    println!("  total records        = {} ({:.2} M)",
             total_records, total_records as f64 / 1e6);
    println!("  rayon threads        = {}", rayon::current_num_threads());
    println!("  shard inner-trace    = 2^{} ({} rows)",
             next_pow2(args.records_per_shard * 4).trailing_zeros(),
             next_pow2(args.records_per_shard * 4));
    println!("  NIST PQ level        = L{}  (signature={}, signed-digest={})",
             match args.nist_level { NistLevel::L1=>1, NistLevel::L3=>3, NistLevel::L5=>5 },
             args.nist_level.ml_dsa_name(),
             args.nist_level.hash_name());
    println!("  LDT mode             = {}", args.ldt.label());
    println!();

    let zone_salt: [u8; 16] = *b"example-com-2026";
    println!("  zone salt (published) = {}", hex::encode(zone_salt));

    // ─── Authority keygen (deterministic seed for demo reproducibility) ──────
    // In production the authority's signing key is generated once and held
    // out-of-band; the demo derives both keys from a fixed seed so successive
    // runs produce identical pk/pk_hash and the binding is reproducible.
    const AUTHORITY_SEED: [u8; 32] = *b"DNS-AUTHORITY-DEMO-SEED-V1\0\0\0\0\0\0";
    let authority = AuthorityKeypair::keygen(args.nist_level, AUTHORITY_SEED);
    let pk_bytes  = authority.pk_bytes();
    let pk_hash   = pk_binding_hash(&pk_bytes);
    println!("  authority pk          = {} bytes ({}…)",
             pk_bytes.len(),
             &hex::encode(&pk_bytes[..16]));
    println!("  authority pk_hash     = {}…  (bound into STARK FS transcript)",
             &hex::encode(pk_hash)[..32]);
    println!();

    let t_total = Instant::now();

    // Generate + prove each shard sequentially (rayon parallelizes within each).
    let mut outputs: Vec<ShardOutput> = Vec::with_capacity(args.shards);
    let mut shards_records: Vec<Vec<DnsRecord>> = Vec::with_capacity(args.shards);

    for s in 0..args.shards {
        let label = format!("shard {} of {}", s + 1, args.shards);
        let t_gen = Instant::now();
        let records: Vec<DnsRecord> = (0..args.records_per_shard)
            .map(|i| make_record((s * args.records_per_shard + i) as u64))
            .collect();
        println!("[shard {}/{}] generated {} records in {:.2} s",
                 s + 1, args.shards, records.len(), t_gen.elapsed().as_secs_f64());

        let out = prove_shard(&label, &zone_salt, &records, &pk_hash, args.ldt);
        outputs.push(out);
        shards_records.push(records);
        println!();
    }

    // Outer rollup over all shard pi_hashes.
    let pi_hashes: Vec<[u8;32]> = outputs.iter().map(|o| o.pi_hash).collect();
    let (outer_prove_ms, outer_verify_ms, outer_proof_bytes, outer_root) =
        prove_outer_rollup(&pi_hashes, &pk_hash, args.ldt);

    let total_secs = t_total.elapsed().as_secs_f64();

    // ─── Authority signature over the rolled-up STARK ────────────────────────
    // Build a level-matched SHA3 digest over everything that uniquely
    // identifies this rollup, then ML-DSA-sign that digest.  The pk_hash
    // is included both inside the STARK (via public_inputs_hash) AND in
    // the signed digest, so:
    //   (a) substituting the pk forces re-proving (FS transcript would diverge),
    //   (b) substituting the proof forces re-signing (digest would diverge).
    let total_records_le = (total_records as u64).to_le_bytes();
    let nist_byte = match args.nist_level { NistLevel::L1=>1u8, NistLevel::L3=>3, NistLevel::L5=>5 };
    let zone_digest = level_hash(args.nist_level, &[
        b"DNS-ZONE-AUTHORITY-V1",
        &[nist_byte],
        &zone_salt,
        &total_records_le,
        &outer_root,                 // commits to outer rollup STARK
        &pk_hash,                    // commits to the authority pk
    ]);

    let t_sign = Instant::now();
    let signature = authority.sign(&zone_digest);
    let sign_ms = t_sign.elapsed().as_secs_f64() * 1e3;

    let t_vsig = Instant::now();
    let sig_ok = authority.verify(&zone_digest, &signature);
    let verify_sig_ms = t_vsig.elapsed().as_secs_f64() * 1e3;
    assert!(sig_ok, "authority signature failed to verify");

    // Tamper test: flip a byte in the digest, signature MUST be rejected.
    let mut tampered = zone_digest.clone();
    tampered[0] ^= 0x01;
    let tampered_ok = authority.verify(&tampered, &signature);
    assert!(!tampered_ok, "tampered digest must NOT verify");

    println!("\n=================================================================");
    println!("  Authority Signature on Rolled-Up STARK");
    println!("=================================================================");
    println!("  signature scheme     : {}  (NIST L{})",
             args.nist_level.ml_dsa_name(), nist_byte);
    println!("  signed-digest hash   : {}  ({} bytes)",
             args.nist_level.hash_name(), zone_digest.len());
    println!("  zone_digest          : {}…", &hex::encode(&zone_digest)[..32]);
    println!("  signature size       : {} bytes", signature.len());
    println!("  sign time            : {:.2} ms", sign_ms);
    println!("  verify time          : {:.2} ms", verify_sig_ms);
    println!("  ✓ signature verifies under authority pk");
    println!("  ✓ tampered digest correctly REJECTED");

    // ─── Inclusion-proof demonstration for one specific record ────────────────
    println!("\n=================================================================");
    println!("  Proof of DNS Entry — inclusion in shard 0");
    println!("=================================================================");
    let probe_index_in_shard = 7.min(args.records_per_shard - 1);
    let probe = make_record(probe_index_in_shard as u64);
    let probe_h2 = probe.leaf_hash(&zone_salt);

    let shard0 = &outputs[0];
    let leaf_index_in_shard = probe_index_in_shard;

    let path = merkle_path(&shard0.merkle_levels, leaf_index_in_shard);
    println!("  probe record         : domain={}, type={}, ttl={}",
             probe.domain, probe.record_type, probe.ttl);
    println!("  probe leaf_hash (h2) : {}…", &hex::encode(probe_h2)[..32]);
    println!("  shard 0 merkle_root  : {}…", &hex::encode(shard0.merkle_root)[..32]);
    println!("  merkle_path siblings : {} ({} bytes total)",
             path.len(), path.len() * 32);

    let inclusion_ok = merkle_verify(probe_h2, leaf_index_in_shard, &path, shard0.merkle_root);
    assert!(inclusion_ok, "inclusion proof must succeed");
    println!("  ✓ inclusion verified against shard 0's merkle_root");

    // Tamper test
    let tampered = make_record(probe_index_in_shard as u64);
    let mut tampered = tampered;
    tampered.ttl ^= 1;          // 1-bit flip in TTL
    let tampered_h2 = tampered.leaf_hash(&zone_salt);
    let tamper_ok = merkle_verify(tampered_h2, leaf_index_in_shard, &path, shard0.merkle_root);
    assert!(!tamper_ok, "tampered record must NOT verify");
    println!("  ✓ tampered record (TTL-bit flipped) correctly REJECTED");

    // ─── Final summary ───────────────────────────────────────────────────────
    println!("\n=================================================================");
    println!("  Summary");
    println!("=================================================================");
    println!("  total wall-clock                 = {:.2} s ({:.2} min)",
             total_secs, total_secs / 60.0);
    let total_inner_prove: f64 = outputs.iter().map(|o| o.prove_ms).sum();
    let max_inner_prove:   f64 = outputs.iter().map(|o| o.prove_ms).fold(0.0_f64, f64::max);
    println!("  total inner prove time (Σ)       = {:.2} s  (sequential)",
             total_inner_prove / 1e3);
    println!("  max  inner prove time            = {:.2} s  (= wall-clock if N machines parallelize)",
             max_inner_prove / 1e3);
    println!("  outer rollup prove               = {:.2} s",
             outer_prove_ms / 1e3);
    println!();
    println!("  total proof storage              = {} KiB ({} inner + 1 outer)",
             (outputs.iter().map(|o| o.proof_size).sum::<usize>() + outer_proof_bytes) / 1024,
             outputs.len());
    println!();
    println!("  verifier work for ANY 1 record");
    println!("    · verify outer rollup          = {:.2} ms", outer_verify_ms);
    println!("    · verify inner shard           ≈ {:.2} ms", outputs[0].verify_ms);
    println!("    · walk merkle path             = {} hashes (~negligible)", path.len());
    println!("  ─ TOTAL verifier               ≈ {:.2} ms",
             outer_verify_ms + outputs[0].verify_ms);
    println!();
    println!("  hypothetical 5-machine parallel wall-clock:");
    println!("    · max(inner prove) + outer    = {:.2} s ({:.2} min)",
             (max_inner_prove + outer_prove_ms) / 1e3,
             (max_inner_prove + outer_prove_ms) / 60_000.0);
    println!("=================================================================");
    println!("  STATUS: ✓ all {} inner + 1 outer proofs verified",
             outputs.len());
    println!("=================================================================");

    // Silence unused-import warning when not needed.
    let _ = F::zero();
    let _ = std::convert::identity::<&[Vec<DnsRecord>]>(&shards_records);
}
