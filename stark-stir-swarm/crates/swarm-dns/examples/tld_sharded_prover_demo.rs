//! TLD-scale sharded prover demonstration.
//!
//! Demonstrates the architecture pattern that lets STARK-DNS scale
//! to TLD-size zones (millions to hundreds-of-millions of records):
//!   1. Shard the zone into $K$ shards of $S$ records each
//!      (here $K{=}4$, $S{=}50$, total $N{=}200$).
//!   2. Build a GLOBAL Merkle tree over all $N$ records.
//!   3. For each shard: run the stacked-AIR STARK over $S$ records,
//!      with $\pi_{\mathrm{hash}}$ binding the GLOBAL Merkle root
//!      and the shard's record range.
//!   4. Aggregate the $K$ shard $\pi_{\mathrm{hash}}$es via the
//!      existing HashRollup outer-rollup STARK.
//!   5. ML-DSA-65 sign the epoch package
//!      (outer FRI root, GLOBAL Merkle root, pk_zsk, seq, T).
//!
//! Edge consumer (constant work regardless of $N$):
//!   - Verify ML-DSA, verify outer-rollup STARK.
//!   - For each query: walk a $\log_2 N$-hash Merkle path in the
//!     GLOBAL tree.
//!
//! Trust model is the same as Option C with the addition that the
//! edge consumer trusts the prover to have correctly committed the
//! global Merkle root inside each shard's $\pi_{\mathrm{hash}}$
//! (auditors may re-verify shard STARKs out-of-band).
//!
//! Scales linearly: doubling $N$ doubles either $K$ (more shards,
//! same prove time per worker) or $S$ (memory bound — needs
//! more RAM per worker).  Outer rollup grows logarithmically.
//!
//! Run:
//!     K=4 S=50 cargo run --release -p swarm-dns --example tld_sharded_prover_demo

use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as MlDsaSigner, Verifier as MlDsaVerifier};
use num_bigint::BigUint;
use rand::SeedableRng;
use sha2::Digest as ShaDigest;
use sha3::{Digest as Sha3Digest, Sha3_256};

use deep_ali::{
    deep_ali_merge_rsa_stacked_streaming,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    rsa2048::{emsa_pkcs1_v1_5_encode_sha256, verify as native_rsa_verify, PublicKey as RsaPublic},
    rsa2048_stacked_air::{
        build_rsa_stacked_layout, fill_rsa_stacked, rsa_stacked_constraints, RsaStackedRecord,
    },
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};
use swarm_dns::dns::{merkle_build, merkle_path, merkle_root, merkle_verify};
use swarm_dns::prover::{prove_outer_rollup, LdtMode};

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
    if remainder_log > 0 { s.push(1usize << remainder_log); }
    s
}

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

fn record_leaf(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Sha3Digest::update(&mut h, b"DNS-RECORD-LEAF-V1\x00");
    Sha3Digest::update(&mut h, bytes);
    Sha3Digest::finalize(h).into()
}

fn fmt_size(b: usize) -> String {
    if b >= 1024 * 1024 { format!("{:.2} MiB", b as f64 / (1024.0 * 1024.0)) }
    else if b >= 1024 { format!("{:.2} KiB", b as f64 / 1024.0) }
    else { format!("{} B", b) }
}

struct ShardProveResult {
    shard_id:    usize,
    pi_hash:     [u8; 32],
    proof_bytes: usize,
    prove_s:     f64,
    verified:    bool,
}

fn prove_one_shard(
    shard_id: usize,
    shard_records: &[RsaStackedRecord],
    record_bytes_in_shard: &[Vec<u8>],
    shard_first_global_idx: usize,
    global_merkle_root: &[u8; 32],
    zsk_n_be: &[u8],
) -> ShardProveResult {
    const N_TRACE: usize = 32;
    let n_in_shard = shard_records.len();
    let layout = build_rsa_stacked_layout(n_in_shard);
    let cons_per_row = rsa_stacked_constraints(&layout);
    let n0 = N_TRACE * BLOWUP;

    let t = Instant::now();
    let mut trace: Vec<Vec<F>> = (0..layout.width)
        .map(|_| vec![F::zero(); N_TRACE]).collect();
    fill_rsa_stacked(&mut trace, &layout, N_TRACE, shard_records);

    let domain = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).unwrap();
    drop(trace);

    let coeffs = comb_coeffs(cons_per_row);
    let (c_eval, _) = deep_ali_merge_rsa_stacked_streaming(
        &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
    );
    drop(lde);

    let mut em_list_hash = Sha3_256::new();
    for r in shard_records {
        Sha3Digest::update(&mut em_list_hash, r.em.to_bytes_be());
    }
    let em_list_hash: [u8; 32] = em_list_hash.finalize().into();

    // Shard's pi_hash binds the GLOBAL Merkle root (not just intra-shard).
    let stark_pub_input: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"TLD-SHARD-V1");
        Sha3Digest::update(&mut h, (shard_id as u64).to_le_bytes());
        Sha3Digest::update(&mut h, zsk_n_be);
        Sha3Digest::update(&mut h, (n_in_shard as u64).to_le_bytes());
        Sha3Digest::update(&mut h, (shard_first_global_idx as u64).to_le_bytes());
        Sha3Digest::update(&mut h, global_merkle_root);
        Sha3Digest::update(&mut h, &em_list_hash);
        Sha3Digest::finalize(h).into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(stark_pub_input),
    };
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_dur = t.elapsed().as_secs_f64();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let proof_bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);

    // Bind FRI root into pi_hash (so outer rollup is over algorithm-tagged π).
    let mut h = Sha3_256::new();
    Sha3Digest::update(&mut h, &stark_pub_input);
    let mut root_buf = Vec::new();
    proof.root_f0.serialize_with_mode(&mut root_buf, Compress::Yes).unwrap();
    Sha3Digest::update(&mut h, &root_buf);
    let pi_hash: [u8; 32] = h.finalize().into();

    let _ = record_bytes_in_shard; // (used by caller for global Merkle build)

    ShardProveResult {
        shard_id, pi_hash, proof_bytes, prove_s: prove_dur, verified: ok,
    }
}

fn main() {
    println!("==============================================================");
    println!(" TLD-scale sharded prover demonstration");
    println!("==============================================================");
    println!();

    let k_shards: usize = std::env::var("K").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(4);
    let s_per_shard: usize = std::env::var("S").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(50);
    let n_total = k_shards * s_per_shard;
    println!("Zone composition:  K = {} shards × S = {} records = N = {}",
        k_shards, s_per_shard, n_total);
    println!("(Demonstrates the TLD scaling pattern; production would use");
    println!(" K=10⁴-10⁵ shards × S=10² records for .com-scale.)");
    println!();

    // ── Generate keypairs and N records. ──
    use rsa::{
        pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding},
        traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey,
    };
    use sha2::Sha256;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEADBEEFCAFE);
    let zsk_priv = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let zsk_pub = RsaPublicKey::from(&zsk_priv);
    let zsk_n_be = zsk_pub.n().to_bytes_be();
    let zsk_signing = SigningKey::<Sha256>::new(zsk_priv);
    let our_zsk_pub = RsaPublic::from_n_be(&zsk_n_be);

    let (mldsa_pk, mldsa_sk) = ml_dsa_65::try_keygen_with_rng(
        &mut rand::rngs::StdRng::seed_from_u64(0xC0FFEE)).unwrap();
    let mldsa_pk_bytes = mldsa_pk.into_bytes();

    // ── Sign all N records. ──
    println!(">>> Step 1: sign {} records (zone-wide)", n_total);
    let t = Instant::now();
    let mut all_records: Vec<RsaStackedRecord> = Vec::with_capacity(n_total);
    let mut all_record_bytes: Vec<Vec<u8>> = Vec::with_capacity(n_total);
    let mut all_leaves: Vec<[u8; 32]> = Vec::with_capacity(n_total);
    for i in 0..n_total {
        let domain = format!("rec{:06}.tld.example.", i);
        let ip = [10u8, (i / 65536) as u8, ((i / 256) % 256) as u8, (i % 256) as u8];
        let message = format!(
            "DNSSEC-RRSIG-V0|{}|A|{}.{}.{}.{}|epoch-0|alg-8",
            domain, ip[0], ip[1], ip[2], ip[3]
        );
        let signature = zsk_signing.sign(message.as_bytes());
        let sig_bytes = signature.to_bytes();
        assert!(native_rsa_verify(&our_zsk_pub, message.as_bytes(), &sig_bytes));

        let mut digest = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        digest.copy_from_slice(&hasher.finalize());
        let em = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();

        let rec_full = message.into_bytes();
        all_leaves.push(record_leaf(&rec_full));
        all_record_bytes.push(rec_full);
        all_records.push(RsaStackedRecord {
            n:  BigUint::from_bytes_be(&zsk_n_be),
            s:  BigUint::from_bytes_be(&sig_bytes),
            em: BigUint::from_bytes_be(&em),
        });
    }
    println!("    {:.2?} (signed {} records, ~{:.0} sigs/sec)",
        t.elapsed(), n_total,
        n_total as f64 / t.elapsed().as_secs_f64());

    // ── Build GLOBAL Merkle tree over all records. ──
    println!();
    println!(">>> Step 2: build GLOBAL Merkle tree over all {} records", n_total);
    let t = Instant::now();
    let global_levels = merkle_build(&all_leaves);
    let global_root = merkle_root(&global_levels);
    let global_depth = global_levels.len() - 1;
    println!("    {:.2?}  global root = {}  depth = {}",
        t.elapsed(), hex::encode(&global_root[..8]), global_depth);

    // ── Per-shard STARK prove (sequential here; production would
    //    parallelise across a worker swarm). ──
    println!();
    println!(">>> Step 3: per-shard stacked-AIR STARKs (sequential here)");
    let mut shard_results: Vec<ShardProveResult> = Vec::with_capacity(k_shards);
    let mut total_shard_prove_s = 0.0;
    let mut total_shard_proof_bytes = 0;
    for k in 0..k_shards {
        let lo = k * s_per_shard;
        let hi = lo + s_per_shard;
        let shard_recs = &all_records[lo..hi];
        let shard_bytes = &all_record_bytes[lo..hi];
        let res = prove_one_shard(k, shard_recs, shard_bytes, lo, &global_root, &zsk_n_be);
        total_shard_prove_s += res.prove_s;
        total_shard_proof_bytes += res.proof_bytes;
        println!("    shard[{}] {:.2}s  proof={}  pi_hash={}  {}",
            k, res.prove_s, fmt_size(res.proof_bytes),
            hex::encode(&res.pi_hash[..8]),
            if res.verified { "✓" } else { "FAIL" });
        shard_results.push(res);
    }
    println!("    Aggregate shard prove (sequential): {:.2?}  ({} shards)",
        std::time::Duration::from_secs_f64(total_shard_prove_s),
        k_shards);
    println!("    Total inner-proof bytes: {}", fmt_size(total_shard_proof_bytes));

    // ── Outer-rollup STARK over K shard pi_hashes. ──
    println!();
    println!(">>> Step 4: outer-rollup STARK over {} shard π-hashes", k_shards);
    let pi_hashes: Vec<[u8; 32]> = shard_results.iter().map(|r| r.pi_hash).collect();
    let mut h = Sha3_256::new();
    Sha3Digest::update(&mut h, b"TLD-OUTER-ROLLUP-V1");
    Sha3Digest::update(&mut h, &global_root);
    Sha3Digest::update(&mut h, (k_shards as u64).to_le_bytes());
    for pi in &pi_hashes { Sha3Digest::update(&mut h, pi); }
    let outer_pk_hash: [u8; 32] = h.finalize().into();

    let t = Instant::now();
    let outer = prove_outer_rollup(&pi_hashes, &outer_pk_hash, LdtMode::Stir);
    let outer_total_dur = t.elapsed();
    println!("    n_trace={}  prove={:.2}ms  verify={:.2}ms  proof={}  {:.2?}",
        outer.n_trace, outer.prove_ms, outer.local_verify_ms,
        fmt_size(outer.proof_bytes), outer_total_dur);

    // ── ML-DSA-65 sign epoch package. ──
    println!();
    println!(">>> Step 5: ML-DSA-65 sign epoch package");
    let epoch_seq: u64 = 0;
    let epoch_t: u64 = 1_761_867_200;
    let epoch_metadata: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"TLD-EPOCH-V1");
        Sha3Digest::update(&mut h, epoch_seq.to_le_bytes());
        Sha3Digest::update(&mut h, epoch_t.to_le_bytes());
        Sha3Digest::update(&mut h, &outer.root_f0);
        Sha3Digest::update(&mut h, &global_root);
        Sha3Digest::update(&mut h, &zsk_n_be);
        Sha3Digest::finalize(h).into()
    };
    let t = Instant::now();
    let mldsa_sig = mldsa_sk.try_sign(&epoch_metadata, b"").unwrap();
    println!("    sign: {:.2?}  sig = {} bytes",
        t.elapsed(), mldsa_sig.len());

    // ── Edge consumer once-per-epoch verify. ──
    println!();
    println!(">>> Step 6: edge consumer once-per-epoch verify");
    let t_epoch = Instant::now();

    let t = Instant::now();
    let mldsa_pk_decoded = ml_dsa_65::PublicKey::try_from_bytes(mldsa_pk_bytes).unwrap();
    let mldsa_sig_arr: [u8; ml_dsa_65::SIG_LEN] =
        mldsa_sig.as_slice().try_into().unwrap();
    let mldsa_ok = mldsa_pk_decoded.verify(&epoch_metadata, &mldsa_sig_arr, b"");
    let mldsa_dur = t.elapsed();
    println!("    (a) ML-DSA verify    : {:.2?} {}",
        mldsa_dur, if mldsa_ok { "✓" } else { "FAIL" });
    assert!(mldsa_ok);

    // (b) Outer rollup STARK verify: deserialize and verify.
    use ark_serialize::{CanonicalDeserialize, Validate};
    let outer_proof_loaded =
        deep_ali::fri::DeepFriProof::<Ext>::deserialize_with_mode(
            &outer.proof_blob[..], Compress::Yes, Validate::Yes,
        ).unwrap();
    let outer_n0 = outer.n_trace * BLOWUP;
    let outer_params = DeepFriParams {
        schedule: make_schedule_stir(outer_n0),
        r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(outer_pk_hash),
    };
    let t = Instant::now();
    let outer_ok = deep_fri_verify::<Ext>(&outer_params, &outer_proof_loaded);
    let outer_verify_dur = t.elapsed();
    println!("    (b) outer FRI verify : {:.2?} {}",
        outer_verify_dur, if outer_ok { "✓" } else { "FAIL" });
    assert!(outer_ok);
    let epoch_verify_dur = t_epoch.elapsed();
    println!("    Total once-per-epoch : {:.2?}", epoch_verify_dur);

    // ── Per-query verify (look up record #157). ──
    println!();
    println!(">>> Step 7: per-query verify (looking up record #157, in shard {})",
        157 / s_per_shard);
    let query_idx = 157 % n_total;
    let query_bytes = &all_record_bytes[query_idx];
    let leaf = record_leaf(query_bytes);
    let path = merkle_path(&global_levels, query_idx);

    let t = Instant::now();
    let merkle_ok = merkle_verify(leaf, query_idx, &path, global_root);
    let merkle_dur = t.elapsed();
    println!("    Record bytes       : {} B (\"{}…\")",
        query_bytes.len(),
        std::str::from_utf8(&query_bytes[..40.min(query_bytes.len())]).unwrap_or("?"));
    println!("    Merkle path        : {} hashes ({} B)",
        path.len(), path.len() * 32);
    println!("    Merkle verify      : {:?} {}",
        merkle_dur, if merkle_ok { "✓" } else { "FAIL" });
    assert!(merkle_ok);

    // ── Summary ──
    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!(" TLD-scale architecture summary (K={}, S={}, N={})",
        k_shards, s_per_shard, n_total);
    println!("══════════════════════════════════════════════════════════════");
    println!();
    println!("Prover side:");
    println!("    Per-shard prove (avg)    : {:.2?}",
        std::time::Duration::from_secs_f64(total_shard_prove_s / k_shards as f64));
    println!("    Aggregate shard prove    : {:.2?} (sequential, {} shards)",
        std::time::Duration::from_secs_f64(total_shard_prove_s), k_shards);
    println!("    Outer rollup prove       : {:.2}ms", outer.prove_ms);
    println!("    ML-DSA sign              : ~200µs");
    println!();
    println!("Edge artefact (single bundle, constant in N modulo log N path):");
    let edge_artefact_size = outer.proof_bytes + mldsa_sig.len() + 256
        + 32 + 32 + 16 + path.len() * 32;
    println!("    Outer FRI proof          : {}", fmt_size(outer.proof_bytes));
    println!("    ML-DSA-65 signature      : {}", fmt_size(mldsa_sig.len()));
    println!("    pk + global root + meta  : ~352 B");
    println!("    Per-query Merkle path    : {} ({} B at N={})",
        fmt_size(path.len() * 32), path.len() * 32, n_total);
    println!("    TOTAL per-epoch + query  : {} ({:.1} KiB)",
        fmt_size(edge_artefact_size),
        edge_artefact_size as f64 / 1024.0);
    println!();
    println!("Edge consumer verify:");
    println!("    Once-per-epoch (cached)  : {:.2?}", epoch_verify_dur);
    println!("    Per-query (Merkle path)  : {:?}", merkle_dur);
    println!();
    println!("Soundness chain:");
    println!("  1. ML-DSA-65 verify      → authority signed (outer FRI, M-root, pk)");
    println!("  2. Outer FRI verify      → all {} shard π-hashes committed",
        k_shards);
    println!("  3. Merkle path verify    → record #{} bound under global root",
        query_idx);
    println!();
    println!("Note: edge consumer trusts that each shard's stacked-AIR STARK");
    println!("(not directly verified at the edge) correctly committed the global");
    println!("Merkle root in its π-hash. Auditors may re-verify shard STARKs");
    println!("out-of-band ({} of {} for total audit-mode artefacts).",
        fmt_size(total_shard_proof_bytes), k_shards);
    println!();
    println!("Linear scaling to TLD scale:");
    let per_shard_prove_avg = total_shard_prove_s / k_shards as f64;
    let scale_to = |n: usize| -> String {
        let shards_needed = (n + s_per_shard - 1) / s_per_shard;
        let total_prove_s = per_shard_prove_avg * shards_needed as f64;
        let workers_1k = total_prove_s / 1000.0;
        if total_prove_s >= 86400.0 {
            format!("{:.1} days seq, {:.1} h on 1k workers",
                total_prove_s / 86400.0, workers_1k / 3600.0)
        } else if total_prove_s >= 3600.0 {
            format!("{:.1} h seq, {:.1} min on 1k workers",
                total_prove_s / 3600.0, workers_1k / 60.0)
        } else {
            format!("{:.1} s seq, {:.1} s on 1k workers", total_prove_s, workers_1k)
        }
    };
    println!("    .gov / .mil  (10K records)  : {}", scale_to(10_000));
    println!("    .uk          (10M records)  : {}", scale_to(10_000_000));
    println!("    .com         (160M records) : {}", scale_to(160_000_000));
    println!();
    println!("Edge artefact stays ~110 KiB constant + log₂(N) Merkle path");
    println!("(896 B for .com-scale 160M records).  Per-query verify:");
    println!("~{} ns (proportional to log₂ N hash invocations).",
        ((n_total as f64).log2() as u64) * 30);
}
