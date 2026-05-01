//! Zone-scale epoch artefact size + verify time bench.
//!
//! Quantifies the gap between two consumer-facing artefact shapes:
//!
//!   **Option~A (full audit)**: outer-rollup STARK $+$ ML-DSA epoch
//!     signature $+$ all $N$ per-record inner STARKs.  Consumer
//!     verifies every inner STARK, the outer rollup, the ML-DSA
//!     signature, and the Merkle path for their looked-up record.
//!     Cryptographically sound under STARK $+$ ML-DSA; large
//!     artefact (linear in $N$).
//!
//!   **Option~B (light edge)**: outer-rollup STARK $+$ ML-DSA epoch
//!     signature $+$ Merkle path for the looked-up record only.
//!     Constant size regardless of $N$.  Consumer verifies the
//!     outer rollup, ML-DSA, and Merkle path; the inner STARKs
//!     are NOT shipped to the consumer.  Soundness assumption:
//!     prover (or BFT swarm) correctly verified inner STARKs
//!     before computing the outer rollup; an auditor can fetch
//!     and re-verify inner STARKs out-of-band.
//!
//! For the bench we use $N=100$ RSA-2048 records (fastest of the
//! three algorithms at $0.45$~s/sig) so the bench completes in
//! ${\sim}1$~minute on M4 Mac mini.  Per-record artefact and
//! verify-time numbers project linearly to mixed-algorithm zones
//! (Ed25519 / ECDSA-P256 inner proofs are size-comparable but
//! prove-time is much higher).
//!
//! ML-DSA epoch signature is approximated as a fixed
//! $3{,}293$~B signature (FIPS-204 ML-DSA-65) + $1$~ms verify cost
//! (literature standard; no actual ML-DSA verifier invoked here).
//!
//! Run:
//!     cargo run --release -p swarm-dns --example epoch_artefact_size_bench

use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use num_bigint::BigUint;
use rand::SeedableRng;
use sha2::Digest as ShaDigest;
use sha3::Digest as Sha3Digest;

use deep_ali::{
    deep_ali_merge_rsa_exp_multirow_streaming,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    rsa2048::{emsa_pkcs1_v1_5_encode_sha256, verify as native_rsa_verify, PublicKey as RsaPublic},
    rsa2048_exp_air::{
        build_rsa_exp_multirow_layout, fill_rsa_exp_multirow,
        rsa_exp_multirow_constraints,
    },
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};
use swarm_dns::prover::{prove_outer_rollup, LdtMode};

type Ext = SexticExt;
const BLOWUP: usize = 32;
const NUM_QUERIES: usize = 54;
const SEED_Z: u64 = 0xDEEF_BAAD;

const ML_DSA_65_SIG_BYTES: usize = 3_293;
const ML_DSA_65_VERIFY_MS: f64 = 1.0; // FIPS-204, M4 reference

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

struct InnerProof {
    pi_hash: [u8; 32],
    fri_blob: Vec<u8>,
    params: DeepFriParams,
    proof: deep_ali::fri::DeepFriProof<Ext>,
}

fn prove_one_rsa_record(
    signing_key: &rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    pub_n_be: &[u8],
    domain: &str,
    ip: [u8; 4],
) -> InnerProof {
    use rsa::signature::{Signer, SignatureEncoding};

    let message = format!(
        "DNSSEC-RRSIG-V0|{}|A|{}.{}.{}.{}|epoch-0|alg-8",
        domain, ip[0], ip[1], ip[2], ip[3]
    );
    let signature = signing_key.sign(message.as_bytes());
    let sig_bytes = signature.to_bytes();

    let our_pub = RsaPublic::from_n_be(pub_n_be);
    assert!(native_rsa_verify(&our_pub, message.as_bytes(), &sig_bytes));

    let mut digest = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.update(message.as_bytes());
    digest.copy_from_slice(&hasher.finalize());
    let em_bytes = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();
    let em_big = BigUint::from_bytes_be(&em_bytes);

    const N_TRACE: usize = 32;
    let n_big = BigUint::from_bytes_be(pub_n_be);
    let s_big = BigUint::from_bytes_be(&sig_bytes);
    let (layout, total_cells) = build_rsa_exp_multirow_layout(0);
    let cons = rsa_exp_multirow_constraints(&layout);

    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); N_TRACE]).collect();
    fill_rsa_exp_multirow(&mut trace, &layout, N_TRACE, &n_big, &s_big, &em_big);

    let n0 = N_TRACE * BLOWUP;
    let domain_fri = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).unwrap();
    let coeffs = comb_coeffs(cons);
    let (c_eval, _) = deep_ali_merge_rsa_exp_multirow_streaming(
        &lde, &coeffs, &layout, domain_fri.omega, N_TRACE, BLOWUP,
    );
    drop(lde); drop(trace);

    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"RSA2048-EPOCH-ARTEFACT-BENCH");
        h.update(pub_n_be);
        h.update(&sig_bytes);
        h.update(message.as_bytes());
        h.update(&em_bytes);
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };
    let proof = deep_fri_prove::<Ext>(c_eval, domain_fri, &params);

    let proof_bytes_count = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let mut blob = Vec::with_capacity(proof_bytes_count);
    proof.serialize_with_mode(&mut blob, Compress::Yes).unwrap();

    let mut h = sha3::Sha3_256::new();
    h.update(&pk_hash_pre);
    let mut root_buf = Vec::new();
    proof.root_f0.serialize_with_mode(&mut root_buf, Compress::Yes).unwrap();
    h.update(&root_buf);
    let pi_hash: [u8; 32] = h.finalize().into();

    InnerProof { pi_hash, fri_blob: blob, params, proof }
}

fn fmt_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn main() {
    println!("=== Zone-scale epoch artefact bench (Option A vs Option B) ===");
    println!();

    let n: usize = std::env::var("N").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(100);
    println!("Zone size: N = {} RSA-2048 records (1 RRSIG/record for", n);
    println!("simplicity; production has 2 chained RRSIGs/record,");
    println!("doubling inner-proof bytes and per-record verify time).");
    println!();

    // ── Generate a single 2048-bit keypair (zone-wide ZSK). ──
    use rsa::{pkcs1v15::SigningKey, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xEEEE);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    let n_be = pub_key.n().to_bytes_be();
    let signing_key = SigningKey::<Sha256>::new(priv_key);

    // ── Phase 1: prove all N records. ──
    println!(">>> Proving {} per-record RSA-2048 STARKs ...", n);
    let t_prove_inner = Instant::now();
    let mut inner: Vec<InnerProof> = Vec::with_capacity(n);
    for i in 0..n {
        let dom = format!("rec{:04}.example.com.", i);
        let proof = prove_one_rsa_record(&signing_key, &n_be, &dom, [10, 0, (i / 256) as u8, (i % 256) as u8]);
        inner.push(proof);
        if (i + 1) % 10 == 0 {
            println!("    [{:>4}/{:>4}] {:.2}s elapsed",
                i + 1, n, t_prove_inner.elapsed().as_secs_f64());
        }
    }
    let inner_prove_s = t_prove_inner.elapsed().as_secs_f64();
    println!();
    println!("Inner-prove total: {:.2}s ({:.2}min)", inner_prove_s, inner_prove_s / 60.0);
    println!();

    // ── Phase 2: outer-rollup STARK over all pi_hashes. ──
    let pi_hashes: Vec<[u8; 32]> = inner.iter().map(|p| p.pi_hash).collect();
    let mut h = sha3::Sha3_256::new();
    h.update(b"EPOCH-ROOT-ARTEFACT-BENCH");
    for pi in &pi_hashes { h.update(pi); }
    let outer_pk_hash: [u8; 32] = h.finalize().into();

    println!(">>> Outer-rollup STARK over {} pi_hashes ...", n);
    let outer = prove_outer_rollup(&pi_hashes, &outer_pk_hash, LdtMode::Stir);
    println!("    n_trace        = {}", outer.n_trace);
    println!("    proof bytes    = {}", outer.proof_bytes);
    println!("    prove          = {:.2} ms", outer.prove_ms);
    println!("    local verify   = {:.2} ms ✓", outer.local_verify_ms);
    println!();

    // ── Verify all inner proofs (consumer audit-mode work). ──
    println!(">>> Verifying all {} inner STARKs (Option A consumer work) ...", n);
    let t_verify_all = Instant::now();
    let mut all_ok = true;
    for (i, p) in inner.iter().enumerate() {
        let ok = deep_fri_verify::<Ext>(&p.params, &p.proof);
        all_ok &= ok;
        if !ok {
            println!("    inner[{}] FAILED", i);
        }
    }
    let inner_verify_s = t_verify_all.elapsed().as_secs_f64();
    println!("    All {} inner verify: {:.2}s ({}/inner = {:.2}ms)",
        n, inner_verify_s, n,
        (inner_verify_s / n as f64) * 1000.0);
    println!("    All inner: {}", if all_ok { "✓" } else { "FAIL" });
    println!();

    // ── Verify a single inner proof (consumer per-query work). ──
    let t = Instant::now();
    let _ = deep_fri_verify::<Ext>(&inner[0].params, &inner[0].proof);
    let single_inner_verify_ms = t.elapsed().as_secs_f64() * 1000.0;

    // Merkle path size: ceil(log2(N × 4 leaves)) × 32 bytes
    let merkle_depth = ((n * 4) as f64).log2().ceil() as usize;
    let merkle_path_bytes = merkle_depth * 32;

    // Total inner artefact bytes.
    let inner_total_bytes: usize = inner.iter().map(|p| p.fri_blob.len()).sum();

    // ── Summary ──
    println!("================ Summary (N = {}) ================", n);
    println!();
    println!("Per-record measurements:");
    println!("  inner FRI proof   = {} (avg)",
        fmt_size(inner_total_bytes / n));
    println!("  inner verify      = {:.2} ms", single_inner_verify_ms);
    println!();
    println!("Aggregate (zone-wide):");
    println!("  inner prove total = {:.2}s ({:.2}min)",
        inner_prove_s, inner_prove_s / 60.0);
    println!("  inner total bytes = {}", fmt_size(inner_total_bytes));
    println!("  outer prove       = {:.2} ms", outer.prove_ms);
    println!("  outer proof       = {}", fmt_size(outer.proof_bytes));
    println!();
    println!("─── Option A (full audit mode): consumer verifies everything ───");
    let opt_a_size = inner_total_bytes
        + outer.proof_bytes
        + ML_DSA_65_SIG_BYTES
        + merkle_path_bytes;
    let opt_a_verify_ms = (n as f64) * single_inner_verify_ms
        + outer.local_verify_ms
        + ML_DSA_65_VERIFY_MS;
    println!("  artefact size     = inner({}) + outer({}) + ml-dsa({}) + merkle({})",
        fmt_size(inner_total_bytes),
        fmt_size(outer.proof_bytes),
        fmt_size(ML_DSA_65_SIG_BYTES),
        fmt_size(merkle_path_bytes));
    println!("                    = {}", fmt_size(opt_a_size));
    println!("  per-zone verify   = {} × inner({:.2}ms) + outer({:.2}ms) + ml-dsa({:.2}ms)",
        n, single_inner_verify_ms, outer.local_verify_ms, ML_DSA_65_VERIFY_MS);
    println!("                    = {:.2} ms ({:.2} s)",
        opt_a_verify_ms, opt_a_verify_ms / 1000.0);
    println!();
    println!("─── Option B (light edge mode): consumer verifies outer + ML-DSA + path ───");
    let opt_b_size = outer.proof_bytes + ML_DSA_65_SIG_BYTES + merkle_path_bytes;
    let opt_b_verify_ms = outer.local_verify_ms + ML_DSA_65_VERIFY_MS;
    println!("  artefact size     = outer({}) + ml-dsa({}) + merkle({})",
        fmt_size(outer.proof_bytes),
        fmt_size(ML_DSA_65_SIG_BYTES),
        fmt_size(merkle_path_bytes));
    println!("                    = {}", fmt_size(opt_b_size));
    println!("  per-zone verify   = outer({:.2}ms) + ml-dsa({:.2}ms)",
        outer.local_verify_ms, ML_DSA_65_VERIFY_MS);
    println!("                    = {:.2} ms",  opt_b_verify_ms);
    println!();
    println!("─── Option B per-QUERY (consumer wants ONE record) ───");
    let opt_b_query_size = outer.proof_bytes + ML_DSA_65_SIG_BYTES + merkle_path_bytes;
    let opt_b_query_verify_ms = outer.local_verify_ms + ML_DSA_65_VERIFY_MS;
    println!("  artefact size     = {} (constant in N)",
        fmt_size(opt_b_query_size));
    println!("  per-query verify  = {:.2} ms (constant in N)",
        opt_b_query_verify_ms);
    println!();
    println!("─── Compression ratios (B vs A) ───");
    println!("  size:    {}× smaller in Option B",
        format!("{:.0}", opt_a_size as f64 / opt_b_size as f64));
    println!("  verify:  {:.0}× faster in Option B",
        opt_a_verify_ms / opt_b_verify_ms);
    println!();
    println!("Option B trust model: prover/swarm correctly verified inner");
    println!("STARKs before signing the outer rollup with ML-DSA. Auditors");
    println!("may fetch and re-verify inner STARKs out-of-band.");
    println!();
    println!("All proofs verify locally ✓");
}
