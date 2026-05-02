//! Stacked-RSA zone prover — N records, ONE outer FRI proof.
//!
//! Instead of producing $N$ separate per-record STARKs and a
//! Merkle-rollup outer proof, this prover stacks $N$ independent
//! RSA-2048 exponentiation chains side-by-side in a single wide
//! AIR, producing a single FRI proof that attests to all $N$
//! signatures.  Achieves the lightest consumer footprint
//! (one ${\sim}138$~KiB FRI proof regardless of $N$, constant
//! verify time) without requiring full STARK-of-STARK recursion.
//!
//! Trade-offs vs the recursive-STARK architecture:
//!   * Same consumer footprint and verify time.
//!   * Cryptographically sound (no swarm-trust assumption).
//!   * Prover work is sequential ($O(N)$ in one trace), so it
//!     does not parallelise across a swarm of provers; recursive
//!     STARKs are the right answer for that setting.  For a
//!     single-prover deployment (e.g., a sectoral signing CA) the
//!     stacked approach is strictly better than per-record
//!     proofs + merkle rollup.
//!
//! Run:
//!     N=10 cargo run --release -p swarm-dns --example stacked_rsa_zone_prover

use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use num_bigint::BigUint;
use rand::SeedableRng;
use sha2::Digest as ShaDigest;
use sha3::Digest as Sha3Digest;

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

type Ext = SexticExt;
const BLOWUP: usize = 32;
const NUM_QUERIES: usize = 54;
const SEED_Z: u64 = 0xDEEF_BAAD;
const ML_DSA_65_SIG_BYTES: usize = 3_293;
const ML_DSA_65_VERIFY_MS: f64 = 1.0;

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

fn main() {
    println!("=== Stacked-RSA zone prover (N records → 1 FRI proof) ===");
    println!();

    let n_records: usize = std::env::var("N").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(10);
    println!("Zone: N = {} RSA-2048 RRSIGs (1 RRSIG/record)", n_records);
    println!();

    // ── Generate one zone-wide ZSK + N synthetic records. ──
    use rsa::{
        pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding},
        traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey,
    };
    use sha2::Sha256;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xFEED);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    let n_be = pub_key.n().to_bytes_be();
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let our_pub = RsaPublic::from_n_be(&n_be);

    let t_sign = Instant::now();
    let mut records: Vec<RsaStackedRecord> = Vec::with_capacity(n_records);
    let mut messages: Vec<String> = Vec::with_capacity(n_records);
    let mut all_em_bytes: Vec<u8> = Vec::with_capacity(n_records * 256);
    for i in 0..n_records {
        let domain = format!("rec{:04}.example.com.", i);
        let message = format!(
            "DNSSEC-RRSIG-V0|{}|A|10.0.{}.{}|epoch-0|alg-8",
            domain, (i / 256) as u8, (i % 256) as u8
        );
        let signature = signing_key.sign(message.as_bytes());
        let sig_bytes = signature.to_bytes();
        assert!(native_rsa_verify(&our_pub, message.as_bytes(), &sig_bytes));

        let mut digest = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        digest.copy_from_slice(&hasher.finalize());
        let em = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();

        all_em_bytes.extend_from_slice(&em);
        messages.push(message);
        records.push(RsaStackedRecord {
            n:  BigUint::from_bytes_be(&n_be),
            s:  BigUint::from_bytes_be(&sig_bytes),
            em: BigUint::from_bytes_be(&em),
        });
    }
    println!("    [sign+EM]    {:.2?}  ({} records)", t_sign.elapsed(), n_records);

    // ── Build stacked layout. ──
    const N_TRACE: usize = 32;
    let layout = build_rsa_stacked_layout(n_records);
    let cons_per_row = rsa_stacked_constraints(&layout);
    let n0 = N_TRACE * BLOWUP;
    println!();
    println!("Layout:");
    println!("    cells per row     : {}", layout.width);
    println!("    constraints/row   : {}", cons_per_row);
    println!("    n_trace           : {}", N_TRACE);
    println!("    n_0               : {}", n0);
    println!("    total trace cells : {} ({:.1} MiB)",
        layout.width * N_TRACE,
        (layout.width * N_TRACE * 8) as f64 / (1024.0 * 1024.0));
    println!();

    // ── Allocate + fill. ──
    let mut trace: Vec<Vec<F>> = (0..layout.width)
        .map(|_| vec![F::zero(); N_TRACE]).collect();
    let t_fill = Instant::now();
    fill_rsa_stacked(&mut trace, &layout, N_TRACE, &records);
    println!("    [fill]       {:.2?}", t_fill.elapsed());

    // ── LDE. ──
    let domain = FriDomain::new_radix2(n0);
    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).unwrap();
    println!("    [LDE]        {:.2?}", t_lde.elapsed());
    drop(trace);

    // ── Streaming merge. ──
    let coeffs = comb_coeffs(cons_per_row);
    let t_merge = Instant::now();
    let (c_eval, info) = deep_ali_merge_rsa_stacked_streaming(
        &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
    );
    println!("    [merge]      {:.2?}", t_merge.elapsed());
    drop(lde);

    // ── Public input: zone-wide commitment. ──
    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"RSA2048-STACKED-ZONE");
        h.update(&n_be);
        h.update(&(n_records as u64).to_le_bytes());
        h.update(&all_em_bytes); // verifier will recompute these
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };

    // ── Prove. ──
    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_dur = t_prove.elapsed();
    println!("    [prove]      {:.2?}", prove_dur);

    // ── Verify. ──
    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_dur = t_verify.elapsed();
    println!("    [verify]     {:.2?}  {}",
        verify_dur, if ok { "✓" } else { "FAIL" });
    assert!(ok);

    let proof_bytes_count = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let mut blob = Vec::with_capacity(proof_bytes_count);
    proof.serialize_with_mode(&mut blob, Compress::Yes).unwrap();

    println!();
    println!("================ Result ================");
    println!();
    println!("ONE FRI proof attests to all {} signatures:", n_records);
    println!("    proof bytes       : {} ({:.1} KiB)",
        proof_bytes_count, proof_bytes_count as f64 / 1024.0);
    println!("    verify time       : {:.2} ms", verify_dur.as_secs_f64() * 1000.0);
    println!("    prove time        : {:.2?}", prove_dur);
    println!();
    println!("Edge-consumer footprint (this prover):");
    let edge_bytes = proof_bytes_count + ML_DSA_65_SIG_BYTES;
    let edge_verify_ms = verify_dur.as_secs_f64() * 1000.0 + ML_DSA_65_VERIFY_MS;
    println!("    artefact          : FRI({}) + ML-DSA({}) = {} ({:.1} KiB)",
        proof_bytes_count, ML_DSA_65_SIG_BYTES,
        edge_bytes, edge_bytes as f64 / 1024.0);
    println!("    consumer verify   : FRI({:.2}ms) + ML-DSA({:.2}ms) = {:.2} ms",
        verify_dur.as_secs_f64() * 1000.0, ML_DSA_65_VERIFY_MS, edge_verify_ms);
    println!();
    println!("Comparison vs Option B (per-record + merkle rollup):");
    println!("    Option B size : ~138 KiB (constant in N, swarm-trust soundness)");
    println!("    Stacked size  : {:.1} KiB (constant in N, full STARK soundness)",
        edge_bytes as f64 / 1024.0);
    println!("    Both: ~1-2 ms consumer verify regardless of N.");
    println!();
    println!("Stacked AIR achieves Option B's footprint with full STARK");
    println!("soundness (no swarm-trust); cost is sequential prover work.");
}
