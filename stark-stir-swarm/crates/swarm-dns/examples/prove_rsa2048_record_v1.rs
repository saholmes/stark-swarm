//! End-to-end RSA-2048 RRSIG STARK proof on real signature input.
//!
//! Generates an RSA-2048 keypair with the `rsa` crate, signs a
//! DNS-style message, and produces a STARK proof of the
//! exponentiation $s^{65537} \bmod n$ in-circuit (Phase 3
//! deliverable: chain only — PKCS#1 padding equality is checked
//! natively at prove time, like the v1 ECDSA path).
//!
//! Soundness model (v2):
//!   - **In-circuit**: $17$-step exponentiation chain (16 squarings
//!     + 1 multiply for $e=65{,}537$) AND a row-16 boundary
//!     constraint binding the chain output `c` to a verifier-supplied
//!     EM column. The verifier re-derives EM = pkcs1_pad(SHA-256(message))
//!     and includes EM bytes in the $\pi_{\mathrm{hash}}$ recipe; the
//!     STARK rejects any trace whose row-16 chain output disagrees
//!     with EM.
//!   - **Verifier-side (deterministic)**: SHA-256 of the message and
//!     the PKCS\#1 v1.5 EM construction. These are pure hash + byte
//!     constants; no signing-key material involved.
//!
//! v3 (future): bring SHA-256 + padding fully in-circuit, eliminating
//! the verifier-side hash work entirely.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example prove_rsa2048_record_v1

use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use num_bigint::BigUint;
use rand::SeedableRng;
use rsa::{
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use sha3::Digest;

use deep_ali::{
    deep_ali_merge_rsa_exp_multirow_streaming,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    rsa2048::{
        emsa_pkcs1_v1_5_encode_sha256, verify as native_rsa_verify,
        PublicKey as RsaPublic,
    },
    rsa2048_exp_air::{
        build_rsa_exp_multirow_layout, fill_rsa_exp_multirow,
        read_exp_output, rsa_exp_multirow_constraints, RSA_EXP_PER_ROW_CONSTRAINTS,
    },
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};
use sha2::Digest as ShaDigest;

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
    if remainder_log > 0 {
        s.push(1usize << remainder_log);
    }
    s
}

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

fn main() {
    println!("=== End-to-end RSA-2048 RRSIG STARK proof (v2) ===");
    println!();
    println!("Soundness model:");
    println!("  In-circuit: 17-step exp chain (e=65537, 16 sq + 1 mul)");
    println!("           + boundary constraint binding row-16 c == EM (Phase 4)");
    println!("  Verifier-side (deterministic): SHA-256 + PKCS#1 v1.5 EM padding");
    println!();

    // ── Generate a 2048-bit RSA keypair (deterministic seed). ──
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF_CAFE_F00D);
    let t_keygen = Instant::now();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048)
        .expect("RSA-2048 keygen failed");
    let pub_key = RsaPublicKey::from(&priv_key);
    println!("    [keygen]  {:.2?}", t_keygen.elapsed());

    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let message = b"DNSSEC-RRSIG-V0|google.com.|A|142.251.46.142|epoch-0";

    let t_sign = Instant::now();
    let signature = signing_key.sign(message);
    println!("    [sign]    {:.2?}", t_sign.elapsed());

    let signature_bytes = signature.to_bytes();
    let n_be = pub_key.n().to_bytes_be();

    // ── Native verify (refuse to STARK invalid sigs). ──
    let our_pub = RsaPublic::from_n_be(&n_be);
    let native_ok = native_rsa_verify(&our_pub, message, &signature_bytes);
    assert!(native_ok, "native RSA-2048 verify failed — refusing to STARK");
    println!("    [native verify] ✓");
    println!();

    // ── Compute the verifier-side EM (Phase 4 v2 binding). ──
    let mut digest = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.update(message);
    digest.copy_from_slice(&hasher.finalize());
    let em_bytes = emsa_pkcs1_v1_5_encode_sha256(&digest, 256)
        .expect("EM construction must succeed for k=256");
    let em_big = BigUint::from_bytes_be(&em_bytes);

    // ── Build the layout + fill the trace. ──
    const N_TRACE: usize = 32;
    let n_big = BigUint::from_bytes_be(&n_be);
    let s_big = BigUint::from_bytes_be(&signature_bytes);
    let (layout, total_cells) = build_rsa_exp_multirow_layout(0);
    let cons_per_row = rsa_exp_multirow_constraints(&layout);

    println!("─── Layout ───");
    println!("    Cells per row:        {}", total_cells);
    println!("    Constraints per row:  {}", cons_per_row);
    println!("    Trace rows (n_trace): {}", N_TRACE);
    println!("    LDE rows (n0):        {}", N_TRACE * BLOWUP);
    println!("    Total trace cells:    {} ({} MiB)",
        total_cells * N_TRACE,
        total_cells * N_TRACE * 8 / 1_048_576);
    println!("    Total cons evals:     {}",
        N_TRACE * BLOWUP * cons_per_row);
    println!();

    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); N_TRACE])
        .collect();

    let t_fill = Instant::now();
    fill_rsa_exp_multirow(&mut trace, &layout, N_TRACE, &n_big, &s_big, &em_big);
    println!("    [fill]    {:.2?}", t_fill.elapsed());

    // Sanity: row 16 output equals s^65537 mod n.
    let m_prime = read_exp_output(&trace, &layout);
    let expected = s_big.modpow(&BigUint::from(65_537u32), &n_big);
    assert_eq!(m_prime, expected, "exp chain produced wrong s^65537 mod n");
    println!("    [exp output sanity] s^65537 mod n matches BigUint modpow ✓");

    // ── LDE expansion. ──
    let n0 = N_TRACE * BLOWUP;
    let domain = FriDomain::new_radix2(n0);
    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).expect("LDE failed");
    println!("    [LDE]     {:.2?}", t_lde.elapsed());

    // ── Streaming merge. ──
    let coeffs = comb_coeffs(cons_per_row);
    let t_merge = Instant::now();
    let (c_eval, info) = deep_ali_merge_rsa_exp_multirow_streaming(
        &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
    );
    println!("    [merge]   {:.2?}", t_merge.elapsed());
    println!("      phi_deg={} quot_deg={} rate={:.3}",
        info.phi_degree_bound, info.quotient_degree_bound, info.rate);

    // ── pi_hash recipe (v2 — binds verifier-derived EM). ──
    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"RSA2048-V2-PI-PRE");
        h.update(&n_be);
        h.update(&signature_bytes);
        h.update(message);
        h.update(&em_bytes);
        h.finalize().into()
    };

    let params = DeepFriParams {
        schedule: make_schedule_stir(n0),
        r: NUM_QUERIES,
        seed_z: SEED_Z,
        coeff_commit_final: true,
        d_final: 1,
        stir: true,
        s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };

    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_dur = t_prove.elapsed();
    println!("    [prove]   {:.2?}", prove_dur);

    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_dur = t_verify.elapsed();
    assert!(ok, "local STARK verify failed");
    println!("    [verify]  {:.2?} ✓", verify_dur);

    let proof_bytes_count = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let mut blob = Vec::with_capacity(proof_bytes_count);
    proof.serialize_with_mode(&mut blob, Compress::Yes).unwrap();

    // pi_hash binding the FRI root.
    let mut h = sha3::Sha3_256::new();
    h.update(&pk_hash_pre);
    let mut root_buf = Vec::new();
    proof.root_f0.serialize_with_mode(&mut root_buf, Compress::Yes).unwrap();
    h.update(&root_buf);
    let pi_hash: [u8; 32] = h.finalize().into();

    println!();
    println!("=== Result ===");
    println!("  pi_hash:        {}", hex::encode(&pi_hash));
    println!("  FRI proof:      {} bytes", proof_bytes_count);
    println!("  prove time:     {:.2?}", prove_dur);
    println!("  verify time:    {:.2?}", verify_dur);
    println!("  Constraints/row:{}", RSA_EXP_PER_ROW_CONSTRAINTS);
    println!("  Cons evals:     {}", n0 * cons_per_row);
}
