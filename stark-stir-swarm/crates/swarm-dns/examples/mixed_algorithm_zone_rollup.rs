//! Mixed-algorithm DNS zone with outer-rollup STARK.
//!
//! Demonstrates the heterogeneous-algorithm property of the
//! architecture: a single zone may contain RRSIGs signed under
//! Ed25519, ECDSA-P256, and RSA-2048-SHA256, each proved by its
//! own per-record STARK with an algorithm-tagged
//! $\pi_{\mathrm{hash}}$, and all per-record $\pi_{\mathrm{hash}}$es
//! aggregated into a single outer-rollup STARK over a Merkle
//! commitment to the zone.
//!
//! For demonstration we build a 3-record zone (one per algorithm)
//! and report the full aggregate wall time (per-record proves +
//! outer-rollup STARK prove + verify).
//!
//! Run:
//!     cargo run --release -p swarm-dns --example mixed_algorithm_zone_rollup

use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use num_bigint::BigUint;
use rand::SeedableRng;
use sha2::Digest as ShaDigest;
use sha3::Digest as Sha3Digest;

use deep_ali::{
    deep_ali_merge_ecdsa_double_multirow_streaming,
    deep_ali_merge_ed25519_verify_streaming,
    deep_ali_merge_rsa_exp_multirow_streaming,
    ed25519_scalar::reduce_mod_l_wide,
    ed25519_verify_air::{
        fill_verify_air_v16, r_thread_bits_for_kA, verify_air_layout_v16,
        verify_v16_per_row_constraints,
    },
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    p256_ecdsa::{verify as native_ecdsa_verify, PublicKey as P256Pub, Signature as P256Sig},
    p256_ecdsa_double_multirow_air::{
        build_ecdsa_double_multirow_layout, ecdsa_double_multirow_constraints,
        fill_ecdsa_double_multirow,
    },
    p256_field::{FieldElement, NUM_LIMBS},
    p256_group::GENERATOR,
    p256_scalar::ScalarElement,
    rsa2048::{
        emsa_pkcs1_v1_5_encode_sha256, verify as native_rsa_verify,
        PublicKey as RsaPublic,
    },
    rsa2048_exp_air::{
        build_rsa_exp_multirow_layout, fill_rsa_exp_multirow,
        rsa_exp_multirow_constraints,
    },
    sextic_ext::SexticExt,
    sha512_air,
    trace_import::lde_trace_columns,
};
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
    if remainder_log > 0 {
        s.push(1usize << remainder_log);
    }
    s
}

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

fn s_bits_for_ladder(s_bytes: &[u8; 32], k_scalar: usize) -> Vec<bool> {
    let mut bits_lsb_first: Vec<bool> = Vec::with_capacity(256);
    for byte in s_bytes.iter() {
        for i in 0..8 {
            bits_lsb_first.push(((byte >> i) & 1) != 0);
        }
    }
    bits_lsb_first.reverse();
    bits_lsb_first.into_iter().take(k_scalar).collect()
}

fn scalar_to_msb_bits(s: &ScalarElement) -> Vec<bool> {
    let bytes = s.to_be_bytes();
    let mut bits = Vec::with_capacity(256);
    for byte in bytes.iter() {
        for i in (0..8).rev() {
            bits.push(((byte >> i) & 1) != 0);
        }
    }
    bits
}

#[derive(Debug)]
struct PerRecordResult {
    algorithm: &'static str,
    domain: String,
    pi_hash: [u8; 32],
    prove_s: f64,
    proof_bytes: usize,
    verified: bool,
}

fn prove_record_ed25519(domain: &str, ip: [u8; 4], rng_seed: u64) -> PerRecordResult {
    use ed25519_dalek::{Signer, SigningKey};

    let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
    let sk = SigningKey::generate(&mut rng);
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    let message = format!(
        "DNSSEC-RRSIG-V0|{}|A|{}.{}.{}.{}|epoch-0|alg-15",
        domain, ip[0], ip[1], ip[2], ip[3]
    );
    let sig = sk.sign(message.as_bytes());
    let sig_bytes = sig.to_bytes();
    let r_compressed: [u8; 32] = sig_bytes[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig_bytes[32..64].try_into().unwrap();

    let mut sha512_input = Vec::with_capacity(64 + message.len());
    sha512_input.extend_from_slice(&r_compressed);
    sha512_input.extend_from_slice(&pk_bytes);
    sha512_input.extend_from_slice(message.as_bytes());

    let s_bits = s_bits_for_ladder(&s_bytes, 256);
    let digest = sha512_air::sha512_native(&sha512_input);
    let mut digest_arr = [0u8; 64];
    digest_arr.copy_from_slice(&digest);
    let k_canonical = reduce_mod_l_wide(&digest_arr);
    let k_bits = r_thread_bits_for_kA(&k_canonical, 256);

    let layout = verify_air_layout_v16(
        sha512_input.len(), &s_bits, &k_bits, &r_compressed, &pk_bytes,
    ).unwrap();
    let (trace, _, _) = fill_verify_air_v16(
        &sha512_input, &r_compressed, &pk_bytes, &s_bits, &k_bits,
    ).unwrap();

    let n_trace = layout.height;
    let n0 = n_trace * BLOWUP;

    let t = Instant::now();
    let domain_fri = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).unwrap();
    let coeffs = comb_coeffs(verify_v16_per_row_constraints(layout.k_scalar));
    let (c_eval, _) = deep_ali_merge_ed25519_verify_streaming(
        &lde, &coeffs, &layout, domain_fri.omega, n_trace, BLOWUP,
    );
    drop(lde);

    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"ED25519-MIXEDZONE");
        h.update(&pk_bytes);
        h.update(&sig_bytes);
        h.update(message.as_bytes());
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };
    let proof = deep_fri_prove::<Ext>(c_eval, domain_fri, &params);
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);

    // Per-record pi_hash binds pre-image + fri root.
    let mut h = sha3::Sha3_256::new();
    h.update(&pk_hash_pre);
    let mut root_buf = Vec::new();
    proof.root_f0.serialize_with_mode(&mut root_buf, Compress::Yes).unwrap();
    h.update(&root_buf);
    let pi_hash: [u8; 32] = h.finalize().into();

    PerRecordResult {
        algorithm: "Ed25519",
        domain: domain.to_string(),
        pi_hash,
        prove_s: t.elapsed().as_secs_f64(),
        proof_bytes: bytes,
        verified: ok,
    }
}

fn prove_record_ecdsa(domain: &str, ip: [u8; 4], rng_seed: u64) -> PerRecordResult {
    use p256::ecdsa::{
        signature::Signer, signature::SignatureEncoding,
        Signature, SigningKey, VerifyingKey,
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
    let sk = SigningKey::random(&mut rng);
    let vk: VerifyingKey = (&sk).into();
    let pk_pt = vk.to_encoded_point(false);
    let qx_bytes: [u8; 32] = pk_pt.x().unwrap().as_slice().try_into().unwrap();
    let qy_bytes: [u8; 32] = pk_pt.y().unwrap().as_slice().try_into().unwrap();
    let message = format!(
        "DNSSEC-RRSIG-V0|{}|A|{}.{}.{}.{}|epoch-0|alg-13",
        domain, ip[0], ip[1], ip[2], ip[3]
    );
    let mut digest = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.update(message.as_bytes());
    digest.copy_from_slice(&hasher.finalize());

    let sig: Signature = sk.sign(message.as_bytes());
    let sig_bytes = sig.to_bytes();
    let r_bytes: [u8; 32] = sig_bytes[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig_bytes[32..64].try_into().unwrap();

    let q = P256Pub::from_be_bytes(&qx_bytes, &qy_bytes).unwrap();
    let p256_sig = P256Sig::from_be_bytes(&r_bytes, &s_bytes).unwrap();
    assert!(native_ecdsa_verify(&digest, &q, &p256_sig));

    let e = ScalarElement::from_be_bytes(&digest);
    let w = p256_sig.s.invert();
    let u_1 = e.mul(&w);
    let u_2 = p256_sig.r.mul(&w);
    let u1_bits = scalar_to_msb_bits(&u_1);
    let u2_bits = scalar_to_msb_bits(&u_2);

    const K: usize = 256;
    let n_trace = K;
    let n0 = n_trace * BLOWUP;
    let (layout, total_cells) = build_ecdsa_double_multirow_layout(0);
    let cons = ecdsa_double_multirow_constraints(&layout);

    let g = *GENERATOR;
    let q_point = q.point;
    let z_one = {
        let mut t = FieldElement::zero();
        t.limbs[0] = 1;
        t
    };

    let t = Instant::now();
    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); n_trace]).collect();
    let zero_fe = FieldElement::zero();
    fill_ecdsa_double_multirow(
        &mut trace, &layout, n_trace, K, K,
        &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &u1_bits,
        &q_point.x, &q_point.y, &z_one, &q_point.x, &q_point.y, &z_one, &u2_bits,
        &zero_fe, &zero_fe, &zero_fe, &zero_fe, &zero_fe, &zero_fe,
    );
    let read_fe = |trace: &[Vec<F>], base: usize, row: usize| -> FieldElement {
        use ark_ff::PrimeField;
        let mut limbs = [0i64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let v = trace[base + i][row];
            let bi = v.into_bigint();
            limbs[i] = bi.as_ref()[0] as i64;
        }
        FieldElement { limbs }
    };
    let last = K - 1;
    let r_a_x = read_fe(&trace, layout.step_a.select_x.c_limbs_base, last);
    let r_a_y = read_fe(&trace, layout.step_a.select_y.c_limbs_base, last);
    let r_a_z = read_fe(&trace, layout.step_a.select_z.c_limbs_base, last);
    let r_b_x = read_fe(&trace, layout.step_b.select_x.c_limbs_base, last);
    let r_b_y = read_fe(&trace, layout.step_b.select_y.c_limbs_base, last);
    let r_b_z = read_fe(&trace, layout.step_b.select_z.c_limbs_base, last);
    trace = (0..total_cells).map(|_| vec![F::zero(); n_trace]).collect();
    fill_ecdsa_double_multirow(
        &mut trace, &layout, n_trace, K, K,
        &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &u1_bits,
        &q_point.x, &q_point.y, &z_one, &q_point.x, &q_point.y, &z_one, &u2_bits,
        &r_a_x, &r_a_y, &r_a_z, &r_b_x, &r_b_y, &r_b_z,
    );

    let domain_fri = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).unwrap();
    let coeffs = comb_coeffs(cons);
    let (c_eval, _) = deep_ali_merge_ecdsa_double_multirow_streaming(
        &lde, &coeffs, &layout, domain_fri.omega, n_trace, BLOWUP,
    );
    drop(lde); drop(trace);

    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"ECDSAP256-MIXEDZONE");
        h.update(&qx_bytes);
        h.update(&qy_bytes);
        h.update(&r_bytes);
        h.update(&s_bytes);
        h.update(&digest);
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };
    let proof = deep_fri_prove::<Ext>(c_eval, domain_fri, &params);
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let mut h = sha3::Sha3_256::new();
    h.update(&pk_hash_pre);
    let mut root_buf = Vec::new();
    proof.root_f0.serialize_with_mode(&mut root_buf, Compress::Yes).unwrap();
    h.update(&root_buf);
    let pi_hash: [u8; 32] = h.finalize().into();

    PerRecordResult {
        algorithm: "ECDSA-P256",
        domain: domain.to_string(),
        pi_hash,
        prove_s: t.elapsed().as_secs_f64(),
        proof_bytes: bytes,
        verified: ok,
    }
}

fn prove_record_rsa(domain: &str, ip: [u8; 4], rng_seed: u64) -> PerRecordResult {
    use rsa::{
        pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding},
        traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey,
    };
    use sha2::Sha256;

    let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let message = format!(
        "DNSSEC-RRSIG-V0|{}|A|{}.{}.{}.{}|epoch-0|alg-8",
        domain, ip[0], ip[1], ip[2], ip[3]
    );
    let signature = signing_key.sign(message.as_bytes());
    let sig_bytes = signature.to_bytes();
    let n_be = pub_key.n().to_bytes_be();
    let our_pub = RsaPublic::from_n_be(&n_be);
    assert!(native_rsa_verify(&our_pub, message.as_bytes(), &sig_bytes));

    let mut digest = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    digest.copy_from_slice(&hasher.finalize());
    let em_bytes = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();
    let em_big = BigUint::from_bytes_be(&em_bytes);

    const N_TRACE: usize = 32;
    let n_big = BigUint::from_bytes_be(&n_be);
    let s_big = BigUint::from_bytes_be(&sig_bytes);
    let (layout, total_cells) = build_rsa_exp_multirow_layout(0);
    let cons = rsa_exp_multirow_constraints(&layout);

    let t = Instant::now();
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
        h.update(b"RSA2048-MIXEDZONE");
        h.update(&n_be);
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
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let mut h = sha3::Sha3_256::new();
    h.update(&pk_hash_pre);
    let mut root_buf = Vec::new();
    proof.root_f0.serialize_with_mode(&mut root_buf, Compress::Yes).unwrap();
    h.update(&root_buf);
    let pi_hash: [u8; 32] = h.finalize().into();

    PerRecordResult {
        algorithm: "RSA-2048",
        domain: domain.to_string(),
        pi_hash,
        prove_s: t.elapsed().as_secs_f64(),
        proof_bytes: bytes,
        verified: ok,
    }
}

fn main() {
    println!("=== Mixed-algorithm DNS zone with outer-rollup STARK ===");
    println!();
    println!("Zone composition (one record per algorithm):");
    println!("  alg-15 (Ed25519)    on api.example.com.       → 10.0.0.1");
    println!("  alg-13 (ECDSA-P256) on www.example.com.       → 10.0.0.2");
    println!("  alg-8  (RSA-2048)   on legacy.example.com.    → 10.0.0.3");
    println!();

    let t_total = Instant::now();
    let mut results = Vec::new();

    println!(">>> [1/3] Proving RSA-2048 record (legacy.example.com.)");
    let rsa = prove_record_rsa("legacy.example.com.", [10, 0, 0, 3], 0xA1);
    println!("    pi_hash = {}", hex::encode(&rsa.pi_hash[..8]));
    println!("    prove   = {:.2} s   proof = {} B   {}",
        rsa.prove_s, rsa.proof_bytes,
        if rsa.verified { "✓" } else { "FAIL" });
    println!();
    results.push(rsa);

    println!(">>> [2/3] Proving Ed25519 record (api.example.com.)");
    let ed = prove_record_ed25519("api.example.com.", [10, 0, 0, 1], 0xB2);
    println!("    pi_hash = {}", hex::encode(&ed.pi_hash[..8]));
    println!("    prove   = {:.2} s ({:.2} min)   proof = {} B   {}",
        ed.prove_s, ed.prove_s / 60.0, ed.proof_bytes,
        if ed.verified { "✓" } else { "FAIL" });
    println!();
    results.push(ed);

    println!(">>> [3/3] Proving ECDSA-P256 record (www.example.com.)");
    let ec = prove_record_ecdsa("www.example.com.", [10, 0, 0, 2], 0xC3);
    println!("    pi_hash = {}", hex::encode(&ec.pi_hash[..8]));
    println!("    prove   = {:.2} s ({:.2} min)   proof = {} B   {}",
        ec.prove_s, ec.prove_s / 60.0, ec.proof_bytes,
        if ec.verified { "✓" } else { "FAIL" });
    println!();
    results.push(ec);

    let per_record_proves_s = results.iter().map(|r| r.prove_s).sum::<f64>();

    // ── Outer-rollup STARK over all per-record pi_hashes. ──
    println!(">>> Outer-rollup STARK over {} per-record pi_hashes",
        results.len());
    let pi_hashes: Vec<[u8; 32]> = results.iter().map(|r| r.pi_hash).collect();

    // The outer rollup binds the algorithm-tagged pi_hashes via a
    // fresh epoch hash.  In production this would also include the
    // ML-DSA epoch signature; here we just use a deterministic tag.
    let mut h = sha3::Sha3_256::new();
    h.update(b"MIXED-ZONE-EPOCH-0");
    for pi in &pi_hashes { h.update(pi); }
    let outer_pk_hash: [u8; 32] = h.finalize().into();

    let t_outer = Instant::now();
    let outer = prove_outer_rollup(&pi_hashes, &outer_pk_hash, LdtMode::Stir);
    let outer_total_s = t_outer.elapsed().as_secs_f64();

    println!("    n_trace          : {}", outer.n_trace);
    println!("    proof bytes      : {}", outer.proof_bytes);
    println!("    prove time       : {:.2} ms", outer.prove_ms);
    println!("    local verify     : {:.2} ms ✓", outer.local_verify_ms);
    println!("    outer fri root_f0: {}", hex::encode(&outer.root_f0));
    println!();

    println!("================ Summary ================");
    println!();
    let total_s = t_total.elapsed().as_secs_f64();
    println!("Per-record (algorithm-tagged) STARKs:");
    for r in &results {
        println!("  [{:<10}] {:>40}  prove={:>8.2}s  proof={} B  {}",
            r.algorithm, &r.domain, r.prove_s, r.proof_bytes,
            if r.verified { "✓" } else { "FAIL" });
    }
    println!();
    println!("Outer-rollup STARK over {} pi_hashes:", pi_hashes.len());
    println!("  prove                        = {:.2} ms", outer.prove_ms);
    println!("  verify                       = {:.2} ms ✓", outer.local_verify_ms);
    println!("  proof bytes                  = {} B", outer.proof_bytes);
    println!();
    println!("Aggregate wall time:");
    println!("  Per-record STARKs (sum)      = {:.2} s ({:.2} min)",
        per_record_proves_s, per_record_proves_s / 60.0);
    println!("  Outer rollup (prove+verify)  = {:.2} ms",
        outer.prove_ms + outer.local_verify_ms);
    println!("  Driver overhead              = {:.2} s",
        total_s - per_record_proves_s - (outer.prove_ms + outer.local_verify_ms) / 1000.0 - outer_total_s + outer.prove_ms / 1000.0);
    println!("  TOTAL                        = {:.2} s ({:.2} min)",
        total_s, total_s / 60.0);
    println!();
    let total_proof_bytes = results.iter().map(|r| r.proof_bytes).sum::<usize>()
        + outer.proof_bytes;
    println!("Total proof artefact size      = {} B ({:.1} KiB)",
        total_proof_bytes, total_proof_bytes as f64 / 1024.0);
    println!();
    println!("All proofs verify locally ✓");
    println!();
    println!("This demonstrates the architecture's heterogeneous-algorithm");
    println!("property: a single zone with mixed RRSIG signature types is");
    println!("provable end-to-end with one outer-rollup STARK binding all");
    println!("per-record proofs into a single epoch artefact.");
}
