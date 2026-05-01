//! Cross-algorithm DNS RRSIG STARK bench — Ed25519 / ECDSA-P256 / RSA-2048.
//!
//! Generates one keypair per algorithm, signs the same DNSSEC-style
//! message, runs the full prove+verify pipeline, and prints a unified
//! per-signature wall-time table.  Mirrors the headline numbers in
//! `tab:sig-circuit` of the paper and ensures all three measurements
//! come from a single run on the same M4 Mac mini state.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example crossalg_three_signature_bench

use std::time::{Duration, Instant};

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

#[derive(Default, Debug)]
struct AlgoResult {
    name: &'static str,
    fill_ms: f64,
    lde_ms: f64,
    merge_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    total_ms: f64,
    fri_proof_bytes: usize,
    constraints_per_row: usize,
    n0: usize,
    verified: bool,
}

impl AlgoResult {
    fn print(&self) {
        let total_s = self.total_ms / 1000.0;
        println!("─── {} ───", self.name);
        println!("    cons/row:        {}", self.constraints_per_row);
        println!("    n_0:             {}", self.n0);
        println!("    fill:            {:>8.2} ms", self.fill_ms);
        println!("    LDE:             {:>8.2} ms", self.lde_ms);
        println!("    streaming merge: {:>8.2} ms", self.merge_ms);
        println!("    prove:           {:>8.2} ms", self.prove_ms);
        println!("    verify:          {:>8.2} ms  {}",
            self.verify_ms, if self.verified { "✓" } else { "FAIL" });
        if total_s > 60.0 {
            println!("    TOTAL:           {:>8.2} s   ({:.2} min)",
                total_s, total_s / 60.0);
        } else {
            println!("    TOTAL:           {:>8.2} s", total_s);
        }
        println!("    FRI proof:       {} bytes", self.fri_proof_bytes);
        println!();
    }
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

fn run_ed25519(message: &[u8]) -> AlgoResult {
    use ed25519_dalek::{Signer, SigningKey};

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x111);
    let sk = SigningKey::generate(&mut rng);
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    let sig = sk.sign(message);
    let sig_bytes = sig.to_bytes();
    let r_compressed: [u8; 32] = sig_bytes[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig_bytes[32..64].try_into().unwrap();

    let mut sha512_input = Vec::with_capacity(64 + message.len());
    sha512_input.extend_from_slice(&r_compressed);
    sha512_input.extend_from_slice(&pk_bytes);
    sha512_input.extend_from_slice(message);

    let k_scalar = 256usize;
    let s_bits = s_bits_for_ladder(&s_bytes, k_scalar);
    let digest = sha512_air::sha512_native(&sha512_input);
    let mut digest_arr = [0u8; 64];
    digest_arr.copy_from_slice(&digest);
    let k_canonical = reduce_mod_l_wide(&digest_arr);
    let k_bits = r_thread_bits_for_kA(&k_canonical, k_scalar);

    let layout = verify_air_layout_v16(
        sha512_input.len(), &s_bits, &k_bits, &r_compressed, &pk_bytes,
    ).expect("layout build");

    let t_total = Instant::now();
    let t_fill = Instant::now();
    let (trace, _layout, _k) = fill_verify_air_v16(
        &sha512_input, &r_compressed, &pk_bytes, &s_bits, &k_bits,
    ).expect("trace build");
    let fill_ms = t_fill.elapsed().as_secs_f64() * 1000.0;

    let n_trace = layout.height;
    let n0 = n_trace * BLOWUP;
    let cons_per_row = verify_v16_per_row_constraints(layout.k_scalar);

    let domain = FriDomain::new_radix2(n0);
    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).unwrap();
    let lde_ms = t_lde.elapsed().as_secs_f64() * 1000.0;

    let coeffs = comb_coeffs(cons_per_row);
    let t_merge = Instant::now();
    let (c_eval, _) = deep_ali_merge_ed25519_verify_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let merge_ms = t_merge.elapsed().as_secs_f64() * 1000.0;
    drop(lde);

    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"ED25519-CROSS-BENCH");
        h.update(&pk_bytes);
        h.update(&sig_bytes);
        h.update(message);
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0),
        r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1,
        stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };
    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

    let proof_bytes_count = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let total_ms = t_total.elapsed().as_secs_f64() * 1000.0;

    AlgoResult {
        name: "Ed25519",
        fill_ms, lde_ms, merge_ms, prove_ms, verify_ms, total_ms,
        fri_proof_bytes: proof_bytes_count,
        constraints_per_row: cons_per_row,
        n0, verified: ok,
    }
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

fn run_ecdsa_p256(message: &[u8]) -> AlgoResult {
    use p256::ecdsa::{signature::Signer as _, SigningKey, Signature, VerifyingKey};
    use p256::ecdsa::signature::SignatureEncoding;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x222);
    let sk = SigningKey::random(&mut rng);
    let vk: VerifyingKey = (&sk).into();
    let pk_bytes = vk.to_encoded_point(false);
    let qx_bytes: [u8; 32] = pk_bytes.x().unwrap().as_slice().try_into().unwrap();
    let qy_bytes: [u8; 32] = pk_bytes.y().unwrap().as_slice().try_into().unwrap();

    // SHA-256 the message → digest.
    let mut digest = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.update(message);
    digest.copy_from_slice(&hasher.finalize());

    // Sign the digest.
    let sig: Signature = sk.sign(message);
    let sig_bytes = sig.to_bytes();
    let r_bytes: [u8; 32] = sig_bytes[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig_bytes[32..64].try_into().unwrap();

    // Native verify (refuse to STARK invalid sigs).
    let q = P256Pub::from_be_bytes(&qx_bytes, &qy_bytes).expect("Q on curve");
    let p256_sig = P256Sig::from_be_bytes(&r_bytes, &s_bytes).expect("sig in range");
    assert!(native_ecdsa_verify(&digest, &q, &p256_sig),
        "native ECDSA verify failed");

    // Derive u_1, u_2.
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
    let cons_per_row = ecdsa_double_multirow_constraints(&layout);

    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); n_trace])
        .collect();
    let g = *GENERATOR;
    let q_point = q.point;
    let z_one = {
        let mut t = FieldElement::zero();
        t.limbs[0] = 1;
        t
    };

    let t_total = Instant::now();
    let t_fill = Instant::now();
    let zero_fe = FieldElement::zero();
    fill_ecdsa_double_multirow(
        &mut trace, &layout, n_trace, K, K,
        &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &u1_bits,
        &q_point.x, &q_point.y, &z_one, &q_point.x, &q_point.y, &z_one, &u2_bits,
        &zero_fe, &zero_fe, &zero_fe, &zero_fe, &zero_fe, &zero_fe,
    );
    // Read chain outputs at row K-1.
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
    let fill_ms = t_fill.elapsed().as_secs_f64() * 1000.0;

    let domain = FriDomain::new_radix2(n0);
    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).unwrap();
    let lde_ms = t_lde.elapsed().as_secs_f64() * 1000.0;

    let coeffs = comb_coeffs(cons_per_row);
    let t_merge = Instant::now();
    let (c_eval, _) = deep_ali_merge_ecdsa_double_multirow_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let merge_ms = t_merge.elapsed().as_secs_f64() * 1000.0;
    drop(lde);
    drop(trace);

    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"ECDSAP256-CROSS-BENCH");
        h.update(&qx_bytes);
        h.update(&qy_bytes);
        h.update(&r_bytes);
        h.update(&s_bytes);
        h.update(&digest);
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0),
        r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1,
        stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };
    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

    let proof_bytes_count = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let total_ms = t_total.elapsed().as_secs_f64() * 1000.0;

    AlgoResult {
        name: "ECDSA-P256",
        fill_ms, lde_ms, merge_ms, prove_ms, verify_ms, total_ms,
        fri_proof_bytes: proof_bytes_count,
        constraints_per_row: cons_per_row,
        n0, verified: ok,
    }
}

fn run_rsa_2048(message: &[u8]) -> AlgoResult {
    use rsa::{
        pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding},
        traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey,
    };
    use sha2::Sha256;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x333);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA-2048 keygen");
    let pub_key = RsaPublicKey::from(&priv_key);
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let signature = signing_key.sign(message);
    let sig_bytes = signature.to_bytes();
    let n_be = pub_key.n().to_bytes_be();

    let our_pub = RsaPublic::from_n_be(&n_be);
    assert!(native_rsa_verify(&our_pub, message, &sig_bytes),
        "native RSA-2048 verify failed");

    let mut digest = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(message);
    digest.copy_from_slice(&hasher.finalize());
    let em_bytes = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();
    let em_big = BigUint::from_bytes_be(&em_bytes);

    const N_TRACE: usize = 32;
    let n_big = BigUint::from_bytes_be(&n_be);
    let s_big = BigUint::from_bytes_be(&sig_bytes);
    let (layout, total_cells) = build_rsa_exp_multirow_layout(0);
    let cons_per_row = rsa_exp_multirow_constraints(&layout);

    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); N_TRACE])
        .collect();
    let n0 = N_TRACE * BLOWUP;

    let t_total = Instant::now();
    let t_fill = Instant::now();
    fill_rsa_exp_multirow(&mut trace, &layout, N_TRACE, &n_big, &s_big, &em_big);
    let fill_ms = t_fill.elapsed().as_secs_f64() * 1000.0;

    let domain = FriDomain::new_radix2(n0);
    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).unwrap();
    let lde_ms = t_lde.elapsed().as_secs_f64() * 1000.0;

    let coeffs = comb_coeffs(cons_per_row);
    let t_merge = Instant::now();
    let (c_eval, _) = deep_ali_merge_rsa_exp_multirow_streaming(
        &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
    );
    let merge_ms = t_merge.elapsed().as_secs_f64() * 1000.0;
    drop(lde);
    drop(trace);

    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"RSA2048-CROSS-BENCH");
        h.update(&n_be);
        h.update(&sig_bytes);
        h.update(message);
        h.update(&em_bytes);
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0),
        r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1,
        stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };
    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

    let proof_bytes_count = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let total_ms = t_total.elapsed().as_secs_f64() * 1000.0;

    AlgoResult {
        name: "RSA-2048",
        fill_ms, lde_ms, merge_ms, prove_ms, verify_ms, total_ms,
        fri_proof_bytes: proof_bytes_count,
        constraints_per_row: cons_per_row,
        n0, verified: ok,
    }
}

fn main() {
    println!("=== Cross-algorithm DNS RRSIG STARK bench ===");
    println!();
    println!("All three production DNSSEC signature schemes,");
    println!("end-to-end on the same Apple M4 Mac mini state.");
    println!();

    let message = b"DNSSEC-RRSIG-V0|google.com.|A|142.251.46.142|epoch-0";

    println!("[1/3] RSA-2048 (PKCS#1 v1.5 + SHA-256, e=65537)");
    let rsa = run_rsa_2048(message);
    rsa.print();

    println!("[2/3] Ed25519 (RFC 8032 §5.1.7 cofactored, K=256)");
    let ed = run_ed25519(message);
    ed.print();

    println!("[3/3] ECDSA-P256 (FIPS 186-4 + SHA-256, double-chain K=256)");
    let ec = run_ecdsa_p256(message);
    ec.print();

    println!("================ Summary ================");
    println!();
    println!("{:<14}  {:>14}  {:>16}  {:>10}",
        "Algorithm", "Per-sig", "Per-record (×2)", "Proof");
    println!("{}", "─".repeat(60));
    let fmt_total = |ms: f64| -> String {
        let s = ms / 1000.0;
        if s > 60.0 {
            format!("{:.2} min", s / 60.0)
        } else {
            format!("{:.2} s", s)
        }
    };
    for r in [&rsa, &ed, &ec] {
        let per_sig = fmt_total(r.total_ms);
        let per_rec = fmt_total(2.0 * r.total_ms);
        println!("{:<14}  {:>14}  {:>16}  {:>10}",
            r.name, per_sig, per_rec,
            format!("{} B", r.fri_proof_bytes));
    }
    println!();
    println!("All three proofs verify locally ✓");
}
