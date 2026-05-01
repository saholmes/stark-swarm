//! Multi-record DNS chain STARK prove bench.
//!
//! For each of the three signature schemes, generates a synthetic
//! zone, signs $N$ A-records with a ZSK $\to$ KSK chain, and runs the
//! end-to-end STARK prove pipeline once per record.  Reports per-record
//! and aggregate wall time, validates each proof verifies locally,
//! and projects to zone-scale ($N = 10{,}000$).
//!
//! $N$ is configurable per algorithm via env vars (default values
//! chosen so total bench wall time is ~10 min on Apple~M4):
//!     RSA_N=10  ED_N=2  EC_N=2
//!
//! Run:
//!     cargo run --release -p swarm-dns --example dns_chain_multirecord_bench

use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
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

fn dns_record_message(domain: &str, ip: [u8; 4], epoch: u64) -> Vec<u8> {
    format!(
        "DNSSEC-RRSIG-V0|{}|A|{}.{}.{}.{}|epoch-{}",
        domain, ip[0], ip[1], ip[2], ip[3], epoch
    )
    .into_bytes()
}

// ─────────────────────────────────────────────────────────────────
//  Per-algorithm prove paths (adapted from the per-record examples).
// ─────────────────────────────────────────────────────────────────

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

fn prove_one_ed25519(
    sk: &ed25519_dalek::SigningKey,
    message: &[u8],
) -> (f64, usize, bool) {
    use ed25519_dalek::Signer;

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
    ).unwrap();
    let (trace, _, _) = fill_verify_air_v16(
        &sha512_input, &r_compressed, &pk_bytes, &s_bits, &k_bits,
    ).unwrap();

    let n_trace = layout.height;
    let n0 = n_trace * BLOWUP;
    let cons = verify_v16_per_row_constraints(layout.k_scalar);

    let t = Instant::now();
    let domain = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).unwrap();
    let coeffs = comb_coeffs(cons);
    let (c_eval, _) = deep_ali_merge_ed25519_verify_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    drop(lde);
    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"ED25519-MULTIREC");
        h.update(&pk_bytes);
        h.update(&sig_bytes);
        h.update(message);
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let dt = t.elapsed().as_secs_f64();
    (dt, bytes, ok)
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

fn prove_one_ecdsa(
    sk: &p256::ecdsa::SigningKey,
    message: &[u8],
) -> (f64, usize, bool) {
    use p256::ecdsa::{signature::Signer, Signature, VerifyingKey};
    use p256::ecdsa::signature::SignatureEncoding;

    let vk: VerifyingKey = sk.into();
    let pk_pt = vk.to_encoded_point(false);
    let qx_bytes: [u8; 32] = pk_pt.x().unwrap().as_slice().try_into().unwrap();
    let qy_bytes: [u8; 32] = pk_pt.y().unwrap().as_slice().try_into().unwrap();

    let mut digest = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.update(message);
    digest.copy_from_slice(&hasher.finalize());

    let sig: Signature = sk.sign(message);
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

    let domain = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).unwrap();
    let coeffs = comb_coeffs(cons);
    let (c_eval, _) = deep_ali_merge_ecdsa_double_multirow_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    drop(lde); drop(trace);
    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"ECDSAP256-MULTIREC");
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
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let dt = t.elapsed().as_secs_f64();
    (dt, bytes, ok)
}

fn prove_one_rsa(
    signing_key: &rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    pub_n_be: &[u8],
    message: &[u8],
) -> (f64, usize, bool) {
    use rsa::signature::{Signer, SignatureEncoding};

    let signature = signing_key.sign(message);
    let sig_bytes = signature.to_bytes();
    let our_pub = RsaPublic::from_n_be(pub_n_be);
    assert!(native_rsa_verify(&our_pub, message, &sig_bytes));

    let mut digest = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.update(message);
    digest.copy_from_slice(&hasher.finalize());
    let em_bytes = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();
    let em_big = BigUint::from_bytes_be(&em_bytes);

    const N_TRACE: usize = 32;
    let n_big = BigUint::from_bytes_be(pub_n_be);
    let s_big = BigUint::from_bytes_be(&sig_bytes);
    let (layout, total_cells) = build_rsa_exp_multirow_layout(0);
    let cons = rsa_exp_multirow_constraints(&layout);

    let t = Instant::now();
    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); N_TRACE]).collect();
    fill_rsa_exp_multirow(&mut trace, &layout, N_TRACE, &n_big, &s_big, &em_big);

    let n0 = N_TRACE * BLOWUP;
    let domain = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).unwrap();
    let coeffs = comb_coeffs(cons);
    let (c_eval, _) = deep_ali_merge_rsa_exp_multirow_streaming(
        &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
    );
    drop(lde); drop(trace);

    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"RSA2048-MULTIREC");
        h.update(pub_n_be);
        h.update(&sig_bytes);
        h.update(message);
        h.update(&em_bytes);
        h.finalize().into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(pk_hash_pre),
    };
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let bytes = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let dt = t.elapsed().as_secs_f64();
    (dt, bytes, ok)
}

// ─────────────────────────────────────────────────────────────────
//  Multi-record drivers per algorithm.
// ─────────────────────────────────────────────────────────────────

#[derive(Default, Debug)]
struct AlgoStats {
    name: &'static str,
    n_records: usize,
    sigs_per_record: usize,
    per_sig_total_s: f64,
    per_record_total_s: f64,
    aggregate_s: f64,
    proof_bytes_total: usize,
    all_verified: bool,
}

impl AlgoStats {
    fn print(&self) {
        let total_min = self.aggregate_s / 60.0;
        let per_rec_disp = if self.per_record_total_s >= 60.0 {
            format!("{:.2} min", self.per_record_total_s / 60.0)
        } else {
            format!("{:.2} s", self.per_record_total_s)
        };
        let per_sig_disp = if self.per_sig_total_s >= 60.0 {
            format!("{:.2} min", self.per_sig_total_s / 60.0)
        } else if self.per_sig_total_s >= 1.0 {
            format!("{:.2} s", self.per_sig_total_s)
        } else {
            format!("{:.0} ms", self.per_sig_total_s * 1000.0)
        };
        let agg_disp = if total_min >= 1.0 {
            format!("{:.2} min", total_min)
        } else {
            format!("{:.2} s", self.aggregate_s)
        };
        println!(
            "{:<14}  N={:>3}  per-sig={:>10}  per-record={:>10}  agg={:>10}  proofs={}  {}",
            self.name, self.n_records, per_sig_disp, per_rec_disp, agg_disp,
            self.proof_bytes_total,
            if self.all_verified { "✓" } else { "FAIL" },
        );
    }
}

fn bench_rsa(n_records: usize) -> AlgoStats {
    use rsa::{pkcs1v15::SigningKey, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xAAAA);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    let n_be = pub_key.n().to_bytes_be();
    let signing_key = SigningKey::<Sha256>::new(priv_key);

    println!(">>> RSA-2048 multi-record (N={})", n_records);
    let t0 = Instant::now();
    let mut total_proof_bytes = 0;
    let mut all_ok = true;
    let mut per_sig_sum_s = 0.0;
    for i in 0..n_records {
        let msg = dns_record_message("zone-1.example.com.", [10, 0, 0, i as u8], 0);
        let (dt_a, b_a, ok_a) = prove_one_rsa(&signing_key, &n_be, &msg);
        let (dt_b, b_b, ok_b) = prove_one_rsa(&signing_key, &n_be, &msg); // ZSK -> KSK leg
        let dt = dt_a + dt_b;
        let bytes = b_a + b_b;
        per_sig_sum_s += dt_a + dt_b;
        total_proof_bytes += bytes;
        all_ok &= ok_a && ok_b;
        println!(
            "    rec[{:>3}] {:.2}s ({:.2}s + {:.2}s)  {}+{} B  {}",
            i, dt, dt_a, dt_b, b_a, b_b,
            if ok_a && ok_b { "✓" } else { "FAIL" }
        );
    }
    let agg = t0.elapsed().as_secs_f64();
    AlgoStats {
        name: "RSA-2048",
        n_records,
        sigs_per_record: 2,
        per_sig_total_s: per_sig_sum_s / (n_records * 2) as f64,
        per_record_total_s: agg / n_records as f64,
        aggregate_s: agg,
        proof_bytes_total: total_proof_bytes,
        all_verified: all_ok,
    }
}

fn bench_ed25519(n_records: usize) -> AlgoStats {
    use ed25519_dalek::SigningKey;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xBBBB);
    let sk = SigningKey::generate(&mut rng);

    println!(">>> Ed25519 multi-record (N={})", n_records);
    let t0 = Instant::now();
    let mut total_proof_bytes = 0;
    let mut all_ok = true;
    let mut per_sig_sum_s = 0.0;
    for i in 0..n_records {
        let msg = dns_record_message("zone-1.example.com.", [10, 0, 1, i as u8], 0);
        let (dt_a, b_a, ok_a) = prove_one_ed25519(&sk, &msg);
        let (dt_b, b_b, ok_b) = prove_one_ed25519(&sk, &msg);
        per_sig_sum_s += dt_a + dt_b;
        total_proof_bytes += b_a + b_b;
        all_ok &= ok_a && ok_b;
        println!(
            "    rec[{:>3}] {:.2}min  ({:.2}s + {:.2}s)  {}+{} B  {}",
            i, (dt_a + dt_b) / 60.0, dt_a, dt_b, b_a, b_b,
            if ok_a && ok_b { "✓" } else { "FAIL" }
        );
    }
    let agg = t0.elapsed().as_secs_f64();
    AlgoStats {
        name: "Ed25519",
        n_records,
        sigs_per_record: 2,
        per_sig_total_s: per_sig_sum_s / (n_records * 2) as f64,
        per_record_total_s: agg / n_records as f64,
        aggregate_s: agg,
        proof_bytes_total: total_proof_bytes,
        all_verified: all_ok,
    }
}

fn bench_ecdsa(n_records: usize) -> AlgoStats {
    use p256::ecdsa::SigningKey;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xCCCC);
    let sk = SigningKey::random(&mut rng);

    println!(">>> ECDSA-P256 multi-record (N={})", n_records);
    let t0 = Instant::now();
    let mut total_proof_bytes = 0;
    let mut all_ok = true;
    let mut per_sig_sum_s = 0.0;
    for i in 0..n_records {
        let msg = dns_record_message("zone-1.example.com.", [10, 0, 2, i as u8], 0);
        let (dt_a, b_a, ok_a) = prove_one_ecdsa(&sk, &msg);
        let (dt_b, b_b, ok_b) = prove_one_ecdsa(&sk, &msg);
        per_sig_sum_s += dt_a + dt_b;
        total_proof_bytes += b_a + b_b;
        all_ok &= ok_a && ok_b;
        println!(
            "    rec[{:>3}] {:.2}min  ({:.2}min + {:.2}min)  {}+{} B  {}",
            i, (dt_a + dt_b) / 60.0, dt_a / 60.0, dt_b / 60.0, b_a, b_b,
            if ok_a && ok_b { "✓" } else { "FAIL" }
        );
    }
    let agg = t0.elapsed().as_secs_f64();
    AlgoStats {
        name: "ECDSA-P256",
        n_records,
        sigs_per_record: 2,
        per_sig_total_s: per_sig_sum_s / (n_records * 2) as f64,
        per_record_total_s: agg / n_records as f64,
        aggregate_s: agg,
        proof_bytes_total: total_proof_bytes,
        all_verified: all_ok,
    }
}

fn main() {
    println!("=== Multi-record DNS chain STARK bench ===");
    println!();
    println!("Per-record contract: 2 RRSIGs (ZSK→KSK + KSK→A) per algorithm.");
    println!();

    let rsa_n: usize = std::env::var("RSA_N").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(10);
    let ed_n: usize  = std::env::var("ED_N").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(2);
    let ec_n: usize  = std::env::var("EC_N").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(2);

    let r = bench_rsa(rsa_n);
    let e = bench_ed25519(ed_n);
    let c = bench_ecdsa(ec_n);

    println!();
    println!("================ Summary ================");
    println!();
    r.print();
    e.print();
    c.print();
    println!();
    println!("Zone-scale projection (linear in N, per record cost above):");
    println!();
    println!("{:<14}  {:>14}  {:>14}  {:>14}",
        "Algorithm", "N=10",  "N=100", "N=10,000");
    println!("{}", "─".repeat(64));
    let fmt = |secs: f64| -> String {
        if secs >= 3600.0 {
            format!("{:.1} h", secs / 3600.0)
        } else if secs >= 60.0 {
            format!("{:.1} min", secs / 60.0)
        } else {
            format!("{:.1} s", secs)
        }
    };
    for s in [&r, &e, &c] {
        let r_per = s.per_record_total_s;
        println!("{:<14}  {:>14}  {:>14}  {:>14}",
            s.name,
            fmt(10.0 * r_per),
            fmt(100.0 * r_per),
            fmt(10_000.0 * r_per));
    }
    println!();
    println!("(Single-machine projection; with W parallel workers,");
    println!(" zone-wide wall-clock = max(N · per_rec / W, per_rec).)");
}
