//! End-to-end ECDSA-P256 RRSIG STARK proof on real signature input.
//!
//! Wires a real ECDSA-P256 signature through the in-circuit
//! double-chain multi-row STARK at production parameters $K{=}256$.
//!
//! Soundness model (v1):
//!   - **In-circuit** (the dominant 99.9 % of cost): the
//!     $K{=}256$ double scalar-mul $u_1{\cdot}G + u_2{\cdot}Q$ is
//!     proved end-to-end via
//!     `deep_ali_merge_ecdsa_double_multirow_streaming`. The trace
//!     is filled from real $(u_1, u_2)$ derived from the signature,
//!     and all $\sim 1.27 \times 10^9$ transition constraint
//!     evaluations satisfy on the LDE domain with local STARK
//!     verify passing.
//!   - **Native at prove time** (the remaining 0.1 %): the chain
//!     output projective-to-affine conversion ($Z^{-1}$ Fermat),
//!     the final group-add, the $R.x \bmod n$ reduction, and the
//!     equality check $R.x \bmod n == r$ are computed natively
//!     out-of-circuit. The native ECDSA verifier (RFC 6979
//!     compliant) is invoked at prove time, and the prover refuses
//!     to emit a STARK for an invalid signature. This is a strictly
//!     stronger soundness model than the original DNSSEC RSA T2
//!     fallback, but a strictly weaker one than the Ed25519
//!     v16 STARK (which is fully in-circuit).
//!
//! v2 (deferred): rigorous in-circuit final ops via a multi-row
//! Fermat extension to the AIR, eliminating the native fall-through.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example prove_ecdsa_record_v1

use std::time::Instant;

use ark_ff::Zero;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use sha3::Digest;

use deep_ali::{
    deep_ali_merge_ecdsa_double_multirow_streaming,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    p256_ecdsa::{verify as native_ecdsa_verify, PublicKey, Signature},
    p256_ecdsa_double_multirow_air::{
        build_ecdsa_double_multirow_layout, ecdsa_double_multirow_constraints,
        fill_ecdsa_double_multirow,
    },
    p256_field::FieldElement,
    p256_group::GENERATOR,
    p256_scalar::ScalarElement,
    sextic_ext::SexticExt,
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

/// Decompose a `ScalarElement` to MSB-first 256 bits.
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

/// Result of an end-to-end ECDSA-P256 RRSIG STARK proof.
struct EcdsaRecordProof {
    pi_hash: [u8; 32],
    fri_proof_bytes: usize,
    prove_ms: f64,
    verify_ms: f64,
    constraint_count: usize,
    constraint_evals_total: usize,
}

fn prove_ecdsa_record_v1(
    public_key_xy: &([u8; 32], [u8; 32]),
    signature_rs: &([u8; 32], [u8; 32]),
    digest_be: &[u8; 32],
) -> EcdsaRecordProof {
    let t_total = Instant::now();

    // ── Native verify (refuse to STARK an invalid signature) ──
    let q = PublicKey::from_be_bytes(&public_key_xy.0, &public_key_xy.1)
        .expect("public key must be on the curve");
    let sig = Signature::from_be_bytes(&signature_rs.0, &signature_rs.1)
        .expect("signature scalars must be in [1, n-1]");
    let native_ok = native_ecdsa_verify(digest_be, &q, &sig);
    assert!(native_ok, "native ECDSA-P256 verify failed — refusing to STARK");

    // ── Derive u_1 = e·s^{-1}, u_2 = r·s^{-1} mod n ──
    let e = ScalarElement::from_be_bytes(digest_be);
    let w = sig.s.invert();
    let u_1 = e.mul(&w);
    let u_2 = sig.r.mul(&w);

    let u1_bits = scalar_to_msb_bits(&u_1);
    let u2_bits = scalar_to_msb_bits(&u_2);

    // ── Build the K=256 double-chain layout ──
    const K: usize = 256;
    let n_trace = K;
    let n0 = n_trace * BLOWUP;
    let (layout, total_cells) = build_ecdsa_double_multirow_layout(0);
    let total_constraints = ecdsa_double_multirow_constraints(&layout);

    println!("    [layout] cells/row={} cons/row={} n_trace={} n0={}",
        total_cells, total_constraints, n_trace, n0);
    println!("    [layout] total cells={}MB total cons evals={}M",
        total_cells * n_trace * 8 / 1_048_576,
        n0 * total_constraints / 1_000_000);

    // ── Allocate + fill the trace ──
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

    let t_fill = Instant::now();
    fill_ecdsa_double_multirow(
        &mut trace, &layout, n_trace, K, K,
        &g.x, &g.y, &z_one, &g.x, &g.y, &z_one, &u1_bits,
        &q_point.x, &q_point.y, &z_one, &q_point.x, &q_point.y, &z_one, &u2_bits,
    );
    println!("    [fill] {:.2?}", t_fill.elapsed());

    // ── LDE ──
    let domain = FriDomain::new_radix2(n0);
    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).expect("LDE failed");
    println!("    [LDE]  {:.2?}", t_lde.elapsed());

    // ── Streaming merge ──
    let coeffs = comb_coeffs(total_constraints);
    let t_merge = Instant::now();
    let (c_eval, _info) = deep_ali_merge_ecdsa_double_multirow_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    println!("    [merge stream] {:.2?}", t_merge.elapsed());
    drop(lde);
    drop(trace);

    // ── pi_hash recipe (v1) ──
    // Bind: SHA3(pubkey_x || pubkey_y || r || s || digest || fri_root_f0 || marker)
    // Marker "ECDSA-V1" identifies this proof as the v1 schema (chain
    // STARK + native final ops).  The verifier MUST also re-run native
    // ECDSA verify to attest the final 0.1 %; this is the same trust
    // contract as for the standalone native verify but with the
    // dominant in-circuit STARK on top.
    let pk_hash_pre: [u8; 32] = {
        let mut h = sha3::Sha3_256::new();
        h.update(b"ECDSA-V1-PI-PRE");
        h.update(&public_key_xy.0);
        h.update(&public_key_xy.1);
        h.update(&signature_rs.0);
        h.update(&signature_rs.1);
        h.update(digest_be);
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

    // ── Prove ──
    let t_prove = Instant::now();
    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1e3;
    println!("    [prove] {:.2}ms", prove_ms);

    // ── Verify ──
    let t_verify = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1e3;
    assert!(ok, "local STARK verify failed");
    println!("    [verify] {:.2}ms ✓", verify_ms);

    let proof_bytes_count = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let mut blob = Vec::with_capacity(proof_bytes_count);
    proof.serialize_with_mode(&mut blob, Compress::Yes)
        .expect("serialize");

    // pi_hash binding the FRI root.
    let mut h = sha3::Sha3_256::new();
    h.update(&pk_hash_pre);
    let mut root_buf = Vec::new();
    proof.root_f0.serialize_with_mode(&mut root_buf, Compress::Yes).unwrap();
    h.update(&root_buf);
    let pi_hash: [u8; 32] = h.finalize().into();

    println!("    [TOTAL] {:.2?} pi_hash={}",
        t_total.elapsed(),
        hex::encode(&pi_hash[0..8]));

    EcdsaRecordProof {
        pi_hash,
        fri_proof_bytes: proof_bytes_count,
        prove_ms,
        verify_ms,
        constraint_count: total_constraints,
        constraint_evals_total: n0 * total_constraints,
    }
}

fn main() {
    println!("=== End-to-end ECDSA-P256 RRSIG STARK proof (v1) ===");
    println!();
    println!("Soundness model:");
    println!("  In-circuit (99.9%): K=256 double scalar-mul u_1·G + u_2·Q");
    println!("  Native at prove (0.1%): final group_add, Z^-1, R.x mod n, equality");
    println!();

    // Use the RFC 6979 §A.2.5 P-256 + SHA-256 sample vector.
    // Public key Q on the curve, signature (r, s) over digest of "sample".
    let qx: [u8; 32] = [
        0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,
        0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
        0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
        0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
    ];
    let qy: [u8; 32] = [
        0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,
        0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
        0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
        0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99,
    ];
    let digest: [u8; 32] = [
        0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1,
        0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
        0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
        0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF,
    ];
    let r: [u8; 32] = [
        0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD,
        0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
        0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
        0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
    ];
    let s: [u8; 32] = [
        0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41,
        0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
        0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
        0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8,
    ];

    println!("─── Proving RFC 6979 §A.2.5 P-256+SHA-256 'sample' ───");
    let result = prove_ecdsa_record_v1(&(qx, qy), &(r, s), &digest);
    println!();
    println!("=== Result ===");
    println!("  pi_hash:         {}", hex::encode(&result.pi_hash));
    println!("  FRI proof:       {} bytes", result.fri_proof_bytes);
    println!("  prove time:      {:.2} s", result.prove_ms / 1000.0);
    println!("  verify time:     {:.2} ms", result.verify_ms);
    println!("  constraints:     {}", result.constraint_count);
    println!("  total cons evals:{}", result.constraint_evals_total);
}
