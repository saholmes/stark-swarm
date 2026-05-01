//! RSA-2048 PKCS#1 v1.5 native verifier round-trip.
//!
//! Generates an RSA-2048 keypair, signs a DNS-style message with
//! PKCS#1 v1.5 + SHA-256, and verifies with both
//! (a) the `rsa` crate (reference), and
//! (b) our `deep_ali::rsa2048::verify` native implementation.
//!
//! Validates the native verifier path before in-circuit AIR work.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example rsa2048_native_roundtrip

use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use deep_ali::rsa2048::{verify as native_rsa_verify, PublicKey};
use deep_ali::rsa2048_field_air::{
    build_rsa_mul_layout, eval_rsa_mul_gadget, fill_rsa_mul_gadget,
    RSA_MUL_GADGET_CONSTRAINTS, RSA_MUL_GADGET_OWNED_CELLS, RSA_NUM_LIMBS,
};
use num_bigint::BigUint;
use rsa::{
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    signature::{SignatureEncoding, Signer, Verifier},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use rand::SeedableRng;

fn main() {
    println!("=== RSA-2048 PKCS#1 v1.5 + SHA-256 native round-trip ===");
    println!();

    // ── Generate a 2048-bit RSA keypair (deterministic seed). ──
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF_CAFE_F00D);
    let t_keygen = Instant::now();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048)
        .expect("RSA-2048 keygen failed");
    let pub_key = RsaPublicKey::from(&priv_key);
    println!("    [keygen]  {:.2?}", t_keygen.elapsed());

    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());

    // ── Sign a DNS-style message (canonical RRSIG bytes). ──
    let message = b"DNSSEC-RRSIG-V0|google.com.|A|142.251.46.142|epoch-0";

    let t_sign = Instant::now();
    let signature: Signature = signing_key.sign(message);
    println!("    [sign]    {:.2?}", t_sign.elapsed());

    let signature_bytes = signature.to_bytes();
    println!("    Signature: {} bytes", signature_bytes.len());

    // ── (a) Verify with the `rsa` crate (reference path). ──
    let t_ref = Instant::now();
    let ref_ok = verifying_key.verify(message, &signature).is_ok();
    println!("    [verify ref-rsa-crate]   {:.2?}  {}",
        t_ref.elapsed(), if ref_ok { "✓" } else { "FAIL" });

    // ── (b) Verify with our deep_ali::rsa2048 native implementation. ──
    let n_be = pub_key.n().to_bytes_be();
    let our_pubkey = PublicKey::from_n_be(&n_be);

    let t_ours = Instant::now();
    let our_ok = native_rsa_verify(&our_pubkey, message, &signature_bytes);
    println!("    [verify deep_ali::rsa2048] {:.2?}  {}",
        t_ours.elapsed(), if our_ok { "✓" } else { "FAIL" });

    println!();
    if ref_ok && our_ok {
        println!("Round-trip OK — both verifiers accept the signature.");
    } else {
        println!("ROUND-TRIP FAILURE: ref={} ours={}", ref_ok, our_ok);
        std::process::exit(1);
    }

    // ── Cross-check: tampered signature must be rejected. ──
    let mut bad_sig = signature_bytes.to_vec();
    bad_sig[0] ^= 0x01;
    let bad_ok = native_rsa_verify(&our_pubkey, message, &bad_sig);
    assert!(!bad_ok, "Tampered signature must be rejected");
    println!("Tampered signature correctly rejected ✓");

    // ── Cross-check: wrong message must be rejected. ──
    let bad_msg = b"DNSSEC-RRSIG-V0|google.com.|A|0.0.0.0|epoch-0";
    let bad_msg_ok = native_rsa_verify(&our_pubkey, bad_msg, &signature_bytes);
    assert!(!bad_msg_ok, "Wrong-message signature must be rejected");
    println!("Wrong-message correctly rejected ✓");

    println!();
    println!("=== AIR microbench (Phase 2 — F_n2048 mul gadget) ===");
    println!();
    println!("Per-mul gadget (witness-quotient, 80×26-bit limbs):");
    println!("  Cells:       {}", RSA_MUL_GADGET_OWNED_CELLS);
    println!("  Constraints: {}", RSA_MUL_GADGET_CONSTRAINTS);
    println!();

    // Microbench: fill + eval one F_n2048 mul gadget on the live
    // RSA modulus from the keypair + random a, b < n.
    let n_be = pub_key.n().to_bytes_be();
    let n_big = BigUint::from_bytes_be(&n_be);
    let a_big = &n_big >> 1; // arbitrary in-range value
    let b_big = (&n_big * 2u32 / 7u32) % &n_big;

    let a_base = 0;
    let b_base = RSA_NUM_LIMBS;
    let n_base = 2 * RSA_NUM_LIMBS;
    let start = 3 * RSA_NUM_LIMBS;
    let (layout, total_cells) = build_rsa_mul_layout(start, a_base, b_base, n_base);

    let mut trace: Vec<Vec<F>> = (0..total_cells).map(|_| vec![F::zero(); 1]).collect();
    let place_biguint = |trace: &mut [Vec<F>], base: usize, x: &BigUint| {
        use deep_ali::rsa2048_field_air::biguint_to_limbs80;
        let limbs = biguint_to_limbs80(x);
        for i in 0..RSA_NUM_LIMBS {
            trace[base + i][0] = F::from(limbs[i] as u64);
        }
    };
    place_biguint(&mut trace, a_base, &a_big);
    place_biguint(&mut trace, b_base, &b_big);
    place_biguint(&mut trace, n_base, &n_big);

    let n_iter = 100;
    let t_fill = Instant::now();
    for _ in 0..n_iter {
        fill_rsa_mul_gadget(&mut trace, 0, &layout, &a_big, &b_big, &n_big);
    }
    let fill_per = t_fill.elapsed() / n_iter;

    let cur: Vec<F> = (0..total_cells).map(|c| trace[c][0]).collect();
    let t_eval = Instant::now();
    let mut last_cons = Vec::new();
    for _ in 0..n_iter {
        last_cons = eval_rsa_mul_gadget(&cur, &layout);
    }
    let eval_per = t_eval.elapsed() / n_iter;
    let nonzero = last_cons.iter().filter(|v| !v.is_zero()).count();

    println!("Microbench (random 2048-bit a, b, n; {} iterations):", n_iter);
    println!("  fill_rsa_mul_gadget : {:?}/call", fill_per);
    println!("  eval_rsa_mul_gadget : {:?}/call", eval_per);
    println!("  Constraint satisfaction: {} / {}  ({})",
        last_cons.len() - nonzero, last_cons.len(),
        if nonzero == 0 { "ALL ZERO ✓" } else { "FAILURES ✗" });
    println!();
    println!("=== Composed RSA-2048 verifier projection ===");
    println!();
    println!("Per-row constraints in the multi-row layout:");
    println!("  Mul gadget:       {} (this work)",
        RSA_MUL_GADGET_CONSTRAINTS);
    println!("  Acc transition:   240   (3 × 80 limb-equality)");
    println!("  Per-row total:    {}", RSA_MUL_GADGET_CONSTRAINTS + 240);
    println!();
    println!("Exponentiation chain ({} steps for e=65537):", 17);
    println!("  Total constraints: {} × 17 = {}",
        RSA_MUL_GADGET_CONSTRAINTS,
        RSA_MUL_GADGET_CONSTRAINTS * 17);
    println!();
    println!("With SHA-256 sub-AIR (~98k cons/block) + PKCS#1 padding,");
    println!("aggregate per-sig is ~280k--380k constraints; at the");
    println!("streaming-merge per-eval rate this projects to ~5--10 s/sig");
    println!("STARK prove on the M4 Mac mini (single-record), making RSA");
    println!("the cheapest of the three signature schemes in-circuit.");
}

