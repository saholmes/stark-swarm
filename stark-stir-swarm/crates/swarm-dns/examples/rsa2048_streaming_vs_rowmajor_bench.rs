//! RSA-2048 merge head-to-head: streaming vs row-major.
//!
//! Validates that the chunked streaming variant produces a bit-exact
//! `c_eval` and measures the wall-time delta against the one-time
//! row-major transpose variant.  At RSA's trace shape
//! ($n_0 = 1{,}024$, $w \approx 11$k, LDE buf ${\sim}90$~MiB) the
//! buffer fits in M4 unified memory and is sequentially accessed,
//! so row-major is expected to win --- this bench quantifies it.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example rsa2048_streaming_vs_rowmajor_bench

use std::time::Instant;

use ark_ff::Zero;
use ark_goldilocks::Goldilocks as F;
use num_bigint::BigUint;
use rand::SeedableRng;
use rsa::{
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

use deep_ali::{
    deep_ali_merge_rsa_exp_multirow,
    deep_ali_merge_rsa_exp_multirow_streaming,
    fri::FriDomain,
    rsa2048::emsa_pkcs1_v1_5_encode_sha256,
    rsa2048_exp_air::{
        build_rsa_exp_multirow_layout, fill_rsa_exp_multirow,
        rsa_exp_multirow_constraints,
    },
    trace_import::lde_trace_columns,
};
use sha2::Digest as ShaDigest;

const BLOWUP: usize = 32;

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

fn main() {
    println!("=== RSA-2048 streaming-vs-row-major merge bench ===");
    println!();

    // Generate a real keypair + signature.
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE_BABE);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048)
        .expect("RSA-2048 keygen failed");
    let pub_key = RsaPublicKey::from(&priv_key);
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let message = b"DNSSEC RRSIG payload for streaming-vs-row-major bench";
    let signature = signing_key.sign(message);
    let sig_bytes = signature.to_bytes();

    let n_be = pub_key.n().to_bytes_be();
    let n_big = BigUint::from_bytes_be(&n_be);
    let s_big = BigUint::from_bytes_be(&sig_bytes);

    // Compute em (verifier-side).
    let mut digest = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(message);
    digest.copy_from_slice(&hasher.finalize());
    let em_bytes = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();
    let em_big = BigUint::from_bytes_be(&em_bytes);

    // Build the trace.
    const N_TRACE: usize = 32;
    let n0 = N_TRACE * BLOWUP;
    let (layout, total_cells) = build_rsa_exp_multirow_layout(0);
    let cons_per_row = rsa_exp_multirow_constraints(&layout);

    println!("Layout:");
    println!("  Cells per row:        {}", total_cells);
    println!("  Constraints per row:  {}", cons_per_row);
    println!("  n_trace:              {}", N_TRACE);
    println!("  n_0 (LDE rows):       {}", n0);
    println!("  Row-major LDE buf:    {} MiB",
        total_cells * n0 * 8 / 1_048_576);
    println!();

    let mut trace: Vec<Vec<F>> = (0..total_cells)
        .map(|_| vec![F::zero(); N_TRACE])
        .collect();
    fill_rsa_exp_multirow(&mut trace, &layout, N_TRACE, &n_big, &s_big, &em_big);

    let domain = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).expect("LDE failed");
    let coeffs = comb_coeffs(cons_per_row);

    // Warm-up + 5-iteration head-to-head.
    println!("Running 5 iterations of each variant on the same LDE...");
    println!();

    let n_iter = 5;

    // Streaming.
    let mut stream_total_ms = 0.0;
    let mut c_stream = Vec::new();
    for i in 0..n_iter {
        let t = Instant::now();
        let (c, _) = deep_ali_merge_rsa_exp_multirow_streaming(
            &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
        );
        let dt = t.elapsed().as_secs_f64() * 1000.0;
        stream_total_ms += dt;
        if i == 0 {
            c_stream = c;
        }
    }
    let stream_avg = stream_total_ms / n_iter as f64;

    // Row-major.
    let mut rm_total_ms = 0.0;
    let mut c_rm = Vec::new();
    for i in 0..n_iter {
        let t = Instant::now();
        let (c, _) = deep_ali_merge_rsa_exp_multirow(
            &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
        );
        let dt = t.elapsed().as_secs_f64() * 1000.0;
        rm_total_ms += dt;
        if i == 0 {
            c_rm = c;
        }
    }
    let rm_avg = rm_total_ms / n_iter as f64;

    // Validate bit-exact.
    assert_eq!(c_stream.len(), c_rm.len());
    let mut diffs = 0usize;
    for (a, b) in c_stream.iter().zip(c_rm.iter()) {
        if a != b {
            diffs += 1;
        }
    }

    println!("Results (avg of {} iterations):", n_iter);
    println!("  Streaming merge   : {:>8.2} ms", stream_avg);
    println!("  Row-major merge   : {:>8.2} ms", rm_avg);
    println!("  Speed-up (rm/str) : {:>8.2}×", rm_avg / stream_avg);
    println!("  Speed-up (str/rm) : {:>8.2}×", stream_avg / rm_avg);
    println!("  c_eval diff       : {}/{} cells {}",
        diffs, c_stream.len(),
        if diffs == 0 { "✓ bit-identical" } else { "✗ MISMATCH" });
    println!();
    println!("Conclusion:");
    if rm_avg < stream_avg {
        println!("  Row-major wins at this trace shape ({:.2}× faster).",
            stream_avg / rm_avg);
        println!("  RSA-2048's LDE buffer is small enough that the M4");
        println!("  prefetcher handles row-major access efficiently;");
        println!("  the streaming variant's chunking overhead is a net loss.");
        println!("  This mirrors the Ed25519 K≤64 regime.");
    } else {
        println!("  Streaming wins at this trace shape ({:.2}× faster).",
            rm_avg / stream_avg);
    }
}
