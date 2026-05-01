//! Head-to-head bench: streaming Ed25519 merge vs row-major Ed25519 merge.
//!
//! Validates `deep_ali_merge_ed25519_verify_streaming` produces the
//! same composition as `deep_ali_merge_ed25519_verify` (bit-exact
//! `c_eval`) and measures the speed-up at production parameters.
//!
//! At full $K=256$ Ed25519, the row-major merge holds an LDE buffer
//! of size $n \cdot w \approx 32{,}768 \cdot 75{,}000 \cdot 8\,\mathrm{B}
//! \approx 19.6\,\mathrm{GiB}$ — well past L3 cache and into main
//! memory.  The streaming variant processes one trace-row chunk at a
//! time (working set $\approx 38\,\mathrm{MiB}$) and so should give a
//! significant speed-up at large $K$.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example ed25519_streaming_merge_bench

use std::time::Instant;

use ark_ff::Zero;
use ark_goldilocks::Goldilocks as F;

use deep_ali::{
    deep_ali_merge_ed25519_verify, deep_ali_merge_ed25519_verify_streaming,
    ed25519_scalar::reduce_mod_l_wide,
    ed25519_verify_air::{
        fill_verify_air_v16, r_thread_bits_for_kA, verify_air_layout_v16,
        verify_v16_per_row_constraints,
    },
    fri::FriDomain,
    sha512_air,
    trace_import::lde_trace_columns,
};

const BLOWUP: usize = 32;

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

/// Convert s scalar bytes into MSB-first ladder bits truncated to k_scalar.
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

fn run_one(k_scalar: usize) {
    println!("─── Ed25519 streaming-vs-row-major bench, K={} ───", k_scalar);
    use ed25519_dalek::{Signer, SigningKey};
    use rand::{rngs::StdRng, SeedableRng};

    // Reproducible signing key + signature.
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);
    let sk = SigningKey::generate(&mut rng);
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    let msg = b"DNS-STARK Ed25519 streaming merge benchmark message";
    let sig = sk.sign(msg);
    let sig_bytes = sig.to_bytes();
    let r_compressed: [u8; 32] = sig_bytes[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig_bytes[32..64].try_into().unwrap();

    let mut sha512_input = Vec::with_capacity(64 + msg.len());
    sha512_input.extend_from_slice(&r_compressed);
    sha512_input.extend_from_slice(&pk_bytes);
    sha512_input.extend_from_slice(msg);

    let s_bits = s_bits_for_ladder(&s_bytes, k_scalar);
    let digest = sha512_air::sha512_native(&sha512_input);
    let mut digest_arr = [0u8; 64];
    digest_arr.copy_from_slice(&digest);
    let k_canonical = reduce_mod_l_wide(&digest_arr);
    let k_bits = r_thread_bits_for_kA(&k_canonical, k_scalar);

    let layout = verify_air_layout_v16(
        sha512_input.len(), &s_bits, &k_bits, &r_compressed, &pk_bytes,
    ).expect("layout build");
    let (trace, _layout, _k) = fill_verify_air_v16(
        &sha512_input, &r_compressed, &pk_bytes, &s_bits, &k_bits,
    ).expect("trace build");

    let n_trace = layout.height;
    let n0 = n_trace * BLOWUP;
    let k_constraints = verify_v16_per_row_constraints(layout.k_scalar);
    let cells_total = layout.width * n_trace;

    println!("    Trace width:        {}", layout.width);
    println!("    Trace height:       {}", n_trace);
    println!("    LDE rows (n0):      {}", n0);
    println!(
        "    Total cells:        {} ({} MiB)",
        cells_total,
        cells_total * 8 / 1_048_576
    );
    println!("    Per-row constraints:{}", k_constraints);
    println!(
        "    Row-major LDE buf:  {} MiB ({} GiB)",
        layout.width * n0 * 8 / 1_048_576,
        layout.width * n0 * 8 / 1_073_741_824
    );

    let t_lde = Instant::now();
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP).expect("LDE failed");
    let lde_dur = t_lde.elapsed();
    println!("    [LDE]                 {:>10.2?}", lde_dur);

    let coeffs = comb_coeffs(k_constraints);
    let domain = FriDomain::new_radix2(n0);

    // Streaming merge.
    let t_stream = Instant::now();
    let (c_stream, _info_s) = deep_ali_merge_ed25519_verify_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let stream_dur = t_stream.elapsed();
    println!("    [merge streaming]     {:>10.2?}", stream_dur);

    // Row-major merge.
    let t_rm = Instant::now();
    let (c_rm, _info_r) = deep_ali_merge_ed25519_verify(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    let rm_dur = t_rm.elapsed();
    println!("    [merge row-major]     {:>10.2?}", rm_dur);

    let speedup = rm_dur.as_secs_f64() / stream_dur.as_secs_f64();
    println!("    speedup:              {:>10.2}×", speedup);

    // Bit-exact validation.
    assert_eq!(c_stream.len(), c_rm.len());
    let mut diffs = 0usize;
    for (a, b) in c_stream.iter().zip(c_rm.iter()) {
        if a != b {
            diffs += 1;
        }
    }
    println!(
        "    c_eval diff:          {}/{} cells {}",
        diffs,
        c_stream.len(),
        if diffs == 0 { "✓ identical" } else { "✗ MISMATCH" }
    );
    println!();
}

fn main() {
    println!("=== Ed25519 streaming-merge head-to-head bench ===");
    println!();
    println!("Validates streaming-merge result equals row-major (bit-exact)");
    println!("and reports speedup.  Same Apple~M4 hardware as the");
    println!("Ed25519 K=256 production measurement (30.6 min/sig).");
    println!();

    let only_k256 = std::env::var("K256_ONLY").ok().is_some();
    let ks: &[usize] = if only_k256 { &[256] } else { &[8, 32, 64, 128, 256] };
    for &k in ks {
        run_one(k);
    }

    println!("Done.");
}
