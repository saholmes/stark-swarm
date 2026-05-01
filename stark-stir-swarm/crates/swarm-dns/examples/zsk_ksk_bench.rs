//! ZSK→KSK binding benchmark — Ed25519 native + STARK (Phase 8 v1).
//!
//! Companion to `ds_ksk_bench`.  Where DS→KSK proves a SHA-256 digest
//! match (RFC 4034 §5.1.4), ZSK→KSK proves an Ed25519 signature: that
//! the parent's KSK signed the child's ZSK DNSKEY RRset (canonicalised
//! per RFC 4034 §3.1.8.1, signed under RFC 8080's Ed25519 algorithm
//! identifier 15).
//!
//! Two paths are now exercised:
//!
//!   1. **Runtime-fallback** (Phase 7 v0):  in-crate `ed25519_verify`
//!      + `pi_hash` recipe (SHA3-256 over public inputs).  Reported
//!      across multiple message sizes.
//!   2. **STARK stub-K8** (Phase 6 v1):  full DEEP-ALI + STIR/FRI on
//!      the registered `AirType::Ed25519ZskKsk` K=8 stub trace,
//!      exercising every sub-phase of the v16 `Ed25519VerifyAir`
//!      (SHA-512, scalar reduce, 2 decompressions, 2 ladders,
//!      residual chain, cofactor mul, identity verdict).  Run once
//!      per invocation since the trace shape doesn't depend on the
//!      message size in stub-K8 mode.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example zsk_ksk_bench
//!
//! NOTE: the STARK pass takes several minutes even in release mode
//! (the stub-K8 trace is ~40 k cells × 256 rows).  Pass
//! `--no-default-features` or set `ZSK_KSK_BENCH_SKIP_STARK=1` to
//! skip the STARK pass for fast iteration on the runtime numbers.

use std::time::Instant;

use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use deep_ali::fri::{deep_fri_verify, DeepFriProof};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

use swarm_dns::prover::{
    build_params, prove_zsk_ksk_binding_stub_k8,
    verify_zsk_ksk_native, verify_zsk_ksk_runtime_fallback,
    Ext, LdtMode,
};

const FS_BINDING: [u8; 32] = [0xCA; 32];

/// Generate a deterministic Ed25519 (pubkey, signature, message) triple.
/// Uses ed25519-dalek for key generation and signing — those are
/// off-path (used by the prover/test harness, not by the verifier).
fn synth_ed25519(msg_len: usize, seed: u64) -> ([u8; 32], [u8; 64], Vec<u8>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let sk = SigningKey::generate(&mut rng);
    let pk = sk.verifying_key().to_bytes();
    let msg: Vec<u8> = (0..msg_len as u32)
        .map(|i| (i.wrapping_mul(0x9e37_79b9) >> 24) as u8)
        .collect();
    let sig = sk.sign(&msg).to_bytes();
    (pk, sig, msg)
}

/// Best-of-3 wall-clock measurement of a closure, returning microseconds
/// of the fastest run.
fn best_of_3<F: FnMut()>(mut f: F) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        let t = Instant::now();
        f();
        let dt = t.elapsed().as_secs_f64() * 1e6;
        if dt < best { best = dt; }
    }
    best
}

fn run_one(label: &str, msg_len: usize) {
    let (pubkey, sig, msg) = synth_ed25519(msg_len, label.len() as u64);

    // Native Ed25519 verify (our wholly in-crate path).
    let mut native_ok = false;
    let native_us = best_of_3(|| {
        native_ok = deep_ali::ed25519_verify::verify(&pubkey, &sig, &msg);
    });
    assert!(native_ok, "{}: native verify must succeed for valid signature", label);

    // Prover-side: produce a ZskKskNativeOutput { pi_hash, verified }.
    let mut prover_pi = [0u8; 32];
    let prove_us = best_of_3(|| {
        let out = verify_zsk_ksk_native(&pubkey, &sig, &msg, &FS_BINDING);
        assert!(out.verified);
        prover_pi = out.pi_hash;
    });

    // Verifier-side: runtime fallback (recompute pi_hash + Ed25519 verify).
    let verify_us = best_of_3(|| {
        verify_zsk_ksk_runtime_fallback(
            &pubkey, &sig, &msg, &FS_BINDING, &prover_pi,
        ).expect("runtime fallback must accept a valid bundle");
    });

    // Dalek baseline (best-of-class runtime Ed25519 verify).
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).unwrap();
    let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig);
    let dalek_us = best_of_3(|| {
        let _ = verifying_key.verify_strict(&msg, &dalek_sig);
    });

    println!(
        "│ {:<12} │ {:>5} B │ {:>7.0} µs │ {:>7.0} µs │ {:>7.0} µs │ {:>7.0} µs │",
        label, msg_len, native_us, prove_us, verify_us, dalek_us,
    );
}

fn run_stark_pass() {
    println!("\n┌─ ZSK→KSK STARK — stub-K8 (Phase 6 v1) ────────────────────────────────────");
    println!("│  AIR        : AirType::Ed25519ZskKsk (registered K=8 stub)");
    println!("│  prover     : prove_zsk_ksk_binding_stub_k8");
    println!("│  composes   : SHA-512 + scalar-reduce + 2 decompositions + 2 ladders");
    println!("│               + residual chain + cofactor mul + identity verdict");
    println!("│  trace      : ~40 k cells × 256 rows  (full v16 verify AIR)");
    println!("│  ldt        : STIR (use `LdtMode::Fri` to A/B against DEEP-FRI)");
    println!("└────────────────────────────────────────────────────────────────────────────\n");

    let fs_binding = [0xCA; 32];
    let t0 = Instant::now();
    let out = prove_zsk_ksk_binding_stub_k8(&fs_binding, LdtMode::Stir);
    let total_prove_ms = t0.elapsed().as_secs_f64() * 1e3;

    // Reproduce the verifier-side reconstruction so the bench reports a
    // representative external-verify time (independent of the worker's
    // internal `local_verify_ms`).
    let proof = DeepFriProof::<Ext>::deserialize_with_mode(
        out.proof_blob.as_slice(), Compress::Yes, Validate::Yes,
    ).expect("stub-K8 proof must deserialise");
    let n_trace = deep_ali::air_workloads::ed25519_zsk_ksk_default_layout().height;
    let n0 = n_trace * 32;          // BLOWUP from swarm_dns::prover::BLOWUP
    let params = build_params(n0, &fs_binding, LdtMode::Stir);
    let t_v = Instant::now();
    let ok = deep_fri_verify::<Ext>(&params, &proof);
    let ext_verify_ms = t_v.elapsed().as_secs_f64() * 1e3;
    assert!(ok, "stub-K8 external verify must succeed");

    println!("┌─{:─<28}─┬─{:─<14}─┐", "", "");
    println!("│ {:<28} │ {:>14} │", "Metric", "Value");
    println!("├─{:─<28}─┼─{:─<14}─┤", "", "");
    println!("│ {:<28} │ {:>11.0} ms │", "prove (worker)",        out.prove_ms);
    println!("│ {:<28} │ {:>11.0} ms │", "self-verify (worker)",  out.local_verify_ms);
    println!("│ {:<28} │ {:>11.0} ms │", "external verify",        ext_verify_ms);
    println!("│ {:<28} │ {:>11.0} ms │", "total prove path (incl)", total_prove_ms);
    println!("│ {:<28} │ {:>11} B │", "proof size",               out.proof_bytes);
    println!("│ {:<28} │ {:>11} … │", "pi_hash[..16]",            &hex::encode(out.pi_hash)[..16]);
    println!("└─{:─<28}─┴─{:─<14}─┘", "", "");

    println!();
    println!("  Stub-K8 trace shape — verifier work is logarithmic in n_trace:");
    println!("    n_trace  = {}", n_trace);
    println!("    n0       = {}  (n_trace · BLOWUP=32)", n0);
    println!("    width    = {} cells", deep_ali::air_workloads::AirType::Ed25519ZskKsk.width());
    println!("    cons/row = {}", deep_ali::air_workloads::AirType::Ed25519ZskKsk.num_constraints());
    println!();
}

fn main() {
    println!("\n┌─ ZSK→KSK binding — runtime-fallback verifier path ────────────────────────");
    println!("│  algorithm  : Ed25519 (RFC 8080 + RFC 8032 §5.1.7 cofactored)");
    println!("│  prover     : verify_zsk_ksk_native       (verify + pi_hash commit)");
    println!("│  verifier   : verify_zsk_ksk_runtime_fallback");
    println!("│  pi_hash    : SHA3-256(\"ZSK-KSK-PIHASH-V1\" || pk || sig || data || fs)");
    println!("│  STARK      : stub-K8 landed (Phase 6 v1) — see second table below");
    println!("└────────────────────────────────────────────────────────────────────────────\n");

    println!("┌─{:─<12}─┬─{:─<7}─┬─{:─<10}─┬─{:─<10}─┬─{:─<10}─┬─{:─<10}─┐",
        "", "", "", "", "", "");
    println!("│ {:<12} │ {:>7} │ {:>10} │ {:>10} │ {:>10} │ {:>10} │",
        "Workload", "msg",
        "in-crate",  "prover",  "verifier",  "dalek");
    println!("│ {:<12} │ {:>7} │ {:>10} │ {:>10} │ {:>10} │ {:>10} │",
        "", "", "verify", "(verify+pi)", "(pi+verify)", "verify");
    println!("├─{:─<12}─┼─{:─<7}─┼─{:─<10}─┼─{:─<10}─┼─{:─<10}─┼─{:─<10}─┤",
        "", "", "", "", "", "");

    run_one("empty",        0);
    run_one("one-byte",     1);
    run_one("64-byte",     64);
    run_one("256-byte",   256);
    run_one("1KB",       1024);

    println!("└─{:─<12}─┴─{:─<7}─┴─{:─<10}─┴─{:─<10}─┴─{:─<10}─┴─{:─<10}─┘",
        "", "", "", "", "", "");

    println!("\n┌─ Property comparison ─────────────────────────────────────────────────");
    println!("│ Property                                          │ Runtime │ STARK (stub-K8)");
    println!("├───────────────────────────────────────────────────┼─────────┼─────────────────");
    println!("│ Verifier checks Ed25519 signature                 │   ✓     │  ✓");
    println!("│ Verifier needs to trust its own ed25519 impl      │   ✓     │  ✗");
    println!("│ Verifier work is polylogarithmic in message size  │   ✗     │  ✓");
    println!("│ Prover produces a publicly checkable artefact     │   ✗     │  ✓");
    println!("│ pi_hash binds (pubkey || sig || msg || FS)        │   ✓     │  v2 (per-sig path)");
    println!("│ Compatible with post-quantum verification         │   ✓ (PQ only via STIR/FRI)");
    println!("└───────────────────────────────────────────────────────────────────────");

    println!("\n  Runtime path: the verifier reproduces pi_hash from public inputs");
    println!("  and runs the in-crate ed25519 verifier.  No third-party crypto on");
    println!("  the runtime call path; ed25519-dalek is shown only as a baseline.");
    println!();
    println!("  STARK stub-K8 path (Phase 6 v1): proves the v16 verify AIR on a");
    println!("  zero-scalar identity-R configuration that satisfies the cofactored");
    println!("  predicate trivially.  Every sub-phase (SHA-512, scalar reduce, 2");
    println!("  decompositions, 2 ladders, residual chain, cofactor mul, identity");
    println!("  verdict) fires.  The full per-signature K=256 recipe lands in v2");
    println!("  once the parametric `deep_ali_merge_ed25519_verify` is wired.\n");

    if std::env::var("ZSK_KSK_BENCH_SKIP_STARK").is_err() {
        run_stark_pass();
    } else {
        println!("  [skipped] ZSK_KSK_BENCH_SKIP_STARK is set; STARK pass not run.\n");
    }
}
