//! DS→KSK binding benchmark (STARK vs. runtime SHA-256).
//!
//! The DNSSEC chain of trust hinges on the parent zone's DS record
//! committing to the child zone's KSK via SHA-256 (RFC 4034 §5.1.4,
//! digest-algorithm 2).  A swarm-prover can either (a) forward the
//! DNSKEY and DS bytes to the verifier and trust the verifier's
//! `sha2` implementation, or (b) prove `SHA-256(dnskey_bytes) ==
//! parent_ds_hash` inside a STARK so the verifier checks a STIR
//! proof in polylogarithmic time.
//!
//! This bench measures option (b) for the three dominant DNSSEC
//! algorithms by RDATA size:
//!
//!   * Ed25519        — 44 bytes  → 1 SHA-256 block
//!   * ECDSA-P256     — 68 bytes  → 2 blocks
//!   * RSA-2048       — ~268 bytes → 5 blocks
//!
//! For each, we report:
//!   * runtime SHA-256 baseline (microseconds)
//!   * STARK prove time, verify time, proof size (STIR mode)
//!
//! Run:
//!     cargo run --release -p swarm-dns --example ds_ksk_bench

use std::time::Instant;

use sha2::{Digest, Sha256};
use swarm_dns::prover::{prove_ds_ksk_binding, LdtMode};

const FS_BINDING: [u8; 32] = [0xCA; 32];

fn synthetic_dnskey(len: usize) -> Vec<u8> {
    // Pseudo-RDATA: deterministic byte pattern, just to size the
    // SHA-256 input correctly.  The semantic content of DNSKEY RDATA
    // (flags, protocol, algo, public-key bytes) doesn't affect the
    // SHA-256 input length, only its bytes — so for measurement
    // purposes any 1-1 mapping from len → bytes works.
    (0..len as u32).map(|i| (i.wrapping_mul(0x9e37_79b9) >> 24) as u8).collect()
}

fn sha256_runtime(msg: &[u8]) -> (f64, [u8; 32]) {
    // Best-of-3 to minimise OS scheduler jitter on the µs-scale.
    let mut best = f64::INFINITY;
    let mut digest = [0u8; 32];
    for _ in 0..3 {
        let t = Instant::now();
        let mut h = Sha256::new();
        Digest::update(&mut h, msg);
        let d: [u8; 32] = Digest::finalize(h).into();
        let dt = t.elapsed().as_secs_f64() * 1e6;  // µs
        if dt < best { best = dt; digest = d; }
    }
    (best, digest)
}

fn run_one(label: &str, dnskey_len: usize) {
    let dnskey = synthetic_dnskey(dnskey_len);
    let (rt_us, parent_ds_hash) = sha256_runtime(&dnskey);

    let t = Instant::now();
    let out = prove_ds_ksk_binding(&dnskey, &parent_ds_hash, &FS_BINDING, LdtMode::Stir);
    let total_ms = t.elapsed().as_secs_f64() * 1e3;

    assert_eq!(out.asserted_digest, parent_ds_hash,
        "STARK-asserted digest must equal sha2 reference");

    println!(
        "│ {:<15} │ {:>5} B │ {:>2} blk │ {:>9.1} µs │ {:>6.0} ms │ {:>6.0} ms │ {:>5.2} ms │ {:>7} B │",
        label, dnskey_len, out.n_blocks,
        rt_us, out.prove_ms, total_ms, out.local_verify_ms, out.proof_bytes,
    );
}

fn main() {
    println!("\n┌─ DS→KSK binding — STARK vs. runtime SHA-256 ───────────────────────────────");
    println!("│  AIR    : Sha256DsKsk  (w=756, 766 transition constraints, deg ≤ 2)");
    println!("│  field  : Goldilocks  Fp²·³·² (sextic ext)");
    println!("│  blowup : 32          NIST L1 calibration");
    println!("│  proves : SHA-256(DNSKEY) = parent_ds_hash  (RFC 4034 §5.1.4 in-circuit)");
    println!("└────────────────────────────────────────────────────────────────────────────\n");

    println!("┌─{:─<15}─┬─{:─<7}─┬─{:─<7}─┬─{:─<11}─┬─{:─<9}─┬─{:─<9}─┬─{:─<8}─┬─{:─<9}─┐",
        "", "", "", "", "", "", "", "");
    println!("│ {:<15} │ {:>7} │ {:>7} │ {:>11} │ {:>9} │ {:>9} │ {:>8} │ {:>9} │",
        "Algorithm", "RDATA", "blocks", "runtime SHA", "prove",
        "prove+vfy", "verify", "proof");
    println!("├─{:─<15}─┼─{:─<7}─┼─{:─<7}─┼─{:─<11}─┼─{:─<9}─┼─{:─<9}─┼─{:─<8}─┼─{:─<9}─┤",
        "", "", "", "", "", "", "", "");

    run_one("Ed25519",       44);
    run_one("ECDSA-P256",    68);
    run_one("RSA-2048",     268);

    println!("└─{:─<15}─┴─{:─<7}─┴─{:─<7}─┴─{:─<11}─┴─{:─<9}─┴─{:─<9}─┴─{:─<8}─┴─{:─<9}─┘",
        "", "", "", "", "", "", "", "");

    println!("\n┌─ Property comparison ─────────────────────────────────────────────────");
    println!("│ Property                                          │ Runtime │ STARK");
    println!("├───────────────────────────────────────────────────┼─────────┼───────");
    println!("│ Verifier checks SHA-256(DNSKEY) = parent_ds_hash  │   ✓     │  ✓");
    println!("│ Verifier needs to trust its own sha2 impl         │   ✓     │  ✗");
    println!("│ Verifier work is polylogarithmic in DNSKEY size   │   ✗     │  ✓");
    println!("│ Prover produces a publicly checkable artefact     │   ✗     │  ✓");
    println!("│ Compatible with post-quantum verification         │   ✓     │  ✓ (STIR/FRI)");
    println!("└───────────────────────────────────────────────────────────────────────");

    println!("\n  The STARK proves that the prover knows a SHA-256 preimage of");
    println!("  parent_ds_hash whose padded form equals dnskey_bytes (bound via");
    println!("  the public-input commitment pi_hash).  The verifier checks the");
    println!("  STIR proof + a 32-byte asserted digest equal to parent_ds_hash —");
    println!("  no SHA-256 implementation needed on the verifier's side.\n");
}
