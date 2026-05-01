//! NSEC3 chain-completeness benchmark.
//!
//! Demonstrates that a STARK over the NSEC3 chain establishes the GLOBAL
//! completeness property (no gaps in namespace coverage) — something a
//! bare Merkle commitment over the same NSEC3 records cannot do.
//!
//! Compares three regimes for a chain of N records:
//!
//!   1. Plain Merkle commitment (baseline) — what most DNSSEC zones
//!      effectively expose today.  Proves: each record is in the set.
//!      Does NOT prove: the chain is closed / covers the namespace.
//!
//!   2. STARK with the Nsec3Chain AIR (this work, STIR mode).
//!      Proves: 1 + global cyclic-chain closure.
//!
//!   3. STARK with the Nsec3Chain AIR (FRI arity-2 mode).
//!      For comparison; same property, different LDT.
//!
//! For each regime we print prove time, verify time, and proof size,
//! across record counts N ∈ {256, 1024, 4096, 16384}.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example nsec3_completeness_bench

use std::time::Instant;

use sha3::Digest;
use swarm_dns::dns::merkle_build;
use swarm_dns::prover::{prove_nsec3_completeness, LdtMode, Nsec3Record};

const SALT: [u8; 16] = *b"swarm-test-zone1";
const FS_BINDING: [u8; 32] = [0xCA; 32]; // arbitrary fixed FS binding for the bench

fn make_chain(n: usize) -> Vec<Nsec3Record> {
    // Generate n distinct synthetic owner hashes, then build a sorted
    // closed cyclic chain on them.
    let mut owners: Vec<[u8; 32]> = (0..n as u64).map(|i| {
        let mut h = sha3::Sha3_256::new();
        Digest::update(&mut h, b"NSEC3-DEMO-OWNER");
        Digest::update(&mut h, &i.to_le_bytes());
        Digest::finalize(h).into()
    }).collect();
    owners.sort();
    let mut chain = Vec::with_capacity(n);
    for i in 0..n {
        chain.push(Nsec3Record {
            owner_hash: owners[i],
            next_hash:  owners[(i + 1) % n],
        });
    }
    chain
}

fn merkle_baseline(records: &[Nsec3Record]) -> (f64, usize, [u8; 32]) {
    // "Bare Merkle" baseline: hash each (owner, next) pair, build a
    // Merkle tree, return the root.  This is what most DNSSEC zones do
    // implicitly when they sign each NSEC3 record but do not prove the
    // global chain closure.
    let t = Instant::now();
    let leaves: Vec<[u8; 32]> = records.iter().map(|r| {
        let mut h = sha3::Sha3_256::new();
        Digest::update(&mut h, b"NSEC3-LEAF");
        Digest::update(&mut h, &r.owner_hash);
        Digest::update(&mut h, &r.next_hash);
        Digest::finalize(h).into()
    }).collect();
    let levels = merkle_build(&leaves);
    let elapsed_ms = t.elapsed().as_secs_f64() * 1e3;
    let root = levels.last().and_then(|lvl| lvl.first()).copied().unwrap_or([0u8; 32]);
    // Merkle "proof" size: log2(n) hashes per record (a single inclusion
    // path).  This is per-query, not per-zone, but we report log2(n)
    // for parity with the STARK's amortised-per-zone numbers.
    let log2n = (records.len() as f64).log2().ceil() as usize;
    let path_bytes = log2n * 32;
    (elapsed_ms, path_bytes, root)
}

fn run_one(n: usize, ldt: LdtMode, label: &str) -> (f64, f64, usize, [u8; 32]) {
    let chain = make_chain(n);
    let t = Instant::now();
    let out = prove_nsec3_completeness(&chain, &SALT, &FS_BINDING, ldt);
    let total_ms = t.elapsed().as_secs_f64() * 1e3;
    println!("    {label:>14}  prove_ms={:>7.1}  total_ms={:>7.1}  verify_ms={:>5.2}  proof_bytes={:>7}",
        out.prove_ms, total_ms, out.local_verify_ms, out.proof_bytes);
    (out.prove_ms, out.local_verify_ms, out.proof_bytes, out.pi_hash)
}

fn main() {
    println!("\n┌─ NSEC3 chain-completeness — STARK vs. Merkle baseline ─");
    println!("│  AIR    : Nsec3Chain  (w=8, 4 chain-link transition constraints)");
    println!("│  field  : Goldilocks  Fp²·³·² (sextic ext)");
    println!("│  blowup : 32          NIST L1 calibration");
    println!("│  proves : closed cyclic chain ⇒ global namespace coverage");
    println!("└─────────────────────────────────────────────────────────\n");

    println!("┌─ Per-N comparison (record counts powers of 2) ──────────────────────────────────────");
    println!("│   N    │  Merkle base (build-ms / path-bytes)  │  STARK STIR (prove / verify / proof) │  STARK FRI (prove / verify / proof)");
    println!("├────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────");

    for &n in &[256usize, 1024, 4096, 16_384] {
        let chain = make_chain(n);
        let (m_build_ms, m_path_b, _root) = merkle_baseline(&chain);
        println!("│ {n:>5}  │   build={:>5.1} ms  path={:>4} B            │", m_build_ms, m_path_b);
        run_one(n, LdtMode::Stir, "STARK STIR");
        run_one(n, LdtMode::Fri,  "STARK FRI");
        println!("│        │                                      │");
    }
    println!("└──────────────────────────────────────────────────────────────────────────────────────");

    // ─── What does the proof actually establish? ────────────────────────────
    println!("\n┌─ Property comparison ─────────────────────────────────────────────────");
    println!("│ Property                                          │ Merkle  │ STARK ");
    println!("├───────────────────────────────────────────────────┼─────────┼───────");
    println!("│ Each NSEC3 record was committed to                │   ✓     │  ✓");
    println!("│ Membership proofs are short                       │   ✓     │  ✓");
    println!("│ Chain is sorted on owner-hash                     │   ✗     │  ✓");
    println!("│ Chain is closed (next[n-1] = owner[0])            │   ✗     │  ✓");
    println!("│ NO GAPS in namespace coverage                     │   ✗     │  ✓ (THIS WORK)");
    println!("│ Negative-existence verifiable in O(1) per query   │   ✗     │  ✓");
    println!("│ Cannot censor by omitting a record                │   ✗     │  ✓");
    println!("└───────────────────────────────────────────────────────────────────────");

    println!("\n  The STARK proves that the chain is a permutation cover of the");
    println!("  hash space.  A bare Merkle tree commits to whatever records the");
    println!("  authority chose to include; it has no mechanism to check that");
    println!("  the union of intervals tiles the namespace.  A cheating zone");
    println!("  authority can publish a Merkle-committed NSEC3 set with a gap,");
    println!("  using the gap to deny existence of a name that actually exists.");
    println!("  The STARK closes that attack — completeness is enforced by the");
    println!("  4 inter-row constraints on the trace.\n");
}
