//! Standalone verifier for the STIR DNS swarm.
//!
//! Loads `<bundle-dir>/zone_bundle.json` and walks the full audit trail:
//!
//!   1. For every inner shard:
//!      a. Deserialize `<bundle-dir>/<shard.proof_path>`.
//!      b. Recompute `pi_hash = SHA3("DNS-SHARD-PIHASH-V1" ‖ salt ‖ count
//!         ‖ merkle_root ‖ proof.root_f0 ‖ pk_hash)` and compare to the
//!         bundle's claim.
//!      c. Run `deep_fri_verify` against the level-matched `DeepFriParams`.
//!      d. Verify the worker's ML-DSA attestation signature.
//!   2. For the outer rollup:
//!      a. Deserialize the outer proof.
//!      b. Confirm the trace would have packed the same `pi_hashes` (by
//!         re-running `deep_fri_verify` with the matching params + n0).
//!   3. Recompute the level-matched `zone_digest`, verify it matches the
//!      bundle, and run ML-DSA on `(authority_pk, zone_digest, sig)`.
//!
//! Exits 0 if every check passes; non-zero with diagnostic on failure.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use clap::Parser;
use deep_ali::fri::{deep_fri_verify, DeepFriProof};
use serde::Deserialize;
use sha3::Digest;

use swarm_dns::dns_authority::{level_hash, NistLevel};
use swarm_dns::prover::{
    build_params, inner_n0_from_record_count, outer_n0_from_pi_count, Ext, LdtMode,
};
use swarm_proto::messages::{ctrl_receipt_digest, shard_fs_binding, ShardReceipt};

#[derive(Parser, Debug)]
#[command(name = "swarm-verify", about = "Standalone verifier for a swarm zone bundle")]
struct Args {
    /// Directory containing `zone_bundle.json` and the `proofs/` subdirectory.
    #[arg(long)]
    bundle_dir: PathBuf,

    /// Optional: directory of worker-side `ShardReceipt`s persisted via
    /// `swarm-worker --receipts-dir`. When set, the verifier additionally
    /// cross-checks every receipt for this job_id against the bundle.
    /// Receipts whose pi_hash does not appear in the bundle are flagged
    /// as evidence of controller-side censorship or substitution (G).
    #[arg(long)]
    receipts_dir: Option<PathBuf>,

    /// Witness-controller receipt archive directory (H — distributed
    /// audit). Repeatable: pass once per witness archive collected.
    /// Format inside each: `job-<hex>/shard-<NNNN>.cbor`. The verifier
    /// requires at least `--witness-threshold` of these to have a matching
    /// receipt for every shard in the bundle.
    #[arg(long = "witness-receipts")]
    witness_receipts: Vec<PathBuf>,

    /// Minimum number of witnesses that must have a matching receipt for
    /// every shard. Defaults to all configured witnesses (M = N). Setting
    /// it lower allows degraded operation if a witness archive is partial.
    #[arg(long)]
    witness_threshold: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ZoneBundle {
    bundle_format:     u32,
    nist_level:        u8,
    ml_dsa_scheme:     String,
    signed_digest_hash: String,
    zone_salt_hex:     String,
    record_count:      usize,
    shard_count:       usize,
    shard_replication: usize,
    ldt:               String,
    authority_pk_hex:  String,
    authority_pk_hash_hex: String,
    job_id_hex:        String,
    #[serde(default)]
    dnskey_pk_hex:     Option<String>,
    #[serde(default)]
    parent_ds_hash_hex: Option<String>,
    /// DS→KSK STARK proof artefacts.  When present, the verifier
    /// checks the STARK in lieu of a runtime SHA-256(DNSKEY) hash —
    /// this is the in-circuit DSKSK-binding path of §10.4.  When
    /// absent, the verifier falls back to the runtime SHA-256 check
    /// (legacy bundles).
    #[serde(default)]
    ds_ksk_proof_path:  Option<String>,
    #[serde(default)]
    ds_ksk_pi_hash_hex: Option<String>,
    #[serde(default)]
    ds_ksk_root_f0_hex: Option<String>,
    #[serde(default)]
    ds_ksk_asserted_digest_hex: Option<String>,
    #[serde(default)]
    ds_ksk_n_blocks:    Option<usize>,
    #[serde(default)]
    ds_ksk_n_trace:     Option<usize>,

    /// ZSK→KSK binding artefacts (§10.7 — Ed25519 RFC 8080).
    ///
    /// Runtime-fallback path (Phase 7 v0): the verifier checks
    /// `pi_hash == SHA3("ZSK-KSK-PIHASH-V1" || pk || sig || data || fs)`
    /// and runs `deep_ali::ed25519_verify::verify` in-process.  When the
    /// `Ed25519VerifyAir` STARK lands (Phase 5 v1b), `zsk_ksk_proof_path`
    /// + `zsk_ksk_root_f0_hex` will become the preferred branch and the
    /// runtime fallback only fires for legacy bundles.
    ///
    /// All four runtime fields are required together (or all absent —
    /// no ZSK→KSK binding in this bundle).
    #[serde(default)]
    zsk_ksk_pubkey_hex:      Option<String>,
    #[serde(default)]
    zsk_ksk_signature_hex:   Option<String>,
    #[serde(default)]
    zsk_ksk_signed_data_hex: Option<String>,
    #[serde(default)]
    zsk_ksk_pi_hash_hex:     Option<String>,
    /// FS binding tag for the ZSK→KSK pi_hash (typically the authority
    /// pk_hash, mirroring DS→KSK).  When absent, falls back to
    /// `pk_hash32` (the same default DS→KSK uses).
    #[serde(default)]
    zsk_ksk_fs_binding_hex:  Option<String>,
    /// STARK proof artefact (Phase 7 v1).  When present, the verifier
    /// runs `deep_fri_verify` on the proof and reproduces the
    /// stub-K8 pi_hash recipe; the runtime fallback fields above are
    /// then advisory (the STARK is the primary cryptographic claim).
    #[serde(default)]
    zsk_ksk_proof_path:      Option<String>,
    /// Bundle-side `root_f0` claim — must equal the proof's commitment.
    #[serde(default)]
    zsk_ksk_root_f0_hex:     Option<String>,
    /// Trace size used by the prover (must match `n_trace` in the
    /// `DeepFriParams` reconstruction).  Power-of-two.
    #[serde(default)]
    zsk_ksk_n_trace:         Option<usize>,
    /// Stub-K8 STARK kind discriminator.  For Phase 7 v1 only the
    /// `"stub-k8"` recipe is recognised; `"v1"` (per-signature
    /// production proof) lands once the parametric merge is wired.
    #[serde(default)]
    zsk_ksk_stark_kind:      Option<String>,
    inner_pi_hashes_hex: Vec<String>,
    outer_root_f0_hex: String,
    outer_n_trace:     usize,
    outer_n0:          usize,
    outer_proof_bytes: usize,
    outer_proof_path:  String,
    zone_digest_hex:   String,
    authority_sig_hex: String,
    inner_workers:     Vec<InnerWorkerRecord>,
}

#[derive(Debug, Deserialize)]
struct InnerWorkerRecord {
    shard_id:        u32,
    shard_nonce_hex: String,
    pi_hash_hex:     String,
    merkle_root_hex: String,
    record_count:    u64,
    n_trace:         u64,
    proof_bytes_len: u64,
    proof_path:      String,
    attestations:    Vec<Attestation>,
}

#[derive(Debug, Deserialize)]
struct Attestation {
    worker_id:      u32,
    worker_pk_hex:  String,
    worker_sig_hex: String,
    prove_ms:       f64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let bundle_path = args.bundle_dir.join("zone_bundle.json");
    let json = std::fs::read_to_string(&bundle_path)
        .with_context(|| format!("read {}", bundle_path.display()))?;
    let bundle: ZoneBundle = serde_json::from_str(&json)
        .with_context(|| format!("parse {}", bundle_path.display()))?;

    println!("\n┌─ STIR DNS Swarm Verifier ───────────────────────────────────────");
    println!("│  bundle dir : {}", args.bundle_dir.display());
    println!("│  scheme     : {}  (NIST L{})", bundle.ml_dsa_scheme, bundle.nist_level);
    println!("│  digest hash: {}", bundle.signed_digest_hash);
    println!("│  zone salt  : {}", bundle.zone_salt_hex);
    println!("│  records    : {}", bundle.record_count);
    println!("│  shards     : {}", bundle.shard_count);
    println!("│  ldt        : {}", bundle.ldt);
    println!("│  format     : v{}", bundle.bundle_format);
    println!("│  replication: k = {}", bundle.shard_replication);
    println!("└──────────────────────────────────────────────────────────────────\n");

    if bundle.bundle_format != 2 {
        return Err(anyhow!(
            "unsupported bundle_format {} (this verifier expects v2)",
            bundle.bundle_format
        ));
    }

    let level = parse_level(bundle.nist_level)?;
    let ldt   = parse_ldt(&bundle.ldt)?;
    let pk_bytes  = hex::decode(&bundle.authority_pk_hex).context("decode authority_pk_hex")?;
    let pk_hash32 = decode_fixed::<32>(&bundle.authority_pk_hash_hex, "authority_pk_hash_hex")?;
    let zone_salt = decode_fixed::<16>(&bundle.zone_salt_hex, "zone_salt_hex")?;
    let job_id    = decode_fixed::<32>(&bundle.job_id_hex, "job_id_hex")?;

    // Sanity: recompute pk_hash from authority_pk and confirm it matches.
    let recomputed_pk_hash = pk_binding_hash(&pk_bytes);
    ensure(recomputed_pk_hash == pk_hash32, "authority_pk_hash does not match SHA3-256(\"DNS-AUTHORITY-PK-V1\" || pk)")?;
    println!("  ✓ authority_pk → pk_hash binding consistent");

    // ─── Phase 1: per-inner-shard verification ───────────────────────────────
    let mut sorted: Vec<&InnerWorkerRecord> = bundle.inner_workers.iter().collect();
    sorted.sort_by_key(|w| w.shard_id);
    if sorted.len() != bundle.shard_count {
        return Err(anyhow!("shard_count {} but inner_workers.len()={}",
            bundle.shard_count, sorted.len()));
    }

    let mut total_inner_verify_ms = 0.0_f64;
    let mut inner_proof_max_ms = 0.0_f64;
    let mut inner_proof_total_kb = 0usize;

    for w in &sorted {
        let pi_hash_claim = decode_fixed::<32>(&w.pi_hash_hex, "pi_hash_hex")?;
        let merkle_root   = decode_fixed::<32>(&w.merkle_root_hex, "merkle_root_hex")?;
        let shard_nonce   = decode_fixed::<32>(&w.shard_nonce_hex, "shard_nonce_hex")?;
        // Recompute the FS-binding tag the worker should have used.
        let fs_binding = shard_fs_binding(&pk_hash32, &job_id, w.shard_id, &shard_nonce);

        let proof_path = args.bundle_dir.join(&w.proof_path);
        let bytes = std::fs::read(&proof_path)
            .with_context(|| format!("read inner proof {}", proof_path.display()))?;
        if bytes.len() as u64 != w.proof_bytes_len {
            return Err(anyhow!(
                "shard {} proof size mismatch: file={} bundle={}",
                w.shard_id, bytes.len(), w.proof_bytes_len));
        }
        let proof = DeepFriProof::<Ext>::deserialize_with_mode(
            bytes.as_slice(), Compress::Yes, Validate::Yes,
        ).with_context(|| format!("deserialize inner proof {}", proof_path.display()))?;

        // Recompute pi_hash from the claimed inputs + the proof's root_f0,
        // using the FS-binding tag (NOT the raw pk_hash) — this is what
        // the worker actually committed to.
        let recomputed_pi = inner_pi_hash_recipe(
            &zone_salt, w.record_count as usize, &merkle_root, &proof.root_f0, &fs_binding,
        );
        ensure(recomputed_pi == pi_hash_claim,
            &format!("shard {} pi_hash recipe mismatch", w.shard_id))?;

        // Run deep_fri_verify against the matching params.
        let n0 = inner_n0_from_record_count(w.record_count as usize);
        if n0 != (w.n_trace as usize) * 32 /* BLOWUP */ {
            return Err(anyhow!(
                "shard {} n0 mismatch: derived={} bundle.n_trace*BLOWUP={}",
                w.shard_id, n0, (w.n_trace as usize) * 32));
        }
        let params = build_params(n0, &fs_binding, ldt);

        let t0 = std::time::Instant::now();
        let ok = deep_fri_verify::<Ext>(&params, &proof);
        let verify_ms = t0.elapsed().as_secs_f64() * 1e3;
        ensure(ok, &format!("deep_fri_verify FAILED for shard {}", w.shard_id))?;

        // Per-replica ML-DSA attestation.  All attestations sign the SAME
        // canonical digest, so we just verify each (pk, sig) pair against
        // the reconstructed digest.  Length must match the bundle's claimed
        // replication factor (or fewer if a dissenting minority got
        // blacklisted under majority-rule).
        let attest_dig = worker_attestation_digest(
            w.shard_id, &pi_hash_claim, &merkle_root, &proof.root_f0,
        );
        ensure(!w.attestations.is_empty(),
            &format!("shard {} has zero attestations", w.shard_id))?;
        ensure(w.attestations.len() <= bundle.shard_replication,
            &format!("shard {} has {} attestations (> k={})", w.shard_id, w.attestations.len(), bundle.shard_replication))?;
        for (i, a) in w.attestations.iter().enumerate() {
            let pk  = hex::decode(&a.worker_pk_hex).context("decode worker_pk_hex")?;
            let sig = hex::decode(&a.worker_sig_hex).context("decode worker_sig_hex")?;
            let sig_ok = verify_ml_dsa(&pk, &attest_dig, &sig);
            ensure(sig_ok,
                &format!("shard {} attestation {} (worker={}) sig FAILED", w.shard_id, i, a.worker_id))?;
        }

        // Aggregate prove time = max across replicas (parallel wall-clock).
        let max_prove = w.attestations.iter().map(|a| a.prove_ms).fold(0.0_f64, f64::max);
        total_inner_verify_ms += verify_ms;
        if max_prove > inner_proof_max_ms { inner_proof_max_ms = max_prove; }
        inner_proof_total_kb += (w.proof_bytes_len as usize) / 1024;

        let workers_csv: String = w.attestations.iter()
            .map(|a| a.worker_id.to_string()).collect::<Vec<_>>().join(",");
        println!(
            "  ✓ shard {:>3}  workers=[{:>9}]  records={:<6}  proof={:>4} KiB  prove(max)={:>5.0}ms  verify={:>4.1}ms  pi_hash={}…  k_attestations={}",
            w.shard_id, workers_csv, w.record_count,
            w.proof_bytes_len / 1024,
            max_prove, verify_ms,
            &w.pi_hash_hex[..16],
            w.attestations.len(),
        );
    }

    // ─── Phase 2: outer rollup verification ──────────────────────────────────
    let outer_proof_path = args.bundle_dir.join(&bundle.outer_proof_path);
    let outer_bytes = std::fs::read(&outer_proof_path)
        .with_context(|| format!("read outer proof {}", outer_proof_path.display()))?;
    if outer_bytes.len() != bundle.outer_proof_bytes {
        return Err(anyhow!(
            "outer proof size mismatch: file={} bundle={}",
            outer_bytes.len(), bundle.outer_proof_bytes));
    }
    let outer_proof = DeepFriProof::<Ext>::deserialize_with_mode(
        outer_bytes.as_slice(), Compress::Yes, Validate::Yes,
    ).context("deserialize outer proof")?;

    let derived_outer_n0 = outer_n0_from_pi_count(sorted.len());
    if derived_outer_n0 != bundle.outer_n0 {
        return Err(anyhow!(
            "outer n0 mismatch: derived={} bundle={}",
            derived_outer_n0, bundle.outer_n0));
    }
    let outer_params = build_params(bundle.outer_n0, &pk_hash32, ldt);
    let t0 = std::time::Instant::now();
    let outer_ok = deep_fri_verify::<Ext>(&outer_params, &outer_proof);
    let outer_verify_ms = t0.elapsed().as_secs_f64() * 1e3;
    ensure(outer_ok, "deep_fri_verify FAILED for outer rollup")?;

    let outer_root_f0 = decode_fixed::<32>(&bundle.outer_root_f0_hex, "outer_root_f0_hex")?;
    ensure(outer_proof.root_f0 == outer_root_f0,
        "outer rollup root_f0 in proof != bundle")?;
    println!(
        "\n  ✓ outer rollup  n_trace={}  proof={} KiB  verify={:.1}ms  root_f0={}…",
        bundle.outer_n_trace, bundle.outer_proof_bytes / 1024,
        outer_verify_ms, &bundle.outer_root_f0_hex[..16],
    );

    // ─── Phase 3: authority signature ────────────────────────────────────────
    let nist_byte = bundle.nist_level;
    // DS-binding bytes (§8.2): empty when not configured.  Including them
    // (or their absence-marker) in the recomputed zone_digest is what
    // makes verifier-side DS→KSK binding cryptographically meaningful.
    let dnskey_bytes: Vec<u8> = match &bundle.dnskey_pk_hex {
        Some(h) => hex::decode(h).context("decode bundle.dnskey_pk_hex")?,
        None    => Vec::new(),
    };
    let ds_hash_bytes: Vec<u8> = match &bundle.parent_ds_hash_hex {
        Some(h) => hex::decode(h).context("decode bundle.parent_ds_hash_hex")?,
        None    => Vec::new(),
    };
    let zone_digest = level_hash(level, &[
        b"DNS-ZONE-AUTHORITY-V1",
        &[nist_byte],
        &zone_salt,
        &(bundle.record_count as u64).to_le_bytes(),
        &outer_root_f0,
        &pk_hash32,
        b"DS-BIND-V1",
        &(dnskey_bytes.len() as u32).to_le_bytes(),
        &dnskey_bytes,
        &(ds_hash_bytes.len() as u32).to_le_bytes(),
        &ds_hash_bytes,
    ]);
    let zone_digest_claim = hex::decode(&bundle.zone_digest_hex).context("decode zone_digest_hex")?;
    ensure(zone_digest == zone_digest_claim, "zone_digest recipe mismatch")?;

    let authority_sig = hex::decode(&bundle.authority_sig_hex).context("decode authority_sig_hex")?;
    let sig_ok = verify_ml_dsa(&pk_bytes, &zone_digest, &authority_sig);
    ensure(sig_ok, "authority ML-DSA signature FAILED")?;
    println!(
        "  ✓ authority sig  scheme={}  digest_bytes={}  sig_bytes={}",
        bundle.ml_dsa_scheme, zone_digest.len(), authority_sig.len(),
    );

    // ─── Phase 3b: DS→KSK binding (§10.4 — STARK preferred, runtime fallback) ─
    if !dnskey_bytes.is_empty() && !ds_hash_bytes.is_empty() {
        if ds_hash_bytes.len() != 32 {
            return Err(anyhow!("parent_ds_hash must be 32 bytes; got {}", ds_hash_bytes.len()));
        }
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&ds_hash_bytes);

        if let Some(proof_path) = &bundle.ds_ksk_proof_path {
            // ── In-circuit STARK path (preferred) ──────────────────
            //
            // The prover ran `swarm_dns::prover::prove_ds_ksk_binding`
            // which: (a) builds a multi-block SHA-256 trace via the
            // `sha256_air` AIR, (b) extracts the asserted digest from
            // the H-state at the post-finalisation row, (c) commits
            // to (dnskey_bytes, parent_ds_hash, asserted_digest,
            // root_f0, fs_binding) in pi_hash, and (d) emits a STIR
            // proof.  Verifier here checks the STIR proof and
            // recomputes the same pi_hash from public inputs.

            let abs_path: PathBuf = if PathBuf::from(proof_path).is_absolute() {
                PathBuf::from(proof_path)
            } else {
                args.bundle_dir.join(proof_path)
            };
            let proof_bytes = std::fs::read(&abs_path)
                .with_context(|| format!("read DS→KSK proof at {}", abs_path.display()))?;
            let proof = DeepFriProof::<Ext>::deserialize_with_mode(
                proof_bytes.as_slice(), Compress::Yes, Validate::Yes,
            ).context("deserialise DS→KSK proof")?;

            let n_blocks = bundle.ds_ksk_n_blocks
                .ok_or_else(|| anyhow!("ds_ksk_n_blocks missing from bundle"))?;
            let n_trace = bundle.ds_ksk_n_trace
                .ok_or_else(|| anyhow!("ds_ksk_n_trace missing from bundle"))?;
            ensure(n_trace.is_power_of_two(),
                "ds_ksk_n_trace must be a power of 2")?;
            // Sanity-check trace dimensions against the message length.
            //   pad: ceil((dnskey_bytes.len() + 9) / 64) blocks.
            let expected_blocks =
                (dnskey_bytes.len() + 9 + 63) / 64;
            ensure(n_blocks == expected_blocks,
                "ds_ksk_n_blocks does not match dnskey_bytes padding")?;

            // Reconstruct DeepFriParams.  FS binding is the authority
            // pk_hash, matching the prover's call site.
            let n0 = n_trace * 32; // BLOWUP from swarm_dns::prover::BLOWUP
            let params = build_params(n0, &pk_hash32, ldt);

            let t0 = std::time::Instant::now();
            let ok = deep_fri_verify::<Ext>(&params, &proof);
            let verify_ms = t0.elapsed().as_secs_f64() * 1e3;
            ensure(ok, "DS→KSK STIR proof verification FAILED")?;

            // Asserted digest carried in the bundle must equal
            // parent_ds_hash.  This is the cryptographic claim of the
            // proof: "SHA-256(dnskey_bytes) = asserted_digest"; the
            // bundle commits asserted_digest = parent_ds_hash.
            let asserted_hex = bundle.ds_ksk_asserted_digest_hex.as_ref()
                .ok_or_else(|| anyhow!("ds_ksk_asserted_digest_hex missing"))?;
            let asserted: [u8; 32] = decode_fixed::<32>(
                asserted_hex, "ds_ksk_asserted_digest_hex")?;
            ensure(asserted == expected,
                "DS→KSK asserted digest ≠ parent_ds_hash")?;

            // Recompute and compare pi_hash.
            let pi_recipe = {
                let mut h = sha3::Sha3_256::new();
                Digest::update(&mut h, b"DS-KSK-PIHASH-V1");
                Digest::update(&mut h, &(dnskey_bytes.len() as u64).to_le_bytes());
                Digest::update(&mut h, &dnskey_bytes);
                Digest::update(&mut h, &expected);
                Digest::update(&mut h, &asserted);
                Digest::update(&mut h, &proof.root_f0);
                Digest::update(&mut h, &pk_hash32);
                let h: [u8; 32] = Digest::finalize(h).into();
                h
            };
            let pi_claim = decode_fixed::<32>(
                bundle.ds_ksk_pi_hash_hex.as_ref()
                    .ok_or_else(|| anyhow!("ds_ksk_pi_hash_hex missing"))?,
                "ds_ksk_pi_hash_hex")?;
            ensure(pi_recipe == pi_claim,
                "DS→KSK pi_hash recipe mismatch")?;

            // root_f0 in the bundle must agree with the proof.
            let root_f0_claim = decode_fixed::<32>(
                bundle.ds_ksk_root_f0_hex.as_ref()
                    .ok_or_else(|| anyhow!("ds_ksk_root_f0_hex missing"))?,
                "ds_ksk_root_f0_hex")?;
            ensure(proof.root_f0 == root_f0_claim,
                "DS→KSK root_f0 mismatch")?;

            println!(
                "  ✓ DS→KSK STARK   n_blocks={} n_trace={}  verify={:.1}ms  \
                 root_f0={}…",
                n_blocks, n_trace, verify_ms,
                &hex::encode(&proof.root_f0)[..16],
            );
        } else {
            // ── Fallback: runtime SHA-256 (legacy bundles) ─────────
            //
            // RFC 4034 §5.1.4 specifies SHA-256 of canonical DNSKEY
            // RDATA for DS digest-algorithm 2.  Without the STARK,
            // the verifier trusts its own sha2 implementation.
            use sha2::{Sha256, Digest as Sha2Digest};
            let mut h = Sha256::new();
            Sha2Digest::update(&mut h, &dnskey_bytes);
            let computed: [u8; 32] = Sha2Digest::finalize(h).into();
            ensure(computed == expected,
                "DS → KSK binding FAILED: SHA-256(DNSKEY) ≠ parent_ds_hash")?;
            println!(
                "  ✓ DS→KSK runtime  SHA-256(DNSKEY[{} B]) = parent_ds_hash[{}…]  \
                 (no STARK in bundle — legacy path)",
                dnskey_bytes.len(), &hex::encode(&ds_hash_bytes)[..16],
            );
        }
    }

    // ─── Phase 3c: ZSK→KSK binding (§10.7 — Ed25519 RFC 8080) ─────
    //
    // Runtime-fallback path (Phase 7 v0): verifier reproduces pi_hash
    // from public inputs and runs the in-crate Ed25519 verifier.  The
    // STARK-preferred path lands once Phase 5 v1b ships
    // `Ed25519VerifyAir`.  Bundle layout is forward-compatible: same
    // pi_hash recipe.
    let zsk_ksk_present = bundle.zsk_ksk_pubkey_hex.is_some()
        || bundle.zsk_ksk_signature_hex.is_some()
        || bundle.zsk_ksk_signed_data_hex.is_some()
        || bundle.zsk_ksk_pi_hash_hex.is_some()
        || bundle.zsk_ksk_proof_path.is_some();
    if zsk_ksk_present {
        // FS binding: explicit if provided, else default to pk_hash32
        // (same convention used by DS→KSK).
        let fs_binding: [u8; 32] = match &bundle.zsk_ksk_fs_binding_hex {
            Some(h) => decode_fixed::<32>(h, "zsk_ksk_fs_binding_hex")?,
            None    => pk_hash32,
        };

        if let Some(proof_path) = &bundle.zsk_ksk_proof_path {
            // ── STARK-preferred path (Phase 7 v1) ──────────────────
            //
            // The prover ran `swarm_dns::prover::prove_zsk_ksk_binding_stub_k8`
            // which: (a) builds the K=8 stub trace via the Ed25519ZskKsk
            // registry, (b) runs DEEP-ALI + STIR on the v16 verify AIR,
            // and (c) emits a STARK proof.  The bundle's pi_hash uses
            // the stub-K8 recipe `SHA3("ZSK-KSK-STUB-K8-PIHASH-V1" ||
            // root_f0 || fs_binding)`.
            //
            // The full per-signature production recipe (binding pk, sig,
            // data, fs into pi_hash AND the proof) lands in v2 once the
            // parametric `deep_ali_merge_ed25519_verify` is wired.

            let kind = bundle.zsk_ksk_stark_kind.as_deref().unwrap_or("stub-k8");
            ensure(kind == "stub-k8",
                &format!("ZSK→KSK STARK kind '{}' not recognised — \
                          this verifier supports only 'stub-k8' (Phase 7 v1)",
                         kind))?;

            let abs_path: PathBuf = if PathBuf::from(proof_path).is_absolute() {
                PathBuf::from(proof_path)
            } else {
                args.bundle_dir.join(proof_path)
            };
            let proof_bytes = std::fs::read(&abs_path)
                .with_context(|| format!("read ZSK→KSK proof at {}", abs_path.display()))?;
            let proof = DeepFriProof::<Ext>::deserialize_with_mode(
                proof_bytes.as_slice(), Compress::Yes, Validate::Yes,
            ).context("deserialise ZSK→KSK proof")?;

            let n_trace = bundle.zsk_ksk_n_trace
                .ok_or_else(|| anyhow!("zsk_ksk_n_trace missing from bundle"))?;
            ensure(n_trace.is_power_of_two(),
                "zsk_ksk_n_trace must be a power of 2")?;
            let n0 = n_trace * 32;          // BLOWUP from swarm_dns::prover::BLOWUP
            let params = build_params(n0, &fs_binding, ldt);

            let t0 = std::time::Instant::now();
            let ok = deep_fri_verify::<Ext>(&params, &proof);
            let verify_ms = t0.elapsed().as_secs_f64() * 1e3;
            ensure(ok, "ZSK→KSK STARK proof verification FAILED")?;

            // root_f0 in the bundle must agree with the proof.
            let root_f0_claim = decode_fixed::<32>(
                bundle.zsk_ksk_root_f0_hex.as_ref()
                    .ok_or_else(|| anyhow!("zsk_ksk_root_f0_hex missing"))?,
                "zsk_ksk_root_f0_hex")?;
            ensure(proof.root_f0 == root_f0_claim,
                "ZSK→KSK root_f0 mismatch")?;

            // Recompute the stub-K8 pi_hash and match the bundle claim.
            let pi_recipe: [u8; 32] = {
                let mut h = sha3::Sha3_256::new();
                Digest::update(&mut h, b"ZSK-KSK-STUB-K8-PIHASH-V1");
                Digest::update(&mut h, &proof.root_f0);
                Digest::update(&mut h, &fs_binding);
                Digest::finalize(h).into()
            };
            let pi_claim = decode_fixed::<32>(
                bundle.zsk_ksk_pi_hash_hex.as_ref()
                    .ok_or_else(|| anyhow!("zsk_ksk_pi_hash_hex missing"))?,
                "zsk_ksk_pi_hash_hex")?;
            ensure(pi_recipe == pi_claim,
                "ZSK→KSK STARK stub-K8 pi_hash recipe mismatch")?;

            println!(
                "  ✓ ZSK→KSK STARK   stub-K8  n_trace={}  verify={:.1}ms  \
                 root_f0={}…",
                n_trace, verify_ms, &hex::encode(&proof.root_f0)[..16],
            );
        } else {
            // ── Runtime fallback (Phase 7 v0, legacy bundles) ──────
            let pubkey_hex = bundle.zsk_ksk_pubkey_hex.as_ref()
                .ok_or_else(|| anyhow!("zsk_ksk_pubkey_hex required when any zsk_ksk_* field is set"))?;
            let signature_hex = bundle.zsk_ksk_signature_hex.as_ref()
                .ok_or_else(|| anyhow!("zsk_ksk_signature_hex required"))?;
            let signed_data_hex = bundle.zsk_ksk_signed_data_hex.as_ref()
                .ok_or_else(|| anyhow!("zsk_ksk_signed_data_hex required"))?;
            let pi_hash_hex = bundle.zsk_ksk_pi_hash_hex.as_ref()
                .ok_or_else(|| anyhow!("zsk_ksk_pi_hash_hex required"))?;

            let pubkey:    [u8; 32] = decode_fixed::<32>(pubkey_hex,    "zsk_ksk_pubkey_hex")?;
            let signature: [u8; 64] = decode_fixed::<64>(signature_hex, "zsk_ksk_signature_hex")?;
            let claimed_pi: [u8; 32] = decode_fixed::<32>(pi_hash_hex,  "zsk_ksk_pi_hash_hex")?;
            let signed_data = hex::decode(signed_data_hex)
                .context("decode zsk_ksk_signed_data_hex")?;

            let t0 = std::time::Instant::now();
            swarm_dns::prover::verify_zsk_ksk_runtime_fallback(
                &pubkey, &signature, &signed_data, &fs_binding, &claimed_pi,
            ).map_err(|e| match e {
                swarm_dns::prover::ZskKskVerifyError::PiHashMismatch =>
                    anyhow!("ZSK→KSK pi_hash recipe mismatch"),
                swarm_dns::prover::ZskKskVerifyError::SignatureInvalid =>
                    anyhow!("ZSK→KSK Ed25519 signature verification failed"),
            })?;
            let verify_ms = t0.elapsed().as_secs_f64() * 1e3;

            println!(
                "  ✓ ZSK→KSK runtime  Ed25519(pk[32 B], sig[64 B], data[{} B])  \
                 verify={:.2}ms  pi_hash={}…  (no STARK in bundle)",
                signed_data.len(), verify_ms,
                &hex::encode(&claimed_pi)[..16],
            );
        }
    }

    println!("\n┌─ Summary ───────────────────────────────────────────────────────");
    println!("│  inner shards verified : {}", sorted.len());
    println!("│  inner proof total KiB : {}", inner_proof_total_kb);
    println!("│  inner max prove (ms)  : {:.0}  (parallel wall-clock baseline)", inner_proof_max_ms);
    println!("│  inner verify Σ (ms)   : {:.1}", total_inner_verify_ms);
    println!("│  outer verify (ms)     : {:.1}", outer_verify_ms);
    println!("│  authority sig         : verified");
    println!("│  STATUS                : ✓ FULL CHAIN VERIFIED");
    println!("└──────────────────────────────────────────────────────────────────");

    // ─── Optional: receipt audit (G — censorship / substitution detection) ───
    if let Some(receipts_dir) = &args.receipts_dir {
        audit_receipts(receipts_dir, &job_id, &pk_bytes, &sorted, bundle.shard_replication)?;
    }

    // ─── Optional: witness M-of-N quorum audit (H — distributed audit) ───
    if !args.witness_receipts.is_empty() {
        let m = args.witness_threshold.unwrap_or(args.witness_receipts.len());
        audit_witnesses(&args.witness_receipts, m, &job_id, &sorted)?;
    }

    Ok(())
}

/// Cross-check every worker-stored receipt against the bundle.
/// Reports:
///   * receipt for this job whose pi_hash matches the bundle  → consistent
///   * receipt for this job whose pi_hash does NOT match (or shard absent)
///                                                          → CENSORSHIP/SUBSTITUTION
///   * receipts for other jobs are ignored (not relevant)
fn audit_receipts(
    receipts_dir:      &std::path::Path,
    job_id:            &[u8; 32],
    expected_ctrl_pk:  &[u8],
    bundle_shards:     &[&InnerWorkerRecord],
    shard_replication: usize,
) -> Result<()> {
    println!("\n┌─ Receipt audit (G) ────────────────────────────────────────────");
    println!("│  receipts dir : {}", receipts_dir.display());

    if !receipts_dir.exists() {
        println!("│  STATUS       : ⚠ receipts dir does not exist");
        println!("└──────────────────────────────────────────────────────────────────");
        return Ok(());
    }

    // Walk receipts_dir/job-<hex>/shard-<NNNN>.cbor
    let job_dir = receipts_dir.join(format!("job-{}", hex::encode(job_id)));
    if !job_dir.exists() {
        println!("│  STATUS       : ⚠ no receipts found for this job_id ({})",
                 &hex::encode(job_id)[..16]);
        println!("│  (workers may not have run with --receipts-dir, or this is a different job)");
        println!("└──────────────────────────────────────────────────────────────────");
        return Ok(());
    }

    let entries = std::fs::read_dir(&job_dir)
        .with_context(|| format!("read_dir {}", job_dir.display()))?;
    let mut total = 0usize;
    let mut consistent = 0usize;
    let mut sig_failed = Vec::<u32>::new();
    let mut wrong_pk = Vec::<u32>::new();
    let mut censored = Vec::<(u32, [u8; 32])>::new();   // shard_id, the orphaned pi_hash

    let bundle_index: HashMap<u32, [u8; 32]> = bundle_shards.iter()
        .map(|w| (w.shard_id, decode_fixed_silent::<32>(&w.pi_hash_hex).unwrap_or([0u8; 32])))
        .collect();

    for entry in entries {
        let Ok(entry) = entry else { continue; };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("cbor") { continue; }
        total += 1;
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read {}", path.display()))?;
        let receipt: ShardReceipt = match ciborium::de::from_reader(bytes.as_slice()) {
            Ok(r) => r,
            Err(e) => {
                println!("│  ⚠ unparseable receipt {} — {e}", path.display());
                continue;
            }
        };

        // (a) job_id match (we already filtered by directory, double-check).
        if receipt.job_id != *job_id { continue; }

        // (b) ctrl pk in receipt matches bundle authority pk.
        if receipt.ctrl_authority_pk != expected_ctrl_pk {
            wrong_pk.push(receipt.shard_id);
            continue;
        }

        // (c) ctrl signature on the receipt verifies.
        let dig = ctrl_receipt_digest(
            &receipt.job_id, receipt.shard_id, receipt.worker_id,
            &receipt.pi_hash, &receipt.merkle_root, receipt.accepted_at_unix_ms,
        );
        if !verify_ml_dsa(&receipt.ctrl_authority_pk, &dig, &receipt.ctrl_sig) {
            sig_failed.push(receipt.shard_id);
            continue;
        }

        // (d) cross-check pi_hash against bundle.
        match bundle_index.get(&receipt.shard_id) {
            Some(bundle_pi) if *bundle_pi == receipt.pi_hash => {
                consistent += 1;
            }
            _ => {
                censored.push((receipt.shard_id, receipt.pi_hash));
            }
        }
    }

    println!("│  receipts found            : {total}");
    println!("│  consistent w/ bundle      : {consistent}");
    println!("│  shard_replication (k)     : {shard_replication}  (up to k receipts per shard expected)");
    if !wrong_pk.is_empty() {
        println!("│  ⚠ wrong-ctrl-pk receipts  : {wrong_pk:?}  (signed by a different ctrl key)");
    }
    if !sig_failed.is_empty() {
        println!("│  ⚠ sig-failed receipts     : {sig_failed:?}");
    }
    if censored.is_empty() {
        if total > 0 {
            println!("│  STATUS                    : ✓ no censorship/substitution evidence");
        } else {
            println!("│  STATUS                    : ⚠ zero receipts to audit");
        }
    } else {
        println!("│  STATUS                    : ✗ CENSORSHIP/SUBSTITUTION DETECTED");
        println!("│  Orphaned receipts (ctrl ack'd these but the bundle disagrees):");
        for (sid, pi) in &censored {
            println!("│    · shard {sid}  receipt.pi_hash = {}…  bundle: {}",
                     &hex::encode(pi)[..32],
                     bundle_index.get(sid).map(|b| format!("{}…", &hex::encode(b)[..32])).unwrap_or_else(|| "(absent)".to_string()));
        }
    }
    println!("└──────────────────────────────────────────────────────────────────");
    if !censored.is_empty() {
        return Err(anyhow!("receipt audit failed — controller-side censorship/substitution evidence"));
    }
    Ok(())
}

/// Walk every witness archive, validate every receipt's ctrl signature,
/// and check that for every shard in the bundle, at least `m` witnesses
/// have a matching `pi_hash`.
fn audit_witnesses(
    witness_dirs: &[PathBuf],
    threshold_m:  usize,
    job_id:       &[u8; 32],
    bundle_shards: &[&InnerWorkerRecord],
) -> Result<()> {
    println!("\n┌─ Witness quorum audit (H) ──────────────────────────────────────");
    println!("│  N witnesses        : {}", witness_dirs.len());
    println!("│  required threshold : M = {threshold_m}");

    if threshold_m > witness_dirs.len() {
        return Err(anyhow!(
            "M ({threshold_m}) exceeds N ({}) — impossible quorum", witness_dirs.len()
        ));
    }

    // For each shard, count witnesses that have a matching receipt.
    let bundle_index: HashMap<u32, [u8; 32]> = bundle_shards.iter()
        .map(|w| (w.shard_id, decode_fixed_silent::<32>(&w.pi_hash_hex).unwrap_or([0u8; 32])))
        .collect();

    // Per-shard "agreeing witnesses" tally. Built incrementally.
    let mut agreeing: HashMap<u32, Vec<String>> = HashMap::new();
    let mut all_pks_seen: HashMap<Vec<u8>, usize> = HashMap::new();

    for dir in witness_dirs {
        let label = dir.file_name().and_then(|s| s.to_str()).unwrap_or("witness").to_string();
        if !dir.exists() {
            println!("│  ⚠ archive missing       : {}", dir.display());
            continue;
        }
        let job_dir = dir.join(format!("job-{}", hex::encode(job_id)));
        if !job_dir.exists() {
            println!("│  ⚠ no job receipts in    : {}", dir.display());
            continue;
        }

        let entries = std::fs::read_dir(&job_dir)
            .with_context(|| format!("read_dir {}", job_dir.display()))?;
        let mut local_ok = 0usize;
        for entry in entries {
            let Ok(entry) = entry else { continue; };
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("cbor") { continue; }
            let bytes = std::fs::read(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let receipt: ShardReceipt = match ciborium::de::from_reader(bytes.as_slice()) {
                Ok(r) => r,
                Err(e) => {
                    println!("│  ⚠ unparseable {} — {e}", path.display());
                    continue;
                }
            };
            if receipt.job_id != *job_id { continue; }

            // Verify ctrl sig.
            let dig = ctrl_receipt_digest(
                &receipt.job_id, receipt.shard_id, receipt.worker_id,
                &receipt.pi_hash, &receipt.merkle_root, receipt.accepted_at_unix_ms,
            );
            if !verify_ml_dsa(&receipt.ctrl_authority_pk, &dig, &receipt.ctrl_sig) {
                println!("│  ⚠ sig FAILED for {}/shard-{:04}", label, receipt.shard_id);
                continue;
            }

            *all_pks_seen.entry(receipt.ctrl_authority_pk.clone()).or_insert(0) += 1;

            // Cross-check pi_hash against bundle.
            match bundle_index.get(&receipt.shard_id) {
                Some(bundle_pi) if *bundle_pi == receipt.pi_hash => {
                    agreeing.entry(receipt.shard_id).or_default().push(label.clone());
                    local_ok += 1;
                }
                Some(_) => {
                    println!(
                        "│  ⚠ pi_hash MISMATCH  witness={label} shard={} (bundle disagrees)",
                        receipt.shard_id);
                }
                None => {
                    println!(
                        "│  ⚠ orphan receipt    witness={label} shard={} (bundle has no such shard)",
                        receipt.shard_id);
                }
            }
        }
        println!("│  archive {label:<24}  {local_ok} matching receipts");
    }

    // For each shard in the bundle, require at least m witness agreements.
    let mut shortfalls: Vec<(u32, usize)> = Vec::new();
    for w in bundle_shards {
        let count = agreeing.get(&w.shard_id).map(|v| v.len()).unwrap_or(0);
        if count < threshold_m {
            shortfalls.push((w.shard_id, count));
        }
    }

    println!("│  distinct ctrl pks  : {}", all_pks_seen.len());
    if shortfalls.is_empty() {
        println!("│  STATUS             : ✓ every shard has ≥ M={threshold_m} matching witnesses");
    } else {
        println!("│  STATUS             : ✗ QUORUM SHORTFALL");
        for (sid, c) in &shortfalls {
            println!("│    · shard {sid}  agreeing_witnesses = {c}  (need ≥ {threshold_m})");
        }
    }
    println!("└──────────────────────────────────────────────────────────────────");
    if !shortfalls.is_empty() {
        return Err(anyhow!("witness quorum audit failed — {} shard(s) below threshold", shortfalls.len()));
    }
    Ok(())
}

fn decode_fixed_silent<const N: usize>(hex_s: &str) -> Result<[u8; N]> {
    let v = hex::decode(hex_s)?;
    if v.len() != N { return Err(anyhow!("len")); }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_level(n: u8) -> Result<NistLevel> {
    Ok(match n {
        1 => NistLevel::L1,
        3 => NistLevel::L3,
        5 => NistLevel::L5,
        _ => return Err(anyhow!("unknown NIST level {n}")),
    })
}

fn parse_ldt(s: &str) -> Result<LdtMode> {
    Ok(match s {
        "STIR" => LdtMode::Stir,
        "FRI(arity-2)" | "FRI" => LdtMode::Fri,
        _ => return Err(anyhow!("unknown LDT label '{s}'")),
    })
}

fn decode_fixed<const N: usize>(hex_s: &str, label: &str) -> Result<[u8; N]> {
    let v = hex::decode(hex_s).with_context(|| format!("decode {label}"))?;
    if v.len() != N {
        return Err(anyhow!("{label}: expected {N} bytes, got {}", v.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

fn ensure(cond: bool, msg: &str) -> Result<()> {
    if cond { Ok(()) } else { Err(anyhow!(msg.to_string())) }
}

fn pk_binding_hash(pk: &[u8]) -> [u8; 32] {
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, b"DNS-AUTHORITY-PK-V1");
    Digest::update(&mut h, pk);
    Digest::finalize(h).into()
}

fn inner_pi_hash_recipe(
    salt: &[u8; 16],
    record_count: usize,
    merkle_root: &[u8; 32],
    root_f0: &[u8; 32],
    pk_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, b"DNS-SHARD-PIHASH-V1");
    Digest::update(&mut h, salt);
    Digest::update(&mut h, &(record_count as u64).to_le_bytes());
    Digest::update(&mut h, merkle_root);
    Digest::update(&mut h, root_f0);
    Digest::update(&mut h, pk_hash);
    Digest::finalize(h).into()
}

fn worker_attestation_digest(
    shard_id:    u32,
    pi_hash:     &[u8; 32],
    merkle_root: &[u8; 32],
    root_f0:     &[u8; 32],
) -> [u8; 32] {
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, b"DNS-SWARM-WORKER-ATTEST-V1");
    Digest::update(&mut h, &shard_id.to_le_bytes());
    Digest::update(&mut h, pi_hash);
    Digest::update(&mut h, merkle_root);
    Digest::update(&mut h, root_f0);
    Digest::finalize(h).into()
}

/// Verify an ML-DSA signature, dispatching by pk length to the appropriate
/// parameter set (44/65/87 ↔ NIST L1/L3/L5).
fn verify_ml_dsa(pk_bytes: &[u8], message: &[u8], sig: &[u8]) -> bool {
    use fips204::traits::{SerDes, Verifier};
    use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};

    match pk_bytes.len() {
        n if n == ml_dsa_44::PK_LEN => {
            let Ok(pk_arr): Result<[u8; ml_dsa_44::PK_LEN], _> = pk_bytes.to_vec().try_into() else { return false };
            let Ok(pk) = ml_dsa_44::PublicKey::try_from_bytes(pk_arr) else { return false };
            if sig.len() != ml_dsa_44::SIG_LEN { return false; }
            let sig_arr: &[u8; ml_dsa_44::SIG_LEN] = sig.try_into().unwrap();
            pk.verify(message, sig_arr, b"")
        }
        n if n == ml_dsa_65::PK_LEN => {
            let Ok(pk_arr): Result<[u8; ml_dsa_65::PK_LEN], _> = pk_bytes.to_vec().try_into() else { return false };
            let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_arr) else { return false };
            if sig.len() != ml_dsa_65::SIG_LEN { return false; }
            let sig_arr: &[u8; ml_dsa_65::SIG_LEN] = sig.try_into().unwrap();
            pk.verify(message, sig_arr, b"")
        }
        n if n == ml_dsa_87::PK_LEN => {
            let Ok(pk_arr): Result<[u8; ml_dsa_87::PK_LEN], _> = pk_bytes.to_vec().try_into() else { return false };
            let Ok(pk) = ml_dsa_87::PublicKey::try_from_bytes(pk_arr) else { return false };
            if sig.len() != ml_dsa_87::SIG_LEN { return false; }
            let sig_arr: &[u8; ml_dsa_87::SIG_LEN] = sig.try_into().unwrap();
            pk.verify(message, sig_arr, b"")
        }
        _ => false,
    }
}
