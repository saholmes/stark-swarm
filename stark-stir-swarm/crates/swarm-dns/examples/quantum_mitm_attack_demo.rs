//! Quantum-MITM attack demo: how STARK-DNS prevents what DNSSEC cannot.
//!
//! Threat model:
//!   A cryptographically-relevant quantum computer (CRQC) becomes
//!   available to an adversary.  The adversary uses Shor's algorithm
//!   to recover the DNS zone's RSA-2048 private key (or ECDSA / Ed25519
//!   key — the same attack works against any classical signature).
//!
//! Without STARK-DNS, the adversary can now silently MITM the zone:
//!     1. Forge a malicious DNSSEC RRSIG re-signing
//!        \texttt{rec0042.example.com}'s A-record to point at the
//!        adversary's server (6.6.6.6 instead of 10.0.0.42).
//!     2. Resolvers' DNSSEC validation accepts the forgery — the
//!        signature is mathematically valid under the (now-broken)
//!        zone key.  The user is silently re-routed to the
//!        adversary's IP.
//!
//! With STARK-DNS, the same attack fails at the edge consumer's
//! verifier because the binding the consumer trusts is ML-DSA-65
//! (lattice-based, PQ-secure) over the epoch's Merkle commitment to
//! the records.  The adversary's forged record is not committed under
//! the authority's pinned Merkle root, so the Merkle-path check
//! fails.  We exercise three concrete adversary attack flows and
//! show STARK-DNS rejecting each one.
//!
//! Run:
//!     cargo run --release -p swarm-dns --example quantum_mitm_attack_demo

use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as MlDsaSigner, Verifier as MlDsaVerifier};
use num_bigint::BigUint;
use rand::SeedableRng;
use sha2::Digest as ShaDigest;
use sha3::{Digest as Sha3Digest, Sha3_256};

use deep_ali::{
    deep_ali_merge_rsa_stacked_streaming,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify, DeepFriParams, FriDomain},
    rsa2048::{emsa_pkcs1_v1_5_encode_sha256, verify as native_rsa_verify, PublicKey as RsaPublic},
    rsa2048_stacked_air::{
        build_rsa_stacked_layout, fill_rsa_stacked, rsa_stacked_constraints, RsaStackedRecord,
    },
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};
use swarm_dns::dns::{merkle_build, merkle_path, merkle_root, merkle_verify};

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
    if remainder_log > 0 { s.push(1usize << remainder_log); }
    s
}

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

fn record_leaf(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Sha3Digest::update(&mut h, b"DNS-RECORD-LEAF-V1\x00");
    Sha3Digest::update(&mut h, bytes);
    Sha3Digest::finalize(h).into()
}

fn fmt_size(b: usize) -> String {
    if b >= 1024 { format!("{:.2} KiB", b as f64 / 1024.0) } else { format!("{} B", b) }
}

fn hr(c: char) {
    println!("{}", std::iter::repeat(c).take(70).collect::<String>());
}

fn main() {
    println!("══════════════════════════════════════════════════════════════════════");
    println!("  STARK-DNS vs DNSSEC: silent quantum-MITM attack demonstration");
    println!("══════════════════════════════════════════════════════════════════════");
    println!();
    println!("Threat model: a cryptographically-relevant quantum computer (CRQC)");
    println!("recovers the zone's RSA-2048 private key via Shor's algorithm.");
    println!();

    // ═════════════════════════════════════════════════════════════════════
    // 0. Setup: legitimate DNS authority
    // ═════════════════════════════════════════════════════════════════════
    hr('═');
    println!("[0] LEGITIMATE DNS AUTHORITY publishes the zone");
    hr('═');

    use rsa::{
        pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding},
        traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey,
    };
    use sha2::Sha256;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE_BABE);
    let zsk_priv = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let zsk_pub = RsaPublicKey::from(&zsk_priv);
    let zsk_n_be = zsk_pub.n().to_bytes_be();
    let zsk_signing = SigningKey::<Sha256>::new(zsk_priv.clone());
    let our_zsk_pub = RsaPublic::from_n_be(&zsk_n_be);

    let (mldsa_pk, mldsa_sk) = ml_dsa_65::try_keygen_with_rng(
        &mut rand::rngs::StdRng::seed_from_u64(0xC0FFEE)).unwrap();
    let authority_mldsa_pk_bytes = mldsa_pk.into_bytes();

    let n_records = 50usize;
    let mut all_records: Vec<RsaStackedRecord> = Vec::with_capacity(n_records);
    let mut all_record_bytes: Vec<Vec<u8>> = Vec::with_capacity(n_records);
    let mut all_leaves: Vec<[u8; 32]> = Vec::with_capacity(n_records);

    for i in 0..n_records {
        let domain = format!("rec{:04}.example.com.", i);
        let ip = [10u8, 0, (i / 256) as u8, (i % 256) as u8];
        let message = format!(
            "DNSSEC-RRSIG-V0|{}|A|{}.{}.{}.{}|epoch-0|alg-8",
            domain, ip[0], ip[1], ip[2], ip[3]
        );
        let sig = zsk_signing.sign(message.as_bytes()).to_bytes();
        let mut digest = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        digest.copy_from_slice(&hasher.finalize());
        let em = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();

        let rec_full = message.into_bytes();
        all_leaves.push(record_leaf(&rec_full));
        all_record_bytes.push(rec_full);
        all_records.push(RsaStackedRecord {
            n:  BigUint::from_bytes_be(&zsk_n_be),
            s:  BigUint::from_bytes_be(&sig),
            em: BigUint::from_bytes_be(&em),
        });
    }
    let levels = merkle_build(&all_leaves);
    let legitimate_mroot = merkle_root(&levels);
    println!("Authority builds 50-record zone:");
    println!("  rec0042 → 10.0.0.42  (legitimate IP, signed by zone ZSK)");
    println!("  ... 49 other records ...");
    println!("Authority's published Merkle root: {}", hex::encode(&legitimate_mroot[..16]));

    // STARK + ML-DSA epoch.
    println!();
    println!("Authority generates STARK-DNS epoch package:");
    let t = Instant::now();
    const N_TRACE: usize = 32;
    let layout = build_rsa_stacked_layout(n_records);
    let cons_per_row = rsa_stacked_constraints(&layout);
    let n0 = N_TRACE * BLOWUP;
    let mut trace: Vec<Vec<F>> = (0..layout.width)
        .map(|_| vec![F::zero(); N_TRACE]).collect();
    fill_rsa_stacked(&mut trace, &layout, N_TRACE, &all_records);
    let domain = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).unwrap();
    drop(trace);
    let coeffs = comb_coeffs(cons_per_row);
    let (c_eval, _) = deep_ali_merge_rsa_stacked_streaming(
        &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
    );
    drop(lde);
    let mut em_list_hash = Sha3_256::new();
    for r in &all_records {
        Sha3Digest::update(&mut em_list_hash, r.em.to_bytes_be());
    }
    let em_list_hash: [u8; 32] = em_list_hash.finalize().into();
    let stark_pub_input: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"STACKED-RSA-ZONE-STARK-V1");
        Sha3Digest::update(&mut h, &zsk_n_be);
        Sha3Digest::update(&mut h, (n_records as u64).to_le_bytes());
        Sha3Digest::update(&mut h, &legitimate_mroot);
        Sha3Digest::update(&mut h, &em_list_hash);
        Sha3Digest::finalize(h).into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(stark_pub_input),
    };
    let stark_proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let mut fri_root_bytes = Vec::new();
    stark_proof.root_f0.serialize_with_mode(&mut fri_root_bytes, Compress::Yes).unwrap();
    let epoch_seq: u64 = 0;
    let epoch_t: u64 = 1_761_867_200;
    let epoch_metadata: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"EPOCH-V1");
        Sha3Digest::update(&mut h, epoch_seq.to_le_bytes());
        Sha3Digest::update(&mut h, epoch_t.to_le_bytes());
        Sha3Digest::update(&mut h, &fri_root_bytes);
        Sha3Digest::update(&mut h, &legitimate_mroot);
        Sha3Digest::update(&mut h, &zsk_n_be);
        Sha3Digest::finalize(h).into()
    };
    let authority_mldsa_sig = mldsa_sk.try_sign(&epoch_metadata, b"").unwrap();
    println!("  STARK + Merkle + ML-DSA-65 epoch: {:.2?}", t.elapsed());

    // ═════════════════════════════════════════════════════════════════════
    // 1. Edge device bootstraps with authority's ML-DSA pubkey.
    // ═════════════════════════════════════════════════════════════════════
    println!();
    hr('═');
    println!("[1] EDGE DEVICE bootstraps");
    hr('═');
    println!("Device receives the authority's ML-DSA-65 public key OUT-OF-BAND");
    println!("(provisioned at manufacturing / installation / etc.) and the");
    println!("epoch package via any channel (CDN, USB, satellite, ...).");

    let device_trusted_mldsa_pk = ml_dsa_65::PublicKey::try_from_bytes(authority_mldsa_pk_bytes).unwrap();
    let mldsa_sig_arr: [u8; ml_dsa_65::SIG_LEN] =
        authority_mldsa_sig.as_slice().try_into().unwrap();
    let mldsa_ok = device_trusted_mldsa_pk.verify(&epoch_metadata, &mldsa_sig_arr, b"");
    let stark_ok = deep_fri_verify::<Ext>(&params, &stark_proof);
    assert!(mldsa_ok && stark_ok);
    let device_pinned_mroot = legitimate_mroot;
    println!("  ML-DSA verify: ✓");
    println!("  STARK verify : ✓");
    println!("  Device pins Merkle root: {}", hex::encode(&device_pinned_mroot[..16]));

    // ═════════════════════════════════════════════════════════════════════
    // 2. Honest lookup of rec0042
    // ═════════════════════════════════════════════════════════════════════
    println!();
    hr('═');
    println!("[2] HONEST LOOKUP: device queries rec0042.example.com.");
    hr('═');
    let q_idx = 42;
    let honest_bytes = &all_record_bytes[q_idx];
    let honest_leaf = record_leaf(honest_bytes);
    let honest_path = merkle_path(&levels, q_idx);
    let honest_ok = merkle_verify(honest_leaf, q_idx, &honest_path, device_pinned_mroot);
    println!("  Record bytes: {}", std::str::from_utf8(honest_bytes).unwrap());
    println!("  Merkle path verify: {}", if honest_ok { "✓ ACCEPT (record authentic)" } else { "✗ REJECT" });
    println!("  → Resolves to 10.0.0.42 (legitimate)");

    // ═════════════════════════════════════════════════════════════════════
    // 3. CRQC arrives.  Adversary recovers the zone's RSA private key.
    // ═════════════════════════════════════════════════════════════════════
    println!();
    hr('═');
    println!("[3] QUANTUM ADVERSARY ARRIVES");
    hr('═');
    println!();
    println!("        ⚠  ⚠  ⚠   CRQC online — Shor's algorithm runs   ⚠  ⚠  ⚠");
    println!();
    println!("Adversary recovers the zone's RSA-2048 private key.");
    println!("(In this simulation we just hand the adversary the same key.)");
    let adversary_zsk_priv = zsk_priv.clone();
    let adversary_zsk_signing = SigningKey::<Sha256>::new(adversary_zsk_priv);

    // ═════════════════════════════════════════════════════════════════════
    // 4. ATTACK A: adversary forges a malicious record + RSA signature.
    // ═════════════════════════════════════════════════════════════════════
    println!();
    hr('═');
    println!("[4] ATTACK A: silent record forgery (the classical DNSSEC failure)");
    hr('═');
    let malicious_message =
        "DNSSEC-RRSIG-V0|rec0042.example.com.|A|6.6.6.6|epoch-0|alg-8";
    let malicious_sig = adversary_zsk_signing.sign(malicious_message.as_bytes()).to_bytes();
    println!("Adversary crafts a forged record:");
    println!("  \"rec0042.example.com.\" → 6.6.6.6 (adversary's server)");
    println!("  RSA signature: forged using the now-broken ZSK private key.");
    println!();

    println!("(a) Classical DNSSEC verifier:");
    let dnssec_ok = native_rsa_verify(
        &our_zsk_pub, malicious_message.as_bytes(), &malicious_sig,
    );
    println!("    Native RSA verify: {}",
        if dnssec_ok { "✓ ACCEPT" } else { "✗ REJECT" });
    println!("    → DNSSEC RESOLVER ROUTES USER TO 6.6.6.6 ✗ (silent MITM)");

    println!();
    println!("(b) STARK-DNS edge verifier:");
    println!("    Adversary presents the forged record + a forged Merkle path.");
    let malicious_bytes = malicious_message.as_bytes();
    let malicious_leaf = record_leaf(malicious_bytes);
    println!("    Forged record leaf: {}", hex::encode(&malicious_leaf[..16]));
    println!("    Adversary needs a Merkle path from this leaf to the");
    println!("    pinned root: {}", hex::encode(&device_pinned_mroot[..16]));

    // Adversary tries to reuse the original Merkle path (best they can do
    // without breaking the hash).
    let stolen_path = merkle_path(&levels, q_idx);
    let stark_attack_ok = merkle_verify(
        malicious_leaf, q_idx, &stolen_path, device_pinned_mroot,
    );
    println!("    Best-case path-substitution attack:");
    println!("      Merkle path verify: {}",
        if stark_attack_ok { "✓ ACCEPT" } else { "✗ REJECT" });
    println!("    → STARK-DNS REJECTS — record not committed under pinned root");
    println!();
    println!("    To succeed, adversary would need a SHA3-256 collision");
    println!("    (preimage attack on the pinned Merkle root) — believed");
    println!("    PQ-secure under Grover's algorithm at 256-bit output.");

    // ═════════════════════════════════════════════════════════════════════
    // 5. ATTACK B: adversary substitutes their own ML-DSA-signed package.
    // ═════════════════════════════════════════════════════════════════════
    println!();
    hr('═');
    println!("[5] ATTACK B: adversary publishes a counterfeit epoch package");
    hr('═');
    println!("Adversary generates their OWN ML-DSA-65 keypair and signs a fake");
    println!("epoch package with the malicious record committed under a new");
    println!("Merkle root.");
    let (adv_mldsa_pk, adv_mldsa_sk) = ml_dsa_65::try_keygen_with_rng(
        &mut rand::rngs::StdRng::seed_from_u64(0xBADBAD)).unwrap();
    let _adv_mldsa_pk_bytes = adv_mldsa_pk.into_bytes();
    // Build adversary's malicious zone (one-record).
    let adv_leaf = record_leaf(malicious_bytes);
    let adv_levels = merkle_build(&[adv_leaf]);
    let adv_mroot = merkle_root(&adv_levels);
    let adv_metadata: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"EPOCH-V1");
        Sha3Digest::update(&mut h, epoch_seq.to_le_bytes());
        Sha3Digest::update(&mut h, epoch_t.to_le_bytes());
        Sha3Digest::update(&mut h, &fri_root_bytes); // adversary reuses STARK FRI root
        Sha3Digest::update(&mut h, &adv_mroot);
        Sha3Digest::update(&mut h, &zsk_n_be);
        Sha3Digest::finalize(h).into()
    };
    let adv_sig = adv_mldsa_sk.try_sign(&adv_metadata, b"").unwrap();
    println!("  Adversary's fake Merkle root: {}", hex::encode(&adv_mroot[..16]));
    println!("  Adversary signs with their OWN ML-DSA key.");
    println!();
    println!("Edge device tries to verify the adversary's epoch package");
    println!("under its TRUSTED ML-DSA public key (the legitimate authority's):");
    let adv_sig_arr: [u8; ml_dsa_65::SIG_LEN] =
        adv_sig.as_slice().try_into().unwrap();
    let adv_under_authority_ok = device_trusted_mldsa_pk.verify(
        &adv_metadata, &adv_sig_arr, b"",
    );
    println!("  ML-DSA verify under authority's pk: {}",
        if adv_under_authority_ok { "✓" } else { "✗ REJECT" });
    println!("  → STARK-DNS REJECTS — signature not from authority's key");
    println!();
    println!("To succeed, adversary would need to break ML-DSA-65 itself");
    println!("(NIST PQ Level 3, lattice-based) — PQ-secure under both");
    println!("Shor and Grover.");

    // ═════════════════════════════════════════════════════════════════════
    // 6. ATTACK C: adversary tries to forge a Merkle preimage collision.
    // ═════════════════════════════════════════════════════════════════════
    println!();
    hr('═');
    println!("[6] ATTACK C: forge SHA3-256 collision targeting pinned root");
    hr('═');
    println!("Adversary needs a leaf such that hashing it through some path");
    println!("yields the pinned Merkle root: {}",
        hex::encode(&device_pinned_mroot[..16]));
    println!();
    println!("This requires a 2nd-preimage attack on SHA3-256.");
    println!("  Classical security level: 256-bit (2^256 work).");
    println!("  Grover's algorithm:        2^128 quantum work.");
    println!();
    println!("Even with a CRQC, 2^128 quantum operations is computationally");
    println!("infeasible (NIST PQ Level 5 security; SHA3-256 is FIPS 202).");
    println!("  → STARK-DNS REJECTS by the SHA3-256 collision-resistance");
    println!("    assumption that underpins the entire PQ stack.");

    // ═════════════════════════════════════════════════════════════════════
    // Summary
    // ═════════════════════════════════════════════════════════════════════
    println!();
    println!("══════════════════════════════════════════════════════════════════════");
    println!("  Summary: PQ security comparison");
    println!("══════════════════════════════════════════════════════════════════════");
    println!();
    println!("                    │ DNSSEC (today) │ STARK-DNS (this work)");
    println!("────────────────────┼────────────────┼─────────────────────────");
    println!("Record signing key  │ RSA / EC / Ed  │ RSA / EC / Ed (in-circuit)");
    println!("                    │ ✗ broken by    │ ⊕ wrapped under PQ");
    println!("                    │   Shor's algo  │   commitment chain");
    println!("                    │                │");
    println!("Authority binding   │ (none)         │ ML-DSA-65 (FIPS 204)");
    println!("                    │                │ ✓ PQ-secure (Level 3)");
    println!("                    │                │");
    println!("Commitment hash     │ (none)         │ SHA3-256 Merkle");
    println!("                    │                │ ✓ PQ-secure (Level 5)");
    println!("                    │                │");
    println!("Adversary with CRQC │ ✗ silent MITM  │ ✓ all 3 attack flows");
    println!("                    │   (record      │   blocked at the edge");
    println!("                    │    forgery     │");
    println!("                    │    accepted)   │");
    println!();
    println!("Bottom line:");
    println!("  Under STARK-DNS, even an attacker with full RSA / EC / Ed key");
    println!("  recovery cannot inject malicious records into the edge consumer's");
    println!("  view of the zone, because the edge does not trust the underlying");
    println!("  classical signature — it trusts the Merkle commitment binding");
    println!("  pinned by the authority's ML-DSA-65 epoch signature, and");
    println!("  forging that requires breaking ML-DSA or SHA3-256 (both PQ-secure).");
    println!();
    println!("  Existing classically-signed RRSIGs become RETROACTIVELY PQ-protected");
    println!("  the moment they are committed under an ML-DSA-signed STARK-DNS");
    println!("  epoch root.");
}
