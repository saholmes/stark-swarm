//! Airgapped DNS resolver demo.
//!
//! Concrete demonstration of the offline-resilient property:
//!   1. Authority publishes a self-contained zone bundle to disk
//!      (epoch package + record bytes + Merkle tree levels).
//!   2. **Simulated network outage**: device reads the bundle once,
//!      then operates with NO network access.
//!   3. Device resolves $M$ random DNS queries entirely from
//!      cached state, with full cryptographic verification per
//!      query.
//!
//! All bytes that flow into the device are signed/proven artefacts;
//! no trust is placed in the storage medium (could be a USB stick
//! delivered by mail).
//!
//! Run:
//!     N=50 M=1000 cargo run --release -p swarm-dns --example airgapped_resolver_demo

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::time::Instant;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as MlDsaSigner, Verifier as MlDsaVerifier};
use num_bigint::BigUint;
use rand::{Rng, SeedableRng};
use sha2::Digest as ShaDigest;
use sha3::{Digest as Sha3Digest, Sha3_256};

use deep_ali::{
    deep_ali_merge_rsa_stacked_streaming,
    fri::{
        deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify,
        DeepFriParams, DeepFriProof, FriDomain,
    },
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
    if b >= 1024 * 1024 { format!("{:.2} MiB", b as f64 / (1024.0 * 1024.0)) }
    else if b >= 1024 { format!("{:.2} KiB", b as f64 / 1024.0) }
    else { format!("{} B", b) }
}

fn write_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_le_bytes()); }
fn read_u32(buf: &[u8], off: &mut usize) -> u32 {
    let v = u32::from_le_bytes(buf[*off..*off + 4].try_into().unwrap());
    *off += 4;
    v
}

fn main() {
    println!("==============================================================");
    println!(" Airgapped DNS resolver demo");
    println!("==============================================================");
    println!();

    let n_records: usize = std::env::var("N").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(50);
    let m_queries: usize = std::env::var("M").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(1000);
    let bundle_path = "/tmp/airgap_zone.bin";

    // ─────────────────────────────────────────────────────────────
    // PHASE 1: Authority side
    // ─────────────────────────────────────────────────────────────
    println!("┌────────────────────────────────────────────────────────────┐");
    println!("│ PHASE 1: DNS authority builds + signs epoch package        │");
    println!("└────────────────────────────────────────────────────────────┘");
    println!("Zone: N = {} records (RSA-2048-signed RRSIGs)", n_records);
    println!();

    use rsa::{
        pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding},
        traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey,
    };
    use sha2::Sha256;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE_BABE);
    let zsk_priv = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let zsk_pub = RsaPublicKey::from(&zsk_priv);
    let zsk_n_be = zsk_pub.n().to_bytes_be();
    let zsk_signing = SigningKey::<Sha256>::new(zsk_priv);
    let our_zsk_pub = RsaPublic::from_n_be(&zsk_n_be);

    let (mldsa_pk, mldsa_sk) = ml_dsa_65::try_keygen_with_rng(
        &mut rand::rngs::StdRng::seed_from_u64(0xC0FFEE)).unwrap();
    let mldsa_pk_bytes = mldsa_pk.into_bytes();

    println!(">>> Step 1.1: sign {} records + build Merkle tree", n_records);
    let t = Instant::now();
    let mut record_bytes_list: Vec<Vec<u8>> = Vec::with_capacity(n_records);
    let mut record_ips: Vec<[u8; 4]> = Vec::with_capacity(n_records);
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(n_records);
    let mut stacked_records: Vec<RsaStackedRecord> = Vec::with_capacity(n_records);
    for i in 0..n_records {
        let domain = format!("rec{:04}.example.com.", i);
        let ip = [10, 0, (i / 256) as u8, (i % 256) as u8];
        let message = format!(
            "DNSSEC-RRSIG-V0|{}|A|{}.{}.{}.{}|epoch-0|alg-8",
            domain, ip[0], ip[1], ip[2], ip[3]
        );
        let signature = zsk_signing.sign(message.as_bytes());
        let sig_bytes = signature.to_bytes();
        assert!(native_rsa_verify(&our_zsk_pub, message.as_bytes(), &sig_bytes));

        let mut digest = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        digest.copy_from_slice(&hasher.finalize());
        let em = emsa_pkcs1_v1_5_encode_sha256(&digest, 256).unwrap();

        let rec_full = message.into_bytes();
        leaves.push(record_leaf(&rec_full));
        record_bytes_list.push(rec_full);
        record_ips.push(ip);

        stacked_records.push(RsaStackedRecord {
            n:  BigUint::from_bytes_be(&zsk_n_be),
            s:  BigUint::from_bytes_be(&sig_bytes),
            em: BigUint::from_bytes_be(&em),
        });
    }
    let levels = merkle_build(&leaves);
    let mroot = merkle_root(&levels);
    println!("    {:.2?}  Merkle root = {}", t.elapsed(), hex::encode(&mroot[..8]));

    println!();
    println!(">>> Step 1.2: stacked-AIR STARK over all {} signatures", n_records);
    const N_TRACE: usize = 32;
    let layout = build_rsa_stacked_layout(n_records);
    let cons_per_row = rsa_stacked_constraints(&layout);
    let n0 = N_TRACE * BLOWUP;
    println!("    cells/row     = {}", layout.width);
    println!("    constraints   = {}", cons_per_row);
    println!("    n_0           = {}", n0);

    let mut trace: Vec<Vec<F>> = (0..layout.width)
        .map(|_| vec![F::zero(); N_TRACE]).collect();
    let t = Instant::now();
    fill_rsa_stacked(&mut trace, &layout, N_TRACE, &stacked_records);
    let fill_dur = t.elapsed();

    let domain = FriDomain::new_radix2(n0);
    let t = Instant::now();
    let lde = lde_trace_columns(&trace, N_TRACE, BLOWUP).unwrap();
    let lde_dur = t.elapsed();
    drop(trace);

    let coeffs = comb_coeffs(cons_per_row);
    let t = Instant::now();
    let (c_eval, _) = deep_ali_merge_rsa_stacked_streaming(
        &lde, &coeffs, &layout, domain.omega, N_TRACE, BLOWUP,
    );
    let merge_dur = t.elapsed();
    drop(lde);

    let mut em_list_hash = Sha3_256::new();
    for rec in &stacked_records {
        Sha3Digest::update(&mut em_list_hash, rec.em.to_bytes_be());
    }
    let em_list_hash: [u8; 32] = em_list_hash.finalize().into();

    let stark_pub_input: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"STACKED-RSA-ZONE-STARK-V1");
        Sha3Digest::update(&mut h, &zsk_n_be);
        Sha3Digest::update(&mut h, (n_records as u64).to_le_bytes());
        Sha3Digest::update(&mut h, &mroot);
        Sha3Digest::update(&mut h, &em_list_hash);
        Sha3Digest::finalize(h).into()
    };
    let params = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(stark_pub_input),
    };
    let t = Instant::now();
    let stark_proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let prove_dur = t.elapsed();
    println!("    fill={:.2?}  LDE={:.2?}  merge={:.2?}  prove={:.2?}",
        fill_dur, lde_dur, merge_dur, prove_dur);

    let stark_proof_bytes = deep_fri_proof_size_bytes::<Ext>(&stark_proof, params.stir);
    let mut stark_blob = Vec::with_capacity(stark_proof_bytes);
    stark_proof.serialize_with_mode(&mut stark_blob, Compress::Yes).unwrap();
    let mut fri_root_bytes = Vec::new();
    stark_proof.root_f0.serialize_with_mode(&mut fri_root_bytes, Compress::Yes).unwrap();

    println!();
    println!(">>> Step 1.3: ML-DSA-65 sign epoch package");
    let epoch_seq: u64 = 0;
    let epoch_t: u64 = 1_761_867_200;
    let epoch_metadata: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"EPOCH-V1");
        Sha3Digest::update(&mut h, epoch_seq.to_le_bytes());
        Sha3Digest::update(&mut h, epoch_t.to_le_bytes());
        Sha3Digest::update(&mut h, &fri_root_bytes);
        Sha3Digest::update(&mut h, &mroot);
        Sha3Digest::update(&mut h, &zsk_n_be);
        Sha3Digest::finalize(h).into()
    };
    let mldsa_sig = mldsa_sk.try_sign(&epoch_metadata, b"").unwrap();
    println!("    ML-DSA-65 sig = {} bytes", mldsa_sig.len());

    println!();
    println!(">>> Step 1.4: serialize zone bundle to disk: {}", bundle_path);
    let mut bundle = Vec::new();
    bundle.extend_from_slice(b"AIRGAP-V1");
    write_u32(&mut bundle, n_records as u32);
    // Epoch package.
    write_u32(&mut bundle, mldsa_pk_bytes.len() as u32);
    bundle.extend_from_slice(&mldsa_pk_bytes);
    write_u32(&mut bundle, zsk_n_be.len() as u32);
    bundle.extend_from_slice(&zsk_n_be);
    write_u32(&mut bundle, mldsa_sig.len() as u32);
    bundle.extend_from_slice(&mldsa_sig);
    bundle.extend_from_slice(&fri_root_bytes); // 32 bytes (Goldilocks F)
    bundle.extend_from_slice(&mroot);          // 32 bytes
    bundle.extend_from_slice(&em_list_hash);   // 32 bytes
    bundle.extend_from_slice(&epoch_seq.to_le_bytes());
    bundle.extend_from_slice(&epoch_t.to_le_bytes());
    write_u32(&mut bundle, stark_blob.len() as u32);
    bundle.extend_from_slice(&stark_blob);
    // Merkle tree: depth + each level's hashes.
    let merkle_depth = levels.len();
    write_u32(&mut bundle, merkle_depth as u32);
    for level in &levels {
        write_u32(&mut bundle, level.len() as u32);
        for h in level {
            bundle.extend_from_slice(h);
        }
    }
    // Record bytes (length-prefixed).
    write_u32(&mut bundle, n_records as u32);
    for r in &record_bytes_list {
        write_u32(&mut bundle, r.len() as u32);
        bundle.extend_from_slice(r);
    }
    fs::write(bundle_path, &bundle).unwrap();
    println!("    bundle size   = {}", fmt_size(bundle.len()));

    let break_idx = bundle.iter().position(|&b| b == b'\0').unwrap_or(bundle.len());
    let _ = break_idx;
    println!();
    println!("              ✂  ✂  ✂   NETWORK OUTAGE   ✂  ✂  ✂");
    println!("       (everything from this point uses ONLY local files)");
    println!();

    // ─────────────────────────────────────────────────────────────
    // PHASE 2: Airgapped device boot
    // ─────────────────────────────────────────────────────────────
    println!("┌────────────────────────────────────────────────────────────┐");
    println!("│ PHASE 2: airgapped device — load bundle from disk          │");
    println!("└────────────────────────────────────────────────────────────┘");

    let t_boot = Instant::now();
    let mut f = fs::File::open(bundle_path).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    let mut off = 0usize;

    assert_eq!(&buf[off..off + 9], b"AIRGAP-V1"); off += 9;
    let n_records_in = read_u32(&buf, &mut off) as usize;
    assert_eq!(n_records_in, n_records);

    let mldsa_pk_len = read_u32(&buf, &mut off) as usize;
    let mldsa_pk_b: [u8; ml_dsa_65::PK_LEN] =
        buf[off..off + mldsa_pk_len].try_into().unwrap();
    off += mldsa_pk_len;
    let zsk_n_len = read_u32(&buf, &mut off) as usize;
    let zsk_n_loaded = buf[off..off + zsk_n_len].to_vec();
    off += zsk_n_len;
    let mldsa_sig_len = read_u32(&buf, &mut off) as usize;
    let mldsa_sig_loaded: [u8; ml_dsa_65::SIG_LEN] =
        buf[off..off + mldsa_sig_len].try_into().unwrap();
    off += mldsa_sig_len;
    let fri_root_loaded = buf[off..off + 32].to_vec(); off += 32;
    let mroot_loaded: [u8; 32] = buf[off..off + 32].try_into().unwrap(); off += 32;
    let em_list_hash_loaded: [u8; 32] = buf[off..off + 32].try_into().unwrap(); off += 32;
    let epoch_seq_loaded = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;
    let epoch_t_loaded = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;
    let stark_blob_len = read_u32(&buf, &mut off) as usize;
    let stark_blob_loaded = buf[off..off + stark_blob_len].to_vec();
    off += stark_blob_len;

    let merkle_depth_loaded = read_u32(&buf, &mut off) as usize;
    let mut levels_loaded: Vec<Vec<[u8; 32]>> = Vec::with_capacity(merkle_depth_loaded);
    for _ in 0..merkle_depth_loaded {
        let lvl_len = read_u32(&buf, &mut off) as usize;
        let mut lvl = Vec::with_capacity(lvl_len);
        for _ in 0..lvl_len {
            lvl.push(buf[off..off + 32].try_into().unwrap());
            off += 32;
        }
        levels_loaded.push(lvl);
    }
    let n_recs_in = read_u32(&buf, &mut off) as usize;
    assert_eq!(n_recs_in, n_records);
    let mut records_loaded: Vec<Vec<u8>> = Vec::with_capacity(n_records);
    for _ in 0..n_records {
        let rl = read_u32(&buf, &mut off) as usize;
        records_loaded.push(buf[off..off + rl].to_vec());
        off += rl;
    }
    let load_dur = t_boot.elapsed();
    println!("    bundle loaded in {:.2?}", load_dur);

    println!();
    println!(">>> Step 2.1: ML-DSA-65 verify epoch package");
    let t = Instant::now();
    let recomputed_metadata: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"EPOCH-V1");
        Sha3Digest::update(&mut h, epoch_seq_loaded.to_le_bytes());
        Sha3Digest::update(&mut h, epoch_t_loaded.to_le_bytes());
        Sha3Digest::update(&mut h, &fri_root_loaded);
        Sha3Digest::update(&mut h, &mroot_loaded);
        Sha3Digest::update(&mut h, &zsk_n_loaded);
        Sha3Digest::finalize(h).into()
    };
    let mldsa_pk_decoded = ml_dsa_65::PublicKey::try_from_bytes(mldsa_pk_b).unwrap();
    let mldsa_ok = mldsa_pk_decoded.verify(&recomputed_metadata, &mldsa_sig_loaded, b"");
    let mldsa_dur = t.elapsed();
    println!("    {:.2?}  {}", mldsa_dur, if mldsa_ok { "✓" } else { "FAIL" });
    assert!(mldsa_ok);

    println!();
    println!(">>> Step 2.2: STARK FRI verify");
    let t = Instant::now();
    let stark_proof_loaded = DeepFriProof::<Ext>::deserialize_with_mode(
        &stark_blob_loaded[..], Compress::Yes, Validate::Yes,
    ).unwrap();
    let recomputed_pub_input: [u8; 32] = {
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, b"STACKED-RSA-ZONE-STARK-V1");
        Sha3Digest::update(&mut h, &zsk_n_loaded);
        Sha3Digest::update(&mut h, (n_records as u64).to_le_bytes());
        Sha3Digest::update(&mut h, &mroot_loaded);
        Sha3Digest::update(&mut h, &em_list_hash_loaded);
        Sha3Digest::finalize(h).into()
    };
    let params_loaded = DeepFriParams {
        schedule: make_schedule_stir(n0), r: NUM_QUERIES, seed_z: SEED_Z,
        coeff_commit_final: true, d_final: 1, stir: true, s0: NUM_QUERIES,
        public_inputs_hash: Some(recomputed_pub_input),
    };
    let stark_ok = deep_fri_verify::<Ext>(&params_loaded, &stark_proof_loaded);
    let stark_verify_dur = t.elapsed();
    println!("    {:.2?}  {}", stark_verify_dur, if stark_ok { "✓" } else { "FAIL" });
    assert!(stark_ok);

    println!();
    println!(">>> Step 2.3: build local lookup table (domain → leaf-index)");
    let t = Instant::now();
    let mut domain_to_idx: HashMap<String, usize> = HashMap::with_capacity(n_records);
    for (i, r) in records_loaded.iter().enumerate() {
        let s = std::str::from_utf8(r).unwrap();
        // Parse "DNSSEC-RRSIG-V0|<domain>|A|<ip>|epoch-0|alg-8"
        let parts: Vec<&str> = s.split('|').collect();
        domain_to_idx.insert(parts[1].to_string(), i);
    }
    println!("    {:.2?}", t.elapsed());

    let total_boot_dur = t_boot.elapsed();
    println!();
    println!("    Total boot time: {:.2?} (one-time per epoch)", total_boot_dur);

    // ─────────────────────────────────────────────────────────────
    // PHASE 3: Airgapped DNS resolution
    // ─────────────────────────────────────────────────────────────
    println!();
    println!("┌────────────────────────────────────────────────────────────┐");
    println!("│ PHASE 3: resolve {} random DNS queries (offline)         │", m_queries);
    println!("└────────────────────────────────────────────────────────────┘");

    let mut query_rng = rand::rngs::StdRng::seed_from_u64(0x1234);
    let domains: Vec<String> = domain_to_idx.keys().cloned().collect();
    let mut total_query_ns: u128 = 0;
    let mut min_ns: u128 = u128::MAX;
    let mut max_ns: u128 = 0;
    let mut all_ok = true;

    for q in 0..m_queries {
        let dom = &domains[query_rng.gen_range(0..domains.len())];
        let t = Instant::now();
        // Look up.
        let idx = *domain_to_idx.get(dom).unwrap();
        // Compute leaf hash.
        let leaf = record_leaf(&records_loaded[idx]);
        // Build path.
        let path = merkle_path(&levels_loaded, idx);
        // Verify.
        let ok = merkle_verify(leaf, idx, &path, mroot_loaded);
        let dt = t.elapsed().as_nanos();
        total_query_ns += dt;
        min_ns = min_ns.min(dt);
        max_ns = max_ns.max(dt);
        all_ok &= ok;
        if q < 3 {
            // Show the parsed IP for the first few queries.
            let s = std::str::from_utf8(&records_loaded[idx]).unwrap();
            let ip_part = s.split('|').nth(3).unwrap();
            println!("    query[{:>4}] {:>30} → {}  ({} ns) {}",
                q, dom, ip_part, dt, if ok { "✓" } else { "FAIL" });
        }
    }
    if m_queries > 3 {
        println!("    ... ({} more queries)", m_queries - 3);
    }

    let avg_ns = total_query_ns as f64 / m_queries as f64;
    println!();
    println!("Per-query stats (M = {}):", m_queries);
    println!("    avg = {:.0} ns ({:.3} µs)", avg_ns, avg_ns / 1000.0);
    println!("    min = {} ns", min_ns);
    println!("    max = {} ns ({:.2} µs)", max_ns, max_ns as f64 / 1000.0);
    println!("    cumulative = {} ns ({:.2} ms)",
        total_query_ns, total_query_ns as f64 / 1_000_000.0);
    println!("    all verify: {}", if all_ok { "✓" } else { "FAIL" });
    assert!(all_ok);

    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!(" SUMMARY — DNS resolves {}× with NO network access ✓", m_queries);
    println!("══════════════════════════════════════════════════════════════");
    println!();
    println!("Bundle on disk:                {}", fmt_size(bundle.len()));
    println!("Once-per-epoch boot:           {:.2?} (parse+ML-DSA+STARK)", total_boot_dur);
    println!("    parse                    : {:.2?}", load_dur);
    println!("    ML-DSA verify            : {:.2?}", mldsa_dur);
    println!("    STARK verify             : {:.2?}", stark_verify_dur);
    println!();
    println!("Per-query DNS resolution (offline):");
    println!("    avg lookup + Merkle      : {:.3} µs", avg_ns / 1000.0);
    println!("    {} queries cumulative   : {:.2} ms",
        m_queries, total_query_ns as f64 / 1_000_000.0);
    println!();
    println!("Trust model: device trusts the DNS authority's ML-DSA-65 key.");
    println!("Storage medium is untrusted — bundle bytes are self-authenticating.");
    println!("All {} DNS queries answered with full crypto verification, no", m_queries);
    println!("network access required.");
    println!();
    println!("Cleanup: rm {}", bundle_path);
    let _ = fs::remove_file(bundle_path);
}
