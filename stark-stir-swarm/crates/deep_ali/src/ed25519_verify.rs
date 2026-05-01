// ed25519_verify.rs — native end-to-end Ed25519 signature verification.
//
// Wires together every primitive built in earlier phases — SHA-512,
// F_{2^255-19} arithmetic, Edwards25519 group ops, scalar mult — into
// a complete RFC 8032 §5.1.7 verifier.  The result is a working
// `verify(pubkey, sig, msg) -> bool` whose internals match what the
// AIR will execute step-for-step in v1.
//
// Phase 5 sub-plan:
//   v0  ✓  native verify (this commit) + RFC 8032 test vectors
//   v1     AIR composition: hook the SHA-512 AIR, scalar-mult AIR, and
//          decompression / cofactor-check sub-traces into one trace
//          driven by a top-level `Ed25519VerifyAir` registry variant
//   v2     `swarm-dns::prove_zsk_ksk_binding` and verifier integration
//
// ─────────────────────────────────────────────────────────────────
// RFC 8032 VERIFY (cofactored)
// ─────────────────────────────────────────────────────────────────
//
// Inputs:
//   pubkey   — 32-byte compressed Edwards encoding of A
//   sig      — 64-byte (R_compressed || S_scalar) signature
//   message  — variable-length M
//
// Procedure:
//   1. Decompress R from sig[0..32]; reject on failure.
//   2. Decompress A from pubkey;     reject on failure.
//   3. Parse S from sig[32..64] as a canonical scalar (S < L); reject otherwise.
//   4. Compute k = SHA-512(R_compressed || A_compressed || M) mod L,
//      interpreting the SHA-512 output as a little-endian 512-bit integer.
//   5. Cofactored equality check:  [8] · ([S]·B − R − [k]·A) == identity.
//      Equivalently: [8]·[S]·B == [8]·R + [8]·[k]·A.
//
// All five steps use only the primitives in this crate's native ref:
//   sha512_air::sha512_native        — for SHA-512
//   ed25519_field::FieldElement      — for arithmetic mod p = 2^255 − 19
//   ed25519_group::EdwardsPoint      — for the curve operations
//   curve25519_dalek::Scalar         — only for scalar reduction mod L
//                                      (the group order); a native
//                                      reduction will land in v1.

#![allow(non_snake_case, dead_code)]

use crate::ed25519_group::EdwardsPoint;
use crate::ed25519_scalar::{is_canonical, reduce_mod_l_wide, scalar_bytes_to_bits_le};
use crate::sha512_air::sha512_native;

/// Verify an Ed25519 signature per RFC 8032 §5.1.7 (cofactored mode).
/// Returns `true` iff the signature is valid for `(pubkey, message)`.
///
/// Wholly native: SHA-512, F25519 arithmetic, Edwards25519 group ops,
/// and scalar reduction are all in-crate.  No `curve25519-dalek` /
/// `ed25519-dalek` runtime dependency.
pub fn verify(pubkey: &[u8; 32], sig: &[u8; 64], message: &[u8]) -> bool {
    // 1. Decompose signature.
    let r_compressed: [u8; 32] = sig[0..32].try_into().unwrap();
    let s_bytes:      [u8; 32] = sig[32..64].try_into().unwrap();

    // 2. Decompress R and A.
    let R = match EdwardsPoint::decompress(&r_compressed) {
        Some(p) => p,
        None    => return false,
    };
    let A = match EdwardsPoint::decompress(pubkey) {
        Some(p) => p,
        None    => return false,
    };

    // 3. Parse S as a canonical scalar (< L).
    if !is_canonical(&s_bytes) { return false; }

    // 4. Compute k = SHA-512(R || A || M) mod L.
    let mut buf = Vec::with_capacity(64 + message.len());
    buf.extend_from_slice(&r_compressed);
    buf.extend_from_slice(pubkey);
    buf.extend_from_slice(message);
    let digest = sha512_native(&buf);
    let k_bytes = reduce_mod_l_wide(&digest);

    // 5. Cofactored equality check:  [8] · ([s]·B − R − [k]·A) = identity.
    //    The two scalar mults are independent — fork them onto OS threads
    //    via std::thread::scope when the `parallel` feature is enabled.
    //    Typical 1.5–2× wall-clock win on a multi-core host since each
    //    mult is ~256 doublings + ~128 conditional adds on average.
    //    (rayon::join was tried first but didn't actually fork from a
    //    non-Rayon caller — std::thread::scope guarantees real threads.)
    let s_bits = scalar_bytes_to_bits_le(&s_bytes);
    let k_bits = scalar_bytes_to_bits_le(&k_bytes);

    // [s]·B uses the precomputed BASEPOINT_POW2_TABLE — skips the 256
    // doublings entirely.  [k]·A is variable-base so it still needs
    // the generic double-and-add.  When `parallel` is enabled, fork
    // the two onto OS threads.
    // [s]·B uses the precomputed BASEPOINT_POW2_TABLE in affine form
    // (one mul saved per add).  [k]·A uses a 4-bit windowed scalar
    // mult that builds 16 multiples of A on the fly and walks the
    // scalar in nibbles, halving the add count vs simple
    // double-and-add.  When `parallel` is enabled, fork the two onto
    // OS threads.
    #[cfg(feature = "parallel")]
    let (sB, kA) = std::thread::scope(|sc| {
        let h1 = sc.spawn(|| EdwardsPoint::scalar_mul_basepoint(&s_bits));
        let h2 = sc.spawn(|| A.scalar_mul_windowed(&k_bits));
        (h1.join().unwrap(), h2.join().unwrap())
    });
    #[cfg(not(feature = "parallel"))]
    let (sB, kA) = (
        EdwardsPoint::scalar_mul_basepoint(&s_bits),
        A.scalar_mul_windowed(&k_bits),
    );

    let residual = sB.sub(&R).sub(&kA);
    residual.mul_by_cofactor().is_identity()
}

// ═══════════════════════════════════════════════════════════════════
//  Tests — RFC 8032 §7.1 vectors + tamper-detection
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: hex string → fixed-size byte array.
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let bytes = hex::decode(s).expect("invalid hex");
        let mut out = [0u8; N];
        assert_eq!(bytes.len(), N, "hex length mismatch ({} vs {})", bytes.len(), N);
        out.copy_from_slice(&bytes);
        out
    }

    #[test]
    fn rfc8032_test1_empty_message() {
        // RFC 8032 §7.1, TEST 1.
        // SECRET KEY: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
        // (kept here only as reference; we don't need it for verify)
        let pubkey: [u8; 32] = hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig: [u8; 64] = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f\
             b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        let msg: &[u8] = b"";
        assert!(verify(&pubkey, &sig, msg),
            "RFC 8032 TEST 1 should verify");
    }

    #[test]
    fn rfc8032_test2_one_byte_message() {
        // RFC 8032 §7.1, TEST 2.
        let pubkey: [u8; 32] = hex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        let sig: [u8; 64] = hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085a\
             c1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        let msg: &[u8] = &hex::<1>("72");
        assert!(verify(&pubkey, &sig, msg),
            "RFC 8032 TEST 2 should verify");
    }

    #[test]
    fn rfc8032_test3_two_byte_message() {
        // RFC 8032 §7.1, TEST 3.
        let pubkey: [u8; 32] = hex(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        );
        let sig: [u8; 64] = hex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff\
             9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        );
        let msg: &[u8] = &hex::<2>("af82");
        assert!(verify(&pubkey, &sig, msg),
            "RFC 8032 TEST 3 should verify");
    }

    #[test]
    fn tamper_with_message_fails_verification() {
        let pubkey: [u8; 32] = hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig: [u8; 64] = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f\
             b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        // Original message was empty; flip to a one-byte message.
        let bad_msg: &[u8] = b"\x00";
        assert!(!verify(&pubkey, &sig, bad_msg),
            "verification should fail when the message changes");
    }

    #[test]
    fn tamper_with_signature_fails_verification() {
        let pubkey: [u8; 32] = hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let mut sig: [u8; 64] = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f\
             b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        // Flip a bit in S.
        sig[40] ^= 0x01;
        assert!(!verify(&pubkey, &sig, b""),
            "verification should fail when S is corrupted");
    }

    #[test]
    fn tamper_with_pubkey_fails_verification() {
        let mut pubkey: [u8; 32] = hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig: [u8; 64] = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f\
             b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        // Flip a bit in pubkey (low byte, far from sign bit).
        pubkey[3] ^= 0x01;
        assert!(!verify(&pubkey, &sig, b""),
            "verification should fail when pubkey is corrupted");
    }

}
