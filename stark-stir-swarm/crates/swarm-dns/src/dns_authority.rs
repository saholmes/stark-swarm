//! Authority signing layer for the DNS rollup demo.
//!
//! Closes the trust model on the privacy-preserving DNS rollup: the zone
//! authority signs the rolled-up STARK with a post-quantum ML-DSA key,
//! and the authority's public key is bound into the STARK's Fiat-Shamir
//! transcript via `public_inputs_hash` so a relying party cannot accept
//! a substituted (proof, sig, pk) bundle.
//!
//! NIST PQ level → ML-DSA parameter set → SHA3 digest variant:
//!
//! | NIST Level | ML-DSA      | Hash for signed digest |
//! |------------|-------------|------------------------|
//! | L1         | ML-DSA-44   | SHA3-256               |
//! | L3         | ML-DSA-65   | SHA3-384               |
//! | L5         | ML-DSA-87   | SHA3-512               |
//!
//! The "hash for signed digest" is the SHA3 variant the user picks for
//! the STARK profile — the same hash is used to compute the message that
//! the authority then signs, so the entire authentication chain runs at
//! one consistent NIST level.

use fips204::traits::{SerDes, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use rand::{rngs::StdRng, SeedableRng};
use sha3::{Digest, Sha3_256, Sha3_384, Sha3_512};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NistLevel {
    L1,
    L3,
    L5,
}

impl NistLevel {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "1" => Ok(Self::L1),
            "3" => Ok(Self::L3),
            "5" => Ok(Self::L5),
            other => Err(format!("invalid NIST level '{other}' (expected 1, 3, or 5)")),
        }
    }
    pub fn ml_dsa_name(self) -> &'static str {
        match self {
            Self::L1 => "ML-DSA-44",
            Self::L3 => "ML-DSA-65",
            Self::L5 => "ML-DSA-87",
        }
    }
    pub fn hash_name(self) -> &'static str {
        match self {
            Self::L1 => "SHA3-256",
            Self::L3 => "SHA3-384",
            Self::L5 => "SHA3-512",
        }
    }
    pub fn digest_size(self) -> usize {
        match self {
            Self::L1 => 32,
            Self::L3 => 48,
            Self::L5 => 64,
        }
    }
    pub fn pk_len(self) -> usize {
        match self {
            Self::L1 => ml_dsa_44::PK_LEN,
            Self::L3 => ml_dsa_65::PK_LEN,
            Self::L5 => ml_dsa_87::PK_LEN,
        }
    }
    pub fn sig_len(self) -> usize {
        match self {
            Self::L1 => ml_dsa_44::SIG_LEN,
            Self::L3 => ml_dsa_65::SIG_LEN,
            Self::L5 => ml_dsa_87::SIG_LEN,
        }
    }
}

/// Hash a sequence of byte slices using the SHA3 variant matching the NIST level.
/// Output length: 32 / 48 / 64 bytes for L1 / L3 / L5.
pub fn level_hash(level: NistLevel, parts: &[&[u8]]) -> Vec<u8> {
    match level {
        NistLevel::L1 => {
            let mut h = Sha3_256::new();
            for p in parts {
                Digest::update(&mut h, p);
            }
            Digest::finalize(h).to_vec()
        }
        NistLevel::L3 => {
            let mut h = Sha3_384::new();
            for p in parts {
                Digest::update(&mut h, p);
            }
            Digest::finalize(h).to_vec()
        }
        NistLevel::L5 => {
            let mut h = Sha3_512::new();
            for p in parts {
                Digest::update(&mut h, p);
            }
            Digest::finalize(h).to_vec()
        }
    }
}

/// 32-byte SHA3-256 binding hash of the authority public key, fed into
/// `DeepFriParams.public_inputs_hash` so it is absorbed into the STARK's
/// Fiat-Shamir transcript. Always 32 B regardless of NIST level — the
/// FS-transcript field is fixed-width and 256 bits is sufficient binding.
pub fn pk_binding_hash(pk_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, b"DNS-AUTHORITY-PK-V1");
    Digest::update(&mut h, pk_bytes);
    Digest::finalize(h).into()
}

/// ML-DSA keypair, statically dispatched per NIST level.
#[derive(Clone)]
pub enum AuthorityKeypair {
    L1 {
        pk: ml_dsa_44::PublicKey,
        sk: ml_dsa_44::PrivateKey,
    },
    L3 {
        pk: ml_dsa_65::PublicKey,
        sk: ml_dsa_65::PrivateKey,
    },
    L5 {
        pk: ml_dsa_87::PublicKey,
        sk: ml_dsa_87::PrivateKey,
    },
}

impl AuthorityKeypair {
    /// Deterministic keygen from a 32-byte seed — reproducible for the demo.
    pub fn keygen(level: NistLevel, seed: [u8; 32]) -> Self {
        let mut rng = StdRng::from_seed(seed);
        match level {
            NistLevel::L1 => {
                let (pk, sk) = ml_dsa_44::try_keygen_with_rng(&mut rng)
                    .expect("ML-DSA-44 keygen failed");
                Self::L1 { pk, sk }
            }
            NistLevel::L3 => {
                let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut rng)
                    .expect("ML-DSA-65 keygen failed");
                Self::L3 { pk, sk }
            }
            NistLevel::L5 => {
                let (pk, sk) = ml_dsa_87::try_keygen_with_rng(&mut rng)
                    .expect("ML-DSA-87 keygen failed");
                Self::L5 { pk, sk }
            }
        }
    }

    pub fn level(&self) -> NistLevel {
        match self {
            Self::L1 { .. } => NistLevel::L1,
            Self::L3 { .. } => NistLevel::L3,
            Self::L5 { .. } => NistLevel::L5,
        }
    }

    /// Encoded authority public key (length depends on NIST level).
    pub fn pk_bytes(&self) -> Vec<u8> {
        match self {
            Self::L1 { pk, .. } => pk.clone().into_bytes().to_vec(),
            Self::L3 { pk, .. } => pk.clone().into_bytes().to_vec(),
            Self::L5 { pk, .. } => pk.clone().into_bytes().to_vec(),
        }
    }

    /// Sign `message` (typically a level-matched SHA3 digest of the rollup
    /// commitment) under the secret key. Returns variable-length signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::L1 { sk, .. } => sk
                .try_sign(message, b"")
                .expect("ML-DSA-44 sign failed")
                .to_vec(),
            Self::L3 { sk, .. } => sk
                .try_sign(message, b"")
                .expect("ML-DSA-65 sign failed")
                .to_vec(),
            Self::L5 { sk, .. } => sk
                .try_sign(message, b"")
                .expect("ML-DSA-87 sign failed")
                .to_vec(),
        }
    }

    /// Verify `signature` over `message` under the public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::L1 { pk, .. } => {
                if signature.len() != ml_dsa_44::SIG_LEN {
                    return false;
                }
                let sig_arr: &[u8; ml_dsa_44::SIG_LEN] =
                    signature.try_into().expect("len checked");
                pk.verify(message, sig_arr, b"")
            }
            Self::L3 { pk, .. } => {
                if signature.len() != ml_dsa_65::SIG_LEN {
                    return false;
                }
                let sig_arr: &[u8; ml_dsa_65::SIG_LEN] =
                    signature.try_into().expect("len checked");
                pk.verify(message, sig_arr, b"")
            }
            Self::L5 { pk, .. } => {
                if signature.len() != ml_dsa_87::SIG_LEN {
                    return false;
                }
                let sig_arr: &[u8; ml_dsa_87::SIG_LEN] =
                    signature.try_into().expect("len checked");
                pk.verify(message, sig_arr, b"")
            }
        }
    }
}
