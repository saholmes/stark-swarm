//! Privacy-preserving DNS-record commitment helpers.
//!
//! Used by both the API integration test (`crates/api/tests/dns_rollup.rs`)
//! and the standalone megazone demo (`examples/dns_megazone_demo.rs`).
//!
//! The leaf hash committed in the STARK is **doubly salted**:
//!
//!   h1 = SHA3-256("DNS-LEAF-V1"        || salt || canonical(record))
//!   h2 = SHA3-256("DNS-LEAF-DOUBLE-V1" || salt || h1)
//!
//! Merkle internal nodes are domain-separated:
//!
//!   parent = SHA3-256("DNS-NODE-V1" || left || right)
//!
//! Inclusion proofs reveal only the leaf + log₂(N) sibling hashes.

use sha3::{Digest, Sha3_256};

pub const TAG_LEAF1: &[u8] = b"DNS-LEAF-V1";
pub const TAG_LEAF2: &[u8] = b"DNS-LEAF-DOUBLE-V1";
pub const TAG_NODE:  &[u8] = b"DNS-NODE-V1";

/// Minimal RFC-1035-shaped DNS record.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsRecord {
    pub domain:      String,
    pub record_type: u16,    // 1=A, 28=AAAA, 5=CNAME, 16=TXT, 15=MX, …
    pub ttl:         u32,
    pub rdata:       Vec<u8>,
}

impl DnsRecord {
    pub fn a   (d: &str, t: u32, ip: [u8; 4])         -> Self { Self{domain:d.into(),record_type:1, ttl:t,rdata:ip.to_vec()} }
    pub fn aaaa(d: &str, t: u32, ip: [u8; 16])        -> Self { Self{domain:d.into(),record_type:28,ttl:t,rdata:ip.to_vec()} }
    pub fn txt (d: &str, t: u32, s: &str)             -> Self { Self{domain:d.into(),record_type:16,ttl:t,rdata:s.as_bytes().to_vec()} }
    pub fn mx  (d: &str, t: u32, prio: u16, ex: &str) -> Self {
        let mut rd = prio.to_be_bytes().to_vec();
        rd.extend_from_slice(ex.as_bytes());
        Self { domain: d.into(), record_type: 15, ttl: t, rdata: rd }
    }

    /// Versioned, length-prefixed canonical encoding (no salt — salt is
    /// applied separately so the encoding is portable).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.domain.len() + self.rdata.len());
        out.extend_from_slice(b"DNS-RECORD-V1");
        out.extend_from_slice(&(self.domain.len() as u32).to_le_bytes());
        out.extend_from_slice(self.domain.as_bytes());
        out.extend_from_slice(&self.record_type.to_le_bytes());
        out.extend_from_slice(&self.ttl.to_le_bytes());
        out.extend_from_slice(&(self.rdata.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.rdata);
        out
    }

    pub fn h1(&self, salt: &[u8; 16]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        Digest::update(&mut h, TAG_LEAF1);
        Digest::update(&mut h, salt);
        Digest::update(&mut h, self.canonical_bytes());
        Digest::finalize(h).into()
    }

    /// Doubly-salted leaf hash.  This is what gets committed in the
    /// STARK and the Merkle tree.
    pub fn leaf_hash(&self, salt: &[u8; 16]) -> [u8; 32] {
        let h1 = self.h1(salt);
        let mut h = Sha3_256::new();
        Digest::update(&mut h, TAG_LEAF2);
        Digest::update(&mut h, salt);
        Digest::update(&mut h, h1);
        Digest::finalize(h).into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Domain-separated SHA3-256 binary Merkle tree
// ─────────────────────────────────────────────────────────────────────────────

pub fn merkle_build(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    assert!(!leaves.is_empty(), "merkle tree needs ≥ 1 leaf");
    let mut levels = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity((prev.len() + 1) / 2);
        for chunk in prev.chunks(2) {
            let l = chunk[0];
            let r = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            let mut h = Sha3_256::new();
            Digest::update(&mut h, TAG_NODE);
            Digest::update(&mut h, l);
            Digest::update(&mut h, r);
            next.push(Digest::finalize(h).into());
        }
        levels.push(next);
    }
    levels
}

pub fn merkle_root(levels: &[Vec<[u8; 32]>]) -> [u8; 32] {
    *levels.last().unwrap().first().unwrap()
}

pub fn merkle_path(levels: &[Vec<[u8; 32]>], leaf_index: usize) -> Vec<[u8; 32]> {
    let mut path = Vec::with_capacity(levels.len().saturating_sub(1));
    let mut idx = leaf_index;
    for level in &levels[..levels.len() - 1] {
        let sib_idx = idx ^ 1;
        let sib = if sib_idx < level.len() { level[sib_idx] } else { level[idx] };
        path.push(sib);
        idx /= 2;
    }
    path
}

pub fn merkle_verify(
    leaf:       [u8; 32],
    mut leaf_index: usize,
    path:       &[[u8; 32]],
    root:       [u8; 32],
) -> bool {
    let mut cur = leaf;
    for &sib in path {
        let (l, r) = if leaf_index & 1 == 0 { (cur, sib) } else { (sib, cur) };
        let mut h = Sha3_256::new();
        Digest::update(&mut h, TAG_NODE);
        Digest::update(&mut h, l);
        Digest::update(&mut h, r);
        cur = Digest::finalize(h).into();
        leaf_index /= 2;
    }
    cur == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_round_trip() {
        let leaves: Vec<[u8;32]> = (0u8..7).map(|i| {
            let mut h = Sha3_256::new();
            Digest::update(&mut h, [i]);
            Digest::finalize(h).into()
        }).collect();

        let levels = merkle_build(&leaves);
        let root = merkle_root(&levels);

        for (i, leaf) in leaves.iter().enumerate() {
            let path = merkle_path(&levels, i);
            assert!(merkle_verify(*leaf, i, &path, root), "leaf {i} fails");
        }
    }

    #[test]
    fn dns_leaf_hash_changes_with_salt() {
        let r = DnsRecord::a("example.com", 300, [1,2,3,4]);
        let salt_a = *b"aaaaaaaaaaaaaaaa";
        let salt_b = *b"bbbbbbbbbbbbbbbb";
        assert_ne!(r.leaf_hash(&salt_a), r.leaf_hash(&salt_b));
    }
}
