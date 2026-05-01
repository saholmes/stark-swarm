//! DNS-rollup record helpers + authority-signing layer for the STIR swarm.
//!
//! Migrated out of `cairo-bench` so the swarm worker / controller can pull
//! in DNS support without dragging the Criterion bench harness along.

pub mod dns;
pub mod dns_authority;
pub mod prover;

// Re-export the most common surface so callers don't need to know the
// internal module split.
pub use dns::{
    merkle_build, merkle_path, merkle_root, merkle_verify, DnsRecord, TAG_LEAF1, TAG_LEAF2,
    TAG_NODE,
};
pub use dns_authority::{level_hash, pk_binding_hash, AuthorityKeypair, NistLevel};
