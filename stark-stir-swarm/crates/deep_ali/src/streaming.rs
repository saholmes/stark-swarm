//! Memory-bounded prover primitives.
//!
//! See `docs/iot-memory-bounded-prover.md` for the full design.  This module
//! is a foundation: it defines the abstractions the existing in-memory FRI
//! prover would dispatch through when running in **memory-bounded mode** for
//! IoT devices.
//!
//! The traits here let an implementation choose between:
//!   * **In-memory backing** — `Vec<F>` / `Vec<E>`, the existing default.
//!   * **mmap-backed disk spill** — `MmapColumn` for LDE columns that don't
//!     fit in RAM.  The OS handles paging; the prover sees a slice-like API.
//!   * **Chunked streaming** — `StreamingColumnReader` / `StreamingColumnWriter`
//!     for sequentially-produced/consumed columns (typical for FRI fold output).
//!
//! The current `deep_ali::fri::deep_fri_prove` runs in **resident mode**
//! (everything in `Vec`).  A future `deep_fri_prove_streaming` would take a
//! `MemoryBudget` and dispatch through these traits.
//!
//! No I/O is performed by this module — it only defines the surface.  The
//! `mmap` and `streaming-prover` features (off by default) gate the actual
//! disk-backed implementations.

use ark_goldilocks::Goldilocks as F;

use crate::tower_field::TowerField;

// ─────────────────────────────────────────────────────────────────────────────
//  Memory budget
// ─────────────────────────────────────────────────────────────────────────────

/// Soft cap on resident heap usage.  When the streaming prover is asked to
/// allocate a column whose in-memory footprint would exceed `max_resident_bytes`,
/// it spills to `spill_dir` (mmap-backed file) instead.
#[derive(Clone, Debug)]
pub struct MemoryBudget {
    /// Total RAM the prover may use for resident buffers (bytes).
    /// Default: `usize::MAX` (unbounded — current behaviour).
    pub max_resident_bytes: usize,
    /// Working chunk size for streaming I/O (bytes).  Smaller = less RAM, more
    /// I/O syscalls.  Default: 4 MiB.
    pub chunk_bytes: usize,
    /// Where to spill columns that don't fit in `max_resident_bytes`.
    pub spill_dir: std::path::PathBuf,
}

impl MemoryBudget {
    /// Resident-mode budget: never spill.  Equivalent to today's prover.
    pub fn unbounded() -> Self {
        Self {
            max_resident_bytes: usize::MAX,
            chunk_bytes:        4 * 1024 * 1024,
            spill_dir:          std::env::temp_dir(),
        }
    }

    /// Bounded-mode budget for an IoT device.  Pick `max_mb` ≤ 80% of physical
    /// RAM; the OS needs the rest for page cache while the prover spills.
    pub fn for_iot(max_mb: usize, spill_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            max_resident_bytes: max_mb.saturating_mul(1024 * 1024),
            chunk_bytes:        4 * 1024 * 1024,
            spill_dir:          spill_dir.into(),
        }
    }

    /// Decide whether a column of `n_elements × elem_size` should be spilled.
    pub fn should_spill(&self, n_elements: usize, elem_size: usize) -> bool {
        let footprint = n_elements.saturating_mul(elem_size);
        footprint > self.max_resident_bytes
    }
}

impl Default for MemoryBudget {
    fn default() -> Self { Self::unbounded() }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Column storage abstraction
// ─────────────────────────────────────────────────────────────────────────────

/// Read-only random access to a column of base-field values.
/// Used by the FFT/NTT and constraint-evaluator phases.
pub trait FpColumnRead {
    fn len(&self) -> usize;
    fn get(&self, idx: usize) -> F;

    /// Iterate over a contiguous range.  Implementors should use mmap or
    /// streaming reads to avoid pulling the whole range into RAM.
    fn iter_range(&self, start: usize, end: usize) -> Box<dyn Iterator<Item = F> + '_> {
        Box::new((start..end).map(|i| self.get(i)))
    }

    /// Whether this column is RAM-resident.  Spilled columns return false.
    fn is_resident(&self) -> bool { true }
}

/// Write-once sequential column writer.  Used by FRI-fold and LDE production
/// to emit a column one chunk at a time without materialising it in RAM.
pub trait FpColumnWrite: Send {
    fn append(&mut self, values: &[F]);
    fn finish(self: Box<Self>) -> Box<dyn FpColumnRead>;
}

/// Same shape, generic over the extension field for FRI layers / payloads.
pub trait ExtColumnRead<E: TowerField> {
    fn len(&self) -> usize;
    fn get(&self, idx: usize) -> E;
    fn is_resident(&self) -> bool { true }
}

pub trait ExtColumnWrite<E: TowerField>: Send {
    fn append(&mut self, values: &[E]);
    fn finish(self: Box<Self>) -> Box<dyn ExtColumnRead<E>>;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Resident (Vec-backed) implementations — the existing path
// ─────────────────────────────────────────────────────────────────────────────

impl FpColumnRead for Vec<F> {
    fn len(&self) -> usize { self.as_slice().len() }
    fn get(&self, idx: usize) -> F { self[idx] }
    fn iter_range(&self, start: usize, end: usize) -> Box<dyn Iterator<Item = F> + '_> {
        Box::new(self[start..end].iter().copied())
    }
}

pub struct ResidentFpWriter { buf: Vec<F> }

impl ResidentFpWriter {
    pub fn with_capacity(n: usize) -> Self { Self { buf: Vec::with_capacity(n) } }
}

impl FpColumnWrite for ResidentFpWriter {
    fn append(&mut self, values: &[F]) { self.buf.extend_from_slice(values); }
    fn finish(self: Box<Self>) -> Box<dyn FpColumnRead> { Box::new(self.buf) }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Streaming Merkle tree — only the right spine lives in RAM
// ─────────────────────────────────────────────────────────────────────────────

/// Append-only Merkle tree builder that holds only `O(log n)` hashes resident.
/// Leaves are pushed in order, hashed immediately, and bubbled up the tree;
/// completed subtrees are discarded as soon as their parent hash is computed.
///
/// At any point during construction the resident state is:
///   * the running "right spine" — at most one hash per tree level
///   * the running streaming SHA-3 state inside the leaf hasher
///
/// Total: ~`(log₂ n + 1) × HASH_BYTES` bytes.  For n = 2³⁰ this is
/// ~31 × 32 = **992 bytes**, regardless of how many leaves were processed.
pub struct StreamingMerkleSpine<const N: usize> {
    /// `levels[i]` holds Some(hash) if level i has a pending right child
    /// waiting for its sibling.
    levels: Vec<Option<[u8; N]>>,
    /// Number of leaves pushed so far.
    n_leaves: usize,
}

impl<const N: usize> Default for StreamingMerkleSpine<N> {
    fn default() -> Self { Self { levels: Vec::new(), n_leaves: 0 } }
}

impl<const N: usize> StreamingMerkleSpine<N> {
    pub fn new() -> Self { Self::default() }

    /// Push the next leaf hash.  `combine` is the parent-hashing function
    /// `(left, right) → parent`.  After pushing, the "spine" still holds
    /// at most one hash per level.
    pub fn push_leaf<H: Fn(&[u8; N], &[u8; N]) -> [u8; N]>(&mut self, leaf: [u8; N], combine: &H) {
        self.n_leaves += 1;
        let mut carry = Some(leaf);
        let mut level = 0;
        while let Some(c) = carry {
            if level >= self.levels.len() {
                self.levels.push(None);
            }
            match self.levels[level].take() {
                Some(left) => {
                    carry = Some(combine(&left, &c));
                    level += 1;
                }
                None => {
                    self.levels[level] = Some(c);
                    carry = None;
                }
            }
        }
    }

    /// Finalise — pad the right side with duplicates **only below the top
    /// level** to reach a power of two, returning the root.  Total resident
    /// memory at finalisation is the spine itself plus a few stack frames.
    ///
    /// The "top level" is determined by the highest set bit in `n_leaves`:
    /// for `n_leaves = 2^k` exactly the spine already holds a fully-formed
    /// subtree at level `k`, so no duplication is needed there.  Levels
    /// strictly below the top get duplicated when there's a left-only or
    /// carry-only orphan.
    pub fn finalise<H>(mut self, combine: &H) -> Option<[u8; N]>
    where H: Fn(&[u8; N], &[u8; N]) -> [u8; N] {
        if self.n_leaves == 0 { return None; }

        // Highest level = position of the highest set bit in n_leaves
        // (= ⌊log₂(n_leaves)⌋ in 0-indexed level numbering).
        let highest_level =
            (usize::BITS - 1 - self.n_leaves.leading_zeros()) as usize;

        let mut carry: Option<[u8; N]> = None;
        for i in 0..self.levels.len() {
            let pending = self.levels[i].take();
            if i < highest_level {
                // Below the top: orphans get duplicated.
                carry = match (pending, carry.take()) {
                    (Some(left), Some(right)) => Some(combine(&left, &right)),
                    (Some(only), None)        => Some(combine(&only, &only)),
                    (None, Some(c))           => Some(combine(&c, &c)),
                    (None, None)              => None,
                };
            } else {
                // At the top: combine with carry if present, otherwise
                // just promote (no duplication of the root).
                carry = match (pending, carry.take()) {
                    (Some(left), Some(right)) => Some(combine(&left, &right)),
                    (Some(only), None)        => Some(only),
                    (None, Some(c))           => Some(c),
                    (None, None)              => None,
                };
            }
        }
        carry
    }

    /// Number of leaves that have been pushed so far.
    pub fn leaf_count(&self) -> usize { self.n_leaves }

    /// Number of resident hashes currently in the spine.
    /// Bounded by `⌈log₂(n_leaves)⌉ + 1`.
    pub fn resident_hashes(&self) -> usize {
        self.levels.iter().filter(|s| s.is_some()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_combine(l: &[u8; 4], r: &[u8; 4]) -> [u8; 4] {
        // toy hash: XOR + add — for testing the spine bookkeeping only.
        let mut o = [0u8; 4];
        for i in 0..4 { o[i] = l[i].wrapping_add(r[i]).wrapping_mul(31); }
        o
    }

    #[test]
    fn streaming_spine_matches_recursive_tree_8_leaves() {
        let leaves: Vec<[u8;4]> = (0..8u8).map(|i| [i, i+1, i+2, i+3]).collect();
        let mut s = StreamingMerkleSpine::<4>::new();
        for &l in &leaves { s.push_leaf(l, &dummy_combine); }
        let streaming_root = s.finalise(&dummy_combine).unwrap();

        // Reference: build full tree in memory.
        let mut level: Vec<[u8;4]> = leaves.clone();
        while level.len() > 1 {
            level = level.chunks(2).map(|c| {
                if c.len() == 2 { dummy_combine(&c[0], &c[1]) } else { dummy_combine(&c[0], &c[0]) }
            }).collect();
        }
        assert_eq!(streaming_root, level[0]);
    }

    #[test]
    fn streaming_spine_unbalanced_5_leaves() {
        // n=5 → highest_level=2 (5 = 101_2).  L4 is orphan at level 0.
        // Expected reference: pad to 8 leaves with L4 triplicated, build full tree.
        let leaves: Vec<[u8;4]> = (0..5u8).map(|i| [i, i+1, i+2, i+3]).collect();
        let mut s = StreamingMerkleSpine::<4>::new();
        for &l in &leaves { s.push_leaf(l, &dummy_combine); }
        let streaming = s.finalise(&dummy_combine).unwrap();

        // Reference: pad with duplicates of L4 to reach 8 leaves.
        let mut padded = leaves.clone();
        let last = *padded.last().unwrap();
        while !padded.len().is_power_of_two() { padded.push(last); }
        while padded.len() > 1 {
            padded = padded.chunks(2).map(|c| dummy_combine(&c[0], &c[1])).collect();
        }
        assert_eq!(streaming, padded[0]);
    }

    #[test]
    fn streaming_spine_resident_size_is_logarithmic() {
        // Push 1024 leaves.  At the end the spine should hold at most
        // ~log₂(1024)=10 hashes, not 1024.
        let mut s = StreamingMerkleSpine::<4>::new();
        for i in 0..1024u32 {
            s.push_leaf(i.to_le_bytes(), &dummy_combine);
        }
        // After 1024 = 2¹⁰ leaves all subtrees collapse: spine has at most
        // a single level set (the running top).  In the middle of pushing,
        // resident is bounded by the bit-count of the leaf index.
        assert!(s.resident_hashes() <= 11,
            "resident={} exceeds log₂(1024)+1", s.resident_hashes());
    }

    #[test]
    fn budget_should_spill_threshold() {
        let b = MemoryBudget::for_iot(100, std::env::temp_dir()); // 100 MB
        let elem_size = 48;                  // Fp⁶
        // 1M elements at 48 B = 48 MB → fits
        assert!(!b.should_spill(1_000_000, elem_size));
        // 4M elements at 48 B = 192 MB → spills
        assert!(b.should_spill(4_000_000, elem_size));
    }

    #[test]
    fn budget_unbounded_never_spills() {
        let b = MemoryBudget::unbounded();
        assert!(!b.should_spill(usize::MAX / 2, 1));
    }

    #[test]
    fn budget_for_iot_caps_at_target() {
        let b = MemoryBudget::for_iot(512, "/tmp");
        assert_eq!(b.max_resident_bytes, 512 * 1024 * 1024);
    }

    #[test]
    fn resident_writer_round_trip() {
        let mut w = ResidentFpWriter::with_capacity(8);
        w.append(&[F::from(1u64), F::from(2u64), F::from(3u64)]);
        w.append(&[F::from(4u64)]);
        let r = (Box::new(w) as Box<dyn FpColumnWrite>).finish();
        assert_eq!(r.len(), 4);
        assert_eq!(r.get(0), F::from(1u64));
        assert_eq!(r.get(3), F::from(4u64));
    }
}
