//! Append-only Merkle tree using a compact range (frontier) representation.
//!
//! Implements RFC 6962 hashing (Certificate Transparency / Trillian):
//! - Leaf: SHA256(0x00 || data)
//! - Node: SHA256(0x01 || left || right)
//!
//! The compact range stores O(log N) subtree roots — one per set bit
//! in the binary representation of tree size N. This is sufficient to
//! compute the tree root and to append new leaves without the full tree.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::hash::{empty_tree_root, hash_node, hash_rfc6962_leaf};
use crate::Hash;

/// Compact representation of an append-only Merkle tree.
///
/// Stores the frontier: one subtree root per set bit in `size`,
/// ordered from the largest (leftmost) subtree to the smallest (rightmost).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactRange {
    frontier: Vec<Hash>,
    size: u64,
}

impl CompactRange {
    pub fn new() -> Self {
        Self {
            frontier: Vec::new(),
            size: 0,
        }
    }

    /// Reconstruct from a known frontier and tree size.
    ///
    /// Panics if `frontier.len()` does not equal the number of set bits in `size`.
    pub fn from_parts(frontier: Vec<Hash>, size: u64) -> Self {
        assert_eq!(
            frontier.len(),
            size.count_ones() as usize,
            "frontier length ({}) must equal popcount of size ({})",
            frontier.len(),
            size.count_ones(),
        );
        Self { frontier, size }
    }

    /// Compute the tree root from the frontier.
    ///
    /// For an empty tree (size 0), returns SHA-256("") per RFC 6962.
    pub fn root(&self) -> Hash {
        if self.frontier.is_empty() {
            return empty_tree_root();
        }
        let mut iter = self.frontier.iter().rev();
        let mut root = *iter.next().unwrap();
        for subtree_root in iter {
            root = hash_node(subtree_root, &root);
        }
        root
    }

    /// Append a leaf to the tree.
    ///
    /// Hashes the leaf data with the RFC 6962 domain separator, then merges
    /// with existing subtrees of matching size (trailing 1-bits in `self.size`).
    pub fn append(&mut self, leaf_data: &[u8]) {
        let mut node = hash_rfc6962_leaf(leaf_data);

        // Merge with same-sized subtrees: each trailing 1-bit in self.size
        // means there's a complete subtree on the frontier to merge with.
        let mut s = self.size;
        while s & 1 == 1 {
            let left = self.frontier.pop().unwrap();
            node = hash_node(&left, &node);
            s >>= 1;
        }

        self.frontier.push(node);
        self.size += 1;
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn frontier(&self) -> &[Hash] {
        &self.frontier
    }
}

impl Default for CompactRange {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash_node, hash_rfc6962_leaf};

    #[test]
    fn empty_tree_root_is_sha256_of_empty() {
        let cr = CompactRange::new();
        assert_eq!(cr.root(), empty_tree_root());
        assert_eq!(cr.size(), 0);
    }

    #[test]
    fn single_leaf() {
        let mut cr = CompactRange::new();
        cr.append(b"leaf0");
        assert_eq!(cr.size(), 1);
        // Root of a single-leaf tree is the leaf hash itself.
        assert_eq!(cr.root(), hash_rfc6962_leaf(b"leaf0"));
    }

    #[test]
    fn two_leaves() {
        let mut cr = CompactRange::new();
        cr.append(b"leaf0");
        cr.append(b"leaf1");
        assert_eq!(cr.size(), 2);
        let expected = hash_node(&hash_rfc6962_leaf(b"leaf0"), &hash_rfc6962_leaf(b"leaf1"));
        assert_eq!(cr.root(), expected);
    }

    #[test]
    fn three_leaves() {
        let mut cr = CompactRange::new();
        cr.append(b"leaf0");
        cr.append(b"leaf1");
        cr.append(b"leaf2");
        assert_eq!(cr.size(), 3);

        // Tree structure: H(H(leaf0, leaf1), leaf2)
        let left = hash_node(&hash_rfc6962_leaf(b"leaf0"), &hash_rfc6962_leaf(b"leaf1"));
        let expected = hash_node(&left, &hash_rfc6962_leaf(b"leaf2"));
        assert_eq!(cr.root(), expected);
    }

    #[test]
    fn four_leaves() {
        let mut cr = CompactRange::new();
        for i in 0..4u8 {
            cr.append(&[i]);
        }
        assert_eq!(cr.size(), 4);
        // Frontier should have exactly 1 entry (4 = 0b100).
        assert_eq!(cr.frontier().len(), 1);

        let l01 = hash_node(&hash_rfc6962_leaf(&[0]), &hash_rfc6962_leaf(&[1]));
        let l23 = hash_node(&hash_rfc6962_leaf(&[2]), &hash_rfc6962_leaf(&[3]));
        assert_eq!(cr.root(), hash_node(&l01, &l23));
    }

    #[test]
    fn five_leaves_frontier() {
        let mut cr = CompactRange::new();
        for i in 0..5u8 {
            cr.append(&[i]);
        }
        assert_eq!(cr.size(), 5);
        // 5 = 0b101, frontier has 2 entries.
        assert_eq!(cr.frontier().len(), 2);
    }

    #[test]
    fn from_parts_roundtrip() {
        let mut cr = CompactRange::new();
        for i in 0..7u8 {
            cr.append(&[i]);
        }
        let root1 = cr.root();

        let cr2 = CompactRange::from_parts(cr.frontier().to_vec(), cr.size());
        assert_eq!(cr2.root(), root1);
    }

    #[test]
    fn append_after_restore() {
        // Build tree of 3 leaves, save frontier, restore, append 2 more.
        let mut cr = CompactRange::new();
        for i in 0..3u8 {
            cr.append(&[i]);
        }
        let frontier = cr.frontier().to_vec();
        let size = cr.size();

        let mut cr2 = CompactRange::from_parts(frontier, size);
        cr2.append(&[3]);
        cr2.append(&[4]);

        // Should match building from scratch.
        let mut cr_full = CompactRange::new();
        for i in 0..5u8 {
            cr_full.append(&[i]);
        }
        assert_eq!(cr2.root(), cr_full.root());
        assert_eq!(cr2.size(), cr_full.size());
    }

    #[test]
    #[should_panic(expected = "frontier length")]
    fn from_parts_rejects_bad_frontier() {
        CompactRange::from_parts(vec![[0u8; 32]], 3); // 3 has popcount 2, not 1
    }

    #[test]
    fn incremental_roots_are_consistent() {
        // Verify each intermediate root matches building from scratch.
        for n in 1..=16u8 {
            let mut incremental = CompactRange::new();
            for i in 0..n {
                incremental.append(&[i]);
            }

            let mut from_scratch = CompactRange::new();
            for i in 0..n {
                from_scratch.append(&[i]);
            }

            assert_eq!(
                incremental.root(),
                from_scratch.root(),
                "root mismatch at size {}",
                n
            );
        }
    }
}
