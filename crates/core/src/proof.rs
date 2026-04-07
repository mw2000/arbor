//! Merkle proof verification for RFC 6962 transparency logs.
//!
//! Implements inclusion and consistency proof verification compatible with
//! Google Trillian and Certificate Transparency (RFC 6962 / transparency-dev).
//!
//! These are pure verification functions -- they don't require tree state or
//! network access. Proof *generation* is delegated to Trillian's gRPC API.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::hash::hash_node;
use crate::Hash;

// ---------------------------------------------------------------------------
// Proof structs
// ---------------------------------------------------------------------------

/// A Merkle inclusion proof: proves that a specific leaf exists at a given
/// index in a tree of a known size and root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    /// 0-based index of the leaf in the log.
    pub leaf_index: u64,
    /// Total number of leaves in the tree this proof is relative to.
    pub tree_size: u64,
    /// Sibling hashes from leaf to root (bottom-up).
    pub hashes: Vec<Hash>,
}

impl InclusionProof {
    /// Verify this inclusion proof against a known leaf hash and expected root.
    ///
    /// `leaf_hash` should be the RFC 6962 leaf hash (`SHA256(0x00 || data)`).
    pub fn verify(&self, leaf_hash: &Hash, expected_root: &Hash) -> bool {
        verify_inclusion(
            self.leaf_index,
            self.tree_size,
            leaf_hash,
            &self.hashes,
            expected_root,
        )
    }

    /// Compute the root implied by this inclusion proof and the given leaf hash.
    ///
    /// Returns `None` if the proof structure is invalid.
    pub fn root_from(&self, leaf_hash: &Hash) -> Option<Hash> {
        root_from_inclusion_proof(self.leaf_index, self.tree_size, leaf_hash, &self.hashes)
    }
}

/// A Merkle consistency proof: proves that a tree of `old_size` is a prefix
/// of a tree of `new_size` (the log only grew, never mutated).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Size of the older (smaller) tree.
    pub old_size: u64,
    /// Size of the newer (larger) tree.
    pub new_size: u64,
    /// Proof hashes (ordered per RFC 6962 / Trillian convention).
    pub hashes: Vec<Hash>,
}

impl ConsistencyProof {
    /// Verify this consistency proof against the old and new roots.
    pub fn verify(&self, old_root: &Hash, new_root: &Hash) -> bool {
        verify_consistency(
            self.old_size,
            self.new_size,
            old_root,
            new_root,
            &self.hashes,
        )
    }

    /// Compute the new root from this consistency proof and the old root.
    ///
    /// Returns `None` if the proof is invalid or doesn't match `old_root`.
    pub fn new_root_from(&self, old_root: &Hash) -> Option<Hash> {
        root_from_consistency_proof(self.old_size, self.new_size, old_root, &self.hashes)
    }
}

// ---------------------------------------------------------------------------
// Standalone verification functions
// ---------------------------------------------------------------------------

/// Verify a Merkle inclusion proof per RFC 6962.
///
/// Returns `true` if `leaf_hash` at `leaf_index` is consistent with
/// `expected_root` for a tree of `tree_size` leaves.
pub fn verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &Hash,
    proof: &[Hash],
    expected_root: &Hash,
) -> bool {
    match root_from_inclusion_proof(leaf_index, tree_size, leaf_hash, proof) {
        Some(root) => root == *expected_root,
        None => false,
    }
}

/// Compute the expected root hash from an inclusion proof.
///
/// Returns `None` if the proof structure is invalid (wrong length, out-of-range index).
pub fn root_from_inclusion_proof(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &Hash,
    proof: &[Hash],
) -> Option<Hash> {
    if leaf_index >= tree_size || tree_size == 0 {
        return None;
    }

    let (inner, border) = decomp_incl_proof(leaf_index, tree_size);
    if proof.len() != inner + border {
        return None;
    }

    let mut hash = chain_inner(*leaf_hash, &proof[..inner], leaf_index);
    hash = chain_border_right(hash, &proof[inner..]);
    Some(hash)
}

/// Verify a Merkle consistency proof per RFC 6962.
///
/// Returns `true` if a tree of `old_size` with `old_root` is a valid prefix
/// of a tree of `new_size` with `new_root`.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    match root_from_consistency_proof(old_size, new_size, old_root, proof) {
        Some(computed_new_root) => computed_new_root == *new_root,
        None => {
            // Special case: equal sizes, empty proof, roots must match.
            old_size == new_size && proof.is_empty() && old_root == new_root
        }
    }
}

/// Compute the new root from a consistency proof and the old root.
///
/// Returns `None` if the proof is structurally invalid or doesn't match `old_root`.
///
/// Mirrors `RootFromConsistencyProof` from transparency-dev/merkle.
pub fn root_from_consistency_proof(
    old_size: u64,
    new_size: u64,
    old_root: &Hash,
    proof: &[Hash],
) -> Option<Hash> {
    if new_size < old_size {
        return None;
    }
    if old_size == new_size {
        if !proof.is_empty() {
            return None;
        }
        return Some(*old_root);
    }
    if old_size == 0 {
        // Consistency proof from an empty tree is meaningless --
        // any root is "consistent" with nothing.
        return None;
    }
    if proof.is_empty() {
        return None;
    }

    let (inner_full, border) = decomp_incl_proof(old_size - 1, new_size);
    let shift = old_size.trailing_zeros() as usize;
    let inner = inner_full - shift;

    // The proof includes the subtree hash at level `shift`, unless old_size
    // is exactly 2^shift (a perfect tree), in which case old_root IS that hash.
    let (seed, start) = if old_size == 1u64 << shift {
        (*old_root, 0)
    } else {
        (proof[0], 1)
    };

    if proof.len() != start + inner + border {
        return None;
    }
    let proof = &proof[start..];

    // Verify the old root by chaining only right-side hashes.
    let mask = (old_size - 1) >> shift;
    let hash1 = chain_inner_right(seed, &proof[..inner], mask);
    let hash1 = chain_border_right(hash1, &proof[inner..]);
    if hash1 != *old_root {
        return None;
    }

    // Compute the new root by chaining all hashes.
    let hash2 = chain_inner(seed, &proof[..inner], mask);
    let hash2 = chain_border_right(hash2, &proof[inner..]);
    Some(hash2)
}

// ---------------------------------------------------------------------------
// Internal helpers (mirror transparency-dev/merkle/proof/verify.go)
// ---------------------------------------------------------------------------

/// Decompose an inclusion proof into inner and border components.
///
/// The splitting point is where paths to `index` and `size-1` diverge.
fn decomp_incl_proof(index: u64, size: u64) -> (usize, usize) {
    let inner = inner_proof_size(index, size);
    let border = (index >> inner).count_ones() as usize;
    (inner, border)
}

/// Number of proof nodes below the point where the paths to `index` and
/// `size-1` diverge. Equivalent to `bits.Len64(index ^ (size - 1))` in Go.
fn inner_proof_size(index: u64, size: u64) -> usize {
    let xor = index ^ (size - 1);
    (u64::BITS - xor.leading_zeros()) as usize
}

/// Chain hash through inner proof nodes, going left or right based on
/// the bits of `index`. Proof hashes are ordered bottom-up.
fn chain_inner(mut seed: Hash, proof: &[Hash], index: u64) -> Hash {
    for (i, h) in proof.iter().enumerate() {
        if (index >> i) & 1 == 0 {
            seed = hash_node(&seed, h);
        } else {
            seed = hash_node(h, &seed);
        }
    }
    seed
}

/// Like `chain_inner`, but only processes hashes where the corresponding bit
/// of `index` is 1 (right child). Used for consistency proof old-root verification.
fn chain_inner_right(mut seed: Hash, proof: &[Hash], index: u64) -> Hash {
    for (i, h) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            seed = hash_node(h, &seed);
        }
    }
    seed
}

/// Chain proof hashes along the right border of the tree.
/// All hashes are left siblings (they go on the left side).
fn chain_border_right(mut seed: Hash, proof: &[Hash]) -> Hash {
    for h in proof {
        seed = hash_node(h, &seed);
    }
    seed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash_node, hash_rfc6962_leaf};
    use crate::CompactRange;

    /// Helper: build a full tree from leaf data and return (root, all leaf hashes).
    fn build_tree(leaf_data: &[&[u8]]) -> (Hash, Vec<Hash>) {
        let mut cr = CompactRange::new();
        let mut leaf_hashes = Vec::new();
        for data in leaf_data {
            cr.append(data);
            leaf_hashes.push(hash_rfc6962_leaf(data));
        }
        (cr.root(), leaf_hashes)
    }

    /// Manually compute the RFC 6962 Merkle tree root for a list of leaf hashes.
    /// Also returns the full node structure for proof extraction.
    fn merkle_root_from_hashes(hashes: &[Hash]) -> Hash {
        match hashes.len() {
            0 => crate::hash::empty_tree_root(),
            1 => hashes[0],
            n => {
                let k = n.next_power_of_two() / 2; // largest power of 2 < n
                let left = merkle_root_from_hashes(&hashes[..k]);
                let right = merkle_root_from_hashes(&hashes[k..]);
                hash_node(&left, &right)
            }
        }
    }

    /// Generate an inclusion proof for `index` in a tree of the given leaf hashes.
    /// This is a reference implementation for testing -- in production, Trillian provides these.
    fn gen_inclusion_proof(leaf_hashes: &[Hash], index: usize) -> Vec<Hash> {
        let n = leaf_hashes.len();
        if n <= 1 {
            return vec![];
        }
        let k = n.next_power_of_two() / 2;
        if index < k {
            let mut proof = gen_inclusion_proof(&leaf_hashes[..k], index);
            proof.push(merkle_root_from_hashes(&leaf_hashes[k..]));
            proof
        } else {
            let mut proof = gen_inclusion_proof(&leaf_hashes[k..], index - k);
            proof.push(merkle_root_from_hashes(&leaf_hashes[..k]));
            proof
        }
    }

    /// Generate a consistency proof in Trillian format for testing.
    ///
    /// The format matches what `verify_consistency` expects:
    /// - For non-power-of-2 old_size: [seed, inner_hashes..., border_hashes...]
    ///   where seed is the subtree hash at the `shift` level.
    /// - For power-of-2 old_size: [inner_hashes..., border_hashes...]
    ///   (seed == old_root and is not included).
    ///
    /// This is constructed from the inclusion proof for leaf `old_size - 1`
    /// in the new tree, which is equivalent to Trillian's GetConsistencyProof.
    fn gen_consistency_proof_trillian(leaf_hashes: &[Hash], old_size: usize) -> Vec<Hash> {
        let new_size = leaf_hashes.len();
        if old_size == 0 || old_size == new_size {
            return vec![];
        }

        let idx = old_size - 1;
        let incl_proof = gen_inclusion_proof(&leaf_hashes[..new_size], idx);
        let shift = old_size.trailing_zeros() as usize;

        // Compute the seed by chaining the first `shift` inclusion proof hashes.
        let mut seed = leaf_hashes[idx];
        for (i, h) in incl_proof[..shift].iter().enumerate() {
            if ((idx as u64) >> i) & 1 == 0 {
                seed = hash_node(&seed, h);
            } else {
                seed = hash_node(h, &seed);
            }
        }

        let remaining = &incl_proof[shift..];

        if old_size.is_power_of_two() {
            // seed == old_root, omit from proof.
            remaining.to_vec()
        } else {
            let mut proof = vec![seed];
            proof.extend_from_slice(remaining);
            proof
        }
    }

    // -- Inclusion proof tests --

    #[test]
    fn inclusion_proof_single_leaf() {
        let (root, leaf_hashes) = build_tree(&[b"only"]);
        let proof = gen_inclusion_proof(&leaf_hashes, 0);
        assert!(proof.is_empty());
        assert!(verify_inclusion(0, 1, &leaf_hashes[0], &proof, &root));
    }

    #[test]
    fn inclusion_proof_two_leaves() {
        let (root, leaf_hashes) = build_tree(&[b"a", b"b"]);
        for i in 0..2 {
            let proof = gen_inclusion_proof(&leaf_hashes, i);
            assert_eq!(proof.len(), 1);
            assert!(verify_inclusion(
                i as u64,
                2,
                &leaf_hashes[i],
                &proof,
                &root
            ));
        }
    }

    #[test]
    fn inclusion_proof_seven_leaves() {
        let data: Vec<&[u8]> = (0..7u8)
            .map(|i| -> &[u8] { Box::leak(vec![i].into_boxed_slice()) })
            .collect();
        let (root, leaf_hashes) = build_tree(&data);
        for i in 0..7 {
            let proof = gen_inclusion_proof(&leaf_hashes, i);
            assert!(
                verify_inclusion(i as u64, 7, &leaf_hashes[i], &proof, &root),
                "inclusion proof failed for index {} in tree of size 7",
                i,
            );
        }
    }

    #[test]
    fn inclusion_proof_power_of_two() {
        let data: Vec<&[u8]> = (0..8u8)
            .map(|i| -> &[u8] { Box::leak(vec![i].into_boxed_slice()) })
            .collect();
        let (root, leaf_hashes) = build_tree(&data);
        for i in 0..8 {
            let proof = gen_inclusion_proof(&leaf_hashes, i);
            assert_eq!(proof.len(), 3, "proof for index {} should have 3 hashes", i);
            assert!(
                verify_inclusion(i as u64, 8, &leaf_hashes[i], &proof, &root),
                "inclusion proof failed for index {} in tree of size 8",
                i,
            );
        }
    }

    #[test]
    fn inclusion_proof_wrong_root_fails() {
        let (_, leaf_hashes) = build_tree(&[b"a", b"b", b"c"]);
        let fake_root = [0xFFu8; 32];
        let proof = gen_inclusion_proof(&leaf_hashes, 0);
        assert!(!verify_inclusion(0, 3, &leaf_hashes[0], &proof, &fake_root));
    }

    #[test]
    fn inclusion_proof_wrong_index_fails() {
        let (root, leaf_hashes) = build_tree(&[b"a", b"b", b"c"]);
        let proof = gen_inclusion_proof(&leaf_hashes, 0);
        // Use the proof for index 0, but claim it's for index 1 -- should fail.
        assert!(!verify_inclusion(1, 3, &leaf_hashes[0], &proof, &root));
    }

    #[test]
    fn inclusion_proof_out_of_range() {
        let (root, leaf_hashes) = build_tree(&[b"a"]);
        assert!(!verify_inclusion(1, 1, &leaf_hashes[0], &[], &root));
        assert!(!verify_inclusion(0, 0, &leaf_hashes[0], &[], &root));
    }

    #[test]
    fn inclusion_proof_struct_verify() {
        let (root, leaf_hashes) = build_tree(&[b"a", b"b", b"c", b"d"]);
        let hashes = gen_inclusion_proof(&leaf_hashes, 2);
        let proof = InclusionProof {
            leaf_index: 2,
            tree_size: 4,
            hashes,
        };
        assert!(proof.verify(&leaf_hashes[2], &root));
        assert_eq!(proof.root_from(&leaf_hashes[2]), Some(root));
    }

    // -- Consistency proof tests --

    #[test]
    fn consistency_proof_same_size() {
        let (root, _) = build_tree(&[b"a", b"b"]);
        assert!(verify_consistency(2, 2, &root, &root, &[]));
    }

    #[test]
    fn consistency_proof_same_size_different_roots_fails() {
        let (root, _) = build_tree(&[b"a", b"b"]);
        let fake_root = [0xFFu8; 32];
        assert!(!verify_consistency(2, 2, &root, &fake_root, &[]));
    }

    #[test]
    fn consistency_proof_power_of_two_to_power_of_two() {
        // 4 -> 8
        let data: Vec<&[u8]> = (0..8u8)
            .map(|i| -> &[u8] { Box::leak(vec![i].into_boxed_slice()) })
            .collect();
        let leaf_hashes: Vec<Hash> = data.iter().map(|d| hash_rfc6962_leaf(d)).collect();
        let old_root = merkle_root_from_hashes(&leaf_hashes[..4]);
        let new_root = merkle_root_from_hashes(&leaf_hashes[..8]);

        let proof = gen_consistency_proof_trillian(&leaf_hashes[..8], 4);
        assert!(
            verify_consistency(4, 8, &old_root, &new_root, &proof),
            "consistency proof failed for 4 -> 8, proof len = {}",
            proof.len(),
        );
    }

    #[test]
    fn consistency_proof_non_power_of_two() {
        // 3 -> 7
        let data: Vec<&[u8]> = (0..7u8)
            .map(|i| -> &[u8] { Box::leak(vec![i].into_boxed_slice()) })
            .collect();
        let leaf_hashes: Vec<Hash> = data.iter().map(|d| hash_rfc6962_leaf(d)).collect();
        let old_root = merkle_root_from_hashes(&leaf_hashes[..3]);
        let new_root = merkle_root_from_hashes(&leaf_hashes[..7]);

        let proof = gen_consistency_proof_trillian(&leaf_hashes[..7], 3);
        assert!(
            verify_consistency(3, 7, &old_root, &new_root, &proof),
            "consistency proof failed for 3 -> 7, proof len = {}",
            proof.len(),
        );
    }

    #[test]
    fn consistency_proof_many_sizes() {
        // Test all combinations from 1..=n to n for n = 16.
        let data: Vec<&[u8]> = (0..16u8)
            .map(|i| -> &[u8] { Box::leak(vec![i].into_boxed_slice()) })
            .collect();
        let leaf_hashes: Vec<Hash> = data.iter().map(|d| hash_rfc6962_leaf(d)).collect();

        for old_sz in 1..=16usize {
            for new_sz in old_sz..=16 {
                let old_root = merkle_root_from_hashes(&leaf_hashes[..old_sz]);
                let new_root = merkle_root_from_hashes(&leaf_hashes[..new_sz]);
                let proof = gen_consistency_proof_trillian(&leaf_hashes[..new_sz], old_sz);

                assert!(
                    verify_consistency(old_sz as u64, new_sz as u64, &old_root, &new_root, &proof),
                    "consistency proof failed for {} -> {}, proof len = {}",
                    old_sz,
                    new_sz,
                    proof.len(),
                );
            }
        }
    }

    #[test]
    fn consistency_proof_wrong_old_root_fails() {
        let data: Vec<&[u8]> = (0..4u8)
            .map(|i| -> &[u8] { Box::leak(vec![i].into_boxed_slice()) })
            .collect();
        let leaf_hashes: Vec<Hash> = data.iter().map(|d| hash_rfc6962_leaf(d)).collect();
        let new_root = merkle_root_from_hashes(&leaf_hashes[..4]);
        let fake_old_root = [0xFFu8; 32];

        let proof = gen_consistency_proof_trillian(&leaf_hashes[..4], 2);
        assert!(!verify_consistency(2, 4, &fake_old_root, &new_root, &proof));
    }

    #[test]
    fn consistency_proof_struct_verify() {
        let data: Vec<&[u8]> = (0..8u8)
            .map(|i| -> &[u8] { Box::leak(vec![i].into_boxed_slice()) })
            .collect();
        let leaf_hashes: Vec<Hash> = data.iter().map(|d| hash_rfc6962_leaf(d)).collect();
        let old_root = merkle_root_from_hashes(&leaf_hashes[..5]);
        let new_root = merkle_root_from_hashes(&leaf_hashes[..8]);

        let hashes = gen_consistency_proof_trillian(&leaf_hashes[..8], 5);
        let proof = ConsistencyProof {
            old_size: 5,
            new_size: 8,
            hashes,
        };
        assert!(proof.verify(&old_root, &new_root));
        assert_eq!(proof.new_root_from(&old_root), Some(new_root));
    }

    // -- Edge cases --

    #[test]
    fn empty_tree_proofs_are_invalid() {
        let root = [0u8; 32];
        assert!(!verify_inclusion(0, 0, &root, &[], &root));
        // Consistency from empty tree returns None (meaningless).
        assert!(root_from_consistency_proof(0, 5, &root, &[]).is_none());
    }

    #[test]
    fn inclusion_proof_wrong_length_fails() {
        let (root, leaf_hashes) = build_tree(&[b"a", b"b", b"c", b"d"]);
        let proof = gen_inclusion_proof(&leaf_hashes, 0);
        // Add an extra hash -- wrong length.
        let mut bad_proof = proof.clone();
        bad_proof.push([0u8; 32]);
        assert!(!verify_inclusion(0, 4, &leaf_hashes[0], &bad_proof, &root));
    }
}
