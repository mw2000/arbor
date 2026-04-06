use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::hash::{compute_empty_hashes, hash_leaf, hash_node};
use crate::{Hash, Key, TREE_DEPTH};

/// A Merkle proof for a key in a sparse Merkle tree.
///
/// `siblings[i]` is the sibling subtree hash at height `i` above the leaf.
/// `siblings[0]` is the direct neighbor at the leaf level.
/// `siblings[TREE_DEPTH - 1]` is the child of the root that this key is NOT in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseMerkleProof {
    pub siblings: Vec<Hash>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    InvalidProofLength,
    RootMismatch,
}

/// Returns the bit of `key` at the given level from the root.
/// Level 0 = most significant bit (root's branching decision).
fn key_bit(key: &Key, level: usize) -> u8 {
    let byte_idx = level / 8;
    let bit_idx = 7 - (level % 8);
    (key[byte_idx] >> bit_idx) & 1
}

impl SparseMerkleProof {
    /// Verify that `value` is stored at `key` in a tree with the given `root`.
    /// For non-membership proofs, pass an empty value slice.
    pub fn verify(&self, root: &Hash, key: &Key, value: &[u8]) -> Result<(), VerifyError> {
        let computed = self.compute_root(key, value)?;
        if computed == *root {
            Ok(())
        } else {
            Err(VerifyError::RootMismatch)
        }
    }

    /// Compute the root hash for a tree containing `value` at `key`,
    /// using the sibling hashes in this proof.
    pub fn compute_root(&self, key: &Key, value: &[u8]) -> Result<Hash, VerifyError> {
        if self.siblings.len() != TREE_DEPTH {
            return Err(VerifyError::InvalidProofLength);
        }

        let mut current = if value.is_empty() {
            let empty_hashes = compute_empty_hashes();
            empty_hashes[0]
        } else {
            hash_leaf(key, value)
        };

        // Walk from leaf (height 0) to root (height TREE_DEPTH).
        // At step i, current has height i, sibling has height i.
        // The branching decision at height i is determined by the key bit
        // at level (TREE_DEPTH - 1 - i) from the root.
        for i in 0..TREE_DEPTH {
            let level = TREE_DEPTH - 1 - i;
            let sibling = &self.siblings[i];
            current = if key_bit(key, level) == 0 {
                hash_node(&current, sibling)
            } else {
                hash_node(sibling, &current)
            };
        }

        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::compute_empty_hashes;

    #[test]
    fn empty_tree_proof() {
        let empty_hashes = compute_empty_hashes();
        let root = empty_hashes[TREE_DEPTH];
        let key = [0u8; 32];

        // All siblings are empty subtrees at their respective heights.
        let siblings: Vec<Hash> = (0..TREE_DEPTH).map(|i| empty_hashes[i]).collect();
        let proof = SparseMerkleProof { siblings };

        assert_eq!(proof.verify(&root, &key, &[]), Ok(()));
    }
}
