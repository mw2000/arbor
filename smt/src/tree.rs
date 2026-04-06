#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "std")]
use crate::hash::{compute_empty_hashes, hash_leaf, hash_node};
#[cfg(feature = "std")]
use crate::proof::SparseMerkleProof;
#[cfg(feature = "std")]
use crate::{Hash, Key, TREE_DEPTH};
#[cfg(feature = "std")]
use alloc::vec::Vec;

/// In-memory sparse Merkle tree. Host-side only (requires std).
///
/// Convention:
/// - Level 0 = root branching (MSB of key), level 255 = leaf branching (LSB)
/// - Height 0 = leaf, height 256 = root
/// - height = TREE_DEPTH - level (when iterating from leaf upward)
#[cfg(feature = "std")]
pub struct SparseMerkleTree {
    leaves: HashMap<Key, Vec<u8>>,
    /// Internal node hashes. Keyed by (height, canonical_key).
    /// canonical_key has all bits below the node's level zeroed out.
    nodes: HashMap<(usize, Key), Hash>,
    empty_hashes: [Hash; TREE_DEPTH + 1],
}

#[cfg(feature = "std")]
impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            empty_hashes: compute_empty_hashes(),
        }
    }

    pub fn root(&self) -> Hash {
        self.get_node(TREE_DEPTH, &[0u8; 32])
    }

    /// Insert or update a key-value pair. Returns the new root.
    pub fn update(&mut self, key: Key, value: Vec<u8>) -> Hash {
        self.leaves.insert(key, value);
        self.recompute_path(&key);
        self.root()
    }

    /// Generate a Merkle proof for the given key.
    /// `siblings[i]` is the sibling hash at height `i` (0 = leaf level).
    pub fn prove(&self, key: &Key) -> SparseMerkleProof {
        let mut siblings = Vec::with_capacity(TREE_DEPTH);

        for height in 0..TREE_DEPTH {
            let level = TREE_DEPTH - 1 - height;
            let sibling_key = flip_and_canonicalize(key, level);
            let sibling_hash = self.get_node(height, &sibling_key);
            siblings.push(sibling_hash);
        }

        SparseMerkleProof { siblings }
    }

    pub fn get(&self, key: &Key) -> Option<&[u8]> {
        self.leaves.get(key).map(|v| v.as_slice())
    }

    /// Look up a node hash at the given height.
    fn get_node(&self, height: usize, canonical_key: &Key) -> Hash {
        if height == 0 {
            match self.leaves.get(canonical_key) {
                Some(value) => hash_leaf(canonical_key, value),
                None => self.empty_hashes[0],
            }
        } else {
            match self.nodes.get(&(height, *canonical_key)) {
                Some(hash) => *hash,
                None => self.empty_hashes[height],
            }
        }
    }

    /// Recompute all internal nodes from leaf to root after a leaf change.
    fn recompute_path(&mut self, key: &Key) {
        let mut current = match self.leaves.get(key) {
            Some(value) => hash_leaf(key, value),
            None => self.empty_hashes[0],
        };

        for height in 0..TREE_DEPTH {
            let level = TREE_DEPTH - 1 - height;
            let bit = key_bit(key, level);

            let sibling_key = flip_and_canonicalize(key, level);
            let sibling_hash = self.get_node(height, &sibling_key);

            current = if bit == 0 {
                hash_node(&current, &sibling_hash)
            } else {
                hash_node(&sibling_hash, &current)
            };

            // Store this node at height+1 with canonical key.
            // The node at height+1 corresponds to level = TREE_DEPTH - 1 - (height+1).
            // For the root (height+1 == TREE_DEPTH), use [0; 32].
            let store_height = height + 1;
            let canonical = if store_height == TREE_DEPTH {
                [0u8; 32]
            } else {
                let store_level = TREE_DEPTH - 1 - store_height;
                canonicalize(key, store_level)
            };
            self.nodes.insert((store_height, canonical), current);
        }
    }
}

#[cfg(feature = "std")]
impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
fn key_bit(key: &Key, level: usize) -> u8 {
    let byte_idx = level / 8;
    let bit_idx = 7 - (level % 8);
    (key[byte_idx] >> bit_idx) & 1
}

#[cfg(feature = "std")]
fn canonicalize(key: &Key, level: usize) -> Key {
    let mut out = *key;
    // Zero out bits at positions level+1 through 255
    let first_clear = level + 1;
    let first_full_byte = (first_clear + 7) / 8;

    // Partial byte
    if first_clear % 8 != 0 {
        let byte_idx = first_clear / 8;
        if byte_idx < 32 {
            let keep_bits = first_clear % 8;
            let mask = !((1u8 << (8 - keep_bits)) - 1);
            out[byte_idx] &= mask;
        }
    }

    // Full bytes
    for b in out.iter_mut().skip(first_full_byte) {
        *b = 0;
    }
    out
}

#[cfg(feature = "std")]
fn flip_and_canonicalize(key: &Key, level: usize) -> Key {
    let mut out = canonicalize(key, level);
    let byte_idx = level / 8;
    let bit_idx = 7 - (level % 8);
    out[byte_idx] ^= 1 << bit_idx;
    out
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;
    use crate::hash::compute_empty_hashes;

    #[test]
    fn empty_tree_root_is_deterministic() {
        let tree = SparseMerkleTree::new();
        let empty_hashes = compute_empty_hashes();
        assert_eq!(tree.root(), empty_hashes[TREE_DEPTH]);
    }

    #[test]
    fn insert_and_prove() {
        let mut tree = SparseMerkleTree::new();
        let key = [0xAB; 32];
        let value = b"hello world";
        let root = tree.update(key, value.to_vec());

        let proof = tree.prove(&key);
        assert_eq!(proof.verify(&root, &key, value), Ok(()));
    }

    #[test]
    fn non_membership_proof() {
        let mut tree = SparseMerkleTree::new();
        let key_a = [0x01; 32];
        tree.update(key_a, b"value_a".to_vec());

        let key_b = [0x02; 32];
        let root = tree.root();
        let proof = tree.prove(&key_b);
        assert_eq!(proof.verify(&root, &key_b, &[]), Ok(()));
    }

    #[test]
    fn update_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let key = [0xFF; 32];

        let root1 = tree.update(key, b"first".to_vec());
        let root2 = tree.update(key, b"second".to_vec());
        assert_ne!(root1, root2);
    }

    #[test]
    fn multiple_keys() {
        let mut tree = SparseMerkleTree::new();
        let key_a = [0x00; 32];
        let key_b = [0xFF; 32];

        tree.update(key_a, b"aaa".to_vec());
        tree.update(key_b, b"bbb".to_vec());
        let root = tree.root();

        let proof_a = tree.prove(&key_a);
        assert_eq!(proof_a.verify(&root, &key_a, b"aaa"), Ok(()));

        let proof_b = tree.prove(&key_b);
        assert_eq!(proof_b.verify(&root, &key_b, b"bbb"), Ok(()));
    }

    #[test]
    fn proof_verify_rejects_wrong_value() {
        let mut tree = SparseMerkleTree::new();
        let key = [0x42; 32];
        let root = tree.update(key, b"correct".to_vec());

        let proof = tree.prove(&key);
        assert!(proof.verify(&root, &key, b"wrong").is_err());
    }

    #[test]
    fn compute_root_matches_verify() {
        let mut tree = SparseMerkleTree::new();
        let key = [0x77; 32];
        let value = b"test value";
        let root = tree.update(key, value.to_vec());

        let proof = tree.prove(&key);
        let computed_root = proof.compute_root(&key, value).unwrap();
        assert_eq!(computed_root, root);
    }
}
