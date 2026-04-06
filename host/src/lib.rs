// Force linker to include jolt-inlines-sha2 inventory registrations.
extern crate jolt_inlines_sha2;

use arbor_smt::SparseMerkleTree;
use guest::{DeriveBatchInput, MapUpdate};

/// Host-side map operator. Maintains the full sparse Merkle tree
/// and produces batched update inputs for the guest prover.
pub struct MapOperator {
    tree: SparseMerkleTree,
}

impl MapOperator {
    pub fn new() -> Self {
        Self {
            tree: SparseMerkleTree::new(),
        }
    }

    pub fn root(&self) -> arbor_smt::Hash {
        self.tree.root()
    }

    pub fn get(&self, key: &arbor_smt::Key) -> Option<&[u8]> {
        self.tree.get(key)
    }

    /// Build a `DeriveBatchInput` for a set of key-value updates.
    /// Generates proofs against the current tree, then applies updates.
    /// The returned input can be passed to the guest program for proving.
    pub fn prepare_batch(&mut self, updates: Vec<(arbor_smt::Key, Vec<u8>)>) -> DeriveBatchInput {
        let old_root = self.tree.root();
        let mut map_updates = Vec::with_capacity(updates.len());

        for (key, new_value) in updates {
            // Generate proof against the *current* tree state
            let proof = self.tree.prove(&key);
            let old_value = self.tree.get(&key).unwrap_or(&[]).to_vec();

            map_updates.push(MapUpdate {
                key,
                value: new_value.clone(),
                proof,
                old_value,
            });

            // Apply the update so the next proof is against the updated tree
            self.tree.update(key, new_value);
        }

        DeriveBatchInput {
            old_root,
            updates: map_updates,
        }
    }
}

impl Default for MapOperator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guest::derive_batch;

    #[test]
    fn batch_derivation_matches_direct_tree() {
        let mut operator = MapOperator::new();

        let updates = vec![
            ([0x01; 32], b"value_one".to_vec()),
            ([0x02; 32], b"value_two".to_vec()),
            ([0x03; 32], b"value_three".to_vec()),
        ];

        let batch_input = operator.prepare_batch(updates);
        let expected_old_root = batch_input.old_root;
        let output = derive_batch(batch_input);

        assert_eq!(output.new_root, operator.root());
        assert_eq!(output.old_root, expected_old_root);
        assert_eq!(output.num_updates, 3);
    }

    #[test]
    fn batch_update_existing_keys() {
        let mut operator = MapOperator::new();

        // First batch: insert keys
        let inserts = vec![
            ([0xAA; 32], b"first".to_vec()),
            ([0xBB; 32], b"second".to_vec()),
        ];
        let input1 = operator.prepare_batch(inserts);
        let output1 = derive_batch(input1);
        assert_eq!(output1.new_root, operator.root());

        // Second batch: update one key, insert another
        let updates = vec![
            ([0xAA; 32], b"updated".to_vec()),
            ([0xCC; 32], b"third".to_vec()),
        ];
        let input2 = operator.prepare_batch(updates);
        let output2 = derive_batch(input2);
        assert_eq!(output2.new_root, operator.root());
        // output2.old_root should be the previous batch's new_root
        assert_eq!(output2.old_root, output1.new_root);
    }

    #[test]
    fn single_update_batch() {
        let mut operator = MapOperator::new();

        let updates = vec![([0xFF; 32], b"solo".to_vec())];
        let input = operator.prepare_batch(updates);
        let output = derive_batch(input);

        assert_eq!(output.new_root, operator.root());
        assert_eq!(output.num_updates, 1);
    }

    #[test]
    fn empty_batch() {
        let mut operator = MapOperator::new();
        let old_root = operator.root();

        let input = operator.prepare_batch(vec![]);
        let output = derive_batch(input);

        assert_eq!(output.new_root, old_root);
        assert_eq!(output.old_root, old_root);
        assert_eq!(output.num_updates, 0);
    }
}
