#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use arbor_smt::{Hash, Key, SparseMerkleProof};
use serde::{Deserialize, Serialize};

/// A single update operation in a map derivation batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MapUpdate {
    pub key: Key,
    pub value: Vec<u8>,
    /// Proof of the current value (or non-membership) at this key
    /// against the tree root *before* this update is applied.
    pub proof: SparseMerkleProof,
    /// The old value at this key (empty if non-membership).
    pub old_value: Vec<u8>,
}

/// Input to the map derivation guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeriveBatchInput {
    pub old_root: Hash,
    pub updates: Vec<MapUpdate>,
}

/// Output of the map derivation guest program.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeriveBatchOutput {
    pub old_root: Hash,
    pub new_root: Hash,
    pub num_updates: u32,
}

/// Execute the batch derivation: verify each update against the rolling root,
/// then apply it. Returns the final root.
///
/// This is the function that runs inside the zkVM guest.
#[jolt::provable(
    max_input_size = 65536,
    max_output_size = 4096,
    stack_size = 65536,
    heap_size = 1048576,
    max_trace_length = 16777216
)]
fn derive_batch(input: DeriveBatchInput) -> DeriveBatchOutput {
    let mut current_root = input.old_root;

    for update in &input.updates {
        // Verify the old value (or non-membership) against the current root
        update
            .proof
            .verify(&current_root, &update.key, &update.old_value)
            .expect("proof verification failed for old value");

        // Compute the new root with the updated value
        current_root = update
            .proof
            .compute_root(&update.key, &update.value)
            .expect("failed to compute new root");
    }

    DeriveBatchOutput {
        old_root: input.old_root,
        new_root: current_root,
        num_updates: input.updates.len() as u32,
    }
}
