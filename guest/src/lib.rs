#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use arbor_core::{CompactRange, Hash};
use serde::{Deserialize, Serialize};

/// Input to the append proof guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppendInput {
    /// Compact range frontier of the existing tree (subtree roots, largest first).
    pub frontier: Vec<Hash>,
    /// Current tree size (number of leaves).
    pub tree_size: u64,
    /// New leaf data to append.
    pub new_leaves: Vec<Vec<u8>>,
}

/// Output of the append proof guest program.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppendOutput {
    pub old_root: Hash,
    pub new_root: Hash,
    pub old_size: u64,
    pub new_size: u64,
}

/// Prove that appending `new_leaves` to a Merkle tree with the given
/// compact range produces the correct new root.
///
/// This runs inside the zkVM guest. The Jolt proof attests:
/// "the tree with frontier F and size N has root R_old, and after
/// appending these leaves, the tree has root R_new and size N+K."
#[jolt::provable(
    max_input_size = 65536,
    max_output_size = 4096,
    stack_size = 65536,
    heap_size = 1048576,
    max_trace_length = 16777216
)]
fn prove_append(input: AppendInput) -> AppendOutput {
    let mut compact = CompactRange::from_parts(input.frontier, input.tree_size);
    let old_root = compact.root();
    let old_size = compact.size();

    for leaf in &input.new_leaves {
        compact.append(leaf);
    }

    AppendOutput {
        old_root,
        new_root: compact.root(),
        old_size,
        new_size: compact.size(),
    }
}
