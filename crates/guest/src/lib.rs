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

/// A self-contained ZK append proof bundle.
///
/// Contains the prover's input, output, and the serialized Jolt ZK proof.
/// Everything needed for a verifier to check the proof (given preprocessing).
///
/// The proof attests: "the tree with the given frontier and size has root `old_root`,
/// and after appending `new_leaves`, the tree has root `new_root` and size `new_size`."
///
/// Create with [`AppendProof::new`]. Verify with `arbor-verify`'s `Verifier`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppendProof {
    /// The input that was given to the guest prover.
    pub input: AppendInput,
    /// The output produced by the guest prover.
    pub output: AppendOutput,
    /// Serialized Jolt ZK proof (ark-serialize compressed format).
    pub proof_bytes: Vec<u8>,
}

impl AppendProof {
    /// Create an `AppendProof` from its components.
    ///
    /// `proof_bytes` should be the Jolt proof serialized via
    /// `jolt_sdk::Serializable::serialize_to_bytes()`.
    pub fn new(input: AppendInput, output: AppendOutput, proof_bytes: Vec<u8>) -> Self {
        Self {
            input,
            output,
            proof_bytes,
        }
    }

    /// Convenience accessors.
    pub fn old_root(&self) -> &Hash {
        &self.output.old_root
    }
    pub fn new_root(&self) -> &Hash {
        &self.output.new_root
    }
    pub fn old_size(&self) -> u64 {
        self.output.old_size
    }
    pub fn new_size(&self) -> u64 {
        self.output.new_size
    }
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
