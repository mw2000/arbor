#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod hash;
mod proof;
mod tree;

pub use hash::{compute_empty_hashes, empty_leaf_hash, hash_leaf, hash_node};
pub use proof::{SparseMerkleProof, VerifyError};
#[cfg(feature = "std")]
pub use tree::SparseMerkleTree;

/// Key size in bytes (256-bit keys).
pub const KEY_BYTES: usize = 32;
/// Tree depth (one level per bit of the key).
pub const TREE_DEPTH: usize = KEY_BYTES * 8;
/// Hash output size in bytes (SHA-256).
pub const HASH_BYTES: usize = 32;

pub type Key = [u8; KEY_BYTES];
pub type Hash = [u8; HASH_BYTES];
