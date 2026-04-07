#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod compact_merkle;
mod hash;

pub use compact_merkle::CompactRange;
pub use hash::{empty_tree_root, hash_node, hash_rfc6962_leaf};

/// Hash output size in bytes (SHA-256).
pub const HASH_BYTES: usize = 32;

pub type Hash = [u8; HASH_BYTES];
