use crate::{Hash, HASH_BYTES, TREE_DEPTH};

/// Compute SHA-256. Uses the Jolt inline on RISC-V targets (guest),
/// standard `sha2` crate on all other targets (host).
pub(crate) fn sha256(data: &[u8]) -> Hash {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        jolt_inlines_sha2::Sha256::digest(data)
    }
    #[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
    {
        use sha2::{Digest, Sha256};
        let result = Sha256::digest(data);
        let mut out = [0u8; HASH_BYTES];
        out.copy_from_slice(&result);
        out
    }
}

/// Domain separator for leaf nodes: SHA256(0x00 || key || value).
pub fn hash_leaf(key: &[u8; 32], value: &[u8]) -> Hash {
    let mut preimage = alloc::vec![0u8; 1 + 32 + value.len()];
    preimage[0] = 0x00;
    preimage[1..33].copy_from_slice(key);
    preimage[33..].copy_from_slice(value);
    sha256(&preimage)
}

/// Domain separator for internal nodes: SHA256(0x01 || left || right).
pub fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut preimage = [0u8; 1 + 32 + 32];
    preimage[0] = 0x01;
    preimage[1..33].copy_from_slice(left);
    preimage[33..65].copy_from_slice(right);
    sha256(&preimage)
}

/// Hash of the default empty leaf: SHA256(0x00 || [0; 32]).
pub fn empty_leaf_hash() -> Hash {
    let mut preimage = [0u8; 1 + 32];
    preimage[0] = 0x00;
    sha256(&preimage)
}

/// RFC 6962 leaf hash: SHA256(0x00 || data).
/// Used for append-only Merkle trees (Certificate Transparency / Trillian).
pub fn hash_rfc6962_leaf(data: &[u8]) -> Hash {
    let mut preimage = alloc::vec![0u8; 1 + data.len()];
    preimage[0] = 0x00;
    preimage[1..].copy_from_slice(data);
    sha256(&preimage)
}

/// Root of an empty tree (0 leaves): SHA-256("") per RFC 6962 §2.1.
pub fn empty_tree_root() -> Hash {
    sha256(&[])
}

/// Compute default hashes for each level of an empty sparse Merkle tree.
/// `result[0]` = empty leaf hash, `result[d]` = hash_node(result[d-1], result[d-1]).
/// `result[TREE_DEPTH]` is the root of a completely empty tree.
pub fn compute_empty_hashes() -> [Hash; TREE_DEPTH + 1] {
    let mut hashes = [[0u8; HASH_BYTES]; TREE_DEPTH + 1];
    hashes[0] = empty_leaf_hash();
    for i in 1..=TREE_DEPTH {
        hashes[i] = hash_node(&hashes[i - 1], &hashes[i - 1]);
    }
    hashes
}
