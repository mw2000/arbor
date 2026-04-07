# Arbor

Zero-knowledge proofs for append-only Merkle tree updates using [Jolt](https://github.com/a16z/jolt) zkVM.

Arbor proves that a batch of leaves was correctly appended to an RFC 6962 Merkle tree (the same structure used by [Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962) and [Trillian](https://github.com/google/trillian)). Instead of clients replaying log operations or checking interactive consistency proofs, they verify a single Jolt proof that attests:

> "The tree with root R_old and size N, after appending these K leaves, has root R_new and size N+K."

## Architecture

```
arbor/
  smt/    -- no_std Merkle tree library: CompactRange (append-only), sparse Merkle tree, hashing
  guest/  -- Jolt guest program: proves append operations inside the zkVM
  host/   -- Host-side operator: maintains tree state, prepares inputs, drives prove/verify
```

### Compact Range

The key data structure is the **compact range** (frontier): O(log N) subtree roots that compactly represent an N-leaf append-only Merkle tree. This is sufficient to compute the tree root and to append new leaves without storing the full tree.

For a tree of size N, the frontier contains one hash per set bit in the binary representation of N. For example, a 13-leaf tree (binary 1101) has 3 frontier entries: roots of subtrees of size 8, 4, and 1.

### Guest Program

`prove_append` takes:
- **Input**: frontier hashes, current tree size, new leaf data
- **Output**: old root, new root, old size, new size

The Jolt proof attests this computation was performed correctly.

### Hashing

RFC 6962 domain-separated SHA-256:
- Leaf: `SHA256(0x00 || data)`
- Node: `SHA256(0x01 || left || right)`
- Empty tree: `SHA256("")`

Uses `jolt-inlines-sha2` (custom RISC-V instructions) when compiled for the zkVM guest, standard `sha2` crate on the host.

## Usage

```rust
use arbor_host::LogProver;

let mut prover = LogProver::new();
let input = prover.prepare_append(vec![
    b"entry_1".to_vec(),
    b"entry_2".to_vec(),
    b"entry_3".to_vec(),
]);

// Native execution (no proof)
let output = guest::prove_append(input.clone());
assert_eq!(output.new_root, prover.root());

// Prove and verify with Jolt
let mut program = guest::compile_prove_append("/tmp/arbor-guest-targets");
let shared = guest::preprocess_shared_prove_append(&mut program).unwrap();
let prover_pp = guest::preprocess_prover_prove_append(shared.clone());
let verifier_pp = guest::preprocess_verifier_prove_append(
    shared, prover_pp.generators.to_verifier_setup(), None,
);
let prove = guest::build_prover_prove_append(program, prover_pp);
let verify = guest::build_verifier_prove_append(verifier_pp);

let (output, proof, io) = prove(input.clone());
assert!(verify(input, output, io.panic, proof));
```

## Building & Testing

Requires Rust 1.94 (set via `rust-toolchain.toml`) with the `riscv64imac-unknown-none-elf` target, and the [Jolt CLI](https://github.com/a16z/jolt) (`cargo install --path .` from the Jolt repo).

```bash
# Unit tests (fast, native execution only)
cargo test --workspace

# End-to-end prove/verify test (compiles guest for RISC-V, generates Jolt proof)
cargo test --release -p arbor-host --test prove_verify
```

## Trillian Integration

Arbor is designed to prove updates to Trillian's append-only log. The integration surface is Trillian's gRPC Log API:

1. Fetch new leaves via `GetLeavesByRange`
2. Package leaf data + current frontier into `AppendInput`
3. Generate Jolt proof via the guest program
4. Clients verify the proof instead of replaying log operations

The `LogProver` maintains the compact range state between batches, so sequential proofs chain together: each batch's `old_root` matches the previous batch's `new_root`.
