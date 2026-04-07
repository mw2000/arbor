# Arbor

Zero-knowledge proofs for [Trillian](https://github.com/google/trillian) log updates using [Jolt](https://github.com/a16z/jolt) zkVM.

Arbor syncs leaves from a Trillian log, rebuilds the append-only Merkle tree locally, and generates a Jolt proof that the update was correct. Instead of clients replaying log operations or checking interactive consistency proofs, they verify a single proof:

> "The tree with root R_old and size N, after appending these K leaves, has root R_new and size N+K."

## Architecture

```
arbor/
  crates/
    core/       -- arbor-core: no_std Merkle tree library (CompactRange, RFC 6962 hashing)
    guest/      -- Jolt guest program: proves append operations inside the zkVM
    host/       -- Host-side LogProver: maintains tree state, prepares inputs, drives prove/verify
    trillian/   -- Trillian gRPC client: syncs log leaves, verifies roots
  docker/       -- Docker Compose for local Trillian (MySQL + log server + signer)
```

### How it works

1. **Sync** — `TrillianSyncer` connects to a Trillian log server, fetches new leaves via gRPC, and appends them to a local `CompactRange` (frontier). After syncing, it verifies the locally-computed root matches Trillian's signed root.

2. **Prove** — The sync result (old frontier, tree size, new leaf data) is fed into the Jolt guest program `prove_append`, which re-executes the append inside the zkVM and produces a proof.

3. **Verify** — Anyone with the proof can verify the log update without trusting the log server or re-fetching leaves.

### Compact Range

The key data structure is the **compact range** (frontier): O(log N) subtree roots that compactly represent an N-leaf append-only Merkle tree. This is sufficient to compute the tree root and to append new leaves without storing the full tree.

For a tree of size N, the frontier contains one hash per set bit in the binary representation of N. For example, a 13-leaf tree (binary 1101) has 3 frontier entries: roots of subtrees of size 8, 4, and 1.

### Hashing

RFC 6962 domain-separated SHA-256:
- Leaf: `SHA256(0x00 || data)`
- Node: `SHA256(0x01 || left || right)`
- Empty tree: `SHA256("")`

Uses `jolt-inlines-sha2` (custom RISC-V instructions) when compiled for the zkVM guest, standard `sha2` crate on the host.

## Usage

```rust
use arbor_host::LogProver;

// Connect to Trillian and create a log tree
let mut prover = LogProver::connect_and_create_tree("http://localhost:8090").await?;

// Queue leaves, sync from Trillian, and prepare the proving input
let (input, result) = prover.sync_and_prepare(vec![
    b"leaf-0".to_vec(),
    b"leaf-1".to_vec(),
]).await?;

// Compile and preprocess the guest program
let mut program = guest::compile_prove_append("/tmp/arbor-guest-targets");
let shared = guest::preprocess_shared_prove_append(&mut program).unwrap();
let prover_pp = guest::preprocess_prover_prove_append(shared.clone());
let verifier_pp = guest::preprocess_verifier_prove_append(
    shared, prover_pp.generators.to_verifier_setup(), None,
);
let prove = guest::build_prover_prove_append(program, prover_pp);
let verify = guest::build_verifier_prove_append(verifier_pp);

// Prove and verify
let (output, proof, io) = prove(input.clone());
assert!(verify(input, output, io.panic, proof));
```

## Building & Testing

Requires Rust 1.94 (set via `rust-toolchain.toml`) with the `riscv64imac-unknown-none-elf` target.

Requires a running Trillian instance for integration and end-to-end tests.

```bash
# Start Trillian (MySQL + log server + signer)
cd docker && docker compose up -d

# Unit tests (fast, native execution)
cargo nextest run --cargo-quiet

# Trillian sync test (verifies RFC 6962 root compatibility)
cargo nextest run -p arbor-trillian --test integration --run-ignored ignored-only --no-capture

# Full pipeline: Trillian sync → Jolt proof → verify (~16s)
cargo nextest run --release -p arbor-host --test trillian_prove --run-ignored ignored-only --no-capture

# Tear down
cd docker && docker compose down
```
