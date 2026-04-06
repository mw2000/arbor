# Arbor

Provable sparse Merkle tree map derivation using [Jolt](https://github.com/a16z/jolt) zkVM.

Arbor extends the [Verifiable Log-Derived Map](https://research.google/pubs/verifiable-data-structures/) pattern: instead of clients replaying an entire log to verify a map was derived correctly, they verify a single Jolt proof that attests "applying these log entries to the old map root produces this new map root."

## Architecture

```
arbor/
  smt/    -- no_std sparse Merkle tree: hash functions, proof verification, in-memory tree
  guest/  -- Jolt guest program: verifies + applies a batch of SMT updates inside the zkVM
  host/   -- Host-side operator: maintains the full tree, prepares batch inputs, drives prove/verify
```

**Guest program** (`derive_batch`): takes an old root and a list of updates (each with key, new value, old value, Merkle proof), verifies each proof against the rolling root, computes the new root, and outputs `(old_root, new_root, num_updates)`.

**SHA-256**: uses `jolt-inlines-sha2` (custom RISC-V instructions) when compiled for the zkVM guest, standard `sha2` crate on the host.

## Usage

```rust
use arbor_host::MapOperator;

let mut operator = MapOperator::new();
let batch_input = operator.prepare_batch(vec![
    ([0x01; 32], b"value_one".to_vec()),
    ([0x02; 32], b"value_two".to_vec()),
]);

// Native execution (no proof)
let output = guest::derive_batch(batch_input.clone());
assert_eq!(output.new_root, operator.root());

// Prove and verify with Jolt
let mut program = guest::compile_derive_batch("/tmp/arbor-guest-targets");
let shared = guest::preprocess_shared_derive_batch(&mut program).unwrap();
let prover_pp = guest::preprocess_prover_derive_batch(shared.clone());
let verifier_pp = guest::preprocess_verifier_derive_batch(
    shared, prover_pp.generators.to_verifier_setup(), None,
);
let prove = guest::build_prover_derive_batch(program, prover_pp);
let verify = guest::build_verifier_derive_batch(verifier_pp);

let (output, proof, io) = prove(batch_input.clone());
assert!(verify(batch_input, output, io.panic, proof));
```

## Building & Testing

Requires Rust 1.94 (set via `rust-toolchain.toml`) with the `riscv64imac-unknown-none-elf` target, and the [Jolt CLI](https://github.com/a16z/jolt) (`cargo install --path .` from the Jolt repo).

```bash
# Unit tests (fast, native execution only)
cargo test --workspace

# End-to-end prove/verify test (compiles guest for RISC-V, generates Jolt proof)
cargo test --release -p arbor-host --test prove_verify
```

## Performance

Single SMT update (256-level tree, SHA-256):
- ~6.4M total cycles (908K real RISC-V + 5.5M virtual)
- ~20s proving time at 318 kHz (release, Apple Silicon)
