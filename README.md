[![Arbor](assets/banner.png)](assets/banner.png)

# Arbor

Zero-knowledge proofs for [Trillian](https://github.com/google/trillian) log updates using [Jolt](https://github.com/a16z/jolt) zkVM.

Arbor syncs leaves from a Trillian log, rebuilds the append-only Merkle tree locally, and generates a Jolt proof that the update was correct. Instead of clients replaying log operations or checking interactive consistency proofs, they verify a single proof:

> "The tree with root R_old and size N, after appending these K leaves, has root R_new and size N+K."

## Architecture

```
arbor/
  crates/
    core/       -- no_std Merkle tree library (CompactRange, RFC 6962 hashing)
    guest/      -- Jolt guest program: proves append operations inside the zkVM
    host/       -- Host-side LogProver: maintains tree state, prepares inputs
    trillian/   -- Trillian gRPC client: syncs log leaves, verifies roots
    server/     -- gRPC service layer (library)
    store/      -- Proof + job storage (SQLite)
    verify/     -- Standalone verifier for all proof types
    bench/      -- Criterion benchmarks
  bin/
    service/    -- Server binary (arbor-service-bin)
  examples/     -- Rust examples (bank-ledger, audit-log, supply-chain, CT)
  etc/
    docker/     -- Dockerfile and docker-compose
    sql/        -- Trillian MySQL schema
```

### How it works

1. **Sync** — `TrillianSyncer` fetches new leaves from a Trillian log server and appends them to a local `CompactRange` (frontier). The locally-computed root is verified against Trillian's signed root.

2. **Prove** — The sync result is fed into the Jolt guest program `prove_append`, which re-executes the append inside the zkVM and produces a ZK proof.

3. **Verify** — Anyone with the proof can verify the log update without trusting the log server or re-fetching leaves.

## Quick start

Requires [Rust 1.94](rust-toolchain.toml), [Docker](https://docs.docker.com/get-docker/), and [just](https://github.com/casey/just).

```bash
# Start the full stack (MySQL + Trillian + Arbor)
docker compose -f etc/docker/docker-compose.examples.yml up -d

# Run an example
just example bank-ledger
```

See [`examples/README.md`](examples/README.md) for all available examples.

## Development

```bash
just fmt        # format
just lint       # clippy
just check      # type-check
just test       # run tests
just ci         # all of the above
```

## Testing

```bash
# Unit tests (no external deps)
just test-core

# All workspace tests
just test
```
