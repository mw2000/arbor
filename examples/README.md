# Examples

Runnable Rust examples demonstrating different use cases for Arbor.

## Available examples

| Example | Run | Description |
|---------|-----|-------------|
| bank-ledger | `cargo run --example bank-ledger` | Immutable financial transaction log |
| software-supply-chain | `cargo run --example software-supply-chain` | Binary transparency for release artifacts |
| audit-log | `cargo run --example audit-log` | Tamper-evident user access tracking |
| certificate-transparency | `cargo run --example certificate-transparency` | Publicly auditable TLS certificate issuance |

## Setup

All examples connect to a running Arbor server as gRPC clients.

### Start the full stack with Docker

From the repository root:

```sh
docker compose -f etc/docker/docker-compose.examples.yml up -d
```

This builds and starts everything: MySQL, Trillian (log server + signer),
and the Arbor service. Arbor will be available on `localhost:50051`.

```sh
# Verify everything is healthy:
docker compose -f etc/docker/docker-compose.examples.yml ps
```

### Run any example

```sh
cargo run --example bank-ledger
cargo run --example audit-log
cargo run --example software-supply-chain
cargo run --example certificate-transparency
```

Each example connects to the Arbor server, appends realistic leaf data,
submits async proof generation jobs, and prints the results.

### Tear down

```sh
docker compose -f etc/docker/docker-compose.examples.yml down -v
```
