# Default: list available recipes
default:
    @just --list

# --------------------------------------------------------------------------
# Development
# --------------------------------------------------------------------------

# Format all code
fmt:
    cargo fmt --all

# Check formatting without modifying files
fmt-check:
    cargo fmt --all -- --check

# Run clippy on the workspace
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Type-check the workspace
check:
    cargo check --workspace

# Build the workspace in release mode
build:
    cargo build --workspace --release

# Build only the service binary in release mode
build-service:
    cargo build -p arbor-service --release

# --------------------------------------------------------------------------
# Testing
# --------------------------------------------------------------------------

# Run all tests
test:
    cargo test --workspace

# Run tests for a specific crate
test-crate crate:
    cargo test -p {{crate}}

# Run only arbor-core tests (no external deps needed)
test-core:
    cargo test -p arbor-core

# --------------------------------------------------------------------------
# Examples
# --------------------------------------------------------------------------

compose := "docker compose -f etc/docker/docker-compose.examples.yml"

# Run an example with full stack lifecycle (e.g., just example bank-ledger)
example name:
    {{compose}} down -v
    {{compose}} up -d --wait
    cargo run --example {{name}}; {{compose}} down -v

# --------------------------------------------------------------------------
# CI-style checks (run before pushing)
# --------------------------------------------------------------------------

# Run all CI checks: format, lint, check, test
ci: fmt-check lint check test
