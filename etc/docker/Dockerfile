# ---------------------------------------------------------------------------
# Arbor — multi-stage Docker build
#
# Techniques used:
#   1. cargo-chef for dependency caching (avoids rebuilding deps on src changes)
#   2. Multi-stage build (planner → builder → runtime)
#   3. Debian slim runtime image (minimal footprint, glibc compatible)
#   4. Non-root user in runtime
#   5. Layer ordering optimised for Docker layer cache
#   6. .dockerignore-friendly (see etc/docker/.dockerignore)
#   7. Pre-compiled Jolt guest ELF — runtime doesn't need Rust or jolt CLI
#
# Build:
#   docker build -f etc/docker/Dockerfile -t arbor .
#
# Run:
#   docker run --rm arbor --help
# ---------------------------------------------------------------------------

# ---- Stage 0: chef planner (compute dependency recipe) --------------------
FROM rust:1.94-bookworm AS planner

RUN cargo install cargo-chef --locked

WORKDIR /app
COPY . .

# Analyse the workspace and produce a recipe.json that captures dependency
# information without any source code — this is the cache key.
RUN cargo chef prepare --recipe-path recipe.json


# ---- Stage 1: builder (compile dependencies, then the project) ------------
FROM rust:1.94-bookworm AS builder

# System dependencies:
#   protobuf-compiler    – tonic-build needs protoc
#   libprotobuf-dev      – Google well-known .proto files (any.proto, timestamp.proto, etc.)
#   pkg-config/cmake     – native dependency builds
#   git                  – git-based Cargo dependencies (jolt, arkworks)
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        libprotobuf-dev \
        pkg-config \
        cmake \
        git \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

# Install the RISC-V target required by the Jolt guest crate.
RUN rustup target add riscv64imac-unknown-none-elf

# Install the Jolt CLI (needed to cross-compile the guest program to RISC-V).
# Pinned to the same commit as jolt-sdk in Cargo.lock for reproducibility.
RUN cargo install --git https://github.com/a16z/jolt --rev 18bfa50983c8202079f8a3ab11c82a96f43f92ef

WORKDIR /app

# --- Cache layer: build only dependencies from the recipe ------------------
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# --- Build the actual project ----------------------------------------------
COPY . .

RUN cargo build --release -p arbor-service && \
    strip target/release/arbor-service-bin

# --- Pre-compile the Jolt guest ELF ---------------------------------------
# This produces the RISC-V ELF that the server loads at startup via
# --precompiled-elf, removing the need for the jolt CLI at runtime.
#
# The guest crate attributes (stack_size, heap_size) must match the
# #[jolt::provable] annotation in crates/guest/src/lib.rs.
RUN mkdir -p /app/guest-elf && \
    JOLT_FUNC_NAME=prove_append \
    jolt build -p arbor-guest \
        --stack-size 65536 \
        --heap-size 1048576 \
        -- --release \
           --target-dir /tmp/jolt-guest/arbor-guest-prove_append \
           --features guest && \
    cp /tmp/jolt-guest/arbor-guest-prove_append/riscv64imac-unknown-none-elf/release/arbor-guest \
       /app/guest-elf/guest.elf


# ---- Stage 2: runtime (minimal image) ------------------------------------
FROM debian:bookworm-slim AS runtime

# libssl + ca-certificates for outbound TLS (Trillian endpoint),
# tini for proper PID 1 signal handling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user.
RUN groupadd --system arbor && \
    useradd --system --gid arbor --create-home arbor

# Copy the release binary.
COPY --from=builder /app/target/release/arbor-service-bin /usr/local/bin/arbor-service-bin

# Copy the pre-compiled guest ELF.
COPY --from=builder /app/guest-elf /opt/arbor/guest-elf

# Proof + job store default paths inside the container.
RUN mkdir -p /data && chown arbor:arbor /data
VOLUME ["/data"]

USER arbor
WORKDIR /data

# Default args point at common paths — override at runtime.
ENTRYPOINT ["tini", "--", "arbor-service-bin"]
CMD [ \
    "--listen", "[::]:50051", \
    "--store-path", "/data/arbor-proofs.db", \
    "--job-store-path", "/data/arbor-jobs.db", \
    "--precompiled-elf", "/opt/arbor/guest-elf" \
]

EXPOSE 50051

# Metadata.
LABEL org.opencontainers.image.title="arbor" \
      org.opencontainers.image.description="Transparency log with ZK append proofs" \
      org.opencontainers.image.source="https://github.com/mw2000/arbor"
