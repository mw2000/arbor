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
#   protobuf-compiler  – tonic-build needs protoc
#   pkg-config/cmake   – native dependency builds
#   git                – git-based Cargo dependencies (jolt, arkworks)
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        pkg-config \
        cmake \
        git \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

# Install the RISC-V target required by the Jolt guest crate.
RUN rustup target add riscv64imac-unknown-none-elf

WORKDIR /app

# --- Cache layer: build only dependencies from the recipe ------------------
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# --- Build the actual project ----------------------------------------------
COPY . .

RUN cargo build --release -p arbor-service && \
    strip target/release/arbor-service-bin


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
    "--job-store-path", "/data/arbor-jobs.db" \
]

EXPOSE 50051

# Metadata.
LABEL org.opencontainers.image.title="arbor" \
      org.opencontainers.image.description="Transparency log with ZK append proofs" \
      org.opencontainers.image.source="https://github.com/mw2000/arbor"
