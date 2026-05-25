# Multi-stage build for the Mantis daemon (PRD §14.2 self-hosted VPS).
# - Stage 1: cargo chef cache layer (rebuilds deps only when Cargo.lock changes)
# - Stage 2: build the daemon and CLI binaries in release mode
# - Stage 3: runtime image with the two statically-linkable binaries
#
# Usage:
#   docker build -t mantis:latest -f deploy/docker/Dockerfile .
#   docker run --rm -p 8080:8080 -v $PWD/workspace:/workspace mantis:latest

FROM rust:1.83-bookworm AS chef
WORKDIR /build
RUN cargo install cargo-chef --locked --version 0.1.69
COPY rust-toolchain.toml ./

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# Cook deps using the recipe (cache-friendly layer)
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin mantis-daemon --bin mantis

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/bash mantis

USER mantis
WORKDIR /home/mantis

# Default workspace path. Operators bind-mount their own data dir
# at /workspace and pass --workspace /workspace.
ENV MANTIS_WORKSPACE=/workspace
VOLUME ["/workspace"]

COPY --from=builder /build/target/release/mantis-daemon /usr/local/bin/mantis-daemon
COPY --from=builder /build/target/release/mantis /usr/local/bin/mantis

# Apache-2.0 §4(a) / §4(d): every distribution of the binaries must
# include a copy of the License texts and the NOTICE file (which
# preserves the upstream Hacker Bob attribution).
COPY --from=builder /build/LICENSE-APACHE /usr/share/doc/mantishack/LICENSE-APACHE
COPY --from=builder /build/LICENSE-MIT    /usr/share/doc/mantishack/LICENSE-MIT
COPY --from=builder /build/NOTICE         /usr/share/doc/mantishack/NOTICE

EXPOSE 8080

# Healthcheck hits the Web UI /healthz endpoint when enabled.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail http://127.0.0.1:8080/healthz || exit 1

CMD ["/usr/local/bin/mantis-daemon"]
