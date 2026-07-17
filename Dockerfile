# syntax=docker/dockerfile:1
# Chainguard Wolfi multi-stage build — CLAUDE.md security non-negotiable.
# Builder: cgr.dev/chainguard/rust:latest-dev  (Wolfi, has build toolchain)
# Runtime: cgr.dev/chainguard/glibc-dynamic    (Wolfi, minimal glibc runtime)
#
# Zero shell, zero package manager, Wolfi-hardened, runs as UID 65532 (nonroot).

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/rust:latest-dev AS builder

WORKDIR /build

# Cache dependency compilation separately from source.
COPY Cargo.toml Cargo.lock ./
COPY crates/shared/Cargo.toml crates/shared/Cargo.toml
COPY crates/gateway/Cargo.toml crates/gateway/Cargo.toml
COPY crates/ingest/Cargo.toml crates/ingest/Cargo.toml
COPY crates/policy/Cargo.toml crates/policy/Cargo.toml
COPY crates/mcp-rs/Cargo.toml crates/mcp-rs/Cargo.toml

RUN mkdir -p crates/shared/src crates/gateway/src crates/ingest/src \
        crates/policy/src crates/mcp-rs/src && \
    echo "pub fn _stub() {}" > crates/shared/src/lib.rs && \
    echo "fn main() {}" > crates/gateway/src/main.rs && \
    echo "fn main() {}" > crates/ingest/src/main.rs && \
    echo "pub fn _stub() {}" > crates/policy/src/lib.rs && \
    echo "pub fn _stub() {}" > crates/mcp-rs/src/lib.rs

RUN cargo build --release -p gateway 2>&1 | tail -5

COPY crates/ crates/
RUN touch crates/gateway/src/main.rs && \
    cargo build --release -p gateway

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/glibc-dynamic:latest AS runtime

LABEL org.opencontainers.image.title="Tracelane Gateway" \
      org.opencontainers.image.description="Predictive reliability gateway for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/tracelane/tracelane"

COPY --from=builder /build/target/release/gateway /usr/local/bin/gateway

EXPOSE 8080

ENV TRACELANE_PORT=8080 \
    TRACELANE_LOG_LEVEL=info \
    RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/gateway"]
