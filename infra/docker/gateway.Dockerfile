# Tracelane gateway — Chainguard Wolfi multi-stage build (CLAUDE.md container base).
#
# Builder: cgr.dev/chainguard/rust:latest-dev  — Wolfi, full toolchain + apk.
# Runtime: cgr.dev/chainguard/glibc-dynamic    — the binary is glibc-linked (the
#          Wolfi rust image targets glibc); chainguard/static has NO libc and the
#          binary would fail to load. Use glibc-dynamic, not static.
#
# Bases are tag-referenced. Pin to the digest from the first node build
# (`docker images --digests`) and re-pin on each base bump — cgr.dev free
# `:latest` digests are GC'd over time, so we pin the digest we actually ran.
FROM cgr.dev/chainguard/rust:latest-dev@sha256:812b1f7bad6a00a1ea4dae924eb9a3621402d6912b37de1d0847d77555282a42 AS builder
USER root
# aws-lc-rs / ring (via rustls + jsonwebtoken's aws_lc_rs feature) compile C → cmake.
RUN apk add --no-cache cmake
WORKDIR /build
# Full workspace context: `cargo build -p gateway` loads ALL workspace members
# (crates/* + packages/verifier-rust per the root Cargo.toml); a partial copy
# fails with "failed to load manifest for workspace member".
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY packages/verifier-rust/ packages/verifier-rust/
# The gateway embeds the authoritative Drizzle migrations at compile time
# (crates/gateway/src/db include_str!("../../../../apps/web/db/migrations/*.sql");
# so they must be present in the build context at the same relative path.
COPY apps/web/db/migrations/ apps/web/db/migrations/
# BuildKit cache mounts persist the cargo registry + target/ across deploys, so a
# gateway-only change recompiles just the changed crate (~1min) instead of the
# full ~500-dep tree from scratch (~5min). The binary MUST be copied OUT of the
# target cache mount — cache-mount contents are NOT in the layer the runtime COPY
# reads (that would `COPY … not found`).
RUN --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release -p gateway && \
    cp /build/target/release/gateway /gateway

FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:57e5704e70a85b90191182eb6110d1c817df0d8e96035cb041195c5a351f0861 AS runtime
LABEL org.opencontainers.image.title="Tracelane Gateway" \
      org.opencontainers.image.description="The flight recorder for AI agents — Rust gateway" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/tracelane/tracelane"
COPY --from=builder /gateway /usr/local/bin/gateway
EXPOSE 8080
ENV TRACELANE_PORT=8080 \
    TRACELANE_LOG_FORMAT=json \
    RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/gateway"]
