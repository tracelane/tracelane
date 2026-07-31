# syntax=docker/dockerfile:1
# Tracelane gateway — Chainguard Wolfi multi-stage build (CLAUDE.md container base).
#
# Builder: cgr.dev/chainguard/rust:latest-dev  — Wolfi, full toolchain + apk.
# Runtime: cgr.dev/chainguard/glibc-dynamic    — the binary is glibc-linked (the
#          Wolfi rust image targets glibc); chainguard/static has NO libc and the
#          binary would fail to load. Use glibc-dynamic, not static.
#
# This is the recipe `.github/workflows/release-container.yml` publishes to GHCR.
# It deliberately mirrors `infra/docker/gateway.Dockerfile` (the one that builds
# the running production gateway) step for step. It previously did NOT, and the
# release job failed 5/5 — never once producing an image — on four independent
# defects, each masked by the one before it:
#   1. `COPY crates/mcp-rs/…` for a crate that exists in no branch of either repo
#      and is not a workspace member  ->  "not found" before anything compiled;
#   2. no `USER root`, so the nonroot Wolfi user cannot mkdir under WORKDIR
#      ->  "mkdir: can't create directory 'crates/shared/src': Permission denied";
#   3. no cmake, which aws-lc-rs / ring need to compile their C;
#   4. a partial workspace copy (no packages/verifier-rust) and no
#      apps/web/db/migrations, which the gateway `include_str!`s at compile time.
# Keep the two files in step: a second, divergent build definition for the same
# binary is what let this rot unnoticed.
FROM cgr.dev/chainguard/rust:latest-dev@sha256:812b1f7bad6a00a1ea4dae924eb9a3621402d6912b37de1d0847d77555282a42 AS builder
USER root
# aws-lc-rs / ring (via rustls + jsonwebtoken's aws_lc_rs feature) compile C -> cmake.
RUN apk add --no-cache cmake
WORKDIR /build
# Full workspace context: `cargo build -p gateway` loads ALL workspace members
# (crates/* + packages/verifier-rust per the root Cargo.toml); a partial copy
# fails with "failed to load manifest for workspace member".
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY packages/verifier-rust/ packages/verifier-rust/
# The gateway embeds the authoritative Drizzle migrations at compile time
# (crates/gateway/src/db include_str!("../../../../apps/web/db/migrations/*.sql")),
# so they must be present in the build context at the same relative path.
COPY apps/web/db/migrations/ apps/web/db/migrations/
# BuildKit cache mounts persist the cargo registry + target/ across builds. The
# binary MUST be copied OUT of the target cache mount — cache-mount contents are
# NOT in the layer the runtime COPY reads (that would `COPY … not found`).
RUN --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release -p gateway && \
    cp /build/target/release/gateway /gateway

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:57e5704e70a85b90191182eb6110d1c817df0d8e96035cb041195c5a351f0861 AS runtime

LABEL org.opencontainers.image.title="Tracelane Gateway" \
      org.opencontainers.image.description="Predictive reliability gateway for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/tracelane/tracelane"

COPY --from=builder /gateway /usr/local/bin/gateway

EXPOSE 8080

ENV TRACELANE_PORT=8080 \
    TRACELANE_LOG_FORMAT=json \
    RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/gateway"]
