# Tracelane ingest — Chainguard Wolfi multi-stage build (CLAUDE.md container base).
#
# Builder: cgr.dev/chainguard/rust:latest-dev  — Wolfi, full toolchain + apk.
# Runtime: cgr.dev/chainguard/glibc-dynamic    — glibc-linked binary (see gateway
#          Dockerfile note: NOT chainguard/static).
#
# ingest's build.rs generates the SPIRE Workload API stubs via tonic-build using
# a VENDORED protoc (protoc-bin-vendored) — no system protobuf-compiler needed.
#
# Bases are tag-referenced; digest-pin from the first node build and re-pin on bump.
FROM cgr.dev/chainguard/rust:latest-dev@sha256:812b1f7bad6a00a1ea4dae924eb9a3621402d6912b37de1d0847d77555282a42 AS builder
USER root
# aws-lc-rs / ring compile C → cmake.
RUN apk add --no-cache cmake
WORKDIR /build
# Full workspace context — all members must be present (see gateway Dockerfile).
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY packages/verifier-rust/ packages/verifier-rust/
RUN cargo build --release -p ingest

FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:57e5704e70a85b90191182eb6110d1c817df0d8e96035cb041195c5a351f0861 AS runtime
LABEL org.opencontainers.image.title="Tracelane Ingest" \
      org.opencontainers.image.description="OTLP receiver + NATS consumer + ClickHouse writer (SPIFFE mTLS)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/tracelane/tracelane"
# Deploy provenance — the SAME stamp the gateway carries, and for the same reason.
# Added 2026-08-11: check-deploy-provenance.sh accepts any container as its argument,
# but ingest carried no labels, so it answered CANNOT DETERMINE for exactly half the
# data plane while reporting STAMPED for the gateway. A control that covers one of two
# services reads as coverage. `scripts/deploy/gateway.sh` already builds both under
# DEPLOY_INGEST=1 with these ARGs set, so this needed no change on the deploy side —
# only the label was missing.
ARG TRACELANE_DEPLOY_SHA=""
ARG TRACELANE_DEPLOY_VIA=""
LABEL org.tracelane.deploy.sha="$TRACELANE_DEPLOY_SHA" \
      org.tracelane.deploy.via="$TRACELANE_DEPLOY_VIA"
COPY --from=builder /build/target/release/ingest /usr/local/bin/ingest
# OTLP HTTP receiver (mTLS-enforced in release builds when TRACELANE_SPIRE_SOCKET set)
EXPOSE 4318
ENV TRACELANE_LOG_FORMAT=json \
    RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/ingest"]
