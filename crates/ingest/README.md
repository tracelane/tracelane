<!-- tracelane:classification: PUBLIC -->
# crates/ingest

Tracelane's Rust ingest workers — span processing pipeline.

## Responsibility

- Consume spans from NATS JetStream (emitted by the gateway)
- Parse and validate against OpenInference + OTel GenAI semconv
- Apply tail-sampling policy when enabled. NOTE: full-fidelity capture is the shipped default — a recorder that drops clean spans is not a recorder
- Batch-write to ClickHouse (hot tier, 365-day retention) — the sole span writer,
  and the sole tier: there is no cold-tier archival to object storage. A cold-tier
  R2 batcher existed in this crate through 2026-09-12 and was deleted —
  it had zero producers wired to it and was never reachable by any span. If
  cold-tier archival is ever rebuilt, it will be built with a real producer.

## Key modules

| Module | Purpose |
|---|---|
| `main.rs` | Binary entry point — load config, start NATS consumer and OTLP receiver |
| `nats_consumer.rs` | JetStream consumer — durable, at-least-once, manual ack on CH write |
| `otlp_receiver.rs` | gRPC OTLP receiver — accepts spans directly from SDKs |
| `clickhouse_writer.rs` | Batched ClickHouse writer — retry loop, back-pressure on downtime (FT-03) |
| `tail_sampler.rs` | Sampling policy — off by default; when enabled, keeps 100% of error/cost/predictive-flagged spans |
| `config.rs` | Environment-based config — NATS_URL, CLICKHOUSE_URL, tenant-specific overrides |
| `auth.rs` | Ingest-side auth — validates SPIFFE mTLS certificates for internal emitters |

## Throughput targets

- ≥50K spans/sec single-node, ≥200K/3-node
- Ingest end-to-end latency: <1s p50, <3s p95, <5s p99

## Fault tolerance

- FT-03: ClickHouse downtime → NATS buffers, zero data loss
- FT-04: R2 outage → degrade to hot-tier-only, alert fires within 60s. **Moot as
  of B-390 (2026-09-12):** there was never an R2 write path for this to degrade
  from — the cold tier is deleted, not merely outage-tolerant.
- FT-08: Disk full → reject new writes, reads continue, alert fires
