<!-- tracelane:classification: PUBLIC -->
# crates/ingest

Tracelane's Rust ingest workers — span processing pipeline.

## Responsibility

- Consume spans from NATS JetStream (emitted by the gateway)
- Parse and validate against OpenInference + OTel GenAI semconv
- Apply tail-sampling policy when enabled. NOTE: full-fidelity capture is the shipped default — a recorder that drops clean spans is not a recorder
- Batch-write to ClickHouse (hot tier, 365-day retention)
- Cold-span packing to Cloudflare R2 (Parquet) is implemented but **not active** —
  `main.rs:350` drops the sender, so no span is written to R2 today

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
- FT-04: R2 outage → degrade to hot-tier-only, alert fires within 60s
- FT-08: Disk full → reject new writes, reads continue, alert fires
