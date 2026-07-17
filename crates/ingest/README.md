# crates/ingest

Tracelane's Rust ingest workers — span processing pipeline.

## Responsibility

- Consume spans from NATS JetStream (emitted by the gateway)
- Parse and validate against OpenInference + OTel GenAI semconv
- Apply tail-sampling policy (100% errors/high-cost/predictive-flagged; 5–10% nominal)
- Batch-write to ClickHouse (hot tier, 90-day retention)
- Pack and write cold spans to Cloudflare R2 (Parquet, 1MB batches)

## Key modules

| Module | Purpose |
|---|---|
| `main.rs` | Binary entry point — load config, start NATS consumer and OTLP receiver |
| `nats_consumer.rs` | JetStream consumer — durable, at-least-once, manual ack on CH write |
| `otlp_receiver.rs` | gRPC OTLP receiver — accepts spans directly from SDKs |
| `clickhouse_writer.rs` | Batched ClickHouse writer — retry loop, back-pressure on downtime (FT-03) |
| `tail_sampler.rs` | Sampling policy — 100% error/cost/predictive, configurable nominal rate |
| `config.rs` | Environment-based config — NATS_URL, CLICKHOUSE_URL, tenant-specific overrides |
| `auth.rs` | Ingest-side auth — validates SPIFFE mTLS certificates for internal emitters |

## Throughput targets

- ≥50K spans/sec single-node, ≥200K/3-node
- Ingest end-to-end latency: <1s p50, <3s p95, <5s p99

## Fault tolerance

- FT-03: ClickHouse downtime → NATS buffers, zero data loss
- FT-04: R2 outage → degrade to hot-tier-only, alert fires within 60s
- FT-08: Disk full → reject new writes, reads continue, alert fires
