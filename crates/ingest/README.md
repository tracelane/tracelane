<!-- tracelane:classification: PUBLIC -->
# crates/ingest

Tracelane's Rust ingest workers — span processing pipeline.

## Responsibility

- Consume spans from NATS JetStream (emitted by the gateway)
- Parse and validate against OpenInference + OTel GenAI semconv
- Apply tail-sampling policy when enabled. NOTE: full-fidelity capture is the shipped default — a recorder that drops clean spans is not a recorder
- Batch-write to ClickHouse — the sole span writer, and it writes one table,
  `tracelane.spans`. Cold archival, where configured, is a ClickHouse storage
  policy that moves aged parts to an object-storage volume (the tiering section
  of migration 24 in `infra/dev/clickhouse/migrations/`) — not a second writer,
  and not this crate's R2 batcher, which was deleted on 2026-09-12 with zero
  producers wired to it.

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

- FT-03: ClickHouse downtime → NATS JetStream buffers up to the stream's byte and
  age limits (set in `nats_consumer.rs`); beyond them the oldest spans are
  discarded and the gap is counted (`/health.spans_stream` on the gateway,
  `tracelane.capture_gaps` in ClickHouse)
- FT-04: R2 outage → degrade to hot-tier-only, alert fires within 60s. **Moot for
  this crate since 2026-09-12:** ingest never had an R2 write path to degrade
  from — its R2 batcher is deleted. Cold archival is a ClickHouse storage policy
  (see Responsibility above), not an ingest concern.
- FT-08: Disk full → reject new writes, reads continue, alert fires
