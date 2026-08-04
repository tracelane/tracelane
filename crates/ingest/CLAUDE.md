# crates/ingest — local rules

> Loads only when working under `crates/ingest/`. Long form: `docs/TRAPS.md`.

## The two fail-directions are OPPOSITE — do not conflate them

Per-tenant capture policy is resolved **at ingest**, not the gateway, from a
Postgres-backed `TenantConfigCache` (30s TTL):

| Situation | Direction | Result |
|---|---|---|
| **Unknown tenant** (no row) | fails **CHEAP** | `Tail` sampling |
| **Resolver FAULT** (Neon blip) | fails **EXPENSIVE** | `fault_keep_all` = Full capture, capped by a finite `fault_quota` (default **25,000,000**) |

`tenant_config.rs:17-27` ("Two distinct fail directions"), `:107-111`;
`quota.rs:74` `DEFAULT_FAULT_QUOTA`.

**Getting this backwards either drops paying customers' data or bills unbounded COGS on
a control-plane blip.** A "simplification" that makes both directions agree is a bug in
one of them.

## Durability is not uniform

- **NATS-sourced spans:** acked **only after** the ClickHouse flush succeeds
  (ack-after-write, #81) — `nats_consumer.rs:119-130`, `clickhouse_writer.rs:277-280`.
- **OTLP-direct spans:** carry **no ack at all**. The receiver returns 200 the moment
  they are `try_send` into the in-process channel (`span_envelope.rs:20-23`).

**The FT-03 zero-loss guarantee covers the NATS path only.** Do not describe OTLP
ingest as durable.

## Ingest is the sole span writer

The gateway **never** writes spans — it publishes to `tracelane.spans.{tenant_id}`.
There is no "redundant gateway ClickHouse write path" despite what some comments here
still claim (`r2_batcher.rs:13-15`). **If ingest drops a span it is gone.**

## Six tasks under one `try_join!`

`main.rs:326-344` — OTLP receiver, SPIRE refresher, disk-guard, NATS consumer,
ClickHouse writer, R2 batcher. **Any one returning `Err` kills the whole process.**
Deliberate (unacked NATS messages redeliver), but it means a persistent ClickHouse
outage propagating out of `flush` crashes ingest rather than degrading it.

## Sampling

- Default keep-rate is **100** — full-fidelity (`config.rs:85-88`). The `TailSampler::new()`
  constructor still hardcodes 10%, but **the binary never calls it** (`main.rs:97-99`
  uses `with_rate`). Reading `new()` and concluding "10% default" is wrong for the
  running binary, and any new call site using `new()` would silently drop 90% of spans.
- Force-keep is sticky per trace: error spans and `tracelane_intervention` keep the
  whole trace.
- A per-trace ceiling (10,000 spans / 64 MiB) clips runaway traces **on all tiers,
  including forced-Full** — "100% capture" is not literally unbounded.

## R2 cold tier is not wired

The NDJSON batcher exists and **nothing feeds it** — `main.rs:350` does `drop(r2_tx)`.
Parquet is deferred. Do not describe cold-tier archival as shipped.
