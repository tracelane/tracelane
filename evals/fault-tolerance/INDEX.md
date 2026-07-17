# Fault-Tolerance Eval Index

> Implemented progressively Weeks 4–8 alongside production code.
> Each FT eval requires the corresponding production implementation to be meaningful.
> All are 🔴 until the production code they test lands.

| ID | Title | Status | Week | Production Code |
|----|-------|--------|------|-----------------|
| FT-01 | Gateway provider failover — secondary activates within 200ms | 🟡 written, integration Week 7 | Week 7 | `crates/gateway/src/providers/mod.rs` |
| FT-02 | Rate-limit queue — requests queued and retried within SLO | 🟡 written, integration Week 7 | Week 7 | `crates/gateway/src/rate_limiter.rs` |
| FT-03 | Ingest ClickHouse downtime — back-pressure, no data loss | 🟡 written, integration Week 7 | Week 7 | `crates/ingest/src/clickhouse_writer.rs` |
| FT-04 | R2 outage — ingest degrades gracefully, hot path unaffected | 🟡 written, integration Week 7 | Week 7 | `crates/ingest/src/cold_storage.rs` |
| FT-05 | Predictive layer ONNX crash — fail-open, not fail-closed | 🟡 written, integration Week 7 | Week 7 | `crates/gateway/src/predictive/mod.rs` |
| FT-06 | Audit log Rekor outage — queued for re-publish | 🟡 written, integration Week 7 | Week 7 | `crates/gateway/src/audit.rs` |
| FT-07 | Dashboard slow ClickHouse query — timeout + partial result | 🟡 written, integration Week 7 | Week 7 | `apps/web/` |
| FT-08 | Self-host disk full — graceful degradation, no crash | 🟡 written, integration Week 8 | Week 8 | `crates/ingest/src/clickhouse_writer.rs` |
| FT-09 | SPIRE agent down — refresher fails closed, process exits | 🟡 written, integration Linux-CI | Week 9 | `crates/ingest/src/{tls.rs,main.rs,auth.rs}` |
| FT-10 | Concurrent promotion — regressive one attribution-rolled-back, clean survives | 🟡 written, integration Week 8 | Week 9 | `03_prompt_promotion.sql`, `auto_rollback.rs`, `rollback.ts` (ADR-038) |

**Legend:** 🟢 green on main | 🟡 written, mock passes | 🔴 not yet written

**Week 9 target:** All 9 🟢 alongside the corresponding production code.
