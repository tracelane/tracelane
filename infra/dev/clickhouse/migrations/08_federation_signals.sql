-- Migration 08: federation_signals — the cross-customer failure-signature
-- substrate. Anonymized aggregate signals for opt-in federated detection across
-- tenants, accumulating from the first customer.
--
-- PRIVACY (load-bearing — see .claude/rules/security.md):
--   * tenant_id_hash = SHA256(tenant_id) is ONE-WAY — the raw tenant_id is
--     NEVER stored; reverse lookup is architecturally impossible.
--   * rows carry NO content — only a bounded AFT taxonomy id (aft_class) +
--     counts + a content-free span-name shape hash.
--   * queries must NEVER join to tracelane.spans / tracelane.audit_log; the
--     only thing a V2 surface may expose is a k-anonymized cross-tenant
--     aggregate (count + confidence per AFT class per hour), gated on
--     count(distinct tenant_id_hash) >= K. Per-hash rows are never exposed.
--
-- This is a DELIBERATE cross-tenant table (no tenant_id column, by design) — the
-- one documented exception to the WHERE tenant_id = ? isolation rule. The ingest
-- write path is insert-only (not a SELECT the isolation guard scans) and hashes
-- the tenant, so it needs no guard change; the isolation contract binds any
-- future V2 READ surface, which must stay k-anonymized (ADR-056).
CREATE TABLE IF NOT EXISTS tracelane.federation_signals (
    tenant_id_hash  String,   -- SHA256(tenant_id) hex — one-way, never the raw id
    bucket_hour     DateTime, -- toStartOfHour(span.start_time), stored as unix seconds
    aft_class       String,   -- the AFT failure-signature id (validated AFT-… shape at ingest)
    signal_count    UInt32,   -- events matching this AFT class in the hour (SUMmed)
    confidence_sum  Float32,  -- SUM of per-span anomaly scores; V2 mean = confidence_sum/signal_count
    anonymized_hash String    -- SHA256 of the redacted span-name shape (no payload content)
) ENGINE = SummingMergeTree((signal_count, confidence_sum))
ORDER BY (aft_class, bucket_hour, tenant_id_hash)
TTL toDate(bucket_hour) + INTERVAL 365 DAY;
