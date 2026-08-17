-- OBS-01 — full-text search over span content.
--
-- WHY AN INDEX AND NOT A SCAN. `tracelane.spans` is ORDER BY (tenant_id, trace_id,
-- span_id) with no skip index, so a content predicate prunes nothing and reads the
-- tenant's whole partition range. Measured on prod 2026-08-08, largest tenant at
-- 12,453 spans: 4.70 MiB / 14,436 rows / 24 ms for substring search vs 634 KiB /
-- 3 ms for an ORDER-BY-aligned count. read_bytes grows LINEARLY with tenant volume;
-- Business sells 5M traces/mo, where the same query is a multi-GB interactive scan.
--
-- ngrambf_v1, not tokenbf_v1: the predicate is a substring match (`LIKE '%q%'`),
-- which is what apps/mcp already implements and what a search box implies. tokenbf_v1
-- serves only whole-token equality, so "auth" would not find "authorize".
--
-- SAFE TO RE-RUN. Adding a skip index is metadata-only; MATERIALIZE rewrites index
-- granules, not data. No span is read, written or deleted by this migration.
ALTER TABLE tracelane.spans
    ADD INDEX IF NOT EXISTS idx_name_ngram name TYPE ngrambf_v1(4, 4096, 3, 0) GRANULARITY 4;

ALTER TABLE tracelane.spans
    ADD INDEX IF NOT EXISTS idx_attributes_ngram attributes TYPE ngrambf_v1(4, 8192, 3, 0) GRANULARITY 4;

-- Backfill existing parts. Without this the index only covers parts written AFTER
-- the ALTER, so historical spans would silently fall back to a scan.
ALTER TABLE tracelane.spans MATERIALIZE INDEX idx_name_ngram;
ALTER TABLE tracelane.spans MATERIALIZE INDEX idx_attributes_ngram;
