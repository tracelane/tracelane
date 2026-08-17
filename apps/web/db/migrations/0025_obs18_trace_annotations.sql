-- 0025 — OBS-18 trace annotations (human labels on a trace).
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` applies
-- only 0000–0008, so this is applied to Neon BY HAND and MUST land BEFORE the
-- gateway that reads it deploys (CLAUDE.md §4.0, serialization point S2).
-- Additive and reversible: it creates one table and takes nothing away, so a
-- gateway that predates it is unaffected.
--
-- WHY POSTGRES, NOT CLICKHOUSE
-- Annotations are low-volume, MUTABLE (edited, removed) and read one trace at a
-- time. ClickHouse is append-only analytical storage; an edit there is a
-- ReplacingMergeTree tombstone that only reads correctly with FINAL and an
-- exclusion join — a whole failure class (the soft-delete/re-create trap) taken
-- on for what is one UPDATE here.
--
-- WHY span_id IS '' AND NOT NULL
-- It is part of the primary key, and NULL is not comparable: `(t, tr, NULL, a)`
-- never equals itself, so `ON CONFLICT` would not fire and every re-flag would
-- insert a SECOND row. The empty string is the trace-level sentinel and makes
-- the uniqueness real.
--
-- WHY THE PK IS THE CONCURRENCY CONTROL
-- Upsert is `ON CONFLICT (tenant_id, trace_id, span_id, author_sub) DO UPDATE`,
-- so two tabs racing the same flag produce exactly one row with no
-- read-modify-write window. One author, one verdict per target.
--
-- Tenancy: `tenant_id` FK-cascades from `tenants`, so a purged tenant takes its
-- annotations with it rather than leaving orphans behind.

CREATE TABLE IF NOT EXISTS trace_annotations (
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    trace_id    text        NOT NULL,
    span_id     text        NOT NULL DEFAULT '',
    label       text        NOT NULL,
    note        text        NOT NULL DEFAULT '',
    author_sub  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT trace_annotations_pkey
        PRIMARY KEY (tenant_id, trace_id, span_id, author_sub),
    -- The vocabulary is CLOSED and enforced in the DATABASE as well as the
    -- gateway. A label the UI cannot render is worse than a rejected write, and
    -- a check here survives a future writer that forgets to validate.
    CONSTRAINT trace_annotations_label_chk
        CHECK (label IN ('good', 'bad', 'needs_review'))
);

CREATE INDEX IF NOT EXISTS trace_annotations_tenant_trace_idx
    ON trace_annotations (tenant_id, trace_id);
