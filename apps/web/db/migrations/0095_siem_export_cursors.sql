-- SIEM configuration and per-destination delivery cursors. ADD-only (pre-deploy allow-list):
-- one clause per ALTER, literal defaults. The CHECK constraints are in 0096 (deploy: post).
-- Source records stay in audit_log_rows / ClickHouse. No per-record Postgres copy.
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS format text NOT NULL DEFAULT 'otlp';
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS action_cursor bigint NOT NULL DEFAULT -1;
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS span_cursor_ms bigint NOT NULL DEFAULT 0;
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS span_cursor_trace text NOT NULL DEFAULT '';
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS span_cursor_id text NOT NULL DEFAULT '';
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS delivery_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS retry_at timestamptz NOT NULL DEFAULT 'epoch';
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS lease_until timestamptz NOT NULL DEFAULT 'epoch';
ALTER TABLE otel_exports ADD COLUMN IF NOT EXISTS lease_token uuid;
