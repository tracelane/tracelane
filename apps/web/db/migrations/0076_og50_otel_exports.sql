-- 0076 — OG-50: OTLP/HTTP export of a workspace's spans to the customer's own collector.
--
-- UN-JOURNALED, like every migration from 0009 on: applied to Neon BY HAND, and WRITTEN
-- NEVER APPLIED by the builder. Number final (2026-10-05 consolidation merge).
--
-- **SERIALIZATION POINT S2.** Order: THIS file, then `node apps/web/db/seed.mjs` (the plan
-- flag below is seeded from `apps/web/db/plans.v3.json`, OFF for every plan until the
-- founder rules, spec §9), THEN the gateway. The gateway's entitlement query reads
-- `plan_entitlements.f_otel_export` / `max_exports` on EVERY resolve, so a gateway against
-- a Neon without this migration fails its boot schema check (the boot check names them).
-- Safe under the CURRENT binaries: nothing deployed reads any of it.
--
-- plan_entitlements.f_otel_export / max_exports — the plan gate. Plan-only (no
--   workspace_entitlements override), read through the entitlement cache like
--   `f_cache_control`. Absent entitlement resolves to REFUSED. DEFAULT false / 0.
--
-- otel_exports — one row per export destination of a workspace.
--   url           https only, path ends /v1/traces; SSRF-validated at create AND on every
--                 delivery. Shown to readers as host + path only (a query can carry a token).
--   headers_enc   the customer's header map (name → value), a JSON object SEALED with
--                 AES-256-GCM under the gateway's BYOK master key, AAD
--                 `otel-export:<tenant>:<id>` — the same envelope as a provider key. NULL =
--                 no headers. A row's blob pasted into another export fails the GCM tag.
--   header_names  the header NAMES (never values), for display.
--   include_content  false (default) = no prompt / response text is exported even when the
--                 workspace captures it; true = exported only when capture already stored it.
--   sample_ratio  0..1, decided by the trace id so a trace is whole or absent.
--   only_errors   export only spans whose status is an error.
--   status        never_delivered | ok | degraded — flushed by ONE background writer.
--   delivered / dropped / failed — spans exported / refused by a full queue / lost after
--                 retries, SINCE GATEWAY START (in-process counters; they reset on a restart).
--
-- Idempotent. REVERSIBLE before the gateway deploy: DROP TABLE otel_exports;
-- ALTER TABLE plan_entitlements DROP COLUMN f_otel_export, DROP COLUMN max_exports;

ALTER TABLE plan_entitlements
  ADD COLUMN IF NOT EXISTS f_otel_export boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS max_exports integer NOT NULL DEFAULT 0;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'plan_entitlements_max_exports_chk'
    ) THEN
        ALTER TABLE plan_entitlements ADD CONSTRAINT plan_entitlements_max_exports_chk
            CHECK (max_exports >= 0);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS otel_exports (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    url              text NOT NULL CHECK (char_length(url) BETWEEN 1 AND 2048),
    headers_enc      text,
    header_names     text[] NOT NULL DEFAULT '{}',
    enabled          boolean NOT NULL DEFAULT true,
    include_content  boolean NOT NULL DEFAULT false,
    sample_ratio     double precision NOT NULL DEFAULT 1
                     CHECK (sample_ratio >= 0 AND sample_ratio <= 1),
    only_errors      boolean NOT NULL DEFAULT false,
    status           text NOT NULL DEFAULT 'never_delivered'
                     CHECK (status IN ('never_delivered', 'ok', 'degraded')),
    last_success_at  timestamptz,
    last_error_class text,
    delivered        bigint NOT NULL DEFAULT 0 CHECK (delivered >= 0),
    dropped          bigint NOT NULL DEFAULT 0 CHECK (dropped >= 0),
    failed           bigint NOT NULL DEFAULT 0 CHECK (failed >= 0),
    created_by       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS otel_exports_tenant_idx ON otel_exports (tenant_id);
CREATE INDEX IF NOT EXISTS otel_exports_enabled_idx ON otel_exports (tenant_id) WHERE enabled;

COMMENT ON TABLE otel_exports IS
  'OG-50: a workspace''s OTLP/HTTP span export destinations. headers_enc is sealed (AES-GCM, BYOK master key, AAD otel-export:<tenant>:<id>); counters are since gateway start. Written only by the gateway''s /v1/exports/otel routes (one admin_audit_log row per write) and its status flusher.';
COMMENT ON COLUMN plan_entitlements.f_otel_export IS
  'OG-50: the plan grants OTLP span export. Seeded OFF for every plan until the founder rules (spec §9).';
COMMENT ON COLUMN plan_entitlements.max_exports IS
  'OG-50: how many otel_exports a workspace on this plan may hold.';
