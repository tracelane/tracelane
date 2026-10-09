-- 0070 — OG-11 (specs/OG-11-weighted-latency-cost-routing.md): several BYOK keys per
-- provider (`provider_keys.label`) and the workspace routing document
-- (`workspace_routing`: virtual models, key pools; OG-12 adds `rules`, OG-13 `timeouts`
-- and `breaker` to the SAME document — no further migration).
--
-- UN-JOURNALED, like every migration from 0009 on: applied to Neon BY HAND.
-- NUMBER IS FINAL (2026-10-05 consolidation merge; 0068–0069 and 0071–0074 stay empty so no
-- applied file ever moves). WRITTEN, NOT APPLIED.
--
-- Expand step: retain the two-column primary key for older binaries' UPSERT.
-- Apply this file, deploy the gateway everywhere, then apply
-- 0077_og11_key_labels.sql to enable named labels. Never contract while an older
-- binary remains: it reads and writes one key per (tenant, provider).
-- Both files are WRITTEN, NEVER APPLIED by this build.
--
-- The ciphertext AAD of a `default` key is byte-identical to before
-- (`provider-key:<tenant>:<provider>`); any other label binds `:<label>` too, so a blob
-- cannot be swapped between labels (`byok::provider_key_aad_labeled`).
--
-- Idempotent. REVERSIBLE before step 3: DELETE FROM provider_keys WHERE label <> 'default';
-- then restore the two-column PK and DROP COLUMN label; DROP TABLE workspace_routing;

ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS label text NOT NULL DEFAULT 'default';

ALTER TABLE provider_keys DROP CONSTRAINT IF EXISTS provider_keys_label_chk;
ALTER TABLE provider_keys ADD CONSTRAINT provider_keys_label_chk
    CHECK (label ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$');

CREATE UNIQUE INDEX IF NOT EXISTS provider_keys_tenant_provider_label_unique
    ON provider_keys (tenant_id, provider_id, label);

COMMENT ON COLUMN provider_keys.label IS
  'OG-11: the key''s name within its provider''s pool (`default` for the single key every workspace had before). Part of the primary key and of the ciphertext AAD for any label other than `default`.';

CREATE TABLE IF NOT EXISTS workspace_routing (
    tenant_id   uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    doc         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    version     integer     NOT NULL DEFAULT 1,
    updated_by  text        NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workspace_routing_doc_object_chk CHECK (jsonb_typeof(doc) = 'object'),
    CONSTRAINT workspace_routing_version_chk CHECK (version >= 1)
);

COMMENT ON TABLE workspace_routing IS
  'OG-11/OG-12/OG-13: one workspace''s routing document (virtual models, key pools, conditional rules + canary splits, per-route timeouts, breaker overrides). Strict-parsed: a document this gateway cannot parse refuses routed requests (503 routing_invalid). Read by the gateway entitlement refresh; written only by the owner-gated PUT /v1/routing (optimistic `version`, one admin_audit_log row per write).';
