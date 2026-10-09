-- 0061 — OG-24: spend threshold alert channels and the delivery outbox.
--
-- UN-JOURNALED, like every migration from 0009 on: applied to Neon BY HAND.
--
-- **SERIALIZATION POINT S2.** The gateway's boot schema check
-- (`scripts/ci/check-deploy-schema.py` reads every table `crates/gateway/src/db/` names)
-- refuses a deploy against a Neon without these tables. Order:
--   1. 0060_og25_workspace_controls.sql and THIS file,
--   2. deploy the gateway.
-- Step 1 is safe under the CURRENT binaries: nothing deployed reads the tables.
--
-- spend_alert_channels — where a workspace's spend alerts go: kind email | slack |
--   webhook. `target` is the email address, the webhook URL, or for Slack a REDACTED
--   display string; the SECRET (the Slack URL, the webhook signing secret) is stored
--   ONLY in `secret_enc` — AES-256-GCM under the gateway's BYOK master key, AAD
--   `spend-alert-channel:<tenant>:<id>` (never in clear).
--
-- spend_alert_events — the OUTBOX and the DEDUP at once: one row per (channel, dedup
--   key), `dedup_key` = budget:<layer>:<subject>:<window>:<threshold>:<period>, so a
--   threshold fires at most once per window per channel across restarts. Inserted
--   ON CONFLICT DO NOTHING (the row count is the decision); delivered by the gateway's
--   background task; status 'delivered' is written only AFTER a 2xx (at-least-once).
--
-- Idempotent. REVERSIBLE before step 2: DROP TABLE spend_alert_events;
-- DROP TABLE spend_alert_channels;

CREATE TABLE IF NOT EXISTS spend_alert_channels (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('email', 'slack', 'webhook')),
    name        text NOT NULL,
    target      text NOT NULL,
    secret_enc  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text,
    CONSTRAINT spend_alert_channels_secret_chk
        CHECK (kind = 'email' OR secret_enc IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS spend_alert_channels_tenant_idx ON spend_alert_channels (tenant_id);

CREATE TABLE IF NOT EXISTS spend_alert_events (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel_id       uuid NOT NULL REFERENCES spend_alert_channels(id) ON DELETE CASCADE,
    dedup_key        text NOT NULL,
    payload          jsonb NOT NULL,
    status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'delivered', 'failed')),
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    delivered_at     timestamptz,
    CONSTRAINT spend_alert_events_dedup_uq UNIQUE (tenant_id, channel_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS spend_alert_events_due_idx
    ON spend_alert_events (next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS spend_alert_events_tenant_idx
    ON spend_alert_events (tenant_id, created_at DESC);

COMMENT ON TABLE spend_alert_channels IS
  'OG-24: a workspace''s spend-alert destinations (email, Slack, signed webhook). Secrets only in secret_enc (AES-GCM, BYOK master key).';
COMMENT ON TABLE spend_alert_events IS
  'OG-24: the spend-alert outbox and dedup — UNIQUE (tenant_id, channel_id, dedup_key) fires a threshold once per window per channel; delivered at-least-once.';
