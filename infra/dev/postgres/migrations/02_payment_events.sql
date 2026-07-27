-- Migration 02: Payment events ledger (x402 / AP2 / ACP protocol spans).
-- Idempotent — every CREATE has IF NOT EXISTS.
--
-- Tenant isolation: every query against this table must filter by tenant_id.
-- Row-level security should be added before multi-tenant production deploy.

CREATE TABLE IF NOT EXISTS payment_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(tenant_id),
    agent_id    TEXT,
    trace_id    UUID,
    span_id     UUID,
    event_type  TEXT NOT NULL CHECK (event_type IN ('intent', 'mandate', 'settled')),
    amount_usd  NUMERIC(20, 8),          -- USD amount, 8 decimal places
    recipient   TEXT,
    mandate_id  TEXT,                    -- AP2 mandate reference
    payload     JSONB,                   -- full x402 receipt / mandate JSON
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS payment_events_tenant_idx
    ON payment_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS payment_events_agent_idx
    ON payment_events (tenant_id, agent_id, created_at DESC);
