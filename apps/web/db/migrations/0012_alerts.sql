-- Migration 0012 — user-facing alerting (ADR-059 V1.1, pulled into the Jul batch).
-- A tenant defines alert rules on THEIR OWN metrics → THEIR Slack/Discord webhook.
-- Deterministic check job (crates/gateway/src/alerts) evaluates enabled rules over
-- the existing slo_hourly_stats / spans, and fires via the existing SSRF-guarded
-- Slack-format notify path. Gated by f_alerts (deny-overrides-grant); DARK by
-- default on every plan until the founder flips it at DoD close (Jul-18).

-- ── Entitlement flag (dark on every plan; per-tenant override for the demo) ────
ALTER TABLE plan_entitlements
  ADD COLUMN IF NOT EXISTS f_alerts boolean NOT NULL DEFAULT false;
ALTER TABLE workspace_entitlements
  ADD COLUMN IF NOT EXISTS f_alerts boolean;  -- NULL = inherit plan

-- ── Destinations — a Slack-compatible webhook (Slack, or Discord with /slack) ──
-- All kinds POST the SAME Slack `{"text":…}` payload; `kind` is a UI hint only.
-- Discord accepts Slack payloads at `<discord-webhook-url>/slack`, so no per-kind
-- code path — the tenant just pastes the right URL.
CREATE TABLE IF NOT EXISTS alert_destinations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        text NOT NULL,
  kind        text NOT NULL DEFAULT 'slack',   -- 'slack' | 'discord' | 'webhook'
  url         text NOT NULL,                    -- validated by ssrf_guard before any POST
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alert_destinations_tenant_idx ON alert_destinations(tenant_id);

-- ── Rules — (metric, comparator, threshold, window) → destination ─────────────
-- metric ∈ {error_rate, burn_rate, latency_p95, cost_usd, quota_pct} (the 5).
-- last_state/last_fired_at drive edge-triggered firing (ok→breach) + a re-fire
-- cooldown, so an ongoing breach does not spam every check tick.
CREATE TABLE IF NOT EXISTS alert_rules (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  metric          text NOT NULL,
  comparator      text NOT NULL DEFAULT 'gt',   -- 'gt' | 'lt'
  threshold       double precision NOT NULL,
  window_minutes  integer NOT NULL DEFAULT 60,
  destination_id  uuid NOT NULL REFERENCES alert_destinations(id) ON DELETE CASCADE,
  enabled         boolean NOT NULL DEFAULT true,
  last_state      text NOT NULL DEFAULT 'ok',   -- 'ok' | 'breach'
  last_fired_at   timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT alert_rules_metric_ck
    CHECK (metric IN ('error_rate','burn_rate','latency_p95','cost_usd','quota_pct')),
  CONSTRAINT alert_rules_comparator_ck CHECK (comparator IN ('gt','lt'))
);
CREATE INDEX IF NOT EXISTS alert_rules_tenant_enabled_idx ON alert_rules(tenant_id, enabled);
