-- GWY-52 (2026-09-26): a workspace's own cross-provider failover — on by default for its
-- requests, with its own ordered fallback models. `specs/GWY-52-workspace-failover.md`.
-- Apply BEFORE the gateway that reads it (S2). Read inside the entitlement refresh (never
-- per request); a missing table yields the operator default + a counted degradation.
-- Written only by the owner-gated `PUT /v1/gateway/failover`, which validates each model
-- against the routing map. Cap: billing_policy.failover_models_max.
CREATE TABLE IF NOT EXISTS workspace_failover (
  tenant_id   uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  enabled     boolean     NOT NULL DEFAULT false,
  models      text[]      NOT NULL DEFAULT '{}',
  updated_by  text        NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT workspace_failover_models_len CHECK (cardinality(models) <= 32)
);
COMMENT ON TABLE workspace_failover IS
  'GWY-52: per-workspace cross-provider failover (default-on flag + ordered fallback models). Read by the gateway entitlement refresh; written only by the owner-gated /v1/gateway/failover.';
