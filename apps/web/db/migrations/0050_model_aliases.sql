-- GWY-27 (2026-09-26): per-workspace model aliases — the first customer-controlled
-- gateway setting. `specs/GWY-27-model-aliases.md` §2.
--
-- Apply BEFORE the gateway that reads it deploys (S2). The gateway reads this table
-- as a SECOND query inside its entitlement refresh (never per request); if the table
-- is missing, that read fails and the tenant resolves with NO aliases (fail-closed
-- routing, counted as `workspace_gateway_config_unreadable`) — entitlements are unaffected.
--
-- Writes come ONLY from the gateway's owner-gated `PUT/DELETE /v1/model-aliases`,
-- which validates the target against the routing map this SQL cannot see.
-- The per-workspace cap is DATA: billing_policy.model_aliases_max_per_workspace.
CREATE TABLE IF NOT EXISTS model_aliases (
  tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  alias         text        NOT NULL,
  target_model  text        NOT NULL,
  updated_by    text        NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, alias),
  CONSTRAINT model_aliases_alias_shape CHECK (alias ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$'),
  CONSTRAINT model_aliases_not_self CHECK (alias <> target_model),
  CONSTRAINT model_aliases_target_len CHECK (char_length(target_model) BETWEEN 1 AND 256)
);
COMMENT ON TABLE model_aliases IS
  'GWY-27: per-workspace model aliases (alias -> one concrete target model). Read by the gateway entitlement refresh; written only by the owner-gated /v1/model-aliases routes.';
