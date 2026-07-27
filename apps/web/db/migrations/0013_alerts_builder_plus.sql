-- Migration 0013 — alerting is a Builder+ TABLE-STAKES retention feature (every
-- competitor ships it), not an Audit-class premium. Seed the plan defaults so it
-- is ON for Builder/Team/Business/Enterprise and OFF for free. Free tenants get
-- the UPSELL surface (settings/alerts renders "available on Builder+"), not the
-- feature. Per-tenant workspace_entitlements overrides (e.g. the demo grant) still
-- win via deny-overrides-grant (COALESCE(we.f_alerts, pe.f_alerts)).
--
-- migration 0012 added the column DARK (default false); this flips the plan seed.

UPDATE plan_entitlements SET f_alerts = TRUE, updated_at = now()
  WHERE plan_lookup_key IN ('builder_v1', 'team_v1', 'business_v1', 'enterprise_v1');

UPDATE plan_entitlements SET f_alerts = FALSE, updated_at = now()
  WHERE plan_lookup_key = 'free_v1';
