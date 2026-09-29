-- Apply schema before the reviewed reference seed and gateway deployment.
-- This migration does not grant cache control; plans.v3.json is the seed authority.
ALTER TABLE plan_entitlements
  ADD COLUMN f_cache_control boolean NOT NULL DEFAULT false,
  ADD COLUMN cache_ttl_hours integer NOT NULL DEFAULT 0 CHECK (cache_ttl_hours >= 0);
