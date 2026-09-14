-- 0039 — B-388: the Polar webhook refuses an event older than the one it applied.
--
-- HMAC + `webhook_events` idempotency stop the SAME delivery applying twice; they say
-- nothing about two DIFFERENT events arriving out of order. Polar retries, and a
-- retried `subscription.updated` (active) landing after `subscription.canceled`
-- re-activated the plan. These two columns persist Polar's own `modified_at` of the
-- last event APPLIED — one for the base plan (per tenant), one for the add-on
-- subscription (per workspace) — and the route refuses anything older.
--
-- Un-journaled (TRAPS §9): apply to Neon BEFORE the web build that reads these
-- columns deploys. Additive and idempotent. NULL = no event applied since this
-- shipped, which the route treats as "apply" (byte-identical behaviour to before).

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS polar_subscription_modified_at timestamptz;

ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS addon_modified_at timestamptz;
