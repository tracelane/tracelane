-- Phase 2 migration: Polar.sh replaces Stripe as the payment provider.
--
-- The `stripe_customer_id` / `stripe_subscription_id` columns are RETAINED
-- on `tenants` for now (rollback safety; existing rows may carry data we
-- don't want to lose if a rollback to Phase 1 is needed). A future Phase 3
-- migration will drop them once we've validated Polar in production for
-- ≥30 days.
--
-- We add two NEW nullable columns: `polar_customer_id` and
-- `polar_subscription_id`. The webhook handler writes to the new columns;
-- new tenants never get the Stripe ones populated.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS polar_customer_id TEXT,
    ADD COLUMN IF NOT EXISTS polar_subscription_id TEXT;

-- Reverse-map index for the webhook handler's `get_by_polar_customer` query.
CREATE INDEX IF NOT EXISTS tenants_polar_customer_id_idx
    ON tenants (polar_customer_id)
    WHERE polar_customer_id IS NOT NULL AND archived_at IS NULL;
