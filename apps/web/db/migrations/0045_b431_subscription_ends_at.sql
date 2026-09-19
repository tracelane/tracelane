-- 0045 — B-431 (found by B7 stage 2 on prod, 2026-09-19): a customer who cancels
-- AT PERIOD END keeps the plan they paid for until Polar's `ends_at`. Until this
-- fix the webhook dropped them to Free the moment `subscription.canceled` arrived
-- (Polar's status in that event is still `active`), and `subscription.uncanceled`
-- kept them there. The resolver now decides on STATUS; this column records the
-- scheduled end so the billing page can say "Cancels on <date> — you keep <plan>
-- until then" instead of pretending nothing is scheduled.
--
-- Expand-only. The gateway's entitlement SELECT reads NONE of this (the plan and
-- the period stay the interface), so the boot schema check is unaffected.
-- Applied BY HAND on Neon before apps/web deploys, like every migration since 0009.
-- Idempotent.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS subscription_ends_at timestamptz;

COMMENT ON COLUMN tenants.subscription_ends_at IS
    'B-431: Polar ends_at when cancel_at_period_end is set on the live subscription; NULL otherwise. The plan stays until this instant; subscription.revoked is what ends it.';
