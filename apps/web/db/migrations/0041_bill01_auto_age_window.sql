-- 0041 — BILL-01 / ADR-076: the AUTO-AGE mechanism (spec §0.4 "at the ceiling: switch to
-- AUTO-AGE, keep ingesting, nothing lost").
--
-- The per-tenant indexed window is a READ-side + METER-side boundary (spec §2.2), so
-- "auto-age" is a SHRINK of that window, not a delete: the daily metering job writes the
-- largest window (≤ the plan's) whose projected hot-window cost fits under the tenant's
-- spend ceiling, and the entitlement resolver COALESCEs it over `indexed_window_days`.
-- Data older than the shrunken window stays queryable (cold) — nothing is lost. NULL = the
-- plan window applies. The job clears it once the projection fits again.
--
-- Un-journaled (TRAPS §9): apply to Neon BEFORE the gateway that reads it deploys.
-- Additive and idempotent.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS auto_age_window_days integer
        CHECK (auto_age_window_days IS NULL OR auto_age_window_days >= 1),
    ADD COLUMN IF NOT EXISTS auto_age_since timestamptz;
