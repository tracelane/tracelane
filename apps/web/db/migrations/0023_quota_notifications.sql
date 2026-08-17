-- 0023 — persisted quota-notification marker (SET-08 correctness fix).
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` only
-- applies 0000–0008, so this is applied to Neon BY HAND and MUST land BEFORE the
-- gateway that reads it deploys (CLAUDE.md §4.0 serialization point S2).
--
-- WHY THIS TABLE EXISTS
-- The first cut of the SET-08 soft cap fired on the transition `used == quota`,
-- with `used` coming from the in-memory `QuotaTracker`. That counter is
-- deploy the equality is unsound in both directions:
--   * a restart landing the counter ABOVE quota never sees `== quota` again, so
--     the tenant is never told they hit 100% — the alert is lost silently;
--   * a restart landing it BELOW quota re-crosses and fires a SECOND time.
-- The predicate is now the position test `used >= quota`, and fire-once comes
-- from this table instead of from the counter's history.
--
-- WHY A TABLE AND NOT A COLUMN ON `tenants`
-- The primary key IS the concurrency control: the claim is
-- `INSERT … ON CONFLICT DO NOTHING`, so two gateway replicas racing the same
-- crossing produce exactly one winner with no read-modify-write window. A
-- `last_notified_period` column would need a transaction to be equally safe.
-- `kind` keeps soft-cap and hard-cap markers independent for when the hard-cap
-- notify moves onto the same mechanism.

CREATE TABLE IF NOT EXISTS quota_notifications (
    tenant_id   uuid        NOT NULL,
    -- Billing period as 'YYYYMM' (UTC), matching the gateway's
    -- `current_year_month()`. Text, not a date: the quota window is a calendar
    -- month and storing a day would invite an off-by-one at the boundary.
    period      text        NOT NULL,
    -- 'soft_cap' | 'hard_cap'. Deliberately not a PG enum — binding a Rust &str
    -- into a PG enum requires a `$N::text::enum` cast and has cost this repo a
    -- debugging session before.
    kind        text        NOT NULL,
    notified_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, period, kind)
);

-- Sweeping old periods is a housekeeping concern, not a correctness one: a stale
-- row only prevents a re-notify for a month that has already ended.
CREATE INDEX IF NOT EXISTS quota_notifications_period_idx
    ON quota_notifications (period);
