-- 0055 — B-409: allowances are pinned by version, the way `pricing_rates` is.
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` applies
-- only 0000–0008, so this is applied to Neon BY HAND.
--
-- **SERIALIZATION POINT S2.** The gateway's entitlement query, metering job and
-- retention sweep READ `plan_allowances` and `tenants.plan_version` /
-- `tenants.price_protected_until`; its boot check (`entitlement_cache::verify_schema`)
-- REFUSES TO BOOT when a column it names is absent. The table and column land in
-- Neon BEFORE the gateway that reads them deploys. Order:
--   1. THIS file (creates the table, backfills version 'v3' from today's
--      plan_entitlements so the current numbers exist the moment it commits),
--   2. `cd apps/web && DATABASE_URL=<Neon direct> node db/seed.mjs` (upserts the
--      JSON's `plan_version` rows; REFUSES if that version already exists with
--      different numbers; marks it `is_current`),
--   3. deploy apps/web (the webhook starts pinning `tenants.plan_version`),
--   4. deploy the gateway (reads the pinned row).
-- Steps 1-2 are safe under the CURRENT binaries: nothing deployed reads the new
-- table, and the new column is NULL ("track the current version").
--
-- WHAT IT FIXES. `tenants.price_version` pinned the RATE version only; the
-- allowances a plan buys were read live from `plan_entitlements`, so a new ruling
-- moved every pinned tenant's allowance the instant it was seeded. Now a ruling
-- INSERTS a `plan_version`; a tenant pinned to an older one keeps reading it while
-- `price_protected_until` is in the future (spec `specs/B-409-allowance-version-pinning.md`).
--
-- IMMUTABILITY IS A CONSTRAINT, NOT A CONVENTION: a trigger refuses any UPDATE that
-- changes a version's numbers (only `is_current` may flip) and any DELETE of a version
-- a tenant is pinned to. A seed that edits v3's numbers in place fails here.
--
-- Idempotent (IF NOT EXISTS / CREATE OR REPLACE / ON CONFLICT DO NOTHING).
-- REVERSIBLE before step 4: DROP TABLE plan_allowances; ALTER TABLE tenants DROP
-- COLUMN plan_version. After step 4 the gateway refuses to boot without them.
--
-- rev4 L6 (2026-10-03): `ALTER TABLE tenants` takes an ACCESS EXCLUSIVE lock, and
-- every gateway auth/entitlement read queues behind it while it waits for the
-- in-flight readers ahead of it — an unbounded wait here is a production stall.
-- Bounded: if the lock is not granted in 5 s the file fails (nothing half-applies:
-- every statement is idempotent) and is re-run at a quieter moment.
SET lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS plan_allowances (
    plan_version         text          NOT NULL,              -- 'v3' (ADR-076), from plans.v3.json `plan_version`
    plan_lookup_key      text          NOT NULL REFERENCES plan_entitlements(plan_lookup_key),
    hot_gb_included      numeric(12,3),                       -- NULL = custom (Enterprise)
    ingest_gb_included   numeric(12,3),
    cold_gb_included     numeric(12,3),                       -- NULL = none (Free) / custom (Enterprise)
    series_included      bigint,
    scan_units_included  bigint,
    eval_runs_included   bigint,
    indexed_window_days  integer       NOT NULL,
    queryable_days       integer       NOT NULL,
    ledger_days          integer       NOT NULL,
    is_current           boolean       NOT NULL DEFAULT false,
    effective_from       date          NOT NULL DEFAULT current_date,
    created_at           timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (plan_version, plan_lookup_key)
);

-- At most ONE current row per plan: the resolver's LEFT JOIN on `is_current` must
-- match at most one row, or a tenant would resolve twice.
CREATE UNIQUE INDEX IF NOT EXISTS plan_allowances_one_current_per_plan
    ON plan_allowances (plan_lookup_key) WHERE is_current;

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS plan_version text;   -- pinned at first paid subscription, beside price_version; NULL = current

COMMENT ON TABLE plan_allowances IS
  'B-409: the six included allowances + three windows per (plan_version, plan). A new ruling INSERTS a version (seed.mjs from plans.v3.json) and flips is_current; rows are immutable (trigger). The gateway resolves a tenant''s row by tenants.plan_version while price_protected_until is in the future, else the is_current row; a missing row fails closed to the deny floor.';
COMMENT ON COLUMN tenants.plan_version IS
  'B-409: the plan_allowances.plan_version this tenant is pinned to, written ONLY by the Polar webhook on the first paid activation (same UPDATE as price_version). NULL = tracks the current version.';

CREATE OR REPLACE FUNCTION plan_allowances_immutable()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.plan_version        IS DISTINCT FROM OLD.plan_version
        OR NEW.plan_lookup_key     IS DISTINCT FROM OLD.plan_lookup_key
        OR NEW.hot_gb_included     IS DISTINCT FROM OLD.hot_gb_included
        OR NEW.ingest_gb_included  IS DISTINCT FROM OLD.ingest_gb_included
        OR NEW.cold_gb_included    IS DISTINCT FROM OLD.cold_gb_included
        OR NEW.series_included     IS DISTINCT FROM OLD.series_included
        OR NEW.scan_units_included IS DISTINCT FROM OLD.scan_units_included
        OR NEW.eval_runs_included  IS DISTINCT FROM OLD.eval_runs_included
        OR NEW.indexed_window_days IS DISTINCT FROM OLD.indexed_window_days
        OR NEW.queryable_days      IS DISTINCT FROM OLD.queryable_days
        OR NEW.ledger_days         IS DISTINCT FROM OLD.ledger_days THEN
            RAISE EXCEPTION 'plan_allowances % / % is immutable (B-409): insert a new plan_version instead',
                OLD.plan_version, OLD.plan_lookup_key;
        END IF;
        RETURN NEW;
    END IF;
    IF EXISTS (SELECT 1 FROM tenants WHERE plan_version = OLD.plan_version) THEN
        RAISE EXCEPTION 'plan_allowances % is pinned by a tenant (B-409): it cannot be deleted',
            OLD.plan_version;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_plan_allowances_immutable ON plan_allowances;
CREATE TRIGGER trg_plan_allowances_immutable
    BEFORE UPDATE OR DELETE ON plan_allowances
    FOR EACH ROW EXECUTE FUNCTION plan_allowances_immutable();

-- rev4 L6: TRUNCATE fires no row trigger, so the DELETE refusal above did not cover
-- it — one statement could wipe every pinned version. Refused while any tenant pins
-- one (the same condition as DELETE; an empty test database can still be reset).
CREATE OR REPLACE FUNCTION plan_allowances_no_truncate()
RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM tenants WHERE plan_version IS NOT NULL) THEN
        RAISE EXCEPTION 'plan_allowances holds versions pinned by tenants (B-409): it cannot be truncated';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_plan_allowances_no_truncate ON plan_allowances;
CREATE TRIGGER trg_plan_allowances_no_truncate
    BEFORE TRUNCATE ON plan_allowances
    FOR EACH STATEMENT EXECUTE FUNCTION plan_allowances_no_truncate();

-- A new version / an is_current flip changes what every unpinned tenant resolves →
-- evict every cached workspace, exactly like a plan_entitlements change (0021).
DROP TRIGGER IF EXISTS trg_plan_allowances_notify ON plan_allowances;
CREATE TRIGGER trg_plan_allowances_notify
    AFTER INSERT OR UPDATE OR DELETE ON plan_allowances
    FOR EACH ROW EXECUTE FUNCTION notify_plan_entitlements_changed();

-- Backfill: today's live allowances ARE version 'v3' (plans.v3.json `plan_version`;
-- check-seed-vs-neon.py proves plan_entitlements equals the JSON on prod). A plan row
-- with a NULL window is skipped — the seed fills it. On a fresh test database
-- plan_entitlements is empty and this inserts nothing.
INSERT INTO plan_allowances (
    plan_version, plan_lookup_key,
    hot_gb_included, ingest_gb_included, cold_gb_included,
    series_included, scan_units_included, eval_runs_included,
    indexed_window_days, queryable_days, ledger_days, is_current)
SELECT 'v3', pe.plan_lookup_key,
       pe.hot_gb_included, pe.ingest_gb_included, pe.cold_gb_included,
       pe.series_included, pe.scan_units_included, pe.eval_runs_included,
       pe.indexed_window_days, pe.queryable_days, pe.ledger_days,
       NOT EXISTS (SELECT 1 FROM plan_allowances c
                   WHERE c.plan_lookup_key = pe.plan_lookup_key AND c.is_current)
FROM plan_entitlements pe
WHERE pe.indexed_window_days IS NOT NULL
  AND pe.queryable_days IS NOT NULL
  AND pe.ledger_days IS NOT NULL
ON CONFLICT (plan_version, plan_lookup_key) DO NOTHING;

-- The bound above is for this file only (a hand-applied psql session runs more).
RESET lock_timeout;
