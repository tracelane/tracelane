-- 0030_evl04_dataset_entitlements.sql
--
-- Sprint 3 (the eval loop) — the FOUR entitlement flags the sprint's surfaces
-- gate on, in ONE migration: `f_datasets` (EVL-04), `f_experiments` (EVL-02),
-- `f_online_evals` (EVL-28), `f_annotation_queues` (EVL-29). Additive and
-- idempotent.
--
-- WHY ONE FILE AND NOT FOUR. Each of those four specs independently names its
-- own migration `0030_*` (EVL-04 §2.8 `0030_evl04_datasets.sql`, EVL-02 §2.7
-- `0030_evl02_experiments_entitlement.sql`, EVL-28 §2 and EVL-29 §2 the same
-- shape). Only one file can be 0030, and four ALTERs on the same two tables
-- applied on four different days is four chances to half-land — which is
-- exactly the failure `scripts/ci/audit-migration-drift.py` exists to
-- catch. The columns are seeded per flag below, so consolidating the DDL costs
-- nothing and the per-spec filenames are the defect (CLAUDE.md §17).
--
-- ORDERING RULE (CLAUDE.md §4.0 · rule 5 · apps/web/CLAUDE.md "Migrations"):
-- this lands in Neon **BEFORE** the gateway that reads these columns deploys.
-- The wrong order does NOT produce a loud failure, and that is the danger.
-- `crates/gateway/src/entitlement_cache.rs:540-570` resolves every flag in ONE
-- SELECT naming each column, so one absent column fails that statement for
-- every tenant — not just the ones who would touch a dataset. The miss path
-- then serves `ResolvedEntitlements::deny_all()`, because a process that just
-- started has no last-known grant to fail open to (`entitlement_cache.rs:459-491`,
-- `:223`). The observable result is every gated feature OFF for every tenant —
-- guardrail rails, prompt promotion, alerts, audit self-verify — carried by a
-- `warn!` and the FAIL_OPEN_TOTAL counter, and by nothing a caller can see.
--
-- Migrations 0009+ are un-journaled and hand-applied (CLAUDE.md rule 5), so
-- `drizzle-kit migrate` will NOT run this. Apply it to Neon by hand; the PGlite
-- suites (`apps/web/lib/e2e-db.ts:52-71`, `apps/web/e2e/polar-webhook.pglite.
-- test.ts:170-177`) pick every non-journaled file up automatically, in name
-- order, so this file must stay runnable top-to-bottom on an empty database.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- NOTIFY PARITY — CHECKED, NOT ASSUMED, AND NOTHING NEW IS NEEDED HERE.
--
-- `0021_entitlements_notify_triggers.sql` binds `trg_plan_entitlements_notify`
-- and `trg_workspace_entitlements_notify` to the TABLES, `FOR EACH ROW` on
-- INSERT/UPDATE/DELETE — they are not column-scoped, so a new column is carried
-- by them the moment it exists. Adding a trigger here would be a second one on
-- the same table firing the same NOTIFY twice.
--
-- What IS worth doing is proving the triggers are actually there, because
--  was precisely the shape where they were not: the gateway logged
-- "control-plane LISTEN active on entitlements_changed" while prod had the
-- functions and triggers MISSING, so a plan flip took up to 15 minutes to
-- unlock a gated feature and nothing said so. This migration seeds a plan
-- default for four gates; if the NOTIFY is dead, every one of those grants is
-- silently late. So: assert first, write second. 0021 is idempotent
-- (CREATE OR REPLACE + DROP TRIGGER IF EXISTS), so the remedy for a failure
-- here is one command, not an investigation.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgname = 'trg_plan_entitlements_notify' AND NOT tgisinternal
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgname = 'trg_workspace_entitlements_notify' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION
            'entitlements_changed NOTIFY triggers are missing (B-130). Apply '
            '0021_entitlements_notify_triggers.sql BEFORE this migration, or '
            'every grant seeded below waits out the gateway 15-min cache TTL '
            'with nothing reporting it.';
    END IF;
END $$;

-- ── Plan defaults: NOT NULL DEFAULT false ────────────────────────────────────
-- FALSE is the unprivileged state, and it is the default for the same reason
-- every other f_* column has it: a control plane that has not been seeded, or
-- a self-host with no plan rows at all, must resolve to free/OSS and never to
-- a paid feature (`.claude/rules/tenancy.md`). The tier split is SEEDED below,
-- as a deliberate act — it is never a column default.
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS f_datasets boolean NOT NULL DEFAULT false;
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS f_experiments boolean NOT NULL DEFAULT false;
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS f_online_evals boolean NOT NULL DEFAULT false;
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS f_annotation_queues boolean NOT NULL DEFAULT false;

-- ── Per-tenant overrides: NULLABLE, no default ───────────────────────────────
-- NULL = inherit the plan. The absence of a default is the mechanism, not an
-- oversight: the gateway resolves `COALESCE(we.f_x, pe.f_x)`, so a NOT NULL
-- DEFAULT false here would make every existing workspace row read FALSE and no
-- plan-level grant would ever reach a tenant that has an override row — a
-- silent, total revoke. A FALSE written here deliberately still beats a plan
-- TRUE (deny-overrides-grant, ADR-009 §7.4.9).
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS f_datasets boolean;
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS f_experiments boolean;
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS f_online_evals boolean;
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS f_annotation_queues boolean;

-- ── Seed the tier split (founder-accepted) ───────────────────────────────────
-- `f_datasets` is BUILDER+ and the other three are TEAM+, mirroring
-- `f_prompt_promotion_write` (0004 + 0005). Datasets sit one tier lower on
-- purpose: they are the table-stakes parity surface every competitor ships, and
-- a dataset a Builder tenant cannot create is the comparison lost before it
-- starts (EVL-04 §9 Q2). Experiments, online evals and review queues all spend
-- provider money or need more than the one seat Builder allows.
--
-- Idempotent, and the WHERE guard is what makes a re-run a no-op. Re-applying
-- this file RE-ASSERTS the plan-level tier split — that is the intended
-- semantics of a plan default, and a per-tenant deviation belongs in
-- `workspace_entitlements`, which is the whole reason that table exists.
UPDATE plan_entitlements
   SET f_datasets = TRUE,
       updated_at = now()
 WHERE plan_lookup_key IN ('builder_v1', 'team_v1', 'business_v1', 'enterprise_v1')
   AND f_datasets IS DISTINCT FROM TRUE;

UPDATE plan_entitlements
   SET f_experiments = TRUE,
       f_online_evals = TRUE,
       f_annotation_queues = TRUE,
       updated_at = now()
 WHERE plan_lookup_key IN ('team_v1', 'business_v1', 'enterprise_v1')
   AND (f_experiments IS DISTINCT FROM TRUE
        OR f_online_evals IS DISTINCT FROM TRUE
        OR f_annotation_queues IS DISTINCT FROM TRUE);

-- There is deliberately NO matching `UPDATE … SET … = FALSE` for free_v1 (and
-- builder_v1 on the Team+ three). The column default already lands them FALSE
-- on first apply, so such a statement would change nothing the first time and,
-- on a re-run, would REVOKE a deliberate plan-level grant made after this
-- migration. A revoke should be a deliberate act, never a side effect of
-- re-applying a file. (0013 wrote both directions; this is the correction.)

COMMENT ON COLUMN plan_entitlements.f_datasets IS
    'EVL-04. Golden datasets + dataset items. Builder+ = TRUE (EVL-04 §9 Q2). '
    'Per-tenant override lives in workspace_entitlements.f_datasets (NULL = inherit); '
    'the gateway resolves COALESCE(we.f_datasets, pe.f_datasets).';
COMMENT ON COLUMN plan_entitlements.f_experiments IS
    'EVL-02. Experiments — a dataset x a prompt version, run and diffed. Team+ = TRUE, '
    'alongside f_prompt_promotion_write which the promote step already requires.';
COMMENT ON COLUMN plan_entitlements.f_online_evals IS
    'EVL-28. Sampled scoring of live production traffic. Team+ = TRUE. Spends the '
    'tenant''s provider money per sampled request, so it is not a Builder default.';
COMMENT ON COLUMN plan_entitlements.f_annotation_queues IS
    'EVL-29. Review/annotation queues over the OBS-18 trace_annotations store. '
    'Team+ = TRUE — a review queue is a multi-seat workflow and Builder is one seat.';
