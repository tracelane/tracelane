-- had a migration, and no earlier migration SQL creates it (0000 baseline omits
-- it; 0001 only *comments* that it deliberately doesn't touch `tenants`). So a
-- fresh `drizzle-kit migrate` (new env / CI-from-scratch) builds a `tenants`
-- table WITHOUT `archived_at` → every `SELECT … WHERE archived_at IS NULL`
-- tenant read 500s. This idempotent ALTER is a no-op on prod (column already
-- present) and creates it on a fresh DB. Matches schema.ts
-- `archivedAt: timestamp("archived_at", { withTimezone: true })` (nullable).
ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "archived_at" timestamp with time zone;
