-- 0063 — SET-60: `signups`, the operator's list of everyone who completed a sign-in.
--
-- WRITTEN, NEVER APPLIED by the build. UN-JOURNALED, like every migration from 0009 on:
-- applied to Neon BY HAND. (0062 belongs to another branch.)
--
-- **SERIALIZATION POINT S2.** Apply this BEFORE the web build that writes it deploys.
-- The write is best-effort (`apps/web/lib/signups.ts` swallows a missing table), so the
-- wrong order loses rows and never breaks a sign-in. The gateway reads nothing from here.
--
-- One row per WorkOS user, written by the sign-in callback's `onSuccess`
-- (`apps/web/app/auth/callback/route.ts`). NOT tenant data: no `tenant_id`, nothing
-- authorizes on it, no API reads it; the founder reads it with SQL. `organization_id` is
-- the WorkOS org id (text), informational, never a join key to `tenants.id`.
--
-- Reading the numbers honestly:
--   * `first_seen_at` = the first sign-in AFTER this table existed, not the WorkOS account
--     creation date.
--   * `login_count`   = completed sign-ins since then, not lifetime.
--   Historical sign-ups are a separate follow-up (specs/SET-60 §6: WorkOS list-users backfill).
--
-- PII (name, email): `DELETE /api/settings/account` hard-deletes the row by
-- `workos_user_id`. Deletion request by email:
--   DELETE FROM signups WHERE lower(email) = lower('<email>');
--
-- Idempotent. REVERSIBLE: DROP TABLE signups;

CREATE TABLE IF NOT EXISTS signups (
    workos_user_id  text PRIMARY KEY,
    email           text NOT NULL,
    name            text,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_login_at   timestamptz,
    login_count     integer NOT NULL DEFAULT 1,
    organization_id text,
    auth_method     text
);
CREATE INDEX IF NOT EXISTS signups_email_lower_idx ON signups (lower(email));
