-- 0009_support_requests — in-product "Reach out" support widget.
-- A user's Question / Feedback / Bug message from the dashboard. WorkOS ids are
-- stored as TEXT (org + user), NOT a FK to tenants.id: the session yields the
-- WorkOS org_id, not the internal tenant UUID, so this sidesteps the org→tenant
-- resolution seam. Idempotent (IF NOT EXISTS) — safe to re-run.

CREATE TABLE IF NOT EXISTS support_requests (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workos_org_id  text        NOT NULL,
    workos_user_id text        NOT NULL,
    email          text,
    kind           text        NOT NULL,
    message        text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS support_requests_created_at_idx
    ON support_requests (created_at);
