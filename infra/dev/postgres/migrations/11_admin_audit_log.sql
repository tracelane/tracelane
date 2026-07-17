-- Migration 11 — Admin-action audit log (ADR-031).
--
-- Durable, queryable trail of every mutating admin action across the
-- TS dashboard (apps/web/app/api/{settings,billing,prompts}/**) and
-- the Rust gateway admin endpoints. Backs the V1 contract that an
-- operator can answer "what did this user do to my workspace?".
--
-- The actor/target columns are denormalised on purpose so the audit
-- row survives even if the underlying row is hard-deleted later. The
-- {before,after}_json columns carry full row snapshots (where small
-- enough) so a future "undo" or forensic query can replay state.

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id                 BIGSERIAL    PRIMARY KEY,
    occurred_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- WorkOS user id (opaque string, e.g. `user_01HXYZ...`). The ADR-031
    -- prompt-spec called for UUID; we use TEXT because Tracelane does
    -- not maintain a local `users` table — WorkOS is the identity
    -- system of record and its ids are opaque strings, not UUIDs.
    actor_user_id      TEXT         NOT NULL,
    -- Internal Tracelane workspace UUID (`tenants.id`). Nullable for
    -- cross-workspace admin actions (e.g. a Tracelane operator
    -- mutating org-level config).
    actor_workspace_id UUID,
    action             TEXT         NOT NULL,
    target_type        TEXT         NOT NULL,
    target_id          TEXT         NOT NULL,
    before_json        JSONB,
    after_json         JSONB,
    ip_addr            INET,
    user_agent         TEXT
);

-- Workspace-scoped query path: "show me everything I did in the last 30 days".
CREATE INDEX IF NOT EXISTS idx_admin_audit_workspace
    ON admin_audit_log (actor_workspace_id, occurred_at DESC);

-- Target-scoped query path: "show me everything that ever happened to this resource".
CREATE INDEX IF NOT EXISTS idx_admin_audit_target
    ON admin_audit_log (target_type, target_id, occurred_at DESC);

COMMENT ON TABLE admin_audit_log IS
  'ADR-031: durable trail of mutating admin actions. Written from apps/web/app/api/{settings,billing,prompts}/** via lib/admin-audit.ts and crates/gateway/src/admin_audit.rs.';

COMMENT ON COLUMN admin_audit_log.action IS
  'Enum-like string. Examples: api_key.create, api_key.revoke, prompt.promote, billing.subscription.cancel, member.invite, byok.provider_key.create, byok.provider_key.delete';

COMMENT ON COLUMN admin_audit_log.target_type IS
  'Schema-bearing category. Examples: api_key, prompt, subscription, provider_key, member';

COMMENT ON COLUMN admin_audit_log.before_json IS
  'Full row snapshot before the mutation; NULL for create actions';

COMMENT ON COLUMN admin_audit_log.after_json IS
  'Full row snapshot after the mutation; NULL for delete actions';
