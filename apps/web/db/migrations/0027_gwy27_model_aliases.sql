-- 0027 — GWY-27 per-tenant model aliases.
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` applies
-- only 0000–0008, so this is applied to Neon BY HAND and MUST land BEFORE the
-- gateway that reads it deploys (CLAUDE.md §4.0, serialization point S2).
-- Additive and reversible: one new table, nothing taken away.
--
-- WHY THIS IS A SEPARATE LAYER FROM GWY-39, AND MUST STAY ONE.
-- `providers/mod.rs:668` already consults an alias — the OPERATOR's
-- `tracelane.yaml`, a process-global read inside `provider_id_for_model`, whose
-- signature is `(model: &str) -> Option<&'static str>` and carries NO tenant.
-- These aliases are per-TENANT. Resolving them in that function would mean
-- threading `tenant_id` through it and through `api_key_env_var`,
-- drift class the comment at `providers/mod.rs:654-659` was written to close.
-- So a tenant alias is rewritten to a concrete model ONCE, at hot-path entry,
-- and every downstream lookup sees a real model name it already understands.
--
-- THE ALIAS IS THE PRIMARY KEY HALF, NOT A UNIQUE INDEX AFTERTHOUGHT.
-- `(tenant_id, alias)` is the identity of a row. A second row for the same pair
-- is not "last write wins", it is two answers to one question on the hot path,
-- and the spec is explicit that a conflict is surfaced inline and never
-- silently overwritten.
--
-- NO DEFAULT TARGET, ENFORCED BY THE ABSENCE OF A DEFAULT.
-- `target_model` is NOT NULL with no default. An alias that resolves to nothing
-- must fail closed as `400 unroutable_model` — defaulting would send one
--
-- `last_used_at` IS NULLABLE AND MEANS "NEVER USED", NOT "USED AT EPOCH".
-- The UI renders a LAST USED column; a NULL renders as "never", which is a
-- different and more useful statement than a fabricated timestamp. It is
-- updated off the hot path (best-effort), so it is a hint, never billing input.

CREATE TABLE IF NOT EXISTS model_aliases (
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alias        text        NOT NULL,
    target_model text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,

    PRIMARY KEY (tenant_id, alias),

    -- An alias is a model string a caller types. Bound it so it cannot be used
    -- to smuggle whitespace, a path, or a 10 KB blob into the routing seam.
    -- 1..=64 printable, no leading/trailing space.
    CONSTRAINT model_aliases_alias_shape_chk
        CHECK (alias ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),

    -- The target must look like a model string, not a URL and not empty.
    -- Whether it actually ROUTES is checked by the gateway against the live
    -- provider map before the row is written — a CHECK cannot know the model
    -- table, and pretending it can is how a stale constraint starts lying.
    CONSTRAINT model_aliases_target_shape_chk
        CHECK (length(target_model) BETWEEN 1 AND 200
               AND target_model !~ '^[a-zA-Z]+://'),

    -- An alias pointing at itself is an infinite indirection that resolves to
    -- nothing useful. Rejected in the database so it cannot arrive by any
    -- writer, including a direct psql session.
    CONSTRAINT model_aliases_no_self_reference_chk
        CHECK (alias <> target_model)
);

-- The hot path reads by (tenant_id, alias) — served by the primary key.
-- This index serves the SETTINGS list ("show me my aliases, newest first"),
-- which is the only other access pattern.
CREATE INDEX IF NOT EXISTS model_aliases_tenant_created_idx
    ON model_aliases (tenant_id, created_at DESC);

-- Cache invalidation, same shape as the entitlement cache: the gateway holds a
-- Moka cache and LISTENs, so a Settings edit takes effect without a per-request
-- Postgres hit and without waiting out a TTL.
--
-- NOTE THE CHANNEL NAME IS FIXED AND MATCHED IN RUST. A rename here that is not
-- made there produces a cache that never invalidates — which looks exactly like
-- a working cache until someone edits an alias and it does not take.
CREATE OR REPLACE FUNCTION notify_model_alias_change() RETURNS trigger AS $$
BEGIN
    -- COALESCE: on DELETE, NEW is NULL and the tenant is only on OLD.
    PERFORM pg_notify('model_alias_changed',
                      COALESCE(NEW.tenant_id, OLD.tenant_id)::text);
    RETURN NULL;  -- AFTER trigger; the return value is ignored.
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS model_aliases_notify ON model_aliases;
CREATE TRIGGER model_aliases_notify
    AFTER INSERT OR UPDATE OR DELETE ON model_aliases
    FOR EACH ROW EXECUTE FUNCTION notify_model_alias_change();
