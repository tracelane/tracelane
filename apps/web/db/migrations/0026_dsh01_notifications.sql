-- 0026 — DSH-01 in-app notification inbox.
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` applies
-- only 0000–0008, so this is applied to Neon BY HAND and MUST land BEFORE the
-- gateway that reads it deploys (CLAUDE.md §4.0, serialization point S2).
-- Additive and reversible: one new table, nothing taken away.
--
-- READ STATE IS TENANT-WIDE, NOT PER-USER, AND THE UI SAYS SO.
-- Per-user read state needs a per-user join for little benefit at this scale.
-- The spec's instruction was explicit: tenant-wide, and disclosed — rather than
-- a per-user feature that silently is not one.
--
-- `link` IS A RELATIVE IN-APP PATH, never an absolute URL.
-- These rows are written by producers and rendered as anchors. A stored
-- absolute URL is an open redirect with extra steps; the CHECK makes that
-- structural rather than a convention someone later forgets.
--
-- THE VOCABULARIES ARE CLOSED IN THE DATABASE TOO, for the same reason as
-- trace_annotations in 0025: a kind or severity the UI cannot render is worse
-- than a rejected write, and the constraint survives a writer that skips the
-- gateway.

CREATE TABLE IF NOT EXISTS notifications (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        text        NOT NULL,
    title       text        NOT NULL,
    body        text        NOT NULL DEFAULT '',
    severity    text        NOT NULL DEFAULT 'info',
    link        text        NOT NULL DEFAULT '',
    read_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT notifications_kind_chk
        CHECK (kind IN ('quota', 'alert', 'promotion')),
    CONSTRAINT notifications_severity_chk
        CHECK (severity IN ('info', 'warning', 'critical')),
    -- Empty, or a path starting with exactly one '/'. `//host` is rejected
    -- because a protocol-relative URL leaves the app just as effectively as
    -- `https://host` does.
    CONSTRAINT notifications_link_relative_chk
        CHECK (link = '' OR (link LIKE '/%' AND link NOT LIKE '//%'))
);

CREATE INDEX IF NOT EXISTS notifications_tenant_created_idx
    ON notifications (tenant_id, created_at DESC);
