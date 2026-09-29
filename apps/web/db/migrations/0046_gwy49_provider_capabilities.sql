-- GWY-49 (2026-09-20): the zero-data-retention capability per provider — a reference table
-- (CLAUDE.md §23) the gateway reads through its refresher to prune routing under an
-- `x-tracelane-zdr: required` constraint. Seeded from apps/web/db/provider_capabilities.v1.json
-- by apps/web/db/seed.mjs; every row ships as `none` until a policy page has been read and dated.
-- S2 ordering: this lands on Neon BEFORE the gateway that reads it deploys (the deploy's
-- schema pre-flight requires every table the binary reads).
CREATE TABLE IF NOT EXISTS provider_capabilities (
    provider_id text PRIMARY KEY,
    zdr         text NOT NULL DEFAULT 'none',
    policy_url  text,
    verified_at timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT provider_capabilities_zdr_chk CHECK (zdr IN ('none', 'default', 'enterprise'))
);
COMMENT ON TABLE provider_capabilities IS
    'GWY-49: per-provider zero-data-retention capability (none | default | enterprise); a default/enterprise row must carry policy_url + verified_at. Seeded from provider_capabilities.v1.json.';
