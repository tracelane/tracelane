-- Ledger of control-plane migrations applied by scripts/deploy/migrate.sh (deploy.yml, on merge to main).
-- Hand-applied ONCE (2026-11-10), with a baseline row for every file 0000..0092 already in Neon.
-- From 0093 on, deploy.yml's migrate job applies each unrecorded file BEFORE the gateway job runs,
-- so "migration before the gateway that reads it" is structural (CLAUDE.md §5). A recorded name
-- whose file hash has changed is a hard failure: an applied migration is never edited.
-- Idempotent. No data, no grants.
CREATE TABLE IF NOT EXISTS ops_applied_migrations (
    name text PRIMARY KEY,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT now()
);
