-- Postgres 17 + Neon-compatible. Idempotent — every CREATE has IF NOT EXISTS.
--
-- The pre-migration schema stored the key body as bare SHA-256 (no salt, no
-- KDF, no pepper). A DB dump exposed hashes that are trivially confirmable
-- against candidate strings.
--
-- New shape:
--   `lookup_hash`  — HMAC-SHA256(pepper, key_body) for the hot-path lookup.
--                    Peppered: DB dump alone cannot regenerate it.
--                    Deterministic: 32 bytes, indexed UNIQUE, ~1us lookup.
--   `argon2id_phc` — Argon2id PHC string for verification, including
--                    per-row salt + standard m/t/p params. Verified AFTER
--                    the lookup hits, so the slow KDF cost is paid only
--                    once per legitimate request (not on every dictionary
--                    guess).
--
-- Lookup vs verify split is the standard "peppered HMAC lookup, KDF verify"
-- pattern (1Password, Bitwarden, Dropbox postmortem). Argon2id alone
-- cannot be used as the lookup column because per-row salt makes the
-- output non-deterministic.
--
-- Backfill: existing rows have `key_hash` (legacy SHA-256). On the next
-- successful auth, the gateway writes `lookup_hash` and `argon2id_phc`
-- lazily — no batch backfill job required. The legacy column stays for
-- now (cut over after observing 100% backfill from telemetry).

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS lookup_hash  BYTEA,
    ADD COLUMN IF NOT EXISTS argon2id_phc TEXT;

-- The `lookup_hash` UNIQUE constraint is added as a partial UNIQUE INDEX
-- so NULL values (un-backfilled legacy rows) don't conflict with each
-- other. Once backfill is complete and the legacy `key_hash` column is
-- dropped, this can be promoted to a full UNIQUE.
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_lookup_hash
    ON api_keys(lookup_hash)
    WHERE lookup_hash IS NOT NULL;

-- Hot-path lookup index: gateway looks up by lookup_hash where the key
-- is not revoked. Same shape as the legacy `idx_api_keys_lookup` but on
-- the new column.
CREATE INDEX IF NOT EXISTS idx_api_keys_lookup_hash_active
    ON api_keys(lookup_hash) WHERE revoked_at IS NULL AND lookup_hash IS NOT NULL;
