-- 0019 (B-119 fix B): emit a `key_revoked` NOTIFY on every api-key revocation so
-- the gateway's in-process auth-result cache evicts IMMEDIATELY (not TTL-bound).
--
-- Covers ALL revoke paths — web team-member removal, account self-delete,
-- workspace soft-delete, and the gateway `api_keys::revoke()` — because every one
-- sets `revoked_at`. A single AFTER-UPDATE trigger fires for all of them; the
-- alternative (a pg_notify in each of the 4 call sites) is more code across more
-- files and drifts.
--
-- Payload = hex(lookup_hash) — the gateway auth cache key (peppered-HMAC digest).
-- Idempotent: safe to re-apply (CREATE OR REPLACE + DROP TRIGGER IF EXISTS).
--
-- NOTE: intentionally NOT added to the gateway `db::apply_migrations` include_str!
-- list — the gateway integration tests do not exercise revocation NOTIFY and need
-- not run plpgsql. Applied to prod directly (like 0009–0018, which the drizzle
-- journal also does not track).

CREATE OR REPLACE FUNCTION notify_key_revoked() RETURNS trigger AS $$
BEGIN
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
    PERFORM pg_notify('key_revoked', encode(NEW.lookup_hash, 'hex'));
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS api_keys_revoked_notify ON api_keys;
CREATE TRIGGER api_keys_revoked_notify
  AFTER UPDATE OF revoked_at ON api_keys
  FOR EACH ROW
  EXECUTE FUNCTION notify_key_revoked();
