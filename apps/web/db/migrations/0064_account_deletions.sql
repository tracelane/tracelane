-- Durable account erasure. Hand-applied before deploying the account route.
-- No contact details: only the opaque identity needed to reject delayed writers.
CREATE TABLE IF NOT EXISTS account_deletions (
    workos_user_id text PRIMARY KEY
);

-- All identity PII writers and the eraser take the same transaction lock. The
-- marker read is a separate query INSIDE this volatile trigger, so READ COMMITTED
-- gets a fresh snapshot AFTER a concurrent eraser releases the lock. A plain
-- INSERT ... WHERE NOT EXISTS with a pre-lock snapshot would still race.
CREATE OR REPLACE FUNCTION suppress_deleted_identity() RETURNS trigger
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
    IF NEW.workos_user_id IS NULL THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.workos_user_id, 0));
    IF EXISTS (SELECT 1 FROM account_deletions WHERE workos_user_id = NEW.workos_user_id) THEN
        RETURN NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS signups_deleted_identity ON signups;
CREATE TRIGGER signups_deleted_identity BEFORE INSERT OR UPDATE ON signups
FOR EACH ROW EXECUTE FUNCTION suppress_deleted_identity();
DROP TRIGGER IF EXISTS users_deleted_identity ON users;
CREATE TRIGGER users_deleted_identity BEFORE INSERT OR UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION suppress_deleted_identity();

-- One statement/transaction: erase first, then record completion. Any error rolls
-- back every local change; the caller must retain the WorkOS identity for retry.
CREATE OR REPLACE FUNCTION erase_account_pii(identity_id text) RETURNS void
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(identity_id, 0));
    DELETE FROM signups WHERE workos_user_id = identity_id;
    UPDATE users SET email = 'deleted-' || identity_id || '@tombstone.invalid',
                     name = NULL, last_login_at = NULL
        WHERE workos_user_id = identity_id;
    INSERT INTO account_deletions (workos_user_id) VALUES (identity_id)
        ON CONFLICT DO NOTHING;
END;
$$;
