-- Retirement can be scheduled in the future. Moving that deadline earlier must
-- invalidate cached authentication too, including on replicas using LISTEN.
-- Replaces the function installed by 0019; the existing trigger stays attached.
CREATE OR REPLACE FUNCTION notify_key_revoked() RETURNS trigger AS $$
BEGIN
  IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    PERFORM pg_notify('key_revoked', encode(NEW.lookup_hash, 'hex'));
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
