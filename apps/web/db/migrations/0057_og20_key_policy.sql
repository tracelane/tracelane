-- 0057 — OG-20: per-key (and per-project) policy.
--
-- UN-JOURNALED, like every migration from 0009 on: applied to Neon BY HAND.
--
-- **SERIALIZATION POINT S2**, and it REQUIRES 0056 (the `projects` table). The
-- gateway's API-key auth SELECT reads `api_keys.policy` and `projects.policy` in the
-- same round trip that authenticates the key; its boot check
-- (`entitlement_cache::verify_schema`) REFUSES TO BOOT when either is absent. Order:
--   1. 0056_og23_projects_environments.sql,
--   2. THIS file,
--   3. deploy the gateway.
-- Step 2 is safe under the CURRENT binaries: nothing deployed reads the columns, and
-- NULL is "no policy" = today's behaviour.
--
-- THE DOCUMENT (spec `specs/OG-20-per-key-policy.md` §2): an object with any of
-- models{allow,deny}, providers{allow,deny}, source_ips, max_input_tokens,
-- max_output_tokens, max_body_bytes, required_tags, required_metadata_keys. The
-- gateway validates it strictly on write and parses it on read; a stored document it
-- cannot parse REFUSES every request on the key (403 policy_invalid) — fail-CLOSED.
-- The database checks only the outer shape: the vocabulary has ONE authority,
-- `crates/gateway/src/key_policy.rs`, exactly as `api_keys.scope`'s does.
--
-- Idempotent. REVERSIBLE before step 3: ALTER TABLE api_keys DROP COLUMN policy;
-- ALTER TABLE projects DROP COLUMN policy.

-- rev5 L2 (2026-10-04): every ALTER below takes an ACCESS EXCLUSIVE lock on `api_keys`
-- -- the table EVERY authenticated request reads. Bounded like 0055/0058: a busy table
-- fails this file fast (re-run it; it is idempotent) instead of queueing every key
-- lookup behind the lock while it waits.
SET lock_timeout = '5s';

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS policy jsonb;
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_policy_object_chk;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_policy_object_chk
    CHECK (policy IS NULL OR jsonb_typeof(policy) = 'object');

ALTER TABLE projects ADD COLUMN IF NOT EXISTS policy jsonb;
ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_policy_object_chk;
ALTER TABLE projects ADD CONSTRAINT projects_policy_object_chk
    CHECK (policy IS NULL OR jsonb_typeof(policy) = 'object');

COMMENT ON COLUMN api_keys.policy IS
  'OG-20: this key''s own policy (NULL = none). Evaluated IN ADDITION to its project''s: both must pass. Authority for the vocabulary: crates/gateway/src/key_policy.rs. An unparseable document refuses every request on the key.';
COMMENT ON COLUMN projects.policy IS
  'OG-20: the policy every key in this project is governed by, in addition to the key''s own (NULL = none).';

RESET lock_timeout;
