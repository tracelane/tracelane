-- 0011_identity_api_keys_minted_by — attribute API keys to their minting user.
--
-- WHY: IDENTITY_TEAM_SPEC §3 requires that removing an org member revokes THAT
-- member's `tlane_` API keys (their next gateway request must 401). To scope the
-- revoke to a single user's keys we need to know who minted each key. The gateway
-- mint path (POST /v1/keys) now records the WorkOS user id (`Claims.sub`) here.
--
-- SHAPE: nullable TEXT holding the WorkOS user id (`user_...`). Nullable because
-- pre-existing keys have no recorded minter — those are NOT revoked on member
-- removal (they can't be attributed). Acceptable: nearly all keys are minted
-- after this ships. New keys always carry it.
--
-- SAFETY: additive, idempotent (IF NOT EXISTS). No existing row is modified.
--
-- APPLY: hand-written + manual-paste to Neon, matching the 0009/0010 pattern
-- (un-journaled; recent Neon migrations here are applied by paste, not

ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "minted_by" text;
