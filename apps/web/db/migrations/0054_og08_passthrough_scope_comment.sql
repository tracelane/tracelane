-- 0054 — OG-08: the `passthrough` scope joins the closed vocabulary.
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` applies
-- only 0000–0008, so this is applied to Neon BY HAND.
--
-- **NOT a serialization point (S2 does not apply).** Nothing reads a column
-- comment — no gateway code path, no query, no entitlement. It may be applied
-- before, after or long after the gateway that adds the scope; no ordering can
-- break anything. It is recorded as a migration only because the comment lives
-- in the database and there is no other way to change it.
--
-- NO SCHEMA CHANGE. `api_keys.scope` is `text[]` (NOT an enum) and the only CHECK
-- on it is `api_keys_scope_not_empty_chk` (`cardinality(scope) > 0`, 0024); the
-- legal VALUES were never enumerated in the database, deliberately, because
-- `Scope::from_slug` is the one authority. Adding a scope needs no DDL.
--
-- THE ONE SCOPE A LEGACY KEY DOES NOT GET. `NULL` = full API surface for every
-- key minted before scopes existed — EXCEPT `passthrough`, which bypasses
-- guardrails and per-model budgets and so must be granted by name, per key
-- (`KeyScope::allows`, crates/shared/src/api_scope.rs). The comment says so,
-- because a psql session during an incident is where someone reads it.
--
-- `scripts/ci/check-api-scope-single-source.py` fails if this comment, the enum,
-- `from_slug` and the mint dialog's checkbox list disagree.
--
-- REVERSIBLE: re-run 0028's COMMENT statement.

COMMENT ON COLUMN api_keys.scope IS
    'Permission scopes from the closed vocabulary {chat,read,ingest,admin,passthrough}. NULL = full API surface (legacy keys) EXCEPT passthrough, which is never inherited and never implied: it must be granted by name. Never empty; an unknown scope denies. Authority is Scope::from_slug in crates/shared/src/api_scope.rs - this comment is documentation, not a constraint.';
