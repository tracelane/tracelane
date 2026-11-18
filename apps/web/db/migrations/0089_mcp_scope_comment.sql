-- Documentation only: MCP is explicit opt-in, just like passthrough.
-- Unjournaled; apply separately. No schema, grants or scope semantics change.
-- Reversible by reapplying the COMMENT statement from migration 0054.
COMMENT ON COLUMN api_keys.scope IS
    'Permission scopes from the closed vocabulary {chat,read,ingest,admin,passthrough,mcp}. NULL = legacy API surface EXCEPT passthrough and mcp, which must each be granted by name and are never implied by admin. Never empty; an unknown scope denies. Authority is Scope::from_slug in crates/shared/src/api_scope.rs - this comment is documentation, not a constraint.';
