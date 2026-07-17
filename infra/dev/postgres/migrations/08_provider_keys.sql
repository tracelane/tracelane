-- Migration 08: BYOK provider keys for the gateway hot path (A4 / R-launch).
-- Postgres 17 + Neon-compatible. Idempotent.
--
-- Pre-migration the gateway resolved provider keys via process env var
-- (single key per family across all tenants). This table holds per-tenant
-- ciphertext-encrypted provider keys, matching the marketing claim in
-- SECURITY.md ("BYOK only — provider API keys envelope-encrypted at rest
-- with AES-256-GCM via ring") and CLAUDE.md security non-negotiable #5.
--
-- Ciphertext layout (v2 wire format, see crates/gateway/src/byok.rs):
--   [version u8 = 0x02][nonce 12 bytes][AES-256-GCM ciphertext][tag 16 bytes]
-- AAD bound to (tenant_id, provider_id) so a DB-dump attacker cannot
-- cross-tenant-swap ciphertext blobs without forfeiting the AEAD tag.

CREATE TABLE IF NOT EXISTS provider_keys (
    tenant_id     UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    provider_id   TEXT NOT NULL,                       -- "anthropic" | "openai" | ...
    -- Base64-encoded BYOK v2 wire (matches what `byok::encrypt_with_context`
    -- returns). TEXT not BYTEA so the encrypt → store → fetch loop never
    -- has to base64-decode-then-re-encode; the gateway always handles
    -- base64 strings.
    ciphertext_b64 TEXT NOT NULL,
    last4         TEXT NOT NULL,                       -- last 4 chars of plaintext (display only)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider_id)
);

-- Hot-path lookup is by `(tenant_id, provider_id)` — the PK covers it.
-- Index `tenant_id` on its own for the "list my keys" endpoint.
CREATE INDEX IF NOT EXISTS idx_provider_keys_tenant
    ON provider_keys(tenant_id);
