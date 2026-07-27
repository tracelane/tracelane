-- Per-tenant Ed25519 signing keypairs for the tamper-evident audit ledger.
--
-- Enterprise-tier feature (F_AUDIT_KEYPAIR entitlement gate).
-- Keypairs are AES-256-GCM envelope-encrypted with the workspace BYOK master
-- key (TRACELANE_BYOK_MASTER_KEY) before storage.
--
-- Key rotation: insert a new row with rotated_from = old keypair's id;
-- the newest row (latest created_at) is the active signing key.
--
-- References: crates/gateway/src/audit_keys.rs

CREATE TABLE IF NOT EXISTS tenant_audit_keys (
    id               UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id        UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- AES-256-GCM envelope-encrypted PKCS#8 DER base64 string.
    -- Format: base64(12-byte nonce || ciphertext || 16-byte GCM tag)
    encrypted_private_key TEXT   NOT NULL,
    -- Public key bytes (SubjectPublicKeyInfo) in base64 for Rekor verification.
    public_key_b64   TEXT        NOT NULL DEFAULT '',
    -- Non-null when this key replaced a prior one (rotation trail).
    rotated_from     UUID        REFERENCES tenant_audit_keys(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at       TIMESTAMPTZ,

    CONSTRAINT one_active_key_per_tenant UNIQUE (tenant_id)
);

CREATE INDEX IF NOT EXISTS tenant_audit_keys_tenant_idx
    ON tenant_audit_keys (tenant_id)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE tenant_audit_keys IS
    'Per-tenant Ed25519 keypairs for Rekor audit-ledger anchoring (Enterprise tier). '
    'Keypairs are BYOK envelope-encrypted; decrypt via crates/gateway/src/byok.rs.';
