-- Customer-managed provider-key envelopes. Written only; apply before the gateway.
ALTER TABLE plan_entitlements ADD COLUMN IF NOT EXISTS f_customer_kms boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS tenant_kms_configs (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    backend text NOT NULL CHECK (backend IN ('aws_kms','vault_transit','gcp_kms','azure_key_vault')),
    key_ref text NOT NULL,
    params jsonb NOT NULL CHECK (jsonb_typeof(params) = 'object'),
    secret_enc text,
    status text NOT NULL DEFAULT 'active' CHECK (status = 'active'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_data_keys (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    wrapped_dek bytea NOT NULL,
    key_ref text NOT NULL,
    retired_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS tenant_data_keys_active_tenant_idx ON tenant_data_keys(tenant_id) WHERE retired_at IS NULL;
