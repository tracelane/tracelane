-- Add before the gateway reads registered principal issuers (S2).
-- Registration serializes under the tenant row until post-deploy constraints land.
CREATE TABLE tenant_principal_issuers (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    issuer text NOT NULL,
    jwks_url text NOT NULL,
    audience text NOT NULL,
    allowed_algs text[] NOT NULL,
    created_by_sub text NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX tenant_principal_issuers_tenant_idx ON tenant_principal_issuers (tenant_id);
