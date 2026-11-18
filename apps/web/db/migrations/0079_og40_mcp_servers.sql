-- Hand apply to Neon before the gateway that reads MCP state. Additive; no seed.
BEGIN;
CREATE TABLE IF NOT EXISTS mcp_servers (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 slug text NOT NULL CHECK (slug ~ '^[a-z0-9-]{1,48}$'),
 name text NOT NULL,
 url text NOT NULL,
 transport text NOT NULL CHECK (transport IN ('streamable_http','legacy_sse')),
 auth_mode text NOT NULL CHECK (auth_mode IN ('none','gateway_held','passthrough')),
 credential_kind text NOT NULL DEFAULT 'bearer' CHECK (credential_kind IN ('bearer','header')),
 credential_header text,
 credential_ct text,
 credential_last4 text,
 enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 archived_at timestamptz,
 UNIQUE(tenant_id,id),
 CHECK ((auth_mode='gateway_held') = (credential_ct IS NOT NULL)),
 CHECK (credential_kind != 'header' OR credential_header IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS mcp_servers_slug ON mcp_servers(tenant_id,slug) WHERE archived_at IS NULL;
COMMIT;
