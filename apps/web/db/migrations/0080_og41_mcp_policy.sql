-- Apply after 0079, before deploying the gateway; retained on application rollback.
BEGIN;
CREATE TABLE IF NOT EXISTS mcp_policy (
 tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
 rules_mode text NOT NULL DEFAULT 'observe' CHECK(rules_mode IN ('observe','enforce')),
 pins_mode text NOT NULL DEFAULT 'observe' CHECK(pins_mode IN ('observe','enforce')),
 injection_mode text NOT NULL DEFAULT 'observe' CHECK(injection_mode IN ('observe','enforce')),
 default_action text NOT NULL DEFAULT 'allow' CHECK(default_action IN ('allow','deny')),
 updated_at timestamptz NOT NULL DEFAULT now(), updated_by text NOT NULL
);
CREATE TABLE IF NOT EXISTS mcp_tool_rules (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 server_id uuid,
 key_id uuid,
 tool_glob text NOT NULL,
 action text NOT NULL CHECK(action IN ('allow','deny','require_approval')),
 reason text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL,
 FOREIGN KEY (tenant_id,server_id) REFERENCES mcp_servers(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS mcp_tool_rules_tenant ON mcp_tool_rules(tenant_id);
CREATE TABLE IF NOT EXISTS mcp_tool_defs (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 server_id uuid NOT NULL,
 tool_name text NOT NULL,
 def_hash text NOT NULL,
 status text NOT NULL DEFAULT 'observed' CHECK(status IN ('observed','approved')),
 first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
 seen_count bigint NOT NULL DEFAULT 1,
 approved_by text, approved_at timestamptz,
 PRIMARY KEY(tenant_id,server_id,tool_name,def_hash),
 FOREIGN KEY (tenant_id,server_id) REFERENCES mcp_servers(tenant_id,id)
);
CREATE UNIQUE INDEX IF NOT EXISTS mcp_tool_defs_approved ON mcp_tool_defs(tenant_id,server_id,tool_name) WHERE status='approved';
COMMIT;
