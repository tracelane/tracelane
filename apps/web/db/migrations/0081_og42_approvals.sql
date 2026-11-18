-- Apply after 0080, before the gateway. No migration is applied by this build.
BEGIN;
CREATE TABLE IF NOT EXISTS approval_settings (
 tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
 require_second_approver boolean NOT NULL DEFAULT false,
 default_ttl_secs integer NOT NULL CHECK(default_ttl_secs > 0),
 updated_at timestamptz NOT NULL DEFAULT now(), updated_by text NOT NULL
);
CREATE TABLE IF NOT EXISTS approval_rules (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 model_glob text NOT NULL, key_id uuid, ttl_secs integer CHECK(ttl_secs > 0),
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE INDEX IF NOT EXISTS approval_rules_tenant ON approval_rules(tenant_id);
CREATE TABLE IF NOT EXISTS approvals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 subject_kind text NOT NULL CHECK(subject_kind IN ('tool','model')),
 server_id uuid, subject text NOT NULL, key_id uuid, project_id uuid,
 requester_sub text NOT NULL, requester_creator text,
 args_fp text NOT NULL, args_bytes bigint NOT NULL, args_preview text,
 rule_id uuid,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','expired','consumed')),
 decided_by text, decided_at timestamptz, decision_note text,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 grant_expires_at timestamptz, consumed_at timestamptz, trace_id uuid,
 FOREIGN KEY(tenant_id,server_id) REFERENCES mcp_servers(tenant_id,id),
 UNIQUE(tenant_id,requester_sub,args_fp)
);
CREATE INDEX IF NOT EXISTS approvals_queue ON approvals(tenant_id,status,created_at DESC,id);
COMMIT;
