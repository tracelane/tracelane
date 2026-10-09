-- Scoped rail configuration; the gateway writes its control audit in the same transaction.
-- Written only: apply before deploying a gateway that reads guardrail_policies.
CREATE TABLE IF NOT EXISTS guardrail_policies (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope text NOT NULL CHECK (scope IN ('workspace', 'key', 'project')),
    scope_id uuid NOT NULL,
    policy jsonb NOT NULL CHECK (jsonb_typeof(policy) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL,
    PRIMARY KEY (tenant_id, scope, scope_id),
    CHECK (scope <> 'workspace' OR scope_id = tenant_id)
);

-- Reuse the entitlement invalidation channel; local PUT also evicts synchronously.
DROP TRIGGER IF EXISTS trg_guardrail_policies_notify ON guardrail_policies;
CREATE TRIGGER trg_guardrail_policies_notify
    AFTER INSERT OR UPDATE OR DELETE ON guardrail_policies
    FOR EACH ROW EXECUTE FUNCTION notify_workspace_entitlements_changed();
