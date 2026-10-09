-- Tenant-owned signed guardrails. Written only; apply before the gateway reads this table.
CREATE TABLE IF NOT EXISTS guardrail_hooks (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    config jsonb NOT NULL CHECK (jsonb_typeof(config) = 'object'),
    ciphertext_b64 text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
DROP TRIGGER IF EXISTS trg_guardrail_hooks_notify ON guardrail_hooks;
CREATE TRIGGER trg_guardrail_hooks_notify
    AFTER INSERT OR UPDATE OR DELETE ON guardrail_hooks
    FOR EACH ROW EXECUTE FUNCTION notify_workspace_entitlements_changed();
