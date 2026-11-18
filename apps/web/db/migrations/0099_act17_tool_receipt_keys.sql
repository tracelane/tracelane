-- ACT-17: the Ed25519 key a tool server countersigns protected receipts with, one per
-- (tenant, server). ADD-only; apply before the gateway that reads it. The key is also
-- recorded in the action ledger (tool_receipt_key_registered), which is what a verifier trusts.
SET lock_timeout = '5s';
CREATE TABLE IF NOT EXISTS action_tool_receipt_keys (
    tenant_id uuid NOT NULL,
    server_id uuid NOT NULL,
    receipt_key_id text NOT NULL,
    public_key bytea NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, server_id)
);
