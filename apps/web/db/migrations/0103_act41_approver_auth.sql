-- ACT-41: how the approver authenticated when approving a held call (specs/ACT-41-approver-step-up.md).
-- ADD only, nullable, no default: safe to apply before the gateway that writes it; nothing reads it yet.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decided_auth_at timestamptz;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decided_auth_method text;
