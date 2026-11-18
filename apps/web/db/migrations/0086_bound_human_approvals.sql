-- Existing 0084 bindings are reused; only constraints and lookup indexes are missing.
SET lock_timeout = '5s';
ALTER TABLE approvals DROP CONSTRAINT approvals_status_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_status_check
 CHECK(status IN ('pending','approved','denied','expired','consumed','invalidated'));
ALTER TABLE approvals ADD CONSTRAINT approvals_protected_binding CHECK (
 action_id IS NULL OR (decision_id IS NOT NULL AND request_digest IS NOT NULL
 AND policy_id IS NOT NULL AND policy_version IS NOT NULL AND policy_hash IS NOT NULL
 AND tool_ref IS NOT NULL AND contract_version IS NOT NULL AND proposer_key_id IS NOT NULL
 AND requester_creator IS NOT NULL AND requester_creator<>''
 AND policy_publisher_sub IS NOT NULL AND policy_publisher_sub<>'')
);
ALTER TABLE approvals ADD CONSTRAINT approvals_protected_state CHECK (
 action_id IS NULL OR (
 (status NOT IN ('approved','denied','consumed') OR
  (decided_ledger_seq IS NOT NULL AND qualified_human_sub IS NOT NULL
   AND qualified_human_sub<>requester_creator AND qualified_human_sub<>policy_publisher_sub))
 AND (status<>'consumed' OR consumed_ledger_seq IS NOT NULL))
);
-- A composite FK needs a unique target; id is already the PK, so this cannot fail.
-- Caught by the 2026-10-25 Neon dry run (no unique constraint matched).
ALTER TABLE api_keys ADD CONSTRAINT api_keys_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE approvals ADD CONSTRAINT approvals_proposer_fk
 FOREIGN KEY(tenant_id,proposer_key_id) REFERENCES api_keys(tenant_id,id) NOT VALID;
ALTER TABLE approvals VALIDATE CONSTRAINT approvals_proposer_fk;
CREATE INDEX approvals_protected_request ON approvals(tenant_id,requester_sub,request_digest,policy_hash,created_at DESC)
 WHERE action_id IS NOT NULL;
