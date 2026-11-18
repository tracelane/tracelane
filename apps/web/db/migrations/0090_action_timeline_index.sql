-- Apply outside a transaction: CONCURRENTLY cannot run inside BEGIN/COMMIT.
-- ACT-10a read API for protected actions. S2: hand-applied to Neon BEFORE the gateway that reads it.
-- Idempotent. A failed CONCURRENTLY build leaves an INVALID index of the same name: DROP INDEX it, re-run.
-- POST-APPLY CHECK (all rows must read indisvalid = t; an INVALID index must be dropped and re-run):
--   SELECT indexrelid::regclass, indisvalid FROM pg_index WHERE indexrelid IN
--     ('audit_action_id'::regclass, 'audit_action_heads'::regclass, 'approvals_tenant_action_id'::regclass);
-- PRE-APPLY CHECK for approvals_tenant_action_id (must return 0 rows, else do not apply):
--   SELECT tenant_id, action_id FROM approvals WHERE action_id IS NOT NULL GROUP BY 1,2 HAVING count(*)>1;
-- Per-action timeline: all events of one action_id, in seq order, for one tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_action_id ON audit_log_rows(tenant_id,((payload::jsonb)->>'action_id'),seq)
 WHERE event_type IN ('action_proposed','decision_made','approval_requested','approval_granted','approval_denied','approval_attempt_rejected','approval_consumed','approval_expired','approval_invalidated','legacy_forward_attempted','execution_started','execution_succeeded','execution_failed','execution_unknown','denied_runtime','policy_activated');
-- Action list: newest action heads first, keyset-paged by seq.
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_action_heads ON audit_log_rows(tenant_id,seq DESC)
 WHERE event_type IN ('action_proposed','denied_runtime');
-- One approval per protected action: the descriptor read assumes it. No code path inserts two
-- (protected.rs mints a fresh action_id per request; the legacy queue leaves action_id NULL).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS approvals_tenant_action_id ON approvals(tenant_id,action_id)
 WHERE action_id IS NOT NULL;
