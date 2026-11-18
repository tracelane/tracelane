-- Apply outside a transaction: CONCURRENTLY cannot run inside BEGIN/COMMIT.
-- Full-dedup verdict replay must not scan the tenant ledger under the workspace lock.
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_protected_event_id ON audit_log_rows(tenant_id,((payload::jsonb)->>'event_id'))
 WHERE event_type IN ('decision_made','denied_runtime');
