-- Canonical receipt-key selection; independent of any optional recording-recovery tables.
-- Apply outside a transaction before the gateway reader rollout.
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_receipt_key_lookup
ON audit_log_rows(tenant_id, ((payload::jsonb)->>'action_id'), seq DESC)
WHERE event_type = 'tool_receipt_key_registered';
