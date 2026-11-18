-- Apply outside a transaction: CONCURRENTLY cannot run inside BEGIN/COMMIT.
-- Hand-applied to Neon BEFORE the gateway that reads it deploys (CLAUDE.md §5); the register
-- as-of read works without it, but scans the tenant's whole ledger until it exists.
-- ACT-15b: the as-of authority register reads only policy_activated rows, by (tenant, seq).
-- After applying, prove the build finished:
--   SELECT indisvalid FROM pg_index WHERE indexrelid = 'audit_policy_activations'::regclass;
-- must return true; if false, DROP INDEX CONCURRENTLY audit_policy_activations and re-run.
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_policy_activations ON audit_log_rows(tenant_id, seq)
 WHERE event_type = 'policy_activated';
