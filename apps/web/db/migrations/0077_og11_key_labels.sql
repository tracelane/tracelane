-- Contract step for routing key pools. WRITTEN, NEVER APPLIED.
-- Prerequisite: 0070 applied and EVERY gateway binary supports labeled keys.
-- 0070 deliberately preserves the old conflict target during the rolling deploy.
-- This step enables non-default labels; older binaries MUST NOT run afterward.
-- A rollback to an older binary requires removing all non-default labels first
-- and restoring PRIMARY KEY (tenant_id, provider_id), under operator review.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'provider_keys'::regclass
          AND conname = 'provider_keys_tenant_provider_label_pk'
    ) THEN
        ALTER TABLE provider_keys DROP CONSTRAINT IF EXISTS provider_keys_tenant_id_provider_id_pk;
        ALTER TABLE provider_keys ADD CONSTRAINT provider_keys_tenant_provider_label_pk
            PRIMARY KEY USING INDEX provider_keys_tenant_provider_label_unique;
    END IF;
END $$;
