-- Hand apply before deploying the gateway that reads these columns.
BEGIN;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS capture jsonb;
DO $$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'api_keys'::regclass AND conname = 'api_keys_capture_object') THEN
ALTER TABLE api_keys ADD CONSTRAINT api_keys_capture_object CHECK (
 capture IS NULL OR (jsonb_typeof(capture) = 'object'
 AND capture - 'input' - 'output' = '{}'::jsonb
 AND (NOT capture ? 'input' OR jsonb_typeof(capture->'input') = 'boolean')
 AND (NOT capture ? 'output' OR jsonb_typeof(capture->'output') = 'boolean'))
);
END IF;
END $$;
CREATE TABLE IF NOT EXISTS workspace_data_controls (
 tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
 retention_days integer CHECK (retention_days > 0),
 updated_by text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
