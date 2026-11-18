-- AUD-12: optional TSA response beside the exact signed checkpoint. Deploy before gateway.
ALTER TABLE audit_head_checkpoints ADD COLUMN IF NOT EXISTS timestamp_response bytea;
ALTER TABLE audit_head_checkpoints ADD COLUMN IF NOT EXISTS timestamp_attempted_at timestamptz;
CREATE INDEX IF NOT EXISTS audit_head_checkpoints_pending_timestamp
  ON audit_head_checkpoints(timestamp_attempted_at NULLS FIRST, checkpoint_order)
  WHERE timestamp_response IS NULL;
