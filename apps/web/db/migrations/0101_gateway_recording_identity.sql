-- Recording identity/projection foundation. No producer or coverage claim is enabled.
-- Retained alongside canonical audit rows, including after tenant deletion.
CREATE TABLE IF NOT EXISTS gateway_recording_events (
    dedup_id text PRIMARY KEY,
    tenant_id uuid NOT NULL,
    event_id text NOT NULL,
    instance_id text NOT NULL,
    boot_epoch uuid NOT NULL,
    emitter_seq bigint NOT NULL CHECK (emitter_seq >= 0),
    event_digest text NOT NULL,
    ledger_seq bigint,
    CONSTRAINT gateway_recording_sequence UNIQUE (tenant_id, instance_id, boot_epoch, emitter_seq),
    CONSTRAINT gateway_recording_ledger UNIQUE (tenant_id, ledger_seq)
);
CREATE TABLE IF NOT EXISTS gateway_emitter_heads (
    tenant_id uuid NOT NULL,
    instance_id text NOT NULL,
    boot_epoch uuid NOT NULL,
    highest_emitter_seq bigint NOT NULL CHECK (highest_emitter_seq >= 0),
    last_ledger_seq bigint NOT NULL CHECK (last_ledger_seq >= 0),
    recorded_events bigint NOT NULL CHECK (recorded_events > 0),
    PRIMARY KEY (tenant_id, instance_id, boot_epoch)
);
