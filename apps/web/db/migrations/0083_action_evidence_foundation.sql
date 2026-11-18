-- Additive control-plane schema. Apply before gateway readers; never run on prod here.
ALTER TABLE tenants ADD COLUMN action_control boolean NOT NULL DEFAULT false;

CREATE TABLE action_executions (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    execution_id uuid NOT NULL,
    action_id uuid NOT NULL,
    agent_key_id uuid NOT NULL,
    decision_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version > 0),
    policy_hash text NOT NULL CHECK (policy_hash ~ '^[0-9a-f]{64}$'),
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    ledger_seq bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('in_flight','succeeded','failed','unknown')),
    receipt_digest text,
    PRIMARY KEY (tenant_id, execution_id),
    FOREIGN KEY (tenant_id, ledger_seq) REFERENCES audit_log_rows(tenant_id, seq)
);
CREATE UNIQUE INDEX action_executions_action ON action_executions(tenant_id, action_id);
CREATE UNIQUE INDEX action_executions_idempotency ON action_executions(tenant_id, idempotency_key);
CREATE TABLE action_tokenization_secrets (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    encrypted_secret text NOT NULL
);
-- Retained alongside canonical evidence, independent of tenant deletion.
CREATE TABLE audit_head_checkpoints (
    tenant_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    checkpoint_order bigserial NOT NULL,
    statement text NOT NULL,
    signature bytea NOT NULL,
    PRIMARY KEY (tenant_id, checkpoint_id)
);
CREATE INDEX audit_head_checkpoints_order ON audit_head_checkpoints(tenant_id, checkpoint_order);

-- Ordinary batch-signature/anchor backfills remain legal; hashed protected bytes do not.
CREATE FUNCTION protect_action_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE protected_types text[] := ARRAY[
    'action_proposed','decision_made','approval_requested','approval_granted',
    'approval_denied','approval_attempt_rejected','approval_consumed','execution_started',
    'execution_succeeded','execution_failed','execution_unknown','denied_runtime','policy_activated'
];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.event_type = ANY(protected_types) THEN
            RAISE EXCEPTION 'protected action evidence is append only';
        END IF;
        RETURN OLD;
    END IF;
    IF (OLD.event_type = ANY(protected_types) OR NEW.event_type = ANY(protected_types)) AND
       ROW(OLD.tenant_id,OLD.seq,OLD.event_time,OLD.event_type,OLD.actor,OLD.payload,OLD.prev_hash,OLD.row_hash)
       IS DISTINCT FROM
       ROW(NEW.tenant_id,NEW.seq,NEW.event_time,NEW.event_type,NEW.actor,NEW.payload,NEW.prev_hash,NEW.row_hash) THEN
        RAISE EXCEPTION 'protected action evidence is append only';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER action_evidence_immutable BEFORE UPDATE OR DELETE ON audit_log_rows
    FOR EACH ROW EXECUTE FUNCTION protect_action_evidence();
-- Role grants are environment-owned. This trigger is defense in depth, not a claim
-- against a table owner disabling triggers or using TRUNCATE. No guessed GRANT/REVOKE.
