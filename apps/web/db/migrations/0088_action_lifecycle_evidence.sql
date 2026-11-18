-- Preserve append-only protection for the newly emitted action lifecycle events.
SET lock_timeout = '5s';
CREATE OR REPLACE FUNCTION protect_action_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE protected_types text[] := ARRAY[
    'action_proposed','decision_made','approval_requested','approval_granted',
    'approval_denied','approval_attempt_rejected','approval_consumed','execution_started',
    'execution_succeeded','execution_failed','execution_unknown','denied_runtime','policy_activated',
    'approval_expired','approval_invalidated','legacy_forward_attempted'
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
