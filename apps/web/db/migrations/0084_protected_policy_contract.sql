-- Additive only; apply before protected readers. No approval flow in this migration.
-- Never queue behind long transactions on the hot ledger table.
SET lock_timeout = '5s';
CREATE TABLE action_tool_contracts (
 tenant_id uuid NOT NULL REFERENCES tenants(id), tool_ref uuid NOT NULL,
 version integer NOT NULL CHECK (version > 0), server_id uuid NOT NULL,
 tool_name text NOT NULL, protected boolean NOT NULL,
 body_jcs text NOT NULL, contract_hash text NOT NULL CHECK (contract_hash ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY (tenant_id, tool_ref, version),
 FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers(tenant_id, id),
 UNIQUE (tenant_id, server_id, tool_name, version)
);
CREATE TABLE action_policies (
 tenant_id uuid NOT NULL REFERENCES tenants(id), policy_id uuid NOT NULL,
 version integer NOT NULL CHECK (version > 0), tool_ref uuid NOT NULL,
 contract_version integer NOT NULL, body_jcs text NOT NULL,
 policy_hash text NOT NULL CHECK (policy_hash ~ '^[0-9a-f]{64}$'),
 publisher_sub text NOT NULL,
 PRIMARY KEY (tenant_id, policy_id, version),
 UNIQUE (tenant_id, tool_ref, version),
 UNIQUE (tenant_id, tool_ref, policy_id, version),
 FOREIGN KEY (tenant_id, tool_ref, contract_version) REFERENCES action_tool_contracts(tenant_id, tool_ref, version)
);
CREATE TABLE action_policy_active (
 tenant_id uuid NOT NULL, tool_ref uuid NOT NULL, policy_id uuid NOT NULL, version integer NOT NULL,
 PRIMARY KEY (tenant_id, tool_ref),
 FOREIGN KEY (tenant_id, tool_ref, policy_id, version) REFERENCES action_policies(tenant_id, tool_ref, policy_id, version)
);
CREATE FUNCTION protect_action_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'protected policy artifacts are immutable'; END;
$$;
CREATE TRIGGER action_contract_immutable BEFORE UPDATE OR DELETE ON action_tool_contracts
 FOR EACH ROW EXECUTE FUNCTION protect_action_policy();
CREATE TRIGGER action_policy_immutable BEFORE UPDATE OR DELETE ON action_policies
 FOR EACH ROW EXECUTE FUNCTION protect_action_policy();
CREATE FUNCTION advance_action_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.tenant_id <> OLD.tenant_id OR NEW.tool_ref <> OLD.tool_ref THEN
  RAISE EXCEPTION 'active policy identity is immutable';
 END IF;
 IF NEW.version <= OLD.version THEN RAISE EXCEPTION 'policy version must increase'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER action_policy_monotonic BEFORE UPDATE ON action_policy_active
 FOR EACH ROW EXECUTE FUNCTION advance_action_policy();
-- DELETE then a lower-version INSERT would bypass the UPDATE trigger.
CREATE TRIGGER action_policy_active_immutable BEFORE DELETE ON action_policy_active
 FOR EACH ROW EXECUTE FUNCTION protect_action_policy();
-- NULL bindings are legacy only, never a protected grant. C1-4 owns lifecycle checks.
ALTER TABLE approvals
 ADD COLUMN action_id uuid,
 ADD COLUMN decision_id uuid,
 ADD COLUMN request_digest text CHECK (request_digest ~ '^[0-9a-f]{64}$'),
 ADD COLUMN policy_id uuid,
 ADD COLUMN policy_version integer,
 ADD COLUMN policy_hash text CHECK (policy_hash ~ '^[0-9a-f]{64}$'),
 ADD COLUMN tool_ref uuid,
 ADD COLUMN contract_version integer,
 ADD COLUMN proposer_key_id uuid,
 ADD COLUMN policy_publisher_sub text,
 ADD COLUMN qualified_human_sub text,
 ADD COLUMN requested_ledger_seq bigint,
 ADD COLUMN decided_ledger_seq bigint,
 ADD COLUMN consumed_ledger_seq bigint,
 ADD FOREIGN KEY (tenant_id, policy_id, policy_version) REFERENCES action_policies(tenant_id, policy_id, version),
 ADD FOREIGN KEY (tenant_id, tool_ref, contract_version) REFERENCES action_tool_contracts(tenant_id, tool_ref, version),
 ADD CONSTRAINT approvals_requested_ledger_fk FOREIGN KEY (tenant_id, requested_ledger_seq) REFERENCES audit_log_rows(tenant_id, seq) NOT VALID,
 ADD CONSTRAINT approvals_decided_ledger_fk FOREIGN KEY (tenant_id, decided_ledger_seq) REFERENCES audit_log_rows(tenant_id, seq) NOT VALID,
 ADD CONSTRAINT approvals_consumed_ledger_fk FOREIGN KEY (tenant_id, consumed_ledger_seq) REFERENCES audit_log_rows(tenant_id, seq) NOT VALID;
-- New columns are all NULL, so validation scans nothing and takes only SHARE UPDATE EXCLUSIVE.
ALTER TABLE approvals VALIDATE CONSTRAINT approvals_requested_ledger_fk;
ALTER TABLE approvals VALIDATE CONSTRAINT approvals_decided_ledger_fk;
ALTER TABLE approvals VALIDATE CONSTRAINT approvals_consumed_ledger_fk;
