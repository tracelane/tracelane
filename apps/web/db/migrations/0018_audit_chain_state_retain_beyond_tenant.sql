-- Migration 0018: audit_chain_state must OUTLIVE the tenant (ADR-068 erasure).
--
-- The tamper-evident ledger head (`audit_chain_state`) is RETAINED when a tenant
-- is erased (ADR-068 option (c): Art.17(3)(b)/(e) legal-retention). But the
-- `audit_chain_state.tenant_id -> tenants(id)` FK was `ON DELETE CASCADE`, so
-- deleting the `tenants` row during a purge would CASCADE-DELETE the ledger head
-- — silently destroying the record we are legally required to keep. (Caught by
-- the tenant-purge test, not the spec — ACCOUNT_LIFECYCLE §6.)
--
-- Fix: DROP the FK. The ledger is deliberately retained beyond tenant deletion,
-- so a chain-state row referencing an erased tenant is the INTENDED state — a
-- referential constraint (cascade → erases it; no-action → blocks the purge;
-- set-null → breaks tenant scoping) is wrong for a legal-retention record.
-- Chain-state rows are only ever written by the gateway for real tenants, so
-- dropping the constraint does not weaken integrity.
ALTER TABLE audit_chain_state
    DROP CONSTRAINT IF EXISTS audit_chain_state_tenant_id_fkey;
