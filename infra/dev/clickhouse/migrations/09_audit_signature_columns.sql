-- 09: audit_log Ed25519 signature columns (ADR-057 — zero-third-party signing).
--
-- Additive + idempotent. Existing rows default to '' (unsigned). The gateway
-- writing the new AuditLogRow fields (signature / signing_pubkey) MUST run only
-- AFTER this migration lands, or the INSERT column set won't match the table.
--
-- These are backfilled per anchor batch by the gateway (crates/gateway/src/audit.rs
-- backfill_signature), independent of any external Rekor anchor: the SHA-256 chain
-- (integrity) + Ed25519 signature over the batch Merkle root (authenticity) are the
-- tamper-evidence, with no third-party dependency.
ALTER TABLE tracelane.audit_log
    ADD COLUMN IF NOT EXISTS signature String DEFAULT '';
ALTER TABLE tracelane.audit_log
    ADD COLUMN IF NOT EXISTS signing_pubkey String DEFAULT '';
