-- 10: audit_anchor_records — the per-batch offline-verifiable anchor bundle
-- (ADR-062 Amendment 1, public Rekor v2 anchoring).
--
-- Written once per SIGNED batch by the gateway (crates/gateway/src/audit.rs
-- write_anchor_record), anchored or not. Rekor v2 has NO online entry lookup, so
-- the inclusion proof + signed checkpoint captured at anchor time are the ONLY
-- source for the three verifiers' offline verification — the audit export
-- streams these rows alongside audit_log rows.
--
-- The gateway writing these rows MUST run only AFTER this migration lands.
-- Additive + idempotent. tenant_id-first ORDER BY per the CLAUDE.md SQL rule.
CREATE TABLE IF NOT EXISTS tracelane.audit_anchor_records
(
    tenant_id           String,
    batch_start_seq     UInt64,
    batch_end_seq       UInt64,
    merkle_root         String,               -- hex of the RFC6962 batch root
    anchor_state        String,               -- 'anchored' | 'unanchored'
    -- ADR-062: Ed25519 sig over LOCAL_ATTEST_MSG (domain ‖ root ‖ commitment).
    ed25519_sig         String DEFAULT '',    -- base64
    ed25519_pubkey      String DEFAULT '',    -- base64 raw 32B (reference; verifier uses the trusted key)
    ecdsa_pubkey_spki   String DEFAULT '',    -- base64 DER SPKI (anchored only)
    rekor_log_url       String DEFAULT '',
    rekor_log_index     String DEFAULT '',
    canonicalized_body  String DEFAULT '',    -- base64 hashedrekord body (anchored only)
    inclusion_proof     String DEFAULT '',    -- JSON {log_index,tree_size,hashes[]} (anchored only)
    checkpoint_envelope String DEFAULT '',    -- C2SP signed-note checkpoint (anchored only)
    anchored_at         DateTime64(6, 'UTC')
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(anchored_at)
ORDER BY (tenant_id, batch_start_seq)
SETTINGS index_granularity = 8192;
