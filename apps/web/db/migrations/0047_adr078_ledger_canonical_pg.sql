-- 0047 — ADR-078 (ruled B, 2026-09-20): the tamper-evident ledger becomes CANONICAL in
-- Postgres. Chain rows and per-batch anchor bundles are written in the SAME transaction
-- that advances `audit_chain_state`, so a restore can never leave the head ahead of the
-- rows (the defect ADR-078 closes). ClickHouse `tracelane.audit_log` /
-- `audit_anchor_records` become a derived copy, backfilled after commit.
--
-- Column-for-column mirrors of the ClickHouse tables so `seq`, `prev_hash` and `row_hash`
-- are byte-identical in both stores (ADR-072: a MIGRATION, not a re-chain). `payload` is
-- text, not jsonb — the row hash covers the payload bytes and jsonb would re-serialise them.
-- No FK to `tenants`: the ledger is retained through a purge (ADR-068 option (c)), like
-- `audit_chain_state`.
--
-- S2 ordering (CLAUDE.md §5): this lands on Neon, then the one-time ClickHouse → Postgres
-- backfill runs (`scripts/ops/ledger-backfill-pg.sh`), THEN the gateway that writes here
-- deploys. Idempotent (IF NOT EXISTS), applied to prod by hand like every 0009+ migration.

CREATE TABLE IF NOT EXISTS audit_log_rows (
  tenant_id       uuid          NOT NULL,
  seq             bigint        NOT NULL,
  event_time      timestamptz(6) NOT NULL,
  event_type      text          NOT NULL,
  actor           text          NOT NULL,
  payload         text          NOT NULL DEFAULT '{}',
  prev_hash       text          NOT NULL DEFAULT '',
  row_hash        text          NOT NULL,
  rekor_entry_id  text,
  signature       text          NOT NULL DEFAULT '',
  signing_pubkey  text          NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, seq)
);
COMMENT ON TABLE audit_log_rows IS
  'ADR-078: the canonical tamper-evident ledger rows (hash chain per tenant). Written in the head-advance transaction; ClickHouse tracelane.audit_log is a derived copy. Retained through tenant purge (ADR-068 c).';

CREATE TABLE IF NOT EXISTS audit_anchor_records (
  tenant_id            uuid          NOT NULL,
  batch_start_seq      bigint        NOT NULL,
  batch_end_seq        bigint        NOT NULL,
  merkle_root          text          NOT NULL,
  anchor_state         text          NOT NULL,
  ed25519_sig          text          NOT NULL DEFAULT '',
  ed25519_pubkey       text          NOT NULL DEFAULT '',
  ecdsa_pubkey_spki    text          NOT NULL DEFAULT '',
  rekor_log_url        text          NOT NULL DEFAULT '',
  rekor_log_index      text          NOT NULL DEFAULT '',
  canonicalized_body   text          NOT NULL DEFAULT '',
  inclusion_proof      text          NOT NULL DEFAULT '',
  checkpoint_envelope  text          NOT NULL DEFAULT '',
  anchored_at          timestamptz(6) NOT NULL,
  PRIMARY KEY (tenant_id, batch_start_seq)
);
COMMENT ON TABLE audit_anchor_records IS
  'ADR-078: the canonical per-batch anchor bundles (Ed25519 attestation + Rekor v2 inclusion proof — the ONLY offline-verification source). ClickHouse tracelane.audit_anchor_records is a derived copy.';
