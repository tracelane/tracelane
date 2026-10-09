-- B-459 (2026-09-30): the tombstone of every purged tenant. `scripts/ops/tenant-purge.sh`
-- writes the id BEFORE it deletes the `tenants` row; the gateway's retention sweep deletes
-- ClickHouse rows `WHERE tenant_id IN <these ids>` (crates/gateway/src/retention_sweep.rs).
-- It replaces "every tenant missing from `tenants`" (NOT IN the live list), which the B-459
-- security review showed deletes a LIVE tenant's data whenever the list is incomplete — a
-- tenant created mid-sweep, or a control plane restored to an earlier point in time.
-- No FK to `tenants` (the row it names is deleted by design). Holds an id and a time, no PII.
-- Apply BEFORE the gateway that reads it (S2); a missing table = the orphan step deletes
-- nothing (fail-safe). Un-journaled like every migration from 0009.
CREATE TABLE IF NOT EXISTS purged_tenants (
  tenant_id  uuid        PRIMARY KEY,
  purged_at  timestamptz NOT NULL DEFAULT now(),
  purged_by  text        NOT NULL DEFAULT ''
);
COMMENT ON TABLE purged_tenants IS
  'B-459: tombstones of purged tenants. Written by scripts/ops/tenant-purge.sh before the tenants row is deleted; read by the gateway retention sweep, which deletes ClickHouse rows of exactly these ids.';
