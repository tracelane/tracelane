-- 0059 — OG-36: a workspace's admin-plane access policy — the admin IP allowlist and
-- SSO-required (`specs/OG-36-admin-ip-allowlist-sso.md`).
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` applies
-- only 0000–0008, so this is applied to Neon BY HAND.
--
-- **SERIALIZATION POINT S2.** The gateway that ships OG-36 READS this table on every
-- control route (`crates/gateway/src/db/admin_security.rs` `get`, called by
-- `control_plane::require_control`) and refuses the request when the read fails
-- (fail-CLOSED — an unreadable allowlist must never read as "no allowlist"). Deployed
-- before this file, every control route would answer 503. Order: 0058, THIS file,
-- then the gateway, then apps/web. Safe under the current binaries: nothing deployed
-- reads it.
--
-- NO ROW = NO POLICY (empty allowlist, SSO not required): exactly today's behaviour
-- for every workspace, so applying this changes nothing until an admin opts in.
--
-- `admin_ip_allowlist` is `text[]`, validated as CIDRs by a CHECK that casts it to
-- `cidr[]` (a non-CIDR or a host-bits-set entry fails the cast, so the write is
-- refused) — the gateway validates first and this is the backstop. `text[]` because
-- tokio-postgres has no `cidr` mapping without a feature this repo does not enable.
-- The cardinality bound is a hard ceiling; the product cap is the reference table
-- (`crates/gateway/control_policy.v1.json` `max_ip_allowlist_entries`).
--
-- Purge: the row cascades with `tenants` (FK ON DELETE CASCADE) and is listed in
-- `scripts/ops/tenant-purge.sh` PG_PURGE.
--
-- Idempotent (IF NOT EXISTS). REVERSIBLE before the gateway deploys:
-- DROP TABLE tenant_admin_security.

CREATE TABLE IF NOT EXISTS tenant_admin_security (
    tenant_id          uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    admin_ip_allowlist text[]      NOT NULL DEFAULT '{}',
    sso_required       boolean     NOT NULL DEFAULT false,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         text        NOT NULL DEFAULT '',
    CONSTRAINT tenant_admin_security_cidrs_chk
        CHECK ((admin_ip_allowlist::cidr[]) IS NOT NULL),
    CONSTRAINT tenant_admin_security_cidrs_max_chk
        CHECK (cardinality(admin_ip_allowlist) <= 256)
);

COMMENT ON TABLE tenant_admin_security IS
    'OG-36: per-workspace admin-plane access policy. Read by the gateway on every control route (require_control), never on inference. No row = no policy. Changed only through PUT /v1/security/admin-access (audited in admin_audit_log) or the operator break-glass script.';
COMMENT ON COLUMN tenant_admin_security.admin_ip_allowlist IS
    'CIDR blocks a control route may be called from; empty = any address. The client address is the gateway''s trusted-proxy derivation (B-594) or the dashboard''s signed attestation.';
COMMENT ON COLUMN tenant_admin_security.sso_required IS
    'Refuse a WorkOS session whose authentication method (WorkOS sessions API, by the JWT sid) is not sso, on every control route.';
