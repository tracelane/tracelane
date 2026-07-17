//! `tenants` table queries — CRUD + Polar correlation.
//!
//! Every query uses parameter binding. The tenant id is always treated as
//! authoritative; callers pass a verified `TenantId` (from JWT claim or
//! API-key lookup) and we trust it.
//!
//! Schema source of truth is the Drizzle/Neon shape (ADR-040): the PK column
//! is `id`, plan is the `plan` enum (read as text via `plan::text`). `name`
//! is dropped (WorkOS owns org names; the gateway works in tenant ids) and
//! `stripe_subscription_id` is dropped (Stripe is gone). `archived_at` is the
//! tenant kill-switch (soft-delete): every read filters `archived_at IS NULL`.

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use tracelane_shared::TenantId;

/// One row in `tenants`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Internal tenant UUID — the `id` PK column.
    pub tenant_id: Uuid,
    /// Plan tier (the `plan` enum, read as text): free | builder | team |
    /// business | enterprise. Polar product metadata `lookup_key` maps to it.
    pub plan_tier: String,
    /// Polar customer ID. Set after the first Polar customer-created event.
    pub polar_customer_id: Option<String>,
    /// Polar subscription ID. Most recent subscription event for this tenant.
    pub polar_subscription_id: Option<String>,
    /// Legacy Stripe customer id — kept for db rollback; no new code path.
    pub stripe_customer_id: Option<String>,
    pub workos_org_id: Option<String>,
    /// Legacy add-on column; drives the `audit_ledger` entitlement.
    pub audit_enabled: bool,
    /// Per-tenant Slack webhook for hard-cap 429 alerts (Migration 09).
    pub slack_webhook_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Soft-delete / kill-switch. Non-NULL = service cut, data retained.
    pub archived_at: Option<DateTime<Utc>>,
}

/// Columns selected by `get` / `get_by_polar_customer`, in `row_to_tenant`
/// order. `plan` is cast to text so tokio-postgres reads it as `String`
/// without an enum type mapping.
const TENANT_COLUMNS: &str = "id, plan::text AS plan, polar_customer_id, polar_subscription_id, \
                              stripe_customer_id, workos_org_id, audit_enabled, \
                              slack_webhook_url, created_at, updated_at, archived_at";

/// SQL cast fragment for binding a Rust string to the `plan` **enum** column.
///
/// tokio-postgres's `ToSql for &str` / `String` does NOT accept custom enum
/// types, so a parameter whose Postgres-inferred type is the `plan` enum — as a
/// bare `$N::plan` makes it — fails at BIND time, before the query runs:
///   `error serializing parameter N: cannot convert between the Rust type
///    &str and the Postgres type plan`
/// (Proven live against the prod pooler; it never surfaced in CI because the
/// webhook tests inject mock lookup/provision closures, so this SQL never ran
/// against a real `plan` enum — a green-while-broken path.)
///
/// The fix: bind the value as `text` (which `&str` serializes) and let the DB
/// coerce text -> enum. The wire param type is then `text`, not `plan`. NEVER
/// write a bare `$N::plan` for a string parameter — pinned by
/// `tests::plan_enum_cast_routes_through_text`.
const PLAN_ENUM_CAST: &str = "::text::plan";

fn row_to_tenant(r: &tokio_postgres::Row) -> Tenant {
    Tenant {
        tenant_id: r.get(0),
        plan_tier: r.get(1),
        polar_customer_id: r.get(2),
        polar_subscription_id: r.get(3),
        stripe_customer_id: r.get(4),
        workos_org_id: r.get(5),
        audit_enabled: r.get(6),
        slack_webhook_url: r.get(7),
        created_at: r.get(8),
        updated_at: r.get(9),
        archived_at: r.get(10),
    }
}

/// Insert a new tenant. `workos_org_id` is required (NOT NULL); `plan` is the
/// plan enum value as a string (e.g. "free").
pub async fn create(
    pool: &Pool,
    tenant_id: Uuid,
    workos_org_id: &str,
    plan: &str,
) -> Result<Tenant> {
    let client = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    let sql = format!(
        "INSERT INTO tenants (id, workos_org_id, plan) \
         VALUES ($1, $2, $3{PLAN_ENUM_CAST}) RETURNING {TENANT_COLUMNS}"
    );
    let row = client
        .query_one(&sql, &[&tenant_id, &workos_org_id, &plan])
        .await
        .context("INSERT INTO tenants failed")?;
    Ok(row_to_tenant(&row))
}

///
/// If an ACTIVE tenant already carries this `workos_org_id`, that EXISTING row
/// is returned untouched (its id, plan, and billing state win —
/// dashboard-onboarded tenants have random UUIDs the caller must never guess).
/// Otherwise a new tenant is inserted with a **random** UUID — never a UUID
/// `tenants` row).
///
/// Returns `Ok(None)` when the org's tenant exists but is ARCHIVED
/// (kill-switched): the guarded `DO UPDATE ... WHERE archived_at IS NULL`
/// yields no row, so a kill-switched org can neither be resurrected nor
/// review F-2). Callers must treat `None` as "refuse + ack".
///
/// # Errors
/// Pool/query errors surface as `Err` (the webhook turns that into a 503 so
/// WorkOS redelivers — at-least-once provisioning).
pub async fn create_or_get_by_workos_org(
    pool: &Pool,
    workos_org_id: &str,
    plan: &str,
) -> Result<Option<Tenant>> {
    let client = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    // ON CONFLICT DO UPDATE (not DO NOTHING) so RETURNING yields the existing
    // row; the update arm only touches updated_at, never plan/billing state,
    // and is guarded on archived_at IS NULL — an archived tenant produces a
    // zero-row upsert (query_opt → None) instead of coming back to life.
    let sql = format!(
        "INSERT INTO tenants (id, workos_org_id, plan) \
         VALUES ($1, $2, $3{PLAN_ENUM_CAST}) \
         ON CONFLICT (workos_org_id) DO UPDATE SET updated_at = now() \
             WHERE tenants.archived_at IS NULL \
         RETURNING {TENANT_COLUMNS}"
    );
    let new_id = Uuid::new_v4();
    let row = client
        .query_opt(&sql, &[&new_id, &workos_org_id, &plan])
        .await
        .context("INSERT ... ON CONFLICT (workos_org_id) failed")?;
    Ok(row.as_ref().map(row_to_tenant))
}

/// Fetch a tenant by id.
pub async fn get(pool: &Pool, tenant_id: &TenantId) -> Result<Option<Tenant>> {
    let client = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    let sql = format!("SELECT {TENANT_COLUMNS} FROM tenants WHERE id = $1 AND archived_at IS NULL");
    let row = client
        .query_opt(&sql, &[tenant_id.as_uuid()])
        .await
        .context("SELECT FROM tenants failed")?;
    Ok(row.as_ref().map(row_to_tenant))
}

/// Update the Polar ids after a successful Polar customer + subscription
/// create. Idempotent.
pub async fn set_polar_ids(
    pool: &Pool,
    tenant_id: &TenantId,
    customer_id: &str,
    subscription_id: Option<&str>,
) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    client
        .execute(
            "UPDATE tenants
             SET polar_customer_id = $2, polar_subscription_id = $3, updated_at = now()
             WHERE id = $1",
            &[tenant_id.as_uuid(), &customer_id, &subscription_id],
        )
        .await
        .context("UPDATE tenants set_polar_ids failed")?;
    Ok(())
}

/// Reverse map: `polar_customer_id` -> `Tenant`. Used by the Polar webhook
/// handler to flip plan tier when `subscription.updated` fires.
pub async fn get_by_polar_customer(pool: &Pool, polar_customer_id: &str) -> Result<Option<Tenant>> {
    let client = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    let sql = format!(
        "SELECT {TENANT_COLUMNS} FROM tenants \
         WHERE polar_customer_id = $1 AND archived_at IS NULL"
    );
    let row = client
        .query_opt(&sql, &[&polar_customer_id])
        .await
        .context("SELECT FROM tenants by polar_customer_id failed")?;
    Ok(row.as_ref().map(row_to_tenant))
}

/// Reverse map: WorkOS `org_id` -> internal tenant UUID. The gateway auth
/// bridge (`auth::validate_jwt`) uses this to resolve a WorkOS-issued JWT —
/// which carries the WorkOS `org_id`, not the internal tenant UUID — to the
/// authoritative tenant id (ADR-042 bug #2). This is the source-of-truth
/// mapping; the deterministic `tenant_uuid_from_workos_org` hash is only a
/// dev/no-pool fallback, because dashboard-onboarded tenants may not use it.
///
/// Returns `Ok(None)` when no **active** tenant carries that `workos_org_id`
/// (unknown org, or the tenant has been archived). Indexed by the
/// `tenants.workos_org_id` UNIQUE constraint; the `archived_at IS NULL` filter
/// means an archived tenant stops authenticating.
///
/// # Errors
/// Fail-closed: a pool/query error surfaces as `Err` so the auth path rejects
/// the request rather than resolving the wrong tenant. (Security path — never
/// fail-open here, unlike the entitlement cache.)
pub async fn get_tenant_id_by_workos_org(pool: &Pool, workos_org_id: &str) -> Result<Option<Uuid>> {
    let client = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    let row = client
        .query_opt(
            "SELECT id FROM tenants WHERE workos_org_id = $1 AND archived_at IS NULL",
            &[&workos_org_id],
        )
        .await
        .context("SELECT tenants.id by workos_org_id failed")?;
    Ok(row.map(|r| r.get(0)))
}

/// Update the plan tier. Used by the Polar webhook on subscription change.
pub async fn set_plan_tier(pool: &Pool, tenant_id: &TenantId, plan: &str) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    let sql =
        format!("UPDATE tenants SET plan = $2{PLAN_ENUM_CAST}, updated_at = now() WHERE id = $1");
    client
        .execute(&sql, &[tenant_id.as_uuid(), &plan])
        .await
        .context("UPDATE tenants set_plan_tier failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Static guard: the `plan` enum bind MUST route through text. tokio-postgres
    /// cannot serialize `&str` into a bare enum param (`$N::plan`), so a revert to
    /// bare `::plan` reintroduces the live "cannot convert &str <-> plan" bind
    /// failure that broke WorkOS `organization.created` provisioning. See
    /// [`PLAN_ENUM_CAST`]. All three write statements interpolate the const, so a
    /// bare `$N::plan` can only reappear by editing the const (caught here).
    #[test]
    fn plan_enum_cast_routes_through_text() {
        assert_eq!(PLAN_ENUM_CAST, "::text::plan");
        assert!(
            PLAN_ENUM_CAST.contains("::text::"),
            "plan enum binds must serialize as text, not the bare enum type"
        );
        let upsert = format!("VALUES ($1, $2, $3{PLAN_ENUM_CAST})");
        assert!(upsert.contains("$3::text::plan"), "must be text-routed");
        assert!(
            !upsert.replace("$3::text::plan", "").contains("::plan"),
            "no bare `$N::plan` may remain"
        );
    }

    /// Live contract (read-only) against a real Postgres carrying a `plan` enum:
    /// a bare `$1::plan` param MUST fail `&str`->enum serialization, and the
    /// text-routed `$1::text::plan` MUST round-trip. This is the regression the
    /// pure-unit suite can't express — fabricating an enum `Type` needs the
    /// `#[non_exhaustive]` `Kind::Enum` — so it is gated on a real DB. Read-only
    /// (no table writes). Run:
    ///   POSTGRES_URL="<neon>" cargo test -p gateway --bins \
    ///     db::tenants::tests::enum_param_serialization_contract -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a real Postgres with a `plan` enum; set POSTGRES_URL"]
    async fn enum_param_serialization_contract() {
        let pool = crate::db::build_pool().await.expect("build_pool");
        let client = pool.get().await.expect("client");
        // Bare enum param: Postgres infers $1 as `plan`; tokio-postgres refuses.
        let bare = client.query_one("SELECT $1::plan::text", &[&"free"]).await;
        assert!(
            bare.is_err(),
            "bare $1::plan must fail &str->enum serialization (the shipped bug)"
        );
        // Text-routed: the wire param type is `text`; the DB coerces text -> enum.
        let fixed: String = client
            .query_one("SELECT $1::text::plan::text", &[&"free"])
            .await
            .expect("$1::text::plan must serialize and round-trip")
            .get(0);
        assert_eq!(fixed, "free");
    }
}
