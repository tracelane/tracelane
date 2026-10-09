//! `OG-36` — a workspace's admin-plane access policy: the admin IP allowlist and
//! SSO-required (`specs/OG-36-admin-ip-allowlist-sso.md`). Table
//! `tenant_admin_security` (migration 0059). Enforced by
//! `control_plane::require_control` on every control route; never on inference.
//!
//! No row = no policy (empty allowlist, SSO not required) — the state of every
//! workspace before OG-36, so the migration changes nothing until an admin opts in.
//!
//! Self-contained (no gateway modules outside `db`) for the same reason as
//! `control_audit`: the real-Postgres test crate mounts `db/mod.rs` by `#[path]`.

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::json;
use tracelane_shared::TenantId;

use super::control_audit::{self, Actor, Change};

/// A workspace's admin-plane access policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdminAccess {
    /// CIDR blocks a control route may be called from. Empty = any address.
    pub admin_ip_allowlist: Vec<String>,
    /// Refuse a WorkOS session that did not authenticate through SSO.
    pub sso_required: bool,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
}

impl AdminAccess {
    /// The audited shape (no timestamps: they are on the row itself).
    #[must_use]
    pub fn audit_json(&self) -> serde_json::Value {
        json!({
            "admin_ip_allowlist": self.admin_ip_allowlist,
            "sso_required": self.sso_required,
        })
    }
}

/// Read a workspace's policy. A missing row is the default (no policy).
///
/// # Errors
/// Pool checkout or query failure. The caller (`require_control`) refuses the
/// control request (fail-CLOSED, 503): an unreadable allowlist must never read as
/// "no allowlist".
pub async fn get(pool: &Pool, tenant: &TenantId) -> Result<AdminAccess> {
    let client = pool.get().await.context("pool checkout")?;
    let row = client
        .query_opt(
            "SELECT admin_ip_allowlist, sso_required, updated_at, updated_by
               FROM tenant_admin_security WHERE tenant_id = $1",
            &[tenant.as_uuid()],
        )
        .await
        .context("tenant_admin_security read failed")?;
    Ok(row.map_or_else(AdminAccess::default, |r| AdminAccess {
        admin_ip_allowlist: r.get(0),
        sso_required: r.get(1),
        updated_at: Some(r.get(2)),
        updated_by: Some(r.get(3)),
    }))
}

/// Replace a workspace's policy and record the change, in ONE transaction.
/// Returns `(before, after)`. The caller has already validated the CIDRs and run
/// the lock-out check; the table's own CHECK refuses an entry that is not a CIDR.
///
/// # Errors
/// Fail-CLOSED: any failure — including the audit insert — rolls the change back.
pub async fn put(
    pool: &Pool,
    tenant: &TenantId,
    allowlist: &[String],
    sso_required: bool,
    actor: &Actor,
) -> Result<(AdminAccess, AdminAccess)> {
    let mut client = pool.get().await.context("pool checkout")?;
    let tx = client.transaction().await?;
    let before = tx
        .query_opt(
            "SELECT admin_ip_allowlist, sso_required, updated_at, updated_by
               FROM tenant_admin_security WHERE tenant_id = $1 FOR UPDATE",
            &[tenant.as_uuid()],
        )
        .await?
        .map_or_else(AdminAccess::default, |r| AdminAccess {
            admin_ip_allowlist: r.get(0),
            sso_required: r.get(1),
            updated_at: Some(r.get(2)),
            updated_by: Some(r.get(3)),
        });
    let allowlist: Vec<String> = allowlist.to_vec();
    let r = tx
        .query_one(
            "INSERT INTO tenant_admin_security
                 (tenant_id, admin_ip_allowlist, sso_required, updated_at, updated_by)
             VALUES ($1, $2, $3, now(), $4)
             ON CONFLICT (tenant_id) DO UPDATE
                SET admin_ip_allowlist = EXCLUDED.admin_ip_allowlist,
                    sso_required = EXCLUDED.sso_required,
                    updated_at = EXCLUDED.updated_at,
                    updated_by = EXCLUDED.updated_by
             RETURNING admin_ip_allowlist, sso_required, updated_at, updated_by",
            &[tenant.as_uuid(), &allowlist, &sso_required, &actor.sub],
        )
        .await
        .context("tenant_admin_security upsert failed")?;
    let after = AdminAccess {
        admin_ip_allowlist: r.get(0),
        sso_required: r.get(1),
        updated_at: Some(r.get(2)),
        updated_by: Some(r.get(3)),
    };
    control_audit::record(
        &tx,
        tenant,
        actor,
        Change {
            action: "security.admin_access.set",
            target_type: "workspace",
            target_id: tenant.to_string(),
            before: Some(before.audit_json()),
            after: Some(after.audit_json()),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((before, after))
}
