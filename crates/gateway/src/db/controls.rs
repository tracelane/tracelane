//! `workspace_controls` — OG-25 (`specs/OG-25-emergency-controls.md`), migration 0060.
//!
//! One row per tenant (absent = nothing set): the workspace layer of the `OG-21`/`OG-22`
//! policy, the pause, and the block lists. The hot path never queries this module per
//! request: `entitlement_cache::attach_workspace_controls` reads it with [`read_with`] on
//! the resolve's own connection, and the write routes (`crate::control_routes`)
//! invalidate the tenant's cache entry after every commit.
//!
//! Every write records ONE control change through [`record_control_change`] in the same
//! transaction (fail-CLOSED: an unrecorded control change is rolled back).
//!
//! Tenant isolation: every statement filters `tenant_id = $1`, the validated claim's
//! tenant UUID — never a path or body field.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::db::DbPool as Pool;

/// The columns the entitlement resolve reads — named by the boot schema check
/// (`entitlement_cache::selected_columns`), so a gateway never boots against a Neon
/// without migration 0060.
pub const CONTROLS_SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("workspace_controls", "tenant_id"),
    ("workspace_controls", "policy"),
    ("workspace_controls", "paused_at"),
    ("workspace_controls", "paused_by"),
    ("workspace_controls", "pause_reason"),
    ("workspace_controls", "blocked_models"),
    ("workspace_controls", "blocked_providers"),
    ("workspace_controls", "blocked_end_users"),
];

const SELECT: &str = "SELECT policy, paused_at, paused_by, pause_reason, blocked_models, \
     blocked_providers, blocked_end_users, updated_at FROM workspace_controls WHERE tenant_id = $1";
const SELECT_FOR_UPDATE: &str = "SELECT policy, paused_at, paused_by, pause_reason, \
     blocked_models, blocked_providers, blocked_end_users, updated_at FROM workspace_controls \
     WHERE tenant_id = $1 FOR UPDATE";

/// One tenant's row (or the empty default).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ControlsRow {
    pub policy: Option<Value>,
    pub paused_at: Option<DateTime<Utc>>,
    pub paused_by: Option<String>,
    pub pause_reason: Option<String>,
    pub blocked_models: Vec<String>,
    pub blocked_providers: Vec<String>,
    pub blocked_end_users: Vec<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl ControlsRow {
    fn from_row(r: &tokio_postgres::Row) -> Self {
        Self {
            policy: r.get(0),
            paused_at: r.get(1),
            paused_by: r.get(2),
            pause_reason: r.get(3),
            blocked_models: r.get(4),
            blocked_providers: r.get(5),
            blocked_end_users: r.get(6),
            updated_at: r.get(7),
        }
    }

    /// The JSON the read route and the audit trail show.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "paused": self.paused_at.is_some(),
            "pausedAt": self.paused_at.map(|t| t.to_rfc3339()),
            "pausedBy": self.paused_by,
            "pauseReason": self.pause_reason,
            "blocks": {
                "models": self.blocked_models,
                "providers": self.blocked_providers,
                "endUsers": self.blocked_end_users,
            },
            "policy": self.policy,
            "updatedAt": self.updated_at.map(|t| t.to_rfc3339()),
        })
    }
}

/// Read on an already-held connection (the entitlement resolve's). `Ok(None)` = no row.
///
/// # Errors
/// The SELECT failed — the caller fails the whole resolve, so the cache keeps the
/// last-known controls (never "no controls" because a read failed).
pub async fn read_with(
    client: &tokio_postgres::Client,
    tenant: &Uuid,
) -> Result<Option<ControlsRow>> {
    let row = client
        .query_opt(SELECT, &[tenant])
        .await
        .context("SELECT workspace_controls failed")?;
    Ok(row.as_ref().map(ControlsRow::from_row))
}

/// Read through the pool (the read route).
///
/// # Errors
/// Pool or SELECT failure.
pub async fn get(pool: &Pool, tenant: &TenantId) -> Result<ControlsRow> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    Ok(read_with(&client, tenant.as_uuid())
        .await?
        .unwrap_or_default())
}

/// One control action, for the audit trail.
#[derive(Debug, Clone)]
pub struct ControlChange<'a> {
    pub tenant: Uuid,
    pub actor: &'a str,
    /// `workspace.pause`, `workspace.resume`, `workspace.blocks.update`,
    /// `workspace.policy.update`, `api_key.revoke_all`, `spend_alert_channel.create` /
    /// `.delete`.
    pub action: &'static str,
    pub target_type: &'static str,
    pub target_id: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
}

/// **`OG-35` HOOK — the ONE place an OG-25 / OG-24 control change is recorded.** It now
/// delegates to the OG-35 writer, `db::control_audit::record` (one control-change log,
/// not two): the same `admin_audit_log` row, in the caller's transaction, with the
/// request actor the route scoped after `control_plane::require_control` (request id,
/// role, auth method, proven address) and OG-35's redaction. Without a scope (a test or
/// a maintenance path) the row is still written, as a system actor of `change.actor`.
///
/// # Errors
/// The insert failed — the caller's transaction rolls back (fail-CLOSED: a control change
/// is never made unrecorded).
pub async fn record_control_change(
    tx: &tokio_postgres::Transaction<'_>,
    change: &ControlChange<'_>,
) -> Result<()> {
    let actor = crate::db::control_audit::current()
        .unwrap_or_else(|| crate::db::control_audit::Actor::system(change.actor));
    crate::db::control_audit::record(
        tx,
        &TenantId::from_jwt_claim(change.tenant),
        &actor,
        crate::db::control_audit::Change {
            action: change.action,
            target_type: change.target_type,
            target_id: change.target_id.clone(),
            before: change.before.clone(),
            after: change.after.clone(),
        },
    )
    .await
    .context("admin_audit_log control-change insert failed")?;
    Ok(())
}

/// What a control write changes.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    /// Replace the workspace policy (`None` clears it). Canonical, already validated.
    Policy(Option<Value>),
    /// Pause, with an optional reason. Idempotent: an already-paused workspace keeps its
    /// original `paused_at`.
    Pause {
        reason: Option<String>,
    },
    Resume,
    /// Replace each given list; `None` leaves a list unchanged.
    Blocks {
        models: Option<Vec<String>>,
        providers: Option<Vec<String>>,
        end_users: Option<Vec<String>>,
    },
}

impl Change {
    fn action(&self) -> &'static str {
        match self {
            Self::Policy(_) => "workspace.policy.update",
            Self::Pause { .. } => "workspace.pause",
            Self::Resume => "workspace.resume",
            Self::Blocks { .. } => "workspace.blocks.update",
        }
    }
}

/// Apply one control change: upsert the row, `SELECT … FOR UPDATE`, update, record the
/// change, commit. Returns the row after.
///
/// # Errors
/// Fail-CLOSED: any failure (including the audit insert) rolls the change back.
#[tracing::instrument(skip(pool, change, actor), fields(tenant_id = %tenant))]
pub async fn apply(
    pool: &Pool,
    tenant: &TenantId,
    change: &Change,
    actor: &str,
) -> Result<ControlsRow> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let t = tenant.as_uuid();
    tx.execute(
        "INSERT INTO workspace_controls (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING",
        &[t],
    )
    .await
    .context("INSERT workspace_controls failed")?;
    let before = tx
        .query_one(SELECT_FOR_UPDATE, &[t])
        .await
        .context("SELECT workspace_controls FOR UPDATE failed")?;
    let before = ControlsRow::from_row(&before);
    match change {
        Change::Policy(p) => {
            tx.execute(
                "UPDATE workspace_controls SET policy = $2, updated_at = now(), updated_by = $3 \
                 WHERE tenant_id = $1",
                &[t, p, &actor],
            )
            .await
            .context("UPDATE workspace_controls policy failed")?;
        }
        Change::Pause { reason } => {
            tx.execute(
                "UPDATE workspace_controls SET paused_at = COALESCE(paused_at, now()), \
                 paused_by = COALESCE(paused_by, $2), \
                 pause_reason = CASE WHEN paused_at IS NULL THEN $3 ELSE pause_reason END, \
                 updated_at = now(), updated_by = $2 WHERE tenant_id = $1",
                &[t, &actor, reason],
            )
            .await
            .context("UPDATE workspace_controls pause failed")?;
        }
        Change::Resume => {
            tx.execute(
                "UPDATE workspace_controls SET paused_at = NULL, paused_by = NULL, \
                 pause_reason = NULL, updated_at = now(), updated_by = $2 WHERE tenant_id = $1",
                &[t, &actor],
            )
            .await
            .context("UPDATE workspace_controls resume failed")?;
        }
        Change::Blocks {
            models,
            providers,
            end_users,
        } => {
            tx.execute(
                "UPDATE workspace_controls SET \
                 blocked_models = COALESCE($2, blocked_models), \
                 blocked_providers = COALESCE($3, blocked_providers), \
                 blocked_end_users = COALESCE($4, blocked_end_users), \
                 updated_at = now(), updated_by = $5 WHERE tenant_id = $1",
                &[t, models, providers, end_users, &actor],
            )
            .await
            .context("UPDATE workspace_controls blocks failed")?;
        }
    }
    let after = ControlsRow::from_row(
        &tx.query_one(SELECT, &[t])
            .await
            .context("SELECT workspace_controls after failed")?,
    );
    record_control_change(
        &tx,
        &ControlChange {
            tenant: *t,
            actor,
            action: change.action(),
            target_type: "workspace",
            target_id: t.to_string(),
            before: Some(before.to_json()),
            after: Some(after.to_json()),
        },
    )
    .await?;
    tx.commit()
        .await
        .context("workspace_controls commit failed")?;
    Ok(after)
}
