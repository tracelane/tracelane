//! `projects` — OG-23 (`specs/OG-23-projects-environments.md`), migration 0056.
//!
//! A project is a tenant's named group of API keys, with the environment labels its keys
//! may carry and (OG-20, migration 0057) a policy every key in it is governed by in
//! addition to its own. The hot path never reads this module: the auth SELECT joins the
//! table (`api_keys::AUTH_PROJECT_JOIN`) and the result rides the auth cache.
//!
//! Writes come only from the owner-gated `/v1/projects` routes (`crate::project_routes`),
//! which validate the name, the environments and the policy BEFORE anything is stored.
//! A project is ARCHIVED, never deleted: a key in an archived project stays governed by
//! it, so an archive can never loosen a key (`api_keys.project_id` is `ON DELETE
//! RESTRICT` as a backstop).
//!
//! Tenant isolation: every statement filters `tenant_id = $1` from the validated claim's
//! tenant UUID, never a path or body field. Another tenant's id answers exactly as an
//! absent one (no existence oracle).

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::db::DbPool as Pool;

/// One project as the API returns it.
#[derive(Debug, Clone, PartialEq)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub environments: Vec<String>,
    pub policy: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A validated create (the route checked the name, the environments and the policy).
#[derive(Debug, Clone)]
pub struct NewProject {
    pub name: String,
    pub environments: Vec<String>,
    /// Canonical (`KeyPolicy::to_value`), or `None`.
    pub policy: Option<serde_json::Value>,
}

/// A validated RFC 7396 patch. Outer `None` = unchanged; `policy: Some(None)` clears.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProjectPatch {
    pub name: Option<String>,
    pub environments: Option<Vec<String>>,
    pub policy: Option<Option<serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateOutcome {
    Created(Project),
    /// A live project of this tenant already has this name (case-insensitive).
    NameTaken,
    /// The tenant holds `max` live projects already.
    LimitReached {
        max: usize,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum PatchOutcome {
    Updated {
        project: Box<Project>,
        changed: Vec<&'static str>,
    },
    NotFound,
    NameTaken,
    /// The patch removes an environment a live key of the project still carries.
    EnvironmentInUse {
        environment: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveOutcome {
    Archived,
    NotFound,
    /// Live (unrevoked, or retiring) keys are still assigned.
    HasKeys {
        count: i64,
    },
}

const COLUMNS: &str = "id, name, environments, policy, created_at, updated_at";

fn from_row(row: &tokio_postgres::Row) -> Project {
    Project {
        id: row.get(0),
        name: row.get(1),
        environments: row.get(2),
        policy: row.get(3),
        created_at: row.get(4),
        updated_at: row.get(5),
    }
}

/// A unique violation on the live-name index.
fn is_name_taken(e: &tokio_postgres::Error) -> bool {
    e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
}

/// The tenant's LIVE projects, oldest first.
///
/// # Errors
/// A database failure (fail-CLOSED: the route answers 5xx, never a guessed list).
#[tracing::instrument(skip(pool, tenant), fields(tenant_id = %tenant))]
pub async fn list(pool: &Pool, tenant: &TenantId) -> Result<Vec<Project>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            &format!(
                "SELECT {COLUMNS} FROM projects \
                 WHERE tenant_id = $1 AND archived_at IS NULL ORDER BY created_at, id"
            ),
            &[tenant.as_uuid()],
        )
        .await
        .context("SELECT projects failed")?;
    Ok(rows.iter().map(from_row).collect())
}

/// One LIVE project of `tenant` and the ids of its live keys (unrevoked or retiring).
///
/// # Errors
/// A database failure.
#[tracing::instrument(skip(pool, tenant), fields(tenant_id = %tenant))]
pub async fn get(pool: &Pool, tenant: &TenantId, id: Uuid) -> Result<Option<(Project, Vec<Uuid>)>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let Some(row) = client
        .query_opt(
            &format!(
                "SELECT {COLUMNS} FROM projects \
                 WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL"
            ),
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("SELECT projects by id failed")?
    else {
        return Ok(None);
    };
    let keys = client
        .query(
            "SELECT id FROM api_keys \
             WHERE tenant_id = $1 AND project_id = $2 \
               AND (revoked_at IS NULL OR revoked_at > clock_timestamp()) \
             ORDER BY created_at, id",
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("SELECT api_keys by project failed")?
        .iter()
        .map(|r| r.get(0))
        .collect();
    Ok(Some((from_row(&row), keys)))
}

/// Create a project. Serialized per tenant (the tenant row is locked) so two concurrent
/// creates cannot both pass the live-project cap. Writes `admin_audit_log`
/// `project.create` in the same transaction.
///
/// # Errors
/// A database failure — fail-CLOSED, the transaction rolls back.
#[tracing::instrument(skip(pool, tenant, new, actor), fields(tenant_id = %tenant))]
pub async fn create(
    pool: &Pool,
    tenant: &TenantId,
    new: &NewProject,
    max_projects: usize,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
) -> Result<CreateOutcome> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    tx.query_opt(
        "SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE",
        &[tenant.as_uuid()],
    )
    .await
    .context("lock tenant (project create) failed")?;
    let live: i64 = tx
        .query_one(
            "SELECT count(*) FROM projects WHERE tenant_id = $1 AND archived_at IS NULL",
            &[tenant.as_uuid()],
        )
        .await
        .context("count projects failed")?
        .get(0);
    if usize::try_from(live).unwrap_or(usize::MAX) >= max_projects {
        return Ok(CreateOutcome::LimitReached { max: max_projects });
    }
    let row = match tx
        .query_one(
            &format!(
                "INSERT INTO projects (tenant_id, name, environments, policy) \
                 VALUES ($1, $2, $3, $4) RETURNING {COLUMNS}"
            ),
            &[tenant.as_uuid(), &new.name, &new.environments, &new.policy],
        )
        .await
    {
        Ok(r) => r,
        Err(e) if is_name_taken(&e) => return Ok(CreateOutcome::NameTaken),
        Err(e) => return Err(anyhow::Error::new(e).context("INSERT INTO projects failed")),
    };
    let project = from_row(&row);
    let after = serde_json::json!({
        "name": project.name,
        "environments": project.environments,
        "policy": project.policy,
    });
    crate::db::control_audit::record(
        &tx,
        tenant,
        &actor.as_actor(),
        crate::db::control_audit::Change {
            action: "project.create",
            target_type: "project",
            target_id: project.id.to_string(),
            before: None,
            after: Some(after),
        },
    )
    .await
    .context("admin_audit_log project.create insert failed")?;
    tx.commit().await.context("project create commit failed")?;
    Ok(CreateOutcome::Created(project))
}

/// Edit a project in place: `SELECT … FOR UPDATE` → refuse removing an environment a
/// live key carries → `UPDATE` only the changed columns → `admin_audit_log`
/// `project.update` (before AND after of each changed field) → commit under the auth
/// cache's write lock and evict every key of the project when its POLICY changed, so the
/// next request on each key reads the new policy.
///
/// # Errors
/// A database failure — fail-CLOSED, nothing is written.
#[tracing::instrument(skip(pool, tenant, patch, actor), fields(tenant_id = %tenant))]
pub async fn update(
    pool: &Pool,
    tenant: &TenantId,
    id: Uuid,
    patch: &ProjectPatch,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
) -> Result<PatchOutcome> {
    use serde_json::json;
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            &format!(
                "SELECT {COLUMNS} FROM projects \
                 WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL FOR UPDATE"
            ),
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("SELECT projects FOR UPDATE failed")?
    else {
        return Ok(PatchOutcome::NotFound);
    };
    let current = from_row(&row);
    let mut changed = Vec::new();
    let mut before = serde_json::Map::new();
    let mut after = serde_json::Map::new();
    let name = patch.name.as_ref().filter(|n| **n != current.name);
    if let Some(n) = name {
        changed.push("name");
        before.insert("name".into(), json!(current.name));
        after.insert("name".into(), json!(n));
    }
    let environments = patch
        .environments
        .as_ref()
        .filter(|e| **e != current.environments);
    if let Some(envs) = environments {
        let removed: Vec<String> = current
            .environments
            .iter()
            .filter(|e| !envs.contains(e))
            .cloned()
            .collect();
        if !removed.is_empty()
            && let Some(r) = tx
                .query_opt(
                    "SELECT environment FROM api_keys \
                     WHERE tenant_id = $1 AND project_id = $2 AND environment = ANY($3) \
                       AND (revoked_at IS NULL OR revoked_at > clock_timestamp()) LIMIT 1",
                    &[tenant.as_uuid(), &id, &removed],
                )
                .await
                .context("SELECT api_keys environment in use failed")?
        {
            return Ok(PatchOutcome::EnvironmentInUse {
                environment: r.get(0),
            });
        }
        changed.push("environments");
        before.insert("environments".into(), json!(current.environments));
        after.insert("environments".into(), json!(envs));
    }
    let policy = patch.policy.as_ref().filter(|p| **p != current.policy);
    if let Some(p) = policy {
        changed.push("policy");
        before.insert("policy".into(), json!(current.policy));
        after.insert("policy".into(), json!(p));
    }
    if changed.is_empty() {
        return Ok(PatchOutcome::Updated {
            project: Box::new(current),
            changed,
        });
    }
    let new_policy: Option<serde_json::Value> = policy.cloned().flatten();
    let row = match tx
        .query_one(
            &format!(
                "UPDATE projects SET \
                   name = CASE WHEN $3 THEN $4::text ELSE name END, \
                   environments = CASE WHEN $5 THEN $6::text[] ELSE environments END, \
                   policy = CASE WHEN $7 THEN $8::jsonb ELSE policy END, \
                   updated_at = now() \
                 WHERE tenant_id = $1 AND id = $2 RETURNING {COLUMNS}"
            ),
            &[
                tenant.as_uuid(),
                &id,
                &name.is_some(),
                &name,
                &environments.is_some(),
                &environments,
                &policy.is_some(),
                &new_policy,
            ],
        )
        .await
    {
        Ok(r) => r,
        Err(e) if is_name_taken(&e) => return Ok(PatchOutcome::NameTaken),
        Err(e) => return Err(anyhow::Error::new(e).context("UPDATE projects failed")),
    };
    let project = from_row(&row);
    crate::db::control_audit::record(
        &tx,
        tenant,
        &actor.as_actor(),
        crate::db::control_audit::Change {
            action: "project.update",
            target_type: "project",
            target_id: id.to_string(),
            before: Some(serde_json::Value::Object(before)),
            after: Some(serde_json::Value::Object(after)),
        },
    )
    .await
    .context("admin_audit_log project.update insert failed")?;
    // The project's policy governs every key in it: evict them all so the next request
    // on each reads the new policy (rather than within the refresh interval).
    let digests: Vec<[u8; 32]> = if policy.is_some() {
        tx.query(
            "SELECT lookup_hash FROM api_keys \
             WHERE tenant_id = $1 AND project_id = $2 AND lookup_hash IS NOT NULL",
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("SELECT project key digests failed")?
        .iter()
        .filter_map(|r| <[u8; 32]>::try_from(r.get::<_, Vec<u8>>(0)).ok())
        .collect()
    } else {
        Vec::new()
    };
    crate::db::api_keys::commit_and_invalidate(tx, digests).await?;
    Ok(PatchOutcome::Updated {
        project: Box::new(project),
        changed,
    })
}

/// Archive a project (`DELETE /v1/projects/{id}`). Refused while a live key is assigned:
/// move or revoke them first. `admin_audit_log` `project.archive` in the same transaction.
///
/// # Errors
/// A database failure — fail-CLOSED.
#[tracing::instrument(skip(pool, tenant, actor), fields(tenant_id = %tenant))]
pub async fn archive(
    pool: &Pool,
    tenant: &TenantId,
    id: Uuid,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
) -> Result<ArchiveOutcome> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "SELECT name FROM projects \
             WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL FOR UPDATE",
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("SELECT projects FOR UPDATE (archive) failed")?
    else {
        return Ok(ArchiveOutcome::NotFound);
    };
    let name: String = row.get(0);
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM api_keys \
             WHERE tenant_id = $1 AND project_id = $2 \
               AND (revoked_at IS NULL OR revoked_at > clock_timestamp())",
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("count project keys failed")?
        .get(0);
    if count > 0 {
        return Ok(ArchiveOutcome::HasKeys { count });
    }
    tx.execute(
        "UPDATE projects SET archived_at = now(), updated_at = now() \
         WHERE tenant_id = $1 AND id = $2",
        &[tenant.as_uuid(), &id],
    )
    .await
    .context("UPDATE projects archive failed")?;
    crate::db::control_audit::record(
        &tx,
        tenant,
        &actor.as_actor(),
        crate::db::control_audit::Change {
            action: "project.archive",
            target_type: "project",
            target_id: id.to_string(),
            before: Some(serde_json::json!({ "name": name })),
            after: Some(serde_json::json!({ "archived": true })),
        },
    )
    .await
    .context("admin_audit_log project.archive insert failed")?;
    tx.commit().await.context("project archive commit failed")?;
    Ok(ArchiveOutcome::Archived)
}
