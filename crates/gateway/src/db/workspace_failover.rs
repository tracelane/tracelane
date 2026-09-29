//! `workspace_failover` — GWY-52 (`specs/GWY-52-workspace-failover.md`): a workspace's
//! own cross-provider failover — on by default for its requests, with its own ordered
//! fallback models. The hot path never reads this table; the row rides the entitlement
//! refresh (`entitlement_cache::attach_workspace_gateway`) and `chat.rs` applies it.
//!
//! Tenant isolation: every statement filters on `tenant_id = $1` from the validated
//! claim's tenant UUID.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use tracelane_shared::TenantId;

use crate::db::DbPool as Pool;

/// A workspace's failover settings as stored. `Default` is the operator default: off,
/// and no chain of its own (the operator's chain applies).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceFailover {
    pub enabled: bool,
    pub models: Vec<String>,
}

/// Why a write was refused — one `400` code each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverError {
    /// A model does not route to any provider.
    Unroutable(String),
    /// The same model appears twice.
    Duplicate(String),
    /// A model is one of the workspace's aliases — a hop dispatches the string as-is.
    IsAlias(String),
    /// More models than the policy allows.
    TooMany { max: u32 },
}

impl FailoverError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unroutable(_) => "unroutable_model",
            Self::Duplicate(_) => "duplicate_model",
            Self::IsAlias(_) => "model_is_alias",
            Self::TooMany { .. } => "failover_cap_reached",
        }
    }
}

/// Every refusal, decided without I/O. `routable` is
/// `ProviderRegistry::provider_id_for_model(..).is_some()` in production.
///
/// # Errors
/// The first [`FailoverError`] in list order.
pub fn validate(
    models: &[String],
    aliases: &BTreeMap<String, String>,
    max: u32,
    routable: impl Fn(&str) -> bool,
) -> std::result::Result<(), FailoverError> {
    if models.len() > usize::try_from(max).unwrap_or(usize::MAX) {
        return Err(FailoverError::TooMany { max });
    }
    let mut seen = std::collections::BTreeSet::new();
    for m in models {
        if aliases.contains_key(m) {
            return Err(FailoverError::IsAlias(m.clone()));
        }
        if !routable(m) {
            return Err(FailoverError::Unroutable(m.clone()));
        }
        if !seen.insert(m.as_str()) {
            return Err(FailoverError::Duplicate(m.clone()));
        }
    }
    Ok(())
}

/// The workspace's row on a connection the caller holds — `None` when it never set one.
///
/// # Errors
/// Propagates the statement error (the entitlement refresh treats it as "operator default").
pub async fn get_with(
    client: &tokio_postgres::Client,
    tenant: &uuid::Uuid,
) -> Result<Option<WorkspaceFailover>> {
    let row = client
        .query_opt(
            "SELECT enabled, models FROM workspace_failover WHERE tenant_id = $1",
            &[tenant],
        )
        .await
        .map_err(|e| anyhow!("workspace_failover read: {e}"))?;
    Ok(row.map(|r| WorkspaceFailover {
        enabled: r.get(0),
        models: r.get(1),
    }))
}

/// [`get_with`] through the pool — the GET route.
///
/// # Errors
/// Propagates pool/statement errors.
pub async fn get(pool: &Pool, tenant_id: &TenantId) -> Result<WorkspaceFailover> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    Ok(get_with(&client, tenant_id.as_uuid())
        .await?
        .unwrap_or_default())
}

/// Replace the workspace's settings. Validation ([`validate`]) runs first.
///
/// # Errors
/// Fails CLOSED on pool/statement errors.
pub async fn put(
    pool: &Pool,
    tenant_id: &TenantId,
    settings: &WorkspaceFailover,
    updated_by: &str,
) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    client
        .execute(
            "INSERT INTO workspace_failover (tenant_id, enabled, models, updated_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id) DO UPDATE SET enabled = EXCLUDED.enabled, \
               models = EXCLUDED.models, updated_by = EXCLUDED.updated_by, updated_at = NOW()",
            &[
                tenant_id.as_uuid(),
                &settings.enabled,
                &settings.models,
                &updated_by,
            ],
        )
        .await
        .map_err(|e| anyhow!("workspace_failover upsert: {e}"))?;
    Ok(())
}

/// `billing_policy.failover_models_max`, read on the write path. `Ok(None)` → the caller
/// refuses rather than guessing a cap.
///
/// # Errors
/// Propagates pool/statement errors.
pub async fn read_cap(pool: &Pool) -> Result<Option<u32>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let row = client
        .query_opt(
            "SELECT value::text FROM billing_policy WHERE key = 'failover_models_max'",
            &[],
        )
        .await
        .map_err(|e| anyhow!("billing_policy read: {e}"))?;
    Ok(row.and_then(|r| r.get::<_, String>(0).trim().parse::<u32>().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routable(m: &str) -> bool {
        m.starts_with("gpt-") || m.starts_with("claude-") || m.starts_with("gemini-")
    }

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn every_refusal_blocks_and_a_clean_chain_passes() {
        let aliases: BTreeMap<String, String> = [("fast".to_string(), "gpt-5".to_string())]
            .into_iter()
            .collect();
        let check = |m: &[&str], max| validate(&v(m), &aliases, max, routable);
        assert_eq!(check(&["gpt-4o", "gemini-2.5-flash"], 5), Ok(()));
        assert_eq!(
            check(&[], 5),
            Ok(()),
            "an empty chain means: use the operator's"
        );
        assert_eq!(
            check(&["gpt-4o", "nope-model"], 5),
            Err(FailoverError::Unroutable("nope-model".into()))
        );
        assert_eq!(
            check(&["gpt-4o", "gpt-4o"], 5),
            Err(FailoverError::Duplicate("gpt-4o".into()))
        );
        assert_eq!(
            check(&["fast"], 5),
            Err(FailoverError::IsAlias("fast".into()))
        );
        assert_eq!(
            check(&["gpt-4o", "claude-x", "gemini-y"], 2),
            Err(FailoverError::TooMany { max: 2 })
        );
    }

    /// Spec §7 row 5 — real Postgres: default when unset, upsert, replace, the CHECK, cascade.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn gwy52_workspace_failover_round_trip_against_real_postgres() {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let mut cfg = deadpool_postgres::Config::new();
        cfg.url = Some(url);
        let pool = cfg
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .expect("pool");
        let client = pool.get().await.expect("connect");
        let id: uuid::Uuid = client
            .query_one(
                "INSERT INTO tenants (workos_org_id, name) VALUES ($1, 'gwy52') RETURNING id",
                &[&format!("org_gwy52_{}", uuid::Uuid::new_v4().simple())],
            )
            .await
            .expect("tenant")
            .get(0);
        let tenant = TenantId::from_jwt_claim(id);
        assert_eq!(
            get(&pool, &tenant).await.unwrap(),
            WorkspaceFailover::default()
        );
        let on = WorkspaceFailover {
            enabled: true,
            models: v(&["gpt-4o-mini", "gemini-2.5-flash"]),
        };
        put(&pool, &tenant, &on, "t").await.unwrap();
        assert_eq!(get(&pool, &tenant).await.unwrap(), on, "order preserved");
        let off = WorkspaceFailover {
            enabled: false,
            models: vec![],
        };
        put(&pool, &tenant, &off, "t").await.unwrap();
        assert_eq!(
            get(&pool, &tenant).await.unwrap(),
            off,
            "replace, not append"
        );
        let too_long: Vec<String> = (0..33).map(|i| format!("m{i}")).collect();
        let refused = client
            .execute(
                "UPDATE workspace_failover SET models = $2 WHERE tenant_id = $1",
                &[&id, &too_long],
            )
            .await;
        assert!(refused.is_err(), "the table CHECK bounds the array");
        client
            .execute("DELETE FROM tenants WHERE id = $1", &[&id])
            .await
            .unwrap();
        let left: i64 = client
            .query_one(
                "SELECT count(*) FROM workspace_failover WHERE tenant_id = $1",
                &[&id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(left, 0, "ON DELETE CASCADE");
    }
}
