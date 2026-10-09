//! `workspace_routing` — the `OG-11`/`OG-12`/`OG-13` routing document, one row per
//! workspace (`apps/web/db/migrations/0070_og11_routing.sql`).
//!
//! The hot path never reads this table: the entitlement refresh loads the document
//! ([`get_with`]) and `crate::routing::RoutingState::from_stored` parses it. Writes come
//! only from the owner-gated `PUT /v1/routing` (`crate::routing::routes`), which validates
//! the document first; [`put`] then applies it with an optimistic version check and the
//! `routing.update` control-audit row in ONE transaction.
//!
//! This module holds the RAW JSON only (no `crate::routing` types) so the real-Postgres
//! harness, which mounts `db` on its own, still compiles.
//!
//! Tenant isolation: every statement filters on `tenant_id = $1`, the validated claim's
//! tenant UUID — never a request body.

use anyhow::{Context as _, Result, anyhow};
use serde_json::Value;
use tracelane_shared::TenantId;

use crate::db::DbPool as Pool;

/// One stored document.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredRouting {
    pub doc: Value,
    pub version: i32,
    pub updated_by: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// The workspace's routing document on a connection the caller holds (the entitlement
/// refresh reuses its own).
///
/// # Errors
/// Propagates the statement error — the refresh then FAILS, so the cache keeps serving
/// the last-known document (a routing change is never dropped because a read failed).
pub async fn get_with(
    client: &tokio_postgres::Client,
    tenant: &uuid::Uuid,
) -> Result<Option<StoredRouting>> {
    let row = client
        .query_opt(
            "SELECT doc, version, updated_by, updated_at FROM workspace_routing \
             WHERE tenant_id = $1",
            &[tenant],
        )
        .await
        .map_err(|e| anyhow!("workspace_routing read: {e}"))?;
    Ok(row.map(|r| StoredRouting {
        doc: r.get(0),
        version: r.get(1),
        updated_by: r.get(2),
        updated_at: r.get(3),
    }))
}

/// [`get_with`] from the pool.
///
/// # Errors
/// Pool or statement error.
pub async fn get(pool: &Pool, tenant: &TenantId) -> Result<Option<StoredRouting>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    get_with(&client, tenant.as_uuid()).await
}

/// What [`put`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    /// Stored; the new version.
    Written { version: i32 },
    /// `If-Match` was not the stored version — nothing written (`409 version_conflict`).
    VersionConflict { current: i32 },
    /// A pool label named by the document is not (or no longer) stored — nothing
    /// written (`400 invalid_field`).
    MissingLabel { provider: String, label: String },
}

/// The `(provider, label)` pairs of every key pool in a raw document.
#[must_use]
pub fn pool_labels(doc: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for p in doc
        .get("key_pools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(provider) = p.get("provider").and_then(Value::as_str) else {
            continue;
        };
        for k in p
            .get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(label) = k.get("label").and_then(Value::as_str) {
                out.push((provider.to_owned(), label.to_owned()));
            }
        }
    }
    out
}

/// Store `doc` if the stored version is `if_match` (0 = no document yet).
///
/// The routing row is locked `FOR UPDATE` and every key the document's pools name is
/// re-read `FOR SHARE` inside the SAME transaction — so a concurrent key delete (which
/// locks the routing row and refuses while it names the key, `db::provider_keys::delete`)
/// either finishes first, and this write sees the key gone, or waits and then sees this
/// document. A pool can never be left naming a deleted key by a race.
///
/// # Errors
/// Fail-CLOSED: any pool or statement error propagates; a write reported as success
/// happened, together with its `routing.update` audit row (OG-35).
pub async fn put(
    pool: &Pool,
    tenant: &TenantId,
    doc: &Value,
    if_match: i32,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
) -> Result<PutOutcome> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    // Lock a row that exists even before the first routing document is written.
    tx.query_one(
        "SELECT id FROM tenants WHERE id = $1 FOR UPDATE",
        &[tenant.as_uuid()],
    )
    .await
    .context("lock tenant for routing/key mutation")?;
    let before = tx
        .query_opt(
            "SELECT doc, version FROM workspace_routing WHERE tenant_id = $1 FOR UPDATE",
            &[tenant.as_uuid()],
        )
        .await
        .context("SELECT workspace_routing FOR UPDATE")?
        .map(|r| (r.get::<_, Value>(0), r.get::<_, i32>(1)));
    let current = before.as_ref().map_or(0, |(_, v)| *v);
    if current != if_match {
        return Ok(PutOutcome::VersionConflict { current });
    }
    let held: Vec<(String, String)> = tx
        .query(
            "SELECT provider_id, label FROM provider_keys WHERE tenant_id = $1 FOR SHARE",
            &[tenant.as_uuid()],
        )
        .await
        .context("SELECT provider_keys FOR SHARE (routing write)")?
        .iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
        .collect();
    for (provider, label) in pool_labels(doc) {
        if !held.iter().any(|(p, l)| *p == provider && *l == label) {
            return Ok(PutOutcome::MissingLabel { provider, label });
        }
    }
    let version = current + 1;
    let actor = actor.as_actor();
    tx.execute(
        "INSERT INTO workspace_routing (tenant_id, doc, version, updated_by, updated_at) \
         VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (tenant_id) DO UPDATE \
            SET doc = EXCLUDED.doc, version = EXCLUDED.version, \
                updated_by = EXCLUDED.updated_by, updated_at = now()",
        &[tenant.as_uuid(), doc, &version, &actor.sub],
    )
    .await
    .context("UPSERT workspace_routing")?;
    crate::db::control_audit::record(
        &tx,
        tenant,
        &actor,
        crate::db::control_audit::Change {
            action: "routing.update",
            target_type: "workspace_routing",
            target_id: "routing".to_owned(),
            before: before.map(|(d, v)| serde_json::json!({"version": v, "doc": d})),
            after: Some(serde_json::json!({"version": version, "doc": doc})),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(PutOutcome::Written { version })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_labels_reads_every_provider_label_pair() {
        let doc = serde_json::json!({"key_pools": [
            {"provider": "openai", "keys": [{"label": "a"}, {"label": "b"}]},
            {"provider": "anthropic", "keys": [{"label": "default"}]}
        ]});
        assert_eq!(
            pool_labels(&doc),
            vec![
                ("openai".to_owned(), "a".to_owned()),
                ("openai".to_owned(), "b".to_owned()),
                ("anthropic".to_owned(), "default".to_owned()),
            ]
        );
        assert!(pool_labels(&serde_json::json!({})).is_empty());
    }

    /// Real Postgres: the optimistic version, the audit row in the same transaction,
    /// and a missing label refused under lock.
    #[tokio::test]
    #[ignore = "requires isolated Postgres with migration 0070; POSTGRES_TEST_URL"]
    async fn og11_routing_put_is_versioned_audited_and_label_checked() -> Result<()> {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let mut cfg = deadpool_postgres::Config::new();
        cfg.url = Some(url);
        let pool = cfg.create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )?;
        let tenant_uuid: uuid::Uuid = pool
            .get()
            .await?
            .query_one(
                "INSERT INTO tenants (workos_org_id, name) VALUES ($1, 'og11') RETURNING id",
                &[&format!("org_og11_{}", uuid::Uuid::new_v4().simple())],
            )
            .await?
            .get(0);
        let tenant = TenantId::from_jwt_claim(tenant_uuid);
        let doc = serde_json::json!({"virtual_models": {"fast": {"targets": [{"model": "gpt-4o-mini"}]}}});
        assert_eq!(
            put(&pool, &tenant, &doc, 1, "test").await?,
            PutOutcome::VersionConflict { current: 0 }
        );
        assert_eq!(
            put(&pool, &tenant, &doc, 0, "test").await?,
            PutOutcome::Written { version: 1 }
        );
        let stored = get(&pool, &tenant).await?.expect("stored");
        assert_eq!((stored.version, stored.doc), (1, doc));
        let pooled = serde_json::json!({"key_pools": [{"provider": "openai", "keys": [{"label": "team-a"}]}]});
        assert_eq!(
            put(&pool, &tenant, &pooled, 1, "test").await?,
            PutOutcome::MissingLabel {
                provider: "openai".into(),
                label: "team-a".into()
            }
        );
        let client = pool.get().await?;
        let n: i64 = client
            .query_one(
                "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 \
                 AND action = 'routing.update'",
                &[&tenant_uuid],
            )
            .await?
            .get(0);
        assert_eq!(
            n, 1,
            "one audit row per applied write, none for a refused one"
        );
        Ok(())
    }
}
