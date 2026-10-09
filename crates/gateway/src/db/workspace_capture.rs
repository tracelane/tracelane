//! `workspace_content_capture` — GWY-53 (`specs/GWY-53-self-serve-content-capture.md`):
//! a workspace owner's opt-in to record prompt (input) and response (output) text on the
//! workspace's gateway spans. Default OFF — no row means both halves off.
//!
//! The hot path never reads this table: the row rides the entitlement refresh
//! (`entitlement_cache::attach_content_capture`) and `config::capture_decision` applies it.
//! The ONLY writer is [`set_recorded`], called by the owner-gated
//! `PUT /v1/workspace/capture`, and it records every change on the tamper-evident ledger
//! inside the same transaction.
//!
//! Tenant isolation: every statement filters on `tenant_id = $1` from the validated
//! claim's tenant UUID.

use std::future::Future;

use anyhow::{Result, anyhow};
use tracelane_shared::TenantId;

use crate::db::DbPool as Pool;

/// The owner's stored choice. `Default` = both off, which is also the answer for a
/// workspace that never set one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkspaceCapture {
    pub input: bool,
    pub output: bool,
}

/// The stored choice plus when it last changed (`None` = never set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredCapture {
    pub setting: WorkspaceCapture,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// What a write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetOutcome {
    pub previous: WorkspaceCapture,
    pub current: WorkspaceCapture,
    /// `false` when the request matched the stored value: nothing written, nothing
    /// recorded.
    pub changed: bool,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Why a write did not land. Either way NOTHING changed.
#[derive(Debug)]
pub enum SetError {
    /// The ledger refused the event; the transaction was rolled back.
    Ledger(anyhow::Error),
    /// Postgres failed.
    Store(anyhow::Error),
}

/// The workspace's row on a connection the caller holds — `None` when it never set one.
///
/// # Errors
/// Propagates the statement error. The entitlement refresh treats it as capture OFF
/// (fail-CLOSED: turning capture off is the privacy-safe direction).
pub async fn get_with(
    client: &tokio_postgres::Client,
    tenant: &uuid::Uuid,
) -> Result<Option<WorkspaceCapture>> {
    let row = client
        .query_opt(
            "SELECT input, output FROM workspace_content_capture WHERE tenant_id = $1",
            &[tenant],
        )
        .await
        .map_err(|e| anyhow!("workspace_content_capture read: {e}"))?;
    Ok(row.map(|r| WorkspaceCapture {
        input: r.get(0),
        output: r.get(1),
    }))
}

/// The stored choice through the pool — the GET route.
///
/// # Errors
/// Propagates pool/statement errors.
pub async fn get(pool: &Pool, tenant_id: &TenantId) -> Result<StoredCapture> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let row = client
        .query_opt(
            "SELECT input, output, updated_at FROM workspace_content_capture WHERE tenant_id = $1",
            &[tenant_id.as_uuid()],
        )
        .await
        .map_err(|e| anyhow!("workspace_content_capture read: {e}"))?;
    Ok(row.map_or(
        StoredCapture {
            setting: WorkspaceCapture::default(),
            updated_at: None,
        },
        |r| StoredCapture {
            setting: WorkspaceCapture {
                input: r.get(0),
                output: r.get(1),
            },
            updated_at: Some(r.get(2)),
        },
    ))
}

/// Replace the workspace's choice and record the change on the ledger — atomically.
///
/// One transaction: materialise the row (so the lock below has something to lock even on
/// a workspace's first write — two concurrent first writes would otherwise both read "no
/// row" and both record), `SELECT … FOR UPDATE`, compare, upsert, then run `record` with
/// the PREVIOUS value, and `COMMIT` only if it returned `Ok`. A refused ledger rolls the
/// change back, so a change never exists without its ledger row. A no-op (the stored value
/// already equals `new`) rolls back without calling `record`.
///
/// The residual window: `record` acked, then `COMMIT` fails. The ledger then carries a
/// change that did not land — it over-reports capture, the privacy-safe direction.
///
/// # Errors
/// [`SetError::Ledger`] when `record` fails, [`SetError::Store`] on any Postgres error.
/// Fail-CLOSED either way: nothing changed.
///
/// OG-35: the `workspace.capture.set` row in `admin_audit_log` (before/after) is
/// written in the SAME transaction, before the ledger is asked — an audit row that
/// cannot be written is [`SetError::Store`] and nothing changes.
pub async fn set_recorded<F, Fut>(
    pool: &Pool,
    tenant_id: &TenantId,
    new: WorkspaceCapture,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
    record: F,
) -> std::result::Result<SetOutcome, SetError>
where
    F: FnOnce(WorkspaceCapture) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let store = |ctx: &str, e: &dyn std::fmt::Display| SetError::Store(anyhow!("{ctx}: {e}"));
    let mut client = pool.get().await.map_err(|e| store("pool", &e))?;
    let tx = client.transaction().await.map_err(|e| store("begin", &e))?;
    let tenant = tenant_id.as_uuid();
    let inserted = tx
        .query_opt(
            "INSERT INTO workspace_content_capture (tenant_id) VALUES ($1) \
             ON CONFLICT (tenant_id) DO NOTHING RETURNING tenant_id",
            &[tenant],
        )
        .await
        .map_err(|e| store("materialise", &e))?
        .is_some();
    let row = tx
        .query_one(
            "SELECT input, output, updated_at FROM workspace_content_capture \
             WHERE tenant_id = $1 FOR UPDATE",
            &[tenant],
        )
        .await
        .map_err(|e| store("lock", &e))?;
    let previous = WorkspaceCapture {
        input: row.get(0),
        output: row.get(1),
    };
    if previous == new {
        // Dropping `tx` rolls back — including a row this call materialised.
        return Ok(SetOutcome {
            previous,
            current: previous,
            changed: false,
            updated_at: (!inserted).then(|| row.get(2)),
        });
    }
    let updated_at: chrono::DateTime<chrono::Utc> = tx
        .query_one(
            "UPDATE workspace_content_capture SET input = $2, output = $3, updated_by = $4, \
             updated_at = now() WHERE tenant_id = $1 RETURNING updated_at",
            &[tenant, &new.input, &new.output, &actor.as_actor().sub],
        )
        .await
        .map_err(|e| store("update", &e))?
        .get(0);
    crate::db::control_audit::record(
        &tx,
        tenant_id,
        &actor.as_actor(),
        crate::db::control_audit::Change {
            action: "workspace.capture.set",
            target_type: "workspace",
            target_id: tenant_id.to_string(),
            before: Some(serde_json::json!({"input": previous.input, "output": previous.output})),
            after: Some(serde_json::json!({"input": new.input, "output": new.output})),
        },
    )
    .await
    .map_err(|e| store("audit", &e))?;
    record(previous).await.map_err(SetError::Ledger)?;
    tx.commit().await.map_err(|e| store("commit", &e))?;
    Ok(SetOutcome {
        previous,
        current: new,
        changed: true,
        updated_at: Some(updated_at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool_or_panic() -> Pool {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let mut cfg = deadpool_postgres::Config::new();
        cfg.url = Some(url);
        cfg.create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .expect("pool")
    }

    const ON: WorkspaceCapture = WorkspaceCapture {
        input: true,
        output: true,
    };

    /// Spec §7 rows 6–7 — real Postgres: default when unset; a refused ledger rolls the
    /// change back; a recorded change lands and hands the ledger the PREVIOUS value; a
    /// no-op records nothing; ON DELETE CASCADE.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn gwy53_workspace_capture_round_trip_against_real_postgres() {
        let pool = pool_or_panic().await;
        let client = pool.get().await.expect("connect");
        let id: uuid::Uuid = client
            .query_one(
                "INSERT INTO tenants (workos_org_id, name) VALUES ($1, 'gwy53') RETURNING id",
                &[&format!("org_gwy53_{}", uuid::Uuid::new_v4().simple())],
            )
            .await
            .expect("tenant")
            .get(0);
        let tenant = TenantId::from_jwt_claim(id);

        let unset = get(&pool, &tenant).await.expect("read");
        assert_eq!(unset.setting, WorkspaceCapture::default(), "no row = OFF");
        assert_eq!(unset.updated_at, None);

        // A refused ledger: nothing changes, not even the materialised row.
        let refused = set_recorded(
            &pool,
            &tenant,
            ON,
            &crate::db::control_audit::Actor::system("user_a"),
            |_| async { Err(anyhow!("ledger down")) },
        )
        .await;
        assert!(matches!(refused, Err(SetError::Ledger(_))), "{refused:?}");
        assert_eq!(
            get(&pool, &tenant).await.expect("read").setting,
            WorkspaceCapture::default(),
            "a change the ledger refused must NOT land"
        );
        let rows: i64 = client
            .query_one(
                "SELECT count(*) FROM workspace_content_capture WHERE tenant_id = $1",
                &[&id],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(rows, 0, "the rollback also removes the materialised row");

        // Recorded: the ledger sees the PREVIOUS value, and the change lands.
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        let out = set_recorded(
            &pool,
            &tenant,
            ON,
            &crate::db::control_audit::Actor::system("user_a"),
            move |prev| async move {
                s.lock().expect("lock").push(prev);
                Ok(())
            },
        )
        .await
        .expect("set");
        assert!(out.changed);
        assert_eq!(out.previous, WorkspaceCapture::default());
        assert_eq!(
            *seen.lock().expect("lock"),
            vec![WorkspaceCapture::default()]
        );
        let stored = get(&pool, &tenant).await.expect("read");
        assert_eq!(stored.setting, ON);
        assert!(stored.updated_at.is_some());
        let mut refreshed = WorkspaceCapture::default();
        if let Some(w) = get_with(&client, &id).await.expect("refresh read") {
            refreshed = w;
        }
        assert_eq!(refreshed, ON, "the refresh read sees the same row");

        // A no-op: nothing recorded.
        let noop = set_recorded(
            &pool,
            &tenant,
            ON,
            &crate::db::control_audit::Actor::system("user_b"),
            |_| async { panic!("a no-op must never reach the ledger") },
        )
        .await
        .expect("noop");
        assert!(!noop.changed);
        assert_eq!(noop.updated_at, stored.updated_at);

        // Input only.
        let half = WorkspaceCapture {
            input: true,
            output: false,
        };
        let out = set_recorded(
            &pool,
            &tenant,
            half,
            &crate::db::control_audit::Actor::system("user_b"),
            |prev| async move {
                assert_eq!(prev, ON);
                Ok(())
            },
        )
        .await
        .expect("half");
        assert!(out.changed);
        assert_eq!(get(&pool, &tenant).await.expect("read").setting, half);
        let by: String = client
            .query_one(
                "SELECT updated_by FROM workspace_content_capture WHERE tenant_id = $1",
                &[&id],
            )
            .await
            .expect("by")
            .get(0);
        assert_eq!(by, "user_b");

        client
            .execute("DELETE FROM tenants WHERE id = $1", &[&id])
            .await
            .expect("delete tenant");
        let left: i64 = client
            .query_one(
                "SELECT count(*) FROM workspace_content_capture WHERE tenant_id = $1",
                &[&id],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(left, 0, "ON DELETE CASCADE");
    }
}
