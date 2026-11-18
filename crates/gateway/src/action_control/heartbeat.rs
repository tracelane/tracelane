//! AUD-32 slice A: signed liveness checkpoints on a fixed cadence (`specs/AUD-32-…`).
//!
//! A heartbeat is an ordinary action-head checkpoint minted on a schedule: when the head has
//! not moved and the latest checkpoint is at least one period old, a new checkpoint repeats the
//! head and links `previous_checkpoint_digest`. Silence between two heartbeats is then signed
//! evidence that the recorder was alive. Off the request path, fail-OPEN per tenant.
use super::*;
use std::future::Future;
use std::time::Duration;
use tracelane_shared::degradation::{self, Degradation};

/// Neon suspends an idle compute after 300 s (measured; `.claude/rules/working-lessons.md`
/// "Durations and thresholds"). A period at or under it keeps the control plane awake forever.
const NEON_SUSPEND_SECS: u64 = 300;
const ENV: &str = "TRACELANE_ACTION_HEARTBEAT_SECS";

/// Parsed `TRACELANE_ACTION_HEARTBEAT_SECS`. `Ok(None)` = unset = disabled.
///
/// # Errors
/// Fails CLOSED at boot on a value that is not an integer above the Neon suspend floor.
pub fn period_from(raw: Option<&str>) -> Result<Option<Duration>> {
    let Some(raw) = raw else { return Ok(None) };
    let secs: u64 = raw
        .trim()
        .parse()
        .with_context(|| format!("{ENV} must be an integer number of seconds"))?;
    ensure!(
        secs > NEON_SUSPEND_SECS,
        "{ENV} must be > {NEON_SUSPEND_SECS} (Neon suspend timeout), got {secs}"
    );
    Ok(Some(Duration::from_secs(secs)))
}

/// Age at which a tick re-signs an unchanged head: 90% of the period. With exactly `period`,
/// a tenant whose turn comes earlier in tick k+1 than in tick k reads age < period and is
/// skipped, so heartbeats land 2x the period apart (review M1, 2026-11-13). The 10% slack is
/// larger than one tick's runtime and keeps at most one mint per period.
pub(crate) fn due_after(period: Duration) -> Duration {
    period - period / 10
}

/// One heartbeat for one tenant. `Ok(true)` = a checkpoint was minted, `Ok(false)` = reused
/// or skipped (an export holds the tenant lock).
///
/// # Errors
/// Any database or signing error; the caller counts it and moves on (fail-OPEN).
pub(crate) async fn beat(
    pool: &deadpool_postgres::Pool,
    keys: &crate::audit_keys::TenantAuditKeyStore,
    tenant: &TenantId,
    period: Duration,
) -> Result<bool> {
    let key = keys.get_or_create(tenant).await?;
    let mut db = pool.get().await?;
    let tx = db
        .build_transaction()
        .isolation_level(CHECKPOINT_ISOLATION)
        .start()
        .await?;
    // Same lock the export takes (`audit_export/action.rs`): never mint beside an export.
    let acquired: bool = tx
        .query_one(
            "SELECT pg_try_advisory_xact_lock(hashtextextended($1::text || ':action_bundle', 0))",
            &[&tenant.to_string()],
        )
        .await?
        .get(0);
    if !acquired {
        return Ok(false);
    }
    let before: i64 = tx
        .query_one(
            "SELECT count(*) FROM audit_head_checkpoints WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await?
        .get(0);
    let head = checkpoint_head_tx(&tx, tenant).await?;
    if let Err(error) = checkpoint_for_head_tx(&tx, tenant, head, &key, Some(period)).await {
        // A checkpoint under a minute old (the export floor) already attests liveness.
        if matches!(
            error.downcast_ref(),
            Some(crate::audit_export::action::ExportError::CheckpointRateLimited(_))
        ) {
            return Ok(false);
        }
        return Err(error);
    }
    let after: i64 = tx
        .query_one(
            "SELECT count(*) FROM audit_head_checkpoints WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await?
        .get(0);
    tx.commit().await?;
    Ok(after > before)
}

/// One pass over every tenant with a ledger whose entitlements enable action control.
/// Returns the number of checkpoints minted.
///
/// # Errors
/// Only the tenant listing; a per-tenant failure is counted and skipped (fail-OPEN).
pub(crate) async fn tick<F, Fut>(
    pool: &deadpool_postgres::Pool,
    keys: &crate::audit_keys::TenantAuditKeyStore,
    period: Duration,
    enabled: F,
) -> Result<u32>
where
    F: Fn(Uuid) -> Fut,
    Fut: Future<Output = bool>,
{
    let tenants: Vec<Uuid> = pool
        .get()
        .await?
        .query(
            "SELECT tenant_id FROM audit_chain_state ORDER BY tenant_id",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut minted = 0;
    for id in tenants {
        if !enabled(id).await {
            continue;
        }
        // Stored tenant ids were written under an authenticated claim; a background worker has
        // none to re-validate. Same convention as `prompt_router::tenant_from_stored`.
        let tenant = TenantId::from_jwt_claim(id);
        match beat(pool, keys, &tenant, period).await {
            Ok(true) => minted += 1,
            Ok(false) => {}
            Err(error) => {
                // One counter; the tenant id is the only context logged, never key material.
                degradation::note(Degradation::ActionHeartbeatFailed);
                tracing::debug!(tenant_id=%id, error=%error, "action heartbeat failed");
            }
        }
    }
    Ok(minted)
}

/// Spawn the heartbeat loop. The gateway is a control-plane singleton (B-386), so exactly one
/// process mints heartbeats.
pub fn spawn(
    pool: deadpool_postgres::Pool,
    keys: std::sync::Arc<crate::audit_keys::TenantAuditKeyStore>,
    entitlements: std::sync::Arc<crate::entitlement_cache::EntitlementCache>,
    period: Duration,
) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(period);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        every.tick().await; // first tick is immediate; let boot settle one period
        loop {
            every.tick().await;
            let cache = entitlements.clone();
            let result = tick(&pool, &keys, due_after(period), move |t| {
                let cache = cache.clone();
                async move { cache.resolved(t).await.action_control }
            })
            .await;
            if result.is_err() {
                degradation::note(Degradation::ActionHeartbeatFailed);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_after_leaves_slack_inside_the_period() {
        let p = Duration::from_secs(3600);
        assert_eq!(due_after(p), Duration::from_secs(3240));
        assert!(due_after(p) < p);
        assert!(due_after(Duration::from_secs(301)) > Duration::from_secs(60));
    }
    #[test]
    fn config_unset_disables() {
        assert_eq!(period_from(None).unwrap(), None);
    }
    #[test]
    fn config_above_floor_accepted() {
        assert_eq!(
            period_from(Some("301")).unwrap(),
            Some(Duration::from_secs(301))
        );
    }
    #[test]
    fn config_hourly_accepted() {
        assert_eq!(
            period_from(Some(" 3600 ")).unwrap(),
            Some(Duration::from_secs(3600))
        );
    }
    #[test]
    fn config_at_floor_refused() {
        assert!(period_from(Some("300")).is_err());
    }
    #[test]
    fn config_zero_refused() {
        assert!(period_from(Some("0")).is_err());
    }
    #[test]
    fn config_garbage_refused() {
        assert!(period_from(Some("1h")).is_err());
        assert!(period_from(Some("-5")).is_err());
    }
}
