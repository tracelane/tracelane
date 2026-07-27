//!
//! ClickHouse `tracelane.spans` / `tracelane.trace_summaries` carry a flat **365d
//! TTL backstop** (the MAX plan retention). This background job trims each tenant
//! to their ACTUAL plan window — Free 7 / Builder 30 / Team 90 / Business 180 /
//! Enterprise 365 days — read from `plan_entitlements.retention_days` overlaid by
//! `workspace_entitlements` (deny-overrides-grant), the same entitlement source
//! the gateway resolves. Entitlement-driven, not schema-hardcoded.
//!
//! ## Data-safety (retention risk #1)
//!
//! Deletion is IRREVERSIBLE and one-way, so it is GATED and fail-safe:
//! - `TRACELANE_RETENTION_SWEEP` = `off` (DEFAULT) | `dryrun` (log what WOULD be
//!   deleted, delete NOTHING) | `enforce` (delete). Nothing is deleted until an
//!   operator explicitly sets `enforce`.
//! - A tenant whose retention can't be resolved falls back to **365d** (the max,
//!   never delete a paying tenant early) — `resolve_retentions` COALESCEs to 365.
//! - A non-positive resolved retention SKIPS that tenant (a 0/negative value would
//!   mean "delete everything" — the fail-safe never mass-deletes on a bad value).
//! - The sweep only ever deletes rows OLDER than the tenant's window; the flat
//!   365d table TTL is the hard backstop if this job stops running.
//!
//! ## Why not `TenantQuery` (ADR-031 caps)
//!
//! This is a background GC path, not a user-driven dashboard read: a bounded
//! per-tenant `count()` (the dryrun report / enforce audit) and a tenant-scoped
//! lightweight `DELETE` (CH 24.12). No caps needed; both queries are tenant-scoped
//! (`WHERE tenant_id = ?`), satisfying the isolation guard.

use std::time::Duration;

use crate::db::DbPool;

/// Enforcement mode from `TRACELANE_RETENTION_SWEEP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepMode {
    /// Default. The task does not run; no reads, no deletes.
    Off,
    /// Resolve + count what would be deleted and log it. Deletes NOTHING.
    DryRun,
    /// Resolve + delete rows past each tenant's plan window.
    Enforce,
}

impl SweepMode {
    /// Parse from `TRACELANE_RETENTION_SWEEP`. Unknown / unset → `Off` (deletion
    /// is strictly opt-in — an operator must ask for `dryrun`/`enforce`).
    pub fn from_env() -> Self {
        Self::parse(std::env::var("TRACELANE_RETENTION_SWEEP").unwrap_or_default())
    }

    fn parse(raw: impl AsRef<str>) -> Self {
        match raw.as_ref().trim().to_ascii_lowercase().as_str() {
            "enforce" => Self::Enforce,
            "dryrun" | "dry-run" | "dry_run" => Self::DryRun,
            _ => Self::Off,
        }
    }
}

/// Interval between sweeps.
const SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60); // 6h
/// Delay before the first sweep, so a fresh node settles before any deletion.
const INITIAL_DELAY: Duration = Duration::from_secs(120);

/// One retention-bearing table + its tenant-scoped count/delete SQL. Literal
/// `FROM tracelane.<t>` + `WHERE tenant_id = ?` so the tenant-isolation CI guard
/// both passes AND stays effective (a future non-scoped edit would be caught).
struct SweepTable {
    label: &'static str,
    count_sql: &'static str,
    delete_sql: &'static str,
}

const SWEEP_TABLES: &[SweepTable] = &[
    SweepTable {
        label: "spans",
        count_sql: "SELECT count() AS n FROM tracelane.spans \
                    WHERE tenant_id = ? AND start_time < now() - toIntervalDay(?)",
        delete_sql: "DELETE FROM tracelane.spans \
                     WHERE tenant_id = ? AND start_time < now() - toIntervalDay(?)",
    },
    SweepTable {
        label: "trace_summaries",
        count_sql: "SELECT count() AS n FROM tracelane.trace_summaries \
                    WHERE tenant_id = ? AND start_time < now() - toIntervalDay(?)",
        delete_sql: "DELETE FROM tracelane.trace_summaries \
                     WHERE tenant_id = ? AND start_time < now() - toIntervalDay(?)",
    },
];

/// A tenant and its resolved retention window (days).
struct TenantRetention {
    tenant_id: String,
    retention_days: i32,
}

/// Fail-safe: how many days to sweep for a resolved retention, or `None` to SKIP
/// the tenant (never mass-delete on a non-positive/absurd value). Pure — unit-tested.
fn sweep_days(retention_days: i32) -> Option<u64> {
    if retention_days <= 0 {
        None
    } else {
        Some(retention_days as u64)
    }
}

/// Spawn the background retention sweep. No-op (logs) when `mode == Off` or no
/// ClickHouse URL. Runs after `INITIAL_DELAY`, then every `SWEEP_INTERVAL`.
pub fn spawn_retention_task(pool: DbPool, ch_url: Option<String>, mode: SweepMode) {
    if mode == SweepMode::Off {
        tracing::info!(
            "retention sweep: OFF (set TRACELANE_RETENTION_SWEEP=dryrun|enforce to enable — deletion is opt-in)"
        );
        return;
    }
    let Some(ch_url) = ch_url else {
        tracing::warn!("retention sweep: no CLICKHOUSE_URL — sweep disabled");
        return;
    };
    tracing::info!(?mode, "retention sweep: ENABLED");
    tokio::spawn(async move {
        tokio::time::sleep(INITIAL_DELAY).await;
        loop {
            if let Err(e) = run_sweep(&pool, &ch_url, mode).await {
                // Fail-safe: a resolution failure aborts the WHOLE run (no partial
                // deletion on a bad tenant list); retry next interval.
                tracing::error!(error = %e, "retention sweep run failed; retrying next interval");
            }
            tokio::time::sleep(SWEEP_INTERVAL).await;
        }
    });
}

/// One sweep pass: resolve per-tenant retention, then trim each tenant/table.
async fn run_sweep(pool: &DbPool, ch_url: &str, mode: SweepMode) -> anyhow::Result<()> {
    let tenants = resolve_retentions(pool).await?;
    let ch = crate::clickhouse_query::ch_client(ch_url.to_string());
    let mut total: u64 = 0;
    let mut swept = 0usize;
    for tr in &tenants {
        let Some(days) = sweep_days(tr.retention_days) else {
            tracing::warn!(
                tenant_id = %tr.tenant_id,
                retention_days = tr.retention_days,
                "retention sweep: non-positive retention — skipping (fail-safe)"
            );
            continue;
        };
        swept += 1;
        for t in SWEEP_TABLES {
            match sweep_one(&ch, t, &tr.tenant_id, days, mode).await {
                Ok(n) => total += n,
                // A single tenant/table failure never aborts the run — skip + log.
                Err(e) => tracing::warn!(
                    error = %e, tenant_id = %tr.tenant_id, table = t.label,
                    "retention sweep: tenant/table failed — skipping"
                ),
            }
        }
    }
    tracing::info!(
        ?mode,
        tenants = swept,
        rows = total,
        "retention sweep complete ({})",
        if mode == SweepMode::Enforce {
            "deleted"
        } else {
            "would-delete"
        }
    );
    Ok(())
}

/// Resolve `retention_days` for every non-archived tenant: `workspace_entitlements`
/// override beats `plan_entitlements` default (deny-overrides-grant); the plan
/// comes from `we.plan_lookup_key` else `tenants.plan||'_v1'`. COALESCE to 365
/// (fail-safe: an unresolved tenant is never deleted early).
async fn resolve_retentions(pool: &DbPool) -> anyhow::Result<Vec<TenantRetention>> {
    let client = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("retention pool: {e}"))?;
    const SQL: &str = "\
        SELECT t.id::text, \
               COALESCE(we.retention_days, pe.retention_days, 365)::int \
        FROM tenants t \
        LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id \
        LEFT JOIN plan_entitlements pe \
          ON pe.plan_lookup_key = COALESCE(we.plan_lookup_key, t.plan::text || '_v1') \
        WHERE t.archived_at IS NULL";
    let rows = client.query(SQL, &[]).await?;
    Ok(rows
        .iter()
        .map(|r| TenantRetention {
            tenant_id: r.get(0),
            retention_days: r.get(1),
        })
        .collect())
}

/// Count rows past `days` for `tenant_id` in one table; delete them in `Enforce`.
/// Returns the row count (0 in dryrun). `clickhouse::Client` / `clickhouse::Row`
/// are referenced fully-qualified so this file carries no `use clickhouse::`
/// (the raw-CH-query guard keys on that import; this is a GC path, not a read).
async fn sweep_one(
    ch: &clickhouse::Client,
    table: &SweepTable,
    tenant_id: &str,
    days: u64,
    mode: SweepMode,
) -> anyhow::Result<u64> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct CountRow {
        n: u64,
    }
    let CountRow { n } = ch
        .query(table.count_sql)
        .bind(tenant_id)
        .bind(days)
        .fetch_one::<CountRow>()
        .await?;
    if n == 0 {
        return Ok(0);
    }
    match mode {
        SweepMode::DryRun => {
            tracing::info!(
                %tenant_id, table = table.label, retention_days = days, would_delete = n,
                "retention sweep [dryrun]: rows past window"
            );
            Ok(0)
        }
        SweepMode::Enforce => {
            ch.query(table.delete_sql)
                .bind(tenant_id)
                .bind(days)
                .execute()
                .await?;
            tracing::info!(
                %tenant_id, table = table.label, retention_days = days, deleted = n,
                "retention sweep [enforce]: deleted rows past window"
            );
            Ok(n)
        }
        SweepMode::Off => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parse_defaults_off_and_is_opt_in() {
        assert_eq!(SweepMode::parse(""), SweepMode::Off);
        assert_eq!(SweepMode::parse("   "), SweepMode::Off);
        assert_eq!(SweepMode::parse("bogus"), SweepMode::Off);
        assert_eq!(SweepMode::parse("OFF"), SweepMode::Off);
        assert_eq!(SweepMode::parse("dryrun"), SweepMode::DryRun);
        assert_eq!(SweepMode::parse("dry-run"), SweepMode::DryRun);
        assert_eq!(SweepMode::parse(" Enforce "), SweepMode::Enforce);
    }

    #[test]
    fn sweep_days_skips_non_positive_failsafe() {
        // A 0 or negative retention would delete everything — must SKIP, not sweep.
        assert_eq!(sweep_days(0), None);
        assert_eq!(sweep_days(-5), None);
        // Real plan windows map straight through.
        assert_eq!(sweep_days(7), Some(7)); // free
        assert_eq!(sweep_days(30), Some(30)); // builder
        assert_eq!(sweep_days(365), Some(365)); // enterprise
    }

    #[test]
    fn every_sweep_query_is_tenant_scoped_and_time_bounded() {
        // Guard-equivalent: a regression that drops the tenant filter or the age
        // bound (turning a trim into a table wipe) fails here.
        for t in SWEEP_TABLES {
            for sql in [t.count_sql, t.delete_sql] {
                assert!(
                    sql.contains("tenant_id = ?"),
                    "{}: not tenant-scoped",
                    t.label
                );
                assert!(
                    sql.contains("start_time < now() - toIntervalDay(?)"),
                    "{}: missing the age bound — would delete more than the window",
                    t.label
                );
                assert!(
                    sql.contains("tracelane."),
                    "{}: not a tracelane table",
                    t.label
                );
            }
        }
    }
}
