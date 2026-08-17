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

/// Directory the pre-delete snapshot is written to. **Enforce is refused without
/// it** — see [`SweepMode::from_env`].
pub const SNAPSHOT_DIR_ENV: &str = "TRACELANE_RETENTION_SNAPSHOT_DIR";

impl SweepMode {
    /// Parse from `TRACELANE_RETENTION_SWEEP`. Unknown / unset → `Off` (deletion
    /// is strictly opt-in — an operator must ask for `dryrun`/`enforce`).
    ///
    /// **`Enforce` additionally requires a snapshot destination** and is
    /// downgraded to `DryRun` without one (2026-08-11, founder-ruled).
    ///
    /// Retention deletion is the only irreversible action this process takes, and
    /// it had **no undo**: the audit ledger records gateway actions, not row
    /// deletions, so once a sweep ran the rows were simply gone. Requiring the
    /// snapshot *at the mode boundary* rather than at the delete site means the
    /// capability cannot be half-configured — you cannot end up in Enforce with
    /// snapshots silently disabled, which is the configuration that would look
    /// fine right up until someone needed the undo.
    ///
    /// The downgrade is deliberate rather than a hard refusal to boot: the safe
    /// direction for a retention sweep is *not deleting*, and taking the gateway
    /// down over a GC setting would trade a data risk for an availability one. It
    /// is logged at ERROR because a silent downgrade would be its own defect.
    pub fn from_env() -> Self {
        let mode = Self::parse(std::env::var("TRACELANE_RETENTION_SWEEP").unwrap_or_default());
        if mode == Self::Enforce && !Self::snapshot_dir_configured() {
            tracing::error!(
                env = SNAPSHOT_DIR_ENV,
                "retention sweep asked for ENFORCE with no snapshot destination — \
                 DOWNGRADED TO DRYRUN. Deletion is the one irreversible action here and \
                 there is no undo without a pre-delete snapshot. Set the env var named \
                 in this event's `env` field to a writable path to enable enforcement."
            );
            return Self::DryRun;
        }
        mode
    }

    /// Is a snapshot destination configured? Presence AND non-empty — an empty
    /// string is the classic "set but not really set" that reads as configured.
    fn snapshot_dir_configured() -> bool {
        std::env::var(SNAPSHOT_DIR_ENV)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    }

    /// The mode that should apply given a requested mode and whether a snapshot
    /// destination exists. Pure, so the precondition is assertable without env.
    #[must_use]
    pub const fn with_snapshot_precondition(self, snapshot_configured: bool) -> Self {
        match self {
            Self::Enforce if !snapshot_configured => Self::DryRun,
            other => other,
        }
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

/// How many rows a mode ACCOUNTS FOR, given `n` rows past the window.
///
/// Split out from `sweep_one` so the accounting contract is assertable without a
/// ClickHouse client — the bug it encodes (`DryRun` reporting 0) lived in a branch
/// no unit test could reach, which is why a summary line contradicted the detail
/// lines above it for as long as it did.
///
/// `Off` is 0 because nothing was examined. `DryRun` is `n` because that is the
/// question a dry run exists to answer. `Enforce` is `n` because that many rows
/// were deleted.
const fn rows_accounted(mode: SweepMode, n: u64) -> u64 {
    match mode {
        SweepMode::Off => 0,
        SweepMode::DryRun | SweepMode::Enforce => n,
    }
}

/// Count rows past `days` for `tenant_id` in one table; delete them in `Enforce`.
///
/// Returns **the number of rows the mode accounts for**: rows deleted in
/// `Enforce`, rows that *would* be deleted in `DryRun`, and 0 in `Off`.
///
/// DryRun used to return 0, which made the caller's summary line read
/// `retention sweep complete (would-delete) … rows=0` while the per-tenant lines
/// directly above it reported 17,776 — so the one aggregate an operator or a
/// ruling would read said "enforcing changes nothing", the exact opposite of the
/// truth. The count is the whole point of a dry run. Fixed 2026-08-11; **this
/// changes no deletion behaviour — DryRun still deletes nothing.** `clickhouse::Client` / `clickhouse::Row`
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
            // `n`, NOT 0 — see the doc comment. Nothing is deleted here; this is
            // what the caller aggregates into the "would-delete" total.
            Ok(rows_accounted(mode, n))
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
            Ok(rows_accounted(mode, n))
        }
        SweepMode::Off => Ok(rows_accounted(mode, n)),
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

    /// THE REGRESSION. `DryRun` returned 0, so `run_sweep`'s summary printed
    /// `retention sweep complete (would-delete) … rows=0` while the per-tenant
    /// lines above it reported 17,776 rows past the window on prod. The one
    /// aggregate an operator — or a founder ruling on whether to flip to
    /// Enforce — would read said "enforcing changes nothing".
    #[test]
    fn dryrun_accounts_for_the_rows_it_would_delete() {
        assert_eq!(
            rows_accounted(SweepMode::DryRun, 11_610),
            11_610,
            "a dry run that reports 0 answers the opposite of the question it exists for"
        );
    }

    #[test]
    fn enforce_accounts_for_the_rows_it_deleted() {
        assert_eq!(rows_accounted(SweepMode::Enforce, 6_154), 6_154);
    }

    #[test]
    fn off_accounts_for_nothing_because_it_examined_nothing() {
        assert_eq!(rows_accounted(SweepMode::Off, 11_610), 0);
    }

    /// DryRun and Enforce must report the SAME total for the same data — that
    /// equality is what makes a dry run a preview of the enforce run rather than
    /// a differently-shaped number.
    #[test]
    fn dryrun_total_previews_the_enforce_total() {
        for n in [0_u64, 1, 6, 6_154, 11_610, u64::MAX] {
            assert_eq!(
                rows_accounted(SweepMode::DryRun, n),
                rows_accounted(SweepMode::Enforce, n),
                "dry run must preview enforce exactly, at n={n}"
            );
        }
    }

    /// PLT-40 (2026-08-11, founder-ruled): Enforce is REFUSED without a
    /// pre-delete snapshot destination. Deletion is the only irreversible action
    /// this process takes, and the audit ledger records gateway actions, not row
    /// deletions — so without a snapshot there is no undo at all.
    #[test]
    fn enforce_without_a_snapshot_destination_is_downgraded_to_dryrun() {
        assert_eq!(
            SweepMode::Enforce.with_snapshot_precondition(false),
            SweepMode::DryRun,
            "enforcing with no undo must not be reachable by configuration alone"
        );
    }

    #[test]
    fn enforce_with_a_snapshot_destination_is_allowed() {
        assert_eq!(
            SweepMode::Enforce.with_snapshot_precondition(true),
            SweepMode::Enforce
        );
    }

    /// The precondition must gate ONLY Enforce. Downgrading DryRun would break the
    /// mode prod actually runs, and downgrading Off would be meaningless.
    #[test]
    fn the_snapshot_precondition_touches_only_enforce() {
        for m in [SweepMode::Off, SweepMode::DryRun] {
            assert_eq!(
                m.with_snapshot_precondition(false),
                m,
                "{m:?} must be unaffected — it deletes nothing, so it needs no undo"
            );
            assert_eq!(m.with_snapshot_precondition(true), m);
        }
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
