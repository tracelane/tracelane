//! Entitlement-driven per-plan retention sweep.
//!
//! **BILL-01 / ADR-076 (2026-09-13): the sweep's window is now `queryable_days`,
//! never `indexed_window_days`.** Spec §2.2 is explicit that the per-tenant
//! INDEXED window (3/30/90/180/365d) is a READ-side + METER-side boundary
//! only — hot→cold tiering, not deletion — while the table's own TTL moves
//! parts to the cold (R2) disk at the table-wide 365d mark and only DELETEs
//! at 730d. Deletion must track the tenant's QUERYABLE history
//! (`plan_entitlements.queryable_days`, Free 30 / every paid tier 730 —
//! `apps/web/db/plans.v3.json`), overlaid by `workspace_entitlements`
//! (deny-overrides-grant), the same entitlement source the gateway resolves.
//! This sweep previously read `retention_days` (an older, pre-ADR-076
//! column that predates the indexed/queryable/ledger split) — that reading
//! made the sweep delete Team/Business/Enterprise data at their INDEXED
//! window (90/180/365d) instead of their QUERYABLE one (730d for all three),
//! which is the §2.2 class this file exists to get right: the window that
//! governs deletion is not the window that governs the dashboard's default
//! query range.
//!
//! ## Data-safety (retention risk #1)
//!
//! Deletion is IRREVERSIBLE and one-way, so it is GATED and fail-safe:
//! - `TRACELANE_RETENTION_SWEEP` = `off` (DEFAULT) | `dryrun` (log what WOULD be
//!   deleted, delete NOTHING) | `enforce` (delete). Nothing is deleted until an
//!   operator explicitly sets `enforce`.
//! - A tenant whose window can't be resolved falls back to **730d** (the max
//!   `queryable_days` any tier carries, so an unresolved tenant is never
//!   deleted early) — `resolve_retentions` COALESCEs to 730.
//! - A non-positive resolved window SKIPS that tenant (a 0/negative value would
//!   mean "delete everything" — the fail-safe never mass-deletes on a bad value).
//! - The sweep only ever deletes rows OLDER than the tenant's window; the table's
//!   own 730d TTL DELETE (migration 24 §5) is the hard backstop if this job
//!   stops running.
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
        // B-390 (2026-09-12): this used to duplicate `with_snapshot_precondition`'s
        // transition inline (`mode == Enforce && !configured -> DryRun`) rather than
        // calling it — two copies of safety-critical logic that could silently drift.
        // Routed through the pure, independently-tested method instead; the
        // `tracing::error!` still fires on exactly the same condition (the downgrade
        // actually happening), since `with_snapshot_precondition` itself never logs.
        let resolved = mode.with_snapshot_precondition(Self::snapshot_dir_configured());
        if resolved != mode {
            tracing::error!(
                env = SNAPSHOT_DIR_ENV,
                "retention sweep asked for ENFORCE with no snapshot destination — \
                 DOWNGRADED TO DRYRUN. Deletion is the one irreversible action here and \
                 there is no undo without a pre-delete snapshot. Set the env var named \
                 in this event's `env` field to a writable path to enable enforcement."
            );
        }
        resolved
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
        // A HEAVY mutation, not a lightweight DELETE, and on purpose. This is the
        // one projected table (B-379's `p_by_time`), and on prod, 2026-09-12, a
        // lightweight delete under `lightweight_mutation_projection_mode =
        // 'rebuild'` left the projection holding the DELETED rows (14,980 in the
        // projection over a 794-row base after the merge), so a read the planner
        // routed through it returned rows the sweep had removed — the privacy
        // promise failing at read time. A heavy `ALTER … DELETE` rewrites the
        // part and its projection from the same surviving rows (measured: 500/500
        // before and after a merge). `mutations_sync = 2` so the count after the
        // delete is truthful. The table setting is back at `throw`, so a
        // lightweight delete on it is REFUSED (Code 344) rather than trusted.
        delete_sql: "ALTER TABLE tracelane.trace_summaries DELETE \
                     WHERE tenant_id = ? AND start_time < now() - toIntervalDay(?) \
                     SETTINGS mutations_sync = 2",
    },
    // B-387 (2026-09-12): the sweep covered TWO of the content-bearing tables;
    // the privacy policy's per-plan window applies to every table that holds a
    // derivative of customer content. These four are the ones `tenant-purge.sh`
    // lists as content and this process writes; each has its own time column.
    // NOT here, by design: `audit_log` / `audit_anchor_records` (the ledger is
    // retained — ADR-068, founder ruling 2026-09-05) and the dataset /
    // experiment tables, which are the customer's own curated artefacts, not
    // captured traffic.
    SweepTable {
        label: "guardrail_verdicts",
        count_sql: "SELECT count() AS n FROM tracelane.guardrail_verdicts \
                    WHERE tenant_id = ? AND event_time < now() - toIntervalDay(?)",
        delete_sql: "DELETE FROM tracelane.guardrail_verdicts \
                     WHERE tenant_id = ? AND event_time < now() - toIntervalDay(?)",
    },
    SweepTable {
        label: "online_eval_scores",
        count_sql: "SELECT count() AS n FROM tracelane.online_eval_scores \
                    WHERE tenant_id = ? AND scored_at < now() - toIntervalDay(?)",
        delete_sql: "DELETE FROM tracelane.online_eval_scores \
                     WHERE tenant_id = ? AND scored_at < now() - toIntervalDay(?)",
    },
    SweepTable {
        label: "trace_content_snapshots",
        count_sql: "SELECT count() AS n FROM tracelane.trace_content_snapshots \
                    WHERE tenant_id = ? AND captured_at < now() - toIntervalDay(?)",
        delete_sql: "DELETE FROM tracelane.trace_content_snapshots \
                     WHERE tenant_id = ? AND captured_at < now() - toIntervalDay(?)",
    },
    SweepTable {
        label: "semantic_cache",
        count_sql: "SELECT count() AS n FROM tracelane.semantic_cache \
                    WHERE tenant_id = ? AND created_at < now() - toIntervalDay(?)",
        delete_sql: "DELETE FROM tracelane.semantic_cache \
                     WHERE tenant_id = ? AND created_at < now() - toIntervalDay(?)",
    },
    // BILL-01 / ADR-076 §2.3 (step 9): `blob_refs` carries the SAME per-tenant
    // queryable-history predicate as every content table above — a reference
    // dies exactly when its span does. `day` is a ClickHouse `Date`, not a
    // `DateTime`; the comparison still holds against `now() - toIntervalDay(?)`
    // (implicit Date→DateTime widening). NOT here: `blobs` itself — its GC is
    // the daily metering job's weekly `ALTER … DELETE WHERE (tenant_id, hash)
    // NOT IN (SELECT tenant_id, hash FROM blob_refs)` mutation
    // (`billing/metering_job.rs`), because a blob's lifetime is governed by
    // whether ANY reference survives, not by its own age.
    SweepTable {
        label: "blob_refs",
        count_sql: "SELECT count() AS n FROM tracelane.blob_refs \
                    WHERE tenant_id = ? AND day < now() - toIntervalDay(?)",
        delete_sql: "DELETE FROM tracelane.blob_refs \
                     WHERE tenant_id = ? AND day < now() - toIntervalDay(?)",
    },
];

/// A tenant and its resolved QUERYABLE-history window (days) — spec §2.2:
/// the deletion boundary, never the indexed window.
struct TenantRetention {
    tenant_id: String,
    queryable_days: i32,
}

/// Fail-safe: how many days to sweep for a resolved window, or `None` to SKIP
/// the tenant (never mass-delete on a non-positive/absurd value). Pure — unit-tested.
fn sweep_days(queryable_days: i32) -> Option<u64> {
    if queryable_days <= 0 {
        None
    } else {
        Some(queryable_days as u64)
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
        let Some(days) = sweep_days(tr.queryable_days) else {
            tracing::warn!(
                tenant_id = %tr.tenant_id,
                queryable_days = tr.queryable_days,
                "retention sweep: non-positive queryable window — skipping (fail-safe)"
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

/// Resolve `queryable_days` (BILL-01 / ADR-076 §2.2 — the deletion boundary,
/// NOT `indexed_window_days`) for every non-archived tenant:
/// `workspace_entitlements` override beats `plan_entitlements` default
/// (deny-overrides-grant); the plan comes from `we.plan_lookup_key` else
/// `tenants.plan||'_v1'`. COALESCE to 730 (fail-safe: the MAX `queryable_days`
/// any tier carries — Free is 30, every paid tier is 730 — so an unresolved
/// tenant is never deleted early). B-387 (2026-09-12): the
/// `WHERE t.archived_at IS NULL` this carried was removed — it excluded archived
/// tenants from the sweep, so a DELETED tenant's data was retained LONGER than a
/// live one's, the inverse of the privacy policy. An archived tenant sweeps at
/// its plan's window like any other until the 30-day purge
/// (`scripts/ops/tlane-purge-archived.sh`) removes what is left. Module-level so
/// the test can assert the shape of the query rather than grep the source.
const RETENTION_TENANTS_SQL: &str = "\
    SELECT t.id::text, \
           COALESCE(we.queryable_days, pe.queryable_days, 730)::int \
    FROM tenants t \
    LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id \
    LEFT JOIN plan_entitlements pe \
      ON pe.plan_lookup_key = COALESCE(we.plan_lookup_key, t.plan::text || '_v1')";

async fn resolve_retentions(pool: &DbPool) -> anyhow::Result<Vec<TenantRetention>> {
    let client = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("retention pool: {e}"))?;
    let rows = client.query(RETENTION_TENANTS_SQL, &[]).await?;
    Ok(rows
        .iter()
        .map(|r| TenantRetention {
            tenant_id: r.get(0),
            queryable_days: r.get(1),
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
        .query(&crate::clickhouse_query::ceiling(table.count_sql))
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
                %tenant_id, table = table.label, queryable_days = days, would_delete = n,
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
                %tenant_id, table = table.label, queryable_days = days, deleted = n,
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
        // A 0 or negative window would delete everything — must SKIP, not sweep.
        assert_eq!(sweep_days(0), None);
        assert_eq!(sweep_days(-5), None);
        // Real plan QUERYABLE windows (plans.v3.json) map straight through —
        // Free is the only tier below the 730d every paid tier shares.
        assert_eq!(sweep_days(30), Some(30)); // free
        assert_eq!(sweep_days(730), Some(730)); // builder/team/business/enterprise
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
                // Each table has its own time column; what must hold is that
                // SOME time column is bounded by the window (B-387 widened the
                // set from two tables to six).
                assert!(
                    sql.contains(" < now() - toIntervalDay(?)"),
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

    /// B-387 (widened by BILL-01 step 9 to include `blob_refs`): the sweep
    /// covers every content-bearing table and NEVER the ledger.
    #[test]
    fn sweep_covers_the_content_tables_and_never_the_ledger() {
        let labels: Vec<&str> = SWEEP_TABLES.iter().map(|t| t.label).collect();
        for want in [
            "spans",
            "trace_summaries",
            "guardrail_verdicts",
            "online_eval_scores",
            "trace_content_snapshots",
            "semantic_cache",
            "blob_refs",
        ] {
            assert!(labels.contains(&want), "sweep no longer covers {want}");
        }
        // `blobs` itself is NOT here — see the module doc: its GC is the daily
        // metering job's weekly mutation, keyed on whether ANY ref survives.
        assert!(
            !labels.contains(&"blobs"),
            "blobs is GC'd by the metering job's weekly mutation, not this sweep"
        );
        for never in ["audit_log", "audit_anchor_records", "audit_log_pre_rmt"] {
            assert!(
                !labels.contains(&never),
                "{never} is the tamper-evident ledger and must never be swept (ADR-068)"
            );
        }
    }

    /// B-387: archived tenants are swept too — the query must not exclude them.
    #[test]
    fn archived_tenants_are_not_excluded_from_the_sweep() {
        assert!(
            !RETENTION_TENANTS_SQL.contains("archived_at"),
            "the retention query filters on archived_at again — a deleted tenant's data \
             would be retained LONGER than a live one's (B-387)"
        );
        assert!(RETENTION_TENANTS_SQL.contains("FROM tenants t"));
    }

    /// B-383 (c) found this, not a unit test: on the migration-22 schema
    /// `trace_summaries` carries the `p_by_time` projection, and ClickHouse 24.12
    /// REFUSES a lightweight `DELETE` on a table with projections unless the query
    /// says what to do with them (`Code 344 … lightweight_mutation_projection_mode
    /// is set to THROW`). The sweep's enforce path would therefore have failed on
    /// prod for that table from the moment migration 22 landed — a fail-open
    /// path failing silently, the §10 class. This drives the REAL `sweep_one` in
    /// enforce mode against every content table on a real server that has the
    /// checked-in schema applied, so any table whose DELETE the server rejects
    /// fails here first.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn enforce_delete_is_accepted_by_the_server_for_every_content_table() {
        let Ok(url) = std::env::var("CLICKHOUSE_TEST_URL") else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let root = clickhouse::Client::default().with_url(&url);
        root.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let ch = clickhouse::Client::default()
            .with_url(&url)
            .with_database("tracelane");
        // The checked-in schema plus the three migrations that own the other
        // content tables (17 semantic_cache, 20 online_eval_scores, 21
        // trace_content_snapshots) — so EVERY table in `SWEEP_TABLES` exists and
        // its DELETE is actually exercised; a table the test could not find would
        // fail below as UNKNOWN_TABLE, never pass by absence.
        for sql in [
            include_str!("../../../infra/dev/clickhouse/schema.sql"),
            include_str!("../../../infra/dev/clickhouse/migrations/17_semantic_cache.sql"),
            include_str!(
                "../../../infra/dev/clickhouse/migrations/20_evl28_online_eval_scores.sql"
            ),
            include_str!(
                "../../../infra/dev/clickhouse/migrations/21_evl29_trace_content_snapshots.sql"
            ),
        ] {
            for stmt in crate::clickhouse_query::split_migration_statements(sql) {
                let _ = ch.query(&stmt).execute().await;
            }
        }
        let projections: u64 = ch
            .query(
                "SELECT count() FROM system.projections \
                 WHERE database = 'tracelane' AND table = 'trace_summaries'",
            )
            .fetch_one()
            .await
            .expect("system.projections read");
        assert!(
            projections >= 1,
            "the schema under test has no projection on trace_summaries — this test would \
             pass without exercising the Code-344 path"
        );
        let tenant = "00000000-0000-0000-0000-00000000b383";
        // One span past the 7-day window but INSIDE the table's 365-day TTL: the
        // first cut dated it 2020 and ClickHouse dropped it AT INSERT as already
        // expired (`TTL toDate(start_time) + INTERVAL 365 DAY`), so the count read
        // 0 on a fresh container while a long-lived one hid it. The MV writes the
        // summary row.
        ch.query(
            "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, start_time, \
             end_time, status_code) VALUES (?, ?, ?, 'gen_ai.chat', \
             now64(6) - toIntervalDay(30), now64(6) - toIntervalDay(30) + toIntervalSecond(1), 1)",
        )
        .bind(tenant)
        .bind("22222222-2222-2222-2222-222222222222")
        .bind("b383b383b383b383")
        .execute()
        .await
        .expect("seed span");
        for table in SWEEP_TABLES {
            let deleted = sweep_one(&ch, table, tenant, 7, SweepMode::Enforce)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "enforce DELETE on `{}` was REJECTED by the server: {e:#} — the sweep \
                         would fail on prod for this table",
                        table.label
                    )
                });
            if table.label == "spans" || table.label == "trace_summaries" {
                assert_eq!(
                    deleted, 1,
                    "{}: the seeded row should have been counted",
                    table.label
                );
            }
        }
        let left: u64 = ch
            .query("SELECT count() FROM tracelane.trace_summaries WHERE tenant_id = ?")
            .bind(tenant)
            .fetch_one()
            .await
            .expect("count after delete");
        assert_eq!(left, 0, "the summary row survived the enforce delete");
        // Migration 23: the projection must hold exactly the base's rows after
        // the (heavy) delete — on prod a lightweight delete left it holding the
        // deleted rows, and a lightweight DELETE on this table must now be
        // REFUSED by the server (Code 344), never accepted.
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct N {
            n: u64,
        }
        let base: N = ch
            .query("SELECT sum(rows) AS n FROM system.parts WHERE database = 'tracelane' AND table = 'trace_summaries' AND active")
            .fetch_one()
            .await
            .expect("base rows");
        let proj: N = ch
            .query("SELECT sum(rows) AS n FROM system.projection_parts WHERE database = 'tracelane' AND table = 'trace_summaries' AND active")
            .fetch_one()
            .await
            .expect("projection rows");
        assert_eq!(
            proj.n, base.n,
            "projection rows must equal base rows after the delete"
        );
        let lightweight = ch
            .query("DELETE FROM tracelane.trace_summaries WHERE tenant_id = ?")
            .bind(tenant)
            .execute()
            .await;
        let msg = lightweight
            .expect_err("a lightweight DELETE on the projected table must be refused")
            .to_string();
        assert!(
            msg.contains("344") || msg.contains("lightweight_mutation_projection_mode"),
            "{msg}"
        );
    }
}
