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
//! heavy `ALTER DELETE` (CH 24.12). Counts are capped; both queries are tenant-scoped
//! (`WHERE tenant_id = ?`), satisfying the isolation guard.

use std::time::Duration;

use crate::billing::rating::RetentionSweepPolicy;
use crate::db::DbPool;
use tracelane_shared::degradation::{self, Degradation};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeleteOutcome {
    Done,
    SkippedPending,
    WaitExceeded,
    BudgetExhausted,
    Failed,
}

pub(crate) struct SweepRun {
    policy: RetentionSweepPolicy,
    deadline: tokio::time::Instant,
    statements_left: u64,
    mutations: u64,
    skipped: u64,
    failed: u64,
    budget_reported: bool,
}
impl SweepRun {
    pub(crate) fn new(policy: RetentionSweepPolicy) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            policy,
            deadline: now
                .checked_add(Duration::from_secs(policy.max_run_secs))
                .unwrap_or(now),
            statements_left: policy.max_mutations_per_run,
            mutations: 0,
            skipped: 0,
            failed: 0,
            budget_reported: false,
        }
    }
    fn skip(&mut self) {
        self.skipped += 1;
        degradation::note(Degradation::RetentionSweepSkipped);
    }
    fn failure(&mut self) {
        self.failed += 1;
        degradation::note(Degradation::RetentionSweepFailed);
    }
    fn exhausted(&mut self, mode: SweepMode) -> bool {
        if tokio::time::Instant::now() >= self.deadline
            || (mode == SweepMode::Enforce && self.statements_left == 0)
        {
            if !self.budget_reported {
                self.budget_reported = true;
                self.skip();
                tracing::warn!(
                    "retention sweep budget exhausted; remaining work waits for next slot"
                );
            }
            true
        } else {
            false
        }
    }
    fn finish(&self) {
        if self.skipped == 0 {
            degradation::resolve(Degradation::RetentionSweepSkipped);
        }
        if self.failed == 0 {
            degradation::resolve(Degradation::RetentionSweepFailed);
        }
    }
}

// System-wide mutation state has no tenant column: it only prevents submitting a
// tenant-scoped deletion. Failure to read it must never authorize a mutation.
const PENDING_MUTATIONS_SQL: &str = "SELECT count() AS n FROM system.mutations WHERE database = 'tracelane' AND table = ? AND is_done = 0";

/// Submit a deletion only after checking pending mutations and the run budget.
///
/// # Errors
/// Fail-CLOSED to new mutations when pending state is unreadable or time/budget
/// is exhausted; returns a counted `DeleteOutcome` instead of propagating errors.
/// Fail-OPEN for gateway availability. A timed-out submitted mutation may finish
/// on the server after the client stops waiting.
pub(crate) async fn delete_bounded(
    ch: &clickhouse::Client,
    label: &str,
    query: clickhouse::query::Query,
    run: &mut SweepRun,
) -> DeleteOutcome {
    if run.exhausted(SweepMode::Enforce) {
        return DeleteOutcome::BudgetExhausted;
    }
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct Pending {
        n: u64,
    }
    let wait_deadline = run.deadline.min(
        tokio::time::Instant::now()
            .checked_add(Duration::from_secs(run.policy.delete_wait_secs))
            .unwrap_or(run.deadline),
    );
    let pending = tokio::time::timeout_at(
        wait_deadline,
        ch.query(&crate::clickhouse_query::ceiling(PENDING_MUTATIONS_SQL))
            .bind(label)
            .fetch_one::<Pending>(),
    )
    .await;
    match pending {
        Ok(Ok(Pending { n })) if n > 0 => {
            run.skip();
            return DeleteOutcome::SkippedPending;
        }
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            // Fail-OPEN for service availability, CLOSED to mutations when state is unknown.
            run.failure();
            tracing::warn!(table = label, %error, "retention sweep: pending state unreadable; table skipped");
            return DeleteOutcome::Failed;
        }
        Err(error) => {
            run.failure();
            tracing::warn!(table = label, %error, "retention sweep: pending state timed out; table skipped");
            return DeleteOutcome::Failed;
        }
    }
    if run.exhausted(SweepMode::Enforce) {
        return DeleteOutcome::BudgetExhausted;
    }
    run.statements_left -= 1;
    run.mutations += 1;
    // No ceiling(): this SQL already has SETTINGS mutations_sync. A dropped HTTP
    // wait does not cancel the enqueued mutation (real-server survival test).
    let wait_deadline = run.deadline.min(
        tokio::time::Instant::now()
            .checked_add(Duration::from_secs(run.policy.delete_wait_secs))
            .unwrap_or(run.deadline),
    );
    match tokio::time::timeout_at(wait_deadline, query.execute()).await {
        Ok(Ok(())) => DeleteOutcome::Done,
        Err(_) => {
            run.skip();
            tracing::warn!(
                table = label,
                "retention sweep: mutation wait exceeded; queued mutation may still finish"
            );
            DeleteOutcome::WaitExceeded
        }
        Ok(Err(error)) => {
            run.failure();
            tracing::warn!(table = label, %error, "retention sweep: delete refused; table skipped");
            DeleteOutcome::Failed
        }
    }
}

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

/// The env var that names a snapshot destination. **Enforce is refused without it**
/// — see [`SweepMode::from_env`]. **B-452 (2026-09-22, §17): nothing in this module
/// WRITES a snapshot** — `grep -n 'std::fs\|tokio::fs' retention_sweep.rs` → 0. The
/// variable is a precondition the operator sets on purpose, not an undo that exists;
/// the founder's Batch 6 ruling left the snapshot unbuilt (retention's system of
/// record is Neon + the hourly ledger archive + the JetStream buffer, RI-06). The
/// comments below that once said "written" are corrected to say "named".
pub const SNAPSHOT_DIR_ENV: &str = "TRACELANE_RETENTION_SNAPSHOT_DIR";

impl SweepMode {
    /// Parse from `TRACELANE_RETENTION_SWEEP`. Unknown / unset → `Off` (deletion
    /// is strictly opt-in — an operator must ask for `dryrun`/`enforce`).
    ///
    /// **`Enforce` additionally requires a snapshot destination to be NAMED** and is
    /// downgraded to `DryRun` without one (2026-08-11, founder-ruled).
    ///
    /// Retention deletion is the only irreversible action this process takes, and
    /// it has **no undo in this module**: the audit ledger records gateway actions,
    /// not row deletions, so once a sweep ran the rows are gone from ClickHouse
    /// (the JetStream buffer and the hourly ledger archive are the recovery paths,
    /// RI-06 / ADR-078). The precondition was designed for a snapshot writer that was
    /// never built (B-452); it is kept at the mode boundary so the intent — an
    /// operator has to ask for deletion twice — survives, and so the day a writer
    /// exists it has a destination.
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
                 DOWNGRADED TO DRYRUN. Deletion is the one irreversible action here; \
                 the destination is a deliberate second opt-in (no snapshot is written \
                 by this process). Set the env var named \
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

/// RI-04 §9 Q4 (founder default, 2026-09-19): WALL-CLOCK slots, not a
/// boot-relative interval — two gateway processes booted at different times
/// never aligned their own timers on the old `SWEEP_INTERVAL`, so even with
/// the RI-04 leader guard below both would still ATTEMPT a run inside the same
/// rolling 6h window rather than converging on one actual run per slot. Four
/// slots a day, spaced like the old interval; see
/// [`secs_until_next_retention_slot`].
const RETENTION_SLOT_HOURS: [u32; 4] = [0, 6, 12, 18];
const RETENTION_SLOT_MINUTE: u32 = 20;
/// Delay before the first sweep, so a fresh node settles before any deletion.
const INITIAL_DELAY: Duration = Duration::from_secs(120);

/// Seconds from `now` until the next fixed retention-sweep slot
/// (00:20/06:20/12:20/18:20 UTC) — today's next slot if one remains, else
/// tomorrow's first. Mirrors `billing::metering_job::secs_until_next_daily`'s
/// same-day-else-tomorrow shape, generalised to more than one slot per day.
/// Never zero (`tokio::time::sleep(0)` would fire immediately and busy-loop).
fn secs_until_next_retention_slot(now: chrono::DateTime<chrono::Utc>) -> u64 {
    let today = now.date_naive();
    for &hour in &RETENTION_SLOT_HOURS {
        let at = today
            .and_hms_opt(hour, RETENTION_SLOT_MINUTE, 0)
            .unwrap_or_else(|| today.and_time(chrono::NaiveTime::MIN));
        if at > now.naive_utc() {
            return (at - now.naive_utc()).num_seconds().max(1) as u64;
        }
    }
    // Every slot today has passed — the first slot tomorrow.
    let tomorrow = today + chrono::Duration::days(1);
    let at = tomorrow
        .and_hms_opt(RETENTION_SLOT_HOURS[0], RETENTION_SLOT_MINUTE, 0)
        .unwrap_or_else(|| tomorrow.and_time(chrono::NaiveTime::MIN));
    (at - now.naive_utc()).num_seconds().max(1) as u64
}

/// One retention-bearing table + its tenant-scoped count/delete SQL. Literal
/// `FROM tracelane.<t>` + `WHERE tenant_id = ?` so the tenant-isolation CI guard
/// both passes AND stays effective (a future non-scoped edit would be caught).
struct SweepTable {
    label: &'static str,
    count_sql: &'static str,
    delete_sql: &'static str,
    /// RI-02 rule 5: rows whose `tenant_id` has NO `tenants` row — a purged tenant, or
    /// one that never existed (B-236's bench fixtures). `?` binds the FULL live tenant
    /// list; `sweep_orphans` refuses to run it on an empty list.
    orphan_count_sql: &'static str,
    orphan_delete_sql: &'static str,
}

const SWEEP_TABLES: &[SweepTable] = &[
    SweepTable {
        label: "outcomes",
        count_sql: "SELECT count() AS n FROM tracelane.outcomes WHERE tenant_id = ? AND recorded_at < now() - toIntervalDay(?)",
        delete_sql: "ALTER TABLE tracelane.outcomes DELETE WHERE tenant_id = ? AND recorded_at < now() - toIntervalDay(?) SETTINGS mutations_sync = 2",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.outcomes WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.outcomes DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    SweepTable {
        label: "spans",
        count_sql: "SELECT count() AS n FROM tracelane.spans \
                    WHERE tenant_id = ? AND start_time < now() - toIntervalDay(?)",
        delete_sql: "ALTER TABLE tracelane.spans DELETE \
                     WHERE tenant_id = ? AND start_time < now() - toIntervalDay(?) SETTINGS mutations_sync = 2",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.spans WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.spans DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
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
        orphan_count_sql: "SELECT count() AS n FROM tracelane.trace_summaries WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.trace_summaries DELETE \
                            WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
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
        delete_sql: "ALTER TABLE tracelane.guardrail_verdicts DELETE \
                     WHERE tenant_id = ? AND event_time < now() - toIntervalDay(?) SETTINGS mutations_sync = 2",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.guardrail_verdicts WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.guardrail_verdicts DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    SweepTable {
        label: "online_eval_scores",
        count_sql: "SELECT count() AS n FROM tracelane.online_eval_scores \
                    WHERE tenant_id = ? AND scored_at < now() - toIntervalDay(?)",
        delete_sql: "ALTER TABLE tracelane.online_eval_scores DELETE \
                     WHERE tenant_id = ? AND scored_at < now() - toIntervalDay(?) SETTINGS mutations_sync = 2",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.online_eval_scores WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.online_eval_scores DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    SweepTable {
        label: "trace_content_snapshots",
        count_sql: "SELECT count() AS n FROM tracelane.trace_content_snapshots \
                    WHERE tenant_id = ? AND captured_at < now() - toIntervalDay(?)",
        delete_sql: "ALTER TABLE tracelane.trace_content_snapshots DELETE \
                     WHERE tenant_id = ? AND captured_at < now() - toIntervalDay(?) SETTINGS mutations_sync = 2",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.trace_content_snapshots WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.trace_content_snapshots DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    SweepTable {
        label: "semantic_cache",
        count_sql: "SELECT count() AS n FROM tracelane.semantic_cache \
                    WHERE tenant_id = ? AND created_at < now() - toIntervalDay(?)",
        delete_sql: "ALTER TABLE tracelane.semantic_cache DELETE \
                     WHERE tenant_id = ? AND created_at < now() - toIntervalDay(?) SETTINGS mutations_sync = 2",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.semantic_cache WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.semantic_cache DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
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
        delete_sql: "ALTER TABLE tracelane.blob_refs DELETE \
                     WHERE tenant_id = ? AND day < now() - toIntervalDay(?) SETTINGS mutations_sync = 2",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.blob_refs WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.blob_refs DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
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
/// ClickHouse URL. Runs after `INITIAL_DELAY`, then on the fixed wall-clock
/// slots (RI-04 §9 Q4 — see [`secs_until_next_retention_slot`]).
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
            // RI-04: claimed before touching ClickHouse. Doubling this is 2×LOAD for
            // the same result, not a correctness hazard (spec §2a #6) — but the guard
            // costs nothing new here: it rides this slot's own Postgres round trip.
            crate::db::job_guard::run_claimed(&pool, "retention_sweep", || async {
                if let Err(e) = run_sweep(&pool, &ch_url, mode).await {
                    // Fail-safe: a resolution failure aborts the WHOLE run (no
                    // partial deletion on a bad tenant list); retry next slot.
                    tracing::error!(error = %e, "retention sweep run failed; retrying next slot");
                }
            })
            .await;
            tokio::time::sleep(std::time::Duration::from_secs(
                secs_until_next_retention_slot(chrono::Utc::now()),
            ))
            .await;
        }
    });
}

/// One sweep pass: resolve per-tenant retention, then trim each tenant/table.
async fn run_sweep(pool: &DbPool, ch_url: &str, mode: SweepMode) -> anyhow::Result<()> {
    let mut run = SweepRun::new(RetentionSweepPolicy::load(pool).await);
    // The wall limit also covers identity/control-plane reads, not only mutations.
    match tokio::time::timeout_at(run.deadline, run_sweep_inner(pool, ch_url, mode, &mut run)).await
    {
        Ok(result) => result,
        Err(_) => {
            run.skip();
            run.finish();
            tracing::warn!(
                mutations = run.mutations,
                skipped = run.skipped,
                failed = run.failed,
                "retention sweep wall budget exceeded; remaining work waits for next slot"
            );
            Ok(())
        }
    }
}

async fn run_sweep_inner(
    pool: &DbPool,
    ch_url: &str,
    mode: SweepMode,
    run: &mut SweepRun,
) -> anyhow::Result<()> {
    let tenants = resolve_retentions(pool).await.inspect_err(|_| {
        degradation::note(Degradation::RetentionSweepFailed);
    })?;
    let ch = crate::clickhouse_query::sweeper_client(ch_url.to_string());
    // Observe the authenticated identity once per process, retrying after a failed read.
    static IDENTITY: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    if let Err(error) = IDENTITY
        .get_or_try_init(|| async {
            let user = crate::clickhouse_query::current_user(&ch).await?;
            tracing::info!(ch_user = %user, "sweeper");
            Ok::<(), clickhouse::error::Error>(())
        })
        .await
    {
        run.failure();
        tracing::warn!(%error, "sweeper identity unavailable");
    }
    let mut total: u64 = 0;
    let mut swept = 0usize;
    'tenants: for tr in &tenants {
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
            if run.exhausted(mode) {
                break 'tenants;
            }
            match sweep_one(&ch, t, &tr.tenant_id, days, mode, run).await {
                Ok(n) => total += n,
                // A single tenant/table failure never aborts the run — skip + log.
                Err(e) => {
                    run.failure();
                    tracing::warn!(error = %e, tenant_id = %tr.tenant_id, table = t.label,
                        "retention sweep: tenant/table failed — skipping");
                }
            }
        }
    }
    // RI-02 rule 5, B-459 shape: rows of tenants RECORDED as purged. An unreadable
    // tombstone table (migration 0053 not applied, a Neon error) deletes NOTHING.
    let mut conflicts = 0;
    let orphans = match resolve_purged(pool).await {
        Ok(purged) => {
            conflicts = observe_tombstone_conflicts(&purged, &tenants, &run.policy);
            let ids = purged.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
            let targets = purge_targets(&ids, &tenants);
            sweep_orphans(&ch, &targets, mode, run).await
        }
        Err(e) => {
            run.failure();
            tracing::warn!(
                error = %e,
                "retention sweep: purged_tenants unreadable — orphan step skipped (fail-safe: nothing deleted)"
            );
            0
        }
    };
    total += orphans;
    run.finish();
    tracing::info!(
        ?mode,
        tenants = swept,
        rows = total,
        orphan_rows = orphans,
        conflicts,
        mutations = run.mutations,
        skipped = run.skipped,
        failed = run.failed,
        "retention sweep complete ({})",
        if mode == SweepMode::Enforce {
            "deleted"
        } else {
            "would-delete"
        }
    );
    Ok(())
}

/// B-459 (2026-09-29): every OTHER table `scripts/ops/tenant-purge.sh` deletes a tenant
/// from (`CH_PURGE`) — the SLO/operability aggregates, prompt and promotion history, and
/// the customer's own datasets and experiments. They carry no per-plan TIME window (the
/// B-387 note above says why the curated ones are excluded from it), but a PURGED tenant
/// must leave none of them behind: a stream replay resurrected one on 2026-09-20
/// (`runbooks/RCA-stream-replay-resurrected-a-purged-tenant.md`), and this boot-time orphan
/// step is the net for that. Orphan-swept only. Held equal to `CH_PURGE` in both directions
/// by `scripts/ci/check-orphan-sweep-covers-purge.py`.
///
/// A HEAVY `ALTER … DELETE`, not a lightweight one, on purpose: a lightweight DELETE needs
/// `ALTER UPDATE(_row_exists)`. The grants proof observed writes to that hidden mask
/// being accepted, but did NOT reproduce resurrection in its row readback. These
/// tables get `ALTER DELETE` only; no visibility-mask UPDATE permission. The mutation is issued only when the count found rows.
struct OrphanOnlyTable {
    label: &'static str,
    orphan_count_sql: &'static str,
    orphan_delete_sql: &'static str,
}

const ORPHAN_ONLY_TABLES: &[OrphanOnlyTable] = &[
    OrphanOnlyTable {
        label: "spend_hourly",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.spend_hourly WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.spend_hourly DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "slo_hourly_stats",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.slo_hourly_stats WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.slo_hourly_stats DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "slo_minute_stats",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.slo_minute_stats WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.slo_minute_stats DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "ttft_stats",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.ttft_stats WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.ttft_stats DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "token_economics",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.token_economics WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.token_economics DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "eval_runs",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.eval_runs WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.eval_runs DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "prompts",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.prompts WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.prompts DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "prompt_versions",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.prompt_versions WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.prompt_versions DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "promotion_decisions",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.promotion_decisions WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.promotion_decisions DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "rollback_events",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.rollback_events WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.rollback_events DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "datasets",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.datasets WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.datasets DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "dataset_items",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.dataset_items WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.dataset_items DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "dataset_snapshots",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.dataset_snapshots WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.dataset_snapshots DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "dataset_snapshot_items",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.dataset_snapshot_items WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.dataset_snapshot_items DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "experiments",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.experiments WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.experiments DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "experiment_arms",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.experiment_arms WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.experiment_arms DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "eval_run_items",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.eval_run_items WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.eval_run_items DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "blobs",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.blobs WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.blobs DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
    OrphanOnlyTable {
        label: "prompt_canaries",
        orphan_count_sql: "SELECT count() AS n FROM tracelane.prompt_canaries WHERE tenant_id IN ?",
        orphan_delete_sql: "ALTER TABLE tracelane.prompt_canaries DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2",
    },
];

/// Every orphan step, time-swept tables first: (label, count SQL, delete SQL).
fn orphan_steps() -> impl Iterator<Item = (&'static str, &'static str, &'static str)> {
    SWEEP_TABLES
        .iter()
        .map(|t| (t.label, t.orphan_count_sql, t.orphan_delete_sql))
        .chain(
            ORPHAN_ONLY_TABLES
                .iter()
                .map(|t| (t.label, t.orphan_count_sql, t.orphan_delete_sql)),
        )
}

/// RI-02 rule 5 — the orphan-tenant step, REDESIGNED by B-459 (2026-09-30).
///
/// Deletes, from every table in [`orphan_steps`], the rows of tenants RECORDED as
/// purged in Postgres `purged_tenants` (written by `scripts/ops/tenant-purge.sh` before
/// it deletes the tenant) — `WHERE tenant_id IN <purged ids>`. The 2026-09-12 restore and
/// the 2026-09-20 stream replay both put a purged tenant's rows back; this is the net.
///
/// WHY NOT "every tenant missing from `tenants`" (the RI-02 shape): the security review
/// of B-459 found that `NOT IN <live list>` deletes a LIVE tenant's rows whenever the list
/// is merely INCOMPLETE — a tenant created between the list read and the DELETE, or a
/// control plane restored to an earlier point in time. With B-459 that would have reached
/// datasets, prompts and experiments a customer cannot regenerate. A tombstone can only
/// name a tenant someone deliberately purged; losing one leaves orphans behind (the safe
/// direction), never deletes a live tenant. `purge_targets` also drops any purged id that
/// is somehow ALSO live.
///
/// # Errors
/// None returned — fault-tolerance path (CLAUDE.md §10): a failure here means the
/// orphans wait for the next slot, never that the sweep aborts.
async fn sweep_orphans(
    ch: &clickhouse::Client,
    targets: &[String],
    mode: SweepMode,
    run: &mut SweepRun,
) -> u64 {
    if !orphan_step_allowed(targets.len()) {
        // Nothing recorded as purged (or every recorded id is live): nothing to delete.
        return 0;
    }
    let ids: Vec<String> = targets.to_vec();
    let mut total = 0;
    for (label, count_sql, delete_sql) in orphan_steps() {
        if run.exhausted(mode) {
            break;
        }
        match sweep_orphans_one(ch, label, count_sql, delete_sql, &ids, mode, run).await {
            Ok(n) => total += n,
            Err(e) => {
                run.failure();
                tracing::warn!(error = %e, table = label,
                    "retention sweep: orphan step failed for a table — skipping");
            }
        }
    }
    total
}

/// ClickHouse's "table does not exist" (code 60, `UNKNOWN_TABLE`). Pure, so the one
/// error the orphan step treats as "nothing here" is pinned by a test; every other
/// error stays an error.
fn is_unknown_table(err: &str) -> bool {
    err.contains("UNKNOWN_TABLE") || err.contains("Code: 60.")
}

/// The orphan step runs only for a NON-EMPTY set of purged tenants (an empty bind is
/// never sent). Pure, so the decision is assertable without ClickHouse or Neon.
const fn orphan_step_allowed(live_tenants: usize) -> bool {
    live_tenants > 0
}

async fn sweep_orphans_one(
    ch: &clickhouse::Client,
    label: &'static str,
    orphan_count_sql: &'static str,
    orphan_delete_sql: &'static str,
    live_tenant_ids: &[String],
    mode: SweepMode,
    run: &mut SweepRun,
) -> anyhow::Result<u64> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct CountRow {
        n: u64,
    }
    if run.exhausted(mode) {
        return Ok(0);
    }
    let counted = match tokio::time::timeout_at(
        run.deadline,
        ch.query(&crate::clickhouse_query::ceiling(orphan_count_sql))
            .bind(live_tenant_ids)
            .fetch_one::<CountRow>(),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            run.skip();
            return Ok(0);
        }
    };
    let n = match counted {
        Ok(CountRow { n }) => n,
        // B-459: a purge-list table this deployment never created (e.g. migration 05's
        // operability tables are not on the hosted node) holds no rows to sweep. Any
        // OTHER error still propagates and is warned about by the caller.
        Err(e) if is_unknown_table(&e.to_string()) => {
            // Visible ONCE per table per process: a migration that never ran here is worth
            // one line, not one per sweep (.claude/rules/logging.md).
            static SEEN: std::sync::Mutex<Vec<&'static str>> = std::sync::Mutex::new(Vec::new());
            if let Ok(mut seen) = SEEN.lock()
                && !seen.contains(&label)
            {
                seen.push(label);
                tracing::info!(
                    table = label,
                    "retention sweep: table absent on this deployment — nothing to sweep"
                );
            }
            return Ok(0);
        }
        Err(e) => return Err(e.into()),
    };
    if n == 0 {
        return Ok(0);
    }
    match mode {
        SweepMode::DryRun => {
            tracing::info!(
                table = label,
                would_delete = n,
                "retention sweep [dryrun]: rows of recorded purges absent from the live tenant list"
            );
            Ok(rows_accounted(mode, n))
        }
        SweepMode::Enforce => {
            // A mutation, not a read (the caps are read protection; the count above is
            // capped). All sweep mutations use the heavy ALTER DELETE form.
            if delete_bounded(
                ch,
                label,
                ch.query(orphan_delete_sql).bind(live_tenant_ids), // "ALTER TABLE … DELETE": bounded mutation
                run,
            )
            .await
                != DeleteOutcome::Done
            {
                return Ok(0);
            }
            tracing::info!(
                table = label,
                deleted = n,
                "retention sweep [enforce]: deleted rows of recorded purges absent from the live tenant list (RI-02 rule 5)"
            );
            Ok(rows_accounted(mode, n))
        }
        SweepMode::Off => Ok(rows_accounted(mode, n)),
    }
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
///
/// B-409: `queryable_days` comes from the tenant's PINNED `plan_allowances` row
/// (`allowance_pin_join!`, the resolver's own rule) — a later ruling that
/// shortens the window must not delete a price-protected tenant's data early. A
/// missing row keeps the 730-day fail-safe: never delete early.
const RETENTION_TENANTS_SQL: &str = concat!(
    "\
    SELECT t.id::text, \
           COALESCE(we.queryable_days, pa.queryable_days, 730)::int \
    FROM tenants t \
    LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id",
    crate::entitlement_cache::allowance_pin_join!(
        "COALESCE(we.plan_lookup_key, t.plan::text || '_v1')"
    ),
);

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

/// B-459: the tombstones `scripts/ops/tenant-purge.sh` writes (migration 0053).
// ponytail: the purged ids are bound as ONE array literal in the SQL text, so ClickHouse's
// default 256 KiB `max_query_size` caps a single orphan step near ~6,500 purged tenants;
// past that every table's step errors (fail-safe — nothing deleted, warned per table).
// Chunk the id list when `purged_tenants` approaches that.
const PURGED_TENANTS_SQL: &str =
    "SELECT tenant_id::text, EXTRACT(EPOCH FROM (now() - purged_at))::float8 FROM purged_tenants";

async fn resolve_purged(pool: &DbPool) -> anyhow::Result<Vec<(String, f64)>> {
    let client = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("retention pool: {e}"))?;
    let rows = client.query(PURGED_TENANTS_SQL, &[]).await?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, f64>(1)))
        .collect())
}

fn tombstone_conflicts(
    purged: &[(String, f64)],
    live: &[TenantRetention],
    grace_secs: f64,
) -> Vec<String> {
    let live = live
        .iter()
        .map(|t| t.tenant_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut conflicts = purged
        .iter()
        .filter(|(id, age)| live.contains(id.as_str()) && *age > grace_secs)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    conflicts.sort();
    conflicts.dedup();
    conflicts
}

fn observe_tombstone_conflicts(
    purged: &[(String, f64)],
    live: &[TenantRetention],
    policy: &RetentionSweepPolicy,
) -> usize {
    let conflicts = tombstone_conflicts(
        purged,
        live,
        policy.tombstone_live_grace_hours as f64 * 3600.0,
    );
    if conflicts.is_empty() {
        degradation::resolve(Degradation::TombstoneLiveConflict);
    } else {
        degradation::note(Degradation::TombstoneLiveConflict);
        tracing::warn!(conflicts = conflicts.len(), tenant_ids = ?&conflicts[..conflicts.len().min(10)],
            "live tenant still has an aged purge tombstone: finish with tenant-purge.sh <id> --execute; only if deliberately abandoned, manually remove that tenant id from purged_tenants");
    }
    conflicts.len()
}

/// The ids the orphan step may delete: recorded as purged AND not live. Pure — the
/// "a live tenant is never a target" rule is pinned by a test, not by the SQL alone.
fn purge_targets(purged: &[String], live: &[TenantRetention]) -> Vec<String> {
    let live: std::collections::HashSet<&str> = live.iter().map(|t| t.tenant_id.as_str()).collect();
    let mut out: Vec<String> = purged
        .iter()
        .filter(|id| !live.contains(id.as_str()))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
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
    run: &mut SweepRun,
) -> anyhow::Result<u64> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct CountRow {
        n: u64,
    }
    if run.exhausted(mode) {
        return Ok(0);
    }
    let CountRow { n } = match tokio::time::timeout_at(
        run.deadline,
        ch.query(&crate::clickhouse_query::ceiling(table.count_sql))
            .bind(tenant_id)
            .bind(days)
            .fetch_one::<CountRow>(),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            run.skip();
            return Ok(0);
        }
    };
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
            if delete_bounded(
                ch,
                table.label,
                ch.query(table.delete_sql).bind(tenant_id).bind(days), // "ALTER TABLE … DELETE": bounded mutation
                run,
            )
            .await
                != DeleteOutcome::Done
            {
                return Ok(0);
            }
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
    #[test]
    fn outcomes_time_sweep_uses_plan_window_and_heavy_delete() {
        let table = SWEEP_TABLES
            .iter()
            .find(|t| t.label == "outcomes")
            .expect("outcomes must join the per-plan TIME sweep");
        assert_eq!(
            table.count_sql,
            "SELECT count() AS n FROM tracelane.outcomes WHERE tenant_id = ? AND recorded_at < now() - toIntervalDay(?)"
        );
        assert_eq!(
            table.delete_sql,
            "ALTER TABLE tracelane.outcomes DELETE WHERE tenant_id = ? AND recorded_at < now() - toIntervalDay(?) SETTINGS mutations_sync = 2"
        );
        assert_eq!(
            orphan_steps()
                .filter(|(label, _, _)| *label == "outcomes")
                .count(),
            1
        );
    }
    #[test]
    fn outcomes_expire_and_are_purgeable_with_heavy_delete_grant() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let read = |path: &str| std::fs::read_to_string(root.join(path)).unwrap();
        for path in [
            "infra/dev/clickhouse/migrations/33_outcomes.sql",
            "infra/dev/clickhouse/schema.sql",
        ] {
            let text = read(path);
            let table = text
                .split("CREATE TABLE IF NOT EXISTS tracelane.outcomes")
                .nth(1)
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            assert!(
                table.contains("TTL toDate(recorded_at) + INTERVAL 365 DAY"),
                "outcomes must mirror span TTL: {path}"
            );
        }
        let table = SWEEP_TABLES
            .iter()
            .find(|t| t.label == "outcomes")
            .expect("outcomes orphan sweep");
        assert_eq!(
            table.orphan_delete_sql,
            "ALTER TABLE tracelane.outcomes DELETE WHERE tenant_id IN ? SETTINGS mutations_sync = 2"
        );
        let purge = read("scripts/ops/tenant-purge.sh");
        assert!(
            purge
                .split("CH_PURGE=(")
                .nth(1)
                .unwrap()
                .split(')')
                .next()
                .unwrap()
                .split_whitespace()
                .any(|v| v == "outcomes")
        );
        // B-601 (merged 2026-10-01): deletes belong to tl_sweeper ONLY; the request-path
        // tl_gateway holds no delete of any kind.
        let grants = read("infra/prod/clickhouse/users.d/services.xml");
        let gateway = grants
            .split("<tl_gateway>")
            .nth(1)
            .and_then(|b| b.split("</tl_gateway>").next())
            .expect("tl_gateway block");
        let sweeper = grants
            .split("<tl_sweeper>")
            .nth(1)
            .and_then(|b| b.split("</tl_sweeper>").next())
            .expect("tl_sweeper block");
        assert!(sweeper.contains("GRANT SELECT, ALTER DELETE ON tracelane.outcomes</query>"));
        assert!(!gateway.contains("tracelane.outcomes"));
        assert!(!grants.contains("ALTER UPDATE(_row_exists) ON tracelane.outcomes"));
    }
    use super::*;

    fn proof_policy() -> RetentionSweepPolicy {
        RetentionSweepPolicy {
            delete_wait_secs: 2,
            max_mutations_per_run: 3,
            max_run_secs: 30,
            tombstone_live_grace_hours: 36,
        }
    }

    async fn proof_table(name: &str) -> clickhouse::Client {
        let ch = clickhouse::Client::default()
            .with_url(std::env::var("CLICKHOUSE_TEST_URL").expect("throwaway URL"));
        ch.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        ch.query(&format!("DROP TABLE IF EXISTS tracelane.{name}"))
            .execute()
            .await
            .unwrap();
        ch.query(&format!("CREATE TABLE tracelane.{name} (tenant_id String, value UInt8) ENGINE=MergeTree ORDER BY (tenant_id, value)")).execute().await.unwrap();
        ch.query(&format!(
            "INSERT INTO tracelane.{name} VALUES ('a',1),('a',2),('b',1)"
        ))
        .execute()
        .await
        .unwrap();
        ch
    }
    async fn proof_count(ch: &clickhouse::Client, sql: &str) -> u64 {
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct N {
            n: u64,
        }
        ch.query(sql).fetch_one::<N>().await.unwrap().n
    }

    #[test]
    fn tombstone_conflict_boundary_and_live_filter() {
        let live = vec![TenantRetention {
            tenant_id: "live".into(),
            queryable_days: 30,
        }];
        assert!(tombstone_conflicts(&[], &live, 36.0).is_empty());
        assert!(
            tombstone_conflicts(
                &[("live".into(), 35.999), ("gone".into(), 72.0)],
                &live,
                36.0
            )
            .is_empty()
        );
        assert!(tombstone_conflicts(&[("live".into(), 36.0)], &live, 36.0).is_empty());
        assert_eq!(
            tombstone_conflicts(
                &[("live".into(), 36.001), ("gone".into(), 72.0)],
                &live,
                36.0
            ),
            vec!["live".to_string()]
        );
    }

    async fn tombstone_pg_fixture() -> DbPool {
        let config: tokio_postgres::Config = std::env::var("POSTGRES_TEST_URL")
            .expect("throwaway Postgres URL")
            .parse()
            .unwrap();
        let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ))
        .max_size(1)
        .build()
        .unwrap();
        {
            // Session-local tables: no application database is migrated or seeded.
            let pg = pool.get().await.unwrap();
            pg.batch_execute("CREATE TEMP TABLE tenants (id uuid, plan text, plan_version text, price_protected_until timestamptz);
                CREATE TEMP TABLE workspace_entitlements (tenant_id uuid, queryable_days int, plan_lookup_key text);
                CREATE TEMP TABLE plan_entitlements (plan_lookup_key text, queryable_days int);
                CREATE TEMP TABLE plan_allowances (plan_version text, plan_lookup_key text, queryable_days int, is_current boolean);
                INSERT INTO plan_allowances VALUES ('v3', 'free_v1', 30, true);
                CREATE TEMP TABLE purged_tenants (tenant_id uuid, purged_at timestamptz NOT NULL DEFAULT now());
                CREATE TEMP TABLE billing_policy (key text, value jsonb);
                INSERT INTO tenants VALUES ('00000000-0000-0000-0000-00000000fa11', 'free', NULL, NULL);
                INSERT INTO plan_entitlements VALUES ('free_v1', 30);
                INSERT INTO purged_tenants VALUES ('00000000-0000-0000-0000-00000000fa11', now() - interval '72 hours');").await.unwrap();
        }
        pool
    }

    #[tokio::test]
    #[ignore = "throwaway Postgres; run-postgres-integration.sh"]
    async fn postgres_retention_tombstone_and_policy_roundtrip() {
        let pool = tombstone_pg_fixture().await;
        let live = resolve_retentions(&pool).await.unwrap();
        let purged = resolve_purged(&pool).await.unwrap();
        let policy = RetentionSweepPolicy::load(&pool).await;
        assert_eq!(
            policy,
            RetentionSweepPolicy::embedded(),
            "missing row fallback"
        );
        let before = degradation::count(Degradation::TombstoneLiveConflict);
        assert_eq!(observe_tombstone_conflicts(&purged, &live, &policy), 1);
        assert!(degradation::count(Degradation::TombstoneLiveConflict) > before);
        assert!(
            degradation::snapshot()
                .iter()
                .any(|s| s.kind == "tombstone_live_conflict" && s.open)
        );
        assert!(
            purge_targets(
                &purged.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>(),
                &live
            )
            .is_empty()
        );
        {
            let pg = pool.get().await.unwrap();
            pg.batch_execute("UPDATE purged_tenants SET purged_at = now() - interval '1 hour';
                INSERT INTO billing_policy VALUES ('retention_sweep', '{\"delete_wait_secs\":1,\"max_mutations_per_run\":2,\"max_run_secs\":3,\"tombstone_live_grace_hours\":4}');").await.unwrap();
        }
        let custom = RetentionSweepPolicy::load(&pool).await;
        assert_eq!(
            custom,
            RetentionSweepPolicy {
                delete_wait_secs: 1,
                max_mutations_per_run: 2,
                max_run_secs: 3,
                tombstone_live_grace_hours: 4
            }
        );
        assert_eq!(
            observe_tombstone_conflicts(&resolve_purged(&pool).await.unwrap(), &live, &custom),
            0
        );
        assert!(
            degradation::snapshot()
                .iter()
                .any(|s| s.kind == "tombstone_live_conflict" && !s.open)
        );
        {
            let pg = pool.get().await.unwrap();
            pg.batch_execute("UPDATE billing_policy SET value = '{}'::jsonb")
                .await
                .unwrap();
        }
        assert_eq!(
            RetentionSweepPolicy::load(&pool).await,
            RetentionSweepPolicy::embedded(),
            "malformed row fallback"
        );
    }

    #[tokio::test]
    #[ignore = "both throwaway stores; run-ledger-integration.sh"]
    async fn retention_dual_store_live_conflict_never_deletes() {
        let pool = tombstone_pg_fixture().await;
        let ch = clickhouse::Client::default()
            .with_url(std::env::var("CLICKHOUSE_TEST_URL").expect("throwaway URL"));
        let live = resolve_retentions(&pool).await.unwrap();
        for sql in crate::clickhouse_query::split_migration_statements(include_str!(
            "../../../infra/dev/clickhouse/schema.sql"
        )) {
            ch.query(&sql).execute().await.unwrap();
        }
        ch.query("ALTER TABLE tracelane.guardrail_verdicts DELETE WHERE tenant_id = ? AND correlation_id = 'live-conflict' SETTINGS mutations_sync = 2").bind(&live[0].tenant_id).execute().await.unwrap();
        ch.query("INSERT INTO tracelane.guardrail_verdicts (tenant_id, correlation_id, event_time) VALUES (?, 'live-conflict', '2090-01-01')").bind(&live[0].tenant_id).execute().await.unwrap();
        let purged = resolve_purged(&pool).await.unwrap();
        let policy = RetentionSweepPolicy::embedded();
        assert_eq!(observe_tombstone_conflicts(&purged, &live, &policy), 1);
        let ids = purged.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
        let targets = purge_targets(&ids, &live);
        let mut run = SweepRun::new(policy);
        assert!(targets.is_empty());
        assert_eq!(
            sweep_orphans(&ch, &targets, SweepMode::Enforce, &mut run).await,
            0
        );
        assert_eq!(proof_count(&ch, "SELECT count() AS n FROM tracelane.guardrail_verdicts WHERE tenant_id='00000000-0000-0000-0000-00000000fa11' AND correlation_id='live-conflict'").await, 1);
        assert_eq!(run.mutations, 0);
        // The young twin must not alert either; neither age authorizes deletion.
        {
            let pg = pool.get().await.unwrap();
            pg.batch_execute("UPDATE purged_tenants SET purged_at=now()-interval '1 hour'")
                .await
                .unwrap();
        }
        assert_eq!(
            observe_tombstone_conflicts(&resolve_purged(&pool).await.unwrap(), &live, &policy),
            0
        );
    }
    #[test]
    fn retention_policy_is_seeded_and_forwarded() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json")).unwrap();
        let policy: RetentionSweepPolicy =
            serde_json::from_value(seed["policy"]["retention_sweep"].clone())
                .expect("reviewed policy row");
        assert_eq!(RetentionSweepPolicy::embedded(), policy);
        assert!(
            include_str!("../../../apps/web/db/seed.mjs")
                .contains("retention_sweep: pol.retention_sweep")
        );
        assert_eq!(policy.delete_wait_secs, 300);
        assert_eq!(policy.max_mutations_per_run, 400);
        assert_eq!(policy.max_run_secs, 3000);
        assert_eq!(policy.tombstone_live_grace_hours, 36);
    }

    #[tokio::test]
    #[ignore = "needs throwaway ClickHouse; run-clickhouse-integration.sh"]
    async fn retention_hardening_pending_skip() {
        let ch = proof_table("s1_pending").await;
        ch.query("SYSTEM STOP MERGES tracelane.s1_pending")
            .execute()
            .await
            .unwrap();
        ch.query("ALTER TABLE tracelane.s1_pending DELETE WHERE tenant_id = 'a' AND value = 1 SETTINGS mutations_sync = 0").execute().await.unwrap();
        let before = proof_count(&ch, "SELECT count() AS n FROM system.mutations WHERE database='tracelane' AND table='s1_pending'").await;
        let mut run = SweepRun::new(proof_policy());
        let result = tokio::time::timeout(Duration::from_secs(4), delete_bounded(&ch, "s1_pending", ch.query("ALTER TABLE tracelane.s1_pending DELETE WHERE tenant_id = 'a' SETTINGS mutations_sync = 2"), &mut run)).await;
        let after = proof_count(&ch, "SELECT count() AS n FROM system.mutations WHERE database='tracelane' AND table='s1_pending'").await;
        let table = SweepTable {
            label: "s1_pending",
            count_sql: "SELECT count() AS n FROM tracelane.s1_pending WHERE tenant_id = ? AND value > ?",
            delete_sql: "ALTER TABLE tracelane.s1_pending DELETE WHERE tenant_id = ? AND value > ? SETTINGS mutations_sync=2",
            orphan_count_sql: "SELECT count() AS n FROM tracelane.s1_pending WHERE tenant_id IN ?",
            orphan_delete_sql: "ALTER TABLE tracelane.s1_pending DELETE WHERE tenant_id IN ? SETTINGS mutations_sync=2",
        };
        let time_result = tokio::time::timeout(
            Duration::from_secs(4),
            sweep_one(&ch, &table, "a", 0, SweepMode::Enforce, &mut run),
        )
        .await;
        let orphan_result = tokio::time::timeout(
            Duration::from_secs(4),
            sweep_orphans_one(
                &ch,
                table.label,
                table.orphan_count_sql,
                table.orphan_delete_sql,
                &["a".into()],
                SweepMode::Enforce,
                &mut run,
            ),
        )
        .await;
        ch.query("SYSTEM START MERGES tracelane.s1_pending")
            .execute()
            .await
            .unwrap();
        assert_eq!(result.unwrap(), DeleteOutcome::SkippedPending);
        assert_eq!(time_result.unwrap().unwrap(), 0);
        assert_eq!(orphan_result.unwrap().unwrap(), 0);
        assert_eq!(proof_count(&ch, "SELECT count() AS n FROM system.mutations WHERE database='tracelane' AND table='s1_pending'").await, before);
        assert_eq!(before, after, "pending skip must submit no mutation");
        assert!(run.skipped > 0);
    }

    #[tokio::test]
    #[ignore = "needs throwaway ClickHouse; run-clickhouse-integration.sh"]
    async fn retention_hardening_wait_and_survival() {
        let ch = proof_table("s1_wait").await;
        ch.query("SYSTEM STOP MERGES tracelane.s1_wait")
            .execute()
            .await
            .unwrap();
        let before = degradation::count(Degradation::RetentionSweepSkipped);
        let mut run = SweepRun::new(proof_policy());
        let start = tokio::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(4), delete_bounded(&ch, "s1_wait", ch.query("ALTER TABLE tracelane.s1_wait DELETE WHERE tenant_id = 'a' SETTINGS mutations_sync = 2"), &mut run)).await;
        let pending = proof_count(&ch, "SELECT count() AS n FROM system.mutations WHERE database='tracelane' AND table='s1_wait' AND is_done=0").await;
        ch.query("SYSTEM START MERGES tracelane.s1_wait")
            .execute()
            .await
            .unwrap();
        assert_eq!(result.unwrap(), DeleteOutcome::WaitExceeded);
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(pending > 0, "mutation survives the dropped HTTP wait");
        assert!(degradation::count(Degradation::RetentionSweepSkipped) > before);
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if proof_count(&ch, "SELECT count() AS n FROM system.mutations WHERE database='tracelane' AND table='s1_wait' AND is_done=0").await == 0 { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(
            proof_count(
                &ch,
                "SELECT count() AS n FROM tracelane.s1_wait WHERE tenant_id='a'"
            )
            .await,
            0
        );
        assert_eq!(
            proof_count(
                &ch,
                "SELECT count() AS n FROM tracelane.s1_wait WHERE tenant_id='b'"
            )
            .await,
            1
        );
    }

    #[tokio::test]
    #[ignore = "needs throwaway ClickHouse; run-clickhouse-integration.sh"]
    async fn retention_hardening_statement_and_wall_budgets() {
        let ch = proof_table("s1_budget0").await;
        for i in 1..10 {
            proof_table(&format!("s1_budget{i}")).await;
        }
        let before = degradation::count(Degradation::RetentionSweepSkipped);
        let mut run = SweepRun::new(proof_policy());
        for i in 0..10 {
            let table = format!("s1_budget{i}");
            delete_bounded(&ch, &table, ch.query(&format!("ALTER TABLE tracelane.{table} DELETE WHERE tenant_id='a' SETTINGS mutations_sync=2")), &mut run).await;
        }
        assert_eq!(proof_count(&ch, "SELECT count() AS n FROM system.mutations WHERE database='tracelane' AND startsWith(table,'s1_budget')").await, 3);
        assert_eq!(run.mutations, 3);
        assert!(degradation::count(Degradation::RetentionSweepSkipped) > before);
        let mut run = SweepRun::new(proof_policy());
        run.deadline = tokio::time::Instant::now();
        assert_eq!(delete_bounded(&ch, "s1_budget9", ch.query("ALTER TABLE tracelane.s1_budget9 DELETE WHERE tenant_id='a' SETTINGS mutations_sync=2"), &mut run).await, DeleteOutcome::BudgetExhausted);
        assert_eq!(run.mutations, 0);
    }

    #[tokio::test]
    #[ignore = "needs throwaway ClickHouse; run-clickhouse-integration.sh"]
    async fn retention_hardening_failures_continue_and_settings_verdict() {
        let ch = proof_table("s1_failure").await;
        ch.query("DROP USER IF EXISTS s1_restricted")
            .execute()
            .await
            .unwrap();
        ch.query("CREATE USER s1_restricted")
            .execute()
            .await
            .unwrap();
        ch.query("GRANT SELECT ON system.mutations TO s1_restricted")
            .execute()
            .await
            .unwrap();
        let restricted = ch.clone().with_user("s1_restricted");
        let mut run = SweepRun::new(proof_policy());
        let before = degradation::count(Degradation::RetentionSweepFailed);
        assert_eq!(delete_bounded(&restricted, "s1_failure", restricted.query("ALTER TABLE tracelane.s1_failure DELETE WHERE tenant_id='a' SETTINGS mutations_sync=2"), &mut run).await, DeleteOutcome::Failed);
        assert!(degradation::count(Degradation::RetentionSweepFailed) > before);
        assert_eq!(delete_bounded(&ch, "s1_failure", ch.query("ALTER TABLE tracelane.s1_failure DELETE WHERE tenant_id='a' SETTINGS mutations_sync=2"), &mut run).await, DeleteOutcome::Done);
        let error = ch.query(&crate::clickhouse_query::ceiling("ALTER TABLE tracelane.s1_failure DELETE WHERE tenant_id='a' SETTINGS mutations_sync=2")).execute().await.unwrap_err();
        assert!(error.to_string().contains("SYNTAX_ERROR"), "{error}");
        let option_ch = proof_table("s1_option").await;
        option_ch
            .query("SYSTEM STOP MERGES tracelane.s1_option")
            .execute()
            .await
            .unwrap();
        let waited = tokio::time::timeout(Duration::from_secs(2), option_ch.query("ALTER TABLE tracelane.s1_option DELETE WHERE tenant_id='a' SETTINGS mutations_sync=2").with_option("max_execution_time", "1").execute()).await;
        option_ch
            .query("SYSTEM START MERGES tracelane.s1_option")
            .execute()
            .await
            .unwrap();
        assert!(
            waited.is_err(),
            "max_execution_time does not bound a mutation wait: {waited:?}"
        );
        // Drive the real loop: an early refused table must not hide a later permitted one.
        for sql in crate::clickhouse_query::split_migration_statements(include_str!(
            "../../../infra/dev/clickhouse/schema.sql"
        )) {
            ch.query(&sql).execute().await.unwrap();
        }
        ch.query("GRANT SELECT ON tracelane.* TO s1_restricted")
            .execute()
            .await
            .unwrap();
        ch.query("GRANT ALTER DELETE ON tracelane.guardrail_verdicts TO s1_restricted")
            .execute()
            .await
            .unwrap();
        ch.query("INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, start_time, end_time) VALUES ('00000000-0000-0000-0000-00000000fa12','00000000-0000-0000-0000-00000000fa12','s1', '2090-01-01','2090-01-01')").execute().await.unwrap();
        ch.query("INSERT INTO tracelane.guardrail_verdicts (tenant_id, correlation_id, event_time) VALUES ('00000000-0000-0000-0000-00000000fa12','s1','2090-01-01')").execute().await.unwrap();
        let mut loop_run = SweepRun::new(RetentionSweepPolicy::embedded());
        let deleted = sweep_orphans(
            &restricted,
            &["00000000-0000-0000-0000-00000000fa12".into()],
            SweepMode::Enforce,
            &mut loop_run,
        )
        .await;
        assert!(deleted > 0, "the later allowed table was still swept");
        assert!(loop_run.failed > 0);
        assert_eq!(proof_count(&ch, "SELECT count() AS n FROM tracelane.guardrail_verdicts WHERE tenant_id='00000000-0000-0000-0000-00000000fa12'").await, 0);
        assert!(proof_count(&ch, "SELECT count() AS n FROM tracelane.spans WHERE tenant_id='00000000-0000-0000-0000-00000000fa12'").await > 0);
        ch.query("DROP USER s1_restricted").execute().await.unwrap();
    }
    #[test]
    fn retention_deletes_are_heavy_and_tenant_first() {
        for table in SWEEP_TABLES {
            assert!(
                table.delete_sql.starts_with("ALTER TABLE tracelane."),
                "{} must use heavy delete",
                table.label
            );
            assert!(table.delete_sql.contains("WHERE tenant_id = ? AND"));
            assert!(table.delete_sql.ends_with("SETTINGS mutations_sync = 2"));
        }
        for (label, count, delete) in orphan_steps() {
            assert!(
                delete.starts_with("ALTER TABLE tracelane."),
                "{label} must use heavy delete"
            );
            assert!(delete.contains("WHERE tenant_id IN ?"));
            assert!(count.contains("WHERE tenant_id IN ?"));
            assert!(delete.ends_with("SETTINGS mutations_sync = 2"));
        }
    }

    /// B-459: only UNKNOWN_TABLE is "nothing to sweep"; a timeout, an auth refusal or a
    /// syntax error must still surface (must-reject twin in the same test).
    #[test]
    fn only_an_unknown_table_error_is_treated_as_nothing_to_sweep() {
        assert!(is_unknown_table(
            "bad response: Code: 60. DB::Exception: Table tracelane.ttft_stats does not exist. (UNKNOWN_TABLE)"
        ));
        assert!(!is_unknown_table(
            "bad response: Code: 497. DB::Exception: tl_gateway: Not enough privileges. (ACCESS_DENIED)"
        ));
        assert!(!is_unknown_table(
            "bad response: Code: 159. Timeout exceeded (TIMEOUT_EXCEEDED)"
        ));
        assert!(!is_unknown_table("Code: 600. something else"));
    }

    /// B-459 security review CRITICAL: a tenant absent from the live list is NOT a
    /// target unless it was recorded as purged; a purged id that is somehow live is
    /// never a target either.
    #[test]
    fn purge_targets_are_recorded_purges_that_are_not_live() {
        let live = vec![TenantRetention {
            tenant_id: "live".into(),
            queryable_days: 730,
        }];
        let purged = vec!["gone".to_string(), "live".to_string(), "gone".to_string()];
        assert_eq!(purge_targets(&purged, &live), vec!["gone".to_string()]);
        // A brand-new tenant missing from `live` is simply not in `purged`: untouched.
        assert!(purge_targets(&[], &live).is_empty());
        assert!(PURGED_TENANTS_SQL.contains("FROM purged_tenants"));
    }

    /// The orphan step never sends an EMPTY target list (nothing recorded as purged =
    /// nothing to do). Pure decision, pinned.
    #[test]
    fn orphan_step_refuses_an_empty_tenant_list() {
        assert!(!orphan_step_allowed(0));
        assert!(orphan_step_allowed(1));
        assert!(orphan_step_allowed(19));
    }

    /// RI-02 §2 guard, B-459 shape: every content table carries an orphan count + delete
    /// that filter on `tenant_id IN ?` (the RECORDED purged tenants) against the table the
    /// label names — never a different table, never unfiltered, never `NOT IN`.
    #[test]
    fn orphan_sql_exists_for_every_sweep_table_and_reads_the_live_tenant_list_from_tenants() {
        assert!(RETENTION_TENANTS_SQL.contains("FROM tenants t"));
        for (label, count_sql, delete_sql) in orphan_steps() {
            for sql in [count_sql, delete_sql] {
                assert!(
                    sql.contains(&format!("tracelane.{label} ")),
                    "{label}: orphan SQL names another table: {sql}"
                );
                assert!(
                    sql.contains("WHERE tenant_id IN ?") && !sql.contains("NOT IN"),
                    "{label}: orphan SQL must name purged tenants (IN), never exclude live ones (NOT IN): {sql}"
                );
            }
        }
        // 8 time-swept + 19 orphan-only = every CH_PURGE table (the guard holds the
        // names; this pins that nothing was silently dropped from either list).
        assert_eq!(
            orphan_steps().count(),
            SWEEP_TABLES.len() + ORPHAN_ONLY_TABLES.len()
        );
        assert_eq!(ORPHAN_ONLY_TABLES.len(), 19);
    }

    /// RI-02 §7 proofs 2 + 3(b), against a REAL ClickHouse (`run-clickhouse-integration.sh`).
    /// One orphan tenant (no `tenants` row) and one live tenant, one row each in all
    /// SEVEN time-swept tables plus the EIGHTEEN orphan-only ones (B-459). `sweep_orphans(Enforce)` with the live list → the orphan's
    /// rows are gone from every table and the bystander's are untouched (counted before
    /// and after). Then the fail-safe: an EMPTY list deletes nothing. RED first: with the
    /// orphan step absent this test's first assertion reads 7, not 0.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn ri02_orphan_step_deletes_purged_tenants_rows_and_spares_bystanders() {
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
        for sql in [
            include_str!("../../../infra/dev/clickhouse/schema.sql"),
            include_str!("../../../infra/dev/clickhouse/migrations/17_semantic_cache.sql"),
            include_str!(
                "../../../infra/dev/clickhouse/migrations/20_evl28_online_eval_scores.sql"
            ),
            include_str!(
                "../../../infra/dev/clickhouse/migrations/21_evl29_trace_content_snapshots.sql"
            ),
            // B-459: the orphan-only tables' homes.
            include_str!("../../../infra/dev/clickhouse/migrations/03_prompt_promotion.sql"),
            include_str!("../../../infra/dev/clickhouse/migrations/05_operability_mvs.sql"),
            include_str!(
                "../../../infra/dev/clickhouse/migrations/18_datasets_and_experiments.sql"
            ),
            include_str!("../../../infra/dev/clickhouse/migrations/19_evl02_experiment_arms.sql"),
            include_str!(
                "../../../infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql"
            ),
            include_str!("../../../infra/dev/clickhouse/migrations/30_prompt_canaries.sql"),
            include_str!("../../../infra/dev/clickhouse/migrations/33_outcomes.sql"),
        ] {
            for stmt in crate::clickhouse_query::split_migration_statements(sql) {
                let _ = ch.query(&stmt).execute().await;
            }
        }
        let orphan = uuid::Uuid::new_v4().to_string();
        let live = uuid::Uuid::new_v4().to_string();
        // B-459: in NO list at all — the tenant created between the list read and the
        // DELETE (or lost by a restored control plane). The old NOT-IN step deleted it.
        let unlisted = uuid::Uuid::new_v4().to_string();
        // (table, time column) — one row per tenant per table; a span also lands its
        // trace_summaries row through the MV, so that table is seeded by the span.
        let seeds: [(&str, &str); 7] = [
            ("outcomes", "recorded_at"),
            ("spans", "start_time"),
            ("guardrail_verdicts", "event_time"),
            ("online_eval_scores", "scored_at"),
            ("trace_content_snapshots", "captured_at"),
            ("semantic_cache", "created_at"),
            ("blob_refs", "day"),
        ];
        for tenant in [&orphan, &live, &unlisted] {
            for (table, col) in seeds {
                let sql = if table == "spans" {
                    "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, start_time, end_time, attributes) \
                     VALUES (?, ?, 'ri02span0000000', 'ri02 fixture', now64(6) - INTERVAL 1 HOUR, now64(6) - INTERVAL 1 HOUR, '{}')"
                        .to_string()
                } else if table == "blob_refs" {
                    format!("INSERT INTO tracelane.{table} (tenant_id, {col}) VALUES (?, today())")
                } else {
                    format!(
                        "INSERT INTO tracelane.{table} (tenant_id, {col}) VALUES (?, now64(6) - INTERVAL 1 HOUR)"
                    )
                };
                let mut q = ch.query(&sql).bind(tenant.as_str());
                if table == "spans" {
                    q = q.bind(uuid::Uuid::new_v4().to_string());
                }
                q.execute()
                    .await
                    .unwrap_or_else(|e| panic!("seed {table} for {tenant}: {e:#}"));
            }
            // B-459: one row per orphan-only table; every other column takes its type
            // default, which is all the orphan step reads (`tenant_id`).
            for t in ORPHAN_ONLY_TABLES {
                // Two tables drop a defaulted row on insert: a 1970 time is already past
                // their TTL, and a SummingMergeTree row whose sums are all zero is removed.
                let sql = match t.label {
                    "token_economics" => "INSERT INTO tracelane.token_economics (tenant_id, day, request_count) VALUES (?, today(), 1)".to_string(),
                    "ttft_stats" => "INSERT INTO tracelane.ttft_stats (tenant_id, bucket_hour) VALUES (?, now())".to_string(),
                    // A+C merge (2026-10-01): a default 1970 bucket_hour is already past
                    // spend_hourly's 365-day TTL and is dropped at insert — seed a live hour.
                    "spend_hourly" => "INSERT INTO tracelane.spend_hourly (tenant_id, bucket_hour) VALUES (?, toStartOfHour(now()))".to_string(),
                    other => format!("INSERT INTO tracelane.{other} (tenant_id) VALUES (?)"),
                };
                ch.query(&sql)
                    .bind(tenant.as_str())
                    .execute()
                    .await
                    .unwrap_or_else(|e| panic!("seed {} for {tenant}: {e:#}", t.label));
            }
        }
        async fn rows_for(ch: &clickhouse::Client, tenant: &str) -> Vec<(String, u64)> {
            let mut out = Vec::new();
            for (label, _, _) in orphan_steps() {
                let n: u64 = ch
                    .query(&format!(
                        "SELECT count() FROM tracelane.{label} WHERE tenant_id = ?"
                    ))
                    .bind(tenant)
                    .fetch_one()
                    .await
                    .expect("count");
                out.push((label.to_string(), n));
            }
            out
        }
        let orphan_before = rows_for(&ch, &orphan).await;
        let live_before = rows_for(&ch, &live).await;
        let unlisted_before = rows_for(&ch, &unlisted).await;
        assert!(
            orphan_before.iter().all(|(_, n)| *n >= 1),
            "every content table must hold the orphan's row before the step: {orphan_before:?}"
        );

        // 3(b) first: an EMPTY target list must delete NOTHING.
        let refused = sweep_orphans(
            &ch,
            &[],
            SweepMode::Enforce,
            &mut SweepRun::new(RetentionSweepPolicy::embedded()),
        )
        .await;
        assert_eq!(refused, 0, "an empty target list deletes nothing");
        assert_eq!(
            rows_for(&ch, &orphan).await,
            orphan_before,
            "nothing deleted on refusal"
        );

        // Proof 2: only `orphan` is RECORDED as purged → its rows go; the live tenant's AND the
        // unlisted tenant's stay (the B-459 CRITICAL: the old NOT-IN step took both).
        let live_list = vec![TenantRetention {
            tenant_id: live.clone(),
            queryable_days: 730,
        }];
        let targets = purge_targets(std::slice::from_ref(&orphan), &live_list);
        let deleted = sweep_orphans(
            &ch,
            &targets,
            SweepMode::Enforce,
            &mut SweepRun::new(RetentionSweepPolicy::embedded()),
        )
        .await;
        assert!(
            deleted >= (SWEEP_TABLES.len() + ORPHAN_ONLY_TABLES.len()) as u64,
            "at least one orphan row per table was accounted: {deleted}"
        );
        let orphan_after = rows_for(&ch, &orphan).await;
        assert!(
            orphan_after.iter().all(|(_, n)| *n == 0),
            "the orphan tenant must be gone from every content table: {orphan_after:?}"
        );
        assert_eq!(
            rows_for(&ch, &live).await,
            live_before,
            "the bystander's rows are byte-for-byte untouched (same counts in every table)"
        );
        assert_eq!(
            rows_for(&ch, &unlisted).await,
            unlisted_before,
            "a tenant missing from the live list but NOT recorded as purged is untouched"
        );
    }

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
    fn secs_until_next_retention_slot_same_day_before_a_slot() {
        // 05:00 UTC -> the 06:20 slot is next, same day.
        let now = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(2026, 9, 19)
                .unwrap()
                .and_hms_opt(5, 0, 0)
                .unwrap(),
            chrono::Utc,
        );
        assert_eq!(secs_until_next_retention_slot(now), 80 * 60);
    }

    #[test]
    fn secs_until_next_retention_slot_rolls_to_tomorrows_first_slot() {
        // 19:00 UTC -> every slot today (00/06/12/18:20) has passed; next is
        // tomorrow's 00:20.
        let now = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(2026, 9, 19)
                .unwrap()
                .and_hms_opt(19, 0, 0)
                .unwrap(),
            chrono::Utc,
        );
        assert_eq!(secs_until_next_retention_slot(now), 5 * 3600 + 20 * 60);
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
            "outcomes",
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
        // The same TIME sweep must enforce Free's plan window on explicit outcomes.
        let policy: serde_json::Value =
            serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json")).unwrap();
        let free_days = policy["plans"]["free_v1"]["queryable_days"]
            .as_i64()
            .unwrap() as i32;
        assert_eq!(free_days, 30);
        let owner = uuid::Uuid::new_v4().to_string();
        let foreign = uuid::Uuid::new_v4().to_string();
        for (t, subject, age) in [
            (&owner, "old", 31_u64),
            (&owner, "young", 29),
            (&foreign, "foreign", 31),
        ] {
            ch.query("INSERT INTO tracelane.outcomes (tenant_id, subject_kind, subject_id, result, source, version, recorded_at) VALUES (?, 'session', ?, 'failure', 'retention-test', 1, now64(3) - toIntervalDay(?))")
                .bind(t).bind(subject).bind(age).execute().await.unwrap();
        }
        let subjects = |t: &str| {
            ch.query("SELECT subject_id FROM tracelane.outcomes FINAL WHERE tenant_id = ? ORDER BY subject_id LIMIT 3").bind(t).fetch_all::<String>()
        };
        assert_eq!(subjects(&owner).await.unwrap(), ["old", "young"]);
        let table = SWEEP_TABLES.iter().find(|t| t.label == "outcomes").unwrap();
        assert_eq!(
            sweep_one(
                &ch,
                table,
                &owner,
                sweep_days(free_days).unwrap(),
                SweepMode::Enforce,
                // B-601 merge (2026-10-01): sweeps now run inside a bounded SweepRun.
                &mut SweepRun::new(RetentionSweepPolicy::embedded()),
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            subjects(&owner).await.unwrap(),
            ["young"],
            "Free must remove the 31-day outcome but retain the 29-day outcome"
        );
        assert_eq!(
            subjects(&foreign).await.unwrap(),
            ["foreign"],
            "another tenant's old outcome must survive"
        );
        ch.query(table.orphan_delete_sql)
            .bind(vec![owner, foreign])
            .execute()
            .await
            .unwrap();
        for table in SWEEP_TABLES {
            let deleted = sweep_one(
                &ch,
                table,
                tenant,
                7,
                SweepMode::Enforce,
                &mut SweepRun::new(RetentionSweepPolicy::embedded()),
            )
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

/// B-409, real Postgres: the DELETION boundary reads the tenant's PINNED
/// `queryable_days` — a later ruling that shortens it must not delete a protected
/// tenant's data early. Run by `run-postgres-integration.sh`.
#[cfg(test)]
mod b409_tests {
    use super::*;
    use crate::entitlement_cache::b409_fixture::*;

    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn b409_retention_reads_the_pinned_queryable_days() {
        let pool = fresh_migrated_pool().await;
        seed_v3_then_v4(&pool).await;
        let pinned = builder_tenant(&pool, Some("v3"), Some(200)).await;
        let fresh = builder_tenant(&pool, None, None).await;
        let live = resolve_retentions(&pool).await.expect("retentions");
        let days = |id: uuid::Uuid| {
            live.iter()
                .find(|r| r.tenant_id == id.to_string())
                .map(|r| r.queryable_days)
                .expect("tenant in the retention map")
        };
        assert_eq!(days(pinned), v3_builder().queryable, "pinned tenant");
        assert_eq!(days(fresh), v4_builder().queryable, "unpinned tenant");
    }
}
