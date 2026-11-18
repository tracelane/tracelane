//! ACT-06a: signed evidence for workspace-pause refusals, written OUT OF BAND.
//!
//! Admission's Controls step runs BEFORE RateLimit, so a paused refusal must do no database work
//! on the request path (review H1: 16 concurrent paused calls pinned the 16-connection pool while
//! holding the workspace and chain-head locks). The request side only calls [`PausedEvidence::offer`]
//! (in-process, no `await`); ONE worker per process drains a bounded queue sequentially.
use super::execution::{
    PausedCall, after_commit, deadline_tx, evidence_deferred, paused_refusal_tx,
};
use super::*;
use crate::entitlement_cache::ResolvedEntitlements;
use moka::sync::Cache;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::mpsc;

/// (tenant, pause epoch µs, api key, server, tool, sha256(canonical args)).
type DedupKey = (Uuid, i64, Uuid, Uuid, String, String);
/// (tenant, pause epoch µs, api key): one key cannot spend another key's budget.
type BudgetKey = (Uuid, i64, Uuid);

/// Queue-memory estimate per job beyond its tool and argument bytes (claims, entitlement `Arc`s).
const JOB_OVERHEAD_BYTES: usize = 1024;

/// One refused call awaiting its signed row.
pub(crate) struct Job {
    dedup: DedupKey,
    /// Tenant's queued-job counter and this job's byte charge; the worker releases both.
    queued: Arc<AtomicUsize>,
    bytes: usize,
    /// When the gateway refused the call: the row's `occurred_at` and the key-validity instant.
    refused_at: DateTime<Utc>,
    claims: crate::auth::Claims,
    resolved: Arc<ResolvedEntitlements>,
    server: Uuid,
    tool: String,
    args: String,
    since: DateTime<Utc>,
}

/// Request-side handle: bounded in-process dedup, per-key budget and queue. Cheap to clone.
#[derive(Clone)]
pub struct PausedEvidence {
    queue: mpsc::Sender<Job>,
    dedup: Cache<DedupKey, ()>,
    budget: Cache<BudgetKey, Arc<AtomicUsize>>,
    per_key: usize,
    /// Per-tenant queued-job counters (bounded cache) and the cap; global queued bytes and cap.
    tenant_queued: Cache<Uuid, Arc<AtomicUsize>>,
    per_tenant: usize,
    bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    #[cfg(test)]
    pub(crate) enqueued: Arc<AtomicUsize>,
}

impl PausedEvidence {
    /// Sizes come from the reference table (`approvals.paused_refusal_*`).
    /// # Errors
    /// Fails CLOSED at boot: an unreadable reference table is a startup error.
    pub(crate) fn new() -> Result<(Self, mpsc::Receiver<Job>)> {
        let l = &crate::mcp_policy::settings()?.approvals;
        Ok(Self::with_limits(
            l.paused_refusal_queue_capacity,
            l.paused_refusal_dedup_entries,
            l.paused_refusal_budget_entries,
            l.paused_refusal_attempts_per_key_epoch,
            l.paused_refusal_queued_per_tenant,
            l.paused_refusal_queue_bytes,
        ))
    }
    pub(crate) fn with_limits(
        queue: usize,
        dedup: usize,
        budget: usize,
        per_key: usize,
        per_tenant: usize,
        max_bytes: usize,
    ) -> (Self, mpsc::Receiver<Job>) {
        let (tx, rx) = mpsc::channel(queue.max(1));
        let cache = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        (
            Self {
                queue: tx,
                dedup: Cache::new(cache(dedup)),
                budget: Cache::new(cache(budget)),
                per_key,
                tenant_queued: Cache::new(cache(budget)),
                per_tenant,
                bytes: Arc::default(),
                max_bytes,
                #[cfg(test)]
                enqueued: Arc::default(),
            },
            rx,
        )
    }
    /// Request path: in-process and non-blocking, NO database and NO `await`. A repeat of an
    /// already-offered call is free; otherwise one unit of the key's epoch budget is charged and
    /// the job is `try_send`-ed. Over budget or a full queue the evidence is skipped and
    /// `ActionEvidenceDeferred` counted; the refusal itself never depends on this.
    /// # Errors
    /// None. Fail-OPEN by design (fault-tolerance path): every skip is counted.
    pub(crate) fn offer(
        &self,
        claims: &crate::auth::Claims,
        resolved: &Arc<ResolvedEntitlements>,
        call: &PausedCall<'_>,
        since: DateTime<Utc>,
    ) {
        let Some(key) = claims.api_key_id().and_then(|k| Uuid::parse_str(k).ok()) else {
            return; // N6: no API-key actor (JWT caller) to attribute a row to; not a gap to count.
        };
        let (tenant, epoch) = (*claims.tenant_id.as_uuid(), since.timestamp_micros());
        let dedup = (
            tenant,
            epoch,
            key,
            call.server,
            call.tool.to_owned(),
            sha(call.args.as_bytes()),
        );
        if !self.dedup.entry(dedup.clone()).or_insert(()).is_fresh() {
            return;
        }
        let budget = self.budget.get_with((tenant, epoch, key), Default::default);
        if budget.fetch_add(1, Ordering::Relaxed) >= self.per_key {
            return evidence_deferred(); // Dedup entry kept: repeats of this call stay free.
        }
        let queued = self.tenant_queued.get_with(tenant, Default::default);
        let size = call.args.len() + call.tool.len() + JOB_OVERHEAD_BYTES;
        let job = Job {
            dedup: dedup.clone(),
            queued: Arc::clone(&queued),
            bytes: size,
            refused_at: Utc::now(),
            claims: claims.clone(),
            resolved: Arc::clone(resolved),
            server: call.server,
            tool: call.tool.to_owned(),
            args: call.args.to_owned(),
            since,
        };
        // N1/N3: a skip caused by shared capacity (tenant cap, bytes, full queue) is not the
        // key's fault: refund its budget unit and forget the dedup entry so a retry can record.
        let tenant_full = queued.fetch_add(1, Ordering::Relaxed) >= self.per_tenant;
        let bytes_full = self.bytes.fetch_add(size, Ordering::Relaxed) + size > self.max_bytes;
        if tenant_full || bytes_full || self.queue.try_send(job).is_err() {
            queued.fetch_sub(1, Ordering::Relaxed);
            self.bytes.fetch_sub(size, Ordering::Relaxed);
            budget.fetch_sub(1, Ordering::Relaxed);
            self.dedup.invalidate(&dedup);
            evidence_deferred();
        } else {
            #[cfg(test)]
            self.enqueued.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Counts jobs still queued when the worker stops (runtime shutdown or channel close).
pub(crate) struct Undrained(pub(crate) mpsc::Receiver<Job>);
impl Drop for Undrained {
    fn drop(&mut self) {
        self.0.close();
        while self.0.try_recv().is_ok() {
            evidence_deferred();
        }
    }
}

/// The ONE background writer. Sequential, so it holds at most one pooled connection and one set
/// of workspace/chain-head locks at a time, each statement bounded server-side and each job by a
/// whole-job deadline (twice the per-statement deadline) that also covers the pool wait.
pub(crate) fn spawn_worker(
    handle: PausedEvidence,
    rx: mpsc::Receiver<Job>,
    pool: crate::db::DbPool,
    chain: Arc<crate::audit::AuditChain>,
) {
    tokio::spawn(async move {
        let mut rx = Undrained(rx);
        while let Some(job) = rx.0.recv().await {
            let whole = crate::mcp_policy::settings()
                .map_or(0, |l| l.approvals.paused_refusal_timeout_ms * 2);
            let done = tokio::time::timeout(
                std::time::Duration::from_millis(whole),
                write(&pool, &chain, &job),
            )
            .await;
            job.queued.fetch_sub(1, Ordering::Relaxed);
            handle.bytes.fetch_sub(job.bytes, Ordering::Relaxed);
            if !matches!(done, Ok(Ok(()))) {
                handle.dedup.invalidate(&job.dedup); // Allow a retry, bounded by the key budget.
                evidence_deferred();
            }
        }
    });
}

/// One job: transaction, `deadline_tx` (statement + lock timeout), row, commit, derived copy.
/// Server-side `statement_timeout`/`lock_timeout` bound each statement even if the caller's
/// whole-job deadline drops this future.
/// # Errors
/// Fails CLOSED for the transaction (rolled back on drop); the worker counts it and continues.
async fn write(
    pool: &crate::db::DbPool,
    chain: &Arc<crate::audit::AuditChain>,
    job: &Job,
) -> Result<()> {
    let limits = crate::mcp_policy::settings()?;
    let mut db = pool.get().await?;
    let tx = db.transaction().await?;
    deadline_tx(
        &tx,
        std::time::Duration::from_millis(limits.approvals.paused_refusal_timeout_ms),
    )
    .await?;
    let call = PausedCall {
        server: job.server,
        tool: &job.tool,
        args: &job.args,
    };
    let rows = paused_refusal_tx(
        &tx,
        &job.claims,
        Some(&job.resolved),
        &call,
        job.since,
        job.refused_at,
    )
    .await?;
    tx.commit().await?;
    after_commit(
        Some(chain),
        &job.claims,
        rows.into_iter().collect(),
        std::time::Duration::from_secs(limits.limits.call_timeout_secs),
    );
    Ok(())
}
