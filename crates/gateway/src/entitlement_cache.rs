//!
//! Resolving `entitlements::check(tenant, F_*)` against Neon on every request
//! is ~5K round-trips/sec at the gateway target — a 5–15ms hop that blows the
//! <5ms p50 budget and makes a serverless DB a hard hot-path dependency. This
//! module removes that ceiling: entitlement reads become CPU-bound, served from
//! a `moka::future::Cache` with a 30s TTL and 25s refresh-ahead.
//!
//! ## Resolution
//!
//! a tenant's `workspace_entitlements` non-NULL columns overlay the
//! `plan_entitlements` plan defaults; a `FALSE` override beats a `TRUE` default.
//! The cache holds the resolved booleans only. We resolve **all** feature flags
//! for a workspace in one query and key the cache per-workspace — the ADR's
//! logical `(WorkspaceId, FeatureKey)` key, resolved with a single round-trip
//! rather than one per feature (strictly fewer Neon hits, same semantics).
//!
//! ## Invalidation
//!
//! A long-lived `LISTEN entitlements_changed` connection (see
//! [`spawn_listen_task`]) evicts a workspace's entry on any write to
//! `workspace_entitlements` / `plan_entitlements`. The 30s TTL is the fallback
//! if `LISTEN` drops — staleness is bounded at 30s, never unbounded.
//!
//! `LISTEN`/`NOTIFY` does **not** work across a PgBouncer transaction pooler,
//! so the listener uses the **direct** Neon endpoint while the resolver's
//! pooled queries use `-pooler` (ADR-035 refined: the ADR mandates `-pooler`
//! for pooled connections; the dedicated listener is the documented exception).
//!
//! ## Fail-open
//!
//! On a Neon outage: serve from cache up to TTL; on a miss during the outage,
//! fail-open to the last-known grant if present (a secondary `last_known` map
//! that outlives the moka TTL), else deny-new-features. Never block an in-flight
//! paying tenant because the control plane blinked.

use anyhow::Context as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use moka::future::Cache;
use uuid::Uuid;

/// Cache TTL — staleness ceiling when `LISTEN` invalidation is unavailable.
const TTL: Duration = Duration::from_secs(30);
/// Refresh-ahead threshold — a read older than this triggers a background
/// re-resolve while still serving the (slightly stale) cached value.
const REFRESH_AHEAD: Duration = Duration::from_secs(25);
/// Max distinct workspaces held warm.
const MAX_CAPACITY: u64 = 100_000;

// ── Metrics (atomic-counter house style, cf. ingest/src/limits.rs) ──────────
static CACHE_MISS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LISTEN_RECONNECT_TOTAL: AtomicU64 = AtomicU64::new(0);
static FAIL_OPEN_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the cache metrics, surfaced as `tracelane_entitlement_*` /
/// `tracelane_listen_reconnect_total` by the metrics scrape.
pub fn metrics_snapshot() -> EntitlementMetrics {
    EntitlementMetrics {
        cache_miss_total: CACHE_MISS_TOTAL.load(Ordering::Relaxed),
        listen_reconnect_total: LISTEN_RECONNECT_TOTAL.load(Ordering::Relaxed),
        fail_open_total: FAIL_OPEN_TOTAL.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EntitlementMetrics {
    pub cache_miss_total: u64,
    pub listen_reconnect_total: u64,
    pub fail_open_total: u64,
}

/// A gated feature flag (the `f_*` columns of `plan_entitlements`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeatureKey {
    Pr7Trajectory,
    Pr8ArgDrift,
    Pr9A2aHandoff,
    Pr10InlineSlmJudge,
    Pr11SloDrift,
    Pr12LanggraphBranch,
    CohortBaselines,
    HipaaGcpAddon,
    AuditAddon,
    /// Free-tier audit self-verify (ADR-066). Default-TRUE on every plan — lets a
    /// tenant SEE + verify their OWN recent chain in-app. Distinct from the paid
    /// `AuditAddon` (the $999 Article-12 evidence-pack export). A per-workspace
    /// `FALSE` override (deny-overrides-grant) can still switch it off.
    AuditSelfVerify,
    /// B1 Prompt-Promotion WRITE workflow (promote / rollback / observe) —
    /// ADR-009 gates it to Team+ (Builder is read-only). Enforced by
    PromptPromotionWrite,
    // Inline guardrails V1 (the guardrail spec §2.7) — the GATED rails. The
    // free defaults (R1, R3 schema-val, R8 heuristic) are NOT here; they are
    // always on and carry no entitlement flag.
    GuardrailR2,
    GuardrailR3Pinning,
    GuardrailR4,
    GuardrailR5,
    GuardrailR6,
    GuardrailR7,
    /// ADR-059 user-facing alerting (a tenant's alert rules → their webhook).
    Alerts,
}

impl FeatureKey {
    /// The Postgres column name backing this feature.
    pub fn column(self) -> &'static str {
        match self {
            Self::Pr7Trajectory => "f_pr7_trajectory",
            Self::Pr8ArgDrift => "f_pr8_argdrift",
            Self::Pr9A2aHandoff => "f_pr9_a2a_handoff",
            Self::Pr10InlineSlmJudge => "f_pr10_inline_slm_judge",
            Self::Pr11SloDrift => "f_pr11_slo_drift",
            Self::Pr12LanggraphBranch => "f_pr12_langgraph_branch",
            Self::CohortBaselines => "f_cohort_baselines",
            Self::HipaaGcpAddon => "f_hipaa_gcp_addon",
            Self::AuditAddon => "f_audit_addon",
            Self::AuditSelfVerify => "f_audit_selfverify",
            Self::PromptPromotionWrite => "f_prompt_promotion_write",
            Self::GuardrailR2 => "f_guardrail_r2",
            Self::GuardrailR3Pinning => "f_guardrail_r3_pinning",
            Self::GuardrailR4 => "f_guardrail_r4",
            Self::GuardrailR5 => "f_guardrail_r5",
            Self::GuardrailR6 => "f_guardrail_r6",
            Self::GuardrailR7 => "f_guardrail_r7",
            Self::Alerts => "f_alerts",
        }
    }
}

/// The resolved entitlement set for one workspace — the deny-overrides-grant
/// result for every feature plus the plan-level limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEntitlements {
    pub plan_lookup_key: String,
    pub f_pr7_trajectory: bool,
    pub f_pr8_argdrift: bool,
    pub f_pr9_a2a_handoff: bool,
    pub f_pr10_inline_slm_judge: bool,
    pub f_pr11_slo_drift: bool,
    pub f_pr12_langgraph_branch: bool,
    pub f_cohort_baselines: bool,
    pub f_hipaa_gcp_addon: bool,
    pub f_audit_addon: bool,
    /// Free-tier audit self-verify (ADR-066). Default-TRUE on every plan.
    pub f_audit_selfverify: bool,
    pub f_prompt_promotion_write: bool,
    // Inline guardrails V1 (§2.7) — gated rails (RailGate maps these to grants).
    pub f_guardrail_r2: bool,
    pub f_guardrail_r3_pinning: bool,
    pub f_guardrail_r4: bool,
    pub f_guardrail_r5: bool,
    pub f_guardrail_r6: bool,
    pub f_guardrail_r7: bool,
    pub retention_days: i32,
    /// ADR-048 D2 — full-capture gate (Business + Enterprise base; an active
    /// Audit SKU forces it). The ingest sampler enforces capture via its own
    /// per-tenant cache; this is carried here so the gateway can inspect or
    /// stamp the resolved grant on the request path.
    pub f_full_capture: bool,
    /// ADR-059 user-facing alerting entitlement (dark by default on every plan).
    pub f_alerts: bool,
    /// B-109: monthly included trace quota (deny-overrides-grant from
    /// `workspace_entitlements` ⊕ `plan_entitlements`). The gateway hard-cap 429
    /// threshold = `trace_quota_monthly` × `overage_hard_cap_multiplier`.
    pub trace_quota_monthly: i64,
    /// B-109: hard-cap multiplier as integer tenths (5.0× → 50, 1.0× → 10) so the
    /// hot-path decision stays integer-only and this struct keeps deriving `Eq`.
    pub overage_hard_cap_multiplier_tenths: i32,
}

impl ResolvedEntitlements {
    /// The deny-all default served on a cache miss during a control-plane
    /// outage when no last-known grant exists. Deny-new-features per ADR-035.
    pub fn deny_all() -> Self {
        Self {
            plan_lookup_key: "free_v1".to_string(),
            f_pr7_trajectory: false,
            f_pr8_argdrift: false,
            f_pr9_a2a_handoff: false,
            f_pr10_inline_slm_judge: false,
            f_pr11_slo_drift: false,
            f_pr12_langgraph_branch: false,
            f_cohort_baselines: false,
            f_hipaa_gcp_addon: false,
            f_audit_addon: false,
            // Fail-closed on a control-plane outage with no last-known grant:
            // deny self-verify until the real (default-TRUE) grant resolves.
            f_audit_selfverify: false,
            f_prompt_promotion_write: false,
            f_guardrail_r2: false,
            f_guardrail_r3_pinning: false,
            f_guardrail_r4: false,
            f_guardrail_r5: false,
            f_guardrail_r6: false,
            f_guardrail_r7: false,
            retention_days: 7,
            f_full_capture: false,
            f_alerts: false,
            // B-109: free-plan quota defaults (10K traces, 1.0× hard cap = 429
            // exactly at the included quota) — fail-restricted, mirrors
            // plan_entitlements.free_v1.
            trace_quota_monthly: 10_000,
            overage_hard_cap_multiplier_tenths: 10,
        }
    }

    /// Project a single feature flag.
    pub fn has(&self, feature: FeatureKey) -> bool {
        match feature {
            FeatureKey::Pr7Trajectory => self.f_pr7_trajectory,
            FeatureKey::Pr8ArgDrift => self.f_pr8_argdrift,
            FeatureKey::Pr9A2aHandoff => self.f_pr9_a2a_handoff,
            FeatureKey::Pr10InlineSlmJudge => self.f_pr10_inline_slm_judge,
            FeatureKey::Pr11SloDrift => self.f_pr11_slo_drift,
            FeatureKey::Pr12LanggraphBranch => self.f_pr12_langgraph_branch,
            FeatureKey::CohortBaselines => self.f_cohort_baselines,
            FeatureKey::HipaaGcpAddon => self.f_hipaa_gcp_addon,
            FeatureKey::AuditAddon => self.f_audit_addon,
            FeatureKey::AuditSelfVerify => self.f_audit_selfverify,
            FeatureKey::PromptPromotionWrite => self.f_prompt_promotion_write,
            FeatureKey::GuardrailR2 => self.f_guardrail_r2,
            FeatureKey::GuardrailR3Pinning => self.f_guardrail_r3_pinning,
            FeatureKey::GuardrailR4 => self.f_guardrail_r4,
            FeatureKey::GuardrailR5 => self.f_guardrail_r5,
            FeatureKey::GuardrailR6 => self.f_guardrail_r6,
            FeatureKey::GuardrailR7 => self.f_guardrail_r7,
            FeatureKey::Alerts => self.f_alerts,
        }
    }

    /// B-109: derive the gateway monthly-quota config from the resolved
    /// entitlements. The 429 hard cap = `trace_quota_monthly` × multiplier, both
    /// sourced from `workspace_entitlements` ⊕ `plan_entitlements` (never the
    /// hardcoded plan map — that drift was the pre-B-109 gap; CLAUDE.md control-
    /// plane rule). A zero/negative quota (only the OSS self-host path) means
    /// "no quota enforced".
    pub fn quota_config(&self) -> crate::rate_limiter::QuotaConfig {
        crate::rate_limiter::QuotaConfig {
            trace_quota_monthly: self.trace_quota_monthly.max(0) as u64,
            hard_cap_tenths: self.overage_hard_cap_multiplier_tenths.max(0) as u32,
        }
    }
}

/// Cached value plus the instant it was resolved (drives refresh-ahead).
#[derive(Debug)]
struct Cached {
    resolved: ResolvedEntitlements,
    fetched_at: Instant,
}

/// Boxed async resolver. Production injects a Postgres-backed closure
/// ([`pg_resolver`]); tests inject a counting mock. A boxed closure keeps the
/// resolver dyn-dispatchable without `async-trait` (banned on the hot path);
/// resolution runs only on a cache miss, off the warm path.
pub type ResolveFn = Arc<
    dyn Fn(Uuid) -> Pin<Box<dyn Future<Output = anyhow::Result<ResolvedEntitlements>> + Send>>
        + Send
        + Sync,
>;

/// In-process entitlement cache. Cheap to clone (all fields are `Arc`-backed).
#[derive(Clone)]
pub struct EntitlementCache {
    cache: Cache<Uuid, Arc<Cached>>,
    /// Survives the moka TTL so an outage can fail-open to the last-known grant.
    last_known: Arc<DashMap<Uuid, Arc<ResolvedEntitlements>>>,
    resolve: ResolveFn,
}

impl EntitlementCache {
    pub fn new(resolve: ResolveFn) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(MAX_CAPACITY)
                .time_to_live(TTL)
                .build(),
            last_known: Arc::new(DashMap::new()),
            resolve,
        }
    }

    /// Resolve `feature` for `tenant`. Warm reads never touch Postgres.
    pub async fn check(&self, tenant: Uuid, feature: FeatureKey) -> bool {
        self.resolved(tenant).await.has(feature)
    }

    /// Resolve the full entitlement set for `tenant` (warm-cache on hit).
    pub async fn resolved(&self, tenant: Uuid) -> Arc<ResolvedEntitlements> {
        if let Some(cached) = self.cache.get(&tenant).await {
            if cached.fetched_at.elapsed() >= REFRESH_AHEAD {
                self.spawn_refresh(tenant);
            }
            return Arc::new(cached.resolved.clone());
        }
        self.resolve_and_store(tenant).await
    }

    /// Miss path: resolve from Postgres, populate the cache + last-known store.
    /// On resolver error, fail-open to the last-known grant, else deny-all.
    async fn resolve_and_store(&self, tenant: Uuid) -> Arc<ResolvedEntitlements> {
        CACHE_MISS_TOTAL.fetch_add(1, Ordering::Relaxed);
        match (self.resolve)(tenant).await {
            Ok(resolved) => {
                let arc = Arc::new(resolved.clone());
                self.last_known.insert(tenant, arc.clone());
                self.cache
                    .insert(
                        tenant,
                        Arc::new(Cached {
                            resolved,
                            fetched_at: Instant::now(),
                        }),
                    )
                    .await;
                arc
            }
            Err(err) => {
                FAIL_OPEN_TOTAL.fetch_add(1, Ordering::Relaxed);
                if let Some(last) = self.last_known.get(&tenant) {
                    tracing::warn!(
                        error = %err,
                        "entitlement resolve failed — failing open to last-known grant"
                    );
                    last.clone()
                } else {
                    tracing::warn!(
                        error = %err,
                        "entitlement resolve failed with no last-known grant — denying new features"
                    );
                    Arc::new(ResolvedEntitlements::deny_all())
                }
            }
        }
    }

    /// Background refresh-ahead: re-resolve without blocking the caller.
    fn spawn_refresh(&self, tenant: Uuid) {
        let this = self.clone();
        tokio::spawn(async move {
            // Re-resolve; ignore the value (resolve_and_store re-inserts).
            let _ = this.resolve_and_store(tenant).await;
        });
    }

    /// Evict a workspace's entry (called by the `LISTEN` task on `NOTIFY`).
    /// The next read re-resolves; the last-known store is intentionally kept
    /// so a concurrent outage still has a fallback.
    pub async fn invalidate(&self, tenant: Uuid) {
        self.cache.invalidate(&tenant).await;
    }

    /// Evict every workspace — used when a `plan_entitlements` row changes, which
    /// affects all tenants on that plan (the `NOTIFY` payload `ALL` triggers this).
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    #[cfg(test)]
    fn last_known_len(&self) -> usize {
        self.last_known.len()
    }
}

/// Build a Postgres-backed resolver closure over a `deadpool` pool (the
/// `-pooler` endpoint). Computes deny-overrides-grant in SQL: a tenant's
/// `workspace_entitlements` non-NULL columns overlay the `plan_entitlements`
/// defaults via `COALESCE`. A tenant with no `workspace_entitlements` row falls
/// back to the `free_v1` plan defaults (deny-new-features for unseeded tenants).
pub fn pg_resolver(pool: crate::db::DbPool) -> ResolveFn {
    Arc::new(move |tenant: Uuid| {
        let pool = pool.clone();
        Box::pin(async move {
            let client = pool
                .get()
                .await
                .map_err(|e| anyhow::anyhow!("entitlement pool: {e}"))?;
            // Overlay overrides over plan defaults. LEFT JOIN so a tenant with
            // no override row still resolves to its plan; if the tenant has no
            // workspace_entitlements row at all the query returns 0 rows and we
            // fall back to free_v1 below.
            const SQL: &str = "\
                SELECT pe.plan_lookup_key, \
                  COALESCE(we.f_pr7_trajectory, pe.f_pr7_trajectory), \
                  COALESCE(we.f_pr8_argdrift, pe.f_pr8_argdrift), \
                  COALESCE(we.f_pr9_a2a_handoff, pe.f_pr9_a2a_handoff), \
                  COALESCE(we.f_pr10_inline_slm_judge, pe.f_pr10_inline_slm_judge), \
                  COALESCE(we.f_pr11_slo_drift, pe.f_pr11_slo_drift), \
                  COALESCE(we.f_pr12_langgraph_branch, pe.f_pr12_langgraph_branch), \
                  COALESCE(we.f_cohort_baselines, pe.f_cohort_baselines), \
                  COALESCE(we.f_hipaa_gcp_addon, pe.f_hipaa_gcp_addon), \
                  COALESCE(we.f_audit_addon, pe.f_audit_addon), \
                  COALESCE(we.retention_days, pe.retention_days), \
                  COALESCE(we.f_guardrail_r2, pe.f_guardrail_r2), \
                  COALESCE(we.f_guardrail_r3_pinning, pe.f_guardrail_r3_pinning), \
                  COALESCE(we.f_guardrail_r4, pe.f_guardrail_r4), \
                  COALESCE(we.f_guardrail_r5, pe.f_guardrail_r5), \
                  COALESCE(we.f_guardrail_r6, pe.f_guardrail_r6), \
                  COALESCE(we.f_guardrail_r7, pe.f_guardrail_r7), \
                  COALESCE(we.f_full_capture, pe.f_full_capture), \
                  COALESCE(we.f_prompt_promotion_write, pe.f_prompt_promotion_write), \
                  COALESCE(we.f_alerts, pe.f_alerts), \
                  COALESCE(we.f_audit_selfverify, pe.f_audit_selfverify), \
                  COALESCE(we.trace_quota_monthly, pe.trace_quota_monthly), \
                  (COALESCE(we.overage_hard_cap_multiplier, pe.overage_hard_cap_multiplier) * 10)::int \
                FROM workspace_entitlements we \
                JOIN plan_entitlements pe ON pe.plan_lookup_key = we.plan_lookup_key \
                WHERE we.tenant_id = $1";
            if let Some(row) = client.query_opt(SQL, &[&tenant]).await? {
                return Ok(row_to_resolved(&row));
            }
            // Unseeded tenant → free plan defaults.
            const FALLBACK: &str = "\
                SELECT plan_lookup_key, f_pr7_trajectory, f_pr8_argdrift, \
                  f_pr9_a2a_handoff, f_pr10_inline_slm_judge, f_pr11_slo_drift, \
                  f_pr12_langgraph_branch, f_cohort_baselines, f_hipaa_gcp_addon, \
                  f_audit_addon, retention_days, \
                  f_guardrail_r2, f_guardrail_r3_pinning, f_guardrail_r4, \
                  f_guardrail_r5, f_guardrail_r6, f_guardrail_r7, \
                  f_full_capture, f_prompt_promotion_write, f_alerts, \
                  f_audit_selfverify, \
                  trace_quota_monthly, (overage_hard_cap_multiplier * 10)::int \
                FROM plan_entitlements WHERE plan_lookup_key = 'free_v1'";
            match client.query_opt(FALLBACK, &[]).await? {
                Some(row) => Ok(row_to_resolved(&row)),
                None => Ok(ResolvedEntitlements::deny_all()),
            }
        }) as Pin<Box<dyn Future<Output = anyhow::Result<ResolvedEntitlements>> + Send>>
    })
}

fn row_to_resolved(row: &tokio_postgres::Row) -> ResolvedEntitlements {
    ResolvedEntitlements {
        plan_lookup_key: row.get(0),
        f_pr7_trajectory: row.get(1),
        f_pr8_argdrift: row.get(2),
        f_pr9_a2a_handoff: row.get(3),
        f_pr10_inline_slm_judge: row.get(4),
        f_pr11_slo_drift: row.get(5),
        f_pr12_langgraph_branch: row.get(6),
        f_cohort_baselines: row.get(7),
        f_hipaa_gcp_addon: row.get(8),
        f_audit_addon: row.get(9),
        retention_days: row.get(10),
        f_guardrail_r2: row.get(11),
        f_guardrail_r3_pinning: row.get(12),
        f_guardrail_r4: row.get(13),
        f_guardrail_r5: row.get(14),
        f_guardrail_r6: row.get(15),
        f_guardrail_r7: row.get(16),
        f_full_capture: row.get(17),
        f_prompt_promotion_write: row.get(18),
        f_alerts: row.get(19),
        f_audit_selfverify: row.get(20),
        trace_quota_monthly: row.get(21),
        overage_hard_cap_multiplier_tenths: row.get(22),
    }
}

/// Spawn the long-lived `LISTEN entitlements_changed` task.
///
/// Uses a **dedicated direct** connection (`POSTGRES_DIRECT_URL`, falling back
/// to `POSTGRES_URL`) because `LISTEN`/`NOTIFY` does not survive a PgBouncer
/// transaction pooler. The `NOTIFY` payload is the workspace UUID; on receipt
/// the matching cache entry is evicted. On connection drop the task reconnects
/// with backoff (the 30s TTL bounds staleness in the gap) and increments
/// `tracelane_listen_reconnect_total`.
///
/// Returns immediately; the task runs until the process exits. A `None` /
/// unset direct URL disables `LISTEN` and the cache relies on the TTL alone.
pub fn spawn_listen_task(cache: EntitlementCache) {
    let Some(conn_str) = std::env::var("POSTGRES_DIRECT_URL")
        .ok()
        .or_else(|| std::env::var("POSTGRES_URL").ok())
    else {
        tracing::info!(
            "no POSTGRES_DIRECT_URL/POSTGRES_URL — entitlement LISTEN disabled, TTL-only invalidation"
        );
        return;
    };

    tokio::spawn(async move {
        loop {
            if let Err(err) = listen_once(&conn_str, &cache).await {
                tracing::warn!(error = %err, "entitlement LISTEN connection error; reconnecting");
            }
            // Either the stream ended cleanly or it errored — either way we
            // reconnect. Backoff first; the 30s TTL bounds staleness in the gap.
            LISTEN_RECONNECT_TOTAL.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// One LISTEN session: connect, `LISTEN entitlements_changed`, and pump
/// notifications into cache invalidations until the connection drops.
async fn listen_once(conn_str: &str, cache: &EntitlementCache) -> anyhow::Result<()> {
    use futures::StreamExt as _;
    use tokio_postgres::AsyncMessage;

    // TLS required — Neon's direct endpoint (like the pooler) rejects plaintext.
    // Reuse the gateway pool's rustls connector (see db::pg_tls_connector).
    //
    // Neon's URL sets `channel_binding=require`, but the rustls connector does
    // not expose `tls-server-end-point` binding, so SCRAM-SHA-256-PLUS is
    // unavailable and a `require` config fails auth ("error connecting to
    // server"). Downgrade to `Prefer` — SCRAM-SHA-256 without binding, exactly
    // what the pool path uses (it builds from components, dropping the param).
    let mut pg_cfg: tokio_postgres::Config =
        conn_str.parse().context("parse POSTGRES_DIRECT_URL")?;
    pg_cfg.channel_binding(tokio_postgres::config::ChannelBinding::Prefer);
    let (client, mut conn) = pg_cfg.connect(crate::db::pg_tls_connector()?).await?;

    // tokio_postgres requires the Connection to be polled continuously for the
    // client to make progress. Drive it on a task (forwarding async messages via
    // a channel) BEFORE issuing LISTEN — polling `conn` only *after*
    // `batch_execute` deadlocks the setup (the latent bug exposed once TLS made
    // connect() succeed). The task's result surfaces connection errors so the
    // caller logs + reconnects.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AsyncMessage>();
    let driver = tokio::spawn(async move {
        let mut messages = futures::stream::poll_fn(move |cx| conn.poll_message(cx));
        while let Some(msg) = messages.next().await {
            match msg {
                Ok(m) => {
                    if tx.send(m).is_err() {
                        break; // receiver dropped
                    }
                }
                Err(e) => return Err(anyhow::Error::new(e).context("LISTEN connection")),
            }
        }
        Ok(())
    });

    client.batch_execute("LISTEN entitlements_changed").await?;
    tracing::info!("entitlement LISTEN active on channel entitlements_changed");

    while let Some(msg) = rx.recv().await {
        match msg {
            AsyncMessage::Notification(note) => {
                let payload = note.payload();
                if payload == "ALL" {
                    // plan_entitlements change — affects every tenant on the plan.
                    cache.invalidate_all();
                    tracing::debug!("entitlement cache fully invalidated via NOTIFY ALL");
                } else if let Ok(tenant) = Uuid::parse_str(payload) {
                    cache.invalidate(tenant).await;
                    tracing::debug!(%tenant, "entitlement cache invalidated via NOTIFY");
                }
            }
            AsyncMessage::Notice(notice) => {
                tracing::debug!(notice = %notice, "postgres notice on LISTEN connection");
            }
            _ => {}
        }
    }

    // Channel closed → driver task ended; surface any connection error.
    match driver.await {
        Ok(res) => res,
        Err(join) => Err(anyhow::Error::new(join).context("LISTEN driver task")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn grant_all() -> ResolvedEntitlements {
        ResolvedEntitlements {
            plan_lookup_key: "enterprise_v1".to_string(),
            f_pr7_trajectory: true,
            f_pr8_argdrift: true,
            f_pr9_a2a_handoff: true,
            f_pr10_inline_slm_judge: true,
            f_pr11_slo_drift: true,
            f_pr12_langgraph_branch: true,
            f_cohort_baselines: true,
            f_hipaa_gcp_addon: true,
            f_audit_addon: true,
            f_audit_selfverify: true,
            f_prompt_promotion_write: true,
            f_guardrail_r2: true,
            f_guardrail_r3_pinning: true,
            f_guardrail_r4: true,
            f_guardrail_r5: true,
            f_guardrail_r6: true,
            f_guardrail_r7: true,
            retention_days: 365,
            f_full_capture: true,
            f_alerts: true,
            trace_quota_monthly: 25_000_000,
            overage_hard_cap_multiplier_tenths: 990,
        }
    }

    /// Resolver that counts invocations and can be flipped to fail.
    fn counting_resolver(
        counter: Arc<AtomicUsize>,
        fail: Arc<std::sync::atomic::AtomicBool>,
    ) -> ResolveFn {
        Arc::new(move |_tenant: Uuid| {
            let counter = counter.clone();
            let fail = fail.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                if fail.load(Ordering::SeqCst) {
                    anyhow::bail!("simulated control-plane outage");
                }
                Ok(grant_all())
            })
        })
    }

    #[tokio::test]
    async fn warm_cache_does_not_re_resolve() {
        let count = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cache = EntitlementCache::new(counting_resolver(count.clone(), fail));
        let tenant = Uuid::new_v4();

        // First read = miss → one resolve.
        assert!(cache.check(tenant, FeatureKey::AuditAddon).await);
        // Subsequent warm reads must not touch the resolver (zero PG queries).
        for _ in 0..50 {
            assert!(cache.check(tenant, FeatureKey::Pr7Trajectory).await);
        }
        assert_eq!(count.load(Ordering::SeqCst), 1, "warm path re-resolved");
    }

    #[tokio::test]
    async fn fails_open_to_last_known_grant_on_outage() {
        let count = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cache = EntitlementCache::new(counting_resolver(count.clone(), fail.clone()));
        let tenant = Uuid::new_v4();

        // Warm the last-known store.
        assert!(cache.check(tenant, FeatureKey::AuditAddon).await);
        assert_eq!(cache.last_known_len(), 1);

        // Outage + cache eviction → resolve fails → serve last-known (granted).
        fail.store(true, Ordering::SeqCst);
        cache.invalidate(tenant).await;
        assert!(
            cache.check(tenant, FeatureKey::AuditAddon).await,
            "should fail open to last-known grant"
        );
    }

    #[tokio::test]
    async fn denies_new_features_on_outage_without_last_known() {
        let count = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true)); // outage from t0
        let cache = EntitlementCache::new(counting_resolver(count, fail));
        let tenant = Uuid::new_v4();

        // No prior successful resolve → deny-new-features.
        assert!(
            !cache.check(tenant, FeatureKey::AuditAddon).await,
            "unknown tenant during outage must be denied"
        );
    }

    #[tokio::test]
    async fn invalidate_forces_re_resolve() {
        let count = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cache = EntitlementCache::new(counting_resolver(count.clone(), fail));
        let tenant = Uuid::new_v4();

        assert!(cache.check(tenant, FeatureKey::AuditAddon).await);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        cache.invalidate(tenant).await;
        assert!(cache.check(tenant, FeatureKey::AuditAddon).await);
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "invalidate should re-resolve"
        );
    }

    #[test]
    fn deny_all_denies_every_feature() {
        let d = ResolvedEntitlements::deny_all();
        for f in [
            FeatureKey::Pr7Trajectory,
            FeatureKey::Pr10InlineSlmJudge,
            FeatureKey::AuditAddon,
            FeatureKey::HipaaGcpAddon,
            FeatureKey::PromptPromotionWrite,
        ] {
            assert!(!d.has(f));
        }
    }

    /// B-109: the gateway quota is entitlement-driven — `quota_config()` reads the
    /// resolved `trace_quota_monthly` × multiplier, NOT the hardcoded plan map.
    #[test]
    fn quota_config_derives_from_entitlements_not_hardcoded() {
        // grant_all() = enterprise (25M, 99.0× → 990 tenths).
        let mut e = grant_all();
        let qc = e.quota_config();
        assert_eq!(qc.trace_quota_monthly, 25_000_000);
        assert_eq!(qc.hard_cap_tenths, 990);

        // deny_all() = free (10K, 1.0×) → the hard cap is EXACTLY the included
        // quota: "429 at quota" holds for free with no code change.
        let d = ResolvedEntitlements::deny_all();
        assert_eq!(d.quota_config().trace_quota_monthly, 10_000);
        assert_eq!(
            d.quota_config().hard_cap_absolute(),
            10_000,
            "free 1.0× → 429 exactly at the included quota"
        );

        // The strict "429 at quota" launch policy for a PAID plan is a data lever,
        // not a code change: a workspace_entitlements override of multiplier→1.0×
        // (tenths 10) makes the hard cap equal the included quota.
        e.trace_quota_monthly = 150_000;
        e.overage_hard_cap_multiplier_tenths = 10;
        assert_eq!(
            e.quota_config().hard_cap_absolute(),
            150_000,
            "multiplier 1.0× makes the 429 fire exactly at the included quota"
        );
        // …and 5.0× (tenths 50) gives the ADR-020 grace band.
        e.overage_hard_cap_multiplier_tenths = 50;
        assert_eq!(e.quota_config().hard_cap_absolute(), 750_000);
    }
}
