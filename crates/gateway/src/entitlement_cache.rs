//! In-process entitlement-resolution cache (ADR-035, TRD §23.1).
//!
//! Resolving `entitlements::check(tenant, F_*)` against Neon on every request
//! is ~5K round-trips/sec at the gateway target — a 5–15ms hop that blows the
//! <5ms p50 budget and makes a serverless DB a hard hot-path dependency. This
//! module removes that ceiling: entitlement reads become CPU-bound, served from
//! a `moka::future::Cache` with a 15-minute TTL (missed-`NOTIFY` backstop) and
//! 25s refresh-ahead — so even low-QPS tenants stay on the warm path.
//!
//! ## Resolution
//!
//! `deny-overrides-grant` is computed in Postgres at refresh time:
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
//! `workspace_entitlements` / `plan_entitlements`. The 15-minute TTL is only the
//! fallback if `LISTEN` drops — staleness is bounded at 15m, never unbounded.
//! (`LISTEN`/`NOTIFY` is the real, immediate invalidation; the TTL used to be
//! 30s, which turned every low-QPS request into a blocking Postgres re-resolve.)
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

/// Cache TTL — **the invalidation bound**, not a backstop behind `NOTIFY`.
///
///  (2026-08-12) corrected this. It read: *"the missed-NOTIFY backstop, NOT
/// the primary invalidation … LISTEN invalidates immediately … so the TTL only
/// bounds staleness in the rare case LISTEN drops."* On prod the drop was not
/// rare — **110 drops in 21.07 h, one per 11.5 min** — because the Neon compute
/// autosuspends at 5 min idle and this listener's own retry is what wakes it
/// (`pg_postmaster_start_time` 10:35:19.76 vs our `LISTEN active` 10:35:20.27).
/// The listener is now OFF by default; see `control_plane_listen_enabled`.
///
/// The 15 minutes below is therefore the real staleness bound for entitlements.
/// API-key REVOCATION is bounded separately and much more tightly — 60s, in
/// `db::api_keys` — because a stale entitlement over-or-under-grants a feature
/// while a stale auth entry keeps a revoked credential working.
///
/// It was 30s, which forced a blocking Postgres
/// re-resolve on EVERY request from a low-QPS tenant (>30s between calls =
/// expired entry = miss), so intermittent/launch-week traffic paid a
/// ~60ms Neon-Frankfurt round-trip per request (~72ms p50 gateway overhead)
/// while the warm/sustained path measured ~1.6ms. 15 minutes keeps sparse
/// traffic on the warm path (served instantly on a hit; `spawn_refresh` keeps
/// the entry fresh off-path when it ages past `REFRESH_AHEAD`) — the warm
/// number becomes honest for every tenant, not just high-QPS ones (2026-07-25,
/// founder decision; matches the 15m auth-cache TTL in `db/api_keys.rs`).
const TTL: Duration = Duration::from_secs(900);
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
    /// `prompt_routes`.
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
    // ── Sprint 3, the eval loop (EVL-04/02/28/29). ──────────────────────────
    //
    // Four flags rather than one, because they gate four independently sellable
    // surfaces and a single `f_evals` would force the cheapest of them onto the
    // tier of the most expensive. `Datasets` is Builder+ (it is table-stakes
    // parity and gating it at Team loses the comparison before it starts); the
    // other three are Team+, mirroring `PromptPromotionWrite`, because each one
    // spends the tenant's provider money.
    //
    // ORDER MATTERS AND IT IS NOT PARALLEL (CLAUDE.md §4.0): the column lands in
    // Neon FIRST (`apps/web/db/migrations/0030_evl04_dataset_entitlements.sql`),
    // and only then does a gateway that reads it deploy. Reversing that reads a
    // column that does not exist yet and 500s the whole entitlement resolve.
    Datasets,
    Experiments,
    OnlineEvals,
    AnnotationQueues,
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
            Self::Datasets => "f_datasets",
            Self::Experiments => "f_experiments",
            Self::OnlineEvals => "f_online_evals",
            Self::AnnotationQueues => "f_annotation_queues",
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
    /// B1 Prompt-Promotion write workflow (ADR-009 Team+;).
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
    // Sprint 3 (EVL-04/02/28/29). Four flags, four surfaces — see FeatureKey.
    pub f_datasets: bool,
    pub f_experiments: bool,
    pub f_online_evals: bool,
    pub f_annotation_queues: bool,
    /// Monthly included trace quota (deny-overrides-grant from
    /// `workspace_entitlements` ⊕ `plan_entitlements`). The gateway hard-cap 429
    /// threshold = `trace_quota_monthly` × `overage_hard_cap_multiplier`.
    pub trace_quota_monthly: i64,
    /// Hard-cap multiplier as integer tenths (5.0× → 50, 1.0× → 10) so the
    /// hot-path decision stays integer-only and this struct keeps deriving `Eq`.
    pub overage_hard_cap_multiplier_tenths: i32,
    /// GWY-43: the workspace-wide monthly USD spend ceiling (`tenants
    /// .budget_usd_monthly`), in integer **micro-USD**. `0` = uncapped.
    ///
    /// Micro-USD rather than `Option<f64>` for one concrete reason: this struct
    /// derives `Eq`, which the cache uses to decide whether a refresh actually
    /// changed anything, and `f64` is not `Eq`. It also matches the unit
    /// `crate::spend` counts in, so no conversion happens on the hot path.
    ///
    /// This rides the entitlement cache rather than getting its own PG read
    /// because that cache is already the sanctioned per-tenant config path —
    /// 15-minute TTL with `LISTEN/NOTIFY` invalidation, never per request
    /// (`CLAUDE.md` §2, gw ↔ PG).
    pub workspace_budget_micro_usd: u64,
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
            // fail-CLOSED: no control plane => free tier, never paid.
            f_datasets: false,
            f_experiments: false,
            f_online_evals: false,
            f_annotation_queues: false,
            // Free-plan quota defaults (10K traces, 1.0× hard cap = 429
            // exactly at the included quota) — fail-restricted, mirrors
            // plan_entitlements.free_v1.
            trace_quota_monthly: 10_000,
            overage_hard_cap_multiplier_tenths: 10,
            workspace_budget_micro_usd: 0,
        }
    }

    /// The ONE sanctioned no-cache grant: the benchmark context (B-187d).
    ///
    /// Resolved at the ENTITLEMENT LAYER — the single site every per-tenant
    /// check reads from — instead of N bypasses at N enforcement points. Four
    /// separate limiters rejected the benchmark in sequence (router 400,
    /// free-tier rate limit 429, Bench-tier-ignored 429, monthly quota 429);
    /// patching each one scatters bench logic across the hot path and is how a
    /// bypass eventually leaks to a real tenant.
    ///
    /// The caller is responsible for the triple gate — see
    /// `.claude/rules/tenancy.md`. This constructor is inert on its own: it
    /// grants nothing unless something calls it, and the ONLY caller is the
    /// bench branch in `chat_completions_handler`, which requires
    /// `entitlements.is_none()` (no Postgres control plane) AND the reserved
    /// `__bench_mock*` model AND the env flag — with a STARTUP REFUSAL making
    /// the flag+Postgres combination impossible to boot.
    ///
    /// `plan_lookup_key` is deliberately `"__bench"`, not a real plan string:
    /// `RateLimitTier::from_plan_tier_str` maps it to `Free`, so even if this
    /// grant leaked into a tier lookup it could not confer a commercial tier.
    /// The unlimited limits come from the explicit fields below, not the key.
    #[must_use]
    /// TEST ONLY — a cache granting the four PAID rails (R2 PII, R5 format,
    /// R6 sysprompt-leak, R7 topic).
    ///
    /// Before the no-cache inversion was fixed, a `None` entitlement
    /// cache granted every rail, so tests exercising a PAID rail could pass
    /// `None` and still get it. That is exactly the bug. Tests that assert paid
    /// behaviour must now GRANT it explicitly — which also means each such test
    /// documents, at its call site, that the behaviour it checks is paid.
    #[cfg(test)]
    pub(crate) fn paid_rails_cache() -> std::sync::Arc<EntitlementCache> {
        let grant: ResolveFn = std::sync::Arc::new(|_tenant| {
            Box::pin(async {
                let mut e = ResolvedEntitlements::deny_all();
                e.f_guardrail_r2 = true;
                e.f_guardrail_r5 = true;
                e.f_guardrail_r6 = true;
                e.f_guardrail_r7 = true;
                Ok(e)
            })
        });
        std::sync::Arc::new(EntitlementCache::new(grant))
    }

    pub fn bench_unlimited() -> Self {
        Self {
            plan_lookup_key: "__bench".to_string(),
            // Predictive/paid features stay OFF: the benchmark measures the
            // gateway's own overhead, not optional inference. Granting them
            // would inflate the number and make it unrepresentative.
            f_pr7_trajectory: false,
            f_pr8_argdrift: false,
            f_pr9_a2a_handoff: false,
            f_pr10_inline_slm_judge: false,
            f_pr11_slo_drift: false,
            f_pr12_langgraph_branch: false,
            f_cohort_baselines: false,
            f_hipaa_gcp_addon: false,
            f_audit_addon: false,
            f_audit_selfverify: true,
            f_prompt_promotion_write: false,
            // Rails ON: the benchmark must measure the guardrail work a real
            // request pays for. This is also what the pre-B-187d no-cache
            // RailGate did implicitly — now it is explicit and bench-scoped.
            f_guardrail_r2: true,
            f_guardrail_r3_pinning: true,
            f_guardrail_r4: true,
            f_guardrail_r5: true,
            f_guardrail_r6: true,
            f_guardrail_r7: true,
            retention_days: 7,
            f_full_capture: false,
            f_alerts: false,
            // fail-CLOSED: no control plane => free tier, never paid.
            f_datasets: false,
            f_experiments: false,
            f_online_evals: false,
            f_annotation_queues: false,
            // The point of the grant: no rate-limit tier and no monthly quota
            // can reject the run. `trace_quota_monthly: 0` is the documented
            // "unlimited" sentinel — `QuotaTracker::check` early-returns Allow
            // on 0 (rate_limiter.rs:312), so this short-circuits the quota the
            // same way the tier short-circuits the limiter.
            trace_quota_monthly: 0,
            overage_hard_cap_multiplier_tenths: 10,
            workspace_budget_micro_usd: 0,
        }
    }

    /// Is this the bench grant? Keyed on the reserved `plan_lookup_key`, which
    /// no Polar plan can produce.
    #[must_use]
    pub fn is_bench(&self) -> bool {
        self.plan_lookup_key == "__bench"
    }

    /// The rate-limit tier this grant confers.
    ///
    /// Lives HERE, on the grant, rather than as a branch in the hot path: the
    /// tier is a property of the entitlement, so `chat_completions_handler` no
    /// longer mentions bench when resolving limits at all. One auditable site.
    #[must_use]
    pub fn rate_limit_tier(&self) -> crate::rate_limiter::RateLimitTier {
        if self.is_bench() {
            crate::rate_limiter::RateLimitTier::Bench
        } else {
            crate::rate_limiter::RateLimitTier::from_plan_tier_str(
                self.plan_lookup_key.trim_end_matches("_v1"),
            )
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
            FeatureKey::Datasets => self.f_datasets,
            FeatureKey::Experiments => self.f_experiments,
            FeatureKey::OnlineEvals => self.f_online_evals,
            FeatureKey::AnnotationQueues => self.f_annotation_queues,
        }
    }

    /// Derive the gateway monthly-quota config from the resolved
    /// entitlements. The 429 hard cap = `trace_quota_monthly` × multiplier, both
    /// sourced from `workspace_entitlements` ⊕ `plan_entitlements` (never the
    /// hardcoded plan map — that drift was the gap; CLAUDE.md control-
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
                  COALESCE(we.f_pr7_trajectory, pe.f_pr7_trajectory) AS f_pr7_trajectory, \
                  COALESCE(we.f_pr8_argdrift, pe.f_pr8_argdrift) AS f_pr8_argdrift, \
                  COALESCE(we.f_pr9_a2a_handoff, pe.f_pr9_a2a_handoff) AS f_pr9_a2a_handoff, \
                  COALESCE(we.f_pr10_inline_slm_judge, pe.f_pr10_inline_slm_judge) AS f_pr10_inline_slm_judge, \
                  COALESCE(we.f_pr11_slo_drift, pe.f_pr11_slo_drift) AS f_pr11_slo_drift, \
                  COALESCE(we.f_pr12_langgraph_branch, pe.f_pr12_langgraph_branch) AS f_pr12_langgraph_branch, \
                  COALESCE(we.f_cohort_baselines, pe.f_cohort_baselines) AS f_cohort_baselines, \
                  COALESCE(we.f_hipaa_gcp_addon, pe.f_hipaa_gcp_addon) AS f_hipaa_gcp_addon, \
                  COALESCE(we.f_audit_addon, pe.f_audit_addon) AS f_audit_addon, \
                  COALESCE(we.retention_days, pe.retention_days) AS retention_days, \
                  COALESCE(we.f_guardrail_r2, pe.f_guardrail_r2) AS f_guardrail_r2, \
                  COALESCE(we.f_guardrail_r3_pinning, pe.f_guardrail_r3_pinning) AS f_guardrail_r3_pinning, \
                  COALESCE(we.f_guardrail_r4, pe.f_guardrail_r4) AS f_guardrail_r4, \
                  COALESCE(we.f_guardrail_r5, pe.f_guardrail_r5) AS f_guardrail_r5, \
                  COALESCE(we.f_guardrail_r6, pe.f_guardrail_r6) AS f_guardrail_r6, \
                  COALESCE(we.f_guardrail_r7, pe.f_guardrail_r7) AS f_guardrail_r7, \
                  COALESCE(we.f_full_capture, pe.f_full_capture) AS f_full_capture, \
                  COALESCE(we.f_prompt_promotion_write, pe.f_prompt_promotion_write) AS f_prompt_promotion_write, \
                  COALESCE(we.f_alerts, pe.f_alerts) AS f_alerts, \
                  COALESCE(we.f_datasets, pe.f_datasets) AS f_datasets, \
                  COALESCE(we.f_experiments, pe.f_experiments) AS f_experiments, \
                  COALESCE(we.f_online_evals, pe.f_online_evals) AS f_online_evals, \
                  COALESCE(we.f_annotation_queues, pe.f_annotation_queues) AS f_annotation_queues, \
                  COALESCE(we.f_audit_selfverify, pe.f_audit_selfverify) AS f_audit_selfverify, \
                  COALESCE(we.trace_quota_monthly, pe.trace_quota_monthly) AS trace_quota_monthly, \
                  (COALESCE(we.overage_hard_cap_multiplier, pe.overage_hard_cap_multiplier) * 10)::int \
                    AS overage_hard_cap_multiplier_tenths, \
                  t.budget_usd_monthly::text AS workspace_budget_usd_text \
                FROM workspace_entitlements we \
                JOIN plan_entitlements pe ON pe.plan_lookup_key = we.plan_lookup_key \
                LEFT JOIN tenants t ON t.id = we.tenant_id \
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
                  f_datasets, f_experiments, f_online_evals, f_annotation_queues, \
                  f_audit_selfverify, \
                  trace_quota_monthly, \
                  (overage_hard_cap_multiplier * 10)::int AS overage_hard_cap_multiplier_tenths \
                FROM plan_entitlements WHERE plan_lookup_key = 'free_v1'";
            match client.query_opt(FALLBACK, &[]).await? {
                Some(row) => Ok(row_to_resolved(&row)),
                None => Ok(ResolvedEntitlements::deny_all()),
            }
        }) as Pin<Box<dyn Future<Output = anyhow::Result<ResolvedEntitlements>> + Send>>
    })
}

/// Map one entitlements row onto [`ResolvedEntitlements`], **by COLUMN NAME**.
///
/// ## Why this is not `row.get(0..23)` any more
///
/// It was, and it was the highest value-to-cost item in the 2026-07-29
/// falsification audit (PL-20 #1). Twenty-four positional reads against two
/// hand-written SELECTs, with **zero real coverage** — every gateway test
/// injects a mock resolver, so nothing exercised this function at all. A single
/// column inserted or reordered in either query shifts every field below it, and
/// the failure is silent: booleans still deserialise as booleans.
///
/// The blast radius is what made it #1. One reorder misgrants across **billing,
/// guardrails and audit simultaneously** — and `f_guardrail_r4` does not merely
/// over-permit, it **BLOCKS with a 403**, so a mis-slotted grant is a live denial
/// of a paying tenant's traffic rather than a quiet extra feature.
///
/// **The audit's recommended fix was a test. This is better than a test:** with
/// every column aliased and every read by name, a reorder cannot land a value in
/// the wrong field at all. The hazard is removed rather than detected. A test
/// tells you afterwards; a name never lets it happen.
///
/// That required aliasing the primary query's columns, which is why they now all
/// carry `AS <field>` — Postgres names a `COALESCE(...)` expression `coalesce`,
/// so name lookup was impossible before and positional indexing was the only
/// option available. The alias is the enabling change.
///
/// Cost: a name lookup is O(columns) rather than O(1). Irrelevant here — this
/// runs on a cache MISS, not per request (`CLAUDE.md` §2: never a per-request
/// Postgres round-trip).
///
/// # Panics
/// `Row::get` panics on an unknown column, which is the correct direction: a
/// query that stops returning a field is a deploy-time bug, and failing loudly
/// beats resolving a tenant's entitlements from a half-read row. The one
/// genuinely optional column uses `try_get` — see below.
fn row_to_resolved(row: &tokio_postgres::Row) -> ResolvedEntitlements {
    ResolvedEntitlements {
        plan_lookup_key: row.get("plan_lookup_key"),
        f_pr7_trajectory: row.get("f_pr7_trajectory"),
        f_pr8_argdrift: row.get("f_pr8_argdrift"),
        f_pr9_a2a_handoff: row.get("f_pr9_a2a_handoff"),
        f_pr10_inline_slm_judge: row.get("f_pr10_inline_slm_judge"),
        f_pr11_slo_drift: row.get("f_pr11_slo_drift"),
        f_pr12_langgraph_branch: row.get("f_pr12_langgraph_branch"),
        f_cohort_baselines: row.get("f_cohort_baselines"),
        f_hipaa_gcp_addon: row.get("f_hipaa_gcp_addon"),
        f_audit_addon: row.get("f_audit_addon"),
        retention_days: row.get("retention_days"),
        f_guardrail_r2: row.get("f_guardrail_r2"),
        f_guardrail_r3_pinning: row.get("f_guardrail_r3_pinning"),
        f_guardrail_r4: row.get("f_guardrail_r4"),
        f_guardrail_r5: row.get("f_guardrail_r5"),
        f_guardrail_r6: row.get("f_guardrail_r6"),
        f_guardrail_r7: row.get("f_guardrail_r7"),
        f_full_capture: row.get("f_full_capture"),
        f_prompt_promotion_write: row.get("f_prompt_promotion_write"),
        f_alerts: row.get("f_alerts"),
        // BY NAME, never by position — `fd51a598` fixed a 23-column positional
        // read with zero coverage, where a reorder would silently misgrant.
        f_datasets: row.get("f_datasets"),
        f_experiments: row.get("f_experiments"),
        f_online_evals: row.get("f_online_evals"),
        f_annotation_queues: row.get("f_annotation_queues"),
        f_audit_selfverify: row.get("f_audit_selfverify"),
        trace_quota_monthly: row.get("trace_quota_monthly"),
        overage_hard_cap_multiplier_tenths: row.get("overage_hard_cap_multiplier_tenths"),
        // Present ONLY on the primary query. The FALLBACK (an unseeded tenant,
        // plan defaults only) has no `tenants` join, so this column does not
        // exist there — and an unseeded tenant has no workspace budget, which is
        // the same answer. `try_get` by name absorbs both "absent column" and
        // "NULL" without conflating them with a real zero.
        //
        // Parse failure is also uncapped: `tenants_budget_nonneg_chk` rejects a
        // negative at write time, and a mis-read that silently refuses every
        // request is worse than one that fails to bite.
        workspace_budget_micro_usd: row
            .try_get::<_, Option<String>>("workspace_budget_usd_text")
            .ok()
            .flatten()
            .and_then(|t| t.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v > 0.0)
            .map_or(0, |v| (v * 1_000_000.0).round() as u64),
    }
}

/// Spawn the long-lived `LISTEN entitlements_changed` task.
///
/// Uses a **dedicated direct** connection (`POSTGRES_DIRECT_URL`, falling back
/// to `POSTGRES_URL`) because `LISTEN`/`NOTIFY` does not survive a PgBouncer
/// transaction pooler. The `NOTIFY` payload is the workspace UUID; on receipt
/// the matching cache entry is evicted. On connection drop the task reconnects
/// with backoff (the 15m TTL bounds staleness in the gap) and increments
/// `tracelane_listen_reconnect_total`.
///
/// Returns immediately; the task runs until the process exits.
///
/// **`LISTEN` is disabled only when BOTH vars are unset** — the fallback below
/// is an `or_else`, not a `None` short-circuit.: this doc comment
/// previously claimed "a `None`/unset direct URL disables `LISTEN`", which the
/// two lines under it contradict; with `POSTGRES_DIRECT_URL` unset and
/// `POSTGRES_URL` pointing at Neon's `-pooler`, the task connects to PgBouncer,
/// `LISTEN` succeeds, and no notification can ever arrive. `listen_once` now
/// inspects the resolved HOST and says `DEGRADED` in that case instead of
/// `active` — see `tracelane_shared::listen_dsn`.
/// Is the control-plane `LISTEN` task enabled? **Default OFF** (re-ruling,
/// 2026-08-12) — opt in with `TRACELANE_CONTROL_PLANE_LISTEN=1`.
///
/// **Why it is off.** Measured on prod over 21.07 h: the LISTEN connection was
/// dropped and re-established **110 times** — one per 11.5 min — with the gateway
/// and ingest sockets dying in the same millisecond, i.e. the Neon compute
/// suspending, not a network blip. `pg_postmaster_start_time()` came back
/// `10:35:19.76` against our own `LISTEN active` at `10:35:20.27`: **our retry is
/// what wakes the compute.** So the listener did not hold the compute open; it
/// resurrected it ~30-60s after every autosuspend, keeping it up ~91-95% of the
/// time and the bill near the pinned-compute figure.
///
/// **And the guarantee it existed for was not being delivered.** `pg_notify`
/// reaches only listeners attached at that instant — it is not durable. The
/// producer is an AFTER-UPDATE trigger inside the revoking transaction
/// (`0019_api_keys_revoke_notify.sql:21`). On an idle system the revoking `UPDATE`
/// is itself what wakes a fresh postmaster, while this listener is still holding a
/// dead socket it has not noticed yet — so the NOTIFY lands on zero listeners and
/// is gone. The revocation traffic causes the wake, so the listener is
/// structurally guaranteed to be late. That is not flakiness; it is a bias
/// against precisely the case the mechanism exists for.
///
/// The honest bound was therefore the auth-cache TTL all along. That TTL is now
/// **60s** (`db::api_keys`), which bounds revocation more tightly than the 15
/// minutes this actually delivered — and, because the cache is positives-only and
/// in-memory, expiry costs a PG query only when a request arrives, so it does NOT
/// poll and does NOT defeat autosuspend.
///
/// Turn it back on when there is enough traffic that the compute never idles
/// anyway; then NOTIFY delivery stops being a lottery and the argument changes.
#[must_use]
pub fn control_plane_listen_enabled() -> bool {
    std::env::var("TRACELANE_CONTROL_PLANE_LISTEN").is_ok_and(|v| v == "1")
}

pub fn spawn_listen_task(cache: EntitlementCache) {
    if !control_plane_listen_enabled() {
        tracing::info!(
            "control-plane LISTEN DISABLED (default; set TRACELANE_CONTROL_PLANE_LISTEN=1 to \
             enable) — entitlement invalidation is TTL-bound (15m) and API-key revocation is \
             TTL-bound (60s). Measured rationale: the listener did not hold the Neon compute \
             open (110 drop/reconnect cycles in 21h) and could not reliably receive a \
             key_revoked NOTIFY, because the revoking UPDATE is what wakes the compute."
        );
        return;
    }
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
            // reconnect. Backoff first; the 15m TTL bounds staleness in the gap.
            LISTEN_RECONNECT_TOTAL.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// The first TCP host in `cfg` that is a pooler and therefore cannot deliver
/// `NOTIFY`, or `None` when every host can.
///
/// Reads the host from the PARSED config rather than substring-matching the DSN:
/// a password may legitimately contain `-pooler`, and matching the raw string
/// would degrade a correctly-configured direct endpoint. The predicate itself
/// (with its label-vs-substring tests) lives in `tracelane_shared::listen_dsn`
/// so the gateway and ingest cannot drift apart on what "pooled" means.
fn pooled_listen_host(cfg: &tokio_postgres::Config) -> Option<String> {
    use tokio_postgres::config::Host;
    cfg.get_hosts().iter().find_map(|h| match h {
        Host::Tcp(host) if tracelane_shared::listen_dsn::host_cannot_deliver_notify(host) => {
            Some(host.clone())
        }
        _ => None,
    })
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
    // A LISTEN connection carries NO traffic by design, so a socket that dies
    // silently — a half-open TCP with no FIN, which is what a cloud proxy or a
    // compute restart can leave behind — is invisible to it. `poll_message` just
    // stays Pending, the driver task never ends, the channel never closes, and the
    // reconnect loop below is never reached. It does not fail; it waits forever.
    //
    // EARNED 2026-08-11: after a Neon compute restart, ingest's LISTEN went silent
    // and never reconnected — no error line, no reconnect line — while the gateway,
    // which happened to receive a clean FIN, reconnected in 3 seconds. tokio-postgres
    // defaults to a 2-HOUR keepalive idle, so the dead listener would have gone
    // unnoticed for two hours, and nothing would have said so. Correctness survived
    // on the TTL fallback; the silence is the defect.
    //
    // 30s idle + a bounded user timeout turns "waits forever" into "reconnects in
    // under a minute, loudly".
    pg_cfg.keepalives(true);
    pg_cfg.keepalives_idle(std::time::Duration::from_secs(30));
    pg_cfg.keepalives_interval(std::time::Duration::from_secs(10));
    pg_cfg.keepalives_retries(3);
    pg_cfg.tcp_user_timeout(std::time::Duration::from_secs(60));
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

    // One dedicated direct LISTEN connection carries both control-plane channels:
    // entitlement invalidation AND api-key revocation (fix B) — no second
    // direct connection needed.
    client
        .batch_execute("LISTEN entitlements_changed; LISTEN key_revoked")
        .await?;
    // `LISTEN` SUCCEEDS on a PgBouncer transaction pooler — the statement
    // is valid, the backend is just handed to another client before any NOTIFY
    // can be routed back. So a successful `batch_execute` is NOT evidence that
    // invalidation works, and reporting "active" here was the guard lying. Ask
    // the resolved host instead; on a pooler this degrades to the 15m TTL, which
    // means a revoked API key stays usable for up to 15 minutes.
    match pooled_listen_host(&pg_cfg) {
        Some(host) => tracing::warn!(
            host = %host,
            "control-plane LISTEN DEGRADED — connected to a POOLED endpoint that cannot \
             deliver NOTIFY; entitlement + key_revoked invalidation is TTL-only (15m), so a \
             revoked API key stays usable until it expires. Set POSTGRES_DIRECT_URL to the \
             direct (non-pooler) endpoint."
        ),
        None => {
            tracing::info!("control-plane LISTEN active on entitlements_changed + key_revoked");
        }
    }

    while let Some(msg) = rx.recv().await {
        match msg {
            AsyncMessage::Notification(note) => match note.channel() {
                //  fix B: an api key was revoked — payload is hex(lookup_hash),
                // the auth-cache key. Evict it so revocation stays immediate.
                "key_revoked" => match hex::decode(note.payload()) {
                    Ok(v) if v.len() == 32 => {
                        let mut digest = [0u8; 32];
                        digest.copy_from_slice(&v);
                        crate::db::api_keys::invalidate(digest).await;
                        tracing::debug!("auth cache invalidated via key_revoked NOTIFY");
                    }
                    _ => {
                        tracing::warn!("key_revoked NOTIFY payload was not 32-byte hex — ignoring")
                    }
                },
                // entitlements_changed (default): payload is a tenant UUID, or
                // "ALL" for a plan_entitlements change affecting every tenant.
                _ => {
                    let payload = note.payload();
                    if payload == "ALL" {
                        cache.invalidate_all();
                        tracing::debug!("entitlement cache fully invalidated via NOTIFY ALL");
                    } else if let Ok(tenant) = Uuid::parse_str(payload) {
                        cache.invalidate(tenant).await;
                        tracing::debug!(%tenant, "entitlement cache invalidated via NOTIFY");
                    }
                }
            },
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

    /// The DEGRADED branch must actually FIRE on the config the ordinary
    /// Neon deployment produces. Driven from a DSN string, not a hand-built
    /// `Config`, so it covers the whole path the running process takes:
    /// env var -> parse -> host -> predicate.
    #[test]
    fn pooled_endpoint_is_reported_degraded() {
        let cfg: tokio_postgres::Config =
            "postgres://u:pw@ep-cool-frost-123456-pooler.eu-central-1.aws.neon.tech/db"
                .parse()
                .expect("parse");
        assert_eq!(
            pooled_listen_host(&cfg).as_deref(),
            Some("ep-cool-frost-123456-pooler.eu-central-1.aws.neon.tech"),
            "the -pooler endpoint must be reported as unable to deliver NOTIFY"
        );
    }

    /// The other direction: a direct endpoint must NOT be degraded, or every
    /// healthy deployment logs a warning and the warning stops meaning anything.
    #[test]
    fn direct_endpoint_is_not_degraded() {
        let cfg: tokio_postgres::Config =
            "postgres://u:pw@ep-cool-frost-123456.eu-central-1.aws.neon.tech/db"
                .parse()
                .expect("parse");
        assert!(pooled_listen_host(&cfg).is_none());
    }

    /// The discriminating case, and the reason this reads the PARSED host rather
    /// than the DSN: a password may legitimately contain `-pooler`. A
    /// `conn_str.contains("-pooler")` check would degrade this correctly-
    /// configured DIRECT endpoint. This test fails against that implementation.
    #[test]
    fn a_password_containing_pooler_does_not_degrade_a_direct_endpoint() {
        let dsn = "postgres://u:s3cret-pooler@ep-cool-frost-123456.eu-central-1.aws.neon.tech/db";
        assert!(
            dsn.contains("-pooler"),
            "fixture must actually exercise the substring trap"
        );
        let cfg: tokio_postgres::Config = dsn.parse().expect("parse");
        assert!(
            pooled_listen_host(&cfg).is_none(),
            "a -pooler in the PASSWORD must not be read as a pooled host"
        );
    }

    fn grant_all() -> ResolvedEntitlements {
        ResolvedEntitlements {
            // Sprint 3 flags. `grant_all` means ALL — a fixture that quietly omits a
            // new flag would make every test using it assert the FREE behaviour while
            // reading as the entitled one, which is the inverted-default shape
            // shipped (`.claude/rules/tenancy.md`).
            f_datasets: true,
            f_experiments: true,
            f_online_evals: true,
            f_annotation_queues: true,
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
            workspace_budget_micro_usd: 0,
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

    /// The gateway quota is entitlement-driven — `quota_config` reads the
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

    /// PL-20 #1 — the falsification proof for the entitlements resolver.
    ///
    /// `row_to_resolved` now reads by NAME, so a column reorder can no longer
    /// misgrant. This closes the other half: that the names it reads actually
    /// EXIST in both queries. Adding a field to `ResolvedEntitlements` and
    /// wiring `row.get("f_new_thing")` without adding the column to the SQL
    /// compiles fine and panics at runtime, on a cache miss, in production —
    /// which is precisely the shape of failure this resolver keeps producing.
    ///
    /// It reads its own source rather than a fixture, so it cannot drift from
    /// the thing it describes. No database required, so it runs in the ordinary
    /// `cargo test` lane rather than the real-Postgres one — the audit's note
    /// that only 2 of 24 CI guards are re-runnable is the reason that matters.
    #[test]
    fn every_column_the_resolver_reads_exists_in_both_queries() {
        let src = include_str!("entitlement_cache.rs");

        // Scan ONLY the mapper's body. Scanning the whole file also matched a
        // `row.get("…")` written inside this test's own doc comment — the probe
        // found itself, which is a self-match, not a finding.
        let body_start = src
            .find("fn row_to_resolved(")
            .expect("row_to_resolved not found");
        let body_end = src[body_start..]
            .find("\n}\n")
            .expect("end of row_to_resolved")
            + body_start;
        let body = &src[body_start..body_end];

        // The names the mapper asks for.
        let mut wanted: Vec<&str> = Vec::new();
        for seg in body.split("row.get(\"").skip(1) {
            if let Some(end) = seg.find('"') {
                wanted.push(&seg[..end]);
            }
        }
        for seg in body.split("try_get::<_, Option<String>>(\"").skip(1) {
            if let Some(end) = seg.find('"') {
                wanted.push(&seg[..end]);
            }
        }
        assert!(
            wanted.len() >= 23,
            "expected the full entitlement column set, found {} — did the mapper change shape?",
            wanted.len()
        );

        // Slice each SQL constant out of the source.
        let cut = |marker: &str| -> String {
            let at = src
                .find(marker)
                .unwrap_or_else(|| panic!("{marker} not found"));
            let from = src[at..].find("SELECT").expect("SELECT") + at;
            let to = src[from..].find("\";").expect("end of SQL literal") + from;
            src[from..to].to_string()
        };
        let primary = cut("const SQL: &str");
        let fallback = cut("const FALLBACK: &str");

        // What NAME would Postgres give each selected column? That is the only
        // thing `row.get(name)` can address, and it is NOT "the name appears
        // somewhere in the SQL text".
        //
        // THE FIRST VERSION OF THIS TEST USED `sql.contains(name)` AND WAS
        // WORTHLESS. Dropping `AS f_guardrail_r4` leaves `f_guardrail_r4` in the
        // text twice over, inside `COALESCE(we.f_guardrail_r4, pe.f_guardrail_r4)`
        // — so the substring check passed while the column had become
        // unaddressable and the resolver would panic in production. Both
        // deliberate falsifications went green. That is the exact PL-20 shape
        // this test exists to close, reproduced by the test itself, which is why
        // it now parses output names instead of grepping.
        fn output_names(sql: &str) -> Vec<String> {
            let list = &sql
                [sql.find("SELECT").map_or(0, |i| i + 6)..sql.find(" FROM ").unwrap_or(sql.len())];
            let mut names = Vec::new();
            let mut depth = 0usize;
            let mut cur = String::new();
            for ch in list.chars() {
                match ch {
                    '(' => {
                        depth += 1;
                        cur.push(ch);
                    }
                    ')' => {
                        depth = depth.saturating_sub(1);
                        cur.push(ch);
                    }
                    ',' if depth == 0 => {
                        names.push(std::mem::take(&mut cur));
                    }
                    _ => cur.push(ch),
                }
            }
            names.push(cur);
            names
                .into_iter()
                .filter_map(|col| {
                    let col = col.replace('\\', " ");
                    let col = col.trim().to_string();
                    if col.is_empty() {
                        return None;
                    }
                    // `… AS name` wins.
                    if let Some(at) = col.rfind(" AS ") {
                        return Some(col[at + 4..].trim().to_string());
                    }
                    // A bare or qualified column reference: `pe.foo` -> `foo`.
                    // Anything with an expression in it (parens, a cast) is
                    // UNNAMED in Postgres and therefore not addressable.
                    if col.contains('(') || col.contains("::") {
                        return None;
                    }
                    Some(col.rsplit('.').next().unwrap_or(&col).trim().to_string())
                })
                .collect()
        }

        let primary_names = output_names(&primary);
        let fallback_names = output_names(&fallback);

        for name in &wanted {
            assert!(
                primary_names.iter().any(|c| c == name),
                "`{name}` is not an addressable OUTPUT COLUMN of the PRIMARY query \
                 (it needs `AS {name}`, or to be a bare column reference) — \
                 `row.get(\"{name}\")` will PANIC on a cache miss in production. \
                 Addressable columns are: {primary_names:?}"
            );
        }

        // The fallback deliberately lacks the workspace budget: it has no
        // `tenants` join, and an unseeded tenant has no workspace budget. That is
        // the ONE permitted absence, and `try_get` is what makes it safe — so
        // this asserts the exception is exactly one column wide rather than
        // letting a second silently join it.
        let missing: Vec<&&str> = wanted
            .iter()
            .filter(|n| !fallback_names.iter().any(|c| c == **n))
            .collect();
        assert_eq!(
            missing,
            vec![&"workspace_budget_usd_text"],
            "the FALLBACK query may omit exactly ONE column (the workspace \
             budget, read with try_get). Anything else listed here is a field \
             that will panic for every unseeded tenant. Fallback columns: \
             {fallback_names:?}"
        );
    }
}
