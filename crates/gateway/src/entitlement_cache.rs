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
/// Requests served a last-known grant past the TTL while a refresh ran off-path.
pub static STALE_SERVED_TOTAL: AtomicU64 = AtomicU64::new(0);
static FAIL_OPEN_TOTAL: AtomicU64 = AtomicU64::new(0);

// `metrics_snapshot` / `EntitlementMetrics` (a `(cache_miss_total,
// listen_reconnect_total, fail_open_total)` reader) were deleted 2026-09-12
// (B-390) — zero callers anywhere, including tests; no `/metrics` route
// wires this in yet, despite the doc comment's claim. The three counters
// themselves (`CACHE_MISS_TOTAL`, `LISTEN_RECONNECT_TOTAL`,
// `FAIL_OPEN_TOTAL`) are untouched and still incremented at their call
// sites below.

/// A gated feature flag (the `f_*` columns of `plan_entitlements`).
///
/// Found 2026-09-12 (B-390): 15 of these variants are never passed to
/// `.has()`/`.check()` by any production request path, in two different
/// ways. `Pr7Trajectory` through `HipaaGcpAddon` (8 variants) are real,
/// tested entitlement plumbing for features that are simply NOT_BUILT yet
/// (matches `docs/inventory/README.md`) — nothing calls
/// `.check(tenant, FeatureKey::PrN...)` because the PR7-12 predictive tiers,
/// cohort baselines and the HIPAA/GCP add-on don't exist. `AuditSelfVerify`
/// and `GuardrailR2`..`GuardrailR7` (7 variants) are the opposite case: the
/// FEATURES are absolutely live, but their entitlement check bypasses this
/// enum entirely — `rail.rs`'s `RailGate::from_resolved` and
/// `audit_self_verify.rs` read the resolved struct's `f_guardrail_r*` /
/// `f_audit_selfverify` fields directly, never through `FeatureKey`.
/// Left as one `#[allow(dead_code)]` rather than deleted or split apart:
/// sorting genuinely-unbuilt from checked-a-different-way needs either an
/// ADR (to drop the `plan_entitlements` columns for the unbuilt half) or a
/// refactor (to route the guardrail/audit-self-verify half through this
/// enum too) — neither is a dead-code cleanup, and getting it wrong here
/// risks entitlement correctness, not just a warning.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeatureKey {
    Pr7Trajectory,
    Pr8ArgDrift,
    Pr9A2aHandoff,
    Pr10InlineSlmJudge,
    Pr11SloDrift,
    Pr12LanggraphBranch,
    CohortBaselines,
    AuditAddon,
    /// Free-tier audit self-verify (ADR-066). Default-TRUE on every plan — lets a
    /// tenant SEE + verify their OWN recent chain in-app. Distinct from the paid
    /// `AuditAddon` (the Article-12 export — Enterprise-seeded; the paid SKU is not sold, B-392). A per-workspace
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
    /// BILL-01 / ADR-076 — SSO from Team. Reads `ResolvedEntitlements.f_sso`,
    /// which the resolver derives from `plan_entitlements.f_sso` (Team+)
    /// overlaid by a `workspace_entitlements.f_sso` override.
    Sso,
}

// `impl FeatureKey { pub fn column(self) -> &'static str { ... } }` (a
// `FeatureKey` -> Postgres column-name mapping) was deleted 2026-09-12
// (B-390) — zero callers anywhere, including tests. The real resolution
// path (below, the `has`-style match) reads each `f_*` struct field
// directly by name rather than building a column-name string dynamically;
// the SQL SELECT lists that name these same columns (`db/mod.rs` and
// friends) are separate hardcoded literals, not built from this method
// either. Restorable from git history at
// `607aaa205d52f2545ab6bf81a76ed524f2747f44` if a dynamic per-flag query
// is ever built. (SHA: `2d1f164ba924f7c0bc846c06e8400866cbb32ae1`.)

/// BILL-01 / ADR-076 §0.4 — the customer's overflow choice at the spend
/// ceiling. `AutoAge` (the default) ages the oldest indexed data out early and
/// keeps it queryable in cold; `AutoOverage` is opt-in and keeps billing past
/// the ceiling. Never a third state: the Postgres columns are `CHECK`-
/// constrained to these two strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowMode {
    AutoAge,
    AutoOverage,
}

impl OverflowMode {
    /// Parse the Postgres `text` value. Anything unrecognised (there should be
    /// none — the column is `CHECK`-constrained) fails to the SAFE default:
    /// auto-age never loses data, auto-overage keeps charging silently.
    #[must_use]
    pub fn from_column(s: &str) -> Self {
        match s {
            "auto_overage" => Self::AutoOverage,
            _ => Self::AutoAge,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoAge => "auto_age",
            Self::AutoOverage => "auto_overage",
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
    /// ADR-048 D2 — full-capture gate (Business + Enterprise base; an active
    /// audit-export entitlement forces it). The ingest sampler enforces capture via its own
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
    /// BILL-01 / ADR-076 — SSO from Team. Own field (not routed only through
    /// `FeatureKey`) because the resolver reads it directly for the pricing
    /// page + `/v1/billing/usage`'s `plan` block.
    pub f_sso: bool,
    // ── BILL-01 / ADR-076 — the six-meter model's per-plan allowances ───────
    //
    // `None` on any `*_included` field means CUSTOM (Enterprise only — the
    // Postgres column is genuinely NULL, never a sentinel zero). `Some(0)` is
    // a real zero allowance (the fail-closed `deny_all()` state). Bytes, not
    // GB: the Postgres `numeric(12,3)` GB figure is converted once, here, so
    // every caller compares against the SAME unit `usage_daily`/`meter_counters`
    // record in (bytes), never re-deriving GB->bytes at each read site.
    pub hot_bytes_included: Option<u64>,
    pub ingest_bytes_included: Option<u64>,
    pub series_included: Option<i64>,
    pub scan_units_included: Option<i64>,
    pub eval_runs_included: Option<i64>,
    pub indexed_window_days: i32,
    pub queryable_days: i32,
    pub ledger_days: i32,
    /// Free is the only tier capped at 1 seat. Every paid tier resolves `true`
    /// (ADR-076 §0.3) — plan-level only, no `workspace_entitlements` override
    /// column exists for this one.
    pub unlimited_seats: bool,
    /// Free: no overage, ages out rather than bills. Every paid tier is `true`.
    pub overage_allowed: bool,
    pub overflow_mode: OverflowMode,
    /// Per-tenant requests-per-minute from the DB (replaces
    /// `RateLimitTier::from_plan_tier_str`). `None` = no limit (Enterprise, and
    /// the no-control-plane self-host default, B-357).
    pub rate_limit_rpm: Option<u32>,
    /// `None` = contract pricing (Enterprise's "from $2,499"), never a customer-
    /// facing zero.
    pub price_monthly_usd: Option<i32>,
    pub price_annual_month_usd: Option<i32>,
    pub price_from_usd: Option<i32>,
    pub polar_product_id_month: Option<String>,
    pub polar_product_id_year: Option<String>,
    /// A3 velocity breaker (`tenants.promotion_frozen_at/_reason`). While set,
    /// `prompt_routes` promote/rollback return `423 promotion_frozen` — read
    /// through this cache rather than a per-request Postgres round trip.
    pub promotion_frozen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub promotion_frozen_reason: Option<String>,
    /// The pricing-rates version this tenant is rated against
    /// (`tenants.price_version`) — price protection (ADR-076 §0.5). `None`
    /// means "the current version", read by `billing::rating`.
    pub price_version: Option<String>,
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
    /// BILL-01 / ADR-076 §0.4 — the customer-set monthly spend ceiling
    /// (`tenants.spend_ceiling_usd`, opt-in, off by default), in integer
    /// micro-USD. `None` = no ceiling — the Postgres column is genuinely
    /// NULL, never a coerced zero (unlike `workspace_budget_micro_usd`
    /// above, whose `0` sentinel predates this field and already shipped
    /// that different contract).
    pub spend_ceiling_micro_usd: Option<u64>,
    /// BILL-01 / ADR-076 §0.4 — AUTO-AGE's shrunken window
    /// (`tenants.auto_age_window_days`), set by the daily metering job when
    /// a ceiling tenant's projected overage would exceed the ceiling at the
    /// plan's full `indexed_window_days`. `None` until a shrink is needed;
    /// the job clears it back to `None` once the projection fits again at
    /// the plan window. **Never read this directly at a window-scoped call
    /// site — call [`Self::effective_window_days`].**
    pub auto_age_window_days: Option<i32>,
}

impl ResolvedEntitlements {
    /// The window every window-scoped read must use instead of
    /// `indexed_window_days` directly (spec §0.4): the usage route's
    /// hot/cold split, `window_breakdown_handler`, and the metering job's
    /// own tenant→window map all narrow together the moment AUTO-AGE sets
    /// `auto_age_window_days` — a caller reading `indexed_window_days`
    /// straight would keep billing/showing the pre-shrink window forever.
    #[must_use]
    pub fn effective_window_days(&self) -> i32 {
        self.auto_age_window_days
            .unwrap_or(self.indexed_window_days)
    }
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
            f_full_capture: false,
            f_alerts: false,
            // fail-CLOSED: no control plane => free tier, never paid.
            f_datasets: false,
            f_experiments: false,
            f_online_evals: false,
            f_annotation_queues: false,
            f_sso: false,
            // Deny-all = zero allowances on every meter, a conservative 30-day
            // window (ADR-076: "deny = zero allowances, 30-day window"). NOT
            // `None` (which would mean "custom/unlimited") — this is the
            // fail-CLOSED floor, never a grant.
            hot_bytes_included: Some(0),
            ingest_bytes_included: Some(0),
            series_included: Some(0),
            scan_units_included: Some(0),
            eval_runs_included: Some(0),
            indexed_window_days: 30,
            queryable_days: 30,
            ledger_days: 30,
            unlimited_seats: false,
            overage_allowed: false,
            overflow_mode: OverflowMode::AutoAge,
            // Fail-restricted: the Free RPM figure, not unlimited.
            rate_limit_rpm: Some(60),
            price_monthly_usd: None,
            price_annual_month_usd: None,
            price_from_usd: None,
            polar_product_id_month: None,
            polar_product_id_year: None,
            promotion_frozen_at: None,
            promotion_frozen_reason: None,
            price_version: None,
            workspace_budget_micro_usd: 0,
            // Deny-all: no ceiling, no auto-age shrink — the fail-closed
            // floor is a denial via zero allowances, not a spend-ceiling
            // state, which does not apply when there is no control plane.
            spend_ceiling_micro_usd: None,
            auto_age_window_days: None,
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
            f_full_capture: false,
            f_alerts: false,
            // fail-CLOSED: no control plane => free tier, never paid.
            f_datasets: false,
            f_experiments: false,
            f_online_evals: false,
            f_annotation_queues: false,
            f_sso: false,
            // BILL-01: bench = None/unlimited on every meter — the point of the
            // grant is that no allowance and no rate-limit tier can reject the
            // run (`rate_limit_rpm: None` on this grant is what confers it —
            // `admission.rs` reads the field directly, no tier indirection).
            hot_bytes_included: None,
            ingest_bytes_included: None,
            series_included: None,
            scan_units_included: None,
            eval_runs_included: None,
            indexed_window_days: 365,
            queryable_days: 730,
            ledger_days: 730,
            unlimited_seats: true,
            overage_allowed: false,
            overflow_mode: OverflowMode::AutoAge,
            rate_limit_rpm: None,
            price_monthly_usd: None,
            price_annual_month_usd: None,
            price_from_usd: None,
            polar_product_id_month: None,
            polar_product_id_year: None,
            promotion_frozen_at: None,
            promotion_frozen_reason: None,
            price_version: None,
            workspace_budget_micro_usd: 0,
            // Bench measures the gateway's own overhead — no ceiling exists
            // for a no-control-plane grant, so no auto-age shrink either.
            spend_ceiling_micro_usd: None,
            auto_age_window_days: None,
        }
    }

    /// Is this the bench grant? Keyed on the reserved `plan_lookup_key`, which
    /// no Polar plan can produce.
    ///
    /// BILL-01 / ADR-076 (2026-09-13) orphaned this method's only caller,
    /// `rate_limit_tier()` — deleted along with the whole `RateLimitTier` type
    /// in the `rate_limiter.rs` rewrite (bench's uncapped rate limit is now
    /// conferred structurally by `bench_unlimited()`'s own `rate_limit_rpm:
    /// None`, not by a branch here). Kept, not deleted: whether bench traffic
    /// should also be exempted from the six usage meters
    /// (`crate::billing::meters`) or from the velocity breaker is a real
    /// question this build did not need to answer — the eight numbered BILL-01
    /// steps never mention bench — and `is_bench()` is the one-line predicate
    /// that answer would be built on.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_bench(&self) -> bool {
        self.plan_lookup_key == "__bench"
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
            FeatureKey::Sso => self.f_sso,
        }
    }

    /// Is a spend/promotion action currently frozen for this tenant (A3
    /// velocity breaker)? `prompt_routes` reads this before promote/rollback.
    #[must_use]
    pub fn is_promotion_frozen(&self) -> bool {
        self.promotion_frozen_at.is_some()
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
    /// Tenants whose next miss must re-resolve INLINE (an explicit invalidation).
    forced: Arc<dashmap::DashSet<Uuid>>,
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
            forced: Arc::new(dashmap::DashSet::new()),
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
        // STALE-WHILE-REVALIDATE (2026-09-04, the p95 investigation). After the
        // 15-minute TTL the entry is gone from `cache`, but `last_known` still
        // holds the last successful resolve. Serving it and refreshing OFF-PATH
        // means a sparse request never waits on the control plane — with the
        // keepalive off (NEON-COMPUTE-PIN) that wait was a fresh connect plus,
        // when the compute had suspended, its ~1.2 s resume, and it showed up
        // as gateway p99 587 ms / max 1.09 s on 2026-09-03. Staleness is bounded
        // by one refresh: the refresh runs on THIS request, so the next request
        // sees the fresh grant. A tenant never resolved before still resolves
        // inline (there is nothing to serve) and fails CLOSED as before.
        if !self.forced.contains(&tenant)
            && let Some(last) = self.last_known.get(&tenant)
        {
            STALE_SERVED_TOTAL.fetch_add(1, Ordering::Relaxed);
            self.spawn_refresh(tenant);
            return last.clone();
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
                self.forced.remove(&tenant);
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
        // An EXPLICIT invalidation (NOTIFY, a plan change) must force an INLINE
        // re-resolve — the stale-while-revalidate branch in `resolved` may not
        // serve the value that was just declared wrong. `last_known` is kept:
        // it is still the fail-open answer if that re-resolve hits an outage.
        self.forced.insert(tenant);
    }

    /// Evict every workspace — used when a `plan_entitlements` row changes, which
    /// affects all tenants on that plan (the `NOTIFY` payload `ALL` triggers this).
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
        for e in self.last_known.iter() {
            self.forced.insert(*e.key());
        }
    }

    #[cfg(test)]
    fn last_known_len(&self) -> usize {
        self.last_known.len()
    }
}

/// Build a Postgres-backed resolver closure over a `deadpool` pool (the
/// `-pooler` endpoint).
///
/// **ADR-073 fix (B-241).** Starts FROM `tenants` — plan MEMBERSHIP — never
/// from `workspace_entitlements`, which is the OVERRIDE layer only. The old
/// query joined `workspace_entitlements JOIN plan_entitlements` and fell back
/// to a hardcoded `free_v1` for any tenant with no override row — silently
/// converting "this tenant has no override row" into "this tenant is on the
/// free plan", which is a different and usually false statement for a paying
/// tenant. There is now exactly one query and no fallback: a tenant with no
/// `workspace_entitlements` row still resolves to *their plan's* defaults via
/// the `LEFT JOIN`; only a MISSING `tenants` ROW (the tenant does not exist at
/// all) reaches `deny_all()`.
///
/// `pe.plan_lookup_key = t.plan::text || '_v1'` mirrors the exact mapping
/// `apps/web/lib/entitlements.ts`'s `PLAN_TO_LOOKUP_KEY` and the Polar webhook's
/// `` `${tenant.plan ?? "free"}_v1` `` use — one rule, expressed once here.
pub fn pg_resolver(pool: crate::db::DbPool) -> ResolveFn {
    Arc::new(move |tenant: Uuid| {
        let pool = pool.clone();
        Box::pin(async move {
            let client = pool
                .get()
                .await
                .map_err(|e| anyhow::anyhow!("entitlement pool: {e}"))?;
            // Overlay overrides over plan defaults. LEFT JOIN so a tenant with
            // no override row still resolves to its plan's defaults — the
            // ADR-073 fix. `numeric` columns are cast to text: tokio-postgres
            // has no numeric->f64 conversion, and a NULL (Enterprise "custom")
            // must survive as a NULL string, never a coerced zero.
            const SQL: &str = "\
                SELECT pe.plan_lookup_key, \
                  COALESCE(we.f_pr7_trajectory, pe.f_pr7_trajectory) AS f_pr7_trajectory, \
                  COALESCE(we.f_pr8_argdrift, pe.f_pr8_argdrift) AS f_pr8_argdrift, \
                  COALESCE(we.f_pr9_a2a_handoff, pe.f_pr9_a2a_handoff) AS f_pr9_a2a_handoff, \
                  COALESCE(we.f_pr10_inline_slm_judge, pe.f_pr10_inline_slm_judge) AS f_pr10_inline_slm_judge, \
                  COALESCE(we.f_pr11_slo_drift, pe.f_pr11_slo_drift) AS f_pr11_slo_drift, \
                  COALESCE(we.f_pr12_langgraph_branch, pe.f_pr12_langgraph_branch) AS f_pr12_langgraph_branch, \
                  COALESCE(we.f_cohort_baselines, pe.f_cohort_baselines) AS f_cohort_baselines, \
                  COALESCE(we.f_audit_addon, pe.f_audit_addon) AS f_audit_addon, \
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
                  COALESCE(we.f_sso, pe.f_sso) AS f_sso, \
                  COALESCE(we.hot_gb_included, pe.hot_gb_included)::text AS hot_gb_included_text, \
                  COALESCE(we.ingest_gb_included, pe.ingest_gb_included)::text AS ingest_gb_included_text, \
                  COALESCE(we.series_included, pe.series_included) AS series_included, \
                  COALESCE(we.scan_units_included, pe.scan_units_included) AS scan_units_included, \
                  COALESCE(we.eval_runs_included, pe.eval_runs_included) AS eval_runs_included, \
                  COALESCE(we.indexed_window_days, pe.indexed_window_days) AS indexed_window_days, \
                  COALESCE(we.queryable_days, pe.queryable_days) AS queryable_days, \
                  COALESCE(we.ledger_days, pe.ledger_days) AS ledger_days, \
                  pe.unlimited_seats AS unlimited_seats, \
                  COALESCE(we.overage_allowed, pe.overage_allowed) AS overage_allowed, \
                  COALESCE(t.overflow_mode, we.overflow_mode, pe.overflow_mode) AS overflow_mode, \
                  COALESCE(we.rate_limit_rpm, pe.rate_limit_rpm) AS rate_limit_rpm, \
                  pe.price_monthly_usd AS price_monthly_usd, \
                  pe.price_annual_month_usd AS price_annual_month_usd, \
                  pe.price_from_usd AS price_from_usd, \
                  pe.polar_product_id_month AS polar_product_id_month, \
                  pe.polar_product_id_year AS polar_product_id_year, \
                  t.promotion_frozen_at AS promotion_frozen_at, \
                  t.promotion_frozen_reason AS promotion_frozen_reason, \
                  t.price_version AS price_version, \
                  t.budget_usd_monthly::text AS workspace_budget_usd_text, \
                  t.spend_ceiling_usd::text AS spend_ceiling_usd_text, \
                  t.auto_age_window_days AS auto_age_window_days, \
                  t.auto_age_since AS auto_age_since \
                FROM tenants t \
                JOIN plan_entitlements pe ON pe.plan_lookup_key = t.plan::text || '_v1' \
                LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id \
                WHERE t.id = $1 AND t.archived_at IS NULL";
            match client.query_opt(SQL, &[&tenant]).await? {
                Some(row) => Ok(row_to_resolved(&row)),
                // No tenant row at all (unknown / archived tenant) — fail
                // CLOSED to nothing, ADR-073 §5. This is deliberately NOT the
                // same as "no workspace_entitlements row", which the LEFT JOIN
                // above already resolves to the tenant's real plan.
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
        f_audit_addon: row.get("f_audit_addon"),
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
        f_sso: row.get("f_sso"),
        // BILL-01 / ADR-076 — numeric(12,3) GB figures arrive cast to text
        // (tokio-postgres has no native numeric->f64); NULL (Enterprise
        // "custom") survives as `None`, never a coerced zero. Converted to
        // BYTES here, once, so every downstream caller compares one unit.
        hot_bytes_included: numeric_text_to_bytes(row.get("hot_gb_included_text")),
        ingest_bytes_included: numeric_text_to_bytes(row.get("ingest_gb_included_text")),
        series_included: row.get("series_included"),
        scan_units_included: row.get("scan_units_included"),
        eval_runs_included: row.get("eval_runs_included"),
        // NOT NULL in practice for every one of the five seeded plan rows
        // (`apps/web/db/seed.mjs` upserts all five); `Row::get` panics on a
        // genuine NULL here, which is the correct direction per this file's
        // own rule (a half-seeded plan row is a deploy-time bug, not a value
        // to silently paper over).
        indexed_window_days: row.get("indexed_window_days"),
        queryable_days: row.get("queryable_days"),
        ledger_days: row.get("ledger_days"),
        unlimited_seats: row.get("unlimited_seats"),
        overage_allowed: row.get("overage_allowed"),
        overflow_mode: OverflowMode::from_column(row.get::<_, &str>("overflow_mode")),
        rate_limit_rpm: row
            .get::<_, Option<i32>>("rate_limit_rpm")
            .and_then(|v| u32::try_from(v).ok()),
        price_monthly_usd: row.get("price_monthly_usd"),
        price_annual_month_usd: row.get("price_annual_month_usd"),
        price_from_usd: row.get("price_from_usd"),
        polar_product_id_month: row.get("polar_product_id_month"),
        polar_product_id_year: row.get("polar_product_id_year"),
        promotion_frozen_at: row.get("promotion_frozen_at"),
        promotion_frozen_reason: row.get("promotion_frozen_reason"),
        price_version: row.get("price_version"),
        // `try_get` by name absorbs both "absent column" and "NULL" without
        // conflating them with a real zero.
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
        // `None` on NULL (no ceiling — the default) or an unparseable value,
        // never a coerced zero: a real `$0` ceiling and "no ceiling" must
        // stay distinguishable, unlike `workspace_budget_micro_usd` above.
        spend_ceiling_micro_usd: row
            .try_get::<_, Option<String>>("spend_ceiling_usd_text")
            .ok()
            .flatten()
            .and_then(|t| t.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .map(|v| (v * 1_000_000.0).round() as u64),
        auto_age_window_days: row.get("auto_age_window_days"),
    }
}

/// Parse a `numeric(12,3)` GB figure read as `::text` and convert to BYTES
/// (×1e9). `None` on a NULL string (Enterprise "custom") or an unparseable
/// value — never a coerced zero, which would read as "zero included" rather
/// than "no cap".
fn numeric_text_to_bytes(text: Option<String>) -> Option<u64> {
    text.and_then(|t| t.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|gb| (gb * 1_000_000_000.0).round() as u64)
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
            f_audit_addon: true,
            f_audit_selfverify: true,
            f_prompt_promotion_write: true,
            f_guardrail_r2: true,
            f_guardrail_r3_pinning: true,
            f_guardrail_r4: true,
            f_guardrail_r5: true,
            f_guardrail_r6: true,
            f_guardrail_r7: true,
            f_full_capture: true,
            f_alerts: true,
            f_sso: true,
            // Enterprise: every allowance is "custom" — genuinely `None`, not a
            // large number, matching what a NULL `plan_entitlements` column
            // resolves to.
            hot_bytes_included: None,
            ingest_bytes_included: None,
            series_included: None,
            scan_units_included: None,
            eval_runs_included: None,
            indexed_window_days: 365,
            queryable_days: 730,
            ledger_days: 2555,
            unlimited_seats: true,
            overage_allowed: true,
            overflow_mode: OverflowMode::AutoAge,
            rate_limit_rpm: None,
            price_monthly_usd: None,
            price_annual_month_usd: None,
            price_from_usd: Some(2499),
            polar_product_id_month: None,
            polar_product_id_year: None,
            promotion_frozen_at: None,
            promotion_frozen_reason: None,
            price_version: None,
            workspace_budget_micro_usd: 0,
            spend_ceiling_micro_usd: None,
            auto_age_window_days: None,
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
            FeatureKey::PromptPromotionWrite,
        ] {
            assert!(!d.has(f));
        }
    }

    /// BILL-01: a NULL `*_gb_included` (Enterprise "custom") must survive as
    /// `None`, never coerce to a zero — "zero included" and "no cap" are
    /// opposite claims and this is the ONE place the numeric->bytes
    /// conversion happens.
    #[test]
    fn numeric_text_to_bytes_preserves_null_as_none_never_zero() {
        assert_eq!(numeric_text_to_bytes(None), None, "NULL must stay None");
        assert_eq!(
            numeric_text_to_bytes(Some("garbage".to_string())),
            None,
            "unparseable must fail open to None, not silently deny at 0"
        );
        assert_eq!(
            numeric_text_to_bytes(Some("5".to_string())),
            Some(5_000_000_000),
            "5 GB -> 5e9 bytes"
        );
        assert_eq!(
            numeric_text_to_bytes(Some("0.25".to_string())),
            Some(250_000_000),
            "Free's 0.25 GB -> 250 MB, not rounded to 0"
        );
    }

    /// `has(Sso)` reads the new `f_sso` field, not a plan-string guess.
    #[test]
    fn sso_feature_key_reads_f_sso() {
        let mut e = grant_all();
        assert!(e.has(FeatureKey::Sso));
        e.f_sso = false;
        assert!(!e.has(FeatureKey::Sso));
        assert!(!ResolvedEntitlements::deny_all().has(FeatureKey::Sso));
    }

    /// A3 velocity breaker: `is_promotion_frozen` is exactly "the two columns
    /// are set", read through the cache rather than a fresh Postgres round trip.
    #[test]
    fn promotion_frozen_reads_the_resolved_timestamp() {
        let mut e = grant_all();
        assert!(!e.is_promotion_frozen());
        e.promotion_frozen_at = Some(chrono::Utc::now());
        assert!(e.is_promotion_frozen());
    }

    /// ADR-073 / B-241, against a REAL Postgres: a tenant whose `tenants.plan =
    /// 'builder'` and who carries NO `workspace_entitlements` row must resolve
    /// `builder_v1` — not `free_v1`. This is the exact shape of the bug ADR-073
    /// exists to close: the OLD resolver started FROM `workspace_entitlements`
    /// and fell back to a hardcoded `free_v1` for any tenant with no override
    /// row, silently downgrading a paying tenant.
    ///
    /// Gated on a real Postgres because the resolution logic lives in the SQL
    /// itself (`t.plan::text || '_v1'` joined against `plan_entitlements`), not
    /// in `row_to_resolved` — a fake `tokio_postgres::Row` cannot be
    /// constructed outside a real query, so this is the only way to prove the
    /// JOIN direction rather than merely describe it.
    ///
    /// Run: `POSTGRES_URL=<neon> cargo test -p gateway --bin gateway \
    ///   entitlement_cache::tests::b241_builder_tenant_with_no_override_resolves_builder_v1 \
    ///   -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "needs a real Postgres with the BILL-01 (0040) migration applied; set POSTGRES_URL"]
    async fn b241_builder_tenant_with_no_override_resolves_builder_v1() {
        let pool = crate::db::build_pool().await.expect("build_pool");
        let client = pool.get().await.expect("client");
        let tenant_id = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO tenants (id, workos_org_id, plan) VALUES ($1, $2, 'builder'::text::plan)",
                &[&tenant_id, &format!("org_b241_{tenant_id}")],
            )
            .await
            .expect("insert builder tenant with NO workspace_entitlements row");

        let resolved = pg_resolver(pool)(tenant_id).await.expect("resolve");
        assert_eq!(
            resolved.plan_lookup_key, "builder_v1",
            "a builder-plan tenant with no override row must resolve builder_v1, \
             never the hardcoded free_v1 fallback (B-241)"
        );
        assert!(
            resolved.overage_allowed,
            "builder_v1 allows overage per the plan defaults, proving the \
             plan_entitlements JOIN actually ran rather than deny_all()"
        );
    }

    /// ADR-073 deny-overrides-grant: Team's plan default for `f_sso` is
    /// `true`; an explicit `workspace_entitlements.f_sso = false` override
    /// must beat it. Same real-Postgres gate as the test above.
    #[tokio::test]
    #[ignore = "needs a real Postgres with the BILL-01 (0040) migration applied; set POSTGRES_URL"]
    async fn deny_overrides_grant_on_f_sso() {
        let pool = crate::db::build_pool().await.expect("build_pool");
        let client = pool.get().await.expect("client");
        let tenant_id = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO tenants (id, workos_org_id, plan) VALUES ($1, $2, 'team'::text::plan)",
                &[&tenant_id, &format!("org_deny_sso_{tenant_id}")],
            )
            .await
            .expect("insert team tenant");
        client
            .execute(
                "INSERT INTO workspace_entitlements (tenant_id, plan_lookup_key, f_sso) \
                 VALUES ($1, 'team_v1', false)",
                &[&tenant_id],
            )
            .await
            .expect("insert workspace override denying SSO");

        let resolved = pg_resolver(pool)(tenant_id).await.expect("resolve");
        assert_eq!(resolved.plan_lookup_key, "team_v1");
        assert!(
            !resolved.f_sso,
            "an explicit workspace_entitlements FALSE must beat the Team plan default TRUE"
        );
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

        for name in &wanted {
            assert!(
                primary_names.iter().any(|c| c == name),
                "`{name}` is not an addressable OUTPUT COLUMN of the query \
                 (it needs `AS {name}`, or to be a bare column reference) — \
                 `row.get(\"{name}\")` will PANIC on a cache miss in production. \
                 Addressable columns are: {primary_names:?}"
            );
        }

        // ADR-073: there is now exactly ONE query (the hardcoded `free_v1`
        // FALLBACK was the B-241 mechanism this ADR removes). The loop above
        // — every wanted column addressable in the one remaining query — is
        // the whole test.
    }
}
