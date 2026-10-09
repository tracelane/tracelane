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
/// B-409: resolves that found no `plan_allowances` row for the tenant's pinned
/// (or current) version and fell back to the deny floor. Should be 0 in prod;
/// >0 = the seed did not run or a pinned version was removed.
pub static ALLOWANCE_ROW_MISSING_TOTAL: AtomicU64 = AtomicU64::new(0);
/// rev4 M3: resolves whose PINNED `plan_allowances` row was missing and that read
/// the plan's CURRENT row instead. Should be 0 in prod (the 0055 trigger refuses
/// to delete or truncate a pinned version); >0 = a pin names a version that does
/// not exist.
pub static ALLOWANCE_PIN_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

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
    pub f_customer_kms: bool,
    pub f_cache_control: bool,
    pub cache_ttl_hours: u32,
    /// `OG-50`: the plan grants OTLP span export (`plan_entitlements.f_otel_export`, seeded OFF
    /// for every plan until the founder rules). Plan-only. **Fail-CLOSED**: `false` on
    /// `deny_all`, on bench and with no control plane — an absent read exports nothing.
    pub f_otel_export: bool,
    /// `OG-50`: how many exports the plan allows (`plan_entitlements.max_exports`).
    pub max_exports: u32,
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
    /// BILL-01 A5: included cold-archive bytes per period (24x monthly ingest on
    /// paid tiers). `None` = no allowance (Free) or custom (Enterprise).
    pub cold_bytes_included: Option<u64>,
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
    /// B-410: the Polar subscription cycle `[start, end)` from the webhook. The
    /// usage route rates over it so the dashboard agrees with the invoice;
    /// `None` = no paid cycle known -> calendar month.
    pub billing_period: Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
    pub promotion_frozen_reason: Option<String>,
    /// The pricing-rates version this tenant is rated against
    /// (`tenants.price_version`) — price protection (ADR-076 §0.5). `None`
    /// means "the current version", read by `billing::rating`.
    pub price_version: Option<String>,
    /// B-409: the `plan_allowances.plan_version` the allowances above were
    /// resolved from — the tenant's pinned version while protection is live,
    /// else the current one. `None` = no row (the allowances are the deny
    /// floor), no control plane, or a synthetic grant.
    pub plan_version: Option<String>,
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
    /// GWY-27: this workspace's model aliases, alias → ONE concrete target model.
    /// Loaded by a second query on the same connection inside the refresh
    /// ([`pg_resolver`]) — never per request. Empty when the workspace has none, when
    /// there is no control plane, and when that read FAILED (fail-closed routing:
    /// an alias then answers `400 unroutable_model`, never a default target).
    pub model_aliases: std::sync::Arc<std::collections::BTreeMap<String, String>>,
    /// GWY-52: the workspace turned cross-provider failover ON for its requests (a
    /// per-request `X-Tracelane-Failover: off` still wins). `false` = the operator
    /// default (opt-in per request), which is also the answer when the read failed.
    pub failover_enabled: bool,
    /// GWY-52: the workspace's own ordered fallback models; empty = the operator chain.
    pub failover_models: std::sync::Arc<Vec<String>>,
    /// GWY-53: the owner's opt-in to record prompt/response text
    /// (`workspace_content_capture`). Loaded in the same refresh as the GWY-27/52
    /// settings, never per request. Both OFF when unset, on `deny_all`/bench, and when
    /// the read FAILED — fail-closed, the privacy-safe direction. Applied only through
    /// `config::capture_decision`.
    pub content_capture: crate::db::workspace_capture::WorkspaceCapture,
    /// `OG-51`: the workspace's response-cache settings, invalidation epochs and per-key
    /// narrowings (`workspace_cache_settings`, `cache_epochs`, `api_keys.cache`), loaded in
    /// the same refresh, never per request. `Default` = no settings = today's behaviour.
    /// A FAILED read resolves to the PRIVACY default (mode `off`), never to "on" — see
    /// [`attach_cache_settings`].
    pub cache: Arc<crate::db::cache_settings::Loaded>,
    /// `OG-25` / `OG-21` / `OG-22`: the workspace's own controls (`workspace_controls`):
    /// pause, block lists, and the workspace policy layer. Read on the resolve's
    /// connection ([`attach_workspace_controls`]), never per request. Empty when unset,
    /// on `deny_all` / bench, and with no control plane. A FAILED read fails the whole
    /// resolve, so the cache keeps serving the LAST-KNOWN controls.
    pub controls: std::sync::Arc<crate::controls::WorkspaceControls>,
    pub guardrail_policies: Arc<crate::guardrail::policy::Policies>,
    /// `OG-11`/`OG-12`/`OG-13`: the workspace's routing document (`workspace_routing`),
    /// parsed once per refresh — never per request. `None` when unset, on `deny_all` /
    /// bench and with no control plane; `Invalid` for a stored document this gateway
    /// cannot parse (routed requests are refused, fail-CLOSED). A FAILED read fails the
    /// whole resolve, so the cache keeps serving the LAST-KNOWN document.
    pub routing: std::sync::Arc<crate::routing::RoutingState>,
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

    /// rev4 M3: whether the six allowances and three windows came from a real
    /// `plan_allowances` row (the tenant's pinned version, or its plan's current
    /// one). `false` = the deny floor, a cold no-control-plane default, or a
    /// synthetic grant — numbers that say nothing about what the customer bought,
    /// so nothing may WARN or AUTO-AGE against them (the metering job checks).
    #[must_use]
    pub fn allowances_known(&self) -> bool {
        self.plan_version.is_some()
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
            f_customer_kms: false,
            f_cache_control: false,
            cache_ttl_hours: 0,
            f_otel_export: false,
            max_exports: 0,
            // Deny-all = zero allowances on every meter, a conservative 30-day
            // window (ADR-076: "deny = zero allowances, 30-day window"). NOT
            // `None` (which would mean "custom/unlimited") — this is the
            // fail-CLOSED floor, never a grant.
            hot_bytes_included: Some(0),
            ingest_bytes_included: Some(0),
            cold_bytes_included: None,
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
            billing_period: None,
            promotion_frozen_reason: None,
            price_version: None,
            plan_version: None,
            workspace_budget_micro_usd: 0,
            // Deny-all: no ceiling, no auto-age shrink — the fail-closed
            // floor is a denial via zero allowances, not a spend-ceiling
            // state, which does not apply when there is no control plane.
            spend_ceiling_micro_usd: None,
            auto_age_window_days: None,
            model_aliases: std::sync::Arc::default(),
            controls: std::sync::Arc::default(),
            guardrail_policies: Arc::default(),
            failover_enabled: false,
            failover_models: std::sync::Arc::default(),
            routing: std::sync::Arc::default(),
            content_capture: crate::db::workspace_capture::WorkspaceCapture::default(),
            cache: std::sync::Arc::default(),
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
            f_customer_kms: false,
            f_cache_control: false,
            cache_ttl_hours: 0,
            f_otel_export: false,
            max_exports: 0,
            // BILL-01: bench = None/unlimited on every meter — the point of the
            // grant is that no allowance and no rate-limit tier can reject the
            // run (`rate_limit_rpm: None` on this grant is what confers it —
            // `admission.rs` reads the field directly, no tier indirection).
            hot_bytes_included: None,
            ingest_bytes_included: None,
            cold_bytes_included: None,
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
            billing_period: None,
            promotion_frozen_reason: None,
            price_version: None,
            plan_version: None,
            workspace_budget_micro_usd: 0,
            // Bench measures the gateway's own overhead — no ceiling exists
            // for a no-control-plane grant, so no auto-age shrink either.
            spend_ceiling_micro_usd: None,
            auto_age_window_days: None,
            model_aliases: std::sync::Arc::default(),
            controls: std::sync::Arc::default(),
            guardrail_policies: Arc::default(),
            failover_enabled: false,
            failover_models: std::sync::Arc::default(),
            routing: std::sync::Arc::default(),
            content_capture: crate::db::workspace_capture::WorkspaceCapture::default(),
            cache: std::sync::Arc::default(),
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
    resolved: Arc<ResolvedEntitlements>,
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

/// rev5 M6: the process's entitlement cache, for the one reader that holds no `AppState`
/// — the API-key authenticator, which enforces the workspace policy's `source_ips` on
/// every route a key can reach. Installed once at boot iff a control plane exists; absent
/// (self-host, tests) ⇒ no workspace policy (nothing can have been set).
static GLOBAL: std::sync::OnceLock<Arc<EntitlementCache>> = std::sync::OnceLock::new();

/// Install the boot-time cache (first call wins).
pub(crate) fn install_global(cache: Arc<EntitlementCache>) {
    let _ = GLOBAL.set(cache);
}

/// The boot-time cache, when a control plane exists.
pub(crate) fn global() -> Option<&'static Arc<EntitlementCache>> {
    GLOBAL.get()
}

/// In-process entitlement cache. Cheap to clone (all fields are `Arc`-backed).
#[derive(Clone)]
pub struct EntitlementCache {
    cache: Cache<Uuid, Arc<Cached>>,
    /// Survives the moka TTL so an outage can fail-open to the last-known grant.
    last_known: Arc<DashMap<Uuid, Arc<ResolvedEntitlements>>>,
    /// Tenants whose next miss must re-resolve INLINE (an explicit invalidation).
    forced: Arc<dashmap::DashSet<Uuid>>,
    resolve: ResolveFn,
    /// Only outstanding resolves live here. The lock serializes cache publication
    /// with invalidation; database waits never hold it. Weak tickets let cancelled
    /// requests be reclaimed without a permanent per-tenant generation map.
    pending: Arc<tokio::sync::Mutex<std::collections::HashMap<Uuid, std::sync::Weak<()>>>>,
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
            pending: Arc::default(),
        }
    }

    /// Resolve `feature` for `tenant`. Warm reads never touch Postgres.
    pub async fn check(&self, tenant: Uuid, feature: FeatureKey) -> bool {
        self.resolved(tenant).await.has(feature)
    }

    /// Resolve the full entitlement set for `tenant` (warm-cache on hit).
    pub async fn resolved(&self, tenant: Uuid) -> Arc<ResolvedEntitlements> {
        self.resolved_traced(tenant).await.0
    }

    /// [`Self::resolved`], also reporting whether THIS request waited on a
    /// blocking resolve (B-568 I5 — one of the four control-plane round trips that
    /// make a request cold). `false` for a warm hit and for a stale-served answer,
    /// whose refresh runs off the request path.
    pub async fn resolved_traced(&self, tenant: Uuid) -> (Arc<ResolvedEntitlements>, bool) {
        if let Some(cached) = self.cache.get(&tenant).await {
            if cached.fetched_at.elapsed() >= REFRESH_AHEAD {
                self.spawn_refresh(tenant);
            }
            return (cached.resolved.clone(), false);
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
            return (last.clone(), false);
        }
        (self.resolve_and_store(tenant, false).await, true)
    }

    /// Whether a real resolver result exists, rather than the outage fallback.
    pub fn has_resolved(&self, tenant: Uuid) -> bool {
        self.last_known.contains_key(&tenant)
    }

    /// A request can wait on a credential or budget after reading controls. Fence
    /// that wait against a newer published policy or an explicit invalidation.
    pub(crate) fn is_current(&self, tenant: Uuid, resolved: &Arc<ResolvedEntitlements>) -> bool {
        !self.forced.contains(&tenant)
            && self
                .last_known
                .get(&tenant)
                .is_some_and(|current| Arc::ptr_eq(current.value(), resolved))
    }

    /// Preserve feature grants during an outage, but never restore an unknown
    /// routing or security policy. An explicit invalidation is a revocation fence.
    fn unavailable(&self, tenant: Uuid) -> Arc<ResolvedEntitlements> {
        let mut resolved = self
            .last_known
            .get(&tenant)
            .map_or_else(ResolvedEntitlements::deny_all, |last| (**last).clone());
        resolved.routing = Arc::new(crate::routing::RoutingState::Invalid);
        let mut controls = (*resolved.controls).clone();
        controls.policy = Some(tracelane_shared::key_policy::LayerPolicy::Invalid);
        resolved.controls = Arc::new(controls);
        Arc::new(resolved)
    }

    /// Each resolve gets a publication ticket. Invalidation or a newer resolve
    /// removes its authority to publish, including when the old query later succeeds.
    async fn resolve_and_store(&self, tenant: Uuid, background: bool) -> Arc<ResolvedEntitlements> {
        let ticket = Arc::new(());
        {
            let mut pending = self.pending.lock().await;
            if background
                && pending
                    .get(&tenant)
                    .and_then(std::sync::Weak::upgrade)
                    .is_some()
            {
                return self.unavailable(tenant);
            }
            if pending.len() >= MAX_CAPACITY as usize {
                pending.retain(|_, value| value.strong_count() != 0);
                if pending.len() >= MAX_CAPACITY as usize && !pending.contains_key(&tenant) {
                    return self.unavailable(tenant);
                }
            }
            pending.insert(tenant, Arc::downgrade(&ticket));
        }
        CACHE_MISS_TOTAL.fetch_add(1, Ordering::Relaxed);
        let result = (self.resolve)(tenant).await;
        let mut pending = self.pending.lock().await;
        let current = pending
            .get(&tenant)
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|active| Arc::ptr_eq(&active, &ticket));
        if !current {
            // A newer published answer is safe to return; otherwise this caller
            // cannot know the post-invalidation controls and must refuse dispatch.
            return if !self.forced.contains(&tenant) {
                self.last_known
                    .get(&tenant)
                    .map(|last| last.clone())
                    .unwrap_or_else(|| self.unavailable(tenant))
            } else {
                self.unavailable(tenant)
            };
        }
        pending.remove(&tenant);
        match result {
            Ok(resolved) => {
                let arc = Arc::new(resolved);
                self.cache
                    .insert(
                        tenant,
                        Arc::new(Cached {
                            resolved: arc.clone(),
                            fetched_at: Instant::now(),
                        }),
                    )
                    .await;
                self.last_known.insert(tenant, arc.clone());
                self.forced.remove(&tenant);
                arc
            }
            Err(err) => {
                FAIL_OPEN_TOTAL.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(error = %err, "entitlement resolve failed; security policy unavailable");
                self.unavailable(tenant)
            }
        }
    }

    /// Background refresh-ahead: re-resolve without blocking the caller.
    fn spawn_refresh(&self, tenant: Uuid) {
        let this = self.clone();
        tokio::spawn(async move {
            // Re-resolve; ignore the value (resolve_and_store re-inserts).
            let _ = this.resolve_and_store(tenant, true).await;
        });
    }

    /// Fence every pending lookup before evicting this workspace. Feature grants
    /// remain available on outage, but routing and security controls fail closed.
    pub async fn invalidate(&self, tenant: Uuid) {
        let mut pending = self.pending.lock().await;
        pending.remove(&tenant);
        self.forced.insert(tenant);
        self.cache.invalidate(&tenant).await;
    }

    /// Fence outstanding lookups too, including tenants with no previous cached row.
    pub async fn invalidate_all(&self) {
        let mut pending = self.pending.lock().await;
        for tenant in pending.keys() {
            self.forced.insert(*tenant);
        }
        pending.clear();
        for e in self.last_known.iter() {
            self.forced.insert(*e.key());
        }
        self.cache.invalidate_all();
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
/// B-409 — the ONE rule for which `plan_allowances` row a tenant reads, as SQL
/// text shared by every query that reads an allowance or a window (this
/// resolver, `billing::metering_job`'s window map, `retention_sweep`'s deletion
/// boundary). `$key` is the SQL expression naming the plan lookup key; the
/// query must alias `tenants` as `t`.
///
/// While the tenant's price protection is live — `t.plan_version` set by the
/// Polar webhook on the first paid activation, and `t.price_protected_until`
/// still in the future (NULL = no expiry recorded) — the PINNED version's row;
/// otherwise the `is_current` row.
///
/// rev4 M3 (2026-10-03): a pinned version with NO row falls back to the plan's
/// `is_current` row — never straight to a fail-direction floor. The pin's row can
/// only be absent through a defect (0055's trigger refuses DELETE and TRUNCATE of a
/// pinned version), and the zero floor turned that defect into "0 GB included"
/// while overage/overflow still came from the plan: 75/90 % warnings against zero
/// and an AUTO-AGE narrowing. One LATERAL row: the pinned row when it exists
/// (ordered first), else the current one; `LIMIT 1` plus the partial unique index
/// `plan_allowances_one_current_per_plan` make it at most one. Only when the plan
/// has NO current row either does each caller apply its own fail direction (the
/// resolver: the deny floor; the metering job: its 3-day window; the sweep: 730
/// days, never delete early). The inner alias is `pa` too, so `verify_schema`'s
/// alias scan sees every `plan_allowances` column the rule names.
macro_rules! allowance_pin_join {
    ($key:literal) => {
        concat!(
            " LEFT JOIN LATERAL (SELECT pa.* FROM plan_allowances pa \
               WHERE pa.plan_lookup_key = ",
            $key,
            " AND (pa.is_current OR (t.plan_version IS NOT NULL \
                 AND (t.price_protected_until IS NULL OR t.price_protected_until > now()) \
                 AND pa.plan_version = t.plan_version)) \
               ORDER BY (t.plan_version IS NOT NULL \
                 AND (t.price_protected_until IS NULL OR t.price_protected_until > now()) \
                 AND pa.plan_version = t.plan_version) DESC \
               LIMIT 1) pa ON true "
        )
    };
}
pub(crate) use allowance_pin_join;

/// The ONE entitlement query. Module-level so the boot schema check
/// (`verify_schema`) parses the same text the resolver runs — no second list
/// of columns to drift (founder, 2026-09-14, B6 audit item B).
///
/// B-409: the six allowances and three windows come from `plan_allowances pa`
/// (the tenant's pinned version, [`allowance_pin_join`]), NOT the catalog
/// `plan_entitlements` columns — a new ruling inserts a version and no pinned
/// tenant's allowance moves. `allowance_row_found` tells "custom" (an Enterprise
/// NULL in a real row) from "no row" (fail closed, [`row_to_resolved`]).
pub(crate) const SQL: &str = concat!(
    "\
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
                  pe.f_customer_kms AS f_customer_kms, pe.f_cache_control AS f_cache_control, pe.cache_ttl_hours AS cache_ttl_hours, \
                  pe.f_otel_export AS f_otel_export, pe.max_exports AS max_exports, \
                  COALESCE(we.hot_gb_included, pa.hot_gb_included)::text AS hot_gb_included_text, \
                  COALESCE(we.ingest_gb_included, pa.ingest_gb_included)::text AS ingest_gb_included_text, \
                  COALESCE(we.cold_gb_included, pa.cold_gb_included)::text AS cold_gb_included_text, \
                  COALESCE(we.series_included, pa.series_included) AS series_included, \
                  COALESCE(we.scan_units_included, pa.scan_units_included) AS scan_units_included, \
                  COALESCE(we.eval_runs_included, pa.eval_runs_included) AS eval_runs_included, \
                  COALESCE(we.indexed_window_days, pa.indexed_window_days) AS indexed_window_days, \
                  COALESCE(we.queryable_days, pa.queryable_days) AS queryable_days, \
                  COALESCE(we.ledger_days, pa.ledger_days) AS ledger_days, \
                  (pa.plan_lookup_key IS NOT NULL) AS allowance_row_found, \
                  pa.plan_version AS plan_version, \
                  (t.plan_version IS NOT NULL \
                    AND (t.price_protected_until IS NULL OR t.price_protected_until > now()) \
                    AND COALESCE(pa.plan_version <> t.plan_version, true)) AS allowance_pin_fell_back, \
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
                  t.current_period_start AS current_period_start, \
                  t.current_period_end AS current_period_end, \
                  t.budget_usd_monthly::text AS workspace_budget_usd_text, \
                  t.spend_ceiling_usd::text AS spend_ceiling_usd_text, \
                  t.auto_age_window_days AS auto_age_window_days, \
                  t.auto_age_since AS auto_age_since \
                FROM tenants t \
                JOIN plan_entitlements pe ON pe.plan_lookup_key = t.plan::text || '_v1' \
                LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id",
    allowance_pin_join!("pe.plan_lookup_key"),
    "WHERE t.id = $1 AND t.archived_at IS NULL"
);

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
            match client.query_opt(SQL, &[&tenant]).await? {
                Some(row) => {
                    let mut resolved = row_to_resolved(&row);
                    attach_model_aliases(&client, &tenant, &mut resolved).await;
                    attach_workspace_failover(&client, &tenant, &mut resolved).await;
                    attach_content_capture(&client, &tenant, &mut resolved).await;
                    attach_cache_settings(&client, &tenant, &mut resolved).await;
                    attach_workspace_controls(&client, &tenant, &mut resolved).await?;
                    resolved.guardrail_policies =
                        Arc::new(crate::guardrail::policy_store::load(&client, &tenant).await?);
                    attach_workspace_routing(&client, &tenant, &mut resolved).await?;
                    Ok(resolved)
                }
                // No tenant row at all (unknown / archived tenant) — fail
                // CLOSED to nothing, ADR-073 §5. This is deliberately NOT the
                // same as "no workspace_entitlements row", which the LEFT JOIN
                // above already resolves to the tenant's real plan.
                None => Ok(ResolvedEntitlements::deny_all()),
            }
        }) as Pin<Box<dyn Future<Output = anyhow::Result<ResolvedEntitlements>> + Send>>
    })
}

/// `OG-25`: load the workspace's controls onto an already-resolved entitlement set, on
/// the refresh's connection.
///
/// # Errors
/// Fail-CLOSED in effect: a failed read FAILS the resolve, so the cache serves the
/// last-known controls (a pause is never dropped because a read failed); a tenant never
/// resolved fails to `deny_all` exactly as any resolve failure does.
pub(crate) async fn attach_workspace_controls(
    client: &tokio_postgres::Client,
    tenant: &Uuid,
    resolved: &mut ResolvedEntitlements,
) -> anyhow::Result<()> {
    let row = crate::db::controls::read_with(client, tenant).await?;
    if let Some(r) = row {
        resolved.controls = Arc::new(crate::controls::WorkspaceControls::from_row(
            r.policy.as_ref(),
            r.paused_at.map(|at| crate::controls::Pause {
                at,
                by: r.paused_by,
                reason: r.pause_reason,
            }),
            r.blocked_models,
            r.blocked_providers,
            r.blocked_end_users,
        ));
    }
    Ok(())
}

/// `OG-11`: load the workspace's routing document onto an already-resolved entitlement
/// set, on the refresh's connection.
///
/// # Errors
/// Fail-CLOSED in effect, as [`attach_workspace_controls`]: a failed read FAILS the
/// resolve, so the cache serves the last-known document; a document that reads but does
/// not parse becomes `RoutingState::Invalid` (routed requests refused 503).
pub(crate) async fn attach_workspace_routing(
    client: &tokio_postgres::Client,
    tenant: &Uuid,
    resolved: &mut ResolvedEntitlements,
) -> anyhow::Result<()> {
    let row = crate::db::routing::get_with(client, tenant).await?;
    resolved.routing = Arc::new(crate::routing::RoutingState::from_stored(
        row.as_ref().map(|r| &r.doc),
    ));
    Ok(())
}

/// GWY-27: load the workspace's model aliases onto an already-resolved entitlement
/// set, on the connection the refresh already holds — no extra Neon wake, never per
/// request. A failed read does NOT fail the resolve: on a cold process that would drop
/// the tenant to fallback limits over a routing convenience. It leaves NO aliases (an
/// alias call answers `400 unroutable_model`, never a default target) and counts
/// `workspace_gateway_config_unreadable`; a later successful read resolves that kind.
pub(crate) async fn attach_model_aliases(
    client: &tokio_postgres::Client,
    tenant: &Uuid,
    resolved: &mut ResolvedEntitlements,
) {
    match crate::db::model_aliases::list_with(client, tenant).await {
        Ok(aliases) => {
            resolved.model_aliases = Arc::new(aliases);
            // The read works again (the cause is systemic — a missing migration, a
            // dead connection — not per-tenant). Idempotent.
            tracelane_shared::degradation::resolve(
                tracelane_shared::degradation::Degradation::WorkspaceGatewayConfigUnreadable,
            );
        }
        Err(e) => {
            resolved.model_aliases = Arc::default();
            if tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::WorkspaceGatewayConfigUnreadable,
            ) == 1
            {
                tracing::warn!(error = %e, tenant_id = %tenant, "model aliases unreadable — this workspace resolves with none until the next refresh. Further occurrences are counted, not logged (kind=workspace_gateway_config_unreadable)");
            }
        }
    }
}

/// GWY-52: load the workspace's own failover settings, on the refresh's connection. A
/// failed read leaves the OPERATOR default (off, operator chain) — never a guessed chain
/// — and counts `workspace_gateway_config_unreadable`; the entitlements are untouched.
pub(crate) async fn attach_workspace_failover(
    client: &tokio_postgres::Client,
    tenant: &Uuid,
    resolved: &mut ResolvedEntitlements,
) {
    match crate::db::workspace_failover::get_with(client, tenant).await {
        Ok(row) => {
            let row = row.unwrap_or_default();
            resolved.failover_enabled = row.enabled;
            resolved.failover_models = Arc::new(row.models);
        }
        Err(e) => {
            resolved.failover_enabled = false;
            resolved.failover_models = Arc::default();
            if tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::WorkspaceGatewayConfigUnreadable,
            ) == 1
            {
                tracing::warn!(error = %e, tenant_id = %tenant, "workspace failover settings unreadable — operator default until the next refresh. Further occurrences are counted, not logged (kind=workspace_gateway_config_unreadable)");
            }
        }
    }
}

/// GWY-53: load the owner's content-capture choice, on the refresh's connection. A
/// failed read (a missing table is the shape of an unapplied migration) leaves capture
/// OFF — never the previous value, never on — and counts
/// `workspace_gateway_config_unreadable`; the entitlements are untouched.
pub(crate) async fn attach_content_capture(
    client: &tokio_postgres::Client,
    tenant: &Uuid,
    resolved: &mut ResolvedEntitlements,
) {
    match crate::db::workspace_capture::get_with(client, tenant).await {
        Ok(row) => resolved.content_capture = row.unwrap_or_default(),
        Err(e) => {
            resolved.content_capture = crate::db::workspace_capture::WorkspaceCapture::default();
            if tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::WorkspaceGatewayConfigUnreadable,
            ) == 1
            {
                tracing::warn!(error = %e, tenant_id = %tenant, "workspace content-capture setting unreadable — capture OFF until the next refresh. Further occurrences are counted, not logged (kind=workspace_gateway_config_unreadable)");
            }
        }
    }
}

/// `OG-51`: load the workspace's response-cache settings, invalidation epochs and per-key
/// narrowings, on the refresh's connection. **Fail-CLOSED on a failed read**: the workspace
/// resolves to cache mode `off` — the privacy-safe direction, because a workspace that
/// invalidated its cache or switched it off must never be served from it while the read is
/// broken — and counts `workspace_gateway_config_unreadable`. The entitlements are untouched.
pub(crate) async fn attach_cache_settings(
    client: &tokio_postgres::Client,
    tenant: &Uuid,
    resolved: &mut ResolvedEntitlements,
) {
    match crate::db::cache_settings::read_with(client, tenant).await {
        Ok(loaded) => {
            resolved.cache = Arc::new(loaded);
            tracelane_shared::degradation::resolve(
                tracelane_shared::degradation::Degradation::WorkspaceGatewayConfigUnreadable,
            );
        }
        Err(e) => {
            resolved.cache = Arc::new(crate::db::cache_settings::Loaded {
                settings: crate::db::cache_settings::Settings {
                    mode: crate::db::cache_settings::Mode::Off,
                    ..crate::db::cache_settings::Settings::default()
                },
                ..crate::db::cache_settings::Loaded::default()
            });
            if tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::WorkspaceGatewayConfigUnreadable,
            ) == 1
            {
                tracing::warn!(error = %e, tenant_id = %tenant, "workspace cache settings unreadable — the response cache is OFF for this workspace until the next refresh. Further occurrences are counted, not logged (kind=workspace_gateway_config_unreadable)");
            }
        }
    }
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
    // B-409: no `plan_allowances` row for the tenant's pinned (or current)
    // version → fail CLOSED. Each allowance/window the workspace does not
    // override takes the `deny_all()` floor — never NULL, which would read as
    // "custom / unlimited". Feature flags are not versioned and are untouched.
    let found: bool = row.get("allowance_row_found");
    let floor = ResolvedEntitlements::deny_all();
    // rev4 M3: the pin named a version with no row and the plan's CURRENT row
    // answered instead (`allowance_pin_join!`). Counted, warned once — a pin that
    // resolves to nothing is a defect even when the fallback hides it.
    if found && row.get::<_, bool>("allowance_pin_fell_back") {
        let n = ALLOWANCE_PIN_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 {
            tracing::warn!(
                plan_lookup_key = %row.get::<_, String>("plan_lookup_key"),
                "a tenant's pinned plan_allowances version has no row — the plan's CURRENT \
                 row answered (rev4 M3). Further occurrences are counted \
                 (ALLOWANCE_PIN_FALLBACK_TOTAL), not logged"
            );
        }
    }
    if !found {
        ALLOWANCE_ROW_MISSING_TOTAL.fetch_add(1, Ordering::Relaxed);
        if ALLOWANCE_ROW_MISSING_TOTAL.load(Ordering::Relaxed) == 1 {
            tracing::warn!(
                plan_lookup_key = %row.get::<_, String>("plan_lookup_key"),
                "no plan_allowances row for this tenant's pinned/current version — \
                 allowances resolve to the deny floor (fail-closed). Seed missing? \
                 Further occurrences are counted (ALLOWANCE_ROW_MISSING_TOTAL), not logged"
            );
        }
    }
    let bytes = |col: &str, floor_v: Option<u64>| {
        let v = numeric_text_to_bytes(row.get(col));
        if found { v } else { v.or(floor_v) }
    };
    let count = |col: &str, floor_v: Option<i64>| {
        let v: Option<i64> = row.get(col);
        if found { v } else { v.or(floor_v) }
    };
    let days = |col: &str, floor_v: i32| row.get::<_, Option<i32>>(col).unwrap_or(floor_v);
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
        f_customer_kms: row.get("f_customer_kms"),
        f_cache_control: row.get("f_cache_control"),
        cache_ttl_hours: u32::try_from(row.get::<_, i32>("cache_ttl_hours")).unwrap_or(0),
        f_otel_export: row.get("f_otel_export"),
        max_exports: u32::try_from(row.get::<_, i32>("max_exports")).unwrap_or(0),
        // BILL-01 / ADR-076 — numeric(12,3) GB figures arrive cast to text
        // (tokio-postgres has no native numeric->f64); NULL (Enterprise
        // "custom") survives as `None`, never a coerced zero. Converted to
        // BYTES here, once, so every downstream caller compares one unit.
        hot_bytes_included: bytes("hot_gb_included_text", floor.hot_bytes_included),
        ingest_bytes_included: bytes("ingest_gb_included_text", floor.ingest_bytes_included),
        cold_bytes_included: bytes("cold_gb_included_text", floor.cold_bytes_included),
        series_included: count("series_included", floor.series_included),
        scan_units_included: count("scan_units_included", floor.scan_units_included),
        eval_runs_included: count("eval_runs_included", floor.eval_runs_included),
        // B-409: NOT NULL in `plan_allowances` (migration 0055), so a NULL here
        // means the row is MISSING (the LEFT JOIN) and no workspace override
        // exists — the deny floor, never a panic on a cache miss.
        indexed_window_days: days("indexed_window_days", floor.indexed_window_days),
        queryable_days: days("queryable_days", floor.queryable_days),
        ledger_days: days("ledger_days", floor.ledger_days),
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
        billing_period: {
            let start: Option<chrono::DateTime<chrono::Utc>> = row.get("current_period_start");
            let end: Option<chrono::DateTime<chrono::Utc>> = row.get("current_period_end");
            start.zip(end)
        },
        promotion_frozen_reason: row.get("promotion_frozen_reason"),
        price_version: row.get("price_version"),
        plan_version: row.get("plan_version"),
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
        // Filled by `pg_resolver` from `model_aliases` after this row is mapped.
        model_aliases: std::sync::Arc::default(),
        controls: std::sync::Arc::default(),
        guardrail_policies: Arc::default(),
        // Filled by `pg_resolver` from `workspace_failover` after this row is mapped.
        failover_enabled: false,
        failover_models: std::sync::Arc::default(),
        routing: std::sync::Arc::default(),
        content_capture: crate::db::workspace_capture::WorkspaceCapture::default(),
        cache: std::sync::Arc::default(),
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
                        cache.invalidate_all().await;
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

    #[tokio::test]
    async fn og11_old_resolve_cannot_overwrite_post_invalidation_controls() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver: ResolveFn = {
            let entered = entered.clone();
            let release = release.clone();
            Arc::new(move |_| {
                let entered = entered.clone();
                let release = release.clone();
                let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                Box::pin(async move {
                    let mut resolved = ResolvedEntitlements::deny_all();
                    if first {
                        entered.notify_one();
                        release.notified().await;
                    } else {
                        resolved.controls = Arc::new(crate::controls::WorkspaceControls {
                            blocked_models: vec!["gpt-*".to_owned()],
                            ..Default::default()
                        });
                    }
                    Ok(resolved)
                })
            })
        };
        let cache = EntitlementCache::new(resolver);
        let tenant = Uuid::new_v4();
        let old = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.resolved(tenant).await })
        };
        entered.notified().await;
        cache.invalidate(tenant).await;
        assert_eq!(
            cache.resolved(tenant).await.controls.blocked_models,
            ["gpt-*"]
        );
        release.notify_one();
        old.await.unwrap();
        assert_eq!(
            cache.resolved(tenant).await.controls.blocked_models,
            ["gpt-*"],
            "a pre-invalidation resolve must never resurrect permissive controls"
        );
    }

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
            f_customer_kms: false,
            f_cache_control: false,
            cache_ttl_hours: 0,
            f_otel_export: false,
            max_exports: 0,
            // Enterprise: every allowance is "custom" — genuinely `None`, not a
            // large number, matching what a NULL `plan_entitlements` column
            // resolves to.
            hot_bytes_included: None,
            ingest_bytes_included: None,
            cold_bytes_included: None,
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
            billing_period: None,
            promotion_frozen_reason: None,
            price_version: None,
            plan_version: None,
            workspace_budget_micro_usd: 0,
            spend_ceiling_micro_usd: None,
            auto_age_window_days: None,
            model_aliases: std::sync::Arc::default(),
            controls: std::sync::Arc::default(),
            guardrail_policies: Arc::default(),
            failover_enabled: false,
            failover_models: std::sync::Arc::default(),
            routing: std::sync::Arc::default(),
            content_capture: crate::db::workspace_capture::WorkspaceCapture::default(),
            cache: std::sync::Arc::default(),
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

    /// B-568 I5: only the resolve the request WAITED on counts as cold. The first
    /// read blocks; a warm read does not; a stale-served read (TTL gone, last-known
    /// present) does not either — its refresh runs off the request path. A
    /// `resolved_traced` that always said `false` would hide the first case, one
    /// that always said `true` would call every sparse tenant cold.
    #[tokio::test]
    async fn resolved_traced_reports_only_the_blocking_resolve() {
        let count = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cache = EntitlementCache::new(counting_resolver(count.clone(), fail));
        let tenant = Uuid::new_v4();

        let (_, blocked) = cache.resolved_traced(tenant).await;
        assert!(
            blocked,
            "a never-resolved tenant waits on the control plane"
        );
        let (_, blocked) = cache.resolved_traced(tenant).await;
        assert!(!blocked, "a warm hit must not report a round trip");

        // Past the TTL: the moka entry is gone, last-known is not → stale-served.
        cache.cache.invalidate(&tenant).await;
        let (_, blocked) = cache.resolved_traced(tenant).await;
        assert!(
            !blocked,
            "a stale-served answer's refresh is off-path, not cold"
        );
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

    /// GWY-27, against the runner's REAL Postgres: the refresh's alias step loads the
    /// workspace's map, and when the read FAILS (here: a session that cannot see the
    /// table — the shape of an unapplied migration) it leaves NO aliases and counts
    /// `workspace_gateway_config_unreadable` instead of failing the entitlement resolve.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn gwy27_attach_model_aliases_loads_the_map_and_fails_to_none() {
        use tracelane_shared::degradation::{Degradation, count, is_open};
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect");
        tokio::spawn(conn);
        let org = format!("org_gwy27r_{}", Uuid::new_v4().simple());
        let id: Uuid = client
            .query_one(
                "INSERT INTO tenants (workos_org_id, name) VALUES ($1, $2) RETURNING id",
                &[&org, &"gwy27-resolver-test"],
            )
            .await
            .expect("tenant")
            .get(0);
        client
            .execute(
                "INSERT INTO model_aliases (tenant_id, alias, target_model) \
                 VALUES ($1, 'fast', 'gpt-4o-mini'), ($1, 'smart', 'gpt-5')",
                &[&id],
            )
            .await
            .expect("aliases");

        let mut resolved = ResolvedEntitlements::deny_all();
        attach_model_aliases(&client, &id, &mut resolved).await;
        let want: std::collections::BTreeMap<String, String> = [
            ("fast".to_string(), "gpt-4o-mini".to_string()),
            ("smart".to_string(), "gpt-5".to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(*resolved.model_aliases, want);
        assert!(!is_open(Degradation::WorkspaceGatewayConfigUnreadable));

        // The failure direction, for real: this session cannot see the table.
        let empty = format!("gwy27_empty_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {empty}; SET search_path TO {empty}"
            ))
            .await
            .expect("empty schema");
        let before = count(Degradation::WorkspaceGatewayConfigUnreadable);
        let mut unreadable = resolved.clone();
        attach_model_aliases(&client, &id, &mut unreadable).await;
        assert!(
            unreadable.model_aliases.is_empty(),
            "an unreadable map must resolve to NO aliases — fail-closed routing — never the previous map"
        );
        assert!(
            count(Degradation::WorkspaceGatewayConfigUnreadable) > before,
            "and it is counted"
        );
        assert!(is_open(Degradation::WorkspaceGatewayConfigUnreadable));
        assert_eq!(
            unreadable.plan_lookup_key, resolved.plan_lookup_key,
            "the entitlements themselves are untouched"
        );

        // Recovery: a successful read closes the kind.
        client
            .batch_execute("SET search_path TO public")
            .await
            .expect("reset search_path");
        attach_model_aliases(&client, &id, &mut unreadable).await;
        assert_eq!(*unreadable.model_aliases, want);
        assert!(!is_open(Degradation::WorkspaceGatewayConfigUnreadable));
        client
            .execute("DELETE FROM tenants WHERE id = $1", &[&id])
            .await
            .expect("cleanup");
    }

    /// GWY-52, real Postgres: the refresh loads the workspace's failover row; an
    /// unreadable table leaves the OPERATOR default (off, no chain) and is counted.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn gwy52_attach_workspace_failover_loads_and_fails_to_default() {
        use tracelane_shared::degradation::{Degradation, count};
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect");
        tokio::spawn(conn);
        let id: Uuid = client
            .query_one(
                "INSERT INTO tenants (workos_org_id, name) VALUES ($1, 'gwy52r') RETURNING id",
                &[&format!("org_gwy52r_{}", Uuid::new_v4().simple())],
            )
            .await
            .expect("tenant")
            .get(0);
        let mut resolved = ResolvedEntitlements::deny_all();
        attach_workspace_failover(&client, &id, &mut resolved).await;
        assert!(
            !resolved.failover_enabled && resolved.failover_models.is_empty(),
            "unset = default"
        );
        client
            .execute(
                "INSERT INTO workspace_failover (tenant_id, enabled, models) VALUES ($1, true, $2)",
                &[&id, &vec!["gpt-4o-mini".to_string()]],
            )
            .await
            .expect("row");
        attach_workspace_failover(&client, &id, &mut resolved).await;
        assert!(resolved.failover_enabled);
        assert_eq!(*resolved.failover_models, vec!["gpt-4o-mini".to_string()]);

        let empty = format!("gwy52_empty_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {empty}; SET search_path TO {empty}"
            ))
            .await
            .expect("empty schema");
        let before = count(Degradation::WorkspaceGatewayConfigUnreadable);
        attach_workspace_failover(&client, &id, &mut resolved).await;
        assert!(
            !resolved.failover_enabled && resolved.failover_models.is_empty(),
            "an unreadable row is the operator default, never the previous settings"
        );
        assert!(count(Degradation::WorkspaceGatewayConfigUnreadable) > before);
        client
            .batch_execute("SET search_path TO public")
            .await
            .expect("reset");
        client
            .execute("DELETE FROM tenants WHERE id = $1", &[&id])
            .await
            .expect("cleanup");
    }

    /// GWY-53, real Postgres: the refresh loads the owner's capture choice through the
    /// FULL resolver (not just the attach step — a resolver that forgot to call it would
    /// pass a step-only test); an unreadable table resolves capture OFF — never the
    /// previous ON — and is counted.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn gwy53_attach_content_capture_loads_and_fails_closed() {
        use crate::db::workspace_capture::WorkspaceCapture;
        use tracelane_shared::degradation::{Degradation, count};
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect");
        tokio::spawn(conn);
        // The migrations create `plan_entitlements` but seed no rows (the seed is
        // `apps/web/db/seed.mjs`), so the resolver's JOIN would match nothing and
        // every read below would be `deny_all` by accident — passing "unset = OFF"
        // for the wrong reason. Measured on the runner's DB 2026-09-28: 0 rows.
        client
            .execute(
                "INSERT INTO plan_entitlements (plan_lookup_key, indexed_window_days, queryable_days, ledger_days) \
                 VALUES ('builder_v1', 30, 730, 730) \
                 ON CONFLICT (plan_lookup_key) DO NOTHING",
                &[],
            )
            .await
            .expect("plan row");
        let id: Uuid = client
            .query_one(
                "INSERT INTO tenants (workos_org_id, name, plan) VALUES ($1, 'gwy53r', 'builder'::text::plan) RETURNING id",
                &[&format!("org_gwy53r_{}", Uuid::new_v4().simple())],
            )
            .await
            .expect("tenant")
            .get(0);
        let mut cfg = deadpool_postgres::Config::new();
        cfg.url = Some(url.clone());
        let pool = cfg
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .expect("pool");
        let resolve = pg_resolver(pool);
        let unset = resolve(id).await.expect("resolve");
        assert_eq!(
            unset.plan_lookup_key, "builder_v1",
            "the resolver must have matched the tenant — a deny_all here proves nothing"
        );
        assert_eq!(
            unset.content_capture,
            WorkspaceCapture::default(),
            "unset = OFF"
        );
        client
            .execute(
                "INSERT INTO workspace_content_capture (tenant_id, input, output) VALUES ($1, true, true)",
                &[&id],
            )
            .await
            .expect("row");
        assert_eq!(
            resolve(id).await.expect("resolve").content_capture,
            WorkspaceCapture {
                input: true,
                output: true
            },
            "the resolver must load the row"
        );

        let mut resolved = ResolvedEntitlements::deny_all();
        attach_content_capture(&client, &id, &mut resolved).await;
        assert!(resolved.content_capture.input && resolved.content_capture.output);
        let empty = format!("gwy53_empty_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {empty}; SET search_path TO {empty}"
            ))
            .await
            .expect("empty schema");
        let before = count(Degradation::WorkspaceGatewayConfigUnreadable);
        attach_content_capture(&client, &id, &mut resolved).await;
        assert_eq!(
            resolved.content_capture,
            WorkspaceCapture::default(),
            "an unreadable row is capture OFF, never the previous ON"
        );
        assert!(count(Degradation::WorkspaceGatewayConfigUnreadable) > before);
        client
            .batch_execute("SET search_path TO public")
            .await
            .expect("reset");
        client
            .execute("DELETE FROM tenants WHERE id = $1", &[&id])
            .await
            .expect("cleanup");
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

// ── Boot schema check (founder, 2026-09-14, B6 audit item B) ────────────────
//
// Nothing applies migrations at prod boot (`apply_migrations` is test-only) and
// every migration since 0009 is hand-applied, so a binary that reads a column
// the target database does not yet have is one `docker compose up` away. The
// deploy script's pre-flight (`check-deploy-schema.py`) covers the scripted
// path; this covers the manual one, permanently: the gateway REFUSES to boot
// when a definite answer says a column is missing.

/// Why the boot check did not pass.
#[derive(Debug)]
pub enum SchemaCheck {
    /// The database answered and these `table.column` pairs are absent — refuse to boot.
    Missing(Vec<String>),
    /// The check could not run (pool / query error) — the caller boots on the
    /// cache's own fail-open path and says so; a restart loop during a
    /// control-plane blip is the worse outcome.
    Unavailable(String),
}

/// `OG-11` (S2, migration 0070): the routing document the resolve reads and the BYOK
/// label every key lookup selects. Absent → the boot check refuses, rather than every
/// resolve failing (routing) or every BYOK lookup 503-ing (label).
const ROUTING_SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("workspace_routing", "tenant_id"),
    ("workspace_routing", "doc"),
    ("workspace_routing", "version"),
    ("provider_keys", "label"),
];

/// Every `(table, column)` the entitlement query reads, parsed from `SQL`
/// itself. Aliases: `pe` plan_entitlements · `we` workspace_entitlements · `t` tenants
/// · `pa` plan_allowances (B-409).
pub fn selected_columns() -> Vec<(&'static str, String)> {
    let re = regex::Regex::new(r"\b(pe|we|pa|t)\.([a-z_][a-z0-9_]*)").expect("static regex");
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for cap in re.captures_iter(SQL) {
        let table = match &cap[1] {
            "pe" => "plan_entitlements",
            "we" => "workspace_entitlements",
            "pa" => "plan_allowances",
            _ => "tenants",
        };
        let col = cap[2].to_string();
        if !out.iter().any(|(t, c)| *t == table && *c == col) {
            out.push((table, col));
        }
    }
    // OG-20 / OG-23 (S2): the API-key auth SELECT's project JOIN and governance
    // columns. Not this module's SQL, but the same failure if absent — every API key's
    // cold lookup would fail (503) — so the same boot refusal names them.
    for (t, c) in crate::db::api_keys::AUTH_SCHEMA_COLUMNS
        .iter()
        .chain(crate::db::controls::CONTROLS_SCHEMA_COLUMNS)
        .chain(crate::db::cache_settings::CACHE_SCHEMA_COLUMNS)
        .chain(crate::guardrail::policy_store::SCHEMA_COLUMNS)
        .chain(crate::guardrail::hooks_api::SCHEMA_COLUMNS)
        .chain(crate::db::control_audit::CONTROL_AUDIT_SCHEMA_COLUMNS)
        .chain(ROUTING_SCHEMA_COLUMNS)
    {
        if !out.iter().any(|(ot, oc)| ot == t && oc == c) {
            out.push((t, (*c).to_string()));
        }
    }
    out
}

/// Pure: which selected columns are not in `present` (`(table, column)` pairs).
pub fn missing_columns(
    selected: &[(&'static str, String)],
    present: &[(String, String)],
) -> Vec<String> {
    selected
        .iter()
        .filter(|(t, c)| !present.iter().any(|(pt, pc)| pt == t && pc == c))
        .map(|(t, c)| format!("{t}.{c}"))
        .collect()
}

/// Ask `information_schema.columns` for every required table and compare with what
/// `SQL` reads. `Ok(n)` = every one of the `n` selected columns exists.
pub async fn verify_schema(pool: &crate::db::DbPool) -> Result<usize, SchemaCheck> {
    let selected = selected_columns();
    // Query the same tables whose columns we require, so a newly registered
    // control schema cannot be absent from the catalog read itself.
    let mut tables: Vec<&str> = selected.iter().map(|(table, _)| *table).collect();
    tables.sort_unstable();
    tables.dedup();
    let client = pool
        .get()
        .await
        .map_err(|e| SchemaCheck::Unavailable(format!("pool: {e}")))?;
    let rows = client
        .query(
            "SELECT table_name::text, column_name::text FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = ANY($1)",
            &[&tables],
        )
        .await
        .map_err(|e| SchemaCheck::Unavailable(format!("information_schema query: {e}")))?;
    let present: Vec<(String, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    if present.is_empty() {
        // An empty answer is "cannot see", never "nothing is wrong" (CLAUDE.md §14).
        return Err(SchemaCheck::Unavailable(
            "information_schema returned no columns for the control-plane tables".into(),
        ));
    }
    let missing = missing_columns(&selected, &present);
    if missing.is_empty() {
        Ok(selected.len())
    } else {
        Err(SchemaCheck::Missing(missing))
    }
}

#[cfg(test)]
mod boot_schema_check_tests {
    use super::*;

    #[test]
    fn every_alias_in_the_query_maps_to_a_real_table_and_the_list_is_deduplicated() {
        let cols = selected_columns();
        assert!(
            cols.len() > 30,
            "the query names dozens of columns, got {}",
            cols.len()
        );
        for pair in [
            // B-409: allowances are read from the versioned table, and the pin
            // itself (`tenants.plan_version` + its expiry) is a boot requirement.
            ("plan_allowances", "hot_gb_included"),
            ("plan_allowances", "plan_version"),
            ("plan_allowances", "is_current"),
            ("tenants", "plan_version"),
            ("tenants", "price_protected_until"),
            ("plan_entitlements", "f_sso"),
            ("workspace_entitlements", "ingest_gb_included"),
            ("tenants", "spend_ceiling_usd"),
            ("tenants", "plan"),
            ("workspace_entitlements", "tenant_id"),
            // OG-20 / OG-23: the API-key auth SELECT's JOIN and policy columns.
            ("api_keys", "project_id"),
            ("api_keys", "policy"),
            ("projects", "policy"),
        ] {
            assert!(
                cols.iter().any(|(t, c)| (*t, c.as_str()) == pair),
                "missing {pair:?}"
            );
        }
        let mut seen = std::collections::HashSet::new();
        assert!(
            cols.iter().all(|p| seen.insert(p.clone())),
            "duplicates in the list"
        );
    }

    #[test]
    fn a_column_the_database_lacks_is_named_and_a_complete_database_passes() {
        let selected = selected_columns();
        let mut present: Vec<(String, String)> = selected
            .iter()
            .map(|(t, c)| ((*t).to_string(), c.clone()))
            .collect();
        assert!(missing_columns(&selected, &present).is_empty());
        // Falsify: drop exactly the column migration 0043 will add, plus one more.
        present.retain(|(t, c)| !(t == "plan_allowances" && c == "hot_gb_included"));
        present.retain(|(t, c)| !(t == "tenants" && c == "spend_ceiling_usd"));
        let missing = missing_columns(&selected, &present);
        assert_eq!(
            missing,
            vec![
                "plan_allowances.hot_gb_included".to_string(),
                "tenants.spend_ceiling_usd".to_string()
            ]
        );
    }

    /// A pool onto a FRESH database on the integration server — the three
    /// control-plane tables are built from `selected_columns()` itself (every
    /// column `text`; only presence matters to `information_schema`), so this
    /// test needs no migration and cannot disturb any other test's database.
    pub(crate) async fn fresh_pool(url: &str, ddl: &[String]) -> crate::db::DbPool {
        let (admin, conn) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .expect("connect to the integration Postgres");
        let handle = tokio::spawn(conn);
        let db = format!("tlane_schema_{}", uuid::Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {db}"))
            .await
            .expect("CREATE DATABASE (the integration role needs createdb)");
        drop(admin);
        let _ = handle.await;

        let pg_cfg: tokio_postgres::Config = url.parse().expect("parse POSTGRES_TEST_URL");
        let mut cfg = deadpool_postgres::Config::new();
        cfg.host = pg_cfg.get_hosts().first().map(|h| match h {
            tokio_postgres::config::Host::Tcp(s) => s.clone(),
            #[cfg(unix)]
            tokio_postgres::config::Host::Unix(p) => p.to_string_lossy().into_owned(),
        });
        cfg.port = pg_cfg.get_ports().first().copied();
        cfg.user = pg_cfg.get_user().map(str::to_owned);
        cfg.password = pg_cfg
            .get_password()
            .map(|p| String::from_utf8_lossy(p).to_string());
        cfg.dbname = Some(db);
        let pool = cfg
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .expect("create pool");
        let client = pool.get().await.expect("pool.get");
        for stmt in ddl {
            client.batch_execute(stmt).await.expect("ddl");
        }
        pool
    }

    /// The boot refusal, observed against a REAL `information_schema` rather
    /// than a hand-built `present` list: a complete database passes with the
    /// full column count, dropping ONE column the SELECT names fails with
    /// exactly that column, and a database with none of the tables is
    /// `Unavailable` (the fail-open branch) — never a silent pass. Until
    /// 2026-09-15 the refusal had been falsified once by hand on a probe
    /// Postgres and never by anything a gate runs (verifier residual R1).
    /// `#[ignore]`d by default; `scripts/ci/run-postgres-integration.sh` runs it.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn verify_schema_refuses_a_missing_column_against_a_real_information_schema() {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let selected = selected_columns();
        let mut by_table: std::collections::BTreeMap<&str, Vec<String>> =
            std::collections::BTreeMap::new();
        for (t, c) in &selected {
            by_table.entry(t).or_default().push(c.clone());
        }
        let ddl: Vec<String> = by_table
            .iter()
            .map(|(t, cols)| {
                let body = cols
                    .iter()
                    .map(|c| format!("{c} text"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("CREATE TABLE {t} ({body})")
            })
            .collect();

        // 1. Complete → Ok(n), n = every column the SELECT names.
        let pool = fresh_pool(&url, &ddl).await;
        assert_eq!(verify_schema(&pool).await.unwrap(), selected.len());

        // 2. Drop exactly one named column → Missing names exactly it.
        let client = pool.get().await.unwrap();
        client
            .batch_execute("ALTER TABLE tenants DROP COLUMN current_period_end")
            .await
            .unwrap();
        drop(client);
        match verify_schema(&pool).await {
            Err(SchemaCheck::Missing(cols)) => {
                assert_eq!(cols, vec!["tenants.current_period_end".to_string()]);
            }
            other => panic!("expected Missing([tenants.current_period_end]), got {other:?}"),
        }

        // 3. Restore it → Ok again (the check is about presence, not history).
        let client = pool.get().await.unwrap();
        client
            .batch_execute("ALTER TABLE tenants ADD COLUMN current_period_end text")
            .await
            .unwrap();
        drop(client);
        assert_eq!(verify_schema(&pool).await.unwrap(), selected.len());

        // 4. No tables at all → Unavailable, the documented fail-OPEN branch
        //    (an empty information_schema answer is "cannot see", CLAUDE.md §14).
        let empty = fresh_pool(&url, &[]).await;
        match verify_schema(&empty).await {
            Err(SchemaCheck::Unavailable(_)) => {}
            other => panic!("expected Unavailable on an empty schema, got {other:?}"),
        }
    }
}

/// B-409 real-Postgres fixture: a FRESH, fully migrated database per test (so the
/// tests run in parallel without sharing `is_current` state), the builder allowances
/// read from `apps/web/db/plans.v3.json` (never re-typed — `.claude/rules/
/// reference-tables.md`), and a hypothetical later ruling `v4` whose every number
/// differs from v3's. Shared with the metering-job and retention-sweep tests.
#[cfg(test)]
pub(crate) mod b409_fixture {
    use uuid::Uuid;

    /// One plan's versioned allowances, in the units `plan_allowances` stores.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Allow {
        pub hot_gb: f64,
        pub ingest_gb: f64,
        pub cold_gb: f64,
        pub series: i64,
        pub scan: i64,
        pub eval: i64,
        pub indexed: i32,
        pub queryable: i32,
        pub ledger: i32,
    }

    /// `builder_v1` exactly as `plans.v3.json` rules it.
    pub(crate) fn v3_builder() -> Allow {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json"))
                .expect("plans.v3.json parses");
        let p = &v["plans"]["builder_v1"];
        let f = |k: &str| {
            p[k].as_f64()
                .unwrap_or_else(|| panic!("plans.v3.json builder_v1.{k}"))
        };
        Allow {
            hot_gb: f("hot_gb_included"),
            ingest_gb: f("ingest_gb_included"),
            cold_gb: f("cold_gb_included"),
            series: f("series_included") as i64,
            scan: f("scan_units_included") as i64,
            eval: f("eval_runs_included") as i64,
            indexed: f("indexed_window_days") as i32,
            queryable: f("queryable_days") as i32,
            ledger: f("ledger_days") as i32,
        }
    }

    /// A later ruling: every allowance and window DIFFERENT from v3's, so a test that
    /// reads the wrong version cannot pass by coincidence.
    pub(crate) fn v4_builder() -> Allow {
        let a = v3_builder();
        Allow {
            hot_gb: a.hot_gb * 2.0,
            ingest_gb: a.ingest_gb * 2.0,
            cold_gb: a.cold_gb * 2.0,
            series: a.series * 2,
            scan: a.scan * 2,
            eval: a.eval * 2,
            indexed: a.indexed * 2,
            queryable: a.queryable / 2,
            ledger: a.ledger / 2,
        }
    }

    pub(crate) fn gb_to_bytes(gb: f64) -> Option<u64> {
        Some((gb * 1_000_000_000.0).round() as u64)
    }

    /// A fresh database on the integration server, migrated with EVERY file the
    /// gateway's `apply_migrations` lists (0055 included).
    pub(crate) async fn fresh_migrated_pool() -> crate::db::DbPool {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let pool = super::boot_schema_check_tests::fresh_pool(&url, &[]).await;
        crate::db::apply_migrations(&pool)
            .await
            .expect("apply every migration to the fresh database");
        pool
    }

    async fn insert_allowance(c: &tokio_postgres::Client, version: &str, a: Allow, current: bool) {
        c.execute(
            "INSERT INTO plan_allowances (plan_version, plan_lookup_key, hot_gb_included, \
               ingest_gb_included, cold_gb_included, series_included, scan_units_included, \
               eval_runs_included, indexed_window_days, queryable_days, ledger_days, is_current) \
             VALUES ($1, 'builder_v1', $2::float8::numeric, $3::float8::numeric, \
               $4::float8::numeric, $5, $6, $7, $8, $9, $10, $11)",
            &[
                &version,
                &a.hot_gb,
                &a.ingest_gb,
                &a.cold_gb,
                &a.series,
                &a.scan,
                &a.eval,
                &a.indexed,
                &a.queryable,
                &a.ledger,
                &current,
            ],
        )
        .await
        .expect("insert plan_allowances row");
    }

    /// The state right after a NEW ruling `v4` is seeded: the catalog
    /// (`plan_entitlements`, what the seed's `update plan_entitlements` writes) carries
    /// v4's numbers; `plan_allowances` keeps v3 (no longer current) and adds v4 (current).
    pub(crate) async fn seed_v3_then_v4(pool: &crate::db::DbPool) {
        let c = pool.get().await.expect("client");
        let n = v4_builder();
        c.execute(
            "INSERT INTO plan_entitlements (plan_lookup_key, hot_gb_included, ingest_gb_included, \
               cold_gb_included, series_included, scan_units_included, eval_runs_included, \
               indexed_window_days, queryable_days, ledger_days, overage_allowed, unlimited_seats) \
             VALUES ('builder_v1', $1::float8::numeric, $2::float8::numeric, $3::float8::numeric, \
               $4, $5, $6, $7, $8, $9, true, true)",
            &[
                &n.hot_gb,
                &n.ingest_gb,
                &n.cold_gb,
                &n.series,
                &n.scan,
                &n.eval,
                &n.indexed,
                &n.queryable,
                &n.ledger,
            ],
        )
        .await
        .expect("plan_entitlements catalog row (v4 numbers)");
        insert_allowance(&c, "v3", v3_builder(), false).await;
        insert_allowance(&c, "v4", n, true).await;
    }

    /// A builder tenant. `pin` = `tenants.plan_version`; `protected_days` = days until
    /// `price_protected_until` (negative = already expired; `None` = never set).
    pub(crate) async fn builder_tenant(
        pool: &crate::db::DbPool,
        pin: Option<&str>,
        protected_days: Option<i32>,
    ) -> Uuid {
        let c = pool.get().await.expect("client");
        c.query_one(
            "INSERT INTO tenants (workos_org_id, plan, plan_version, price_protected_until) \
             VALUES ($1, 'builder'::text::plan, $2, \
               CASE WHEN $3::int IS NULL THEN NULL ELSE now() + make_interval(days => $3::int) END) \
             RETURNING id",
            &[
                &format!("org_b409_{}", Uuid::new_v4().simple()),
                &pin,
                &protected_days,
            ],
        )
        .await
        .expect("insert builder tenant")
        .get(0)
    }
}

/// B-409 — allowances pinned by version. Real Postgres, `#[ignore]`d; run by
/// `scripts/ci/run-postgres-integration.sh` (filter `entitlement_cache::b409_tests`).
#[cfg(test)]
mod b409_tests {
    use super::b409_fixture::*;
    use super::*;

    fn assert_allowances(e: &ResolvedEntitlements, a: Allow, what: &str) {
        assert_eq!(e.hot_bytes_included, gb_to_bytes(a.hot_gb), "{what}: hot");
        assert_eq!(
            e.ingest_bytes_included,
            gb_to_bytes(a.ingest_gb),
            "{what}: ingest"
        );
        assert_eq!(
            e.cold_bytes_included,
            gb_to_bytes(a.cold_gb),
            "{what}: cold"
        );
        assert_eq!(e.series_included, Some(a.series), "{what}: series");
        assert_eq!(e.scan_units_included, Some(a.scan), "{what}: scan units");
        assert_eq!(e.eval_runs_included, Some(a.eval), "{what}: eval runs");
        assert_eq!(e.indexed_window_days, a.indexed, "{what}: indexed window");
        assert_eq!(e.queryable_days, a.queryable, "{what}: queryable");
        assert_eq!(e.ledger_days, a.ledger, "{what}: ledger");
    }

    /// The defect itself: a tenant pinned to v3 keeps v3's allowances after a new
    /// ruling v4 is seeded with different numbers (and made current).
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn b409_pinned_tenant_keeps_its_version_after_a_new_one_is_seeded() {
        let pool = fresh_migrated_pool().await;
        seed_v3_then_v4(&pool).await;
        let pinned = builder_tenant(&pool, Some("v3"), Some(200)).await;
        let e = pg_resolver(pool)(pinned).await.expect("resolve");
        assert_eq!(e.plan_lookup_key, "builder_v1");
        assert_allowances(&e, v3_builder(), "pinned to v3 after v4 was seeded");
        assert_eq!(e.plan_version.as_deref(), Some("v3"));
    }

    /// A tenant with no pin (never paid) reads the CURRENT version; so does one whose
    /// protection window has expired.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn b409_unpinned_and_expired_tenants_read_the_current_version() {
        let pool = fresh_migrated_pool().await;
        seed_v3_then_v4(&pool).await;
        let fresh = builder_tenant(&pool, None, None).await;
        let expired = builder_tenant(&pool, Some("v3"), Some(-1)).await;
        let resolve = pg_resolver(pool);
        let f = resolve(fresh).await.unwrap();
        assert_allowances(&f, v4_builder(), "unpinned");
        assert_eq!(f.plan_version.as_deref(), Some("v4"));
        let x = resolve(expired).await.unwrap();
        assert_allowances(&x, v4_builder(), "protection expired");
        assert_eq!(x.plan_version.as_deref(), Some("v4"));
    }

    /// rev4 M3: the pinned version's row is MISSING → the tenant's plan's CURRENT
    /// row, never the zero floor. The floor would answer zero allowances while
    /// overage/overflow still come from the plan — 75/90 % warnings against zero and
    /// an auto-age narrowing on a deploy defect, not on the customer's usage.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn b409_missing_pinned_row_falls_back_to_the_current_row() {
        let pool = fresh_migrated_pool().await;
        seed_v3_then_v4(&pool).await;
        let orphan = builder_tenant(&pool, Some("v_never_seeded"), Some(200)).await;
        let before = ALLOWANCE_PIN_FALLBACK_TOTAL.load(Ordering::Relaxed);
        let e = pg_resolver(pool)(orphan).await.expect("resolve");
        assert_eq!(e.plan_lookup_key, "builder_v1");
        assert_allowances(&e, v4_builder(), "pinned row missing → current row");
        assert_eq!(e.plan_version.as_deref(), Some("v4"));
        assert!(e.allowances_known());
        assert!(
            ALLOWANCE_PIN_FALLBACK_TOTAL.load(Ordering::Relaxed) > before,
            "the fallback is counted"
        );
    }

    /// Neither the pinned nor a current row → fail CLOSED to the deny floor: zero
    /// allowances (never `None`, which means custom/unlimited) and the floor windows.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn b409_missing_pinned_and_current_rows_fail_closed_to_the_deny_floor() {
        let pool = fresh_migrated_pool().await;
        seed_v3_then_v4(&pool).await;
        // v4 (the current row) is unpinned, so it may go; v3 is not current.
        pool.get()
            .await
            .unwrap()
            .execute("DELETE FROM plan_allowances WHERE plan_version = 'v4'", &[])
            .await
            .expect("an unpinned version is deletable");
        let orphan = builder_tenant(&pool, Some("v_never_seeded"), Some(200)).await;
        let e = pg_resolver(pool)(orphan).await.expect("resolve");
        let floor = ResolvedEntitlements::deny_all();
        assert_eq!(
            e.plan_lookup_key, "builder_v1",
            "the tenant row itself resolved"
        );
        assert_eq!(e.hot_bytes_included, Some(0), "never None (= unlimited)");
        assert_eq!(e.ingest_bytes_included, floor.ingest_bytes_included);
        assert_eq!(e.series_included, Some(0));
        assert_eq!(e.scan_units_included, Some(0));
        assert_eq!(e.eval_runs_included, Some(0));
        assert_eq!(e.indexed_window_days, floor.indexed_window_days);
        assert_eq!(e.queryable_days, floor.queryable_days);
        assert_eq!(e.ledger_days, floor.ledger_days);
        assert_eq!(e.plan_version, None, "no row resolved");
        assert!(
            !e.allowances_known(),
            "the metering job must not warn or auto-age against this floor"
        );
        assert!(
            ALLOWANCE_ROW_MISSING_TOTAL.load(Ordering::Relaxed) >= 1,
            "counted"
        );
    }

    /// The pinned allowance is served by the cache: one resolve, then warm reads
    /// that never reach Postgres (`CLAUDE.md` §2 — never a per-request round trip).
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn b409_cache_serves_the_pinned_allowance_without_a_per_request_db_call() {
        let pool = fresh_migrated_pool().await;
        seed_v3_then_v4(&pool).await;
        let pinned = builder_tenant(&pool, Some("v3"), Some(200)).await;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inner = pg_resolver(pool);
        let counted: ResolveFn = {
            let calls = calls.clone();
            Arc::new(move |t: Uuid| {
                calls.fetch_add(1, Ordering::SeqCst);
                inner(t)
            })
        };
        let cache = EntitlementCache::new(counted);
        for _ in 0..20 {
            let served = cache.resolved(pinned).await;
            assert_allowances(served.as_ref(), v3_builder(), "cached pinned read");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "warm reads must not re-resolve"
        );
    }

    /// A version's numbers are immutable (only `is_current` flips) and a pinned
    /// version cannot be deleted — the migration's trigger, proven to REFUSE.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn b409_a_versions_numbers_are_immutable_and_a_pinned_version_undeletable() {
        let pool = fresh_migrated_pool().await;
        seed_v3_then_v4(&pool).await;
        builder_tenant(&pool, Some("v3"), Some(200)).await;
        let c = pool.get().await.unwrap();
        let edit = c
            .execute(
                "UPDATE plan_allowances SET series_included = series_included + 1 \
                 WHERE plan_version = 'v3'",
                &[],
            )
            .await;
        assert!(
            edit.is_err(),
            "editing a version's numbers in place must be refused"
        );
        let del = c
            .execute("DELETE FROM plan_allowances WHERE plan_version = 'v3'", &[])
            .await;
        assert!(del.is_err(), "deleting a pinned version must be refused");
        // rev4 L6: a statement-level TRUNCATE skips every row trigger — it must be
        // refused too while any tenant pins a version.
        let trunc = c.batch_execute("TRUNCATE plan_allowances").await;
        assert!(
            trunc.is_err(),
            "TRUNCATE must be refused while a version is pinned"
        );
        // Flipping is_current is the ONE permitted update (the seed's job).
        c.batch_execute(
            "BEGIN; UPDATE plan_allowances SET is_current = false WHERE plan_version = 'v4'; \
             UPDATE plan_allowances SET is_current = true WHERE plan_version = 'v3'; COMMIT;",
        )
        .await
        .expect("is_current may flip");
        // An unpinned version CAN be deleted (nothing pins it).
        c.execute("DELETE FROM plan_allowances WHERE plan_version = 'v4'", &[])
            .await
            .expect("an unpinned version is deletable");
    }
}

/// rev4 L7: the dashboard shows the SAME floor this gateway enforces when no
/// allowance row resolves — `apps/web/lib/entitlements.ts` `ALLOWANCE_DENY_FLOOR`
/// is read from source and held equal to [`ResolvedEntitlements::deny_all`].
#[cfg(test)]
mod rev4_l7_tests {
    use super::*;

    #[test]
    fn rev4_l7_the_web_deny_floor_is_the_gateways() {
        let ts = include_str!("../../../apps/web/lib/entitlements.ts");
        let start = ts
            .find("export const ALLOWANCE_DENY_FLOOR = {")
            .expect("the web deny floor exists");
        let body = &ts[start..start + ts[start..].find('}').expect("closing brace")];
        let field = |k: &str| -> i64 {
            let at = body.find(&format!("{k}:")).unwrap_or_else(|| panic!("{k}"));
            body[at + k.len() + 1..]
                .trim_start()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("{k} is not a number"))
        };
        let d = ResolvedEntitlements::deny_all();
        assert_eq!(Some(field("hot_gb_included") as u64), d.hot_bytes_included);
        assert_eq!(
            Some(field("ingest_gb_included") as u64),
            d.ingest_bytes_included
        );
        assert_eq!(Some(field("series_included")), d.series_included);
        assert_eq!(Some(field("scan_units_included")), d.scan_units_included);
        assert_eq!(Some(field("eval_runs_included")), d.eval_runs_included);
        assert_eq!(
            field("indexed_window_days"),
            i64::from(d.indexed_window_days)
        );
        assert_eq!(field("queryable_days"), i64::from(d.queryable_days));
        assert_eq!(field("ledger_days"), i64::from(d.ledger_days));
    }
}
