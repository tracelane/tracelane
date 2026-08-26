//! Per-API-key monthly spend, and the budget cut-off it enforces (GWY-43).
//!
//! `api_keys.budget_usd_monthly` has existed since A13. It was validated at
//! mint, INSERTed, and then **never read again** — the hot-path auth SELECT
//! reads five columns and that was not one of them. A13 deferred enforcement
//! deliberately and said so ("v1 RECORDS and REPORTS the budget; it does not
//! enforce a cut-off"), so this is the deferred half arriving, not drift.
//!
//! ## Why a counter and not a query
//!
//! The obvious implementation — sum this key's spend in ClickHouse per request
//! — puts a cross-network aggregate on the hot path of a gateway whose whole
//! product claim is added latency. It is not viable, and B-256 (an unexplained
//! 13× production overhead regression) is open while this ships.
//!
//! So this mirrors [`crate::rate_limiter::QuotaTracker`] exactly, including the
//! part that took a bug to learn. **: an in-memory counter alone is not a
//! cap.** The quota counter reset to zero on every process restart, so
//! a redeploy forgave accrued usage and the hard cap was bypassable by shipping.
//! The fix, reused here: the counter is *seeded* from a durable ClickHouse total
//! once per key per month per process, guarded by a `(key, YYYYMM)` entry so
//! concurrent first-requests seed exactly once and never clobber increments the
//! seeding request's peers already made.
//!
//! ## What this can and cannot promise
//!
//! It is a **soft-real-time** cap, and the honest statement of its limit is:
//!
//!   * spend is added AFTER a request completes, because the cost is not known
//!     until the provider reports tokens — so the request that crosses the line
//!     is served, and the one after it is refused. A single very large request
//!     can overshoot by its own cost. It cannot run away: the next check sees
//!     the new total.
//!   * the ClickHouse seed only covers spans written since migration 16, since
//!     that is when `api_key_id` began being recorded. Spend before the cutover
//!     is not attributable to a key and is not counted.
//!   * a ClickHouse read failure seeds **0**, which fails OPEN — the same choice
//!     `quota_baseline_from_clickhouse` makes, and for the same reason: a
//!     control-plane outage must not stop a customer's production traffic. It is
//!     stated here because a fail-open budget is a thing an operator must know
//!     about rather than discover.
//!
//! Fail-open is correct here and is NOT in tension with
//! `.claude/rules/tenancy.md`: that rule governs *entitlement* reads, where the
//! absent-cache state must resolve to the unprivileged tier. A budget is a
//! customer's own self-imposed ceiling, not a paid capability, so the
//! fault-tolerance direction applies (`CLAUDE.md` §10).

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// USD are held as integer micro-dollars so the hot path touches an `AtomicU64`
/// and never a float. 1 USD = 1_000_000 µUSD; a single request's cost is
/// comfortably above 1 µUSD, so rounding is not a leak.
const MICRO: f64 = 1_000_000.0;

/// What the budget check decided.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BudgetDecision {
    /// No budget set on this key, or the key is under it.
    Allow,
    /// The key is at or over its monthly budget. HARD STOP.
    Exceeded {
        /// The key's configured monthly ceiling, USD.
        budget_usd: f64,
        /// Spend recorded against the key so far this month, USD.
        spent_usd: f64,
    },
}

/// Which subject a spend counter belongs to.
///
/// Keys and tenants are both UUIDs, and one map serves both — so the namespace
/// has to be part of the map key or a tenant whose id happened to equal a key id
/// would share a counter. That cannot happen with random v4 UUIDs, but "cannot
/// happen" is not a property a money counter should rest on when the fix is one
/// enum discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subject {
    /// One API key — `api_keys.id`.
    Key(Uuid),
    /// The whole workspace — `tenants.id`. The "per-team" cap: a team in this
    /// product IS the workspace (there is no `teams` table and never was).
    Workspace(Uuid),
}

/// Per-subject monthly spend, in micro-USD.
pub struct SpendTracker {
    /// subject → µUSD spent this month.
    spend: Arc<DashMap<Subject, AtomicU64>>,
    /// `api_keys.id` → the `YYYYMM` its counter was last seeded for. Absent
    /// means never seeded in this process (fresh start / post-deploy); a
    /// different month means the month rolled. Both need a re-seed, and this one
    /// map expresses both — the same trick `QuotaTracker` uses, and the reason
    /// there is no separate month-boundary reset job to forget to run.
    seeded: Arc<DashMap<Subject, u32>>,
}

impl Default for SpendTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SpendTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            spend: Arc::new(DashMap::new()),
            seeded: Arc::new(DashMap::new()),
        }
    }

    /// Does this key's counter need seeding for `year_month` (`YYYYMM`)?
    ///
    /// The hot path calls this FIRST so the durable ClickHouse read happens once
    /// per key per month per process, never per request.
    #[must_use]
    pub fn needs_seed(&self, who: Subject, year_month: u32) -> bool {
        self.seeded.get(&who).is_none_or(|m| *m != year_month)
    }

    /// Seed the counter from a durable baseline. Idempotent and race-safe: the
    /// `seeded` entry is the guard, so concurrent first-requests for one key
    /// seed exactly once. Returns whether this call did the seeding.
    ///
    /// The baseline is ADDED, not stored: a concurrent request may already have
    /// recorded its own spend while the ClickHouse read was in flight, and
    /// `store` would silently discard it.
    pub fn seed_if_needed(&self, who: Subject, year_month: u32, baseline_usd: f64) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.seeded.entry(who) {
            Entry::Occupied(mut e) if *e.get() != year_month => {
                // Month rolled: the previous month's total must not carry over.
                self.spend
                    .entry(who)
                    .or_insert_with(|| AtomicU64::new(0))
                    .store(to_micro(baseline_usd), Ordering::Relaxed);
                e.insert(year_month);
                true
            }
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
                self.spend
                    .entry(who)
                    .or_insert_with(|| AtomicU64::new(0))
                    .fetch_add(to_micro(baseline_usd), Ordering::Relaxed);
                e.insert(year_month);
                true
            }
        }
    }

    /// Record the cost of a completed request. Called off the response path.
    ///
    /// A `None` cost — a model whose price we do not know — adds nothing. It
    /// does NOT add zero as if the request were free: the counter simply has no
    /// information about it, and `pricing::cost_usd` returning `None` is the
    /// honest answer the whole cost stack preserves.
    pub fn record(&self, who: Subject, cost_usd: Option<f64>) {
        let Some(cost) = cost_usd else { return };
        if !(cost.is_finite() && cost > 0.0) {
            return;
        }
        self.spend
            .entry(who)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(to_micro(cost), Ordering::Relaxed);
    }

    /// Decide whether this key may spend more.
    ///
    /// `budget_usd` of `None` (no ceiling set) or `<= 0` is [`BudgetDecision::Allow`].
    /// Zero deliberately means "uncapped", matching the column's own semantics
    /// (`NULL = uncapped`) rather than "may spend nothing" — a key that could
    /// never be used would be a foot-gun, and `revoked_at` already exists for
    /// switching a key off.
    #[must_use]
    pub fn check(&self, who: Subject, budget_usd: Option<f64>) -> BudgetDecision {
        let Some(budget) = budget_usd else {
            return BudgetDecision::Allow;
        };
        if !(budget.is_finite() && budget > 0.0) {
            return BudgetDecision::Allow;
        }
        let spent = self.current_micro(who);
        if spent >= to_micro(budget) {
            BudgetDecision::Exceeded {
                budget_usd: budget,
                spent_usd: from_micro(spent),
            }
        } else {
            BudgetDecision::Allow
        }
    }

    /// Spend recorded against this key so far this month, USD. For status
    /// surfaces and the 402 body. `0.0` for a key with no recorded spend.
    #[must_use]
    pub fn current_usd(&self, who: Subject) -> f64 {
        from_micro(self.current_micro(who))
    }

    fn current_micro(&self, who: Subject) -> u64 {
        self.spend
            .get(&who)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }
}

fn to_micro(usd: f64) -> u64 {
    if !usd.is_finite() || usd <= 0.0 {
        return 0;
    }
    // `as` on an out-of-range f64 saturates in Rust, so a nonsense budget
    // cannot wrap the counter.
    (usd * MICRO).round() as u64
}

fn from_micro(micro: u64) -> f64 {
    micro as f64 / MICRO
}

/// The process-wide tracker.
///
/// A global, not a field on `AppState`, for the same reason
/// [`crate::rejection_metrics::registry`] is: spend has to be RECORDED from
/// inside `provider_stream_to_sse`, which outlives the handler frame and is
/// handed its dependencies one by one. Threading an `Arc<SpendTracker>` through
/// a 23-argument function to reach one `record()` call would add a parameter to
/// every call site including the tests, for no isolation benefit — the tracker
/// is keyed by `api_keys.id`, so there is exactly one correct instance per
/// process either way.
pub fn tracker() -> &'static SpendTracker {
    static T: std::sync::OnceLock<SpendTracker> = std::sync::OnceLock::new();
    T.get_or_init(SpendTracker::new)
}

/// The workspace's monthly ceiling in USD, or `None` for uncapped.
///
/// **ONE resolution of the ceiling, reused by every surface that spends money
/// off the chat path** — the eval runner and the experiment runner both call
/// this rather than each reading the cache their own way. Two readings of one
/// number is how a cap that is enforced on one path and not another appears,
/// and nothing fails when it does.
///
/// `0` in the column means UNCAPPED, matching [`SpendTracker::check`] and the
/// chat path's own reading of `workspace_budget_micro_usd` — not "may spend
/// nothing", which would make a workspace that set no budget unable to run
/// anything.
///
/// **An ABSENT cache returns `None` (uncapped), and that is fault tolerance, not
/// a grant.** `.claude/rules/tenancy.md` governs ENTITLEMENT reads, where absent
/// must resolve to the unprivileged tier; a budget is the customer's own
/// self-imposed ceiling rather than a paid capability, so `CLAUDE.md` §10's
/// fail-OPEN direction applies — the same choice the seed path makes when
/// ClickHouse cannot be read. The surface that gates the FEATURE still
/// fail-closes independently.
pub async fn workspace_budget_usd(
    entitlements: Option<&std::sync::Arc<crate::entitlement_cache::EntitlementCache>>,
    tenant: &tracelane_shared::TenantId,
) -> Option<f64> {
    let cache = entitlements?;
    let micro = cache
        .resolved(*tenant.as_uuid())
        .await
        .workspace_budget_micro_usd;
    (micro > 0).then(|| micro as f64 / MICRO)
}

/// The PRE-FLIGHT refusal: is this workspace already over its ceiling?
///
/// Returns the typed `402` body when it is, `None` when it may spend. **The body
/// is byte-identical to the chat path's** (`server.rs`, `workspace_budget_exceeded`)
/// — same `error` slug, same three fields — because a client that learned to
/// handle a budget refusal on one surface must not have to learn a second shape
/// on another.
///
/// Seeding is the CALLER's job and must happen first, or this reads a counter of
/// zero on a fresh process and lets a run through that the durable total would
/// have refused.
#[must_use]
pub fn workspace_refusal(who: Subject, budget_usd: Option<f64>) -> Option<serde_json::Value> {
    match tracker().check(who, budget_usd) {
        BudgetDecision::Allow => None,
        BudgetDecision::Exceeded {
            budget_usd,
            spent_usd,
        } => Some(serde_json::json!({
            "error": "workspace_budget_exceeded",
            "message": "this workspace has reached its monthly budget",
            "budget_usd": budget_usd,
            "spent_usd": spent_usd,
            "resets_at": crate::server::next_month_boundary_iso(),
        })),
    }
}

/// Seed the workspace counter from the durable ClickHouse total, once per
/// workspace per month per process. Fail-OPEN — see
/// [`workspace_budget_usd`] for why that direction is correct for a budget.
pub async fn seed_workspace(ch: &clickhouse::Client, tenant: &tracelane_shared::TenantId) {
    let who = Subject::Workspace(*tenant.as_uuid());
    let ym = year_month(chrono::Utc::now());
    if !tracker().needs_seed(who, ym) {
        return;
    }
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct SumRow {
        usd: f64,
    }
    // ADR-031 CAPS, at the TIGHTEST tier. A budget seed is BACKGROUND work — it
    // runs before an eval or experiment starts, never on the chat path — so it
    // must not be able to out-consume the interactive queries of the same
    // workspace. The query is a single-row aggregate already bounded by
    // `tenant_id` and a month, so the caps cost nothing and remove the whole
    // class rather than arguing about this one.
    //
    // The chat path runs the SAME SQL uncapped (`server.rs`). That is B-225's
    // row, not this change's to move: touching the hot path's seeding to satisfy
    // a guard on a background path is exactly the widening this repo asks not to
    // do mid-build.
    let sql = crate::clickhouse_query::TenantQuery::new(
        crate::server::WORKSPACE_SPEND_THIS_MONTH_SQL,
        crate::clickhouse_query::PlanTier::Builder,
    )
    .sql_with_settings();
    let baseline = match ch
        .query(&sql)
        .bind(tenant.to_string())
        .fetch_one::<SumRow>()
        .await
    {
        Ok(r) if r.usd.is_finite() && r.usd > 0.0 => r.usd,
        Ok(_) => 0.0,
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant,
                "workspace spend baseline read failed; seeding 0 (fail-open)"
            );
            0.0
        }
    };
    tracker().seed_if_needed(who, ym, baseline);
}

/// `YYYYMM` for a UTC instant — the period key both this tracker and
/// `QuotaTracker` bucket by.
#[must_use]
pub fn year_month(now: chrono::DateTime<chrono::Utc>) -> u32 {
    use chrono::Datelike as _;
    now.year() as u32 * 100 + now.month()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> Subject {
        Subject::Key(Uuid::new_v4())
    }

    #[test]
    fn no_budget_always_allows() {
        let t = SpendTracker::new();
        let key = k();
        t.record(key, Some(1_000_000.0));
        assert_eq!(t.check(key, None), BudgetDecision::Allow);
    }

    #[test]
    fn zero_budget_means_uncapped_not_unusable() {
        let t = SpendTracker::new();
        let key = k();
        t.record(key, Some(5.0));
        assert_eq!(
            t.check(key, Some(0.0)),
            BudgetDecision::Allow,
            "0 matches the column's NULL=uncapped semantics; use revoked_at to switch a key off"
        );
    }

    /// The control, observed BLOCKING. A budget that has never been seen to
    /// refuse is not a budget.
    #[test]
    fn a_key_over_its_budget_is_refused() {
        let t = SpendTracker::new();
        let key = k();
        assert_eq!(t.check(key, Some(10.0)), BudgetDecision::Allow);
        t.record(key, Some(9.99));
        assert_eq!(
            t.check(key, Some(10.0)),
            BudgetDecision::Allow,
            "under budget must still pass — the check is not vacuous"
        );
        t.record(key, Some(0.02));
        match t.check(key, Some(10.0)) {
            BudgetDecision::Exceeded {
                budget_usd,
                spent_usd,
            } => {
                assert!((budget_usd - 10.0).abs() < 1e-9);
                assert!(spent_usd > 10.0, "spent {spent_usd} should exceed the cap");
            }
            BudgetDecision::Allow => panic!("10.01 spent against a $10 budget must be refused"),
        }
    }

    #[test]
    fn exactly_at_budget_is_refused_not_allowed() {
        let t = SpendTracker::new();
        let key = k();
        t.record(key, Some(10.0));
        assert!(
            matches!(t.check(key, Some(10.0)), BudgetDecision::Exceeded { .. }),
            "at the cap is over: a $10 budget must not permit a $10.000001 total"
        );
    }

    /// An unknown cost adds NOTHING. Adding zero would be indistinguishable from
    /// a free request and would let unpriced traffic run under a budget forever
    /// — which is exactly what the read-side `if(…, 0)` coercions did to the
    /// spend tile.
    #[test]
    fn an_unpriced_request_adds_nothing_rather_than_zero() {
        let t = SpendTracker::new();
        let key = k();
        t.record(key, None);
        t.record(key, Some(f64::NAN));
        t.record(key, Some(-1.0));
        assert_eq!(t.current_usd(key), 0.0);
        assert_eq!(t.check(key, Some(0.000_001)), BudgetDecision::Allow);
    }

    /// lesson, applied here: a restart must not forgive spend.
    #[test]
    fn seeding_restores_spend_after_a_restart() {
        let t = SpendTracker::new(); // a "fresh process"
        let key = k();
        assert!(t.needs_seed(key, 202_608));
        assert!(t.seed_if_needed(key, 202_608, 7.5));
        assert!(!t.needs_seed(key, 202_608));
        assert!((t.current_usd(key) - 7.5).abs() < 1e-6);
        assert!(
            matches!(t.check(key, Some(5.0)), BudgetDecision::Exceeded { .. }),
            "a restart must not hand the key its budget back"
        );
    }

    #[test]
    fn seeding_twice_in_one_month_does_not_double_count() {
        let t = SpendTracker::new();
        let key = k();
        t.seed_if_needed(key, 202_608, 4.0);
        t.record(key, Some(1.0));
        assert!(
            !t.seed_if_needed(key, 202_608, 4.0),
            "second seed must be a no-op"
        );
        assert!(
            (t.current_usd(key) - 5.0).abs() < 1e-6,
            "got {}, expected 5.0 — the re-seed must not clobber the concurrent record()",
            t.current_usd(key)
        );
    }

    #[test]
    fn a_new_month_resets_to_that_months_baseline() {
        let t = SpendTracker::new();
        let key = k();
        t.seed_if_needed(key, 202_608, 40.0);
        t.record(key, Some(5.0));
        assert!(t.needs_seed(key, 202_609), "September needs its own seed");
        assert!(t.seed_if_needed(key, 202_609, 0.0));
        assert_eq!(
            t.current_usd(key),
            0.0,
            "August's spend must not carry into September"
        );
    }

    #[test]
    fn year_month_is_yyyymm() {
        let d = chrono::DateTime::parse_from_rfc3339("2026-08-18T04:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(year_month(d), 202_608);
    }

    #[test]
    fn an_absurd_budget_cannot_wrap_the_counter() {
        let t = SpendTracker::new();
        let key = k();
        t.record(key, Some(f64::MAX));
        assert_eq!(
            t.check(key, Some(f64::INFINITY)),
            BudgetDecision::Allow,
            "a non-finite budget is treated as no budget, not as zero"
        );
    }
}
