//! The deterministic alert-check background job (ADR-059 / ADR-037).
//!
//! Every tick it loads all enabled rules, re-gates each on `f_alerts`, evaluates
//! its metric over the ClickHouse span data for the rule's window, and fires an
//! edge-triggered notification (ok→breach) via the SSRF-guarded notifier. It
//! calls **no** LLM/agent/provider — a recovery/notification path must stay
//! deterministic (ADR-037, enforced by `scripts/ci/no-llm-in-recovery.sh`).
//!
//! Edge-triggering (fire only on the ok→breach transition, reset on recovery)
//! means an ongoing breach alerts once, not every tick — no spam, no cooldown
//! bookkeeping needed for V1.

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use super::{AlertRule, breach_message, fire_alert_async, is_breach};
use crate::db::DbPool;
use crate::entitlement_cache::{EntitlementCache, FeatureKey};

/// Per-metric ClickHouse scalar over `spans` in the rule window. `?` order:
/// tenant, window_minutes. Provider-scoped (gateway LLM spans) for rate/latency
/// so non-LLM tool spans don't skew them; cost sums every priced span.
const ERROR_RATE_SQL: &str = "SELECT if(count() = 0, 0.0, \
    100.0 * countIf(status_code = 2) / count()) \
    FROM tracelane.spans \
    WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != '' \
    AND start_time >= now() - toIntervalMinute(?)";
// burn = error_fraction / error_budget, where error_budget = 1 - SLO_target.
// Business 99.9% / Enterprise 99.95%), resolved per-tenant in Rust — NOT a
// hardcoded 0.001 (99.9%), which overstated a Team tenant's burn 10×. This SQL
// returns the raw error fraction; `burn_rate()` divides by the tenant budget.
const ERROR_FRACTION_SQL: &str = "SELECT if(count() = 0, 0.0, \
    (countIf(status_code = 2) / count())) \
    FROM tracelane.spans \
    WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != '' \
    AND start_time >= now() - toIntervalMinute(?)";
const LATENCY_P95_SQL: &str = "SELECT if(count() = 0, 0.0, \
    quantile(0.95)(duration_us) / 1000.0) \
    FROM tracelane.spans \
    WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != '' \
    AND start_time >= now() - toIntervalMinute(?)";
// Gateway-OVERHEAD p99 in ms — the time Tracelane adds, EXCLUDING the provider
// round-trip (`gateway_overhead_us`, migration 13). This is the SRE budget
// metric (< 15ms): the mechanical control that would have caught the 6s
// transcontinental-Postgres regression (an earlier latency-tax incident). `> 0` excludes error/block
// spans (no measured provider round-trip → no overhead value).
const OVERHEAD_P99_SQL: &str = "SELECT if(count() = 0, 0.0, \
    quantile(0.99)(gateway_overhead_us) / 1000.0) \
    FROM tracelane.spans \
    WHERE tenant_id = ? AND gateway_overhead_us > 0 \
    AND start_time >= now() - toIntervalMinute(?)";
const COST_SQL: &str = "SELECT sum(if(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) \
    AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0, \
    JSONExtractFloat(attributes, 'gen_ai_usage_cost'), 0.0)) \
    FROM tracelane.spans \
    WHERE tenant_id = ? AND start_time >= now() - toIntervalMinute(?)";
// quota_pct: traces month-to-date (the rule's window is ignored — quota is monthly).
// `uniqExact(trace_id)`, NOT `count()` — same defect and same reason as
// `server::TRACES_THIS_MONTH_SQL` (B-243). A split trace emits >1 partial row in
// `trace_summaries` that never collapses, so `count()` made the `quota_pct` alert
// fire EARLY on real agent traffic. Kept numerically identical to the enforcer's
// figure on purpose: an alert that disagrees with the quota it warns about is
// worse than no alert.
const QUOTA_USED_SQL: &str = "SELECT toFloat64(uniqExact(trace_id)) FROM tracelane.trace_summaries \
    WHERE tenant_id = ? AND start_time >= toStartOfMonth(now())";

/// The error-budget fraction (`1 - availability SLO target`) for a plan lookup
/// key (ADR-020 SLAs): Team 99% → 0.01, Enterprise 99.95% → 0.0005, everything
/// else (Business 99.9%, Free / Builder no-SLA, or unknown / missing) → 0.001
/// (99.9%). Pure so the mapping is unit-testable without a Postgres pool.
fn plan_key_to_error_budget(key: Option<&str>) -> f64 {
    match key {
        Some("team_v1") => 0.01,         // 99%
        Some("enterprise_v1") => 0.0005, // 99.95%
        _ => 0.001,                      // business_v1 / free / builder / none → 99.9%
    }
}

/// Evaluates alert rules and fires notifications. Spawned once at startup;
/// requires both the control plane (Postgres, for rules) and ClickHouse (metrics).
/// How long a fetched rule set is reused before Postgres is asked again.
///
/// alert_destinations` query on EVERY tick. At the 60-second default that is
/// 1,440 round trips a day to a Frankfurt compute to ask a question that, with
/// zero alert rules configured, has no rows behind it — and every one of them
/// keeps the compute awake.
///
/// Raising the tick interval was the workaround; this is the fix, and it is
/// deliberately a rule-set cache rather than a zero-rules special case, because
/// a special case stops paying the moment the first rule is created. Here the
/// Postgres query drops from once per tick to once per TTL **whether or not
/// rules exist**, and evaluation continues at full tick rate against the cached
/// set — so alert latency is unchanged.
///
/// The cost of the TTL is bounded and stated: a newly created or deleted rule
/// takes effect within this window rather than on the next tick.
const RULES_CACHE_TTL: Duration = Duration::from_secs(900);

/// One enabled rule joined to the destination it fires to.
type RuleWithDest = (AlertRule, super::AlertDestination);

/// `(fetched_at, rules)` — `None` until the first fetch.
type CachedRules = Option<(std::time::Instant, Vec<RuleWithDest>)>;

pub struct AlertChecker {
    pool: DbPool,
    ch: clickhouse::Client,
    entitlements: Arc<EntitlementCache>,
    interval: Duration,
    /// `(fetched_at, rules)`. `None` = never fetched.
    rules_cache: tokio::sync::RwLock<CachedRules>,
}

impl AlertChecker {
    pub fn new(
        pool: DbPool,
        ch: clickhouse::Client,
        entitlements: Arc<EntitlementCache>,
        interval: Duration,
    ) -> Self {
        Self {
            pool,
            ch,
            entitlements,
            interval,
            rules_cache: tokio::sync::RwLock::new(None),
        }
    }

    /// Spawn the periodic checker. Mirrors the billing flusher: discard the
    /// immediate first tick, then evaluate on every interval. Errors are logged,
    /// never fatal — a check failure must not take the gateway down.
    pub fn spawn(self: Arc<Self>) {
        let interval = self.interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // discard the immediate first tick
            loop {
                ticker.tick().await;
                if let Err(err) = self.run_once().await {
                    tracing::warn!(error = %err, "alert checker tick failed");
                }
            }
        });
    }

    /// The enabled rule set, from cache when fresh.
    ///
    /// # Errors
    /// Propagates a Postgres failure only when the cache is cold or stale — a
    /// fresh cache serves without touching the control plane at all.
    async fn cached_rules(&self) -> anyhow::Result<Vec<RuleWithDest>> {
        if let Some((fetched_at, rules)) = self.rules_cache.read().await.as_ref()
            && fetched_at.elapsed() < RULES_CACHE_TTL
        {
            return Ok(rules.clone());
        }
        let rules = super::list_enabled_rules_with_dest(&self.pool).await?;
        *self.rules_cache.write().await = Some((std::time::Instant::now(), rules.clone()));
        Ok(rules)
    }

    /// One evaluation pass over all enabled rules.
    pub async fn run_once(&self) -> anyhow::Result<()> {
        let rules = self.cached_rules().await?;
        // Zero rules is the steady state today (alerting ships dark), and it must
        // cost nothing: no ClickHouse queries, no entitlement lookups, no work.
        if rules.is_empty() {
            return Ok(());
        }
        for (rule, dest) in rules {
            // Re-gate on the entitlement so a revoked tenant stops firing.
            if !self
                .entitlements
                .check(rule.tenant_id, FeatureKey::Alerts)
                .await
            {
                continue;
            }
            let Some(value) = self.evaluate(&rule).await else {
                // "I cannot see" as "nothing to do": the rule is skipped, the customer's
                // alert silently stops evaluating, and the dashboard still shows it
                // enabled. Fail-safe is the right CHOICE — firing on an unreadable metric
                // would be worse — but it was completely uninstrumented, which is the
                // exact defect this registry exists to close. The thing that tells you
                // something is broken must not itself break quietly.
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::AlertEvalSkipped,
                );
                continue; // metric unavailable this tick → fail-safe skip
            };
            let breach = is_breach(value, &rule.comparator, rule.threshold);
            match (breach, rule.last_state.as_str()) {
                (true, "ok") => {
                    // Edge: ok → breach. Fire once, record the fire.
                    tracing::info!(
                        rule_id = %rule.id,
                        tenant_id = %rule.tenant_id,
                        metric = %rule.metric,
                        value,
                        threshold = rule.threshold,
                        "alert breach — firing notification"
                    );
                    fire_alert_async(dest.url.clone(), breach_message(&rule, value));
                    // DSH-01: also land it in the tenant's in-app inbox. This is
                    // on the ok->breach EDGE, so it is one row per breach, not one
                    // per tick — the same discipline the webhook fire already
                    // follows (.claude/rules/logging.md: transitions, not
                    // occurrences).
                    //
                    // Deliberately AFTER the webhook: the outbound alert is the
                    // load-bearing delivery and must not wait on a Postgres write.
                    // `notify` fails OPEN and logs, so a full inbox table can
                    // never suppress an alert.
                    crate::notification_routes::notify(
                        &self.pool,
                        rule.tenant_id,
                        "alert",
                        &format!("Alert fired: {}", rule.metric),
                        &breach_message(&rule, value),
                        "warning",
                        "/slo",
                    )
                    .await;
                    let _ = super::update_rule_state(&self.pool, rule.id, "breach", true).await;
                }
                (false, "breach") => {
                    // Recovery: breach → ok. Reset so the next breach re-fires.
                    let _ = super::update_rule_state(&self.pool, rule.id, "ok", false).await;
                }
                // (true, "breach") already alerted; (false, "ok") steady state.
                _ => {}
            }
        }
        Ok(())
    }

    /// Compute the rule's metric value, or `None` if the backing query fails.
    async fn evaluate(&self, rule: &AlertRule) -> Option<f64> {
        match rule.metric.as_str() {
            "error_rate" => self.ch_scalar(ERROR_RATE_SQL, rule).await,
            "burn_rate" => self.burn_rate(rule).await,
            "latency_p95" => self.ch_scalar(LATENCY_P95_SQL, rule).await,
            "overhead_p99" => self.ch_scalar(OVERHEAD_P99_SQL, rule).await,
            "cost_usd" => self.ch_scalar(COST_SQL, rule).await,
            "quota_pct" => self.quota_pct(rule.tenant_id).await,
            _ => None,
        }
    }

    /// Bind (tenant, window) and fetch a single f64. Logs + returns None on error.
    async fn ch_scalar(&self, sql: &str, rule: &AlertRule) -> Option<f64> {
        let window = rule.window_minutes.max(1) as u32;
        match self
            .ch
            .query(sql)
            .bind(rule.tenant_id.to_string())
            .bind(window)
            .fetch_one::<f64>()
            .await
        {
            Ok(v) => Some(v),
            Err(err) => {
                tracing::warn!(error = %err, metric = %rule.metric, "alert metric query failed");
                None
            }
        }
    }

    /// burn_rate = error_fraction / error_budget, where the error budget is
    /// `1 - SLO_target` for the tenant's PLAN (ADR-020). Dividing by a hardcoded
    /// 0.001 (99.9%) overstated a Team tenant's burn 10× (their target is 99%,
    /// budget 0.01). Fail-open: an unresolvable plan falls back to the 99.9%
    /// budget (the prior behavior) rather than dropping the alert.
    async fn burn_rate(&self, rule: &AlertRule) -> Option<f64> {
        let err_frac = self.ch_scalar(ERROR_FRACTION_SQL, rule).await?;
        let budget = self.slo_budget_fraction(rule.tenant_id).await;
        if budget <= 0.0 {
            return None;
        }
        Some(err_frac / budget)
    }

    /// The tenant's error-budget fraction = `1 - availability SLO target`, from
    /// the resolved plan lookup key (ADR-020 SLAs: Team 99% / Business 99.9% /
    /// Enterprise 99.95%). Free / Builder carry no SLA → the 99.9% default, which
    /// also covers a missing workspace row or a Postgres read error (fail-open).
    async fn slo_budget_fraction(&self, tenant: Uuid) -> f64 {
        let Ok(client) = self.pool.get().await else {
            return plan_key_to_error_budget(None); // pool unavailable → 99.9% default
        };
        let key: Option<String> = client
            .query_opt(
                "SELECT plan_lookup_key FROM workspace_entitlements WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .ok()
            .flatten()
            .and_then(|row| row.get(0));
        plan_key_to_error_budget(key.as_deref())
    }

    /// quota_pct = 100 × (traces month-to-date) / (monthly trace quota). The
    /// quota comes from the resolved plan/override; a missing/zero quota → None
    /// (can't compute a percentage against no limit).
    async fn quota_pct(&self, tenant: Uuid) -> Option<f64> {
        let used = match self
            .ch
            .query(QUOTA_USED_SQL)
            .bind(tenant.to_string())
            .fetch_one::<f64>()
            .await
        {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(error = %err, "quota used query failed");
                return None;
            }
        };
        let limit = self.trace_quota(tenant).await?;
        if limit <= 0.0 {
            return None;
        }
        Some(100.0 * used / limit)
    }

    /// Resolve the tenant's monthly trace quota (override → plan → free default).
    async fn trace_quota(&self, tenant: Uuid) -> Option<f64> {
        let client = self.pool.get().await.ok()?;
        // Override overlays plan; a tenant with no workspace row → free plan.
        let row = client
            .query_opt(
                "SELECT COALESCE(we.trace_quota_monthly, pe.trace_quota_monthly) \
                 FROM workspace_entitlements we \
                 JOIN plan_entitlements pe ON pe.plan_lookup_key = we.plan_lookup_key \
                 WHERE we.tenant_id = $1",
                &[&tenant],
            )
            .await
            .ok()?;
        let quota: i64 = match row {
            Some(r) => r.get(0),
            None => {
                let fallback = client
                    .query_opt(
                        "SELECT trace_quota_monthly FROM plan_entitlements \
                         WHERE plan_lookup_key = 'free_v1'",
                        &[],
                    )
                    .await
                    .ok()??;
                fallback.get(0)
            }
        };
        Some(quota as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::{RULES_CACHE_TTL, plan_key_to_error_budget};
    use std::time::Duration;

    /// not a hardcoded 99.9%. The discriminating case: a Team tenant's target is
    /// 99% (budget 0.01), so the same error fraction yields a burn 10× lower than
    /// the old hardcoded 0.001 divisor — the exact overstatement this fixes.
    /// money (Postgres is not consulted on every tick) without needing a live
    /// Neon: the cache decision is a pure function of `fetched_at` vs the TTL.
    #[test]
    fn a_fresh_cache_entry_is_reused_and_a_stale_one_is_not() {
        let fresh = std::time::Instant::now();
        assert!(
            fresh.elapsed() < RULES_CACHE_TTL,
            "a just-fetched rule set must be served from cache — that is the whole saving"
        );
        // The boundary is what matters: at TTL the query must happen again, or a
        // new rule would never take effect.
        let stale = std::time::Instant::now()
            .checked_sub(RULES_CACHE_TTL + Duration::from_secs(1))
            .expect("representable");
        assert!(
            stale.elapsed() >= RULES_CACHE_TTL,
            "past the TTL the rule set must be re-read, or a created rule never fires"
        );
    }

    /// The TTL bounds how long a new rule waits, so it must stay small enough to
    /// be an operational nuisance rather than a broken feature. Named so a future
    /// "just make it an hour" has to argue with this line.
    #[test]
    fn rules_cache_ttl_stays_within_a_defensible_window() {
        assert!(
            RULES_CACHE_TTL <= Duration::from_secs(900),
            "a newly created alert rule must start evaluating within 15 minutes"
        );
        assert!(
            RULES_CACHE_TTL >= Duration::from_secs(300),
            "below 5 minutes the per-tick Postgres saving stops being worth the code"
        );
    }

    #[test]
    fn plan_error_budget_matches_adr020_slas_and_fixes_team_10x() {
        assert_eq!(plan_key_to_error_budget(Some("team_v1")), 0.01); // 99%
        assert_eq!(plan_key_to_error_budget(Some("business_v1")), 0.001); // 99.9%
        assert_eq!(plan_key_to_error_budget(Some("enterprise_v1")), 0.0005); // 99.95%
        assert_eq!(plan_key_to_error_budget(Some("builder_v1")), 0.001); // no SLA → 99.9%
        assert_eq!(plan_key_to_error_budget(None), 0.001); // no plan → 99.9%

        // Same 2% error fraction, Team plan: correct burn 2× vs the old 20× (0.001).
        let err_frac = 0.02;
        let team_burn = err_frac / plan_key_to_error_budget(Some("team_v1"));
        let old_hardcoded_burn = err_frac / 0.001;
        assert_eq!(team_burn, 2.0);
        assert_eq!(old_hardcoded_burn, 20.0);
        assert_eq!(old_hardcoded_burn / team_burn, 10.0); // 10× overstated, now fixed
    }
}
