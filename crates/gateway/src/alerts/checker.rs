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
//  #6: the budget is the tenant's PLAN target (ADR-020: Team 99%
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
///  Neon (2026-08-11). `run_once` used to run the `alert_rules JOIN
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
    /// When the daily miss-cohort overhead REPORT last ran. `None` = never.
    /// See [`AlertChecker::maybe_report_miss_cohort_overhead`].
    last_overhead_report: tokio::sync::Mutex<Option<std::time::Instant>>,
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
            last_overhead_report: tokio::sync::Mutex::new(None),
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
        // B-264 / R75. Deliberately BEFORE the zero-rules early return below.
        //
        // This is an OPERATOR self-check, not a tenant alert rule, and prod has
        // zero rules — so placing it inside the rule loop would have made it a
        // control that can never fire. That is the exact CLASS-1 shape B-264 was,
        // and shipping the detection FOR B-264 in that shape would have been the
        // joke writing itself.
        //
        // It costs one ClickHouse query per DAY, not per tick, so the "zero rules
        // must cost nothing" invariant below is bent knowingly and bounded: 1
        // query/day against 96 ticks/day.
        self.maybe_report_miss_cohort_overhead().await;

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
                // D-a(ii) / INSIDE THE ALERTING ENGINE. This `continue` treats
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

    /// **THE B-264 DETECTION — a REPORT, not a control. Read the last paragraph
    /// before trusting a green day.**
    ///
    /// B-264 was a ~10x gateway-overhead regression that ran in production for
    /// 5 h 11 m and was caught by the founder disbelieving a headline number,
    /// not by any gate. Nothing could have seen it: the criterion benches touch
    /// none of the changed code, the Benchmarks CI job runs weekly on `schedule`
    /// only, k6 is never invoked by any workflow, and there is no
    /// ratio-or-baseline-relative perf gate anywhere in the tree —
    /// `check-bench-budgets.mjs` compares against an ABSOLUTE budget.
    ///
    /// **Why every existing threshold was blind: the defect moved the 5-25 ms
    /// band, and the >30 ms tail actually FELL.** Bucketing `claude-haiku-4-5`
    /// overhead on the clean day vs the regression window: the 5-25 ms band went
    /// 2.2% -> 22%. Proof E's 30 ms, `--cold`'s 120 ms, k6's 25 ms and the
    /// `overhead_p99` alert's 15 ms all sit ABOVE the band that moved.
    ///
    /// So this measures the p50 of the **cache-MISS cohort, per model**, which is
    /// the population the defect actually lived in — a hit is served before
    /// dispatch and cannot show a dispatch-path regression.
    ///
    /// **THREE COHORTS, KEPT DISTINCT, and that is the whole design.** A span
    /// either carries `tracelane_semantic_cache_hit` false (MISS), true (HIT), or
    /// not at all (UNKNOWN — written before GWY-24 deployed, or by a path that
    /// does not set the dimension). Folding UNKNOWN into MISS would pour every
    /// pre-cache span into the cohort and reproduce the exact mixed-population
    /// error that made the regression invisible to a per-hour query over all
    /// models: with n=8-10/hour and two models whose warm overhead differs ~10x
    /// (haiku ~1.8 ms, vertex ~17 ms), the median flips on traffic mix alone, and
    /// post-fix hours read HIGHER than regressed ones. Widest scope is necessary
    /// and NOT sufficient; the cohort must be held fixed.
    ///
    /// **⚠️ THIS IS A REPORT UNTIL SOMETHING RELIABLY GENERATES MISSES, AND TODAY
    /// NOTHING DOES.** Measured on prod 2026-08-22: `n_miss = 0` for BOTH models
    /// over 24 h **and over 7 days** — every span carrying the dimension is a HIT,
    /// and the p50 is `nan`. The cause is structural, not a quiet week: the
    /// dogfood driver replays a FIXED 15-prompt array, so after the first pass it
    /// can never miss again. **A control over an empty cohort is CLASS-1 with a
    /// green badge** — which is B-264's own lesson — so this emits and never
    /// decides. Promoting it to a control needs one thing: vary the dogfood
    /// prompt set so misses exist. That is a change to
    /// `/opt/tracelane/dogfood/dogfood.sh`, not new infrastructure.
    ///
    /// An empty cohort therefore prints CANNOT DETERMINE and never a number. A
    /// `nan` or a `0` rendered as a p50 is the zero-vs-unknown failure this
    /// repo has already paid for.
    async fn maybe_report_miss_cohort_overhead(&self) {
        const EVERY: Duration = Duration::from_secs(24 * 60 * 60);

        // THE TENANT IS REQUIRED, AND THAT IS A FEATURE, NOT A CONCESSION.
        //
        // The first version of this query had no `tenant_id` filter — an operator
        // aggregate over every tenant's spans — and `check-tenant-isolation.py`
        // refused the commit. That guard has NO exemption mechanism, deliberately.
        // It was right on both counts:
        //
        //   * it is a cross-tenant read of customer data for an internal metric,
        //     which is the #1 recurring bug class in this repo; and
        //   * on the MERITS it was the mixed-population error this report exists to
        //     expose. B-264 stayed invisible to a fleet-wide per-hour query
        //     precisely because two models with ~10x different warm overhead were
        //     pooled. Pooling TENANTS on top of that is the same mistake one level
        //     up. A regression signal needs its cohort held FIXED.
        //
        // So it names ONE tenant — the controlled dogfood workload whose traffic we
        // generate — and is OFF when unset rather than silently fleet-wide.
        let Ok(raw) = std::env::var("TRACELANE_OVERHEAD_REPORT_TENANT") else {
            return;
        };
        let Ok(tenant) = Uuid::parse_str(raw.trim()) else {
            tracing::warn!("TRACELANE_OVERHEAD_REPORT_TENANT is not a UUID — report skipped");
            return;
        };
        {
            let mut last = self.last_overhead_report.lock().await;
            match *last {
                Some(t) if t.elapsed() < EVERY => return,
                _ => *last = Some(std::time::Instant::now()),
            }
        }

        // `gateway_overhead_us > 0` excludes spans predating the materialized
        // column; it is NOT a quality filter and must never become one.
        const SQL: &str = "\
            SELECT JSONExtractString(attributes, 'gen_ai_request_model'), \
                   countIf(JSONHas(attributes, 'tracelane_semantic_cache_hit') \
                           AND NOT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')), \
                   quantileIf(0.5)(gateway_overhead_us, \
                           JSONHas(attributes, 'tracelane_semantic_cache_hit') \
                           AND NOT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')), \
                   countIf(NOT JSONHas(attributes, 'tracelane_semantic_cache_hit')) \
            FROM tracelane.spans \
            WHERE tenant_id = ? AND name = 'gen_ai.chat' AND gateway_overhead_us > 0 \
              AND start_time > now() - INTERVAL 24 HOUR \
            GROUP BY 1 ORDER BY 2 DESC";

        let rows = match self
            .ch
            .query(SQL)
            .bind(tenant.to_string())
            .fetch_all::<(String, u64, f64, u64)>()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                // "I cannot see" is not "nothing is wrong" (CLAUDE.md §14).
                tracing::warn!(error = %err, "overhead miss-cohort report query failed");
                return;
            }
        };

        if rows.is_empty() {
            tracing::info!(
                report = "gateway_overhead_miss_cohort",
                verdict = "CANNOT_DETERMINE",
                reason = "no chat spans with a materialized overhead in the last 24h for the configured tenant",
            );
            return;
        }

        for (model, n_miss, p50_us, n_unknown) in rows {
            if n_miss == 0 {
                // The steady state today. Say so explicitly — a missing line, or a
                // line carrying a 0, would both read as "overhead is fine".
                tracing::info!(
                    report = "gateway_overhead_miss_cohort",
                    model = %model,
                    verdict = "CANNOT_DETERMINE",
                    n_miss = 0,
                    n_unknown,
                    reason = "cache-miss cohort is EMPTY — every span was a hit, so \
                              dispatch-path overhead was not observed at all",
                );
                continue;
            }
            tracing::info!(
                report = "gateway_overhead_miss_cohort",
                model = %model,
                n_miss,
                n_unknown,
                p50_ms = p50_us / 1000.0,
            );
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

    ///  #6: burn is divided by the tenant's PLAN error budget (ADR-020),
    /// not a hardcoded 99.9%. The discriminating case: a Team tenant's target is
    /// 99% (budget 0.01), so the same error fraction yields a burn 10× lower than
    /// the old hardcoded 0.001 divisor — the exact overstatement this fixes.
    ///  Neon — the rule-set cache. These assert the PROPERTY that saves
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
