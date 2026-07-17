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
// burn = error_fraction / (1 - 0.999) = error_fraction / 0.001.
const BURN_RATE_SQL: &str = "SELECT if(count() = 0, 0.0, \
    (countIf(status_code = 2) / count()) / 0.001) \
    FROM tracelane.spans \
    WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != '' \
    AND start_time >= now() - toIntervalMinute(?)";
const LATENCY_P95_SQL: &str = "SELECT if(count() = 0, 0.0, \
    quantile(0.95)(duration_us) / 1000.0) \
    FROM tracelane.spans \
    WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != '' \
    AND start_time >= now() - toIntervalMinute(?)";
const COST_SQL: &str = "SELECT sum(if(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) \
    AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0, \
    JSONExtractFloat(attributes, 'gen_ai_usage_cost'), 0.0)) \
    FROM tracelane.spans \
    WHERE tenant_id = ? AND start_time >= now() - toIntervalMinute(?)";
// quota_pct: traces month-to-date (the rule's window is ignored — quota is monthly).
const QUOTA_USED_SQL: &str = "SELECT toFloat64(count()) FROM tracelane.trace_summaries \
    WHERE tenant_id = ? AND start_time >= toStartOfMonth(now())";

/// Evaluates alert rules and fires notifications. Spawned once at startup;
/// requires both the control plane (Postgres, for rules) and ClickHouse (metrics).
pub struct AlertChecker {
    pool: DbPool,
    ch: clickhouse::Client,
    entitlements: Arc<EntitlementCache>,
    interval: Duration,
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

    /// One evaluation pass over all enabled rules.
    pub async fn run_once(&self) -> anyhow::Result<()> {
        let rules = super::list_enabled_rules_with_dest(&self.pool).await?;
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
            "burn_rate" => self.ch_scalar(BURN_RATE_SQL, rule).await,
            "latency_p95" => self.ch_scalar(LATENCY_P95_SQL, rule).await,
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
