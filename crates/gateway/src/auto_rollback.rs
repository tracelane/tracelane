//! B1 Auto-Rollback Engine — EWMA-based per-prompt-version drift detection.
//!
//! access is gated at runtime via `workspace_entitlements`, not a
//! `cfg(feature)` flag. Fed from the production path via
//! `PromptRouter::observe_and_maybe_rollback` (POST /v1/prompts/:name/observe).
//!
//! Subsumes prior PR11 (Cost Drift Sentinel) machinery, repointed at
//! per-prompt-version granularity instead of per-tenant aggregation.
//!
//! - **Auto-rollback (objective):** cost, latency, error_rate, guardrail_fire_rate.
//!   Above 2σ EWMA drift triggers `Some(RollbackMode::Auto)` — caller flips
//!   the routing pointer back to the previous production version.
//! - **Suggest-rollback (subjective):** accuracy, hallucination_rate.
//!   Above 2σ EWMA drift triggers `Some(RollbackMode::Suggested)` — surface
//!   a dashboard panel; customer confirms before any pointer swap.
//!

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{Context as _, Result};
use clickhouse::Client as ClickhouseClient;
use tracelane_shared::TenantId;
use uuid::Uuid;

/// Metric class — drives auto vs suggest behavior on >2σ drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriggerMetric {
    // Objective — auto-rollback
    Cost,
    Latency,
    ErrorRate,
    GuardrailFire,
    // Subjective — suggest-rollback
    Accuracy,
    Hallucination,
}

impl TriggerMetric {
    /// Whether this metric authorizes automatic rollback (objective) or
    /// only a human-confirmable suggestion (subjective).
    pub fn is_objective(self) -> bool {
        matches!(
            self,
            Self::Cost | Self::Latency | Self::ErrorRate | Self::GuardrailFire
        )
    }

    /// All metric classes, in canonical order (objective first).
    pub fn all() -> [TriggerMetric; 6] {
        [
            Self::Cost,
            Self::Latency,
            Self::ErrorRate,
            Self::GuardrailFire,
            Self::Accuracy,
            Self::Hallucination,
        ]
    }
}

/// Aggregate metrics observed for a single prompt-version request.
#[derive(Debug, Clone, Default)]
pub struct PromptMetrics {
    pub cost_usd: f64,
    pub latency_ms: f64,
    pub error: bool,
    pub guardrail_fired: bool,
    /// Optional — populated by post-hoc eval pass over the response.
    pub accuracy: Option<f64>,
    /// Optional — populated by SLM-judge hallucination score.
    pub hallucination: Option<f64>,
}

impl PromptMetrics {
    /// Project metrics into the (metric, value) pairs the EWMA cells expect.
    /// Returns only metrics whose value is observable on this sample —
    /// e.g. accuracy is None when no eval ran for this request.
    fn observed(&self) -> Vec<(TriggerMetric, f64)> {
        let mut out: Vec<(TriggerMetric, f64)> = Vec::with_capacity(6);
        out.push((TriggerMetric::Cost, self.cost_usd));
        out.push((TriggerMetric::Latency, self.latency_ms));
        out.push((TriggerMetric::ErrorRate, if self.error { 1.0 } else { 0.0 }));
        out.push((
            TriggerMetric::GuardrailFire,
            if self.guardrail_fired { 1.0 } else { 0.0 },
        ));
        if let Some(a) = self.accuracy {
            out.push((TriggerMetric::Accuracy, a));
        }
        if let Some(h) = self.hallucination {
            out.push((TriggerMetric::Hallucination, h));
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackMode {
    /// Objective metric drifted; routing pointer should flip immediately.
    Auto,
    /// Subjective metric drifted; surface a dashboard suggestion.
    Suggested,
    /// Customer confirmed the suggested rollback.
    HumanConfirmed,
    /// Customer dismissed the suggestion.
    HumanDismissed,
}

/// Outcome of a rollback evaluation.
#[derive(Debug, Clone)]
pub struct RollbackDecision {
    pub rollback_id: Uuid,
    pub trigger_metric: Option<TriggerMetric>,
    pub trigger_value: f64,
    pub ewma_baseline: f64,
    pub sigma_drift: f32,
    pub mode: Option<RollbackMode>,
}

impl RollbackDecision {
    pub fn no_action() -> Self {
        Self {
            rollback_id: Uuid::nil(),
            trigger_metric: None,
            trigger_value: 0.0,
            ewma_baseline: 0.0,
            sigma_drift: 0.0,
            mode: None,
        }
    }
}

/// EWMA + variance state for a single (tenant, prompt_version, metric) cell.
#[derive(Debug, Clone, Default)]
struct EwmaState {
    mean: f64,
    variance: f64,
    samples_seen: u64,
}

impl EwmaState {
    fn observe(&mut self, sample: f64, alpha: f64) {
        self.samples_seen = self.samples_seen.saturating_add(1);
        if self.samples_seen == 1 {
            // Initialize mean to first sample so the first batch isn't biased
            // toward 0 — would otherwise inflate every subsequent z-score.
            self.mean = sample;
            self.variance = 0.0;
            return;
        }
        let prev_mean = self.mean;
        self.mean = (1.0 - alpha) * prev_mean + alpha * sample;
        let diff = sample - self.mean;
        self.variance = (1.0 - alpha) * self.variance + alpha * (diff * diff);
    }

    /// Compute the absolute z-score for `sample` against the current mean
    /// and std-dev. Returns 0 during cold start so we don't fire spurious
    /// rollbacks on the first few samples.
    fn z_score(&self, sample: f64, cold_start: u64, min_stddev: f64) -> f64 {
        if self.samples_seen < cold_start {
            return 0.0;
        }
        let stddev = self.variance.max(min_stddev * min_stddev).sqrt();
        let stddev = stddev.max(min_stddev);
        ((sample - self.mean) / stddev).abs()
    }
}

/// All metric cells for one (tenant, prompt_version) pair.
#[derive(Debug, Clone, Default)]
struct MetricStates {
    cost: EwmaState,
    latency: EwmaState,
    error_rate: EwmaState,
    guardrail_fire: EwmaState,
    accuracy: EwmaState,
    hallucination: EwmaState,
}

impl MetricStates {
    fn cell_mut(&mut self, m: TriggerMetric) -> &mut EwmaState {
        match m {
            TriggerMetric::Cost => &mut self.cost,
            TriggerMetric::Latency => &mut self.latency,
            TriggerMetric::ErrorRate => &mut self.error_rate,
            TriggerMetric::GuardrailFire => &mut self.guardrail_fire,
            TriggerMetric::Accuracy => &mut self.accuracy,
            TriggerMetric::Hallucination => &mut self.hallucination,
        }
    }

    fn cell(&self, m: TriggerMetric) -> &EwmaState {
        match m {
            TriggerMetric::Cost => &self.cost,
            TriggerMetric::Latency => &self.latency,
            TriggerMetric::ErrorRate => &self.error_rate,
            TriggerMetric::GuardrailFire => &self.guardrail_fire,
            TriggerMetric::Accuracy => &self.accuracy,
            TriggerMetric::Hallucination => &self.hallucination,
        }
    }
}

const COLD_START: u64 = 30;
const MIN_STDDEV: f64 = 1e-6;

/// Persistence hook for the rollback-events audit trail. Production
/// uses `ClickHouseRollbackPersister`; tests + dev use `NoOpRollbackPersister`.
#[async_trait::async_trait]
pub trait RollbackEventPersister: Send + Sync {
    async fn persist(
        &self,
        tenant_id: &TenantId,
        prompt_version_id: Uuid,
        decision: &RollbackDecision,
    ) -> Result<()>;
}

/// Default persister — drops events on the floor. For tests + dev runs.
pub struct NoOpRollbackPersister;

#[async_trait::async_trait]
impl RollbackEventPersister for NoOpRollbackPersister {
    async fn persist(
        &self,
        _tenant_id: &TenantId,
        _prompt_version_id: Uuid,
        _decision: &RollbackDecision,
    ) -> Result<()> {
        Ok(())
    }
}

/// ClickHouse-backed rollback-event persister — INSERTs into
/// `tracelane.rollback_events` per migration 03_prompt_promotion.sql.
pub struct ClickHouseRollbackPersister {
    client: ClickhouseClient,
}

impl ClickHouseRollbackPersister {
    pub fn new(client: ClickhouseClient) -> Self {
        Self { client }
    }
}

#[derive(Debug, serde::Serialize, clickhouse::Row)]
struct RollbackEventRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    rollback_id: ::uuid::Uuid,
    /// Resolved at persist time. Today the RollbackDecision doesn't carry
    /// prompt_id directly so we proxy it from prompt_version_id; B1
    /// follow-up plumbs the real prompt_id through the engine.
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    from_version_id: ::uuid::Uuid,
    /// Same proxy as prompt_id today — the rollback target's version is
    /// the caller's job to determine. Defaults to the same as
    /// from_version_id (no-op rollback) for the audit trail until the
    /// caller passes the real previous-version id.
    #[serde(with = "clickhouse::serde::uuid")]
    to_version_id: ::uuid::Uuid,
    trigger_metric: String,
    trigger_value: f64,
    ewma_baseline: f64,
    sigma_drift: f32,
    rollback_mode: String,
    fired_at: i64,
    confirmed_at: Option<i64>,
    confirmed_by_user_id: Option<String>,
}

#[async_trait::async_trait]
impl RollbackEventPersister for ClickHouseRollbackPersister {
    async fn persist(
        &self,
        tenant_id: &TenantId,
        prompt_version_id: Uuid,
        decision: &RollbackDecision,
    ) -> Result<()> {
        let trigger_metric = decision.trigger_metric.map(|m| match m {
            TriggerMetric::Cost => "cost",
            TriggerMetric::Latency => "latency",
            TriggerMetric::ErrorRate => "error_rate",
            TriggerMetric::GuardrailFire => "guardrail_fire",
            TriggerMetric::Accuracy => "accuracy",
            TriggerMetric::Hallucination => "hallucination",
        });
        let mode_str = match decision.mode {
            Some(RollbackMode::Auto) => "auto",
            Some(RollbackMode::Suggested) => "suggested",
            Some(RollbackMode::HumanConfirmed) => "human_confirmed",
            Some(RollbackMode::HumanDismissed) => "human_dismissed",
            None => return Ok(()), // no-action — don't persist
        };
        let row = RollbackEventRow {
            tenant_id: tenant_id.to_string(),
            rollback_id: decision.rollback_id,
            prompt_id: prompt_version_id,
            from_version_id: prompt_version_id,
            to_version_id: prompt_version_id,
            trigger_metric: trigger_metric.unwrap_or("unknown").to_string(),
            trigger_value: decision.trigger_value,
            ewma_baseline: decision.ewma_baseline,
            sigma_drift: decision.sigma_drift,
            rollback_mode: mode_str.to_string(),
            fired_at: chrono::Utc::now().timestamp_micros(),
            confirmed_at: None,
            confirmed_by_user_id: None,
        };
        let mut insert = self
            .client
            .insert("rollback_events")
            .context("clickhouse rollback_events insert init")?;
        insert
            .write(&row)
            .await
            .context("clickhouse rollback_events insert write")?;
        insert
            .end()
            .await
            .context("clickhouse rollback_events insert end")?;
        Ok(())
    }
}

/// Per-(tenant, prompt-version) EWMA aggregator + rollback dispatcher.
pub struct RollbackEngine {
    /// Effective EWMA window length in samples. PR11-locked at 100.
    window: usize,
    /// Half-life in samples. PR11-locked at 25 — alpha = 1 - 0.5^(1/25).
    half_life: f64,
    /// Sigma threshold for both auto and suggest fires. PR11-locked at 2.0.
    drift_sigma: f32,
    /// Per-(tenant, prompt-version) state map.
    states: RwLock<HashMap<(TenantId, Uuid), MetricStates>>,
    /// Audit-trail persister for fired rollback events. Defaults to
    /// `NoOpRollbackPersister`; production swaps in
    /// `ClickHouseRollbackPersister` via `with_persister(...)`.
    persister: Arc<dyn RollbackEventPersister>,
}

impl RollbackEngine {
    /// PR11-locked defaults: window 100, half-life 25, drift 2σ.
    pub fn new() -> Self {
        Self {
            window: 100,
            half_life: 25.0,
            drift_sigma: 2.0,
            states: RwLock::new(HashMap::new()),
            persister: Arc::new(NoOpRollbackPersister),
        }
    }

    /// Plug in a rollback-events persister (production:
    /// `ClickHouseRollbackPersister::new(clickhouse_client)`).
    pub fn with_persister(mut self, persister: Arc<dyn RollbackEventPersister>) -> Self {
        self.persister = persister;
        self
    }

    /// EWMA decay factor derived from half-life: alpha = 1 - 0.5^(1/half_life).
    fn alpha(&self) -> f64 {
        1.0 - 0.5f64.powf(1.0 / self.half_life)
    }

    /// Update the per-(tenant, prompt-version) EWMA state with a new sample.
    /// Hot path target: <100µs. Single write-lock acquisition for all 6
    /// metric cells.
    #[tracing::instrument(skip(self, metrics), fields(tenant_id = %tenant_id))]
    pub async fn observe(
        &self,
        tenant_id: TenantId,
        prompt_version_id: Uuid,
        metrics: &PromptMetrics,
    ) {
        let alpha = self.alpha();
        let observations = metrics.observed();
        let key = (tenant_id, prompt_version_id);
        let mut guard = match self.states.write() {
            Ok(g) => g,
            // Lock poison shouldn't happen on this code path, but if it
            // does, drift detection is a soft signal — fail open by
            // skipping the update rather than panicking.
            Err(_) => return,
        };
        let cell = guard.entry(key).or_insert_with(MetricStates::default);
        for (metric, value) in observations {
            cell.cell_mut(metric).observe(value, alpha);
        }
    }

    /// Inspect EWMA state, decide auto / suggest / no-action.
    ///
    /// Returns the **most severe** drift across all 6 metric classes for the
    /// given sample. Severity order: Auto (objective) > Suggested (subjective)
    /// > none. If multiple objective metrics drift simultaneously, the one
    /// with the highest sigma_drift wins.
    ///
    /// this function takes <1µs since the actual swap is the caller's job.
    #[tracing::instrument(skip(self, metrics), fields(tenant_id = %tenant_id))]
    pub async fn check_and_rollback(
        &self,
        tenant_id: TenantId,
        prompt_version_id: Uuid,
        metrics: &PromptMetrics,
    ) -> Result<RollbackDecision> {
        // Clone tenant_id into the key so we can also borrow it for the
        // persister call below — TenantId isn't Copy by design (the
        // opaque-wrapper invariant), so we explicitly clone.
        let key = (tenant_id.clone(), prompt_version_id);
        let drift_threshold = self.drift_sigma as f64;
        let observations = metrics.observed();

        // Compute drift while holding the read guard, then DROP the guard
        // before the persister .await — std::sync::RwLock guards across
        // await points can deadlock the tokio scheduler (clippy
        // await_holding_lock).
        let best: Option<(TriggerMetric, f64, f64, f64)> = {
            let states = match self.states.read() {
                Ok(g) => g,
                Err(_) => return Ok(RollbackDecision::no_action()),
            };
            let Some(cell) = states.get(&key) else {
                return Ok(RollbackDecision::no_action());
            };

            // Track the most-severe drift seen. Auto beats Suggested;
            // within a class, higher z-score wins.
            let mut best: Option<(TriggerMetric, f64, f64, f64)> = None;
            for (metric, value) in observations {
                let z = cell.cell(metric).z_score(value, COLD_START, MIN_STDDEV);
                if z <= drift_threshold {
                    continue;
                }
                let baseline = cell.cell(metric).mean;
                let candidate = (metric, value, baseline, z);
                best = match best {
                    None => Some(candidate),
                    Some(prev) => {
                        let prev_obj = prev.0.is_objective();
                        let new_obj = metric.is_objective();
                        // Promote objective over subjective unconditionally.
                        if new_obj && !prev_obj {
                            Some(candidate)
                        } else if !new_obj && prev_obj {
                            Some(prev)
                        } else if z > prev.3 {
                            Some(candidate)
                        } else {
                            Some(prev)
                        }
                    }
                };
            }
            best
        };

        let Some((metric, value, baseline, z)) = best else {
            return Ok(RollbackDecision::no_action());
        };

        let mode = if metric.is_objective() {
            RollbackMode::Auto
        } else {
            RollbackMode::Suggested
        };

        let decision = RollbackDecision {
            rollback_id: Uuid::new_v4(),
            trigger_metric: Some(metric),
            trigger_value: value,
            ewma_baseline: baseline,
            sigma_drift: z as f32,
            mode: Some(mode),
        };

        // Persist the event. Failure to persist DOES propagate — the
        // audit-trail is load-bearing for the EU AI Act Article 12
        // claim, so a silent persistence failure would be worse than
        // surfacing the error to the caller.
        self.persister
            .persist(&tenant_id, prompt_version_id, &decision)
            .await?;

        Ok(decision)
    }
}

impl Default for RollbackEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn tid(n: u128) -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(n))
    }

    fn pv(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn objective_classification() {
        assert!(TriggerMetric::Cost.is_objective());
        assert!(TriggerMetric::Latency.is_objective());
        assert!(TriggerMetric::ErrorRate.is_objective());
        assert!(TriggerMetric::GuardrailFire.is_objective());
        assert!(!TriggerMetric::Accuracy.is_objective());
        assert!(!TriggerMetric::Hallucination.is_objective());
    }

    #[test]
    fn engine_constructs_with_pr11_defaults() {
        let e = RollbackEngine::new();
        assert_eq!(e.window, 100);
        assert!((e.half_life - 25.0).abs() < f64::EPSILON);
        assert!((e.drift_sigma - 2.0).abs() < f32::EPSILON);
        // alpha = 1 - 0.5^(1/25) ≈ 0.0273
        let alpha = e.alpha();
        assert!(alpha > 0.025 && alpha < 0.030, "alpha = {}", alpha);
    }

    #[test]
    fn ewma_state_initializes_to_first_sample() {
        let mut s = EwmaState::default();
        s.observe(42.0, 0.0273);
        assert_eq!(s.samples_seen, 1);
        assert_eq!(s.mean, 42.0);
        assert_eq!(s.variance, 0.0);
    }

    #[test]
    fn ewma_state_converges_to_stable_input() {
        let mut s = EwmaState::default();
        for _ in 0..200 {
            s.observe(10.0, 0.0273);
        }
        assert!((s.mean - 10.0).abs() < 0.01);
        assert!(s.variance < 0.01);
    }

    #[test]
    fn cold_start_z_score_is_zero() {
        let mut s = EwmaState::default();
        for _ in 0..10 {
            s.observe(10.0, 0.0273);
        }
        // Even a wildly different sample has z=0 during cold start.
        let z = s.z_score(1000.0, COLD_START, MIN_STDDEV);
        assert_eq!(z, 0.0);
    }

    #[tokio::test]
    async fn no_state_returns_no_action() {
        let e = RollbackEngine::new();
        let decision = e
            .check_and_rollback(tid(1), pv(1), &PromptMetrics::default())
            .await
            .unwrap();
        assert!(decision.mode.is_none());
    }

    #[tokio::test]
    async fn stable_metrics_yield_no_action_after_warmup() {
        let e = RollbackEngine::new();
        let t = tid(2);
        let v = pv(2);
        // Warm with 100 stable samples.
        for _ in 0..100 {
            e.observe(
                t.clone(),
                v,
                &PromptMetrics {
                    cost_usd: 0.001,
                    latency_ms: 250.0,
                    error: false,
                    guardrail_fired: false,
                    accuracy: Some(0.9),
                    hallucination: Some(0.05),
                },
            )
            .await;
        }
        // Same sample → no drift.
        let decision = e
            .check_and_rollback(
                t.clone(),
                v,
                &PromptMetrics {
                    cost_usd: 0.001,
                    latency_ms: 250.0,
                    error: false,
                    guardrail_fired: false,
                    accuracy: Some(0.9),
                    hallucination: Some(0.05),
                },
            )
            .await
            .unwrap();
        assert!(decision.mode.is_none(), "got: {decision:?}");
    }

    #[tokio::test]
    async fn cost_spike_triggers_auto_rollback() {
        let e = RollbackEngine::new();
        let t = tid(3);
        let v = pv(3);
        // Warm with stable cost.
        for i in 0..100 {
            e.observe(
                t.clone(),
                v,
                &PromptMetrics {
                    // Tiny per-sample noise so variance > 0.
                    cost_usd: 0.001 + ((i % 5) as f64) * 1e-6,
                    latency_ms: 250.0,
                    ..Default::default()
                },
            )
            .await;
        }
        // 50× cost spike — well beyond 2σ.
        let decision = e
            .check_and_rollback(
                t.clone(),
                v,
                &PromptMetrics {
                    cost_usd: 0.05,
                    latency_ms: 250.0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(decision.mode, Some(RollbackMode::Auto));
        assert_eq!(decision.trigger_metric, Some(TriggerMetric::Cost));
        assert!(decision.sigma_drift > 2.0);
    }

    #[tokio::test]
    async fn accuracy_drop_triggers_suggest_only() {
        let e = RollbackEngine::new();
        let t = tid(4);
        let v = pv(4);
        // Warm with stable accuracy.
        for i in 0..100 {
            e.observe(
                t.clone(),
                v,
                &PromptMetrics {
                    cost_usd: 0.001,
                    latency_ms: 250.0,
                    accuracy: Some(0.92 + ((i % 5) as f64) * 1e-4),
                    hallucination: Some(0.05),
                    ..Default::default()
                },
            )
            .await;
        }
        // Accuracy plummets — subjective metric, suggest-only.
        let decision = e
            .check_and_rollback(
                t.clone(),
                v,
                &PromptMetrics {
                    cost_usd: 0.001,
                    latency_ms: 250.0,
                    accuracy: Some(0.40),
                    hallucination: Some(0.05),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(decision.mode, Some(RollbackMode::Suggested));
        assert_eq!(decision.trigger_metric, Some(TriggerMetric::Accuracy));
    }

    #[tokio::test]
    async fn objective_drift_promotes_over_subjective() {
        let e = RollbackEngine::new();
        let t = tid(5);
        let v = pv(5);
        // Warm with stable everything.
        for i in 0..100 {
            e.observe(
                t.clone(),
                v,
                &PromptMetrics {
                    cost_usd: 0.001 + ((i % 5) as f64) * 1e-6,
                    latency_ms: 250.0,
                    accuracy: Some(0.92 + ((i % 5) as f64) * 1e-4),
                    ..Default::default()
                },
            )
            .await;
        }
        // BOTH cost (objective) and accuracy (subjective) drift.
        let decision = e
            .check_and_rollback(
                t.clone(),
                v,
                &PromptMetrics {
                    cost_usd: 0.05,
                    latency_ms: 250.0,
                    accuracy: Some(0.40),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Auto wins over Suggested even though both fired.
        assert_eq!(decision.mode, Some(RollbackMode::Auto));
        assert!(matches!(
            decision.trigger_metric,
            Some(TriggerMetric::Cost | TriggerMetric::Latency)
        ));
    }

    #[tokio::test]
    async fn cross_tenant_state_is_isolated() {
        let e = RollbackEngine::new();
        let t_a = tid(10);
        let t_b = tid(11);
        let v = pv(0);
        // Warm A with high cost.
        for _ in 0..100 {
            e.observe(
                t_a.clone(),
                v,
                &PromptMetrics {
                    cost_usd: 0.5,
                    ..Default::default()
                },
            )
            .await;
        }
        // B has no state — first sample, even if huge, is no-action.
        let d = e
            .check_and_rollback(
                t_b,
                v,
                &PromptMetrics {
                    cost_usd: 9999.0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(d.mode.is_none());
    }
}
