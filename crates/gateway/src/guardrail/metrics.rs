//! Per-rail guardrail metrics + structured tracing events (the guardrail spec
//! §4). Mirrors the existing gateway metrics pattern (atomic counters read by
//! the metrics scrape, e.g. `entitlement_cache`), extended with `{rail,…}`
//! labels via `DashMap` because §4 mandates labeled series:
//!
//! - `guardrail_evaluations_total{rail,outcome}`
//! - `guardrail_latency_micros{rail}` (histogram: count / sum / buckets)
//! - `guardrail_fail_open_total{rail,reason}`
//! - `guardrail_block_total{rail,reason_code}`
//!
//! Every block / redact / warn / fail_open also emits a structured `tracing`
//! event carrying `tenant_id`, `correlation_id`, `rail`, `reason_code` — never
//! secrets/PII (§4). The **fail-open rate** is deliberately first-class: it is
//! the honesty signal (`fail_open_total` > 0 must be visible).
//!
//! Recording is done on a `&GuardrailMetrics` instance so tests use a fresh
//! local registry; production records onto the process-global [`metrics`].

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::dispatcher::SideOutcome;
use crate::guardrail::outcome::Outcome;

/// Histogram bucket upper bounds in micros (§4). The last (implicit) bucket is
/// `+Inf`. Bounds bracket the p99 ≤ 5ms request-side budget.
const LATENCY_BUCKETS_US: [u64; 6] = [50, 100, 500, 1_000, 5_000, 25_000];

/// Per-rail latency accumulator (Prometheus histogram shape).
struct RailLatency {
    count: AtomicU64,
    sum_micros: AtomicU64,
    /// One counter per bucket bound + a final `+Inf` bucket.
    buckets: [AtomicU64; LATENCY_BUCKETS_US.len() + 1],
}

impl Default for RailLatency {
    fn default() -> Self {
        Self {
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl RailLatency {
    fn observe(&self, micros: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        let idx = LATENCY_BUCKETS_US
            .iter()
            .position(|&bound| micros <= bound)
            .unwrap_or(LATENCY_BUCKETS_US.len());
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }
}

/// Labeled guardrail counters. Cheap to construct; one process-global instance
/// lives behind [`metrics`].
#[derive(Default)]
pub struct GuardrailMetrics {
    evaluations: DashMap<(&'static str, &'static str), AtomicU64>,
    fail_open: DashMap<(&'static str, &'static str), AtomicU64>,
    block: DashMap<(&'static str, &'static str), AtomicU64>,
    latency: DashMap<&'static str, RailLatency>,
}

impl GuardrailMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one side's dispatched outcome: bump per-rail counters + the
    /// latency histogram, and emit a structured tracing event for every
    /// actionable (non-allow / non-not_applicable) outcome (§4).
    pub fn record(&self, side_outcome: &SideOutcome, ctx: &GuardrailContext<'_>) {
        for record in &side_outcome.records {
            let rail = record.rail;
            let outcome = record.outcome.outcome;
            bump(&self.evaluations, (rail, outcome.as_str()));
            self.latency
                .entry(rail)
                .or_default()
                .observe(record.latency_micros);

            let reason = record.outcome.reason_code.unwrap_or("");
            match outcome {
                Outcome::Block => {
                    bump(&self.block, (rail, reason));
                    tracing::warn!(
                        tenant_id = %ctx.tenant_id,
                        correlation_id = %ctx.correlation_id,
                        rail,
                        side = side_outcome.side.as_str(),
                        outcome = "block",
                        reason_code = reason,
                        "guardrail rail blocked the request"
                    );
                }
                Outcome::FailOpen => {
                    bump(&self.fail_open, (rail, reason));
                    tracing::warn!(
                        tenant_id = %ctx.tenant_id,
                        correlation_id = %ctx.correlation_id,
                        rail,
                        side = side_outcome.side.as_str(),
                        outcome = "fail_open",
                        reason_code = reason,
                        "tracelane.guardrail.fail_open=true — quality rail proceeded after error"
                    );
                }
                Outcome::Redact | Outcome::Warn => {
                    tracing::info!(
                        tenant_id = %ctx.tenant_id,
                        correlation_id = %ctx.correlation_id,
                        rail,
                        side = side_outcome.side.as_str(),
                        outcome = outcome.as_str(),
                        reason_code = reason,
                        "guardrail rail action"
                    );
                }
                Outcome::Allow | Outcome::NotApplicable => {}
            }
        }
    }

    // ── Snapshot accessors (tests + scrape) ─────────────────────────────────

    #[must_use]
    pub fn eval_count(&self, rail: &'static str, outcome: &'static str) -> u64 {
        load(&self.evaluations, (rail, outcome))
    }

    #[must_use]
    pub fn block_count(&self, rail: &'static str, reason_code: &'static str) -> u64 {
        load(&self.block, (rail, reason_code))
    }

    #[must_use]
    pub fn fail_open_count(&self, rail: &'static str, reason: &'static str) -> u64 {
        load(&self.fail_open, (rail, reason))
    }

    /// Total fail-opens across all rails — the headline honesty signal (§4).
    #[must_use]
    pub fn fail_open_total(&self) -> u64 {
        self.fail_open
            .iter()
            .map(|e| e.value().load(Ordering::Relaxed))
            .sum()
    }

    #[must_use]
    pub fn latency_count(&self, rail: &'static str) -> u64 {
        self.latency
            .get(rail)
            .map_or(0, |l| l.count.load(Ordering::Relaxed))
    }

    /// Render the counters in Prometheus text exposition format, ready to serve
    /// from a `/metrics` route. Eventually-consistent snapshot.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str("# TYPE guardrail_evaluations_total counter\n");
        for e in &self.evaluations {
            let (rail, outcome) = *e.key();
            out.push_str(&format!(
                "guardrail_evaluations_total{{rail=\"{rail}\",outcome=\"{outcome}\"}} {}\n",
                e.value().load(Ordering::Relaxed)
            ));
        }
        out.push_str("# TYPE guardrail_block_total counter\n");
        for e in &self.block {
            let (rail, rc) = *e.key();
            out.push_str(&format!(
                "guardrail_block_total{{rail=\"{rail}\",reason_code=\"{rc}\"}} {}\n",
                e.value().load(Ordering::Relaxed)
            ));
        }
        out.push_str("# TYPE guardrail_fail_open_total counter\n");
        for e in &self.fail_open {
            let (rail, reason) = *e.key();
            out.push_str(&format!(
                "guardrail_fail_open_total{{rail=\"{rail}\",reason=\"{reason}\"}} {}\n",
                e.value().load(Ordering::Relaxed)
            ));
        }
        out.push_str("# TYPE guardrail_latency_micros histogram\n");
        for e in &self.latency {
            let rail = *e.key();
            let lat = e.value();
            let mut cumulative = 0u64;
            for (i, bound) in LATENCY_BUCKETS_US.iter().enumerate() {
                cumulative += lat.buckets[i].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "guardrail_latency_micros_bucket{{rail=\"{rail}\",le=\"{bound}\"}} {cumulative}\n"
                ));
            }
            cumulative += lat.buckets[LATENCY_BUCKETS_US.len()].load(Ordering::Relaxed);
            out.push_str(&format!(
                "guardrail_latency_micros_bucket{{rail=\"{rail}\",le=\"+Inf\"}} {cumulative}\n"
            ));
            out.push_str(&format!(
                "guardrail_latency_micros_sum{{rail=\"{rail}\"}} {}\n",
                lat.sum_micros.load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "guardrail_latency_micros_count{{rail=\"{rail}\"}} {}\n",
                lat.count.load(Ordering::Relaxed)
            ));
        }
        out
    }
}

fn bump(map: &DashMap<(&'static str, &'static str), AtomicU64>, key: (&'static str, &'static str)) {
    map.entry(key).or_default().fetch_add(1, Ordering::Relaxed);
}

fn load(
    map: &DashMap<(&'static str, &'static str), AtomicU64>,
    key: (&'static str, &'static str),
) -> u64 {
    map.get(&key).map_or(0, |c| c.load(Ordering::Relaxed))
}

/// The process-global metrics registry. The gateway records onto this; a
/// `/metrics` route renders [`GuardrailMetrics::render_prometheus`].
#[must_use]
pub fn metrics() -> &'static GuardrailMetrics {
    static M: LazyLock<GuardrailMetrics> = LazyLock::new(GuardrailMetrics::new);
    &M
}

/// Record onto the process-global registry (production hot path).
pub fn record_side_outcome(side_outcome: &SideOutcome, ctx: &GuardrailContext<'_>) {
    metrics().record(side_outcome, ctx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::CapabilityRegistry;
    use crate::guardrail::context::SessionState;
    use crate::guardrail::dispatcher::RailRecord;
    use crate::guardrail::outcome::{Decision, RailOutcome, Side, reason_codes};
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};
    use ulid::Ulid;
    use uuid::Uuid;

    fn request() -> ChatRequest {
        ChatRequest {
            model: "claude-sonnet-4-6".to_string(),
            system: None,
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hi".to_string()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
        }
    }

    fn rec(rail: &'static str, outcome: RailOutcome, latency: u64) -> RailRecord {
        RailRecord {
            rail,
            policy_version: "t@1",
            latency_micros: latency,
            outcome,
        }
    }

    /// §4 done-test: counters increment under a recorded side outcome and the
    /// fail-open rate is observable.
    #[test]
    fn counters_increment_and_fail_open_observable() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(9));
        let req = request();
        let reg = CapabilityRegistry::new();
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &req,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        let so = SideOutcome {
            side: Side::Request,
            decision: Decision::Block,
            records: vec![
                rec(
                    "R4_trifecta",
                    RailOutcome::block(reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION),
                    40,
                ),
                rec(
                    "R5_format",
                    RailOutcome::fail_open(reason_codes::CONFIG_MISSING),
                    120,
                ),
                rec("R1_cost", RailOutcome::allow(), 5),
            ],
            total_latency_micros: 165,
        };

        let m = GuardrailMetrics::new();
        m.record(&so, &ctx);

        // evaluations_total{rail,outcome}
        assert_eq!(m.eval_count("R4_trifecta", "block"), 1);
        assert_eq!(m.eval_count("R5_format", "fail_open"), 1);
        assert_eq!(m.eval_count("R1_cost", "allow"), 1);
        // block_total{rail,reason_code}
        assert_eq!(
            m.block_count(
                "R4_trifecta",
                reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION
            ),
            1
        );
        // fail_open observable
        assert_eq!(
            m.fail_open_count("R5_format", reason_codes::CONFIG_MISSING),
            1
        );
        assert_eq!(m.fail_open_total(), 1);
        // latency observed per rail
        assert_eq!(m.latency_count("R4_trifecta"), 1);
        assert_eq!(m.latency_count("R5_format"), 1);

        // Recording again accumulates.
        m.record(&so, &ctx);
        assert_eq!(m.eval_count("R4_trifecta", "block"), 2);
        assert_eq!(m.fail_open_total(), 2);
    }

    #[test]
    fn prometheus_render_contains_series() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(9));
        let req = request();
        let reg = CapabilityRegistry::new();
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &req,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        let so = SideOutcome {
            side: Side::Request,
            decision: Decision::Block,
            records: vec![rec(
                "R4_trifecta",
                RailOutcome::block(reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION),
                40,
            )],
            total_latency_micros: 40,
        };
        let m = GuardrailMetrics::new();
        m.record(&so, &ctx);
        let text = m.render_prometheus();
        assert!(
            text.contains("guardrail_evaluations_total{rail=\"R4_trifecta\",outcome=\"block\"} 1")
        );
        assert!(text.contains("guardrail_block_total{rail=\"R4_trifecta\",reason_code=\"TRIFECTA_EXFIL_IN_TAINTED_SESSION\"} 1"));
        assert!(text.contains("guardrail_latency_micros_count{rail=\"R4_trifecta\"} 1"));
        // 40µs falls in the le="50" bucket → cumulative 1 there and at +Inf.
        assert!(text.contains("guardrail_latency_micros_bucket{rail=\"R4_trifecta\",le=\"50\"} 1"));
        assert!(
            text.contains("guardrail_latency_micros_bucket{rail=\"R4_trifecta\",le=\"+Inf\"} 1")
        );
    }

    #[test]
    fn allow_and_not_applicable_do_not_emit_block_or_fail_open() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(9));
        let req = request();
        let reg = CapabilityRegistry::new();
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &req,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        let so = SideOutcome {
            side: Side::Response,
            decision: Decision::Allow,
            records: vec![
                rec("R6_leak", RailOutcome::allow(), 10),
                rec("R3_pin", RailOutcome::not_applicable(), 2),
            ],
            total_latency_micros: 12,
        };
        let m = GuardrailMetrics::new();
        m.record(&so, &ctx);
        assert_eq!(m.eval_count("R6_leak", "allow"), 1);
        assert_eq!(m.eval_count("R3_pin", "not_applicable"), 1);
        assert_eq!(m.fail_open_total(), 0);
        assert_eq!(m.block_count("R6_leak", ""), 0);
    }
}
