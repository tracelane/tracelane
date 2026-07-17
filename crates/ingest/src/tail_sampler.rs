//! Tail-based span sampler (PP-O2).
//!
//! Keep policy, evaluated per span but **sticky per trace**:
//!   - keep if the span's status is `Error`
//!   - keep if the span carries a predictive-layer intervention
//!     (`attributes.tracelane_intervention`)
//!   - otherwise keep at the configured rate via a deterministic hash of
//!     `trace_id`, so every span of a trace shares one keep/drop verdict and
//!     the decision is stable across the (out-of-order) trace window.
//!
//! Once a trace is force-kept (error or intervention on any of its spans),
//! the verdict is remembered in a `DashMap<trace_id, Instant>` so later spans
//! of that trace are retained too — you want the whole failing trace, not just
//! the erroring span. The map is bounded by [`TailSampler::prune`], which ages
//! out traces untouched for longer than a max window (the ClickHouse writer
//! calls it periodically); [`TailSampler::forget`] drops a single trace.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

use tracelane_shared::{SpanStatusCode, TracelaneSpan};

/// Sampling decision for a single span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleDecision {
    Keep,
    Drop,
}

/// The resolved per-tenant capture policy (ADR-048 D1/D2), supplied by the
/// caller from the tenant-config cache. `Full` keeps every span; `Tail` runs the
/// sticky error/intervention + rate-sample logic. The policy is resolved
/// server-side from entitlement — a `Full` here means the tenant is entitled
/// (Business/Enterprise) or has the Audit SKU forcing it; a non-entitled tenant
/// always resolves to `Tail` (fail-safe to the cheaper policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SamplingPolicy {
    #[default]
    Tail,
    Full,
}

/// Tail sampler with sticky per-trace keep-on-error / keep-on-intervention
/// and deterministic probabilistic sampling otherwise.
pub struct TailSampler {
    /// Keep probability in `0..=100` for traces with no error/intervention.
    sample_rate_pct: u8,
    /// Trace ids force-kept (error or intervention seen), each stamped with the
    /// last time it was touched. The stamp drives [`TailSampler::prune`] so the
    /// map stays bounded in a long-running streaming writer that never sees an
    /// explicit trace-close.
    forced_keep: DashMap<Uuid, Instant>,
}

impl TailSampler {
    /// Default 10% baseline sample rate (PP-O2).
    pub fn new() -> Self {
        Self::with_rate(10)
    }

    /// Construct with an explicit baseline keep rate (clamped to `0..=100`).
    pub fn with_rate(sample_rate_pct: u8) -> Self {
        Self {
            sample_rate_pct: sample_rate_pct.min(100),
            forced_keep: DashMap::new(),
        }
    }

    /// Evaluate whether a span should be kept, under the tenant's resolved
    /// [`SamplingPolicy`] (ADR-048 D2).
    ///
    /// `Full` keeps every span unconditionally (the entitled / audit-forced
    /// path). `Tail` is the real decision: force-keep on error or predictive
    /// intervention (sticky for the whole trace), else a deterministic per-trace
    /// rate sample. Error/intervention traces are ALWAYS kept even under tail —
    /// a regression that tail-drops a flagged trace is a debugging blind spot
    /// (ADR-048 Risks).
    pub fn evaluate(&self, span: &TracelaneSpan, policy: SamplingPolicy) -> SampleDecision {
        // Full capture: keep everything, no sticky state needed.
        if policy == SamplingPolicy::Full {
            return SampleDecision::Keep;
        }
        let force_keep = span.status.code == SpanStatusCode::Error
            || span.attributes.tracelane_intervention.is_some();
        if force_keep {
            // Stamp (or refresh) the trace's last-seen time so an active trace
            // is never pruned mid-flight; a quiet trace ages out via prune().
            self.forced_keep.insert(span.trace_id, Instant::now());
            return SampleDecision::Keep;
        }
        // An earlier span in this trace may already have forced keep.
        if self.forced_keep.contains_key(&span.trace_id) {
            return SampleDecision::Keep;
        }
        if self.keep_by_rate(span.trace_id) {
            SampleDecision::Keep
        } else {
            SampleDecision::Drop
        }
    }

    /// Drop the sticky verdict for a single closed trace window (memory bound).
    pub fn forget(&self, trace_id: Uuid) {
        self.forced_keep.remove(&trace_id);
    }

    /// Evict every sticky verdict last touched more than `max_age` before `now`.
    /// Bounds `forced_keep` for a streaming writer that never gets an explicit
    /// trace-close: a trace quiet for longer than the max trace window is
    /// assumed finished. `now` is injected so the cadence is testable without
    /// the wall clock (testing.md). Uses a saturating delta, so a clock that
    /// appears to move backwards never panics.
    pub fn prune_at(&self, now: Instant, max_age: Duration) {
        self.forced_keep
            .retain(|_, last_seen| now.saturating_duration_since(*last_seen) < max_age);
    }

    /// Convenience over [`prune_at`](Self::prune_at) using the current monotonic
    /// clock. The ClickHouse writer calls this periodically.
    pub fn prune(&self, max_age: Duration) {
        self.prune_at(Instant::now(), max_age);
    }

    /// Deterministic, uniform per-trace keep decision. Stable across the
    /// whole trace window because it is a pure function of `trace_id`.
    fn keep_by_rate(&self, trace_id: Uuid) -> bool {
        if self.sample_rate_pct == 0 {
            return false;
        }
        if self.sample_rate_pct >= 100 {
            return true;
        }
        let bucket = (trace_id.as_u128() % 100) as u8;
        bucket < self.sample_rate_pct
    }
}

impl Default for TailSampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tracelane_shared::{Intervention, SpanAttributes, SpanStatus, TenantId};

    fn span(trace_id: Uuid, code: SpanStatusCode) -> TracelaneSpan {
        TracelaneSpan {
            span_id: Uuid::new_v4(),
            trace_id,
            parent_span_id: None,
            tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(1)),
            name: "op".into(),
            start_time: Utc::now(),
            end_time: None,
            attributes: SpanAttributes::default(),
            status: SpanStatus {
                code,
                message: None,
            },
        }
    }

    #[test]
    fn error_span_is_always_kept() {
        let s = TailSampler::with_rate(0); // 0% baseline — only forced keeps
        let t = Uuid::from_u128(0xE);
        assert_eq!(
            s.evaluate(&span(t, SpanStatusCode::Error), SamplingPolicy::Tail),
            SampleDecision::Keep
        );
    }

    #[test]
    fn intervention_span_is_always_kept() {
        let s = TailSampler::with_rate(0);
        let t = Uuid::from_u128(0x1);
        let mut sp = span(t, SpanStatusCode::Ok);
        sp.attributes.tracelane_intervention = Some(Intervention::Block);
        assert_eq!(s.evaluate(&sp, SamplingPolicy::Tail), SampleDecision::Keep);
    }

    #[test]
    fn keep_is_sticky_across_a_trace() {
        let s = TailSampler::with_rate(0);
        let t = Uuid::from_u128(0xABC);
        // First span errors → trace force-kept.
        assert_eq!(
            s.evaluate(&span(t, SpanStatusCode::Error), SamplingPolicy::Tail),
            SampleDecision::Keep
        );
        // A later OK span in the SAME trace is still kept (sticky).
        assert_eq!(
            s.evaluate(&span(t, SpanStatusCode::Ok), SamplingPolicy::Tail),
            SampleDecision::Keep
        );
        // A different trace with no error at 0% baseline is dropped.
        assert_eq!(
            s.evaluate(
                &span(Uuid::from_u128(0xDEF), SpanStatusCode::Ok),
                SamplingPolicy::Tail
            ),
            SampleDecision::Drop
        );
    }

    #[test]
    fn zero_rate_drops_clean_traces_full_rate_keeps_all() {
        let drop_all = TailSampler::with_rate(0);
        let keep_all = TailSampler::with_rate(100);
        let t = Uuid::from_u128(0x777);
        assert_eq!(
            drop_all.evaluate(&span(t, SpanStatusCode::Ok), SamplingPolicy::Tail),
            SampleDecision::Drop
        );
        assert_eq!(
            keep_all.evaluate(&span(t, SpanStatusCode::Ok), SamplingPolicy::Tail),
            SampleDecision::Keep
        );
    }

    #[test]
    fn rate_decision_is_deterministic_per_trace() {
        let s = TailSampler::with_rate(50);
        let t = Uuid::from_u128(0x12345);
        let first = s.evaluate(&span(t, SpanStatusCode::Ok), SamplingPolicy::Tail);
        // Same trace, repeated — identical verdict every time.
        for _ in 0..10 {
            assert_eq!(
                s.evaluate(&span(t, SpanStatusCode::Ok), SamplingPolicy::Tail),
                first
            );
        }
    }

    #[test]
    fn forget_releases_sticky_state() {
        let s = TailSampler::with_rate(0);
        let t = Uuid::from_u128(0x55);
        s.evaluate(&span(t, SpanStatusCode::Error), SamplingPolicy::Tail);
        assert!(s.forced_keep.contains_key(&t));
        s.forget(t);
        assert!(!s.forced_keep.contains_key(&t));
    }

    #[test]
    fn prune_evicts_only_stale_sticky_state() {
        let s = TailSampler::with_rate(0);
        let t = Uuid::from_u128(0x99);
        let t0 = Instant::now();
        s.evaluate(&span(t, SpanStatusCode::Error), SamplingPolicy::Tail); // stamped at ~t0
        assert!(s.forced_keep.contains_key(&t));

        // As of t0 + 1min with a 10min window, the entry is still fresh.
        s.prune_at(t0 + Duration::from_secs(60), Duration::from_secs(600));
        assert!(
            s.forced_keep.contains_key(&t),
            "a fresh sticky entry must survive prune"
        );

        // As of t0 + 11min with a 10min window, it has aged out.
        s.prune_at(t0 + Duration::from_secs(660), Duration::from_secs(600));
        assert!(
            !s.forced_keep.contains_key(&t),
            "a stale sticky entry must be pruned"
        );
    }

    #[test]
    fn full_policy_keeps_a_clean_span_that_tail_would_drop() {
        // ADR-048 D2: a Full-entitled tenant keeps every span — including a
        // clean span that the 0%-rate tail sampler would drop. This is the
        // observable difference between the two policies on the same input.
        let s = TailSampler::with_rate(0);
        let t = Uuid::from_u128(0xF0);
        assert_eq!(
            s.evaluate(&span(t, SpanStatusCode::Ok), SamplingPolicy::Tail),
            SampleDecision::Drop,
            "tail at 0% drops a clean span"
        );
        assert_eq!(
            s.evaluate(&span(t, SpanStatusCode::Ok), SamplingPolicy::Full),
            SampleDecision::Keep,
            "full keeps the same clean span"
        );
        // Full does not touch the sticky map (it needs no per-trace memory).
        assert!(!s.forced_keep.contains_key(&t));
    }
}
