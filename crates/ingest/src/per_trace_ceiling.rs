//! Per-trace span/byte ceiling (ADR-048 D4.3).
//!
//! The fat-agent-trace cost class is 1000× a chat trace (a ~2-span chat ≈ 417 B;
//! a 2 000-span agent trace ≈ 417 KB; a runaway loop can emit far more into a
//! single trace). A per-*tenant* quota (D4.2) bounds totals, but a single
//! pathological trace can still blow a batch — so this caps **spans and bytes
//! per trace**, applied to KEPT spans on **all** tiers, including forced-full
//! (matrix §4: the ceiling bounds pathological volume even under the Audit-SKU
//! guarantee). It is the cheap structural backstop the sampler can't provide —
//! the sampler decides keep/drop per trace; this bounds an accepted trace's size.
//!
//! Stateful like the tail sampler's sticky map: a `DashMap<trace_id, accum>`
//! bounded by [`PerTraceCeiling::prune`] (the ClickHouse writer calls it on the
//! same cadence as the sampler prune), since a streaming writer never sees an
//! explicit trace-close. Defaults are generous — a normal 2 000-span agent trace
//! passes; only true runaways (≫10 000 spans or ≫64 MiB in one trace) are
//! clipped. Env-overridable (`TRACELANE_MAX_SPANS_PER_TRACE` /
//! `TRACELANE_MAX_BYTES_PER_TRACE`).
//!
//! When a trace hits its ceiling, **further** spans of that trace are dropped
//! (the spans already written stay — this clips the tail, it does not discard
//! the trace) and `tracelane_ingest_trace_ceiling_dropped_total` is incremented.
//! This is an intentional, counted drop — distinct from the #81 *silent* drop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

/// Default max spans retained per single trace. A normal large agent trace is
/// ~2 000 spans; this is 5× headroom, so only runaway emitters are clipped.
pub const DEFAULT_MAX_SPANS_PER_TRACE: u32 = 10_000;

/// Default max total (estimated) bytes retained per single trace. 64 MiB — a
/// 2 000-span × 417 B trace is ~0.8 MiB, so this only clips pathological payload.
pub const DEFAULT_MAX_BYTES_PER_TRACE: u64 = 64 * 1024 * 1024;

/// Result of a ceiling check for one span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingDecision {
    /// Within the per-trace ceiling — keep the span.
    Accept,
    /// This trace already hit its span or byte ceiling — drop this span.
    Exceeded,
}

#[derive(Debug)]
struct TraceAccum {
    spans: u32,
    bytes: u64,
    last_seen: Instant,
}

/// Counter for `tracelane_ingest_trace_ceiling_dropped_total`.
static CEILING_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Snapshot the ceiling-drop counter (for the metrics endpoint / tests).
pub fn dropped_total() -> u64 {
    CEILING_DROPPED.load(Ordering::Relaxed)
}

/// Per-trace span + byte ceiling with a bounded sticky accumulator.
///
/// Keyed by `(tenant_id, trace_id)` (review P1-3) — correct-by-construction:
/// two tenants can never share a ceiling bucket, closing both the (astronomically
/// unlikely) cross-tenant trace_id collision and the debug-only multi-tenant OTLP
/// batch edge.
pub struct PerTraceCeiling {
    max_spans: u32,
    max_bytes: u64,
    accum: DashMap<(Uuid, Uuid), TraceAccum>,
}

impl PerTraceCeiling {
    /// Construct with explicit caps. A cap of `0` disables that dimension.
    pub fn with_limits(max_spans: u32, max_bytes: u64) -> Self {
        Self {
            max_spans,
            max_bytes,
            accum: DashMap::new(),
        }
    }

    /// Default caps (see the `DEFAULT_*` constants).
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_SPANS_PER_TRACE, DEFAULT_MAX_BYTES_PER_TRACE)
    }

    /// Account a kept span against its trace and decide whether to keep it.
    ///
    /// Returns [`CeilingDecision::Exceeded`] (and increments the drop counter)
    /// once the trace has reached either cap; otherwise records the span and
    /// returns [`CeilingDecision::Accept`]. Idempotent in spirit: an Exceeded
    /// span is not added to the totals, so the accumulator does not grow
    /// unboundedly for a runaway trace.
    pub fn check_and_record(
        &self,
        tenant_id: Uuid,
        trace_id: Uuid,
        span_bytes: u64,
    ) -> CeilingDecision {
        let now = Instant::now();
        let mut e = self
            .accum
            .entry((tenant_id, trace_id))
            .or_insert(TraceAccum {
                spans: 0,
                bytes: 0,
                last_seen: now,
            });
        e.last_seen = now;
        let span_cap_hit = self.max_spans > 0 && e.spans >= self.max_spans;
        let byte_cap_hit = self.max_bytes > 0 && e.bytes >= self.max_bytes;
        if span_cap_hit || byte_cap_hit {
            CEILING_DROPPED.fetch_add(1, Ordering::Relaxed);
            return CeilingDecision::Exceeded;
        }
        e.spans += 1;
        e.bytes = e.bytes.saturating_add(span_bytes);
        CeilingDecision::Accept
    }

    /// Evict accumulators for traces untouched for longer than `max_age`.
    /// `now` is injected so the cadence is testable without the wall clock.
    pub fn prune_at(&self, now: Instant, max_age: Duration) {
        self.accum
            .retain(|_, a| now.saturating_duration_since(a.last_seen) < max_age);
    }

    /// Convenience over [`prune_at`](Self::prune_at) using the current clock.
    pub fn prune(&self, max_age: Duration) {
        self.prune_at(Instant::now(), max_age);
    }
}

impl Default for PerTraceCeiling {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEN: Uuid = Uuid::from_u128(0x7E); // a fixed tenant for the single-tenant cases

    #[test]
    fn accepts_up_to_the_span_cap_then_drops() {
        let c = PerTraceCeiling::with_limits(3, 0); // span cap 3, bytes disabled
        let t = Uuid::from_u128(1);
        assert_eq!(c.check_and_record(TEN, t, 10), CeilingDecision::Accept);
        assert_eq!(c.check_and_record(TEN, t, 10), CeilingDecision::Accept);
        assert_eq!(c.check_and_record(TEN, t, 10), CeilingDecision::Accept);
        // 4th span of the same trace is over the cap.
        assert_eq!(c.check_and_record(TEN, t, 10), CeilingDecision::Exceeded);
        // A different trace is unaffected.
        assert_eq!(
            c.check_and_record(TEN, Uuid::from_u128(2), 10),
            CeilingDecision::Accept
        );
    }

    #[test]
    fn same_trace_id_different_tenants_do_not_collide() {
        // P1-3: the bucket is keyed by (tenant, trace) — tenant A hitting its cap
        // must not clip tenant B's identically-numbered trace.
        let c = PerTraceCeiling::with_limits(1, 0);
        let a = Uuid::from_u128(0xA);
        let b = Uuid::from_u128(0xB);
        let trace = Uuid::from_u128(0x5A);
        assert_eq!(c.check_and_record(a, trace, 1), CeilingDecision::Accept);
        assert_eq!(c.check_and_record(a, trace, 1), CeilingDecision::Exceeded); // A capped
        // B's same-id trace is a separate bucket — still accepts.
        assert_eq!(c.check_and_record(b, trace, 1), CeilingDecision::Accept);
    }

    #[test]
    fn byte_cap_clips_a_fat_trace() {
        let c = PerTraceCeiling::with_limits(0, 100); // bytes cap 100, spans disabled
        let t = Uuid::from_u128(3);
        assert_eq!(c.check_and_record(TEN, t, 60), CeilingDecision::Accept); // total 60
        assert_eq!(c.check_and_record(TEN, t, 60), CeilingDecision::Accept); // total 120 (recorded; next check sees >=cap)
        assert_eq!(c.check_and_record(TEN, t, 1), CeilingDecision::Exceeded); // 120 >= 100
    }

    #[test]
    fn exceeded_span_does_not_grow_the_accumulator() {
        let c = PerTraceCeiling::with_limits(1, 0);
        let t = Uuid::from_u128(4);
        assert_eq!(c.check_and_record(TEN, t, 5), CeilingDecision::Accept);
        // Many over-cap spans: all Exceeded, none added to totals (no unbounded growth).
        for _ in 0..1000 {
            assert_eq!(c.check_and_record(TEN, t, 5), CeilingDecision::Exceeded);
        }
    }

    #[test]
    fn drop_counter_increments_on_exceeded() {
        let c = PerTraceCeiling::with_limits(1, 0);
        let t = Uuid::from_u128(5);
        let before = dropped_total();
        c.check_and_record(TEN, t, 1); // accept
        c.check_and_record(TEN, t, 1); // exceeded → counter++
        assert!(dropped_total() > before);
    }

    #[test]
    fn prune_evicts_only_stale_traces() {
        let c = PerTraceCeiling::with_limits(10, 0);
        let t = Uuid::from_u128(6);
        let key = (TEN, t);
        let t0 = Instant::now();
        c.check_and_record(TEN, t, 1);
        assert!(c.accum.contains_key(&key));
        c.prune_at(t0 + Duration::from_secs(60), Duration::from_secs(600));
        assert!(c.accum.contains_key(&key), "fresh trace survives prune");
        c.prune_at(t0 + Duration::from_secs(660), Duration::from_secs(600));
        assert!(!c.accum.contains_key(&key), "stale trace is pruned");
    }

    #[test]
    fn zero_caps_disable_the_ceiling() {
        let c = PerTraceCeiling::with_limits(0, 0);
        let t = Uuid::from_u128(7);
        for _ in 0..100_000 {
            assert_eq!(
                c.check_and_record(TEN, t, 1_000_000),
                CeilingDecision::Accept
            );
        }
    }
}
