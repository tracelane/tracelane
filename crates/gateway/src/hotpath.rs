//! Per-stage hot-path timing — the B-256 instrument.
//!
//! # Why this exists
//!
//! The span carries ONE overhead number, `tracelane_gateway_overhead_us` =
//! `(dispatch − received) + (sent − provider_complete)`. That number is enough
//! to say the gateway got slower and structurally incapable of saying WHERE, so
//! B-256 (a 13× overhead regression, open since 2026-08-11) could be argued
//! about but not attributed. This splits the same interval into named stages.
//!
//! # Why it is not a per-request log line
//!
//! `.claude/rules/logging.md` sets the arithmetic: at 5,000 rps one 200-byte
//! line per request is ~86 GB/day, which on this single un-replicated box is an
//! outage, not a tuning problem. So this emits nothing on a healthy request.
//! Two independent bounds:
//!
//!   1. **Threshold** — a request under `TRACELANE_STAGE_TRACE_THRESHOLD_US`
//!      (default 25 ms) emits nothing at all. A gateway inside its p99 budget of
//!      15 ms is silent by construction.
//!   2. **Rate limit** — at most one line per
//!      `TRACELANE_STAGE_TRACE_INTERVAL_MS` (default 10 s) across the whole
//!      process, so a *sustained* pathology costs ≤6 lines/min rather than one
//!      per affected request. The suppressed ones are not lost: every slow
//!      request increments `slow_total`, and the line carries that counter, so
//!      the reader sees the rate even though they see one sample of it.
//!
//! That is the shape logging.md mandates — "a repeating condition gets a
//! COUNTER, not a line per occurrence" — with one worked example attached so the
//! counter is actionable rather than merely small.
//!
//! # What it covers, and what it does not
//!
//! It splits the **pre-dispatch** segment — `dispatch_ts − request_start`, which
//! is auth, entitlements, quota, both budget ceilings, detection, the audit
//! append, routing/BYOK and the request-side guardrails. That is where every
//! control-plane Postgres round trip on the hot path lives.
//!
//! It does **not** split the post-provider segment (span build + publish). The
//! response path forks into streaming and buffered closures that own their own
//! completion, and threading a timer through them is a larger change than the
//! question needs — the span's `tracelane_gateway_overhead_us` is
//! `pre + post`, so `post` is recoverable as `overhead − pre` by joining the
//! emitted line to the span on time. Stated here rather than left for a reader
//! to discover, because an instrument whose blind spot is undocumented is how a
//! partial measurement gets reported as a whole one.
//!
//! # What it deliberately does NOT do
//!
//! It does not add a span attribute. Span size is a load-bearing number in this
//! product (92.6 B/span is cited as part of the margin moat), and eight more
//! fields on every span would grow it several-fold to answer a question that is
//! only ever asked about the slow tail. If the breakdown later earns a place in
//! ClickHouse it can be added deliberately, with that cost priced in.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Stage slots. The chat hot path marks nine; the headroom means adding one
/// never silently drops another. Overflow is *recorded*, never swallowed — see
/// [`StageTimer::mark`].
const MAX_STAGES: usize = 16;

/// Requests slower than this (gateway overhead, not total) get a breakdown.
/// Default 25 ms — comfortably above the 15 ms p99 budget, so a healthy gateway
/// never emits.
fn threshold_us() -> u64 {
    std::env::var("TRACELANE_STAGE_TRACE_THRESHOLD_US")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25_000)
}

/// Minimum gap between two emitted breakdown lines, process-wide.
fn interval_ms() -> u64 {
    std::env::var("TRACELANE_STAGE_TRACE_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000)
}

/// Count of slow requests since boot. Monotonic; reported on every emitted line
/// so a suppressed burst is still visible as a rate.
static SLOW_TOTAL: AtomicU64 = AtomicU64::new(0);
/// `Instant`-derived millis of the last emitted line, for the rate limit.
static LAST_EMIT_MS: AtomicU64 = AtomicU64::new(0);

/// Monotonic process clock in ms. Uses a lazily-initialised epoch `Instant` so
/// the rate limiter never consults the wall clock (which can step backwards).
fn mono_ms() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    // `+1` so this never returns 0, which `emit_if_slow` reserves as the
    // never-emitted sentinel — otherwise a slow request in the first
    // millisecond of uptime would store the sentinel back and un-limit the next.
    // Saturates rather than wraps; a >584-million-year uptime reads as u64::MAX.
    u64::try_from(epoch.elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .saturating_add(1)
}

/// Records how long each named hot-path stage took.
///
/// Cost per `mark` is one `Instant::now()` and two array writes — no allocation,
/// no lock, no formatting. Formatting happens only on the slow path, after the
/// threshold and the rate limit have both passed.
pub struct StageTimer {
    last: Instant,
    names: [&'static str; MAX_STAGES],
    micros: [u32; MAX_STAGES],
    n: usize,
    dropped: u32,
}

impl StageTimer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            last: Instant::now(),
            names: [""; MAX_STAGES],
            micros: [0; MAX_STAGES],
            n: 0,
            dropped: 0,
        }
    }

    /// Close the stage that ended here, recording it under `name`.
    ///
    /// Beyond [`MAX_STAGES`] the mark is counted in `dropped` and the emitted
    /// line carries that count. A silently-truncated breakdown would be the
    /// worse failure: it reads as a complete accounting that sums to less than
    /// the total, which is exactly the kind of quiet wrongness this instrument
    /// exists to remove.
    pub fn mark(&mut self, name: &'static str) {
        let now = Instant::now();
        let us = u32::try_from(now.duration_since(self.last).as_micros()).unwrap_or(u32::MAX);
        self.last = now;
        if self.n < MAX_STAGES {
            self.names[self.n] = name;
            self.micros[self.n] = us;
            self.n += 1;
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// `stage=us` pairs, in the order they were marked.
    pub fn stages(&self) -> impl Iterator<Item = (&'static str, u32)> + '_ {
        (0..self.n).map(|i| (self.names[i], self.micros[i]))
    }

    /// Sum of every recorded stage. Compared against the span's own overhead
    /// number in the emitted line, so an unaccounted remainder is visible rather
    /// than assumed to be zero.
    #[must_use]
    pub fn accounted_us(&self) -> u64 {
        (0..self.n).map(|i| u64::from(self.micros[i])).sum()
    }

    /// Emit the breakdown iff `overhead_us` is over threshold AND the
    /// process-wide rate limit allows it. Returns whether a line was emitted.
    ///
    /// The counter is incremented for EVERY slow request, including suppressed
    /// ones — the rate limit governs the log line, never the measurement.
    pub fn emit_if_slow(&self, overhead_us: u64) -> bool {
        if overhead_us < threshold_us() {
            return false;
        }
        let nth = SLOW_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;

        // Claim the emission slot with a CAS, so two concurrent slow requests
        // cannot both decide they are the one allowed to log. The loop retries
        // only when another thread moved the value between the load and the
        // swap; it re-reads and re-tests rather than assuming its first read.
        let now = mono_ms();
        let interval = interval_ms();
        loop {
            let last = LAST_EMIT_MS.load(Ordering::Relaxed);
            // 0 is the never-emitted sentinel. Without it the first slow request
            // after boot is suppressed, because `mono_ms()` also starts near 0 —
            // the instrument would be deaf for exactly the interval in which a
            // boot-time pathology shows itself.
            if last != 0 && now.saturating_sub(last) < interval {
                return false;
            }
            if LAST_EMIT_MS
                .compare_exchange_weak(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        let mut breakdown = String::with_capacity(160);
        for (name, us) in self.stages() {
            if !breakdown.is_empty() {
                breakdown.push(' ');
            }
            // Milliseconds with one decimal: microsecond precision here is noise
            // against a 25 ms threshold, and the shorter string is the one a
            // human actually reads in a log tail.
            let _ = std::fmt::Write::write_fmt(
                &mut breakdown,
                format_args!("{}={:.1}ms", name, f64::from(us) / 1000.0),
            );
        }
        let accounted = self.accounted_us();
        tracing::warn!(
            target: "gateway::hotpath",
            overhead_us,
            accounted_us = accounted,
            // Overhead the stages did not claim. A large value means a mark is
            // missing, not that the gateway was idle.
            unaccounted_us = overhead_us.saturating_sub(accounted),
            slow_total = nth,
            dropped_marks = self.dropped,
            stages = %breakdown,
            "TRACELANE_SLOW_REQUEST — gateway overhead over threshold; per-stage breakdown"
        );
        true
    }
}

impl Default for StageTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_recorded_in_order_and_sum_to_accounted() {
        let mut t = StageTimer::new();
        t.mark("a");
        t.mark("b");
        t.mark("c");
        let names: Vec<&str> = t.stages().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
        assert_eq!(
            t.accounted_us(),
            t.stages().map(|(_, us)| u64::from(us)).sum::<u64>()
        );
    }

    /// The overflow case is COUNTED, not swallowed. Falsified by the assertion
    /// on `dropped`: a timer that silently ignored the extra marks would still
    /// pass the `n == MAX_STAGES` check, and that is the bug this guards.
    #[test]
    fn marks_past_capacity_are_counted_not_silently_dropped() {
        let mut t = StageTimer::new();
        for _ in 0..(MAX_STAGES + 3) {
            t.mark("x");
        }
        assert_eq!(t.stages().count(), MAX_STAGES);
        assert_eq!(t.dropped, 3, "overflow must be reported, not hidden");
    }

    /// A fast request must emit NOTHING — this is the property that keeps the
    /// instrument off the 86 GB/day path in `.claude/rules/logging.md`.
    #[test]
    fn a_request_under_threshold_never_emits() {
        let t = StageTimer::new();
        assert!(!t.emit_if_slow(0), "a 0 us request emitted a line");
        assert!(
            !t.emit_if_slow(threshold_us() - 1),
            "a request just under threshold emitted a line"
        );
    }

    /// And a slow one must emit — otherwise the test above passes for the
    /// trivial reason that nothing ever emits, which would make it vacuous.
    #[test]
    fn a_slow_request_does_emit() {
        // Sole writer of LAST_EMIT_MS in this test binary's default interval is
        // the emit path itself; reset it so ordering between tests cannot make
        // this one flaky.
        LAST_EMIT_MS.store(0, Ordering::Relaxed);
        let mut t = StageTimer::new();
        t.mark("auth");
        assert!(
            t.emit_if_slow(threshold_us() + 1),
            "a request over threshold emitted nothing"
        );
    }
}
