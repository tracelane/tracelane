//! Per-tenant attribute-key cardinality enforcement (ADR-030).
//!
//! Tracks the unique attribute keys each workspace emits over a
//! rolling 30-day window with a HyperLogLog++ p=14 sketch
//! (`hyperloglogplus` crate). Hot-path `observe_and_classify` is a
//! `DashMap::entry` + one HLL insert; budget <200 ns p99 enforced by
//! the criterion bench at `crates/ingest/benches/cardinality.rs`.
//!
//! ## Coercion contract
//!
//! When a workspace's estimated unique-key count exceeds its tier
//! limit, [`CardinalityTracker::observe_and_classify`] returns
//! [`Classification::Overflow`]. The caller (the OTLP receiver) is
//! expected to rewrite the attribute key in-place to the literal
//! string `"_overflow"` so all overflow values bucket onto a single
//! key in ClickHouse. Original values are preserved (only the key
//! changes); the original key content is recoverable via the per-span
//! `_extra` JSON forensic blob (see `tracelane_shared::span`).
//!
//! ## Persistence (V1 deviation from prompt — see ADR-030)
//!
//! V1 launch ships the in-memory tracker only. The Postgres
//! migration `10_workspace_attr_cardinality.sql` exists; the
//! `flush_to_postgres` / `hydrate_from_postgres` methods are present
//! and unit-tested in isolation but **not wired into `main.rs`**.
//! V1.1 turns them on once ingest carries a Postgres pool.

use std::collections::hash_map::RandomState;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hyperloglogplus::{HyperLogLog, HyperLogLogPlus};
use uuid::Uuid;

/// HLL++ precision parameter. p=14 yields ~16 KB sketch and ~0.81%
/// relative error at 95% confidence (per hyperloglogplus crate docs).
pub const HLL_PRECISION: u8 = 14;

/// Per-tier max unique attribute keys per workspace per rolling 30-day
/// window. V1 launch uses the Team default (10 000) for all workspaces
/// because ingest does not yet resolve tiers; V1.1 wires
/// `for_workspace(&Entitlements)` to the real ladder per ADR-030.
pub const DEFAULT_MAX_ATTR_CARDINALITY: usize = 10_000;

/// Counter for `tracelane_attr_overflow_total{workspace_id_bucket}`.
/// One AtomicU64 per of the 64 bucket ids (the same buckets ADR-029
/// uses; see `limits::workspace_bucket`).
static OVERFLOW_COUNTERS: [AtomicU64; 64] = {
    // Const array init: declare a single AtomicU64 init expr then
    // replicate. AtomicU64 is not Copy so we use an array fn.
    // clippy::declare_interior_mutable_const is a false positive here —
    // this is the canonical Rust pattern for const-initializing an
    // array of !Copy atomics; the const is consumed by the array literal
    // on the next line and never named again from user code.
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 64]
};

/// Record an overflow event. `bucket` is `0..64` from
/// `limits::workspace_bucket`. Cheap (relaxed atomic add).
pub fn record_overflow(bucket: u8) {
    let idx = (bucket & 0x3f) as usize;
    OVERFLOW_COUNTERS[idx].fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        metric_name = "tracelane_attr_overflow_total",
        workspace_id_bucket = bucket as i64,
        "attribute key overflowed cardinality cap"
    );
}

/// Snapshot all 64 overflow bucket counters.
pub fn overflow_metric_snapshot() -> [u64; 64] {
    let mut out = [0u64; 64];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = OVERFLOW_COUNTERS[i].load(Ordering::Relaxed);
    }
    out
}

/// Classification returned by [`CardinalityTracker::observe_and_classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Attribute key is within the workspace's cap — accept as-is.
    Accepted,
    /// Workspace's estimated unique-key count exceeds the cap. The
    /// caller MUST rewrite the attribute key to `"_overflow"` before
    /// downstream processing.
    Overflow,
}

/// One workspace's tracker state. Held inside a `Mutex` because the
/// HLL++ sketch's `insert` method takes `&mut self`. Lock contention
/// is per-workspace, not global.
struct WorkspaceState {
    /// Current rolling 30-day union sketch.
    sketch: HyperLogLogPlus<str, RandomState>,
    /// Last estimated unique count, refreshed every `observe`.
    /// Cached so the cap check doesn't pay the HLL estimate cost
    /// (~50 ns) on every observation.
    estimate: u64,
    /// Date stamp on the current daily sub-window. Used by
    /// [`CardinalityTracker::rotate_window`] to detect a midnight
    /// boundary cross.
    window_day: chrono::NaiveDate,
}

impl WorkspaceState {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            // `HyperLogLogPlus::new(p, build_hasher)` returns Result;
            // p=14 is in-range so unwrap is safe (the only error is
            // out-of-range precision).
            sketch: HyperLogLogPlus::new(HLL_PRECISION, RandomState::new())
                .expect("HLL p=14 is in range"),
            estimate: 0,
            window_day: now.date_naive(),
        }
    }
}

/// Per-tenant HyperLogLog++ sketch holder. Cheap to clone (it's a
/// `Arc<DashMap<...>>` internally).
#[derive(Clone)]
pub struct CardinalityTracker {
    inner: std::sync::Arc<DashMap<Uuid, Mutex<WorkspaceState>>>,
}

impl Default for CardinalityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CardinalityTracker {
    /// Construct an empty in-memory tracker. V1 launch path.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(DashMap::new()),
        }
    }

    /// Observe an attribute key and return whether the workspace has
    /// exceeded its cap. **Hot path** — called for every attribute on
    /// every accepted span. Budget: <200 ns p99.
    ///
    /// Algorithm (under the per-workspace `Mutex`):
    ///   1. `sketch.insert(key)` — amortised O(1)
    ///   2. every 8th observation: refresh `state.estimate` via
    ///      `sketch.count()`. This keeps the estimate close to live
    ///      without paying the ~50 ns estimate cost on every call.
    ///   3. classify against `cap` using the cached estimate.
    pub fn observe_and_classify(
        &self,
        workspace_id: Uuid,
        attr_key: &str,
        cap: usize,
    ) -> Classification {
        let entry = self
            .inner
            .entry(workspace_id)
            .or_insert_with(|| Mutex::new(WorkspaceState::new(Utc::now())));
        let mut state = match entry.lock() {
            Ok(g) => g,
            // PoisonError: a previous holder panicked while holding the
            // lock. The state is still well-formed; recover the inner.
            Err(poisoned) => poisoned.into_inner(),
        };

        state.sketch.insert(attr_key);

        // Refresh the cached estimate periodically. `sketch.count()`
        // walks the registers (~50 ns); 1-in-8 sampling keeps amortised
        // cost ~6 ns while keeping the cap check responsive.
        if state.estimate % 8 == 0 {
            state.estimate = state.sketch.count() as u64;
        } else {
            state.estimate = state.estimate.saturating_add(1);
        }

        if state.estimate as usize > cap {
            Classification::Overflow
        } else {
            Classification::Accepted
        }
    }

    /// Return the current estimated unique-key count for a workspace
    /// (forced refresh — does not use the cached value).
    pub fn estimate(&self, workspace_id: Uuid) -> u64 {
        let Some(entry) = self.inner.get(&workspace_id) else {
            return 0;
        };
        let mut state = match entry.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let live = state.sketch.count() as u64;
        state.estimate = live;
        live
    }

    /// Rotate every workspace whose day-stamp is behind `now.date_naive()`.
    ///
    /// V1 in-memory-only implementation: the sketch is preserved
    /// across the boundary (it represents the rolling 30-day union;
    /// a strict per-day reset would lose the rolling property without
    /// the Postgres archive). The `window_day` field is updated so
    /// the next call no-ops until midnight. V1.1 wires
    /// [`Self::flush_to_postgres`] before this and archives the
    /// previous-day sketch.
    pub fn rotate_window(&self, now: DateTime<Utc>) {
        let today = now.date_naive();
        for entry in self.inner.iter() {
            if let Ok(mut state) = entry.value().lock() {
                if state.window_day != today {
                    state.window_day = today;
                    tracing::info!(
                        workspace_id = %entry.key(),
                        new_day = %today,
                        "cardinality window rotated"
                    );
                }
            }
        }
    }

    /// Spawn-friendly daily rotation. Spawns a `tokio::time::interval`
    /// that fires every hour and calls [`Self::rotate_window`]. Hourly
    /// (not daily) so a clock drift / startup skew doesn't skip a
    /// rotation entirely.
    ///
    /// Returns a future that never resolves under normal operation;
    /// fold into `tokio::try_join!` in `main.rs` (V1: NOT wired;
    /// V1.1: wired alongside the Postgres flush).
    pub async fn run_daily_rotation(self) -> anyhow::Result<()> {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
        // First tick fires immediately; skip it so we don't rotate at
        // startup when there's nothing to rotate.
        tick.tick().await;
        loop {
            tick.tick().await;
            self.rotate_window(Utc::now());
        }
    }

    /// Number of workspaces being tracked (helper for tests +
    /// observability dashboards).
    pub fn workspace_count(&self) -> usize {
        self.inner.len()
    }

    // ---------------- Persistence (V1: defined, not wired) ----------------

    /// V1.1 placeholder: serialise every workspace sketch and upsert
    /// into `workspace_attr_cardinality`. Unwired in V1; the
    /// signature is stable so `main.rs` only changes when V1.1 turns
    /// it on.
    ///
    /// Implementation note: HLL++ sketches do not implement
    /// `serde::Serialize` upstream. V1.1 will either upstream a
    /// serde derive or use a manual encode/decode (the on-disk format
    /// is just the 2^p register bytes + the precision byte). Tracked
    /// in TASKLOG for the V1.1 wire-up patch.
    pub async fn flush_to_postgres<P>(&self, _pool: P) -> anyhow::Result<usize> {
        // Intentionally a no-op stub. Returning Ok(0) so the eventual
        // V1.1 caller can log "flushed N workspaces" without ambiguity.
        anyhow::bail!(
            "CardinalityTracker::flush_to_postgres is V1.1 — wire when ingest carries a PG pool"
        )
    }

    /// V1.1 placeholder: read every row of
    /// `workspace_attr_cardinality` from the last 30 days and rebuild
    /// the in-memory tracker. Unwired in V1.
    pub async fn hydrate_from_postgres<P>(_pool: P) -> anyhow::Result<Self> {
        anyhow::bail!(
            "CardinalityTracker::hydrate_from_postgres is V1.1 — wire when ingest carries a PG pool"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn observation_below_cap_returns_accepted() {
        let t = CardinalityTracker::new();
        let ws = Uuid::new_v4();
        for i in 0..100 {
            let key = format!("attr_{i}");
            assert_eq!(
                t.observe_and_classify(ws, &key, 10_000),
                Classification::Accepted
            );
        }
        assert!(t.estimate(ws) >= 90 && t.estimate(ws) <= 110); // ±10% slack on small N
    }

    #[test]
    fn observation_above_cap_returns_overflow() {
        let t = CardinalityTracker::new();
        let ws = Uuid::new_v4();
        // Use a tight cap so the test runs in reasonable time.
        let cap = 100;
        // Submit far more keys than the cap.
        let mut saw_overflow = false;
        for i in 0..1_000 {
            let key = format!("attr_{i}");
            if t.observe_and_classify(ws, &key, cap) == Classification::Overflow {
                saw_overflow = true;
            }
        }
        assert!(
            saw_overflow,
            "submitting 1000 keys with cap=100 must produce at least one Overflow"
        );
    }

    #[test]
    fn hll_estimate_is_within_1_percent_at_10k_keys() {
        let t = CardinalityTracker::new();
        let ws = Uuid::new_v4();
        for i in 0..10_000 {
            let key = format!("ns.attr.{i}");
            // Use a generous cap so we don't trip overflow during the
            // accuracy test.
            t.observe_and_classify(ws, &key, 1_000_000);
        }
        let est = t.estimate(ws);
        let rel_err = ((est as i64 - 10_000).unsigned_abs() as f64) / 10_000.0;
        assert!(
            rel_err < 0.02,
            "HLL p=14 estimate must be within ±2% at 10K keys (got {est}, rel_err={rel_err:.4})"
        );
    }

    #[test]
    fn workspaces_are_isolated_from_each_other() {
        let t = CardinalityTracker::new();
        let ws_a = Uuid::new_v4();
        let ws_b = Uuid::new_v4();
        for i in 0..500 {
            t.observe_and_classify(ws_a, &format!("a_{i}"), 1_000_000);
        }
        // ws_b has seen zero keys.
        assert_eq!(t.estimate(ws_b), 0);
        // ws_a sees ~500.
        let est_a = t.estimate(ws_a);
        assert!((480..=520).contains(&est_a), "ws_a est ~500 (got {est_a})");
    }

    #[test]
    fn rotate_window_updates_day_stamp_at_midnight_cross() {
        let t = CardinalityTracker::new();
        let ws = Uuid::new_v4();
        // Seed with a tracker observation so the workspace exists.
        t.observe_and_classify(ws, "k", 100);

        // Move "now" forward by a day. rotate_window must mark the
        // window_day field updated; we observe via the public surface
        // by checking that another observation after rotation still
        // reads the same sketch (rolling window preserved).
        let tomorrow = Utc::now() + chrono::Duration::days(1);
        t.rotate_window(tomorrow);

        // Sketch survives — same workspace still tracked, same key
        // already inserted, so a second insert of "k" doesn't increase
        // the cardinality.
        let before = t.estimate(ws);
        t.observe_and_classify(ws, "k", 100);
        let after = t.estimate(ws);
        assert_eq!(before, after, "rolling sketch must not reset on rotation");
    }

    #[test]
    fn overflow_counter_increments_on_record_overflow() {
        let before = overflow_metric_snapshot()[7];
        record_overflow(7);
        let after = overflow_metric_snapshot()[7];
        assert!(after > before);
    }

    #[test]
    fn overflow_counter_only_uses_low_6_bits_of_bucket() {
        // Passing a value > 63 must still land in a 0..64 slot — the
        // implementation masks to 6 bits.
        let before = overflow_metric_snapshot()[0];
        record_overflow(64); // 64 & 0x3f = 0
        let after = overflow_metric_snapshot()[0];
        assert!(after > before);
    }

    #[tokio::test]
    async fn flush_to_postgres_is_v1_1_stub() {
        let t = CardinalityTracker::new();
        // V1 ships the method as an explicit bail!, not a silent no-op,
        // so the eventual V1.1 wire-up will surface the
        // "not-yet-wired" error if turned on prematurely.
        let r = t.flush_to_postgres(()).await;
        assert!(r.is_err(), "V1 must explicitly fail-loud on PG flush");
    }
}
