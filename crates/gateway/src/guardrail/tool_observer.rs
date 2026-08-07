//! Observe the tool definitions that actually arrive, so they can be approved
//!
//! ## Why in-process, and why not per-request I/O
//!
//! Approving a tool requires knowing which tools a tenant uses. The gateway
//! already computes `def_hash` for every tool on every request when it builds
//! `ToolDef` (`capability.rs:297`), so **capture costs one `DashMap` entry
//! update and no I/O** — the hash is already in hand.
//!
//! Writing Postgres per request was never an option: that is the shape of
//! ceiling A in `docs/reference/SCALING_LADDER.md`. Instead this dedupes in-process and a
//! background task flushes off the hot path.
//!
//! ## The property to be honest about
//!
//! Dedupe state is **per process**. With N gateway replicas each one flushes its
//! own first sighting, so a tool is written once per replica on warmup, and a
//! restart re-writes. Those are UPSERTs on a `(tenant, tool, hash)` primary key,
//! so the effect is bounded and harmless — but `seen_count` therefore
//! **under-counts**, and it is documented as an approve-UI hint rather than a
//! metric anything depends on. It must never become a billing or quota input.
//!
//! ## Fail-open, deliberately
//!
//! Observing is a convenience; the request is the product. A full map, a dead
//! Postgres or a failed flush must never affect a response — this module has no
//! path that returns an error to a request.

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracelane_shared::TenantId;

/// Cap on distinct `(tenant, tool, hash)` triples held in memory.
///
/// Bounded so a hostile or broken client generating unique tool names cannot
/// grow the map without limit. On reaching the cap we stop tracking NEW triples
/// rather than evicting: eviction would let a flood push out the real tools a
/// tenant needs to approve, which is the outcome that actually matters.
const MAX_TRACKED: usize = 10_000;

/// Cap on a stored `tool_name`.
///
/// Found by the verifier: bounding the triple COUNT is not the same as bounding
/// MEMORY. `tool_name` is client-supplied text copied into the key, so without
/// this the buffer's footprint is `MAX_TRACKED × (whatever the client sends)`.
/// The pin endpoint already rejects names past this length, so a name longer
/// than it could never be approved anyway — recording it would only cost memory
/// for a row no one can act on. Matches `tool_pins_api::MAX_TOOL_NAME_LEN`.
const MAX_OBSERVED_NAME_LEN: usize = 256;

/// In-process observation buffer.
#[derive(Debug, Default)]
pub struct ToolObserver {
    seen: DashMap<(TenantId, String, String), i64>,
    /// Latched so a full map logs once, not once per request.
    warned_full: AtomicBool,
}

impl ToolObserver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one sighting. Hot path: a `DashMap` update, no I/O, never fails.
    pub fn observe(&self, tenant: &TenantId, tool_name: &str, def_hash: &str) {
        // Bound MEMORY, not just entry count — the name is client-supplied.
        // A name this long cannot be approved anyway (the pin endpoint rejects
        // it), so recording it would cost memory for an unusable row.
        if tool_name.len() > MAX_OBSERVED_NAME_LEN {
            return;
        }
        let key = (tenant.clone(), tool_name.to_owned(), def_hash.to_owned());
        if let Some(mut e) = self.seen.get_mut(&key) {
            *e += 1;
            return;
        }
        if self.seen.len() >= MAX_TRACKED {
            if !self.warned_full.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    cap = MAX_TRACKED,
                    "tool observation buffer full — new tool definitions will not be \
                     recorded for approval until the next flush drains it"
                );
            }
            return;
        }
        self.seen.insert(key, 1);
    }

    /// Take everything buffered, leaving the map empty.
    #[must_use]
    pub fn drain(&self) -> Vec<(TenantId, String, String, i64)> {
        let keys: Vec<_> = self.seen.iter().map(|e| e.key().clone()).collect();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some((key, count)) = self.seen.remove(&k) {
                out.push((key.0, key.1, key.2, count));
            }
        }
        // The map has drained, so a previously-full buffer may track again.
        self.warned_full.store(false, Ordering::Relaxed);
        out
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Spawn the flush loop. Returns immediately; the task runs for process life.
///
/// Fail-open: a flush error is logged and the batch is dropped. Retrying would
/// mean holding a growing buffer against a database that is already unhappy,
/// and losing observations only costs a tenant an approve suggestion.
pub fn spawn_flusher(observer: Arc<ToolObserver>, period: std::time::Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let batch = observer.drain();
            if batch.is_empty() {
                continue;
            }
            let Some(pool) = crate::db::global_pool() else {
                continue;
            };
            match crate::db::observed_tools::flush_batch(pool, &batch).await {
                Ok(n) => tracing::debug!(rows = n, "flushed observed tool definitions"),
                Err(e) => tracing::warn!(
                    error = %e,
                    dropped = batch.len(),
                    "observed-tools flush failed — batch dropped (observation is \
                     best-effort and must never affect a request)"
                ),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn t(n: u128) -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(n))
    }

    #[test]
    fn repeated_sightings_dedupe_and_count() {
        let o = ToolObserver::new();
        for _ in 0..5 {
            o.observe(&t(1), "get_weather", "aa");
        }
        assert_eq!(o.len(), 1, "one triple, not five rows");
        let d = o.drain();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].3, 5, "count accumulates in-process");
        assert!(o.is_empty(), "drain empties the buffer");
    }

    /// A CHANGED definition is a distinct observation — that is the rug-pull
    /// signal. If these collapsed, drift would be invisible in the approve list.
    #[test]
    fn a_changed_hash_is_a_separate_observation() {
        let o = ToolObserver::new();
        o.observe(&t(1), "get_weather", "aa");
        o.observe(&t(1), "get_weather", "bb");
        assert_eq!(
            o.len(),
            2,
            "same tool, two definitions → two rows to approve"
        );
    }

    /// Tenant isolation in the buffer itself.
    #[test]
    fn tenants_do_not_share_observations() {
        let o = ToolObserver::new();
        o.observe(&t(1), "tool", "aa");
        o.observe(&t(2), "tool", "aa");
        assert_eq!(o.len(), 2);
        let d = o.drain();
        let tenants: std::collections::HashSet<_> = d.iter().map(|r| r.0.clone()).collect();
        assert_eq!(tenants.len(), 2);
    }

    /// MECHANISM: the cap holds, and it stops tracking NEW triples rather than
    /// evicting existing ones — a flood must not push out the real tools a
    /// tenant needs to approve.
    #[test]
    fn buffer_is_bounded_and_does_not_evict_existing_entries() {
        let o = ToolObserver::new();
        o.observe(&t(1), "real_tool", "aa");
        for i in 0..(MAX_TRACKED + 500) {
            o.observe(&t(1), &format!("flood_{i}"), "bb");
        }
        assert!(o.len() <= MAX_TRACKED, "buffer must stay bounded");
        let d = o.drain();
        assert!(
            d.iter().any(|r| r.1 == "real_tool"),
            "the pre-existing real tool must survive a flood"
        );
    }

    /// MECHANISM (verifier caveat): bounding the entry COUNT is not bounding
    /// MEMORY. `tool_name` is client-supplied, so an over-long name is dropped
    /// rather than stored — it could never be approved anyway.
    #[test]
    fn over_long_tool_names_are_not_stored() {
        let o = ToolObserver::new();
        let huge = "x".repeat(MAX_OBSERVED_NAME_LEN + 1);
        o.observe(&t(1), &huge, "aa");
        assert_eq!(o.len(), 0, "an unapprovable name must not consume buffer");

        let at_limit = "y".repeat(MAX_OBSERVED_NAME_LEN);
        o.observe(&t(1), &at_limit, "aa");
        assert_eq!(o.len(), 1, "a name at the limit is still recorded");
    }

    /// A full buffer must still count repeat sightings of tools it already
    /// tracks — otherwise a flood silently freezes all existing counters.
    #[test]
    fn full_buffer_still_counts_known_tools() {
        let o = ToolObserver::new();
        o.observe(&t(1), "known", "aa");
        for i in 0..MAX_TRACKED {
            o.observe(&t(1), &format!("f_{i}"), "bb");
        }
        o.observe(&t(1), "known", "aa");
        let d = o.drain();
        let known = d.iter().find(|r| r.1 == "known").expect("known present");
        assert_eq!(known.3, 2, "repeat sighting counted even when full");
    }
}
