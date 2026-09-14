//! Evicts IDLE pooled Postgres connections so the pool cannot pin the managed
//! compute awake by itself (NEON-TO-ZERO 3a, founder-directed 2026-09-03).
//!
//! # Why
//!
//! With the keepalive off (`keepalive.rs`, `TRACELANE_PG_KEEPALIVE_SECS=0`) the
//! gateway still held **2 idle pooled connections** open through Neon's pooler,
//! and the compute never suspended: `pg_postmaster_start_time()` read **14.9 h**
//! of continuous uptime on 2026-09-03 with zero users. Whether an idle pooled
//! socket counts as activity is the compute provider's rule, not ours — so we do
//! not depend on it. An idle connection is closed after `max_idle`, and a pool
//! with no connections holds nothing awake. Belt and suspenders.
//!
//! # What it costs
//!
//! The next request after an idle gap pays a fresh connect (~94 ms measured,
//! B-256). With zero users that protects nobody; with customers the keepalive
//! goes back on (`scripts/ops/growth-mode.sh on`) and this eviction becomes a
//! no-op because the keepalive touches the connections inside `max_idle`.
//!
//! # Knobs
//!
//! - `TRACELANE_PG_IDLE_EVICT_SECS` — max idle age before eviction. Default
//!   **120**. `0` disables eviction entirely.
//!
//! The sweep runs every `max_idle / 2` seconds (floor 15 s), so a connection is
//! closed between `max_idle` and `1.5 × max_idle` after its last use.

use std::time::Duration;

use super::DbPool;

const DEFAULT_MAX_IDLE_SECS: u64 = 120;

fn max_idle_secs() -> u64 {
    parse_secs(
        std::env::var("TRACELANE_PG_IDLE_EVICT_SECS")
            .ok()
            .as_deref(),
    )
}

/// Unset / empty / unparseable ⇒ the default. ONLY an explicit `0` disables.
fn parse_secs(raw: Option<&str>) -> u64 {
    match raw.map(str::trim) {
        Some("0") => 0,
        Some(v) => v.parse::<u64>().unwrap_or(DEFAULT_MAX_IDLE_SECS),
        None => DEFAULT_MAX_IDLE_SECS,
    }
}

/// The sweep cadence for a given `max_idle`: half the idle budget, never under
/// 15 s (a tighter loop buys nothing and a `retain` walks the whole pool).
const fn sweep_secs(max_idle: u64) -> u64 {
    let half = max_idle / 2;
    if half < 15 { 15 } else { half }
}

/// Spawn the eviction loop. Returns immediately; a disabled configuration spawns
/// nothing and says so ONCE (a lifecycle line, not a per-request one).
pub fn spawn(pool: DbPool) {
    let max_idle = max_idle_secs();
    if max_idle == 0 {
        tracing::info!(
            "Postgres idle-connection eviction DISABLED (TRACELANE_PG_IDLE_EVICT_SECS=0) — \
             idle pooled connections stay open indefinitely and may hold a managed compute awake"
        );
        return;
    }
    let every = sweep_secs(max_idle);
    tracing::info!(
        max_idle_secs = max_idle,
        sweep_secs = every,
        "Postgres idle-connection eviction ON — a pooled connection idle longer than \
         max_idle_secs is closed, so the pool cannot pin the compute by itself"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(every));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let limit = Duration::from_secs(max_idle);
        loop {
            ticker.tick().await;
            let result = pool.retain(|_, metrics| metrics.last_used() < limit);
            if !result.removed.is_empty() {
                // A repeating condition gets a counter-shaped line at DEBUG, never
                // a per-occurrence WARN (.claude/rules/logging.md).
                tracing::debug!(
                    evicted = result.removed.len(),
                    retained = result.retained,
                    "evicted idle Postgres connections"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_explicit_zero_disables_eviction() {
        assert_eq!(parse_secs(None), DEFAULT_MAX_IDLE_SECS);
        assert_eq!(parse_secs(Some("")), DEFAULT_MAX_IDLE_SECS);
        assert_eq!(parse_secs(Some("garbage")), DEFAULT_MAX_IDLE_SECS);
        assert_eq!(parse_secs(Some(" 45 ")), 45);
        assert_eq!(parse_secs(Some("0")), 0);
    }

    #[test]
    fn sweep_is_half_the_idle_budget_with_a_floor() {
        assert_eq!(sweep_secs(120), 60);
        assert_eq!(sweep_secs(20), 15);
        assert_eq!(sweep_secs(600), 300);
    }

    /// The property the module exists for: a connection whose last use is older
    /// than the budget is the one `retain` drops. Exercised against a real pool
    /// object so a deadpool API change (the `retain` signature, `Metrics::last_used`)
    /// fails HERE and not on the node.
    #[tokio::test]
    async fn retain_predicate_drops_only_the_stale_connection() {
        let limit = Duration::from_secs(120);
        let fresh = deadpool_postgres::Metrics::default();
        assert!(
            fresh.last_used() < limit,
            "a just-created connection is retained"
        );
        let stale = deadpool_postgres::Metrics {
            created: std::time::Instant::now() - Duration::from_secs(600),
            recycled: None,
            recycle_count: 0,
        };
        assert!(
            stale.last_used() >= limit,
            "a 10-minute-idle connection is evicted"
        );
    }
}
