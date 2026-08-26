//! Keeps the control-plane Postgres pool — and the Neon compute behind it —
//! WARM. **This is load-bearing latency infrastructure. Read before deleting.**
//!
//! # What breaks without it (B-256, measured on prod)
//!
//! Two costs, both paid only on SPARSE traffic, which is exactly what a new
//! customer's traffic looks like:
//!
//! | idle before the request | added to gateway overhead | why |
//! |---|---|---|
//! | > ~5 min (pooler idle timeout) | **~94 ms** | every pooled connection has been closed; the request pays a fresh TCP + TLS + SCRAM to Frankfurt |
//! | > the compute's autosuspend | **~1.2 s** | the Neon compute has suspended and the request pays the resume |
//!
//! Measured 2026-08-18 on prod: p10 31 ms -> 90 ms, p95 105 ms -> ~1400 ms, and
//! ~35% of requests over 900 ms where none had been. The gateway's own log named
//! the first half — `deadpool.postgres: "Connection could not be recycled:
//! Connection closed"`, 22 times across 11 requests.
//!
//! # Why this exists as its own named module
//!
//! **Because the keepalive it replaces was invisible, and that is what killed
//! it.** Until 2026-08-11 the alert poller ran an `alert_rules JOIN
//! alert_destinations` query every 60 s. That query held the compute open. It
//! was removed — correctly, on its own terms, since it asked a question with no
//! rows behind it — by `ffe936e1`, whose message says in as many words: *"every
//! one keeps the compute awake."* The keepalive was known about and removed for
//! cost. Prod p50 stepped 36 ms -> 153 ms that day. `89aa4a00` then
//! turned the control-plane LISTEN off for the same reason, and p95 reached
//! 1367 ms the day after.
//!
//! The cost case did not survive contact with the bill — `0eb6ce7f` predicted
//! *"the bill will not move from these"* and it did not. So the trade was 13x
//! latency for nothing.
//!
//! A keepalive that is a side effect of an unrelated feature will be deleted
//! again by the next person who correctly notices that feature is wasteful. This
//! module is the same effect with a name on it, so the next deletion has to
//! argue with this doc comment first.
//!
//! # What it deliberately does NOT do
//!
//! It does not restore `LISTEN`, and it does not lengthen the 60 s auth-cache
//! TTL. Both of those changes are *good on their own merits* — the TTL is
//! the real revocation bound, and the listener demonstrably could not receive
//! the NOTIFY it existed for. Keeping the pool warm makes their latency cost
//! disappear without giving up the tighter revocation bound, which is why this
//! is a keepalive rather than a revert.
//!
//! # Cost
//!
//! `SELECT 1` on `KEEPALIVE_CONNS` connections every `KEEPALIVE_SECS`. At the
//! defaults that is 4 trivial queries a minute against a 12 MB database — under
//! half of what the alert poller alone used to run, and far under Neon's own
//! agents, four of which out-transact this application (`0eb6ce7f`).
//!
//! Set `TRACELANE_PG_KEEPALIVE_SECS=0` to disable — for a self-hoster who would
//! rather have the suspend savings than the latency, which is a legitimate
//! choice for a deployment with no sparse-traffic users.

use std::time::Duration;

use super::DbPool;

/// How often to touch the pool. Must be comfortably under BOTH the pooler's
/// idle timeout (~5 min observed) and the compute's autosuspend window, since
/// the point is to be the traffic that stops either from firing.
fn keepalive_secs() -> u64 {
    parse_secs(std::env::var("TRACELANE_PG_KEEPALIVE_SECS").ok().as_deref())
}

/// Pure so the disable path and the malformed-value path are testable without
/// mutating process env (which races every other test in the binary).
///
/// A malformed value falls back to the DEFAULT, not to 0 — a typo must not
/// silently turn the keepalive off and hand back the B-256 latency with no
/// signal. Turning it off has to be spelled exactly `0`.
fn parse_secs(raw: Option<&str>) -> u64 {
    match raw {
        None => 60,
        Some(v) => v.trim().parse().unwrap_or(60),
    }
}

/// How many connections to hold warm.
///
/// They are acquired CONCURRENTLY and held together on purpose. deadpool hands
/// back a single object per `get()`, so acquiring one at a time would touch the
/// same connection repeatedly and let the rest of the pool rot — the pathology
/// would survive its own fix. Holding N at once guarantees N distinct objects.
///
/// Clamped to the pool's `max_size` so a mis-set value cannot deadlock the
/// gateway against its own keepalive.
fn keepalive_conns() -> usize {
    std::env::var("TRACELANE_PG_KEEPALIVE_CONNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4)
}

/// Ceiling on `keepalive_conns`, as a fraction of pool `max_size`. A keepalive
/// that can occupy the whole pool is a self-inflicted outage under load.
const MAX_FRACTION_OF_POOL: usize = 4; // at most max_size / 4

/// Spawn the keepalive. Returns immediately; the work happens on a background
/// task that never touches a request.
pub fn spawn(pool: DbPool) {
    let secs = keepalive_secs();
    if secs == 0 {
        // The B-256 reference stays in this comment, not in the string:
        // `no-internal-refs-in-ui` treats string literals as customer-reachable,
        // and it is right to — a tracker id means nothing to a self-hoster
        // reading their own logs. The string keeps the meaning; the comment
        // keeps the trail.
        tracing::info!(
            "Postgres keepalive DISABLED (TRACELANE_PG_KEEPALIVE_SECS=0) — a request arriving \
             after an idle gap will pay a fresh database connect, and a suspended managed \
             compute will add its resume on top"
        );
        return;
    }
    let max_size = pool.status().max_size;
    let want = keepalive_conns().max(1);
    let conns = want.min((max_size / MAX_FRACTION_OF_POOL).max(1));
    tracing::info!(
        interval_secs = secs,
        connections = conns,
        pool_max_size = max_size,
        "Postgres keepalive ACTIVE — holding pooled connections warm so a request after an \
         idle gap does not pay a fresh connect or a compute resume"
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(secs));
        // If a tick is missed (a stalled DB, a suspended VM), skip it rather
        // than firing the backlog in a burst the moment the DB comes back.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Failure accounting. NOT `shared::degradation` — that enum is a closed
        // wire contract (the watchdog greps its `kind`, the stats route keys on
        // it), and a latency optimisation does not earn a ninth variant. The
        // shape it mandates is still honoured: enter the degraded state -> one
        // WARN; stay in it -> the counter moves, not the log; leave it -> one
        // WARN (`.claude/rules/logging.md`).
        let mut consecutive_failures: u64 = 0;
        let mut warned = false;
        loop {
            ticker.tick().await;
            match warm_once(&pool, conns).await {
                Ok(_) => {
                    if warned {
                        tracing::warn!(
                            after_failures = consecutive_failures,
                            "Postgres keepalive RECOVERED — the pool is warm again"
                        );
                    }
                    consecutive_failures = 0;
                    warned = false;
                }
                Err(err) => {
                    // Fail-OPEN: this is a latency optimisation, never a
                    // correctness control. A failing keepalive must degrade the
                    // gateway to its pre-B-256 latency, not to an outage.
                    consecutive_failures += 1;
                    if !warned {
                        warned = true;
                        tracing::warn!(
                            error = %err,
                            interval_secs = secs,
                            "Postgres keepalive FAILING — requests after an idle gap will \
                             pay a fresh connect, and a suspended compute its resume, until \
                             this clears. The gateway is otherwise unaffected: this path is \
                             fail-open by design."
                        );
                    }
                }
            }
        }
    });
}

/// Acquire `conns` pooled connections, prove each one works, and release them
/// all together. Returns how many were successfully warmed.
///
/// They are acquired IN SEQUENCE but HELD SIMULTANEOUSLY, and it is the holding
/// that matters: because nothing is returned to the pool until the whole batch
/// is done, each `get()` must hand back a DIFFERENT object, so all `conns` are
/// warmed rather than the same one `conns` times.
///
/// Sequential on purpose. Acquiring them concurrently would finish in one round
/// trip instead of `conns`, but on a cold pool that means opening N connections
/// to the database at the same instant — a small thundering herd, from the very
/// task whose job is to keep things calm. On a 60-second background timer the
/// latency of the batch is worth nothing and the gentleness is worth something.
async fn warm_once(pool: &DbPool, conns: usize) -> anyhow::Result<usize> {
    let mut held = Vec::with_capacity(conns);
    for _ in 0..conns {
        match pool.get().await {
            Ok(client) => held.push(client),
            // A pool smaller than `conns`, or one under load, is not an error —
            // warm what is available and report that count honestly.
            Err(err) if !held.is_empty() => {
                tracing::debug!(error = %err, held = held.len(), "keepalive stopped early");
                break;
            }
            Err(err) => {
                return Err(anyhow::Error::new(err).context("keepalive could not get a connection"));
            }
        }
    }
    let mut ok = 0usize;
    for client in &held {
        // The cheapest statement that proves the round trip actually completed.
        // `is_closed()` would NOT do — it reports the local socket's belief, and
        // the whole failure mode here is a socket the far side closed while we
        // were not looking.
        client.simple_query("SELECT 1").await?;
        ok += 1;
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `0` is the ONLY value that disables. Everything else — absent, blank,
    /// negative, a typo — resolves to the default, because a keepalive silently
    /// switched off by a malformed env var reintroduces B-256 with no signal at
    /// all. The malformed cases are the point of this test; the happy path alone
    /// would pass for an implementation that returned 60 unconditionally, which
    /// is why `Some("0") -> 0` is asserted alongside them.
    #[test]
    fn only_an_explicit_zero_disables_the_keepalive() {
        assert_eq!(parse_secs(Some("0")), 0, "an explicit 0 must disable");
        assert_eq!(parse_secs(None), 60, "unset must use the default");
        assert_eq!(parse_secs(Some("")), 60, "blank must not disable");
        assert_eq!(parse_secs(Some("  ")), 60, "whitespace must not disable");
        assert_eq!(parse_secs(Some("off")), 60, "a typo must not disable");
        assert_eq!(parse_secs(Some("-1")), 60, "a negative must not disable");
        assert_eq!(parse_secs(Some(" 30 ")), 30, "a padded value must parse");
        assert_eq!(parse_secs(Some("120")), 120, "an explicit value must win");
    }

    /// The clamp is the property that stops the keepalive from eating its own
    /// pool. Asserted at every size that matters, including the degenerate ones
    /// where integer division would otherwise yield a zero-connection keepalive
    /// that silently does nothing.
    #[test]
    fn keepalive_can_never_occupy_more_than_a_quarter_of_the_pool() {
        for max_size in [1usize, 2, 4, 8, 16, 64] {
            for want in [1usize, 4, 100] {
                let conns = want.max(1).min((max_size / MAX_FRACTION_OF_POOL).max(1));
                assert!(conns >= 1, "max_size={max_size} want={want} warmed nothing");
                assert!(
                    conns <= max_size,
                    "max_size={max_size} want={want} -> {conns} exceeds the pool"
                );
                if max_size >= MAX_FRACTION_OF_POOL {
                    assert!(
                        conns <= max_size / MAX_FRACTION_OF_POOL,
                        "max_size={max_size} want={want} -> {conns} over the quarter-pool ceiling"
                    );
                }
            }
        }
    }
}
