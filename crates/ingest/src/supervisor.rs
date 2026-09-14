//! B-390 (2026-09-12): supervised restart for ingest subsystems that can
//! safely restart without losing data.
//!
//! Before this, `main.rs` folded every task into one `tokio::try_join!`
//! (nats consumer, ClickHouse writer, OTLP receiver, the SPIRE bundle
//! refresher, the metrics server, the disk-guard refresher). Two independent
//! defects followed from that shape:
//!
//! 1. `nats_consumer::run` returns `Ok(())` when its JetStream message stream
//!    ends (the `None => break` arm of its `select!`) — a deleted or reset
//!    consumer makes that arm finish quietly while the process stays "alive"
//!    and consumes nothing. `try_join!` then just... waits forever for the
//!    other arms, having silently stopped capturing spans. A SILENT CAPTURE
//!    OUTAGE.
//! 2. An `Err` from any of the three auxiliary arms (the SPIRE bundle
//!    refresher, the disk-guard refresher, the metrics server) aborted span
//!    ingestion via `try_join!`'s all-or-nothing semantics, even though each
//!    is documented as a fail-OPEN path in its own right (`crates/ingest/CLAUDE.md`
//!    §"metrics_server::run is the one arm that CANNOT [fail]").
//!
//! [`supervise`] fixes both: it treats an unexpected `Ok(())` (returned
//! before shutdown was requested) exactly like an `Err` — both are logged
//! ONCE (`.claude/rules/logging.md` — a state transition, not a per-request
//! event) and trigger a restart after an exponential backoff (1s → 30s cap).
//! Only an `Ok(())` returned AFTER `shutdown.fired()` is a genuine, expected
//! exit.
//!
//! # What this does NOT supervise, and why
//!
//! The ClickHouse writer and the OTLP receiver stay UNSUPERVISED and fatal —
//! wrapping them here would hide real data loss, not prevent it:
//!   - the writer holds spans that are un-acked back to JetStream (or, for
//!     OTLP-direct spans, hold a channel receiver with no redelivery at all);
//!     silently restarting it after a fatal error would ack nothing while
//!     quietly discarding what was in flight, worse than the current loud
//!     crash;
//!   - the receiver holds the listening socket; restarting it in-process on a
//!     bind/accept fatal error is strictly worse than letting the container
//!     die and restart cleanly.
//!
//! `docker run --restart unless-stopped` (`infra/prod/docker-compose.yml`) is
//! the correct supervisor for those two arms — a fresh process, a fresh bind,
//! a fresh JetStream durable-consumer session. That file is out of scope for
//! this change (do-not-touch); this module supervises everything else.
//!
//! # Restart requires a fresh future, not a fresh poll
//!
//! A `Future` is consumed by driving it to completion, so restarting a task
//! means calling a **factory** that builds a brand-new future per attempt —
//! not re-polling the one that just returned. The NATS consumer's `span_tx`
//! is the clearest example: it must be cloned INSIDE the factory (once per
//! attempt), never captured by value, so a restarted consumer can still hand
//! the (unsupervised, still-running) ClickHouse writer a live sender.

use std::future::Future;
use std::time::Duration;

use crate::shutdown::Signal;

/// Initial backoff after the first unexpected exit.
const MIN_BACKOFF: Duration = Duration::from_secs(1);
/// Backoff ceiling — doubles from [`MIN_BACKOFF`] until it hits this.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Run `make_fut()` repeatedly, restarting on every exit that is not an
/// `Ok(())` observed after `shutdown` has fired.
///
/// `make_fut` is called once per attempt; each call must return a fresh
/// future (see the module docs on why a `Future` cannot be re-driven).
///
/// # Errors
///
/// Never returns `Err` — that is the point. A supervised task's failure is
/// logged and retried, not propagated; propagating it would hand the
/// `try_join!` in `main.rs` the exact all-or-nothing behavior this module
/// exists to remove. The `anyhow::Result` return type exists only so this
/// composes with `tokio::try_join!`'s other arms.
pub async fn supervise<F, Fut>(
    name: &'static str,
    shutdown: Signal,
    mut make_fut: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut backoff = MIN_BACKOFF;
    loop {
        let result = make_fut().await;

        // Checked AFTER the future resolves, deliberately not raced against
        // it: the futures this wraps already take `shutdown` themselves (the
        // NATS consumer) or are pre-wrapped by the caller with
        // `shutdown::until_shutdown` (the three loop-only arms) — either way,
        // shutdown is why the future returned. Racing `shutdown.wait()`
        // against the inner future HERE too would risk winning that race
        // before a data-holding task (the consumer) finishes its drain,
        // which is exactly the ordering `shutdown.rs` says matters.
        if shutdown.fired() {
            return Ok(());
        }

        match result {
            Ok(()) => {
                tracing::warn!(
                    task = name,
                    backoff_secs = backoff.as_secs(),
                    "ingest task returned Ok(()) before shutdown was requested — \
                     restarting (this is the silent-capture-outage class, B-390)"
                );
            }
            Err(error) => {
                tracing::warn!(
                    task = name,
                    error = %error,
                    backoff_secs = backoff.as_secs(),
                    "ingest task failed — restarting"
                );
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A future that returns `Err` the first two times it is built, then
    /// parks forever (never resolves) on the third — modelling a task that
    /// fails twice, recovers, and then just... runs, same as a healthy
    /// long-lived consumer.
    fn err_twice_then_parks(
        attempts: Arc<AtomicUsize>,
    ) -> impl Future<Output = anyhow::Result<()>> {
        let n = attempts.fetch_add(1, Ordering::SeqCst);
        async move {
            if n < 2 {
                anyhow::bail!("attempt {n} fails on purpose")
            }
            std::future::pending::<()>().await;
            unreachable!("pending() never resolves")
        }
    }

    #[tokio::test]
    async fn restarts_twice_then_stops_on_manual_shutdown() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let (tx, shutdown) = crate::shutdown::manual();

        let a = Arc::clone(&attempts);
        let sd = shutdown.clone();
        let handle = tokio::spawn(async move {
            supervise("test_err_twice", sd.clone(), move || {
                shutdown_aware(sd.clone(), err_twice_then_parks(Arc::clone(&a)))
            })
            .await
        });

        // Give the two failing attempts + their backoff a moment, then a
        // third attempt that parks. Backoff starts at 1s, so this must wait
        // past the first restart to observe attempt 3 having started.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            attempts.load(Ordering::SeqCst) >= 1,
            "the first attempt must have run immediately"
        );

        // Signal shutdown while attempt 3 (or a retry of 1/2, backoff
        // pending) is in flight/parked; supervise must notice and return.
        tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervise must return once shutdown fires, even with a parked inner future")
            .unwrap();
        assert!(result.is_ok());
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "must have retried at least twice: {}",
            attempts.load(Ordering::SeqCst)
        );
    }

    /// Wraps `fut` so it also resolves (with whatever it would have
    /// resolved to, or `Ok(())` if it never does) once `shutdown` fires —
    /// exactly the shape every real caller in `main.rs` uses (the NATS
    /// consumer takes `shutdown` itself; the three loop-only arms are
    /// pre-wrapped with `shutdown::until_shutdown`).
    async fn shutdown_aware<Fut>(mut shutdown: Signal, fut: Fut) -> anyhow::Result<()>
    where
        Fut: Future<Output = anyhow::Result<()>>,
    {
        tokio::select! {
            r = fut => r,
            () = shutdown.wait() => Ok(()),
        }
    }

    #[tokio::test]
    async fn ok_before_shutdown_is_restarted() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let (tx, shutdown) = crate::shutdown::manual();

        let a = Arc::clone(&attempts);
        let sd = shutdown.clone();
        let handle = tokio::spawn(async move {
            supervise("test_premature_ok", sd.clone(), move || {
                let a = Arc::clone(&a);
                let sd2 = sd.clone();
                shutdown_aware(sd2, async move {
                    let n = a.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        // First attempt: return Ok(()) immediately, with
                        // shutdown NOT fired — the exact silent-capture-outage
                        // shape (nats_consumer's stream-ended arm).
                        return Ok(());
                    }
                    std::future::pending::<()>().await;
                    unreachable!()
                })
            })
            .await
        });

        // Attempt 1 returns Ok(()) immediately; supervise then sleeps
        // MIN_BACKOFF (1s) before attempt 2. Wait past that.
        tokio::time::sleep(MIN_BACKOFF + Duration::from_millis(200)).await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "a premature Ok(()) must be restarted, not treated as a clean exit"
        );

        tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervise must still return once shutdown fires")
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ok_after_shutdown_is_not_restarted() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let (tx, shutdown) = crate::shutdown::manual();
        tx.send(true).unwrap(); // shutdown already fired before supervise starts

        let a = Arc::clone(&attempts);
        let sd = shutdown.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            supervise("test_ok_after_shutdown", sd.clone(), move || {
                let a = Arc::clone(&a);
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }),
        )
        .await
        .expect("supervise must return promptly when shutdown already fired");

        assert!(result.is_ok());
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "shutdown already fired — the single Ok(()) must be accepted, not restarted"
        );
    }
}
