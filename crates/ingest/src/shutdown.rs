//! B-377 (2026-09-12): graceful shutdown for ingest.
//!
//! Before this, ingest had no signal handler at all: `docker stop` sent SIGTERM,
//! nothing caught it, and after Docker's 10 s grace the process was SIGKILLed —
//! with the ClickHouse writer's current batch un-flushed and un-acked. JetStream
//! redelivers un-acked spans, so that path lost nothing *durably*; what it lost
//! was every OTLP span already answered 200 and sitting in the 65,536-deep
//! channel, which has no ack to redeliver from.
//!
//! The sequence on SIGTERM is deliberately ordered so the writer runs LAST:
//!
//! 1. the OTLP receivers stop accepting and finish in-flight requests, then
//!    return — dropping their `span_tx`;
//! 2. the NATS consumer stops pulling and returns — dropping its `span_tx`;
//! 3. `main.rs` has already dropped the original `span_tx` (it was never
//!    dropped before, which meant the channel could not close at all);
//! 4. the ClickHouse writer sees `recv() == None`, flushes what it holds, acks,
//!    and returns — its channel-closed arm predates this change and was correct;
//! 5. the arms that only loop (metrics, disk refresher, config refresher) are
//!    raced against the signal in `main.rs` and return `Ok` when it fires.
//!
//! `try_join!` then resolves `Ok(())` and the process exits under its own power.

use std::time::Duration;

/// How long any single drain step may wait. Must stay UNDER the compose
/// `stop_grace_period` (30 s) — past that Docker sends SIGKILL.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(20);

/// A cloneable "shutdown has been requested" signal.
#[derive(Clone, Debug)]
pub struct Signal {
    rx: tokio::sync::watch::Receiver<bool>,
}

impl Signal {
    /// Resolves once shutdown has been requested. Safe to await repeatedly and
    /// from many clones; resolves immediately if it already fired.
    pub async fn wait(&mut self) {
        if *self.rx.borrow() {
            return;
        }
        // `changed()` errs only when the sender is gone — treat that as shutdown
        // too, since nothing can ever flip the flag again.
        let _ = self.rx.wait_for(|fired| *fired).await;
    }

    /// `wait` as an owned, `'static` future — what `axum::serve(..)
    /// .with_graceful_shutdown` requires.
    pub async fn into_wait(mut self) {
        self.wait().await;
    }

    /// Whether shutdown has already been requested (non-blocking).
    pub fn fired(&self) -> bool {
        *self.rx.borrow()
    }
}

/// Install the SIGTERM / ctrl-c handler and hand out the signal.
///
/// The sender is kept alive by the spawned task for the life of the process.
pub fn install() -> Signal {
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let ctrl_c = async {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::warn!(error = %e, "ctrl-c handler unavailable");
                std::future::pending::<()>().await;
            }
        };
        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SIGTERM handler unavailable");
                    std::future::pending::<()>().await;
                }
            }
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            () = ctrl_c => {}
            () = terminate => {}
        }
        tracing::info!("shutdown signal received — draining ingest");
        let _ = tx.send(true);
        // Keep the sender alive so `wait_for` never sees a closed channel
        // before the flag is observed by every arm.
        std::future::pending::<()>().await;
    });
    Signal { rx }
}

/// A signal wired to a caller-held trigger — for tests, which have no SIGTERM.
#[cfg(test)]
pub fn manual() -> (tokio::sync::watch::Sender<bool>, Signal) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    (tx, Signal { rx })
}

/// Run `fut` until it completes OR shutdown fires, whichever is first. For the
/// arms that only loop forever and hold nothing that needs draining.
pub async fn until_shutdown<F>(mut signal: Signal, fut: F) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    tokio::select! {
        r = fut => r,
        () = signal.wait() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_resolves_when_the_signal_fires_and_immediately_after() {
        let (tx, mut sig) = manual();
        let mut sig2 = sig.clone();
        let waiter = tokio::spawn(async move {
            sig2.wait().await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "must block until the signal fires");
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter resolves after the signal")
            .unwrap();
        // A second wait on an already-fired signal returns at once.
        tokio::time::timeout(Duration::from_millis(50), sig.wait())
            .await
            .expect("an already-fired signal must not block");
        assert!(sig.fired());
    }

    #[tokio::test]
    async fn until_shutdown_returns_ok_when_the_signal_fires_first() {
        let (tx, sig) = manual();
        let forever = std::future::pending::<anyhow::Result<()>>();
        let task = tokio::spawn(until_shutdown(sig, forever));
        tx.send(true).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("must return once shutdown fires")
            .unwrap();
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn until_shutdown_propagates_the_future_error_when_it_fails_first() {
        let (_tx, sig) = manual();
        let failing = async { anyhow::bail!("subsystem died") };
        let r = until_shutdown(sig, failing).await;
        assert!(r.is_err(), "a real failure must still abort try_join!");
    }
}
