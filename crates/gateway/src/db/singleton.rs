//! Single-instance advisory lock — the per-process counters' assumption, ENFORCED
//! (B-386 a, 2026-09-12).
//!
//! # Why
//!
//! The rate limiter, the monthly quota, the key and workspace budgets and the
//! online-eval cap are all process-local (`crates/gateway/CLAUDE.md`). They are
//! correct on exactly ONE gateway per control plane. Nothing prevented a second
//! one: a duplicate container, a blue-green stack, a laptop pointed at prod's
//! `POSTGRES_URL` — and every cap silently became cap × instances, on the bill
//! and in the ledger, with no signal anywhere. Until B-382's shared counters
//! exist, the honest posture is to REFUSE the second instance.
//!
//! # How
//!
//! At boot, when Postgres is configured, one dedicated connection (outside the
//! pool, so pool churn cannot release it) takes
//! `pg_try_advisory_lock(hashtext('tracelane-gateway-singleton'))` — a
//! session-scoped lock Postgres releases the moment that session ends, which is
//! what makes it safe across a crash: no stale lock file, no lease to expire. If
//! the lock is held elsewhere, boot is refused with the reason, unless
//! `TRACELANE_ALLOW_MULTI_INSTANCE=1` says, in the environment, that the operator
//! accepts cap × instances.
//!
//! Held for the process lifetime. If the connection drops (Neon restarts, a
//! network blip), the lock is gone with it: the holder re-acquires in the
//! background, WARNs once per transition and notes `SingletonLockLost` while
//! unheld — a second instance that slipped in during the gap is then visible on
//! `/health.degraded`, not silent. The process does not stop itself: it is
//! serving traffic, and stopping would turn a counter drift into an outage.
//!
//! Accepted, stated (security review L-5, 2026-09-12): any role on the same
//! Postgres that can call `pg_try_advisory_lock` can hold this key and keep a
//! gateway from booting until `TRACELANE_ALLOW_MULTI_INSTANCE=1`. A credential
//! that can reach the control plane can already do worse; the lock is a guard
//! against an honest second instance, not against a hostile database session.
//!
//! Deploys: `scripts/deploy/gateway.sh` recreates the container with `compose
//! up -d`, which stops the old process (B-377's drain) BEFORE starting the new,
//! so the lock is free by the time the new process boots. Self-host without a
//! control plane: no Postgres, no lock — a single-process deployment by
//! construction (`.claude/rules/tenancy.md`).

use anyhow::{Context as _, Result};
use std::time::Duration;

/// The lock key — one per control plane, hashed server-side.
pub const LOCK_NAME: &str = "tracelane-gateway-singleton";
const RETRY: Duration = Duration::from_secs(5);

/// A held lock: dropping it ends the session and releases the lock.
pub struct SingletonLock {
    _client: tokio_postgres::Client,
    /// Resolves when the connection ends — the "lock lost" signal.
    connection: tokio::task::JoinHandle<()>,
}

/// The lock's connection config: the DIRECT endpoint (`POSTGRES_DIRECT_URL`),
/// never the pooler.
///
/// **Earned on prod, 2026-09-12, as a 2.5-minute outage.** The first cut used
/// `POSTGRES_URL`, which on prod is Neon's pgbouncer endpoint (transaction
/// pooling). A session-level advisory lock taken through a pooler lives on the
/// pooler's SERVER connection, which the pooler keeps and reuses after the
/// client goes away — so the old gateway's lock outlived the old gateway, the
/// recreated container refused to boot against its own predecessor's lock, and
/// `restart: unless-stopped` turned that into a crash loop. The same class
/// CLAUDE.md §2 records for LISTEN/NOTIFY: a pooler cannot carry a session.
///
/// Built from the same five fields the pool uses (`PgFields`), because a raw
/// URL parse (with Neon's `sslmode=require&channel_binding=require` query)
/// failed to connect where the field form connected in the same process.
///
/// # Errors
/// `Ok(None)` when the only endpoint available is a pooler — the lock is then
/// UNENFORCEABLE and the caller says so (a degradation, not a refusal: a guard
/// that cannot be held must not take the service down); `Err` when no endpoint
/// is configured at all or the URL does not parse.
pub fn config_from_env() -> Result<Option<tokio_postgres::Config>> {
    let fields = if std::env::var("POSTGRES_DIRECT_URL").is_ok() {
        super::PgFields::from_url_var("POSTGRES_DIRECT_URL")?
    } else {
        super::PgFields::from_env()?
    };
    if let Some(host) = &fields.host
        && tracelane_shared::listen_dsn::host_cannot_deliver_notify(host)
    {
        return Ok(None);
    }
    let mut cfg = fields.to_tokio_config();
    cfg.application_name(LOCK_NAME);
    Ok(Some(cfg))
}

/// Try ONCE to take the lock on a fresh dedicated session.
///
/// `Ok(Some)` = held; `Ok(None)` = another session holds it; `Err` = could not
/// reach Postgres at all (the caller decides: at boot that is fail-closed
/// because the pool probe already required Postgres; in the background it is a
/// retry).
///
/// # Errors
/// Connection or query failure.
pub async fn try_acquire(cfg: &tokio_postgres::Config) -> Result<Option<SingletonLock>> {
    let tls = super::pg_tls_connector()?;
    let (client, connection) = cfg.connect(tls).await.context("singleton lock: connect")?;
    let connection = tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!(error = %e, "singleton lock: connection ended with an error");
        }
    });
    let row = client
        .query_one("SELECT pg_try_advisory_lock(hashtext($1))", &[&LOCK_NAME])
        .await
        .context("singleton lock: pg_try_advisory_lock")?;
    let held: bool = row.get(0);
    if held {
        Ok(Some(SingletonLock {
            _client: client,
            connection,
        }))
    } else {
        // Ending this session is what makes "not held" cost nothing.
        drop(client);
        connection.abort();
        Ok(None)
    }
}

/// Boot policy: with a control plane configured, either hold the lock or refuse
/// — unless the operator opted into multiple instances by name.
///
/// # Errors
/// Fail-CLOSED: the lock is held elsewhere and `TRACELANE_ALLOW_MULTI_INSTANCE`
/// is not `1`; or Postgres is unreachable for the lock session.
pub async fn acquire_at_boot() -> Result<Option<SingletonLock>> {
    let Some(cfg) = config_from_env()? else {
        tracing::warn!(
            "single-instance lock NOT taken: the only Postgres endpoint configured is a \
             POOLER, and a session-level advisory lock cannot live on a pooled connection \
             (it outlives the client and blocks the next boot). Set POSTGRES_DIRECT_URL to \
             the direct endpoint to enforce one gateway per control plane."
        );
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::SingletonLockLost,
        );
        return Ok(None);
    };
    match try_acquire(&cfg).await? {
        Some(lock) => {
            tracing::info!(lock = LOCK_NAME, "single-instance lock held");
            Ok(Some(lock))
        }
        None if multi_instance_allowed() => {
            tracing::warn!(
                "another gateway holds the single-instance lock and \
                 TRACELANE_ALLOW_MULTI_INSTANCE=1 — every per-process cap (rate limit, \
                 quota, budgets) is now cap × instances until shared counters exist"
            );
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::SingletonLockLost,
            );
            Ok(None)
        }
        None => anyhow::bail!(
            "REFUSING TO BOOT: another gateway holds the per-process counters for this \
             control plane (advisory lock `{LOCK_NAME}` is taken). A second instance \
             would make every rate limit, quota and budget cap × 2. Stop the other \
             gateway, or set TRACELANE_ALLOW_MULTI_INSTANCE=1 to accept that."
        ),
    }
}

fn multi_instance_allowed() -> bool {
    std::env::var("TRACELANE_ALLOW_MULTI_INSTANCE").is_ok_and(|v| v == "1")
}

/// Hold the lock for the process lifetime: when the carrying connection ends,
/// note the loss and re-acquire until it is ours again. Returns only on shutdown.
pub async fn hold(mut lock: SingletonLock) {
    let Ok(Some(cfg)) = config_from_env() else {
        return;
    };
    loop {
        // Wait for the session to end — the only way the lock is lost.
        let _ = (&mut lock.connection).await;
        tracing::warn!("singleton lock: session ended — lock LOST; re-acquiring");
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::SingletonLockLost,
        );
        loop {
            tokio::time::sleep(RETRY).await;
            match try_acquire(&cfg).await {
                Ok(Some(next)) => {
                    tracing::warn!("singleton lock: re-acquired");
                    lock = next;
                    break;
                }
                Ok(None) => {
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::SingletonLockLost,
                    );
                }
                Err(e) => {
                    tracing::debug!(error = %e, "singleton lock: re-acquire attempt failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pooler_host_is_never_used_for_the_lock() {
        // The prod outage's shape: pgbouncer keeps the server connection — and
        // the session lock on it — after the client leaves.
        assert!(tracelane_shared::listen_dsn::host_cannot_deliver_notify(
            "ep-spring-bread-asrn0mea-pooler.c-4.eu-central-1.aws.neon.tech"
        ));
        assert!(!tracelane_shared::listen_dsn::host_cannot_deliver_notify(
            "ep-spring-bread-asrn0mea.c-4.eu-central-1.aws.neon.tech"
        ));
    }

    #[test]
    fn config_from_env_reads_a_url_and_names_the_session() {
        // Pure parse — no connection; the env is read through a scoped override.
        let cfg: tokio_postgres::Config = "postgres://u:p@h:5433/d".parse().unwrap();
        assert_eq!(cfg.get_dbname(), Some("d"));
        let mut cfg = cfg;
        cfg.application_name(LOCK_NAME);
        assert_eq!(cfg.get_application_name(), Some(LOCK_NAME));
    }
}
