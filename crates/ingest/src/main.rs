//! Tracelane ingest service entry point.
//!
//! Spawns three concurrent tasks:
//! 1. OTLP HTTP receiver (port 4318) — accepts SDK-instrumented spans
//! 2. NATS JetStream consumer — reads spans from the message bus
//! 3. ClickHouse batch writer — drains the span channel into ClickHouse
//!

// Many modules contain scaffolded items awaiting wiring in upcoming milestones.
// Suppress dead_code and unused_imports globally for this binary crate during
// the active development phase.
#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    clippy::needless_return,
    clippy::collapsible_match,
    clippy::collapsible_if,
    clippy::manual_is_multiple_of,
    clippy::too_many_arguments,
    clippy::redundant_closure
)]

use anyhow::Context as _;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};

mod auth;
mod cardinality;
mod clickhouse_writer;
mod config;
mod db;
mod disk_guard;
mod federation;
mod limits;
mod nats_consumer;
mod otlp_decode;
mod otlp_receiver;
mod per_trace_ceiling;
mod quota;
mod r2_batcher;
mod rrweb_enricher;
mod span_envelope;
mod spire_client;
#[cfg(test)]
mod spire_mock;
mod spire_proto;
mod tail_sampler;
mod tenant_config;
mod tls;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = config::IngestConfig::from_env().context("failed to load ingest config")?;

    // ADR-067: single-tenant self-host mode. `from_env` fail-closes if
    // TRACELANE_SELF_HOST=1 is set alongside any multi-tenant/hosted signal
    // (Postgres / WorkOS / a SPIRE socket) or without a valid single tenant id,
    // so this can NEVER activate in the hosted deployment. When active it lets
    // ingest boot WITHOUT SPIRE and stamps every span with the one configured
    // tenant (see the SPIRE bail + the receiver/consumer wiring below).
    let self_host = tracelane_shared::self_host::from_env()
        .context("single-tenant self-host config (TRACELANE_SELF_HOST) is invalid")?;
    let single_tenant = self_host.as_ref().map(|c| c.tenant_id().clone());
    if let Some(t) = single_tenant.as_ref() {
        tracing::warn!(
            single_tenant_id = %t,
            "SINGLE-TENANT SELF-HOST mode active (ADR-067) — SPIRE mTLS DISABLED; every ingested \
             span will be stamped with this one tenant. This is safe ONLY single-tenant and \
             refuses to start if any hosted/multi-tenant signal is present."
        );
    }

    tracing::info!(
        otlp_port = cfg.otlp_port,
        nats_url = %cfg.nats_url,
        clickhouse_url = %cfg.clickhouse_url,
        "tracelane ingest starting"
    );

    // Bounded channels: span pipeline + R2 batcher
    // 64K-item capacity buffers short bursts without unbounded memory growth.
    // The pipeline carries SpanEnvelope (span + optional ack) so the writer can
    // ack the JetStream message only AFTER the row is durably written (#81).
    let (span_tx, span_rx) = tokio::sync::mpsc::channel::<span_envelope::SpanEnvelope>(65_536);
    let (r2_tx, r2_rx) = tokio::sync::mpsc::channel::<r2_batcher::SpanRecord>(16_384);

    let otlp_tx = span_tx.clone();
    let nats_tx = span_tx.clone();

    // sample the rest. Shared into the ClickHouse writer, which applies the
    // per-span keep/drop verdict and periodically prunes the sticky map. Before
    // this, `evaluate()` was never called — sampling silently never ran.
    let sampler = std::sync::Arc::new(tail_sampler::TailSampler::with_rate(
        cfg.tail_sample_rate_pct,
    ));

    // ADR-048 D4.1: per-tenant config cache — ONE cache, two consumers (the
    // ClickHouse writer reads the sampling policy; the OTLP receiver reads the
    // quota cap + billing email).
    //
    // SELF-GATING on POSTGRES_URL — prod ingest does NOT set it today, so this
    // takes the `None` branch (tenant-blind default: Tail + uniform quota,
    // non-regressing with the 100% tail rate). The COGS levers turn on only when
    // the founder (#5) sets POSTGRES_URL on the ingest container (→ per-tenant
    // Full + real per-tenant caps via the resolver), applies migration 14, and
    // lowers TRACELANE_TAIL_SAMPLE_RATE_PCT. A configured-but-broken DB fails
    // fast rather than silently running blind.
    let tenant_cfg = match db::build_pool_opt().await {
        Ok(Some(pool)) => {
            // Pool created (lazy). PG may be momentarily unreachable at boot —
            // that's fine: the resolver fault-keeps until PG returns, then
            // auto-recovers (build_pool_opt no longer fails on a startup blip).
            tracing::info!(
                "control-plane Postgres configured — per-tenant config resolver + LISTEN active"
            );
            let cache = std::sync::Arc::new(tenant_config::TenantConfigCache::new(
                tenant_config::pg_tenant_config_resolver(pool, cfg.fault_quota),
                std::time::Duration::from_secs(30),
            ));
            tenant_config::spawn_listen_task(cache.clone());
            cache
        }
        Ok(None) => {
            tracing::warn!(
                "no POSTGRES_URL — per-tenant config resolver DISABLED; tenant-blind default \
                 (Tail + uniform quota). ADR-048 COGS levers stay off until Postgres is wired."
            );
            std::sync::Arc::new(tenant_config::TenantConfigCache::default_with_quota(
                cfg.default_ingest_quota,
            ))
        }
        Err(e) => {
            // Genuine config error (malformed/incomplete POSTGRES_URL — NOT a
            // transient outage, which build_pool_opt now tolerates). Fail-OPEN:
            // log loudly and fall back to the tenant-blind default cache rather
            // than refusing to boot — a control-plane misconfig must not stop the
            // data plane (CLAUDE.md). Fix the config to enable per-tenant capture.
            tracing::error!(
                error = %e,
                "ingest control-plane Postgres config is INVALID — per-tenant resolver DISABLED; \
                 using tenant-blind default (Tail + uniform quota). Fix POSTGRES_URL to enable it."
            );
            std::sync::Arc::new(tenant_config::TenantConfigCache::default_with_quota(
                cfg.default_ingest_quota,
            ))
        }
    };

    // ADR-048 D4.2/D5: per-tenant ingest quota tracker + dedup'd breach notifier.
    // The quota is the SDK/OTLP-direct cost backstop; the notifier emails the
    // billing contact once per 24h (loud log when RESEND_API_KEY/email unset).
    let quota = std::sync::Arc::new(quota::QuotaTracker::new());
    let quota_notifier = std::sync::Arc::new(quota::QuotaNotifier::new(
        std::env::var("RESEND_API_KEY")
            .ok()
            .map(secrecy::SecretString::from),
        std::env::var("RESEND_FROM").unwrap_or_else(|_| "alerts@tracelane.dev".into()),
        std::env::var("TRACELANE_UPGRADE_URL")
            .unwrap_or_else(|_| "https://app.tracelane.dev/settings/billing".into()),
    ));

    // Bound the receiver-side maps (review): the quota counter + notifier dedup
    // grow one entry per tenant ever seen. Their siblings (sampler/ceiling) prune
    // on the writer loop; these live on the receiver, so a small hourly sweep
    // drops stale-month counters + past-window dedup entries. Detached — dies
    // with the process.
    {
        let q = quota.clone();
        let n = quota_notifier.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                q.prune(quota::current_period());
                n.prune();
            }
        });
    }

    // ADR-048 D4.3: per-trace span/byte ceiling — clips a runaway trace's tail
    // on ALL tiers (incl forced-full), so one pathological trace can't blow a
    // batch. Generous defaults (a normal agent trace passes); env-overridable.
    let ceiling = std::sync::Arc::new(per_trace_ceiling::PerTraceCeiling::with_limits(
        cfg.max_spans_per_trace,
        cfg.max_bytes_per_trace,
    ));

    // FT-08: disk-pressure guard. Reads TRACELANE_INGEST_DATA_DIR +
    // TRACELANE_INGEST_MIN_FREE_BYTES; sheds new spans (507) when the volume
    // backing local spill/WAL drops below the floor. One clone serves the
    // receiver hot path (atomic flag); a second drives the refresher.
    let disk = disk_guard::DiskGuard::from_env();

    // Ensure the R2 DLQ JetStream stream exists before starting the batcher.
    // Non-fatal if NATS is unavailable — batcher degrades gracefully.
    if let Ok(nats) = async_nats::connect(&cfg.nats_url).await {
        if let Err(e) = r2_batcher::ensure_dlq_stream(&nats).await {
            tracing::warn!(error = %e, "could not ensure R2 DLQ stream; DLQ disabled");
        } else {
            tracing::info!("R2 DLQ stream TRACELANE_SPANS_DLQ ready");
        }
    }

    // Hard-fail if the runtime trust domain doesn't match the compile-time
    // TRUST_DOMAIN in auth.rs. Without this check, the SPIRE bootstrap
    // could validate a SVID against a different trust domain than the
    // per-request middleware will accept — silent half-broken auth.
    if cfg.spire_trust_domain.to_ascii_lowercase() != auth::TRUST_DOMAIN {
        anyhow::bail!(
            "config TRACELANE_TRUST_DOMAIN ({:?}) must equal auth::TRUST_DOMAIN ({:?}). The middleware enforces the compile-time value; mismatching runtime would silently break auth.",
            cfg.spire_trust_domain,
            auth::TRUST_DOMAIN,
        );
    }

    // mTLS bootstrap. When TRACELANE_SPIRE_SOCKET is set, fetch the
    // workload SVID + trust bundle from the SPIRE agent and run the
    // receiver in mTLS mode (INGEST-002). Otherwise fall back to
    // plaintext (dev only).
    //
    // The refresher returns a future we fold into `try_join!` so its
    // failure (after exhausted retries) brings the whole process down
    // cleanly — preferable to a zombie task with a frozen trust bundle.
    // Plaintext fallback is debug-only — release binaries MUST run
    // with SPIFFE mTLS, because the tenant-resolution code in
    // `otlp_decode::resolve_tenant` only accepts the resource-attribute
    // fallback under `#[cfg(debug_assertions)]`. Booting without SPIRE
    // in a release build would let any caller spoof any tenant_id.
    //
    // ADR-067 exception: single-tenant self-host mode. When active, there is
    // exactly one tenant and the receiver stamps EVERY span with it (ignoring
    // any body-supplied tenant), so the spoof threat SPIRE guards against cannot
    // occur — the SPIRE requirement is safely lifted. `self_host.is_some()` is
    // proof the multi-tenant hard-fail guard passed (it refuses to boot if a
    // SPIRE socket, Postgres, or WorkOS is present), so this can never weaken
    // the hosted path.
    #[cfg(not(debug_assertions))]
    if cfg.spire_socket.is_none() && self_host.is_none() {
        anyhow::bail!(
            "TRACELANE_SPIRE_SOCKET is required in release builds — ingest refuses to start \
             without mTLS-authenticated peers (A1 launch invariant). For a single-tenant \
             self-host deployment, set TRACELANE_SELF_HOST=1 + TRACELANE_SINGLE_TENANT_ID=<uuid> \
             instead (ADR-067)."
        );
    }

    let (mtls_state, refresher_fut) = match cfg.spire_socket.as_deref() {
        Some(path) => {
            tracing::info!(spire_socket = %path, "bootstrapping mTLS from SPIRE");
            let client = spire_client::SpireClient::connect(path.into())
                .await
                .context("connect SPIRE Workload API")?;
            let (server_config, bundle) =
                tls::bootstrap_from_spire(&client, &cfg.spire_trust_domain)
                    .await
                    .context("initial SPIRE bootstrap")?;
            let refresher =
                tls::BundleRefresher::new(client, bundle, cfg.spire_trust_domain.clone());
            let fut: std::pin::Pin<
                Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>,
            > = Box::pin(async move { refresher.run().await });
            (Some(std::sync::Arc::new(server_config)), fut)
        }
        None => {
            // Plaintext mode: refresher future is a no-op that lives
            // forever (pending) so `try_join!` only exits when one of
            // the other tasks errors out. Reached in debug builds, and in
            // release builds ONLY when single-tenant self-host is active
            // (ADR-067) — the hosted release path still bails above.
            if single_tenant.is_some() {
                tracing::info!(
                    "TRACELANE_SPIRE_SOCKET unset — plaintext mode under single-tenant \
                     self-host (ADR-067); every span is stamped with the fixed tenant."
                );
            } else {
                tracing::warn!(
                    "TRACELANE_SPIRE_SOCKET unset — DEV-ONLY plaintext mode. Hosted release \
                     builds bail at startup; this branch is debug-only (or single-tenant self-host)."
                );
            }
            let fut: std::pin::Pin<
                Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>,
            > = Box::pin(std::future::pending::<anyhow::Result<()>>());
            (None, fut)
        }
    };

    let receiver_disk = disk.clone();
    let receiver_cfg = tenant_cfg.clone(); // shared cache (writer keeps `tenant_cfg`)
    let receiver_quota = quota.clone();
    let receiver_notifier = quota_notifier.clone();
    let receiver_single_tenant = single_tenant.clone();
    let otlp_task = async {
        match mtls_state {
            Some(sc) => {
                otlp_receiver::run_mtls(
                    cfg.otlp_port,
                    otlp_tx,
                    sc,
                    receiver_disk,
                    receiver_cfg,
                    receiver_quota,
                    receiver_notifier,
                )
                .await
            }
            None => {
                otlp_receiver::run(
                    cfg.otlp_port,
                    otlp_tx,
                    receiver_disk,
                    receiver_cfg,
                    receiver_quota,
                    receiver_notifier,
                    receiver_single_tenant,
                )
                .await
            }
        }
    };

    tokio::try_join!(
        otlp_task,
        refresher_fut,
        disk.run_refresher(),
        nats_consumer::run(cfg.nats_url.clone(), nats_tx, single_tenant.clone()),
        clickhouse_writer::run(
            cfg.clickhouse_url.clone(),
            cfg.clickhouse_user.clone(),
            cfg.clickhouse_password.clone(),
            cfg.clickhouse_db.clone(),
            sampler,
            tenant_cfg,
            ceiling,
            span_rx,
            cfg.batch_size,
            std::time::Duration::from_millis(cfg.batch_timeout_ms),
        ),
        r2_batcher::run(r2_rx),
    )?;

    // r2_tx kept alive until the select above exits so the batcher doesn't
    // see a closed channel immediately. The compiler will warn it's unused —
    // this is intentional (the ClickHouse writer will feed r2_tx in Week 8
    // when R2 cold-path is enabled). Suppress the warning explicitly.
    drop(r2_tx);

    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,ingest=debug,tracelane=debug"));

    let use_json = std::env::var("TRACELANE_LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false);

    // A10: wrap stdout in the same RedactingMakeWriter the gateway uses,
    // so credential / API-key leaks in error paths (OTLP decode failures,
    // ClickHouse panics) are scrubbed before they hit disk or a terminal.
    use tracelane_shared::redact::RedactingMakeWriter;

    if use_json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .json()
                    .with_writer(RedactingMakeWriter::new(std::io::stdout)),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .pretty()
                    .with_writer(RedactingMakeWriter::new(std::io::stdout)),
            )
            .init();
    }
}
