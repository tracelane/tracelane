//! Control-plane Postgres pool for the ingest per-tenant config resolver
//! (ADR-048 D4.1).
//!
//! Ingest is normally Postgres-free (spans flow OTLP/NATS → ClickHouse). This
//! pool exists only so the `tenant_config` resolver can read each tenant's
//! sampling policy + ingest quota + billing contact from the Neon control plane.
//! It mirrors `crates/gateway/src/db`: `deadpool-postgres` over `tokio-postgres`
//! with a rustls TLS connector (Neon mandates TLS; `NoTls` fails the handshake)
//! and the webpki root set (no filesystem dependency — works in the distroless
//! runtime). `openssl` is banned (CLAUDE.md).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres_rustls::MakeRustlsConnect;

/// Shared Postgres pool — cheap to `clone()`.
pub type DbPool = Pool;

/// Build a Postgres pool from `POSTGRES_URL` or the standard `PG*` env vars.
/// Returns `None` when no connection config is present (ingest then runs
/// Postgres-free with the tenant-blind default config cache — non-regressing).
///
/// # Errors
/// Returns `Err` only when a URL is set but malformed, or the startup probe
/// fails — surfaced so a misconfigured DB fails fast rather than silently
/// resolving every tenant to the fallback.
pub async fn build_pool_opt() -> Result<Option<DbPool>> {
    let mut cfg = Config::new();

    // NOTE (review P1-2): `deadpool_postgres::Config.password` is a plain
    // `Option<String>`, so the DB password lives un-zeroized for the pool's
    // lifetime — the deadpool API forces the type at this boundary (no
    // SecretString hook), identical to the gateway `db` module. Accepted: the
    // value is never logged (no error path interpolates it) and never leaves this
    // process; wrapping it would only delay the same plaintext handoff to deadpool.
    if let Ok(url) = std::env::var("POSTGRES_URL") {
        let pg_cfg: tokio_postgres::Config = url
            .parse()
            .context("POSTGRES_URL is not a valid Postgres URL")?;
        cfg.host = pg_cfg.get_hosts().first().and_then(host_to_string);
        cfg.port = pg_cfg.get_ports().first().copied();
        cfg.user = pg_cfg.get_user().map(str::to_owned);
        cfg.password = pg_cfg
            .get_password()
            .map(|p| String::from_utf8_lossy(p).to_string());
        cfg.dbname = pg_cfg.get_dbname().map(str::to_owned);
    } else if let Ok(host) = std::env::var("PGHOST") {
        cfg.host = Some(host);
        cfg.port = std::env::var("PGPORT").ok().and_then(|p| p.parse().ok());
        cfg.user = std::env::var("PGUSER").ok();
        cfg.password = std::env::var("PGPASSWORD").ok();
        cfg.dbname = std::env::var("PGDATABASE").ok();
    } else {
        // No control-plane configured — caller uses the tenant-blind default.
        return Ok(None);
    }

    if cfg.host.is_none() || cfg.dbname.is_none() {
        anyhow::bail!("Postgres config incomplete: set POSTGRES_URL or PGHOST + PGDATABASE");
    }

    cfg.pool = Some(deadpool_postgres::PoolConfig {
        // Small — ingest only reads tenant config on a cache miss, not per span.
        max_size: 4,
        timeouts: deadpool_postgres::Timeouts {
            wait: Some(Duration::from_secs(5)),
            create: Some(Duration::from_secs(5)),
            recycle: Some(Duration::from_secs(2)),
        },
        ..Default::default()
    });

    let pool = cfg
        .create_pool(Some(Runtime::Tokio1), pg_tls_connector()?)
        .context("failed to create ingest Postgres pool")?;
    // Best-effort startup probe — log, but DO NOT fail. A control-plane DB
    // outage must never stop the data plane (CLAUDE.md: fail-open for FT/data
    // paths). deadpool's pool is lazy, so connectivity is re-established on the
    // next resolver query when Postgres returns; until then the resolver
    // fault-keeps every span (see `pg_tenant_config_resolver`). Boot proceeds
    // either way — ingest never refuses to start because the control plane blipped.
    match pool.get().await {
        Ok(_) => tracing::info!("ingest control-plane Postgres reachable"),
        Err(e) => tracing::warn!(
            error = %e,
            "ingest control-plane Postgres unreachable at startup — ingest CONTINUES; \
             the per-tenant resolver fault-keeps (Full) until Postgres returns, then auto-recovers"
        ),
    }
    Ok(Some(pool))
}

/// rustls TLS connector for Postgres (webpki roots, aws-lc-rs provider).
pub fn pg_tls_connector() -> Result<MakeRustlsConnect> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("rustls: set protocol versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

fn host_to_string(host: &tokio_postgres::config::Host) -> Option<String> {
    #[cfg(unix)]
    {
        match host {
            tokio_postgres::config::Host::Tcp(s) => Some(s.clone()),
            tokio_postgres::config::Host::Unix(p) => Some(p.to_string_lossy().into_owned()),
        }
    }
    #[cfg(not(unix))]
    {
        match host {
            tokio_postgres::config::Host::Tcp(s) => Some(s.clone()),
        }
    }
}
