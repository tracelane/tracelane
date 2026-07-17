//! Postgres pool + per-table query modules.
//!
//! Tracelane's source-of-truth split:
//!   - ClickHouse holds high-cardinality observational data (spans,
//!     audit_log, prompt_versions, promotion_decisions, rollback_events).
//!   - Postgres holds low-cardinality metadata (tenants, api_keys, users).
//!
//! Connection pooling: `deadpool-postgres` over `tokio-postgres`. The
//! pool is constructed once at startup from `POSTGRES_URL` (or the
//! component env vars `PG{HOST,PORT,USER,PASSWORD,DBNAME}`) and shared
//! via `Arc<DbPool>` on `AppState`.
//!
//! Migration discipline: Drizzle (`apps/web/db/migrations/`) is the single
//! embeds those files for integration tests; prod is migrated by
//! `drizzle-kit migrate`. (The old `infra/dev/postgres/migrations/` divergent
//!
//! Query style: raw SQL with parameter binding, never string-concat. See
//! `tenants.rs` and `api_keys.rs` for the patterns.

pub mod api_keys;
pub mod audit_chain_state;
pub mod provider_keys;
pub mod tenants;
pub mod webhook_events;

use anyhow::{Context as _, Result};
use deadpool_postgres::{Config, Pool, PoolError, Runtime};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio_postgres_rustls::MakeRustlsConnect;

/// Shared Postgres pool — wrapped in `Arc` on AppState. `clone()` is cheap.
pub type DbPool = Pool;

/// Global pool slot. Set once at startup via `set_global_pool` so call
/// sites like `auth::api_key::validate` can reach the DB without
/// threading the pool through every function signature. `OnceLock`
/// semantics: set returns `Err` on second call.
static GLOBAL_POOL: OnceLock<DbPool> = OnceLock::new();

/// Install the global pool. Call once at gateway startup. Panics if
/// called twice — that's a programmer bug, not a runtime condition.
pub fn set_global_pool(pool: DbPool) {
    GLOBAL_POOL
        .set(pool)
        .map_err(|_| ())
        .expect("set_global_pool called twice");
}

/// Read the global pool, if set. Returns `None` when the gateway is
/// running in dev mode without `POSTGRES_URL` configured.
pub fn global_pool() -> Option<&'static DbPool> {
    GLOBAL_POOL.get()
}

/// Render an error's FULL anyhow chain (`{:#}`) plus, when a `tokio_postgres`
/// `DbError` is anywhere in the chain, its SQLSTATE code / message / detail /
/// hint / column / table.
///
/// The bare `%err` Display drops BOTH the context chain and the Postgres error
/// code — which is exactly what masked the WorkOS `organization.created`
/// dispatch failure: only the outermost context (`upsert tenant for workos_org
/// ...`) surfaced, never the root DB error. Log DB-touching failures through
/// this so the SQLSTATE (`23502` not-null, `42704` undefined type, `26000`
/// prepared-statement-missing, `42P01` undefined table, ...) is always visible.
///
/// Cold path (error logging only) — the allocation is irrelevant.
pub fn pg_error_chain(err: &anyhow::Error) -> String {
    use std::fmt::Write as _;
    let mut s = format!("{err:#}");
    for cause in err.chain() {
        if let Some(pg) = cause.downcast_ref::<tokio_postgres::Error>() {
            if let Some(db) = pg.as_db_error() {
                let _ = write!(s, " [pg {}: {}", db.code().code(), db.message());
                if let Some(d) = db.detail() {
                    let _ = write!(s, "; detail={d}");
                }
                if let Some(h) = db.hint() {
                    let _ = write!(s, "; hint={h}");
                }
                if let Some(c) = db.column() {
                    let _ = write!(s, "; column={c}");
                }
                if let Some(t) = db.table() {
                    let _ = write!(s, "; table={t}");
                }
                s.push(']');
            }
            break;
        }
    }
    s
}

/// Build a Postgres pool from `POSTGRES_URL` or the standard `PG*` env vars.
///
/// `POSTGRES_URL` example: `postgres://user:pass@host:5432/dbname`.
///
/// Pool config:
///   - `max_size = 16` per gateway instance (fits 4-8 cores at default ratios).
///   - `wait_timeout = 5s` so a saturated pool surfaces 503 to the caller
///     instead of stacking unbounded request latency.
///
/// # Errors
/// Returns `Err` if the URL parse fails or the initial connection probe fails.
pub async fn build_pool() -> Result<DbPool> {
    let mut cfg = Config::new();

    if let Ok(url) = std::env::var("POSTGRES_URL") {
        // tokio-postgres only does positional URL parsing via tokio_postgres::Config
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
    } else {
        // Component env-var fallback — same names libpq honours.
        cfg.host = std::env::var("PGHOST").ok();
        cfg.port = std::env::var("PGPORT").ok().and_then(|p| p.parse().ok());
        cfg.user = std::env::var("PGUSER").ok();
        cfg.password = std::env::var("PGPASSWORD").ok();
        cfg.dbname = std::env::var("PGDATABASE").ok();
    }

    if cfg.host.is_none() || cfg.dbname.is_none() {
        anyhow::bail!(
            "Postgres connection config missing: set POSTGRES_URL or PGHOST + PGDATABASE"
        );
    }

    let pool_cfg = deadpool_postgres::PoolConfig {
        max_size: 16,
        timeouts: deadpool_postgres::Timeouts {
            wait: Some(Duration::from_secs(5)),
            create: Some(Duration::from_secs(5)),
            recycle: Some(Duration::from_secs(2)),
        },
        ..Default::default()
    };
    cfg.pool = Some(pool_cfg);

    let pool = cfg
        .create_pool(Some(Runtime::Tokio1), pg_tls_connector()?)
        .context("failed to create Postgres pool")?;

    // Probe — fail fast at startup, don't paper over a misconfigured DB.
    let _client = pool
        .get()
        .await
        .context("initial Postgres connection probe failed")?;

    Ok(pool)
}

/// Build the rustls TLS connector for Postgres. Managed Postgres (Neon) mandates
/// TLS — a `NoTls` pool fails the handshake at startup probe. Uses the webpki
/// root set (no filesystem dependency — works in the distroless runtime) and an
/// explicit aws-lc-rs crypto provider (rustls/aws-lc-rs only per CLAUDE.md; the
/// dep tree carries more than one provider, so rustls has no installed default).
pub(crate) fn pg_tls_connector() -> Result<MakeRustlsConnect> {
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
    // tokio_postgres::config::Host is `#[non_exhaustive]` only on unix
    // (where it gains the `Unix(PathBuf)` variant). On Windows the only
    // variant is `Tcp(String)`, so a catch-all arm trips the
    // unreachable_patterns lint. Branch on cfg to keep both targets
    // happy without `#[allow]`.
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

/// Apply the **canonical Drizzle migrations** (`apps/web/db/migrations/`)
///
/// The old `infra/dev/postgres/migrations/` set was a divergent second system
/// (pre-ADR-040 `tenant_id`/`plan_tier` shape); this helper no longer reads it
/// Drizzle file is `include_str!`'d and applied with `batch_execute` — Drizzle's
/// `--> statement-breakpoint` markers are `--` line comments, so the whole file
/// runs as one multi-statement script (each file is its own implicit txn).
///
/// **Fresh-database helper for integration tests only.** The Drizzle SQL is NOT
/// `IF NOT EXISTS`-guarded, so re-running against a populated DB fails.
/// Production is migrated by `drizzle-kit migrate`, never this.
pub async fn apply_migrations(pool: &DbPool) -> Result<()> {
    let client = pool
        .get()
        .await
        .map_err(|e: PoolError| anyhow::anyhow!("pool: {e}"))?;
    // Applied in order. Keep in sync with `apps/web/db/migrations/meta/_journal.json`.
    const MIGRATIONS: &[&str] = &[
        include_str!("../../../../apps/web/db/migrations/0000_initial_baseline.sql"),
        include_str!("../../../../apps/web/db/migrations/0001_reconcile_gateway_tables.sql"),
        include_str!("../../../../apps/web/db/migrations/0002_reconcile_full_capture.sql"),
        include_str!("../../../../apps/web/db/migrations/0003_add_e2e_disposable_tenant_check.sql"),
        include_str!("../../../../apps/web/db/migrations/0004_prompt_promotion_write.sql"),
        include_str!(
            "../../../../apps/web/db/migrations/0005_adr009_seed_and_audit_addon_backfill.sql"
        ),
        include_str!("../../../../apps/web/db/migrations/0006_b084_users_name_guardrails.sql"),
        // 0011 adds api_keys.minted_by (IDENTITY_TEAM_SPEC §3), which the
        // `create`/`mint` INSERT now writes. Independent ALTER — safe to apply
        // list; the ignored PG integration test needs the column to exist.
        include_str!("../../../../apps/web/db/migrations/0011_identity_api_keys_minted_by.sql"),
    ];
    for migration in MIGRATIONS {
        client
            .batch_execute(migration)
            .await
            .with_context(|| "Drizzle migration batch failed".to_string())?;
    }
    Ok(())
}
