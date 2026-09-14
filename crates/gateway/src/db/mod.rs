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
//! Postgres source of truth (ADR-040 /). The `apply_migrations` helper
//! embeds those files for integration tests; prod is migrated by
//! `drizzle-kit migrate`. (The old `infra/dev/postgres/migrations/` divergent
//! set is being retired in; it survives only for the COGS eval bubble
//! until that migrates to the id-PK shape — tracked as.)
//!
//! Query style: raw SQL with parameter binding, never string-concat. See
//! `tenants.rs` and `api_keys.rs` for the patterns.

pub mod api_keys;
pub mod audit_chain_state;
pub mod idle_evict;
pub mod keepalive;
pub mod observed_tools;
pub mod provider_keys;
pub mod quota_notifications;
pub mod singleton;
pub mod tenants;
pub mod tool_capabilities;
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
///
/// B-386 (b): stays global — MIGRATING, not staying. The same pool is now
/// `AppState::pg` (the EXPAND step); `server::run` and the chat handler read
/// the field. This static remains readable for the callers that have no state
/// handle yet (`auth::api_key::validate`, `resolve_provider_key`, the quota
/// webhook, the WorkOS webhook, the BYOK / tool-pin routes …), converted per
/// module; it is deleted when its last reader is gone (CONTRACT).
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
/// The five connection fields every Postgres session in this process is built
/// from — the pool AND the single-instance lock's dedicated session. ONE
/// derivation, so the two cannot disagree: on 2026-09-12 the lock parsed the
/// raw `POSTGRES_URL` (with its `sslmode=require&channel_binding=require`
/// query) into a `tokio_postgres::Config` while the pool used these fields,
/// and the lock's connect failed on prod (`Network is unreachable`) in the same
/// process where the pool had just connected. The deploy rolled back on it.
pub(crate) struct PgFields {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub dbname: Option<String>,
}

impl PgFields {
    /// `POSTGRES_URL` (parsed positionally) or the libpq `PG*` variables.
    ///
    /// # Errors
    /// The URL does not parse, or neither a host nor a database is configured.
    pub(crate) fn from_env() -> Result<Self> {
        Self::from_url_var("POSTGRES_URL")
    }

    /// The same, from a named URL variable — `POSTGRES_DIRECT_URL` for the
    /// sessions that must NOT go through a pooler (the singleton lock; the
    /// LISTEN connection in `entitlement_cache`). Falls back to the `PG*`
    /// variables like `from_env` when the variable is unset.
    ///
    /// # Errors
    /// As `from_env`.
    pub(crate) fn from_url_var(var: &str) -> Result<Self> {
        let mut f = Self {
            host: None,
            port: None,
            user: None,
            password: None,
            dbname: None,
        };
        if let Ok(url) = std::env::var(var) {
            // tokio-postgres only does positional URL parsing via tokio_postgres::Config
            let pg_cfg: tokio_postgres::Config = url
                .parse()
                .with_context(|| format!("{var} is not a valid Postgres URL"))?;
            f.host = pg_cfg.get_hosts().first().and_then(host_to_string);
            f.port = pg_cfg.get_ports().first().copied();
            f.user = pg_cfg.get_user().map(str::to_owned);
            f.password = pg_cfg
                .get_password()
                .map(|p| String::from_utf8_lossy(p).to_string());
            f.dbname = pg_cfg.get_dbname().map(str::to_owned);
        } else {
            // Component env-var fallback — same names libpq honours.
            f.host = std::env::var("PGHOST").ok();
            f.port = std::env::var("PGPORT").ok().and_then(|p| p.parse().ok());
            f.user = std::env::var("PGUSER").ok();
            f.password = std::env::var("PGPASSWORD").ok();
            f.dbname = std::env::var("PGDATABASE").ok();
        }
        if f.host.is_none() || f.dbname.is_none() {
            anyhow::bail!(
                "Postgres connection config missing: set POSTGRES_URL or PGHOST + PGDATABASE"
            );
        }
        Ok(f)
    }

    /// A standalone `tokio_postgres::Config` with exactly these fields — the
    /// shape deadpool builds from the same struct for the pool.
    pub(crate) fn to_tokio_config(&self) -> tokio_postgres::Config {
        let mut c = tokio_postgres::Config::new();
        if let Some(h) = &self.host {
            c.host(h);
        }
        if let Some(p) = self.port {
            c.port(p);
        }
        if let Some(u) = &self.user {
            c.user(u);
        }
        if let Some(p) = &self.password {
            c.password(p);
        }
        if let Some(d) = &self.dbname {
            c.dbname(d);
        }
        c
    }
}

pub async fn build_pool() -> Result<DbPool> {
    let mut cfg = Config::new();
    let f = PgFields::from_env()?;
    cfg.host = f.host;
    cfg.port = f.port;
    cfg.user = f.user;
    cfg.password = f.password;
    cfg.dbname = f.dbname;

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
/// against the pool — the single Postgres source of truth (ADR-040 /).
///
/// The old `infra/dev/postgres/migrations/` set was a divergent second system
/// (pre-ADR-040 `tenant_id`/`plan_tier` shape); this helper no longer reads it
/// (that dir is retired in, kept only for the COGS eval until). Each
/// Drizzle file is `include_str!`'d and applied with `batch_execute` — Drizzle's
/// `--> statement-breakpoint` markers are `--` line comments, so the whole file
/// runs as one multi-statement script (each file is its own implicit txn).
///
/// **Fresh-database helper for integration tests only.** The Drizzle SQL is NOT
/// `IF NOT EXISTS`-guarded, so re-running against a populated DB fails.
/// Production is migrated by `drizzle-kit migrate`, never this.
///
/// Called only from `crates/gateway/tests/postgres_tenant_integration.rs`,
/// which compiles as a SEPARATE crate linking against this one — invisible
/// to this crate's own `dead_code` reachability analysis, hence the allow
/// (B-390, 2026-09-12; not a case of genuinely dead code, confirmed by
/// grep — deleting this breaks that integration test).
#[allow(dead_code)]
pub async fn apply_migrations(pool: &DbPool) -> Result<()> {
    let client = pool
        .get()
        .await
        .map_err(|e: PoolError| anyhow::anyhow!("pool: {e}"))?;
    // Applied in order. Keep in sync with `apps/web/db/migrations/meta/_journal.json`.
    // EVERY file in `apps/web/db/migrations/`, in lexical order — the definition of
    // a fresh database. Pinned against the directory by
    // `scripts/ci/check-migration-list-complete.py`, because this list DRIFTED:
    // it read 0000-0006 then jumped to 0011, silently skipping 0007 (which adds
    // `tenants.archived_at`) through 0010. Any integration test using this helper
    // therefore died on `column "archived_at" does not exist` — one of three
    // independent reasons the only test covering `api_keys::create` had never run.
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
        include_str!("../../../../apps/web/db/migrations/0007_b063_archived_at.sql"),
        include_str!("../../../../apps/web/db/migrations/0008_api_keys_key_hash_partial.sql"),
        include_str!("../../../../apps/web/db/migrations/0009_support_requests.sql"),
        include_str!("../../../../apps/web/db/migrations/0010_a5_tenants_plan_default_free.sql"),
        include_str!("../../../../apps/web/db/migrations/0011_identity_api_keys_minted_by.sql"),
        include_str!("../../../../apps/web/db/migrations/0012_alerts.sql"),
        include_str!("../../../../apps/web/db/migrations/0013_alerts_builder_plus.sql"),
        include_str!("../../../../apps/web/db/migrations/0014_rekor_v2_anchor_key.sql"),
        include_str!("../../../../apps/web/db/migrations/0015_audit_selfverify.sql"),
        include_str!("../../../../apps/web/db/migrations/0016_tool_capabilities.sql"),
        include_str!("../../../../apps/web/db/migrations/0017_overhead_p99_alert_metric.sql"),
        include_str!(
            "../../../../apps/web/db/migrations/0018_audit_chain_state_retain_beyond_tenant.sql"
        ),
        include_str!("../../../../apps/web/db/migrations/0019_api_keys_revoke_notify.sql"),
        include_str!("../../../../apps/web/db/migrations/0020_audit_appended_dedup.sql"),
        include_str!("../../../../apps/web/db/migrations/0021_entitlements_notify_triggers.sql"),
        include_str!("../../../../apps/web/db/migrations/0022_observed_tools.sql"),
        include_str!("../../../../apps/web/db/migrations/0023_quota_notifications.sql"),
        include_str!(
            "../../../../apps/web/db/migrations/0024_a13_scoped_keys_and_b188_residue.sql"
        ),
        include_str!("../../../../apps/web/db/migrations/0025_obs18_trace_annotations.sql"),
        include_str!("../../../../apps/web/db/migrations/0026_dsh01_notifications.sql"),
        include_str!("../../../../apps/web/db/migrations/0028_gwy41_ingest_scope_comment.sql"),
        include_str!(
            "../../../../apps/web/db/migrations/0029_gwy43_per_key_rate_limit_and_workspace_budget.sql"
        ),
        // EVL-04. Caught by `check-migration-list-complete.py`, which is the whole
        // reason this list is not a convention: a migration that exists on disk but
        // not HERE never reaches a fresh database, and every Postgres integration
        // test builds its schema from this array — so the gateway would read
        // `f_datasets` from a column that does not exist and 500 the entire
        // entitlement resolve, on a surface that had passed every local test.
        include_str!("../../../../apps/web/db/migrations/0030_evl04_dataset_entitlements.sql"),
        include_str!("../../../../apps/web/db/migrations/0031_evl28_online_eval_policies.sql"),
        // EVL-29 item 12. Applied to prod Neon ahead of any reader; listed here
        // so a FRESH database and every Postgres integration test build the same
        // schema. 0033 corrects 0032 (nullable target -> NOT NULL, version
        // counter -> immutable snapshot) per founder rulings R222/R224, on an
        // empty table with no reader — so the pair must be applied IN ORDER.
        include_str!("../../../../apps/web/db/migrations/0032_evl29_annotation_queues.sql"),
        include_str!(
            "../../../../apps/web/db/migrations/0033_evl29_required_target_and_rubric_snapshot.sql"
        ),
        // DSH-13 custom dashboards (2026-09-05): `dashboards` + `dashboard_tiles`, CHECK-
        // constrained closed sets; additive, no reader in the gateway.
        include_str!("../../../../apps/web/db/migrations/0034_dsh13_dashboards.sql"),
        include_str!("../../../../apps/web/db/migrations/0035_dsh13_tile_position_unique.sql"),
        // OBS-48 shareable trace links. Un-journaled (TRAPS §9): applied to Neon
        // BEFORE the gateway build that reads/writes `trace_shares` deploys.
        include_str!("../../../../apps/web/db/migrations/0036_trace_shares.sql"),
        // DSH-13 tile height (2026-09-07): `dashboard_tiles.height` compact|regular|tall,
        // DEFAULT 'regular'. Un-journaled (TRAPS §9): applied to Neon BEFORE the web
        // build that reads/writes it deploys; additive, idempotent, no gateway reader.
        include_str!("../../../../apps/web/db/migrations/0037_dashboard_tile_height.sql"),
        // DSH-13 §9 section dividers (2026-09-07): widens `dashboard_tiles_shape_chk` to
        // admit 'divider' and adds a CHECK pinning a divider row to width=12/metric_id=
        // '__divider__'. Additive, idempotent, no gateway reader.
        include_str!("../../../../apps/web/db/migrations/0038_dashboard_tile_divider.sql"),
        include_str!("../../../../apps/web/db/migrations/0039_polar_event_ordering.sql"),
        // BILL-01 / ADR-076 (2026-09-13/14): the six-meter allowances, prices, windows,
        // `pricing_rates`, `billing_policy`, `meter_warnings`, the tenant ceiling /
        // dunning / price-version columns and the per-key `budget_reset` +
        // `velocity_breaker` — every one of which `db/api_keys.rs` and
        // `entitlement_cache.rs` now READ. Applied to prod Neon by hand (TRAPS §9) before
        // the binary; listed here so the Postgres integration harness builds the same
        // shape — its first run without these lines failed on the api_keys INSERT.
        include_str!("../../../../apps/web/db/migrations/0040_bill01_pricing_v3_entitlements.sql"),
        // 0041: `tenants.auto_age_window_days` / `auto_age_since` (ceiling AUTO-AGE).
        include_str!("../../../../apps/web/db/migrations/0041_bill01_auto_age_window.sql"),
        // BILL-01 contract step: the ADR-020 columns go. On prod this is applied BY
        // HAND after web + gateway deploy (this list feeds the test databases only).
        include_str!(
            "../../../../apps/web/db/migrations/0042_bill01_contract_drop_adr020_columns.sql"
        ),
    ];
    for migration in MIGRATIONS {
        client
            .batch_execute(migration)
            .await
            .with_context(|| "Drizzle migration batch failed".to_string())?;
    }
    Ok(())
}
