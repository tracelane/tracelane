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

pub mod admin_security;
pub mod api_keys;
pub mod audit_chain_state;
pub mod cache_settings;
pub mod control_audit;
pub mod controls;
pub mod idle_evict;
pub mod job_guard;
pub mod keepalive;
pub mod ledger;
pub mod model_aliases;
pub mod observed_tools;
pub mod otel_exports;
pub mod projects;
pub mod provider_keys;
pub mod quota_notifications;
pub mod routing;
pub mod singleton;
pub mod spend_alerts;
pub mod tenants;
pub mod tool_capabilities;
pub mod webhook_events;
pub mod workspace_capture;
pub mod workspace_failover;

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
        // BILL-01 A5 + B-410: cold_gb_included on both entitlement tables, the Polar
        // cycle on tenants. Nullable adds; applied BY HAND on prod BEFORE the
        // gateway that reads them (its boot check refuses otherwise).
        include_str!(
            "../../../../apps/web/db/migrations/0043_bill01_cold_allowance_and_billing_period.sql"
        ),
        // BILL-02 (B14 → (c)): the annual pair's subscription ids + base period on
        // tenants, the two product ids on plan_entitlements. Nullable adds; the
        // gateway reads none of them (test-database applier only).
        include_str!("../../../../apps/web/db/migrations/0044_bill02_annual_two_subscriptions.sql"),
        include_str!("../../../../apps/web/db/migrations/0045_b431_subscription_ends_at.sql"),
        // GWY-49: the per-provider ZDR capability reference table the gateway's
        // `zdr.rs` refresher reads. Prod gets it by hand BEFORE the deploy (S2).
        include_str!("../../../../apps/web/db/migrations/0046_gwy49_provider_capabilities.sql"),
        // ADR-078 (B): the canonical ledger rows + anchor records. Prod gets it by
        // hand, then the CH → PG backfill, THEN the gateway that writes here (S2).
        include_str!("../../../../apps/web/db/migrations/0047_adr078_ledger_canonical_pg.sql"),
        include_str!(
            "../../../../apps/web/db/migrations/0048_api_keys_scheduled_revoke_notify.sql"
        ),
        // P0-4: f_cache_control + the per-plan TTL ceiling. Registered here because a
        // fresh database — and EVERY Postgres integration test — builds its schema from
        // this list, so a migration that exists only as a file is a migration prod's
        // tests never exercise. check-migration-list-complete.py caught the omission.
        include_str!("../../../../apps/web/db/migrations/0049_request_cache_control.sql"),
        // GWY-27: per-workspace model aliases (`crate::db::model_aliases`).
        include_str!("../../../../apps/web/db/migrations/0050_model_aliases.sql"),
        // GWY-52: per-workspace failover (`crate::db::workspace_failover`).
        include_str!("../../../../apps/web/db/migrations/0051_workspace_failover.sql"),
        // GWY-53: per-workspace content capture (`crate::db::workspace_capture`).
        include_str!("../../../../apps/web/db/migrations/0052_workspace_content_capture.sql"),
        // B-459: purged-tenant tombstones (`crate::retention_sweep`).
        include_str!("../../../../apps/web/db/migrations/0053_purged_tenants.sql"),
        include_str!("../../../../apps/web/db/migrations/0054_og08_passthrough_scope_comment.sql"),
        // B-409: versioned allowances (`plan_allowances`) + `tenants.plan_version`. S2 —
        // prod gets it by hand, then the seed, BEFORE the gateway that reads them.
        include_str!("../../../../apps/web/db/migrations/0055_b409_plan_allowances_versioned.sql"),
        // OG-23: `projects` + `api_keys.project_id` / `environment`. S2 — read by the
        // API-key auth JOIN; prod gets it by hand BEFORE the gateway.
        include_str!("../../../../apps/web/db/migrations/0056_og23_projects_environments.sql"),
        // OG-20: `api_keys.policy` + `projects.policy`. S2, after 0056.
        include_str!("../../../../apps/web/db/migrations/0057_og20_key_policy.sql"),
        // OG-35: `admin_audit_log` gains request_id / actor_role / actor_auth_method and
        // becomes append-only. S2 — before the gateway that writes the columns.
        include_str!(
            "../../../../apps/web/db/migrations/0058_og35_admin_audit_log_append_only.sql"
        ),
        // OG-36: `tenant_admin_security` (admin IP allowlist + SSO-required). S2.
        include_str!("../../../../apps/web/db/migrations/0059_og36_tenant_admin_security.sql"),
        // OG-25 / OG-21 / OG-22: `workspace_controls`. S2 — read by the entitlement resolve.
        include_str!("../../../../apps/web/db/migrations/0060_og25_workspace_controls.sql"),
        // OG-24: spend alert channels + outbox. S2.
        include_str!("../../../../apps/web/db/migrations/0061_og24_spend_alerts.sql"),
        // rev6 residual: `api_keys (created_at)` partial index for the valid-key-set delta
        // read. Index only — nothing depends on it, so no serialization point.
        include_str!("../../../../apps/web/db/migrations/0062_api_keys_created_at_idx.sql"),
        // SET-60: `signups` (operator's sign-in list; web-written, gateway reads nothing). S2.
        include_str!("../../../../apps/web/db/migrations/0063_signups.sql"),
        include_str!("../../../../apps/web/db/migrations/0064_account_deletions.sql"),
        include_str!("../../../../apps/web/db/migrations/0065_og30_guardrail_policies.sql"),
        include_str!("../../../../apps/web/db/migrations/0066_guardrail_hooks.sql"),
        include_str!("../../../../apps/web/db/migrations/0067_og37_tenant_kms.sql"),
        // OG-11: `provider_keys.label` + the three-column PK, and `workspace_routing`.
        // S2 — the gateway's boot schema check refuses to start without both.
        include_str!("../../../../apps/web/db/migrations/0070_og11_routing.sql"),
        // OG-51: `workspace_cache_settings`, `cache_epochs`, `api_keys.cache`. S2 — read by the
        // entitlement resolve; prod gets it by hand BEFORE the gateway.
        include_str!("../../../../apps/web/db/migrations/0075_og51_cache_controls.sql"),
        // OG-50: `otel_exports` + `plan_entitlements.f_otel_export / max_exports`. S2 — the
        // entitlement query reads the plan columns; prod gets it by hand, then the seed, BEFORE
        // the gateway.
        include_str!("../../../../apps/web/db/migrations/0076_og50_otel_exports.sql"),
        include_str!("../../../../apps/web/db/migrations/0077_og11_key_labels.sql"),
    ];
    for migration in MIGRATIONS {
        client
            .batch_execute(migration)
            .await
            .with_context(|| "Drizzle migration batch failed".to_string())?;
    }
    Ok(())
}
