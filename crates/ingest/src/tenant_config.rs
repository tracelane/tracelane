//! Per-tenant ingest config cache (ADR-048 D4.1).
//!
//! The tail sampler lives in INGEST and is tenant-blind by design
//! (`tail_sampler::evaluate(span, policy)` takes the policy as an argument).
//! This cache is what resolves the per-tenant [`SamplingPolicy`] the writer
//! feeds it — covering BOTH span sources uniformly (gateway-proxied AND
//! SDK/OTLP-direct), because resolution happens at ingest after the sources
//! merge. See the sampling-mechanism design.
//!
//! Design (mirrors the gateway `entitlement_cache` pattern, CLAUDE.md
//! control-plane rule): an in-process cache keyed by `tenant_id`, an injectable
//! async resolver, and a TTL that bounds staleness. Correctness never depends on
//! LISTEN/NOTIFY delivery — the 30s TTL is the floor; a `tenant_config_changed`
//! NOTIFY listener (migration 14) calls [`TenantConfigCache::invalidate`] as an
//! optimisation when wired.
//!
//! **Two distinct fail directions (do not conflate):**
//! - A **never-seen / no-row tenant** (the resolver *succeeds* but finds no
//!   config) resolves to the cheaper [`SamplingPolicy::Tail`] — a non-entitled
//!   tenant must not get unbounded Full.
//! - A **resolver FAULT** (pool/query error — a control-plane blip) resolves to
//!   [`TenantConfig::fault_keep_all`] = **Full, keep every span** regardless of
//!   the tail rate (bounded by the per-trace ceiling), so a DB outage never
//!   silently drops benign spans (the #81 class). Founder-decided (data-safe over
//!   COGS-safe on a fault); a sustained outage trades elevated cost for zero loss.
//!   This is paired with the startup fail-open in `db.rs` (a PG blip at boot does
//!   not stop ingest; the resolver auto-recovers when PG returns).
//!
//! ## The production resolver (Postgres)
//!
//! [`TenantConfigCache::default_tail`] resolves every tenant to `Tail`; it is
//! correct when no control plane is wired. The production resolver queries the
//! Neon control plane and computes the ADR-048 precedence (highest wins):
//!
//! 1. **Audit SKU active** (`f_audit_addon`) → `Full`, forced (a tamper-evident
//!    record of every action cannot tail-drop spans; non-overridable — matrix §4).
//! 2. **`force_tail` kill-switch** (ADR-048 D4.4) → `Tail` (bounds a runaway
//!    tenant without a deploy; does NOT override the audit guarantee above).
//! 3. **`f_full_capture` granted AND `tenants.sampling_policy = 'full'`** →
//!    `Full`.
//! 4. otherwise → `Tail`.
//!
//! Audit-SKU-active is read from `f_audit_addon` (the entitlements mirror in
//! migration 09 — reliably present), NOT the Drizzle-only `tenants.audit_enabled`
//! column (which the SQL migrations never create — referencing it would fail at
//! runtime; the recurring SQL↔Drizzle drift). SQL (resolved by `tenant_id`,
//! never request body) — also yields the ingest quota cap and billing email:
//! ```sql
//! SELECT t.sampling_policy, t.force_tail, t.billing_email,
//!        COALESCE(we.f_full_capture, pe.f_full_capture, FALSE) AS f_full_capture,
//!        COALESCE(we.f_audit_addon,  pe.f_audit_addon,  FALSE) AS f_audit_addon,
//!        (COALESCE(we.trace_quota_monthly, pe.trace_quota_monthly, 0)
//!         * COALESCE(we.overage_hard_cap_multiplier, pe.overage_hard_cap_multiplier, 1.0))::BIGINT
//!          AS quota_cap
//! FROM tenants t
//! LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id
//! LEFT JOIN plan_entitlements      pe ON pe.plan_lookup_key = we.plan_lookup_key
//! WHERE t.id = $1
//! ```
//! [`pg_tenant_config_resolver`] runs exactly this, maps the row → [`PolicyInputs`]
//! (→ [`resolve_policy`]) + `monthly_span_quota` (the cap, in spans) +
//! `billing_email`. A *no-row* result → Tail (cheap); a *query fault* →
//! [`TenantConfig::fault_keep_all`] (keep-all). [`spawn_listen_task`] keeps the
//! cache fresh via LISTEN/NOTIFY.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use dashmap::DashMap;
use uuid::Uuid;

use crate::db::DbPool;
use crate::tail_sampler::SamplingPolicy;

/// Resolved per-tenant ingest config. Carries the sampling policy + the ingest
/// quota cap + billing contact; the design reserves room for `retention_days`
/// (the TTL task shares this one cache).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantConfig {
    pub policy: SamplingPolicy,
    /// Monthly ingest **span** quota — the hard cap = `trace_quota_monthly ×
    /// overage_hard_cap_multiplier` (5× paid, 99× Enterprise; ADR-048 D5).
    /// `0` = unlimited (the default until the Postgres resolver supplies a real
    /// per-tenant cap — non-regressing on a fresh deploy).
    pub monthly_span_quota: u64,
    /// Tenant billing contact for the quota-breach email (ADR-048 D5). `None`
    /// until the Postgres resolver populates it.
    pub billing_email: Option<String>,
}

impl TenantConfig {
    /// The fail-config returned when a resolver query FAULTS at runtime (pool /
    /// query error) — distinct from a legitimate Tail resolution or an
    /// unknown-tenant no-row (both of which return [`TenantConfig::default`] =
    /// Tail). A control-plane blip must NOT silently drop benign spans (the #81
    /// class), so a fault keeps **every** span (Full) regardless of the tail
    /// rate, still bounded by the per-trace ceiling, with a **finite**
    /// `fault_quota` cap (review P1-1) so a sustained/induced fault hard-stops
    /// rather than running uncapped. Trade-off (founder-accepted): a sustained
    /// outage keeps everything at elevated cost up to that cap. This
    /// deliberately reverses the design's original "fail-safe to the cheaper
    /// policy" for the fault path; a planned Tail (entitlement says so) is
    /// unaffected and still cheap.
    pub fn fault_keep_all(fault_quota: u64) -> Self {
        Self {
            policy: SamplingPolicy::Full,
            // FINITE (review P1-1): generous for a brief blip, but a sustained or
            // induced fault hard-stops at the cap instead of running uncapped.
            monthly_span_quota: fault_quota,
            billing_email: None,
        }
    }
}

/// The control-plane inputs that decide a tenant's capture policy. Kept separate
/// from the DB layer so the precedence ([`resolve_policy`]) is pure + testable.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyInputs {
    /// `tenants.sampling_policy == 'full'` — the tenant's preference.
    pub wants_full: bool,
    /// `f_full_capture` resolved (plan default ∪ workspace override).
    pub full_capture_entitled: bool,
    /// Audit SKU active — resolved from `f_audit_addon` (the entitlements
    /// mirror; the ingest resolver does not read the Drizzle-only
    /// `tenants.audit_enabled`, which the SQL migrations never create).
    pub audit_active: bool,
    /// `tenants.force_tail` operational kill-switch.
    pub force_tail: bool,
}

/// The ADR-048 capture-policy precedence. Pure; the production Postgres resolver
/// maps a DB row into [`PolicyInputs`] and calls this.
///
/// Precedence (highest first): audit-forced Full → force_tail kill-switch →
/// entitled-and-wants Full → Tail.
pub fn resolve_policy(i: PolicyInputs) -> SamplingPolicy {
    if i.audit_active {
        // Non-overridable: the audit completeness guarantee beats the
        // kill-switch (a runaway audited tenant is bounded by the per-trace
        // ceiling + quota 429, never by silently dropping audited spans).
        return SamplingPolicy::Full;
    }
    if i.force_tail {
        return SamplingPolicy::Tail;
    }
    if i.full_capture_entitled && i.wants_full {
        return SamplingPolicy::Full;
    }
    SamplingPolicy::Tail
}

/// Boxed async resolver: `tenant_id -> TenantConfig`. Production injects a
/// Postgres-backed closure (see module docs); tests inject a map-backed mock.
/// A resolver MUST resolve internal errors to the safe default (Tail) itself.
pub type ResolveFn =
    Arc<dyn Fn(Uuid) -> Pin<Box<dyn Future<Output = TenantConfig> + Send>> + Send + Sync>;

struct Cached {
    cfg: TenantConfig,
    fetched_at: Instant,
}

/// In-process per-tenant config cache with a TTL fallback.
pub struct TenantConfigCache {
    resolver: ResolveFn,
    ttl: Duration,
    entries: DashMap<Uuid, Cached>,
}

impl TenantConfigCache {
    /// Construct with an injected resolver and a TTL staleness bound.
    pub fn new(resolver: ResolveFn, ttl: Duration) -> Self {
        Self {
            resolver,
            ttl,
            entries: DashMap::new(),
        }
    }

    /// A cache that resolves every tenant to `Tail` with an unlimited quota —
    /// correct when no control plane (Postgres) is wired. Non-regressing: with
    /// the writer's tail rate at 100 this keeps every span (the post-#81
    /// behaviour) and the unlimited quota rejects nothing; the Postgres resolver
    /// turns the ADR-048 levers on.
    pub fn default_tail() -> Self {
        Self::default_with_quota(0)
    }

    /// Like [`default_tail`](Self::default_tail) but with a uniform default span
    /// quota (`0` = unlimited) applied to every tenant — a global anti-abuse
    /// backstop on the direct OTLP path until the Postgres resolver supplies real
    /// per-tenant caps.
    pub fn default_with_quota(default_quota: u64) -> Self {
        Self::new(
            Arc::new(move |_| {
                Box::pin(async move {
                    TenantConfig {
                        policy: SamplingPolicy::Tail,
                        monthly_span_quota: default_quota,
                        billing_email: None,
                    }
                })
            }),
            Duration::from_secs(30),
        )
    }

    /// Resolve+cache a tenant's full config (fresh entry or re-resolve past the
    /// TTL). The resolver is responsible for fail-safe (Tail) on error, so this
    /// never surfaces an error to the hot path.
    async fn resolve_into_cache(&self, tenant: Uuid) -> TenantConfig {
        if let Some(e) = self.entries.get(&tenant) {
            if e.fetched_at.elapsed() < self.ttl {
                return e.cfg.clone();
            }
        }
        let cfg = (self.resolver)(tenant).await;
        self.entries.insert(
            tenant,
            Cached {
                cfg: cfg.clone(),
                fetched_at: Instant::now(),
            },
        );
        cfg
    }

    /// Resolve a tenant's sampling policy (writer hot path).
    pub async fn policy_for(&self, tenant: Uuid) -> SamplingPolicy {
        self.resolve_into_cache(tenant).await.policy
    }

    /// Resolve a tenant's full config — quota cap + billing email (OTLP receiver
    /// quota path).
    pub async fn config_for(&self, tenant: Uuid) -> TenantConfig {
        self.resolve_into_cache(tenant).await
    }

    /// Drop a tenant's cached config — the LISTEN/NOTIFY invalidation hook
    /// (`tenant_config_changed`, migration 14). The next `policy_for` re-resolves.
    pub fn invalidate(&self, tenant: Uuid) {
        self.entries.remove(&tenant);
    }

    /// Drop every cached config — the `NOTIFY entitlements_changed, 'ALL'` hook
    /// (a `plan_entitlements` change affects every tenant on that plan).
    pub fn invalidate_all(&self) {
        self.entries.clear();
    }
}

/// Production resolver: read each tenant's config from the Neon control plane.
/// Computes the ADR-048 policy precedence ([`resolve_policy`]) + the ingest quota
/// cap (`trace_quota_monthly × overage_hard_cap_multiplier`, in spans) + billing
/// email. Two fail directions: an unknown tenant (query OK, no row) → cheap
/// `Tail`; a pool/query **fault** → [`TenantConfig::fault_keep_all`] (Full,
/// keep-all) with the finite `fault_quota` cap. The hot path never sees an error.
pub fn pg_tenant_config_resolver(pool: DbPool, fault_quota: u64) -> ResolveFn {
    Arc::new(move |tenant: Uuid| {
        let pool = pool.clone();
        Box::pin(async move {
            match resolve_one(&pool, tenant).await {
                Ok(cfg) => cfg,
                Err(e) => {
                    // THREE WEEKS after a migration, promoting every tenant to Full
                    // capture and leaving force_tail inert, and the per-resolve `warn!`
                    // below was the only trace of it — a line nobody greps, in a log
                    // nobody tails, that looks identical on resolve #1 and #3,000,000.
                    // The counter carries first_seen, so "how long has this been open?"
                    // now has an answer.
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::TenantConfigFault,
                    );
                    tracing::warn!(
                        %tenant, error = %e, fault_quota,
                        "tenant config resolve FAULTED — keep-all (Full) so a control-plane blip \
                         never drops benign spans (#81 class); bounded by the per-trace ceiling \
                         + the finite fault quota"
                    );
                    TenantConfig::fault_keep_all(fault_quota)
                }
            }
        })
    })
}

const RESOLVE_SQL: &str = "\
    SELECT t.sampling_policy, t.force_tail, t.billing_email, \
      COALESCE(we.f_full_capture, pe.f_full_capture, FALSE), \
      COALESCE(we.f_audit_addon, pe.f_audit_addon, FALSE), \
      (COALESCE(we.trace_quota_monthly, pe.trace_quota_monthly, 0) \
       * COALESCE(we.overage_hard_cap_multiplier, pe.overage_hard_cap_multiplier, 1.0))::BIGINT \
    FROM tenants t \
    LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id \
    LEFT JOIN plan_entitlements pe ON pe.plan_lookup_key = we.plan_lookup_key \
    WHERE t.id = $1";

async fn resolve_one(pool: &DbPool, tenant: Uuid) -> anyhow::Result<TenantConfig> {
    let client = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    let Some(row) = client.query_opt(RESOLVE_SQL, &[&tenant]).await? else {
        // Unknown tenant (no row) → fail-safe default.
        return Ok(TenantConfig::default());
    };
    let sampling_policy: String = row.get(0);
    let force_tail: bool = row.get(1);
    let billing_email: Option<String> = row.get(2);
    let f_full_capture: bool = row.get(3);
    let f_audit_addon: bool = row.get(4);
    let quota_cap: i64 = row.get(5);

    let policy = resolve_policy(PolicyInputs {
        wants_full: sampling_policy.eq_ignore_ascii_case("full"),
        full_capture_entitled: f_full_capture,
        audit_active: f_audit_addon,
        force_tail,
    });
    Ok(TenantConfig {
        policy,
        monthly_span_quota: quota_cap.max(0) as u64,
        billing_email,
    })
}

/// Spawn the long-lived LISTEN task that evicts cache entries on control-plane
/// change. Uses a **dedicated direct** connection (`POSTGRES_DIRECT_URL`, else
/// `POSTGRES_URL`) — LISTEN/NOTIFY does not survive a PgBouncer pooler. Listens
/// on `entitlements_changed` (migration 12) AND `tenant_config_changed`
/// (migration 14). Reconnects with backoff; the 30s TTL bounds staleness in the
/// gap. **LISTEN is disabled only when BOTH vars are unset** (the fallback is an
/// `or_else`) — correctness never depends on NOTIFY delivery.
///
/// connects to PgBouncer, where `LISTEN` succeeds and no notification can ever
/// arrive. `listen_once` inspects the resolved HOST and reports `DEGRADED`
/// rather than `active` in that case — see `tracelane_shared::listen_dsn`.
pub fn spawn_listen_task(cache: Arc<TenantConfigCache>) {
    // switch as the gateway (`entitlement_cache::control_plane_listen_enabled`).
    // Ingest's listener died in the SAME MILLISECOND as the gateway's on all 110
    // observed cycles, which is what identified the cause as the Neon compute
    // suspending rather than either container's network. Correctness here never
    // depended on NOTIFY — the 30s TTL is the floor and always was.
    if !std::env::var("TRACELANE_CONTROL_PLANE_LISTEN").is_ok_and(|v| v == "1") {
        tracing::info!(
            "tenant-config LISTEN DISABLED (default; set TRACELANE_CONTROL_PLANE_LISTEN=1 to \
             enable) — tenant-config invalidation is TTL-bound (30s), which is the floor it \
             always relied on"
        );
        return;
    }
    let Some(conn_str) = std::env::var("POSTGRES_DIRECT_URL")
        .ok()
        .or_else(|| std::env::var("POSTGRES_URL").ok())
    else {
        tracing::info!(
            "no POSTGRES_DIRECT_URL/POSTGRES_URL — tenant-config LISTEN disabled (TTL-only)"
        );
        return;
    };
    tokio::spawn(async move {
        loop {
            if let Err(e) = listen_once(&conn_str, &cache).await {
                tracing::warn!(error = %e, "tenant-config LISTEN error; reconnecting");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// The first TCP host in `cfg` that is a pooler and therefore cannot deliver
///
/// Reads the host from the PARSED config, never a substring of the DSN — a
/// password may contain `-pooler`. The predicate lives in
/// `tracelane_shared::listen_dsn` so ingest and the gateway agree on what
/// "pooled" means.
fn pooled_listen_host(cfg: &tokio_postgres::Config) -> Option<String> {
    use tokio_postgres::config::Host;
    cfg.get_hosts().iter().find_map(|h| match h {
        Host::Tcp(host) if tracelane_shared::listen_dsn::host_cannot_deliver_notify(host) => {
            Some(host.clone())
        }
        _ => None,
    })
}

async fn listen_once(conn_str: &str, cache: &TenantConfigCache) -> anyhow::Result<()> {
    use futures::StreamExt as _;
    use tokio_postgres::AsyncMessage;

    // Neon's URL sets `channel_binding=require`, but the rustls connector does
    // not expose tls-server-end-point binding → downgrade to Prefer (SCRAM
    // without binding), matching the pool path.
    let mut pg_cfg: tokio_postgres::Config =
        conn_str.parse().context("parse LISTEN connection string")?;
    pg_cfg.channel_binding(tokio_postgres::config::ChannelBinding::Prefer);
    // A LISTEN connection carries NO traffic by design, so a socket that dies
    // silently — a half-open TCP with no FIN, which is what a cloud proxy or a
    // compute restart can leave behind — is invisible to it. `poll_message` just
    // stays Pending, the driver task never ends, the channel never closes, and the
    // reconnect loop below is never reached. It does not fail; it waits forever.
    //
    // EARNED 2026-08-11: after a Neon compute restart, ingest's LISTEN went silent
    // and never reconnected — no error line, no reconnect line — while the gateway,
    // which happened to receive a clean FIN, reconnected in 3 seconds. tokio-postgres
    // defaults to a 2-HOUR keepalive idle, so the dead listener would have gone
    // unnoticed for two hours, and nothing would have said so. Correctness survived
    // on the TTL fallback; the silence is the defect.
    //
    // 30s idle + a bounded user timeout turns "waits forever" into "reconnects in
    // under a minute, loudly".
    pg_cfg.keepalives(true);
    pg_cfg.keepalives_idle(std::time::Duration::from_secs(30));
    pg_cfg.keepalives_interval(std::time::Duration::from_secs(10));
    pg_cfg.keepalives_retries(3);
    pg_cfg.tcp_user_timeout(std::time::Duration::from_secs(60));
    let (client, mut conn) = pg_cfg.connect(crate::db::pg_tls_connector()?).await?;

    // Drive the connection on a task BEFORE issuing LISTEN (polling only after
    // batch_execute deadlocks the setup).
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AsyncMessage>();
    let driver = tokio::spawn(async move {
        let mut messages = futures::stream::poll_fn(move |cx| conn.poll_message(cx));
        while let Some(msg) = messages.next().await {
            match msg {
                Ok(m) => {
                    if tx.send(m).is_err() {
                        break;
                    }
                }
                Err(e) => return Err(anyhow::Error::new(e).context("LISTEN connection")),
            }
        }
        Ok(())
    });

    client
        .batch_execute("LISTEN entitlements_changed; LISTEN tenant_config_changed")
        .await?;
    // `batch_execute` proves nothing about NOTIFY delivery. Ask the resolved
    // host instead of reporting "active" unconditionally.
    match pooled_listen_host(&pg_cfg) {
        Some(host) => tracing::warn!(
            host = %host,
            "tenant-config LISTEN DEGRADED — connected to a POOLED endpoint that cannot \
             deliver NOTIFY; tenant-config invalidation is TTL-only. Set POSTGRES_DIRECT_URL \
             to the direct (non-pooler) endpoint."
        ),
        None => tracing::info!(
            "tenant-config LISTEN active (entitlements_changed + tenant_config_changed)"
        ),
    }

    while let Some(msg) = rx.recv().await {
        if let AsyncMessage::Notification(note) = msg {
            let payload = note.payload();
            if payload == "ALL" {
                cache.invalidate_all();
                tracing::debug!("tenant-config cache fully invalidated via NOTIFY ALL");
            } else if let Ok(tenant) = Uuid::parse_str(payload) {
                cache.invalidate(tenant);
                tracing::debug!(%tenant, "tenant-config cache entry invalidated via NOTIFY");
            }
        }
    }

    match driver.await {
        Ok(res) => res,
        Err(join) => Err(anyhow::Error::new(join).context("LISTEN driver task")),
    }
}

#[cfg(test)]
mod tests {

    /// deployment produces, and must NOT fire on a direct endpoint whose
    /// PASSWORD merely contains `-pooler` (the case that makes a DSN substring
    /// check wrong). Driven from DSN strings so the whole parse->host->predicate
    /// path is covered, not just the predicate.
    #[test]
    fn pooled_endpoint_reported_degraded_direct_endpoint_not() {
        let pooled: tokio_postgres::Config =
            "postgres://u:pw@ep-x-pooler.eu-central-1.aws.neon.tech/db"
                .parse()
                .expect("parse");
        assert_eq!(
            super::pooled_listen_host(&pooled).as_deref(),
            Some("ep-x-pooler.eu-central-1.aws.neon.tech")
        );

        let direct: tokio_postgres::Config = "postgres://u:pw@ep-x.eu-central-1.aws.neon.tech/db"
            .parse()
            .expect("parse");
        assert!(super::pooled_listen_host(&direct).is_none());

        let trap_dsn = "postgres://u:s3cret-pooler@ep-x.eu-central-1.aws.neon.tech/db";
        assert!(
            trap_dsn.contains("-pooler"),
            "fixture must exercise the trap"
        );
        let trap: tokio_postgres::Config = trap_dsn.parse().expect("parse");
        assert!(
            super::pooled_listen_host(&trap).is_none(),
            "a -pooler in the PASSWORD must not be read as a pooled host"
        );
    }

    /// A LISTEN socket that dies silently must be DETECTED, not waited on.
    ///
    /// The 2026-08-11 incident: after a Neon compute restart ingest's listener went
    /// silent and never reconnected — no error, no reconnect — because
    /// tokio-postgres defaults to a 2-hour keepalive idle and `poll_message` simply
    /// stayed Pending on a half-open socket. This asserts the config we now build
    /// actually carries a short keepalive, which is the difference between "waits
    /// two hours" and "reconnects in under a minute".
    #[test]
    fn listen_config_sets_a_short_keepalive_not_the_two_hour_default() {
        let mut cfg: tokio_postgres::Config = "postgresql://u:p@h/db".parse().expect("parse");
        cfg.channel_binding(tokio_postgres::config::ChannelBinding::Prefer);
        cfg.keepalives(true);
        cfg.keepalives_idle(std::time::Duration::from_secs(30));

        assert_eq!(
            cfg.get_keepalives_idle(),
            std::time::Duration::from_secs(30),
            "a LISTEN connection carries no traffic, so the keepalive IS the liveness check"
        );
        assert!(
            cfg.get_keepalives(),
            "keepalives must be on for a silent socket"
        );
        assert!(
            cfg.get_keepalives_idle() <= std::time::Duration::from_secs(60),
            "anything near tokio-postgres' 2-hour default reproduces the incident"
        );
    }
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn full() -> TenantConfig {
        TenantConfig {
            policy: SamplingPolicy::Full,
            ..Default::default()
        }
    }

    ///
    /// The production resolver returns `TenantConfig`, never `Result`, so a control-plane
    /// fault is structurally invisible to every caller: the hot path receives a perfectly
    /// valid `fault_keep_all` config and cannot tell it apart from a real one. That is how
    /// this faulted continuously for THREE WEEKS, promoting every tenant to Full capture
    /// against their entitlement and leaving `force_tail` inert, with nothing but a
    /// per-resolve `warn!` nobody was reading.
    ///
    /// Drives the real fault: a pool pointed at a closed port, so `resolve_one` genuinely
    /// errors and the `Err` arm runs. Asserts BOTH halves — the fallback config is still
    /// returned (fail-open preserved) AND the counter moved (no longer silent).
    ///
    /// Delta, not absolute — the registry is process-global.
    #[tokio::test]
    async fn resolver_fault_advances_the_degradation_counter() {
        use tracelane_shared::degradation::{Degradation, count};

        // Port 1 on loopback: nothing listens, so pool.get() fails fast. deadpool is
        // lazy, so building the pool itself does not connect.
        let mut cfg = deadpool_postgres::Config::new();
        cfg.host = Some("127.0.0.1".to_string());
        cfg.port = Some(1);
        cfg.user = Some("nobody".to_string());
        cfg.dbname = Some("nodb".to_string());
        let pool = cfg
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .expect("pool config is valid; connecting is what must fail");

        let fault_quota = 4_242;
        let resolver = pg_tenant_config_resolver(pool, fault_quota);

        let before = count(Degradation::TenantConfigFault);
        let cfg_out = resolver(uuid::Uuid::from_u128(0xB187)).await;
        let after = count(Degradation::TenantConfigFault);

        assert_eq!(
            cfg_out.policy,
            SamplingPolicy::Full,
            "fail-open must be PRESERVED — a control-plane blip must not drop benign spans"
        );
        assert!(
            after > before,
            "a faulting resolver must advance the degradation counter (before={before}, \
             after={after}) — otherwise three weeks of every-tenant-promoted looks exactly \
             like a healthy control plane"
        );
    }

    // ── resolve_policy precedence (pure) ──────────────────────────────────

    #[test]
    fn audit_forces_full_even_over_kill_switch_and_no_entitlement() {
        // Audit beats force_tail and needs no f_full_capture grant.
        let p = resolve_policy(PolicyInputs {
            audit_active: true,
            force_tail: true,
            full_capture_entitled: false,
            wants_full: false,
        });
        assert_eq!(p, SamplingPolicy::Full);
    }

    #[test]
    fn kill_switch_forces_tail_over_a_full_grant() {
        let p = resolve_policy(PolicyInputs {
            audit_active: false,
            force_tail: true,
            full_capture_entitled: true,
            wants_full: true,
        });
        assert_eq!(p, SamplingPolicy::Tail);
    }

    #[test]
    fn entitled_and_wanting_full_resolves_full() {
        let p = resolve_policy(PolicyInputs {
            full_capture_entitled: true,
            wants_full: true,
            ..Default::default()
        });
        assert_eq!(p, SamplingPolicy::Full);
    }

    #[test]
    fn entitled_but_not_wanting_full_stays_tail() {
        // Business/Enterprise that left sampling_policy='tail' stays tail.
        let p = resolve_policy(PolicyInputs {
            full_capture_entitled: true,
            wants_full: false,
            ..Default::default()
        });
        assert_eq!(p, SamplingPolicy::Tail);
    }

    #[test]
    fn wanting_full_without_entitlement_is_ignored() {
        // A non-entitled tenant that set 'full' resolves to Tail (fail-safe).
        let p = resolve_policy(PolicyInputs {
            full_capture_entitled: false,
            wants_full: true,
            ..Default::default()
        });
        assert_eq!(p, SamplingPolicy::Tail);
    }

    #[test]
    fn fault_keep_all_is_full_with_finite_quota_distinct_from_default_tail() {
        // A runtime resolver FAULT keeps every span (Full) regardless of the
        // tail rate — a control-plane blip must not drop benign spans (#81
        // class) — but with a FINITE quota (review P1-1) so a sustained/induced
        // fault hard-stops, not uncapped. An unknown-tenant/no-row resolution is
        // NOT a fault and stays the cheaper Tail default.
        let fault = TenantConfig::fault_keep_all(25_000_000);
        assert_eq!(fault.policy, SamplingPolicy::Full);
        assert_eq!(
            fault.monthly_span_quota, 25_000_000,
            "fault quota is FINITE (P1-1), not unlimited"
        );
        assert_ne!(
            fault.monthly_span_quota, 0,
            "a fault must NOT be uncapped/unlimited"
        );
        assert_eq!(
            TenantConfig::default().policy,
            SamplingPolicy::Tail,
            "the non-fault default (unknown tenant) stays cheap Tail"
        );
    }

    // ── cache behaviour ───────────────────────────────────────────────────

    #[tokio::test]
    async fn default_tail_resolves_every_tenant_to_tail() {
        let c = TenantConfigCache::default_tail();
        assert_eq!(c.policy_for(Uuid::from_u128(1)).await, SamplingPolicy::Tail);
    }

    #[tokio::test]
    async fn resolver_differentiates_tenants_and_caches_hits() {
        let full_tenant = Uuid::from_u128(0xF);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let resolver: ResolveFn = Arc::new(move |t: Uuid| {
            let calls = calls2.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if t == full_tenant {
                    full()
                } else {
                    TenantConfig::default()
                }
            })
        });
        let c = TenantConfigCache::new(resolver, Duration::from_secs(300));

        // Per-tenant differentiation: the full tenant keeps, others tail.
        assert_eq!(c.policy_for(full_tenant).await, SamplingPolicy::Full);
        assert_eq!(c.policy_for(Uuid::from_u128(2)).await, SamplingPolicy::Tail);
        // A warm hit does NOT re-resolve (one call per distinct tenant).
        assert_eq!(c.policy_for(full_tenant).await, SamplingPolicy::Full);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_forces_a_re_resolve() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let resolver: ResolveFn = Arc::new(move |_| {
            let calls = calls2.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                TenantConfig::default()
            })
        });
        let c = TenantConfigCache::new(resolver, Duration::from_secs(300));
        let t = Uuid::from_u128(7);
        c.policy_for(t).await;
        c.policy_for(t).await; // cached
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        c.invalidate(t);
        c.policy_for(t).await; // re-resolved
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn zero_ttl_always_re_resolves() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let resolver: ResolveFn = Arc::new(move |_| {
            let calls = calls2.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                TenantConfig::default()
            })
        });
        let c = TenantConfigCache::new(resolver, Duration::ZERO);
        let t = Uuid::from_u128(9);
        c.policy_for(t).await;
        c.policy_for(t).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "TTL=0 must re-resolve every call"
        );
    }

    /// never the old `tenant_id` column (prod `tenants` has no `tenant_id`). A
    /// revert would make the ingest resolver 500 against prod (same class as
    #[test]
    fn resolve_sql_uses_tenants_id_pk_not_tenant_id() {
        assert!(
            super::RESOLVE_SQL.contains("WHERE t.id = $1"),
            "must filter on tenants.id"
        );
        assert!(
            super::RESOLVE_SQL.contains("we.tenant_id = t.id"),
            "must join workspace_entitlements.tenant_id -> tenants.id"
        );
        assert!(
            !super::RESOLVE_SQL.contains("t.tenant_id"),
            "tenants has no tenant_id column (id-PK per ADR-040)"
        );
    }
}
