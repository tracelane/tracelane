//! Axum HTTP server — router, state, and handlers.
//!
//! Exposes:
//!   GET  /health                    — unauthenticated liveness probe
//!   POST /v1/chat/completions       — OpenAI-compatible chat endpoint
//!   POST /v1/embeddings             — OpenAI-compatible embeddings endpoint
//!
//! AppState bundles all shared components:
//!   providers    — ProviderRegistry (6 native adapters + every row of providers.tsv + failover chain)
//!   audit_chain  — AuditChain (SHA-256 hash chain + Rekor anchoring every 100 events)
//!   rate_limiter — RateLimiter (per-tenant token bucket, DashMap-backed single-node V1)
//!   predictive   — PredictiveLayer (8 predictors, inline on every request)
//!   nats         — Optional NATS client for span publish to ingest workers
//!
//! Streaming: when `"stream": true` is set in the request body, the provider's
//! SSE event stream is forwarded directly to the client in OpenAI chunk format.
//! Non-streaming requests buffer the full response before returning.

use anyhow::Context as _;
use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use std::{net::SocketAddr, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing::instrument;

use crate::audit::AuditChain;
use crate::predictive::PredictiveLayer;
use crate::providers::ProviderRegistry;
use crate::rate_limiter::RateLimiter;

/// `tracelane.yaml` reader (GWY-39) — `crates/gateway/src/config.rs`.
///
/// Declared here with `#[path]`, resolved relative to `src/`, rather than as a
/// `mod config;` in `main.rs`. The module is only ever reached through
/// `crate::server::config::…`; folding the declaration into `main.rs`'s module
/// list is a mechanical follow-up with no behaviour change.
#[path = "config.rs"]
pub mod config;

/// `OBS-48` shareable trace links (`crates/gateway/src/trace_share.rs`).
///
/// Declared here with `#[path]` rather than as a `mod trace_share;` in
/// `main.rs`, mirroring the `config` module immediately above: `main.rs` is
/// outside this change's edit scope, and nothing outside `server.rs` needs to
/// reach this module (unlike `config`, which many files read via
/// `crate::server::config::…`), so it stays private to this file's mount code.
#[path = "trace_share.rs"]
mod trace_share;

// ── B-385 §2d: the hot path, split by concern (2026-09-12) ──────────────────
//
// `server.rs` keeps what BOOTS the gateway — `Config`, `AppState`, `run()`
// (the router and every env-conditional mount), the admission layer, graceful
// shutdown, `/health` and `/v1/auth/whoami`. Everything a request runs through
// once it is routed lives in `server/`, one file per concern, declared here so
// `crate::server::…` paths keep resolving through the re-exports below:
//
//   chat.rs        `chat_completions_handler` — its `// --- Step N` markers are
//                  there (`grep -n 'Step' crates/gateway/src/server/chat.rs`);
//                  admission (auth → … → the fail-CLOSED `503 audit_unavailable`
//                  ledger publish) is `crate::admission`.
//   embeddings.rs  `embeddings_handler` (GWY-26).
//   dispatch.rs    BYOK key resolve, `dispatch_to_provider`, the A7 retry loop,
//                  the bench-mock gate, `DispatchGuard`, the post-ledger error
//                  span funnel.
//   stream.rs      `provider_stream_to_sse` + `StreamFinalizer` (B-375).
//   buffered.rs    `buffer_provider_stream` + the tool-call / finish-reason fold.
//   spans.rs       `build_gateway_span` and everything it is built from; the
//                  span-publish / billing / key-spend spawns.
//   errors.rs      the typed, scrubbed client-facing error responses.
//   quota.rs       the GWY-43 per-key/workspace spend baselines (BILL-01 /
//                  ADR-076 deleted the monthly trace-count quota + its
//                  notification seam entirely — see that file's module doc).
mod buffered;
mod chat;
mod dispatch;
mod embeddings;
mod errors;
mod quota;
mod spans;
mod stream;

pub(crate) use chat::chat_completions_handler;
pub(crate) use dispatch::{
    DispatchGuard, ProviderKey, REQUESTS_CANCELLED_IN_DISPATCH, bench_mock_active,
    dispatch_to_provider, resolve_provider_key,
};
pub(crate) use embeddings::embeddings_handler;
pub(crate) use errors::provider_error_response;
pub use quota::{WORKSPACE_SPEND_THIS_MONTH_SQL, next_month_boundary_iso};
pub(crate) use quota::{
    current_year_month, spend_baseline_from_clickhouse, workspace_spend_baseline_from_clickhouse,
};
pub(crate) use spans::{
    CallerIdentity, CapturedInput, GatewayTiming, RequestConfig, SpanUsageMeta, build_gateway_span,
    record_key_spend, spawn_span_publish,
};
pub(crate) use stream::STREAMS_FINALIZED_ON_DROP;

/// Gateway configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub log_level: String,
    /// PKCS#8 DER base64-encoded Ed25519 key for audit signing (ADR-057).
    /// If absent, signing is disabled (events are still hashed). Wrapped in
    /// `SecretString` (zeroize-on-drop; redacted in `Debug`) per security.md —
    /// this is key material, never a plain `String`.
    pub rekor_signing_key: Option<secrecy::SecretString>,
    /// Rekor anchor every N audit events (default: 100).
    pub rekor_anchor_every: usize,
    /// ClickHouse HTTP URL for audit_log persistence (e.g. http://localhost:8123).
    /// If absent, audit events are hashed and anchored but not stored in ClickHouse.
    pub clickhouse_url: Option<String>,
    /// NATS server URL for span publish to ingest workers.
    /// If absent, span publish is disabled (spans only appear as structured logs).
    pub nats_url: Option<String>,
    /// Benchmark-only: when true, requests for the reserved `__bench_mock*`
    /// models return an instant canned response instead of dispatching upstream,
    /// so a load test measures *gateway overhead* with ~0 provider time
    /// (`bench/gateway/`). Off by default; double-gated (this flag AND the
    /// reserved model prefix), so a normal tenant request can never reach it.
    /// Env: `TRACELANE_BENCH_MOCK_UPSTREAM=1`. NEVER set on a tenant-serving node.
    pub bench_mock_upstream: bool,
    /// `OBS-48` — the web app's public base URL, used ONLY to build the
    /// `url` field of a minted share link (`<web_base_url>/s/<token>`). The
    /// gateway never redirects here and never calls it; it is pure string
    /// composition. Env: `TRACELANE_WEB_URL`, default
    /// `https://app.tracelane.dev`.
    pub web_base_url: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            port: std::env::var("TRACELANE_PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .context("TRACELANE_PORT must be a valid port number")?,
            log_level: std::env::var("TRACELANE_LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            // `OTEL_EXPORTER_OTLP_ENDPOINT` was read here and used by nothing
            // (B-390, 2026-09-12): the log-only emitter it configured was never
            // called. The public self-hosting page that listed it as "export the
            // gateway's own spans" was corrected in the same change.
            rekor_signing_key: std::env::var("TRACELANE_REKOR_SIGNING_KEY")
                .ok()
                // Treat a set-but-empty value as "disabled" (the documented
                // self-host default is `TRACELANE_REKOR_SIGNING_KEY=` to disable
                // anchoring). Docker `${VAR:-}` interpolation passes an empty
                // string, which otherwise reaches the audit chain as an invalid
                // Ed25519 key and crash-loops the gateway at boot.
                .filter(|s| !s.trim().is_empty())
                .map(secrecy::SecretString::from),
            rekor_anchor_every: std::env::var("TRACELANE_REKOR_ANCHOR_EVERY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            clickhouse_url: std::env::var("CLICKHOUSE_URL").ok(),
            nats_url: std::env::var("NATS_URL").ok(),
            bench_mock_upstream: std::env::var("TRACELANE_BENCH_MOCK_UPSTREAM")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            web_base_url: match std::env::var("TRACELANE_WEB_URL") {
                Ok(v) if !v.trim().is_empty() => v,
                _ => "https://app.tracelane.dev".to_string(),
            },
        })
    }
}

/// Shared gateway state — cloned cheaply via `Arc` on every request.
#[derive(Clone)]
pub struct AppState {
    pub providers: Arc<ProviderRegistry>,
    /// GWY-24 semantic cache. `None` when `semantic_cache:` is absent from
    /// `tracelane.yaml` OR `CLICKHOUSE_URL` is unset — off is the only safe
    /// default, because a cache that turns itself on serves a remembered answer
    /// to somebody who never asked for one.
    pub semantic_cache: Option<Arc<crate::semantic_cache::SemanticCache>>,
    pub audit_chain: Arc<AuditChain>,
    pub rate_limiter: Arc<RateLimiter>,
    /// ClickHouse URL the GWY-43 per-key/workspace spend baselines rehydrate
    /// from on (re)start / month rollover, so a restart or blue-green deploy
    /// no longer forgives accrued spend. `None` (dev / no CH) disables
    /// rehydration — the counter starts at 0. Mirrors `config.clickhouse_url`.
    /// (BILL-01 / ADR-076: the monthly trace-count `quota_tracker` this field
    /// used to also serve is deleted; the name stays because the spend
    /// baselines are its only reader now and renaming it is out of this
    /// change's scope.)
    pub quota_ch_url: Option<String>,
    /// BILL-01 / ADR-076 — the gateway half of the six-meter usage model
    /// (ingest bytes, eval runs, per-key token/spend sub-meters). `None` when
    /// `CLICKHOUSE_URL` is unset — every record site is then a no-op. Mirrors
    /// the process-wide `billing::meters::global()` accessor (installed at
    /// boot, immediately below) so handlers that already hold `&AppState`
    /// never need the global lookup.
    pub meters: Option<Arc<crate::billing::MeterSink>>,
    /// BILL-01 / ADR-076 — the rate card (bands + policy) loaded from
    /// `pricing_rates` + `billing_policy`, refreshed on the SAME cadence as
    /// the entitlement cache (never per request — `.claude/rules/reference-tables.md`).
    /// `RateCard::unavailable()` before the first load or with no control
    /// plane; `/v1/billing/usage` reads this and reports `rates_available:
    /// false` rather than a fabricated number.
    pub rate_card: Arc<ArcSwap<crate::billing::RateCard>>,
    pub predictive: Arc<PredictiveLayer>,
    /// Predictive enforcement mode (ADR-055 amendment — flight-recorder posture).
    /// When FALSE (the DEFAULT), the predictive layer is OBSERVE-FIRST: a `Block`
    /// decision is RECORDED as a flagged event and the request PROCEEDS, so a
    /// false positive never breaks a legitimate agent run. Stopping agents is
    /// destructive, so it is opt-in: set `TRACELANE_PREDICTIVE_ENFORCE=1` to turn
    /// a `Block` into a real 403.
    pub predictive_enforce: bool,
    /// Inline guardrails engine (the guardrail spec) — request-side rail
    /// dispatch (R4 lethal-trifecta + future rails) over the parsed request,
    /// verdict recording to the tamper-evident ledger + ClickHouse mirror.
    /// Additive to `predictive`; a block short-circuits with 403.
    pub guardrail: Arc<crate::guardrail::GuardrailEngine>,
    /// NATS client for span publish. `None` when NATS_URL is unset — span
    /// data still appears in structured logs but is not forwarded to ingest.
    pub nats: Option<Arc<async_nats::Client>>,
    /// In-process entitlement cache (ADR-035). `None` when Postgres is unset
    /// (dev mode); the warm path never hits Neon. See `entitlement_cache.rs`.
    pub entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
    /// Per-`(provider, region)` circuit breakers (ADR-036). Bulkheads each
    /// upstream so one provider's failure can't exhaust the gateway.
    pub circuit_breaker: Arc<crate::circuit_breaker::CircuitBreaker>,
    /// Operational kill-switch / flag layer (ADR-038). Disable a predictor or
    /// force a provider open fleet-wide without a redeploy. Fail-safe defaults.
    pub kill_switch: Arc<crate::kill_switch::KillSwitch>,
    /// B1 prompt router (always present). Shared with the `/v1/prompts/*`
    /// sub-router; the chat handler feeds per-prompt-version drift metrics
    /// into its auto-rollback engine off the response path.
    pub prompt_router: Arc<crate::prompt_router::PromptRouter>,
    /// Benchmark-only instant-upstream flag (see [`Config::bench_mock_upstream`]).
    /// A single cheap bool read on the dispatch path; the mock branch is only
    /// considered when this is true AND the model is `__bench_mock*`.
    pub bench_mock_upstream: bool,
    /// B-386 (b) / BILL-01: the RPM a request resolves to when there is NO
    /// control plane (`entitlements` is `None`). Read ONCE at boot from
    /// `TRACELANE_SELF_HOST`
    /// (`rate_limiter::no_control_plane_rate_limit_rpm_from_env`); a test
    /// constructs it directly instead of mutating the process environment.
    /// Hosted deployments never read it: they have a control plane, so
    /// `entitlements` is `Some` and `ResolvedEntitlements.rate_limit_rpm`
    /// governs instead. `None` = unlimited (self-host default, B-357/F8).
    pub no_control_plane_rate_limit_rpm: Option<u32>,
    /// B-386 (b): the per-tenant rate-limit / quota rejection counters the
    /// `/v1/gateway` stats surface reports. Constructed here, shared with
    /// `TraceReadState` by `Arc` — one instance, no process global.
    pub rejection_metrics: Arc<crate::rejection_metrics::RejectionRegistry>,
    /// B-386 (b): the B-256 slow-request breakdown thresholds, read ONCE at boot.
    /// They used to be read from the environment on EVERY request inside
    /// `StageTimer::emit_if_slow`.
    pub hotpath: crate::hotpath::Config,
    /// B-386 (b): the `failover:` block of `tracelane.yaml`, read ONCE at boot
    /// from the installed file config. `None` ⇒ the built-in chain. A
    /// `&'static` because the file config is install-once for the process
    /// lifetime (`config::install_from_env`); a test passes `None` or a leaked
    /// block instead of installing a file.
    pub failover: Option<&'static self::config::FailoverConfig>,
    /// B-386 (b), EXPAND step: the control-plane pool as a field. `None` with no
    /// `POSTGRES_URL` (dev / OSS self-host). `db::global_pool()` still answers
    /// the same pool for the readers not yet converted; the static is deleted
    /// when its last reader is gone (migrate → contract).
    pub pg: Option<crate::db::DbPool>,
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    // GWY-39: read `tracelane.yaml` BEFORE anything routes. Model aliases are
    // consulted inside `ProviderRegistry::provider_id_for_model`, so installing
    // them after the first request would mean two different routing tables in
    // one process lifetime. Absent file ⇒ no aliases, no behaviour change;
    // present-but-invalid ⇒ this `?` refuses to boot (see `config::install_from_env`).
    self::config::install_from_env().context("tracelane.yaml")?;

    let providers = Arc::new(ProviderRegistry::new().context("build provider registry")?);

    // ADR-067: single-tenant self-host mode. `from_env` fail-closes if
    // TRACELANE_SELF_HOST=1 is set alongside any hosted/multi-tenant signal
    // (Postgres / WorkOS / a SPIRE socket) or without a valid single tenant id,
    // so this can NEVER activate in hosted. When active, wire the gateway auth
    // to authenticate every request as the one configured tenant (gated on the
    // operator's TRACELANE_MASTER_KEY) — self-host has no Postgres/WorkOS to
    // authenticate against, so without this the release gateway 401s every call.
    if let Some(sh) = tracelane_shared::self_host::from_env()
        .context("single-tenant self-host config (TRACELANE_SELF_HOST) is invalid")?
    {
        let master_key = std::env::var("TRACELANE_MASTER_KEY")
            .ok()
            .filter(|s| !s.is_empty())
            .map(secrecy::SecretString::from);
        if master_key.is_none() {
            tracing::warn!(
                "SINGLE-TENANT SELF-HOST: TRACELANE_MASTER_KEY unset — the gateway will accept ANY \
                 bearer token as the single tenant. Set TRACELANE_MASTER_KEY to require an auth secret."
            );
        }
        crate::auth::install_self_host_auth(sh.tenant_id().clone(), master_key);
        // ADR-067. The ref lives here, not in the string: an operator-visible log
        // line is a surface `no-internal-refs-in-ui` scans, and it was right to.
        tracing::warn!(
            single_tenant_id = %sh.tenant_id(),
            "SINGLE-TENANT SELF-HOST mode active — every request authenticates as this \
             one tenant; the Postgres/WorkOS auth paths are bypassed. Safe ONLY single-tenant."
        );
    }

    // API-key pepper — required when Postgres is present, because every
    // hot-path lookup needs to HMAC the key body. In release builds we
    // refuse to start without it (operator misconfig is louder than
    // silent fallback). Debug builds may continue with a deterministic
    // test pepper so the dev loop doesn't break.
    match std::env::var("TRACELANE_APIKEY_PEPPER") {
        Ok(raw) => crate::db::api_keys::init_pepper(&raw)
            .context("TRACELANE_APIKEY_PEPPER could not be decoded")?,
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                tracing::warn!(
                    "TRACELANE_APIKEY_PEPPER not set — initializing debug-only test pepper"
                );
                crate::db::api_keys::init_pepper(&"00".repeat(32))
                    .context("debug test pepper init failed")?;
            }
            #[cfg(not(debug_assertions))]
            {
                if std::env::var("POSTGRES_URL").is_ok() || std::env::var("PGHOST").is_ok() {
                    anyhow::bail!(
                        "TRACELANE_APIKEY_PEPPER is required in release builds when Postgres is configured"
                    );
                }
            }
        }
    }

    // A4: install the BYOK master key for the per-tenant provider-key path.
    // Without it the hot path silently falls back to the legacy env-var
    // resolution. Release builds with Postgres configured must have it.
    match crate::byok::ByokMasterKey::from_env().context("TRACELANE_BYOK_MASTER_KEY decode")? {
        Some(master) => {
            tracing::info!(
                loaded = ?master.loaded_keks(),
                active = master.active_kek(),
                "BYOK master key ring installed — per-tenant provider keys enabled"
            );
            crate::byok::set_global_master_key(master);
        }
        None => {
            #[cfg(not(debug_assertions))]
            if std::env::var("POSTGRES_URL").is_ok() || std::env::var("PGHOST").is_ok() {
                anyhow::bail!(
                    "TRACELANE_BYOK_MASTER_KEY is required in release builds when Postgres is configured (A4)"
                );
            }
            tracing::warn!(
                "TRACELANE_BYOK_MASTER_KEY unset — provider keys served from env vars only (dev mode)"
            );
        }
    }

    // Postgres pool — optional. If POSTGRES_URL is unset the gateway runs
    // in dev mode (api_key validation falls back to the dev-stub path).
    // Production sets POSTGRES_URL; the absence of the pool there means
    // api_key auth bails as designed.
    // B-386 (b), expand → migrate → contract: the pool is ALSO a field of
    // `AppState` (`pg`) from here on. `run()` and the chat handler read the
    // field; the remaining `db::global_pool()` readers (helpers with no state
    // handle, route families with their own state types) are converted per
    // module, and the static goes when its last reader does.
    let mut pg: Option<crate::db::DbPool> = None;
    if std::env::var("POSTGRES_URL").is_ok() || std::env::var("PGHOST").is_ok() {
        match crate::db::build_pool().await {
            Ok(pool) => {
                tracing::info!("Postgres pool ready");
                pg = Some(pool.clone());
                // B-256: hold a few pooled connections warm. Without this a
                // request arriving after an idle gap pays a fresh connect
                // (~94 ms measured) and, if the managed compute has suspended,
                // its resume (~1.2 s). See `db/keepalive.rs` — it documents what
                // breaks if this line is removed, because the keepalive this
                // replaces was an accidental side effect of the alert poller and
                // was deleted without anyone knowing it was load-bearing.
                crate::db::keepalive::spawn(pool.clone());
                // NEON-TO-ZERO 3a (founder, 2026-09-03): close idle pooled
                // connections so the pool alone cannot hold the compute awake.
                // Complements the keepalive rather than fighting it — when the
                // keepalive is ON it touches connections inside the idle budget.
                crate::db::idle_evict::spawn(pool.clone());
                // B-256: keep ACTIVE api-key entries warm against the control
                // plane. Without it a key presented less often than the 60s
                // cache TTL misses on every request and pays a Neon round trip
                // plus an Argon2id verify — the same defect the entitlement
                // cache already fixed for itself. The refresh interval becomes
                // the revocation bound, which is TIGHTER than the TTL it
                // replaces, so this is not a security relaxation.
                crate::db::api_keys::spawn_auth_cache_refresher(pool.clone());
                crate::db::set_global_pool(pool);
                // B-386 (a): with a control plane, this process must be the ONLY
                // gateway enforcing the per-process caps against it. Refuses
                // to boot if another holds the advisory lock (or says so in the
                // env); held for the process lifetime by the task below, which
                // re-acquires and notes a degradation while it is lost.
                if let Some(lock) = crate::db::singleton::acquire_at_boot().await? {
                    tokio::spawn(crate::db::singleton::hold(lock));
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "Postgres pool init failed — api_key validation will refuse");
            }
        }
    } else {
        tracing::info!(
            "POSTGRES_URL not set — running without DB. api_key validation falls back to dev stub."
        );
    }

    // Audit chain — built AFTER the Postgres pool so it can persist + warm the
    // per-tenant hash-chain state and sign anchors with per-tenant keys (ADR-042
    // bugs #4 + #5):
    //   #4: with `new()` (no pool) `audit_chain_state` is never written, so the
    //       chain seq resets to genesis on every restart — a break in the
    //       tamper-evident guarantee. `warm_from_postgres` resumes each tenant's
    //       seq + prev_hash so the chain continues unbroken across restarts.
    //   #5: without a `TenantAuditKeyStore` the anchor falls back to the global
    //       `TRACELANE_REKOR_SIGNING_KEY` (unset in prod) → no signature at all.
    //       Wiring the store lets each tenant's Merkle root be signed by a
    //       tenant-scoped Ed25519 key (`tenant_audit_keys`), envelope-encrypted
    //       under the BYOK master key. A second `from_env()` builds the Arc the
    //       store needs (the global slot consumed the first instance).
    // Entitlement cache (ADR-035) — built BEFORE the audit key store so minting a
    // per-tenant audit keypair can be gated on `f_audit_addon` (#3: the Audit-SKU
    // artifact must not be given away). Built only when Postgres is configured;
    // the resolver uses the pooled (`-pooler`) connection and the LISTEN task
    // opens its own direct connection for NOTIFY-driven invalidation (TTL fallback).
    let entitlements = pg.as_ref().map(|pool| {
        let cache = crate::entitlement_cache::EntitlementCache::new(
            crate::entitlement_cache::pg_resolver(pool.clone()),
        );
        crate::entitlement_cache::spawn_listen_task(cache.clone());
        Arc::new(cache)
    });

    // Entitlement-driven per-plan retention sweep. Gated OFF by default;
    // `TRACELANE_RETENTION_SWEEP=dryrun|enforce` enables it. The flat 365d table
    // TTL is the fail-safe backstop (never deletes a paying tenant early); this
    // trims each tenant to their plan window (Free 7 … Enterprise 365).
    if let Some(pool) = pg.clone() {
        crate::retention_sweep::spawn_retention_task(
            pool,
            config.clickhouse_url.clone(),
            crate::retention_sweep::SweepMode::from_env(),
        );
    }

    let tenant_audit_keys = match pg.as_ref() {
        Some(pool) => match crate::byok::ByokMasterKey::from_env() {
            Ok(Some(master)) => Some(Arc::new(crate::audit_keys::TenantAuditKeyStore::new(
                pool.clone(),
                Arc::new(master),
                entitlements.clone(),
            ))),
            _ => None,
        },
        None => None,
    };
    // R47. Publish the verification key for any pre-H1 row BEFORE the chain is built,
    // so `/v1/audit/pubkey` stops answering 200-with-an-empty-string on this boot rather
    // than on the tenant's next anchor — which for a quiet, already-anchored tenant may
    // never come. Idempotent and a no-op once the fleet is clean.
    if let Some(ref store) = tenant_audit_keys {
        let n = store.backfill_missing_public_keys().await;
        if n > 0 {
            tracing::info!(
                rows = n,
                "audit keys: published verification keys for pre-H1 rows (R47)"
            );
        }
    }

    let rekor_key_b64 = config
        .rekor_signing_key
        .as_ref()
        .map(secrecy::ExposeSecret::expose_secret);
    let audit_chain = Arc::new(
        AuditChain::with_tenant_keys(
            config.rekor_anchor_every,
            rekor_key_b64,
            config.clickhouse_url.as_deref(),
            pg.clone(),
            tenant_audit_keys,
        )
        .context("failed to initialise audit chain")?,
    );
    if let Err(err) = audit_chain.warm_from_postgres().await {
        tracing::warn!(error = %err, "audit_chain_state warm failed — chain resumes from genesis");
    }

    // NATS JetStream client — fire-and-forget span publish to ingest workers.
    //
    // A1: an UNSET `NATS_URL` is now a BOOT REFUSAL, not a warning.
    //
    // It used to log and continue, and that is the single worst failure this product
    // can have: the gateway answers 200 to every request while recording nothing, and
    // looks perfectly healthy doing it. A flight recorder that returns 200 while not
    // recording is the #81 shape at the gateway edge, and every "full-fidelity capture"
    // claim we publish is conditional on it. A warning does not carry that — nobody
    // reads a startup line from three weeks ago.
    //
    // The escape hatch is explicit and must be TYPED by a human:
    // `TRACELANE_ALLOW_NO_CAPTURE=1`. Dev and any deliberately capture-less deployment
    // set it once; a production config that merely FORGOT `NATS_URL` cannot set it by
    // accident. That asymmetry is the whole design — the mistake we are guarding
    // against is omission, so the remedy has to be commission.
    //
    // NOTE the deliberate asymmetry with a CONNECT FAILURE just below, which still only
    // logs. Unset is a misconfiguration that will never work; a failed connect is an
    // operational blip that may clear on its own, and refusing to boot during a NATS
    // restart would convert a recoverable outage into a hard one. That gap is real and
    // tracked (the client is not re-established for the process lifetime) — it is a
    // separate defect from this one and is NOT closed here.
    let allow_no_capture = std::env::var("TRACELANE_ALLOW_NO_CAPTURE").as_deref() == Ok("1");
    let nats = match capture_boot_decision(config.nats_url.is_some(), allow_no_capture) {
        // `Connect` is returned only when `nats_url` is `Some`, so the `None` arm is
        // unreachable by construction. It resolves to "no capture" rather than
        // unwrapping: a panic on a path that cannot happen is strictly worse than a
        // defensive fallthrough, and `.claude/rules/rust.md` bans `expect` here anyway.
        CaptureBoot::Connect => match config.nats_url.as_deref() {
            // `retry_on_initial_connect` — the connection is established in
            // the BACKGROUND and retried, instead of `connect()` returning `Err` once
            // and capture being dead for the life of the process.
            //
            // The old shape lost a whole class of outage to ordering alone: if the
            // gateway happened to start while NATS was restarting, or before DNS was
            // warm, `nats` was `None` forever. The gateway then served 200s and dropped
            // EVERY span until a human noticed and restarted it. async_nats already
            // auto-reconnects once connected — the gap was only ever the FIRST connect,
            // which is exactly the moment a dependency is most likely to be unready.
            //
            // Deliberately NOT a boot refusal (that is A1, for an UNSET url): refusing
            // to start during a NATS restart converts a recoverable dependency outage
            // into a hard gateway outage.
            // B-383 (b): the credential is lifted OUT of the URL (async-nats does
            // not honour `user:pass@` — `tracelane_shared::nats_connect` says why)
            // and the URL that is dialled and LOGGED is the credential-free one.
            Some(url) => {
                let nc = tracelane_shared::nats_connect::NatsConnect::from_url(url);
                let authenticates = nc.authenticates();
                let connected = nc
                    .options()
                    .retry_on_initial_connect()
                    .connect(&nc.url)
                    .await;
                match (nc.url, authenticates, connected) {
                    (url, authenticates, Ok(client)) => {
                        tracing::info!(
                            %url,
                            authenticates,
                            "NATS span publish wired (connect retries in the background if \
                             the server is not yet reachable)"
                        );
                        CAPTURE_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                        Some(Arc::new(client))
                    }
                    // With retry enabled this is now genuinely exceptional — a malformed
                    // URL or an auth rejection, not "the server is down". Still fail-open
                    // rather than fatal, and still loud.
                    (url, _, Err(err)) => {
                        tracing::error!(
                            error = %err, %url,
                            "NATS client could not be constructed even with initial-connect \
                             retry — span publish DISABLED; ALL spans will be dropped. This \
                             is a bad NATS_URL or an auth rejection, not an unreachable \
                             server. Check the value."
                        );
                        None
                    }
                }
            }
            None => None,
        },
        CaptureBoot::RunWithoutCapture => {
            tracing::warn!(
                "NATS_URL not set and TRACELANE_ALLOW_NO_CAPTURE=1 — span publish DISABLED, \
                 ALL spans will be dropped. This deployment has explicitly opted out of \
                 capture; /health reports capture_healthy=false."
            );
            None
        }
        CaptureBoot::Refuse => anyhow::bail!(
            "REFUSING TO BOOT: NATS_URL is not set, so span publish would be disabled and \
             EVERY span dropped while the gateway returned 200 — a recorder that records \
             nothing and looks healthy. Set NATS_URL, or set TRACELANE_ALLOW_NO_CAPTURE=1 \
             to run deliberately without capture (dev / a gateway-only deployment)."
        ),
    };

    let rate_limiter = Arc::new(RateLimiter::new());
    // Operational kill-switch (ADR-038) — built first so the predictive layer
    // can consult `kill.predictive.*` per request.
    let kill_switch = Arc::new(crate::kill_switch::KillSwitch::from_env());
    let predictive = Arc::new(PredictiveLayer::new().with_kill_switch(kill_switch.clone()));

    // ADR-069: async audit append. Create the JetStream context + the
    // durable TRACELANE_AUDIT stream BEFORE serving (so the first publish lands),
    // enable the acked-publish path on the audit chain, and spawn the sole
    // head-writer consumer. On any setup failure the audit path stays SYNCHRONOUS
    // (fail-safe): publish() falls back to append() when no JetStream is wired.
    if let Some(ref nats_client) = nats {
        let js = async_nats::jetstream::new((**nats_client).clone());
        match crate::audit_consumer::ensure_audit_stream(&js).await {
            // NEVER ENABLE THE ASYNC PATH WITHOUT THE POSTGRES IT REQUIRES.
            //
            // `append_from_wire` bails with "audit consumer requires a Postgres pool",
            // and the consumer does NOT ack a failed append — by design, so a real
            // PG/CH outage redelivers rather than losing an event. With no pool at all
            // that correct-for-an-outage behaviour becomes an infinite loop: every
            // audit event fails forever and JetStream redelivers it forever.
            //
            // MEASURED on a self-host stack, which runs no Postgres by design: four
            // chat requests produced FOUR spans and ZERO audit_log rows, plus a
            // redelivery storm of ~16 failures/minute that never terminates — on a box
            // infra/self-host/docker-compose.yml says can be 2 vCPU. The gateway
            // advertised the ledger at boot and then failed every append silently.
            //
            // The SYNC path needs no Postgres and was there all along: `publish()`
            // falls back to `append()` when no JetStream is wired, and `append()`
            // falls back to `append_in_memory`, which hashes the chain and persists the
            // `audit_log` row to ClickHouse. So NOT enabling the async path is what
            // makes the ledger work here — the bug was enabling a path that could
            // never succeed and thereby bypassing the one that could.
            Ok(()) if !audit_chain.has_pg_pool() => {
                // ADR-069 is the async design this branch declines to enable.
                tracing::warn!(
                    "audit: no Postgres control plane — using the SYNCHRONOUS append \
                     path (ClickHouse-persisted). The async JetStream stream is NOT \
                     enabled: its consumer requires Postgres and would fail every \
                     append and redeliver forever. NOTE: without Postgres the chain \
                     does not resume across a restart (warm_from_postgres is the only \
                     resume path), so seq restarts at genesis on reboot."
                );
            }
            Ok(()) => {
                audit_chain.set_jetstream(js, kill_switch.clone());
                crate::audit_consumer::spawn(Arc::clone(&audit_chain), (**nats_client).clone());
                // ADR-069.
                tracing::info!(
                    "async audit enabled — TRACELANE_AUDIT stream + head-writer consumer"
                );
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "TRACELANE_AUDIT stream setup failed — audit stays SYNCHRONOUS (fail-safe)"
                );
            }
        }
    }

    // Polar.sh billing recorder — optional. When POLAR_ACCESS_TOKEN is
    // set we spawn the flusher background task that drains accumulated
    // meter counts to Polar every 60s. Without a token, the recorder is
    // The Polar client serves /v1/billing/portal and the BILL-01 metering job.
    // (The ADR-020 `tokens_processed` / `audit_anchors` recorder that used to be
    // built here was deleted 2026-09-14 — the six ruled meters flow through
    // `billing::MeterSink` → ClickHouse → the daily job, never per request.)
    let polar_for_portal = match crate::billing::polar_client::access_token_from_env() {
        Ok(token) => {
            // The token stays a SecretString end to end (security review H-1,
            // 2026-09-12: this site copied it into a plain String and re-wrapped).
            Some(Arc::new(crate::billing::PolarClient::new(token)))
        }
        Err(_) => {
            tracing::info!("POLAR_ACCESS_TOKEN not set — Polar client disabled");
            None
        }
    };

    // R21/R32: the time-based anchor flush. Spawned HERE — last of the audit-chain
    // wiring — because the sweep reads the anchor watermark seeded by
    // `warm_from_postgres` above and dispatches through the billing hook set
    // directly above it. Ordering is belt-and-braces rather than load-bearing: the
    // sweeper sleeps one full `ANCHOR_SWEEP_INTERVAL` before its first pass and
    // reads the hook at flush time, not at spawn time.
    //
    // WHY A BACKGROUND TASK AND NOT A CHECK IN `publish()`: an append-triggered
    // condition cannot fix the tenants this exists for. `should_anchor` is a pure
    // per-tenant COUNT threshold, so a tenant that appended 35 events and went quiet
    // never signs and never anchors, ever — which is exactly the measured population
    // (2026-08-14: 92 rows across 5 tenants, 100% unsigned and unanchored, at 35, 35,
    // 12, 7 and 3 lifetime events).
    //
    // Spawned UNCONDITIONALLY: `flush_aged_batches` returns 0 immediately when the
    // chain has no ClickHouse client, so a dev/OSS process without one gets an idle
    // sleeper rather than a second boot condition to keep in sync with this one.
    crate::audit::spawn_anchor_age_sweeper(Arc::clone(&audit_chain));
    tracing::info!(
        max_batch_age_secs = crate::audit::ANCHOR_MAX_BATCH_AGE.as_secs(),
        sweep_interval_secs = crate::audit::ANCHOR_SWEEP_INTERVAL.as_secs(),
        "audit anchor age-sweeper started"
    );

    // (entitlements cache is constructed earlier — before the audit key store —
    // so the per-tenant audit keypair mint can be gated on f_audit_addon.)

    // Per-upstream circuit breakers (ADR-036) — bulkhead each provider.
    let circuit_breaker = Arc::new(crate::circuit_breaker::CircuitBreaker::default());
    // Expose it to the read surfaces (/gateway router health) via a process-wide
    // read handle — mirrors rejection_metrics, no state threading needed.
    crate::circuit_breaker::register_global(circuit_breaker.clone());

    // B1 prompt router — built once and shared between the chat handler
    // (drift-metric feed) and the /v1/prompts/* sub-router.
    let prompt_router = build_prompt_router(config.clickhouse_url.as_deref());
    // ADR-054: rebuild the version registry + routing pointers from ClickHouse at
    // startup so authored prompts survive a restart. Fail-open (logs, starts
    // empty) — a cold store must never block the gateway from serving. No-op with
    // the NoOp store (CLICKHOUSE_URL unset).
    prompt_router.load_from_clickhouse().await;

    // B-187b (verifier finding 1): make condition 3 a STARTUP INVARIANT.
    //
    // The request-time check is `state.entitlements.is_none()`, which is `Some`
    // iff the Postgres pool initialised. But :244-258 logs a warn and CONTINUES
    // when pool init fails on a hosted node — leaving `entitlements = None` on a
    // node that IS hosted. A legacy JWT carrying a direct `tenant_id` UUID
    // authenticates without touching Postgres (auth/mod.rs:361-388), so in that
    // window a real tenant could have reached the bench tier with the flag set.
    // Four things had to line up, but "structurally impossible" was not true.
    //
    // Refusing to boot closes it: on any node configured for hosted (POSTGRES_URL
    // / PGHOST present) the bench flag is now a hard startup failure, so the
    // combination cannot exist at request time regardless of pool health.
    if config.bench_mock_upstream
        && (std::env::var("POSTGRES_URL").is_ok() || std::env::var("PGHOST").is_ok())
    {
        anyhow::bail!(
            "TRACELANE_BENCH_MOCK_UPSTREAM=1 with a Postgres control plane configured \
             (POSTGRES_URL/PGHOST) — refusing to start. The bench mock and its \
             unlimited-rate tier are for a NON-hosted bench node only; see \
             bench/gateway/BENCH_TODO.md for the sanctioned ephemeral-container run."
        );
    }
    // ── B-239: bench mode must not be able to reach a PRODUCTION data plane ──
    //
    // The refusal above closes the CONTROL plane (Postgres). It says nothing
    // about where the bench process PUBLISHES, and that gap was exercised: a
    // bench-mode gateway wrote 10,154 spans AND 20,307 rows of the
    // tamper-evident audit ledger into production ClickHouse on 2026-08-04,
    // through the real NATS -> ingest pipeline. The bench triple-gate protected
    // the tenant GRANT and had nothing to say about the endpoints.
    //
    // WHY THIS SHAPE, and it is the whole point of the mechanism: the check does
    // NOT enumerate known variables (`NATS_URL`, `CLICKHOUSE_URL`, ...). A list
    // is a thing someone must remember to extend, and the next endpoint added to
    // the data plane would be uncovered by construction — which is exactly how
    // this hole existed. Instead it scans the ENTIRE environment by NAME SHAPE
    // (`*_URL` / `*_ENDPOINT`) and refuses any value that does not resolve to
    // loopback. A `FOO_URL` introduced next year is covered without anyone
    // editing this function. Default-deny over a discovered set, not
    // allow-by-omission over a maintained one.
    if config.bench_mock_upstream {
        let offenders = bench_nonlocal_endpoints(std::env::vars());
        if !offenders.is_empty() {
            anyhow::bail!(
                "TRACELANE_BENCH_MOCK_UPSTREAM=1 with NON-LOOPBACK endpoint(s) configured: {} \
                 — refusing to start. A bench-mode gateway publishes real spans and real \
                 audit-ledger rows; pointed at a production endpoint it contaminates both, \
                 and its tenant id can never exist in Postgres (the bench grant REQUIRES no \
                 control plane), so the rows are unreachable by tenant-purge. Point every \
                 *_URL / *_ENDPOINT at loopback, or unset it.",
                offenders.join(", ")
            );
        }
    }
    if config.bench_mock_upstream {
        tracing::warn!(
            "TRACELANE_BENCH_MOCK_UPSTREAM is ENABLED — requests for `__bench_mock*` \
             models return an instant canned response (gateway-overhead benchmarking, \
             bench/gateway/). This MUST NOT be set on a production tenant-serving node."
        );
    }

    // Inline guardrails engine (the guardrail spec). Shares the audit chain
    // (for the tamper-evident verdict ledger) + the entitlement cache (rail
    // gating). The ClickHouse mirror is best-effort: `None` when unconfigured →
    // ledger-only, fail-open-loud. V1 ships a single shared capability registry
    // that is permissive-by-default (empty → no tool blocked) — a per-workspace
    // registry loader is the follow-up that flips a configured workspace to
    // enforcing. So R4 records verdicts everywhere but only BLOCKS once a
    // workspace registers tool capabilities.
    let guardrail = {
        let ch = config
            .clickhouse_url
            .as_deref()
            .map(|u| crate::clickhouse_query::ch_client(u.to_string()));
        let registry = Arc::new(crate::guardrail::CapabilityRegistry::new());
        let mut engine = crate::guardrail::GuardrailEngine::new(
            Arc::clone(&audit_chain),
            ch,
            entitlements.clone(),
            registry,
        );
        // Per-workspace capability-registry loader (Migration 13). Wired only
        // when Postgres is configured; without it the shared permissive registry
        // is used (no enforcement). Permissive on a store outage — never blocks.
        if let Some(pool) = pg.as_ref() {
            let loader = Arc::new(crate::guardrail::RegistryLoader::new(
                crate::guardrail::pg_registry_resolver(pool.clone()),
            ));
            engine = engine.with_registry_loader(loader);
            tracing::info!("inline guardrails: per-workspace capability-registry loader wired");

            // B: observe the tool definitions that actually arrive, so a
            // tenant can approve them instead of hand-authoring tool JSON.
            // Postgres-gated for the same reason as the loader — there is
            // nowhere to flush to otherwise. Capture is a DashMap update on the
            // hot path (the hash is already computed); the flush is off-path and
            // best-effort, so a database problem can never affect a response.
            let observer = Arc::new(crate::guardrail::tool_observer::ToolObserver::new());
            crate::guardrail::tool_observer::spawn_flusher(
                Arc::clone(&observer),
                std::time::Duration::from_secs(30),
            );
            engine = engine.with_tool_observer(observer);
            tracing::info!(
                "inline guardrails: tool observation wired (flush every 30s, best-effort)"
            );
        }
        tracing::info!(
            rails = engine.rail_count(),
            "inline guardrails engine ready"
        );
        Arc::new(engine)
    };

    // GWY-24. Requires BOTH a `semantic_cache:` block in `tracelane.yaml` and a
    // ClickHouse URL — either missing means OFF, and off is silent by design:
    // an operator who has not asked for a cache must not get one.
    let semantic_cache = match (
        self::config::semantic_cache(),
        config.clickhouse_url.as_deref(),
    ) {
        (Some(cfg), Some(url)) => {
            tracing::info!(
                embedding_models = ?cfg.embedding_models(),
                dims = cfg.embedding_dimensions(),
                threshold = cfg.default_threshold(),
                max_scan_entries = cfg.max_scan_entries(),
                "semantic cache ENABLED"
            );
            Some(Arc::new(
                crate::semantic_cache::SemanticCache::new(
                    crate::clickhouse_query::ch_client(url),
                    providers.clone(),
                    cfg.clone(),
                )
                .with_entitlements(entitlements.clone()),
            ))
        }
        (Some(_), None) => {
            // Configured but unusable. LOUD, because the operator believes they
            // enabled a cache and the bill will say otherwise.
            tracing::warn!(
                "semantic_cache is configured in tracelane.yaml but CLICKHOUSE_URL is \
                 unset — the cache is OFF and every request will go to the provider"
            );
            None
        }
        _ => None,
    };

    // BILL-01 / ADR-076 — the gateway half of the six-meter usage model.
    // `None` when CLICKHOUSE_URL is unset — every meter-record call site is
    // then a no-op (`billing::meters::global()` mirrors this).
    let meters = config.clickhouse_url.as_deref().map(|url| {
        let sink = Arc::new(crate::billing::MeterSink::new(url.to_string()));
        Arc::clone(&sink).spawn_flusher();
        sink
    });
    crate::billing::meters::install(meters.clone());

    // The rate card + policy (`pricing_rates` + `billing_policy`) — loaded
    // ONCE per refresh cycle, never per request (spec §2.5b), held in an
    // ArcSwap. `RateCard::unavailable()` serves every read until the first
    // load succeeds, and forever when there is no control plane at all.
    let rate_card = Arc::new(ArcSwap::from_pointee(
        crate::billing::RateCard::unavailable(),
    ));
    if let Some(pool) = pg.as_ref() {
        crate::billing::rating::spawn_refresher(pool.clone(), Arc::clone(&rate_card)).await;
        // A3 velocity breaker — ONE GROUP BY tick over ALL keys, never per key.
        if let Some(url) = config.clickhouse_url.clone() {
            crate::billing::velocity_breaker::spawn(pool.clone(), url, Arc::clone(&rate_card));
        }
        // BILL-01 / ADR-076 — the daily metering job (meters 2-5) + Polar
        // usage emission + weekly blob GC. Needs BOTH a control plane (the
        // tenant → window map) and ClickHouse (the four meter reads), so it
        // is gated the same way the velocity breaker is, one level deeper.
        if let Some(url) = config.clickhouse_url.clone() {
            let resend = std::env::var("RESEND_API_KEY").ok().map(|key| {
                let from = match std::env::var("RESEND_FROM") {
                    Ok(v) => v,
                    Err(_) => "alerts@tracelane.dev".to_string(),
                };
                Arc::new(crate::billing::metering_job::ResendSettings {
                    http: crate::billing::email::http_client(),
                    api_key: Some(secrecy::SecretString::from(key)),
                    from,
                })
            });
            crate::billing::metering_job::spawn(
                pool.clone(),
                url,
                Arc::clone(&rate_card),
                polar_for_portal.clone(),
                resend,
                entitlements.clone(),
            );
        }
    }

    // EVL-04: the dataset routes need the SAME entitlement cache the hot path uses,
    // and the struct below MOVES it. Clone once, here, rather than resolving a second
    // cache — two caches would drift and a tenant could be entitled on one surface and
    // not the other, which is the shape `.claude/rules/tenancy.md` exists to prevent.
    let entitlements_for_state = entitlements.clone();
    let state = AppState {
        providers,
        semantic_cache,
        audit_chain,
        rate_limiter,
        quota_ch_url: config.clickhouse_url.clone(),
        meters,
        rate_card,
        predictive,
        // Observe-first by default (ADR-055 amendment); opt-in enforcement.
        predictive_enforce: std::env::var("TRACELANE_PREDICTIVE_ENFORCE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        guardrail,
        nats: nats.clone(),
        entitlements: entitlements_for_state,
        circuit_breaker,
        kill_switch,
        prompt_router,
        bench_mock_upstream: config.bench_mock_upstream,
        no_control_plane_rate_limit_rpm:
            crate::rate_limiter::no_control_plane_rate_limit_rpm_from_env(),
        rejection_metrics: Arc::new(crate::rejection_metrics::RejectionRegistry::new()),
        hotpath: crate::hotpath::Config::from_env(),
        failover: self::config::failover(),
        pg,
    };

    // `/health` is mounted LAST, outside the admission layers (B-389) — see the
    // end of this function for why the liveness probe must answer under shed.
    let mut app = Router::new()
        .route("/v1/auth/whoami", get(whoami_handler))
        .route("/v1/chat/completions", post(chat_completions_handler))
        // GWY-26. Mounted UNCONDITIONALLY, beside chat/completions — an
        // embeddings call that silently bypasses the gateway is the fidelity
        // hole this closes, so it must not be env-gated into a 404.
        .route("/v1/embeddings", post(embeddings_handler))
        // GWY-47 — the Anthropic-native wire. Mounted UNCONDITIONALLY, beside
        // `/v1/chat/completions`, for the same reason `/v1/embeddings` is: a
        // Claude Code / Anthropic-SDK user points `ANTHROPIC_BASE_URL` here and
        // an env-gated 404 would read as "wrong hostname" rather than "not
        // configured". `count_tokens` is the SDK's pre-flight sizing call and is
        // useless without the route beside it, so the two mount together.
        //
        // The handlers live in `crate::anthropic_messages`, NOT here: the chat
        // hot path must gain no new call (spec `GWY-47` §7 proof 6), and a
        // separate module makes that a source-level fact rather than a promise.
        .route(
            "/v1/messages",
            post(crate::anthropic_messages::messages_handler),
        )
        .route(
            "/v1/messages/count_tokens",
            post(crate::anthropic_messages::count_tokens_handler),
        )
        // GWY-41 / B-227 — the OTLP WRITE path, mounted DELIBERATELY here.
        //
        // `/v1/traces` is also a READ route: `trace_reads::routes()` binds GET on
        // the same path, behind a `CLICKHOUSE_URL` gate and a different state type.
        // This is the POST, it needs `AppState.nats`, and it must exist whether or
        // not ClickHouse is configured — so it mounts here rather than there. Axum
        // combines the two method routers because GET and POST are disjoint;
        // `both_methods_on_v1_traces_coexist` asserts that instead of assuming it.
        //
        // UNCONDITIONAL, like `/v1/embeddings` and for the same reason: before this
        // route existed, `POST /v1/traces` returned 405 and a Cloud customer could
        // not produce a multi-span trace by any means. A 404 from an env-gated
        // mount would read as "wrong URL" and send them hunting a hostname that
        // does not exist. When capture is unwired the handler answers 503
        // `capture_disabled`, which is the honest answer.
        .route(
            "/v1/traces",
            post(crate::trace_ingest::ingest_traces_handler),
        )
        .with_state(state.clone());

    // Polar webhooks are handled by the SINGLE receiver in the web tier
    // (`apps/web/app/api/webhooks/polar`), which correlates the tenant by the
    // checkout's `customer.external_id` and owns the `tenants` / entitlements
    // writes via Drizzle. The gateway once mounted a SECOND receiver here, but
    // it keyed correlation only on `polar_customer_id` — a column no real
    // checkout ever populates — so it could never flip a real subscription, and
    // two receivers could silently drift. Retired 2026-07-28: one
    // correct path. Polar is registered against the web route; the gateway never
    // received a delivery. (WorkOS webhooks stay on the gateway — separate path.)

    // Polar billing-portal endpoint — POST /v1/billing/portal.
    // Tenants exchange their bearer token for a Polar-hosted self-
    // service URL (plan changes, payment method, invoices). Mounted
    // only when the PolarClient is available — without a token we
    // have nothing to call.
    if let Some(ref polar) = polar_for_portal {
        let portal_state = crate::billing::PortalState::from_env(Arc::clone(polar));
        let portal_app = crate::billing::portal::routes().with_state(portal_state);
        app = app.merge(portal_app);
        tracing::info!("Polar portal mounted at /v1/billing/portal");

        // Customer onboarding flow — POST /v1/billing/checkout.
        // Mounted alongside the portal because both share the same
        // PolarClient + env-driven configuration.
        let checkout_state = crate::billing::checkout::CheckoutState::from_env(Arc::clone(polar));
        let checkout_app = crate::billing::checkout::routes().with_state(checkout_state);
        app = app.merge(checkout_app);
        tracing::info!("Polar checkout mounted at /v1/billing/checkout");
    } else {
        tracing::info!("POLAR_ACCESS_TOKEN not set — billing portal + checkout not mounted");
    }

    // SET-07: the usage read the dashboard has always called and the gateway never
    // mounted. Deliberately OUTSIDE the Polar block — it reads ClickHouse and the
    // entitlement cache, not Polar, so gating it on POLAR_ACCESS_TOKEN would make a
    // self-host deployment silently show no usage. Polar is the payment processor;
    // consumption is ours.
    app = app.merge(crate::billing::usage::routes(state.clone()));
    tracing::info!("billing usage mounted at /v1/billing/usage");

    // WorkOS webhook — same secret-or-skip pattern as the Polar webhook above.
    // Provisions tenants from organization.created and users from
    // user.created / dsync.user.created. Without WORKOS_WEBHOOK_SECRET
    // the route stays absent.
    if let Some(wh_cfg) = crate::auth::workos_webhook::WorkOsWebhookConfig::from_env() {
        let wh_state = crate::auth::workos_webhook::WorkOsWebhookState {
            config: Arc::new(wh_cfg),
            // Ingress cap on control-plane–growing WorkOS events.
            rate_limiter: Arc::new(crate::auth::workos_webhook::WebhookRateLimiter::from_env()),
        };
        let wh_app = Router::new()
            .route(
                "/v1/webhooks/workos",
                post(crate::auth::workos_webhook::handler),
            )
            .with_state(wh_state);
        app = app.merge(wh_app);
        tracing::info!("WorkOS webhook handler mounted at /v1/webhooks/workos");
    } else {
        tracing::info!("WORKOS_WEBHOOK_SECRET not set — workos webhook not mounted");
    }

    // Public audit-pubkey endpoint (ADR-062 C2 trust channel). Unauthenticated by
    // design — a public key is public — and rate-limited. Reads tenant_audit_keys
    // from Postgres at request time (503 when PG is unset), so it mounts
    // unconditionally. Lets an offline verifier fetch the TRUSTED --tenant-pubkey
    // from our TLS-authenticated domain instead of trusting the export's copy.
    app = app
        .merge(crate::audit_pubkey::routes().with_state(crate::audit_pubkey::PubkeyState::new()));
    tracing::info!("Audit pubkey mounted at /v1/audit/pubkey");

    // Audit-log export endpoint — customer-facing audit-log download.
    // Streams NDJSON rows from `tracelane.audit_log` filtered by the
    // requesting tenant + time range. Mounted only when CLICKHOUSE_URL
    // is set; without it the route stays absent (clean 404 on dev
    // beats 500 on every request).
    if let Some(ref ch_url) = config.clickhouse_url {
        let ch = crate::clickhouse_query::ch_client(ch_url.clone());
        let reader = std::sync::Arc::new(
            crate::audit_export::ClickHouseExportReader::new(ch)
                .with_entitlements(entitlements.clone()),
        );
        let export_state = crate::audit_export::ExportState {
            reader,
            // Audit-SKU entitlement gate. Reuse the app's entitlement
            // cache; `None` only if Postgres is unset, in which case the export
            // fails closed (503) rather than serving a paid capability unverified.
            entitlements: state.entitlements.clone(),
        };
        let export_app = crate::audit_export::routes().with_state(export_state.clone());
        app = app.merge(export_app);
        tracing::info!("Audit export mounted at /v1/audit/export");

        // Free-tier audit self-verify (ADR-066). Distinct route + gate from the
        // paid export: default-granted `f_audit_selfverify`, scope-floored to the
        // caller's own chain within their retention window. Shares the SAME
        // tenant-isolated reader + entitlement cache (via a cloned ExportState) so
        // there is one read path and one tenant seam — never a second one.
        let ledger_range_app = crate::audit_ledger_range::routes().with_state(export_state.clone());
        let self_verify_app = crate::audit_self_verify::routes().with_state(export_state);
        app = app.merge(ledger_range_app);
        app = app.merge(self_verify_app);
        tracing::info!("Audit self-verify mounted at /v1/audit/self-verify");

        // Option 1: gateway-proxied trace + SLO reads. The dashboard
        // (off-node on Vercel) and `tlane replay` read ClickHouse ONLY through
        // these endpoints — tenant comes from the validated Claims.tenant_id,
        // never from a session org_id bound into the query. Same CLICKHOUSE_URL
        // gate as the audit export above (ClickHouse is on-node only).
        let trace_ch = crate::clickhouse_query::ch_client(ch_url.clone());
        // B-330 / DSH-13: the reader resolves each tenant's OWN cap tier from the
        // entitlement cache (no Postgres per request); `None` here means no control
        // plane, which the reader treats as the Free tier — fail-closed.
        // Typed as the trait object (rather than left as `Arc<ClickHouseTraceReader>`)
        // so the SAME reader — and so the SAME tenant-capped seam, SRE #20 — can be
        // reused below by the OBS-48 share routes without a second ClickHouse client.
        let trace_reader: std::sync::Arc<dyn crate::trace_reads::TraceReader> = std::sync::Arc::new(
            crate::trace_reads::ClickHouseTraceReader::new(trace_ch)
                .with_entitlements(state.entitlements.clone()),
        );
        let trace_state = crate::trace_reads::TraceReadState {
            reader: trace_reader.clone(),
            // The SAME counters the admission pipeline records on (B-386 b).
            rejections: state.rejection_metrics.clone(),
        };
        let trace_app = crate::trace_reads::routes().with_state(trace_state);
        app = app.merge(trace_app);
        // OBS-48 shareable trace links. Needs BOTH ClickHouse (reuses `trace_reader`
        // above — one reader, one cap seam, never a second client for this data) AND
        // Postgres (the `trace_shares` table, migration 0036, un-journaled — TRAPS
        // §9). With no control plane the mint/list/revoke/public routes are simply
        // ABSENT — a clean 404, never a route that answers and cannot store a link.
        if let Some(pg_pool) = state.pg.clone() {
            let share_state = trace_share::ShareState {
                store: std::sync::Arc::new(trace_share::PgShareStore { pool: pg_pool }),
                reader: trace_reader.clone(),
                rate_limiter: std::sync::Arc::new(trace_share::ShareRateLimiter::new()),
                web_base_url: config.web_base_url.clone(),
            };
            app = app.merge(trace_share::routes().with_state(share_state));
            tracing::info!(
                "Trace share links mounted at /v1/traces/{{id}}/share(s) + /v1/share/{{token}}"
            );
        }
        // Tool-analytics (Trajectory / ledger #14) — same on-node CH gate.
        let tool_state = crate::tool_analytics::ToolAnalyticsState {
            entitlements: entitlements.clone(),
            ch: crate::clickhouse_query::ch_client(ch_url.clone()),
        };
        app = app.merge(crate::tool_analytics::routes().with_state(tool_state));
        // EVL-04 datasets. Same on-node ClickHouse gate as the trace reads above:
        // the tables live in ClickHouse beside `prompts`/`eval_runs`, so with no
        // CLICKHOUSE_URL the surface is simply ABSENT — a clean 404 rather than a
        // route that answers and cannot read.
        //
        // `entitlements` is passed as an `Option` and the gate REFUSES on `None`.
        // That is the unprivileged direction (`.claude/rules/tenancy.md`): no
        // control plane means free tier, never paid. `guardrail/rail.rs` once
        // resolved the opposite way and silently granted every paid rail to OSS
        // self-hosts — nobody was billed wrongly, so nothing looked wrong.
        let dataset_state = crate::dataset_routes::DatasetRoutesState {
            store: std::sync::Arc::new(
                crate::dataset_routes::ClickHouseDatasetStore::new(
                    crate::clickhouse_query::ch_client(ch_url.clone()),
                )
                .with_entitlements(entitlements.clone()),
            ),
            entitlements: entitlements.clone(),
        };
        app = app.merge(crate::dataset_routes::routes().with_state(dataset_state));
        tracing::info!(
            "Trace reads mounted at /v1/traces, /v1/traces/{{id}}/spans, /v1/slo, /v1/query/signatures; datasets at /v1/datasets"
        );
    } else {
        tracing::info!("CLICKHOUSE_URL not set — audit export + trace read routes not mounted");
    }

    // A4: customer-facing BYOK management endpoints. Mounted whenever
    // Postgres is configured — the master-key requirement is checked at
    // request time inside the handlers so dev mode (no BYOK_MASTER_KEY)
    // still returns a clean 503 instead of crashing on route mount.
    if state.pg.is_some() {
        let byok_app = crate::byok_api::provider_keys_api::router(state.clone());
        app = app.merge(byok_app);
        tracing::info!("BYOK management mounted at /v1/byok/provider-keys (POST/GET/DELETE)");

        // The WRITE path for R3 rug-pull detection. The read path
        // (registry_loader), the table and the comparison all shipped earlier;
        // with no way to CREATE a pin the rail was correct and permanently
        // inert. Postgres-gated for the same reason as BYOK above: a self-host
        // with no control plane has nowhere to store a pin.
        let pins_app = crate::guardrail::tool_pins_api::router(state.clone());
        app = app.merge(pins_app);
        tracing::info!("Tool pinning mounted at /v1/guardrails/tool-pins (POST/GET/DELETE)");
    }

    // Gateway-side API-key mint. The dashboard proxies key creation here
    // because the Cloudflare Workers runtime can't run the web minter's WASM
    // Argon2; RustCrypto Argon2 runs natively here. Same pepper + params, so
    // minted keys stay verify-compatible with `lookup_tenant_by_key_body`.
    if let Some(pool) = state.pg.as_ref() {
        let key_state = crate::key_routes::KeyRoutesState {
            minter: std::sync::Arc::new(crate::key_routes::PgKeyMinter { pool: pool.clone() }),
        };
        app = app.merge(crate::key_routes::routes().with_state(key_state));
        tracing::info!("API-key mint mounted at POST /v1/keys");

        // OBS-18 annotations. Postgres-backed (mutable, low-volume, read one
        // trace at a time), so it mounts here beside the other PG routes rather
        // than in `trace_reads`, which is the ClickHouse surface. Gated on the
        // same pool — with no control plane the routes are simply
        // absent, which is a clean 404 rather than a broken surface.
        //
        // EVL-29 mounts HERE too, on the same state, because a queue review and
        // an ad-hoc OBS-18 flag write the same `trace_annotations` row through
        // the same store. It additionally needs ClickHouse (candidates are a
        // read-time query — R221.1) and item 8's dataset store (the one action
        // copies through the path item 8 proved). Both arrive as `Option`: with
        // no ClickHouse the queue routes answer a typed 503 naming what is
        // missing, rather than 404-ing a feature the tenant is entitled to.
        let ann_state = crate::annotation_routes::AnnotationRoutesState {
            store: std::sync::Arc::new(crate::annotation_routes::PgAnnotationStore {
                pool: pool.clone(),
            }),
            entitlements: entitlements.clone(),
            datasets: config.clickhouse_url.as_ref().map(|u| {
                std::sync::Arc::new(
                    crate::dataset_routes::ClickHouseDatasetStore::new(
                        crate::clickhouse_query::ch_client(u.clone()),
                    )
                    .with_entitlements(entitlements.clone()),
                ) as std::sync::Arc<dyn crate::dataset_routes::DatasetStore>
            }),
            ch_url: config.clickhouse_url.clone(),
        };
        app = app.merge(crate::annotation_routes::routes().with_state(ann_state));
        tracing::info!(
            "annotations mounted at /v1/traces/{{trace_id}}/annotations; \
             EVL-29 queues at /v1/annotation-queues/*"
        );

        // DSH-01 in-app inbox. Same Postgres gate.
        let notif_state = crate::notification_routes::NotificationRoutesState {
            store: std::sync::Arc::new(crate::notification_routes::PgNotificationStore {
                pool: pool.clone(),
            }),
        };
        app = app.merge(crate::notification_routes::routes().with_state(notif_state));
        tracing::info!("notifications mounted at /v1/notifications");
    }

    // B1 Prompt Promotion routes (per ADR-009 /). The router was
    // built once (build_prompt_router) and lives in AppState so the chat
    // handler can feed drift metrics into it; here we mount the same shared
    // Arc behind the /v1/prompts/* sub-router. The write workflow
    // (promote/rollback/observe) is gated on FeatureKey::PromptPromotionWrite
    // via the app entitlement cache (, ADR-009 Team+); with no Postgres
    // the gate fails closed inside the handlers (503 on writes).
    {
        // EVL-05: the eval engine needs ClickHouse (to write `eval_runs`) and the
        // provider registry (to run a case through the SAME dispatch the chat
        // path uses). `None` without ClickHouse — the routes then answer a typed
        // 503 rather than pretending the feature does not exist.
        let eval = config.clickhouse_url.as_deref().map(|url| {
            std::sync::Arc::new(
                crate::prompt_eval::PromptEvalEngine::new(
                    crate::clickhouse_query::ch_client(url),
                    state.providers.clone(),
                    state.prompt_router.clone(),
                    // R81: the SAME NATS client the chat path publishes through, so an
                    // eval case's span travels the identical route to ClickHouse. A
                    // second publish path would be a second definition of "a span was
                    // captured", and the two would disagree on the first failure.
                    state.nats.clone(),
                )
                .with_entitlements(state.entitlements.clone()),
            )
        });
        if let Some(engine) = eval.clone() {
            // Sweep runs orphaned by a restart BEFORE serving. The gate maps
            // `running` to blocked, so a row left behind by a process death is a
            // promotion wedged shut until someone notices — the same shape as
            // `prev_production` never being rebuilt, which silently disarmed
            // auto-rollback after every deploy.
            engine.reconcile_stale_runs().await;
        }
        // EVL-02 experiments. Mounted only when BOTH ClickHouse (every row this
        // surface reads and writes lives there) and the eval engine exist — an
        // experiment is a fan-out over that ONE engine, never a second executor,
        // so a surface without it could accept a request it could not run.
        if let (Some(engine), Some(ch_url)) = (eval.clone(), config.clickhouse_url.clone()) {
            let xstate = crate::experiment_routes::ExperimentRoutesState {
                store: std::sync::Arc::new(
                    crate::experiment_routes::ClickHouseExperimentStore::new(
                        crate::clickhouse_query::ch_client(&ch_url),
                    )
                    .with_entitlements(entitlements.clone()),
                ),
                // The SAME dataset store the dataset routes use, so "which
                // snapshot is latest" has one answer.
                datasets: std::sync::Arc::new(
                    crate::dataset_routes::ClickHouseDatasetStore::new(
                        crate::clickhouse_query::ch_client(&ch_url),
                    )
                    .with_entitlements(entitlements.clone()),
                ),
                engine,
                // `Option`, and the gate REFUSES on `None` — no control plane
                // means free tier, never paid (`.claude/rules/tenancy.md`).
                entitlements: state.entitlements.clone(),
            };
            app = app.merge(crate::experiment_routes::routes().with_state(xstate));
            tracing::info!("experiments mounted at /v1/experiments (+ /v1/evals/{{id}}/items)");
        }

        let prompt_state = crate::prompt_routes::PromptRoutesState {
            router: state.prompt_router.clone(),
            entitlements: state.entitlements.clone(),
            audit_chain: state.audit_chain.clone(),
            eval,
        };
        let prompt_app = crate::prompt_routes::routes().with_state(prompt_state);
        app = app.merge(prompt_app);
    }

    // Alerting (ADR-059) — customer alert rules → their Slack/Discord webhook.
    // Needs Postgres (rules), ClickHouse (metrics), and the entitlement cache
    // (the f_alerts gate). DARK by default; the background checker re-gates every
    // tenant each tick, so a revoked f_alerts stops firing with no rules delete.
    if let (Some(pool), Some(ents), Some(ch_url)) = (
        state.pg.clone(),
        state.entitlements.clone(),
        config.clickhouse_url.clone(),
    ) {
        let interval_secs = std::env::var("TRACELANE_ALERTS_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);
        let checker = std::sync::Arc::new(crate::alerts::checker::AlertChecker::new(
            pool.clone(),
            crate::clickhouse_query::ch_client(ch_url),
            ents.clone(),
            std::time::Duration::from_secs(interval_secs),
        ));
        checker.spawn();
        let alert_state = crate::alerts::routes::AlertRoutesState {
            pool,
            entitlements: ents,
        };
        app = app.merge(crate::alerts::routes::routes().with_state(alert_state));
        tracing::info!(
            "alerting mounted at /v1/alerts/* (f_alerts-gated, {interval_secs}s checker)"
        );
    }

    // Online evals (EVL-28, Sprint 3 item 11) — the SURFACE for the sampling
    // vertical in `online_eval.rs`.
    //
    // Mounting this is what makes that vertical live. Until this router exists
    // no policy can be created, so `admission()` returns `None` for every
    // request and nothing samples or spends. Read the gate below as the money
    // gate it is, not as boilerplate.
    //
    // BOTH Postgres AND the entitlement cache are REQUIRED, and the `if let`
    // is the enforcement rather than a convenience: with no entitlement cache
    // there is no way to verify `f_online_evals`, and `.claude/rules/tenancy.md`
    // is explicit that an absent cache is the UNPRIVILEGED state. Not mounting
    // is the fail-closed answer — a router that answered anything at all here
    // would have to decide what an unverifiable entitlement means, and every
    // permissive answer to that spends a customer's money.
    //
    // ClickHouse is an `Option` INSIDE the state rather than a mount condition:
    // the POLICY routes are Postgres-only and must still work so a customer can
    // switch scoring OFF on a node whose results store is down. Refusing to
    // disable a spending feature because the read path is unavailable is the
    // wrong direction.
    if let (Some(pool), Some(ents)) = (state.pg.clone(), state.entitlements.clone()) {
        let oe_state = crate::online_eval_routes::OnlineEvalRoutesState {
            pool,
            entitlements: ents,
            clickhouse_url: config.clickhouse_url.clone(),
        };
        app = app.merge(crate::online_eval_routes::routes().with_state(oe_state));
        tracing::info!(
            "online evals mounted at /v1/online-evals/* (f_online_evals-gated, \
             scores {})",
            if config.clickhouse_url.is_some() {
                "readable"
            } else {
                "UNCONFIGURED"
            }
        );
    }

    // B-389 (2026-09-12): ADMISSION. Before this the router carried exactly one
    // layer (`TraceLayer`): no request timeout, no concurrency limit, no load
    // shed — a slow upstream or a runaway client could hold connections without
    // bound, and the only ceiling on in-flight work was the process's memory.
    //
    //   load_shed ─► concurrency_limit(N) ─► timeout(T) ─► handler
    //
    // `load_shed` sits OUTSIDE the limit so the (N+1)th request gets an
    // immediate 503 instead of queueing — queueing at the edge is how p99
    // becomes minutes; a fast 503 is what a client with a retry policy wants.
    // The timeout bounds the HEAD of the response (the handler returning its
    // `Response`); a streaming BODY is not under it, so a legitimate ten-minute
    // SSE stream is untouched while a handler stuck on an upstream that never
    // answers is cut. Both refusals are counted on `/metrics` and noted as a
    // degradation once. `/health` is mounted below, OUTSIDE this stack: a load
    // balancer that cannot read the liveness probe during overload pulls the
    // node, which turns overload into outage.
    let admission = AdmissionConfig::from_env();
    tracing::info!(
        max_inflight = admission.max_inflight,
        request_timeout_secs = admission.request_timeout.as_secs(),
        "admission control: load-shed above max_inflight, head-of-response timeout"
    );
    // B-383 (f): a source past its failed-auth budget is refused with 429 BEFORE
    // the handler — no HMAC, no key lookup, no Postgres. Inside the admission
    // stack (so an overloaded node still sheds first) and on every route except
    // `/health`, which is mounted below. `preauth_limiter.rs` says why it is
    // fail-open and what it deliberately is not.
    let preauth = crate::preauth_limiter::PreAuthLimiter::from_env();
    let app = app.layer(axum::middleware::from_fn_with_state(
        preauth,
        crate::preauth_limiter::layer,
    ));
    let app = with_admission(app, admission)
        .route("/health", get(health_handler))
        // B-389: per-route request counters + head-of-response histogram, and the
        // in-flight gauge, for `/metrics`. Outermost so it sees the admission
        // layer's own 503s and 408s.
        .layer(axum::middleware::from_fn(crate::metrics::track))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind listener")?;

    // B-377 (2026-09-12): serve until SIGTERM / ctrl-c, then DRAIN. Before this
    // the call was a bare `axum::serve(..).await`: no signal handler anywhere in
    // the binary, so every `compose up -d` deploy hard-cut in-flight streams
    // (their `StreamFinalizer` never ran — B-375) and dropped whatever the NATS
    // client had buffered. axum finishes in-flight connections on graceful
    // shutdown; the two things it cannot know about are ours — the spawned span
    // publishes still awaiting their JetStream ack, and the client's outbound
    // buffer — so both are drained explicitly below, with a bound, and anything
    // still outstanding at the bound is LOGGED AS LOST rather than assumed sent.
    // B-389: the loopback `/metrics` listener. Fail-open by construction —
    // `metrics::run` never returns `Err` — and aborted with the process.
    tokio::spawn(crate::metrics::run());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum serve error")?;
    drain_on_shutdown(nats.as_deref()).await;
    Ok(())
}

/// Resolves on SIGTERM (what `docker stop` / compose send) or ctrl-c (a terminal).
/// Extracted so the drain path can be driven by a test without a real signal.
/// B-389: the two admission knobs, env-tunable, logged once at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmissionConfig {
    /// Requests allowed inside the router at once; the next is shed with 503.
    pub max_inflight: usize,
    /// Head-of-response ceiling; a handler still running past it answers 408.
    pub request_timeout: std::time::Duration,
}

impl AdmissionConfig {
    /// 8× the concurrency the published 5,000 rps bench ran at (256): a ceiling
    /// for a runaway client, not a throttle.
    pub const DEFAULT_MAX_INFLIGHT: usize = 2048;
    /// The longest provider-side generation the adapters allow (their reqwest
    /// clients are built with a 300 s timeout) — anything longer is not a
    /// request, it is a leak.
    pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;

    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var("TRACELANE_MAX_INFLIGHT").ok().as_deref(),
            std::env::var("TRACELANE_REQUEST_TIMEOUT_SECS")
                .ok()
                .as_deref(),
        )
    }

    /// Pure, so the parsing rules are testable: unset or unparsable → the
    /// default WITH a warning (fail-open — a typo must not make the gateway
    /// refuse every request or accept an unbounded number of them); `0` is
    /// refused the same way, because a limit of zero is an outage with a config
    /// key.
    pub(crate) fn from_values(max_inflight: Option<&str>, timeout_secs: Option<&str>) -> Self {
        let parse = |raw: Option<&str>, name: &str, default: u64| -> u64 {
            match raw {
                None => default,
                Some(v) => match v.trim().parse::<u64>() {
                    Ok(n) if n > 0 => n,
                    _ => {
                        tracing::warn!(
                            value = %v,
                            default,
                            "{name} is not a positive integer — using the default"
                        );
                        default
                    }
                },
            }
        };
        Self {
            max_inflight: parse(
                max_inflight,
                "TRACELANE_MAX_INFLIGHT",
                Self::DEFAULT_MAX_INFLIGHT as u64,
            ) as usize,
            request_timeout: std::time::Duration::from_secs(parse(
                timeout_secs,
                "TRACELANE_REQUEST_TIMEOUT_SECS",
                Self::DEFAULT_REQUEST_TIMEOUT_SECS,
            )),
        }
    }
}

/// Wrap `app` in the admission stack (load-shed → concurrency limit →
/// head-of-response timeout). Routes added to the RETURNED router afterwards
/// (`/health`) sit outside it — which is how the liveness probe stays
/// answerable under shed. One function so the tests drive the exact stack
/// `run()` serves.
pub(crate) fn with_admission(app: Router, cfg: AdmissionConfig) -> Router {
    // GLOBAL, not `concurrency_limit`: axum applies a layer to every route's
    // service separately, so the plain `ConcurrencyLimitLayer` would mint one
    // semaphore PER ROUTE and the "limit" would be N per route, not N for the
    // process. The test below drives two routes against one limit for exactly
    // this reason.
    let global = tower::limit::GlobalConcurrencyLimitLayer::new(cfg.max_inflight);
    app.layer(
        tower::ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(admission_error))
            .load_shed()
            .layer(global)
            .timeout(cfg.request_timeout),
    )
}

/// The admission stack's errors, as HTTP. `HandleErrorLayer` needs an
/// `Infallible` service under axum, so every tower error becomes a response
/// here — and each one is counted, because a refusal nobody can see is a
/// refusal nobody will size against.
async fn admission_error(err: tower::BoxError) -> axum::response::Response {
    if err.is::<tower::timeout::error::Elapsed>() {
        crate::metrics::note_request_timeout();
        return (
            StatusCode::REQUEST_TIMEOUT,
            Json(serde_json::json!({
                "error": "request_timeout",
                "message": "the gateway did not produce a response head within its timeout"
            })),
        )
            .into_response();
    }
    if err.is::<tower::load_shed::error::Overloaded>() {
        crate::metrics::note_load_shed();
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "1")],
            Json(serde_json::json!({
                "error": "overloaded",
                "message": "the gateway is at its in-flight request limit; retry"
            })),
        )
            .into_response();
    }
    tracing::error!(error = %err, "admission layer: unexpected error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": "internal" })),
    )
        .into_response()
}

pub(crate) async fn shutdown_signal() {
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
    tracing::info!("shutdown signal received — no longer accepting connections; draining");
}

/// The bound on how long shutdown waits for in-flight span publishes and the
/// NATS flush. Must stay UNDER `stop_grace_period` in `infra/prod/docker-compose.yml`
/// (30 s) — past that Docker sends SIGKILL and nothing here runs.
pub(crate) const SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Wait for spawned span publishes to be acked, then flush the NATS client.
/// Every outstanding publish at the deadline is counted as a publish failure —
/// a span the stream never confirmed — so the loss is on the counter, not silent.
pub(crate) async fn drain_on_shutdown(nats: Option<&async_nats::Client>) {
    let left = crate::otlp_emit::drain_in_flight(SHUTDOWN_DRAIN_TIMEOUT).await;
    if left > 0 {
        for _ in 0..left {
            crate::otlp_emit::note_span_publish_failed();
        }
        tracing::error!(
            spans = left,
            timeout_secs = SHUTDOWN_DRAIN_TIMEOUT.as_secs(),
            "shutdown drain timed out — these span publishes were never acked and are LOST"
        );
    }
    if let Some(client) = nats {
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.flush()).await {
            Ok(Ok(())) => tracing::info!("NATS client flushed; exiting"),
            Ok(Err(e)) => tracing::error!(error = %e, "NATS flush on shutdown failed"),
            Err(_) => tracing::error!("NATS flush on shutdown timed out"),
        }
    }
}

/// Is span publish WIRED? True once a NATS client exists.
///
/// **Precisely: wired, not necessarily connected right now.** Since the client
/// is built with `retry_on_initial_connect()`, so it exists and reconnects in the
/// background even while the server is unreachable. Treating this as "we are currently
/// publishing" would be the overclaim; the live signal is `spans_dropped`, which only
/// moves when a span is actually lost. A span buffered during a NATS restart is not
/// lost, and is deliberately not counted as such.
///
/// **That sentence was FALSE until B-376 (2026-09-12).** `publish_span` was a core
/// NATS publish that returned `Ok` on in-process enqueue, so `spans_dropped` could
/// not observe a disconnect, a full buffer or a JetStream reject — the counter the
/// whole capture-health story rested on was structurally unable to fire. It is an
/// acked JetStream publish now (`otlp_emit::publish_span`), so a moved counter
/// means a span the stream does not have.
///
/// A1. Deliberately a process-global rather than `AppState`: `/health` is mounted
/// before state exists on some paths, and the one thing this must never do is be
/// unavailable exactly when capture is broken.
pub(crate) static CAPTURE_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// What boot should do about span capture (A1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureBoot {
    /// `NATS_URL` is set — try to connect.
    Connect,
    /// No `NATS_URL`, but the operator explicitly opted out of capture.
    RunWithoutCapture,
    /// No `NATS_URL` and no explicit opt-out — refuse to start.
    Refuse,
}

/// The A1 boot rule, extracted so it can be FALSIFIED.
///
/// Left inline it would be reachable only by booting a real gateway against a real
/// NATS, which is precisely how a rule like this ends up never being tested in the
/// state that matters (the refusal). The decision is pure; the I/O is not.
pub(crate) const fn capture_boot_decision(
    nats_url_set: bool,
    allow_no_capture: bool,
) -> CaptureBoot {
    match (nats_url_set, allow_no_capture) {
        // A set NATS_URL wins outright: the opt-out is about running WITHOUT capture,
        // not about suppressing capture that was configured.
        (true, _) => CaptureBoot::Connect,
        (false, true) => CaptureBoot::RunWithoutCapture,
        (false, false) => CaptureBoot::Refuse,
    }
}

/// The `audit_backlog` object on `/health` (B-378), from the head-writer's
/// last `consumer.info()` reading.
fn audit_backlog_json() -> serde_json::Value {
    let b = crate::audit_consumer::backlog_snapshot();
    serde_json::json!({
        "pending": b.pending,
        "ack_pending": b.ack_pending,
        "read_secs_ago": b.read_secs_ago,
        "healthy": b.healthy,
    })
}

/// The `/health` body (A1), extracted so the contract is testable without a server.
pub(crate) fn health_body(
    capture_enabled: bool,
    spans_dropped: u64,
    audit_backfill_failures: u64,
) -> serde_json::Value {
    let degraded: Vec<serde_json::Value> = tracelane_shared::degradation::snapshot()
        .into_iter()
        .filter(|st| st.count > 0)
        .map(|st| {
            serde_json::json!({
                "kind": st.kind,
                "count": st.count,
                "open_for_secs": st.open_for_secs,
                "last_seen": st.last_seen,
            })
        })
        .collect();
    serde_json::json!({
        "status": "ok",
        "service": "tracelane-gateway",
        "capture_enabled": capture_enabled,
        "spans_dropped": spans_dropped,
        "capture_healthy": capture_enabled && spans_dropped == 0,
        // 2026-09-04 stale-while-revalidate counters: how often a sparse request was
        // served a last-known auth / entitlement answer while the control plane was
        // re-checked off the request path. Non-zero on a zero-user deployment is the
        // EXPECTED shape; it is what keeps the p99 off the Neon resume.
        "auth_stale_served": crate::db::api_keys::AUTH_STALE_SERVED_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        "entitlement_stale_served": crate::entitlement_cache::STALE_SERVED_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        // R17. Deliberately NOT folded into `capture_healthy`: capture and
        // attestation fail independently and a reader must be able to tell which
        // is broken. Every span can be captured while the ledger silently stops
        // being third-party verifiable — that is precisely the state this exists
        // to make visible.
        "audit_backfill_failures": audit_backfill_failures,
        "audit_attestation_healthy": audit_backfill_failures == 0,
        // S6 (SRE audit 2026-09-04). Eleven fail-open paths call
        // `degradation::note()`; SEVEN had no consumer outside tests, so a
        // degradation could stay open indefinitely with every board green — and one
        // was: `semantic_cache_unavailable` ran open on prod for hours while
        // `watchdog.state` read `verdict=green`. The counters existed; nothing
        // published them. This is the publish.
        //
        // Only kinds with `count > 0` are listed, so the field is `[]` on a healthy
        // gateway and a reader does not have to know the eleven names. `open_for_secs`
        // is last_seen - first_seen, which is the question a fail-open must be able to
        // answer (docs/reference/TRAPS.md §16): not "did it happen" but "is it STILL
        // happening, and for how long".
        "degraded_open": degraded.len(),
        "degraded": degraded,
        // B-378 (2026-09-12): the audit JetStream backlog, read from
        // `consumer.info()` every 10 s by the head-writer. Before this nothing
        // read the queue depth at all, and the first symptom of a lagging
        // ledger was the 1 GiB stream bound turning every request into a 503.
        // `healthy` is false when the reading is STALE as well as when it is
        // high — a number nobody has refreshed is not a zero.
        "audit_backlog": audit_backlog_json(),
        // B-383 (a): which master keys this process holds and which it encrypts
        // under — the operator's read during a rotation (runbooks/byok-key-loss.md
        // § Case A). Ids only, never material. (First landed 2026-09-12, lost to
        // a concurrent save of this file, restored the same day.)
        "byok_ring": crate::byok::master_key().map(|k| serde_json::json!({
            "loaded": k.loaded_keks(),
            "active": k.active_kek(),
        })),
        // S7 (2026-09-04): the PR6 sidecar fail-open count, published rather than only
        // logged. The ops board used to grep the log for a string this tree never
        // emitted; a counter cannot be broken by rewording a message.
        "prompt_guard_fail_opens": crate::predictive::prompt_guard::fail_opens_total(),
        // A count of zero is only good news once you know the thing executed. On prod
        // `PROMPT_GUARD_URL` is unset, so the predictor is omitted from the stack and the
        // count is trivially zero forever — which the ops board first rendered as
        // "PromptGuard enforcing". Publish the denominator too.
        "prompt_guard_configured": crate::predictive::prompt_guard::is_configured(),
    })
}

#[instrument]

/// A1 — capture completeness, exposed where an operator can actually see it.
///
/// The hole this closes: the gateway returned `{"status":"ok"}` while dropping every
/// span, and nothing on any read route said so. "The gateway is up" was being read as
/// "we are recording", and those are different facts.
///
/// **`status` stays `ok` and this route stays 200 even when capture is dead.** That is
/// on purpose: `/health` is the liveness probe the load balancer reads, so failing it
/// would pull a serving node out of rotation and turn a recording outage into a serving
/// outage. The signal belongs in the BODY, where an operator and a watchdog can alert on
/// it, not in the status code.
///
/// - `capture_enabled` — span publish is wired (NATS connected at boot).
/// - `spans_dropped` — cumulative spans dropped because publish was unavailable.
/// - `capture_healthy` — `capture_enabled && spans_dropped == 0`. It is deliberately
///   STICKY: once anything has been lost, this stays false until the process restarts,
///   because "we lost data" does not stop being true when the cause clears.
async fn health_handler() -> impl IntoResponse {
    use tracelane_shared::degradation::{Degradation, count};
    let capture_enabled = CAPTURE_ENABLED.load(std::sync::atomic::Ordering::Relaxed);
    // Both drop causes, summed: "publish was never wired" and "publish was wired and
    // failed" are different faults but identical consequences — a span that is gone.
    let spans_dropped =
        count(Degradation::SpansDroppedNoNats) + count(Degradation::SpanPublishFailed);
    // R17: the ledger's attestation half, reported beside capture and never merged
    // into it.
    //
    // R21 adds the second cause, summed for the same reason `spans_dropped` sums its
    // two: "the post-anchor backfill failed" and "the age sweep could not read the
    // tenant, so it never anchored at all" are different faults with one consequence —
    // rows that stay unsigned and unanchored with nothing to retry them. The wire field
    // name is a contract (R17: the watchdog greps it), so it stays; the two counters
    // remain separable by `kind` at /v1/gateway/stats when an operator needs the cause.
    let audit_backfill_failures =
        count(Degradation::AuditBackfillFailed) + count(Degradation::AuditAgeSweepSkipped);
    Json(health_body(
        capture_enabled,
        spans_dropped,
        audit_backfill_failures,
    ))
}

/// A2: validate the bearer credential and return the tenant. Lets sub-
/// services (e.g. the MCP server's HTTP transport) reuse the gateway's
/// hardened auth surface (JWT alg allowlist, audience check, JWKS,
/// peppered HMAC API-key lookup) without duplicating it. Returns 401
/// when the bearer is missing or invalid; the body is always JSON.
#[instrument(skip(headers))]
async fn whoami_handler(headers: HeaderMap) -> impl IntoResponse {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing bearer" })),
        )
            .into_response();
    }
    match crate::auth::validate_authorization(auth).await {
        Ok(claims) => Json(serde_json::json!({
            "tenant_id": claims.tenant_id.to_string(),
            "auth_method": format!("{:?}", claims.auth_method),
        }))
        .into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "whoami: invalid credentials");
            let (status, msg) = crate::auth::failure(&err);
            (status, Json(serde_json::json!({ "error": msg }))).into_response()
        }
    }
}

/// Build the B1 `PromptRouter` with its ClickHouse persister / eval gate /
/// auto-rollback engine when `CLICKHOUSE_URL` is set, else the in-memory
/// dev defaults. Shared (via `Arc`) between `AppState` (so the chat handler
/// can feed drift metrics) and the `/v1/prompts/*` sub-router.
pub(crate) fn build_prompt_router(
    clickhouse_url: Option<&str>,
) -> Arc<crate::prompt_router::PromptRouter> {
    let mut prompt_router = crate::prompt_router::PromptRouter::new();
    if let Some(url) = clickhouse_url {
        let ch = crate::clickhouse_query::ch_client(url.to_string());
        let reader = Arc::new(crate::prompt_history::ClickHouseHistoryReader::new(
            ch.clone(),
        ));
        let persister = Arc::new(crate::prompt_router::ClickHousePersister::new(ch.clone()));
        let eval_gate = Arc::new(crate::prompt_router::ClickHouseEvalGate::new(ch.clone()));
        let version_store = Arc::new(crate::prompt_router::ClickHouseVersionStore::new(
            ch.clone(),
        ));
        let rollback_engine = Arc::new(crate::auto_rollback::RollbackEngine::new().with_persister(
            Arc::new(crate::auto_rollback::ClickHouseRollbackPersister::new(ch)),
        ));
        prompt_router = prompt_router
            .with_history_reader(reader)
            .with_persister(persister)
            .with_eval_gate(eval_gate)
            .with_version_store(version_store)
            .with_rollback_engine(rollback_engine);
        tracing::info!(
            "PromptRouter wired with ClickHouse history reader + promotion persister + eval gate + auto-rollback engine"
        );
    } else {
        tracing::warn!(
            "PromptRouter using in-memory NoOp persister + PermissiveGate \
             (CLICKHOUSE_URL unset): promotion records are NOT durable and \
             eval gates are NOT enforced — set CLICKHOUSE_URL in production"
        );
    }
    Arc::new(prompt_router)
}

// `providers::behavioral_tests` drives the buffered tool-call fold directly, and
// only tests do — so the re-export is test-only. It sits HERE, below every
// production item, because four source-scanning guards read this file up to its
// FIRST `cfg(test)` attribute and treat everything after it as test code.
#[cfg(test)]
pub(crate) use buffered::{BufferedToolState, buffered_completion_payload};

#[cfg(test)]
mod tests {
    use super::*;

    // ── A1: capture completeness ────────────────────────────────────────────
    // The gateway used to answer 200 while dropping every span, and nothing said
    // so. These assert the two halves of the fix: it REFUSES to start in the
    // config that causes it, and it TELLS you when it is happening anyway.

    /// The state that matters. Everything else here is the happy path; this is the
    /// one the old code got wrong, and a test suite that only covers the others
    /// would have passed against the defect.
    #[test]
    fn unset_nats_url_without_an_explicit_opt_out_refuses_to_boot() {
        assert_eq!(
            capture_boot_decision(false, false),
            CaptureBoot::Refuse,
            "a forgotten NATS_URL must stop the process, not produce a warning \
             nobody reads three weeks later"
        );
    }

    /// The escape hatch must work, or dev and capture-less deployments are bricked
    /// and someone deletes the check. A guard people must route around is not a guard.
    #[test]
    fn an_explicit_opt_out_runs_without_capture() {
        assert_eq!(
            capture_boot_decision(false, true),
            CaptureBoot::RunWithoutCapture
        );
    }

    /// A configured NATS_URL wins regardless of the opt-out: the flag means "run
    /// without capture", not "suppress capture that was configured".
    #[test]
    fn a_configured_nats_url_always_connects() {
        assert_eq!(capture_boot_decision(true, false), CaptureBoot::Connect);
        assert_eq!(capture_boot_decision(true, true), CaptureBoot::Connect);
    }

    /// . THE DEFECT: a gateway that started while NATS was unreachable had
    /// `nats = None` for the life of the process — 200s and total span loss until a
    /// human restarted it. async_nats already auto-reconnects once connected; the gap
    /// was only ever the FIRST connect, which is exactly when a dependency is most
    /// likely to be unready (NATS restarting, DNS not yet warm).
    ///
    /// Both directions, against a port nothing listens on:
    ///   - plain `connect()`   -> Err  (the old behaviour, permanent capture loss)
    ///   - `retry_on_initial_connect()` -> Ok (a client that heals itself)
    /// Asserting only the second would not show that anything changed.
    ///
    /// INCLUDE_STR GUARD (B-385 2c) — its source half pins a boot-path LITERAL
    /// in `run()` (`retry_on_initial_connect`), which no in-process test can
    /// drive; the behavioural half above is the discriminating one.
    #[tokio::test]
    async fn nats_initial_connect_failure_is_retried_not_fatal() {
        // Port 1 is reserved; nothing listens there, so this is a real connect
        // failure rather than a simulated one.
        const DEAD: &str = "nats://127.0.0.1:1";

        assert!(
            async_nats::connect(DEAD).await.is_err(),
            "sanity: a plain connect to a dead port must fail — if this ever passes, \
             the test below proves nothing because both paths would succeed"
        );

        let retried = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .connect(DEAD)
            .await;
        assert!(
            retried.is_ok(),
            "with retry_on_initial_connect the client must be constructed and keep \
             retrying in the background; returning Err here restores the defect — capture \
             dead for the whole process because NATS happened to be down at boot"
        );

        // Both assertions above exercise async_nats directly, so they would still pass
        // if someone reverted the BOOT PATH to a plain `connect()`. Pin the call site.
        //
        // COMMENTS ARE STRIPPED FIRST, and that is not incidental. The first version of
        // this check searched the raw source, and the raw source is full of prose about
        // the very thing being checked — this comment, the boot-path comment, the
        // assertion message below. Reverting the boot path left every one of those in
        // place, so the check passed against the defect. That is the second time today
        // a guard keyed on a WORD instead of a CONSTRUCTION (see
        // scripts/ci/check-federation-hash-deferral.py), and both were caught only by
        // falsifying rather than by reading.
        // ...and the search is scoped to PRODUCTION code — everything before the test
        // module. Stripping comments was not enough: this test's own body calls
        // `retry_on_initial_connect()` a few lines up, so with the whole file in scope
        // the boot path could be deleted entirely and the needle would still be found
        // in the test that exists to catch that. Third self-match today (see
        // billing/usage.rs and tlane-watchdog.sh) — a source-scanning assertion must
        // never be able to see itself.
        let whole = include_str!("server.rs");
        let prod = whole
            .split_once("\n#[cfg(test)]")
            .map_or(whole, |(before, _)| before);
        let code: String = prod
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        // Needle split so it cannot match this line either.
        assert!(
            code.contains(concat!(".retry_on_initial", "_connect()")),
            "the gateway's NATS boot path must CALL retry_on_initial_connect — without \
             it a gateway that starts while NATS is down never records again"
        );
    }

    /// the LIVE half. The test above proves the client is CONSTRUCTED against a
    /// dead port; it does not prove the client HEALS. This does: build against a dead
    /// port, then start a real NATS on that port and confirm the SAME client publishes.
    ///
    /// `#[ignore]` because it needs docker and ~20s. Run it deliberately:
    ///   cargo test -p gateway --bin gateway -- b198_client_heals --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs docker; run deliberately"]
    async fn b198_client_heals_once_nats_appears() {
        use std::process::Command;
        const PORT: &str = "4299";
        let url = format!("nats://127.0.0.1:{PORT}");
        let name = "b198-nats-heal";

        let _ = Command::new("docker").args(["rm", "-f", name]).output();

        // 1. Build the client while NOTHING is listening. Under the old code path this
        //    is where capture died permanently.
        let client = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .connect(&url)
            .await
            .expect("client must be constructed against a dead port");

        // 2. Bring NATS up on that port.
        let up = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                name,
                "-p",
                &format!("127.0.0.1:{PORT}:4222"),
                "nats:2.10-alpine",
            ])
            .output()
            .expect("docker run");
        assert!(
            up.status.success(),
            "could not start NATS: {}",
            String::from_utf8_lossy(&up.stderr)
        );

        // 3. Poll publish until the background retry connects.
        let mut healed = false;
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            // publish() alone can succeed into the client's buffer while still
            // disconnected — flush() is what proves the bytes reached a server, so
            // both must succeed or this would report "healed" on a queued message.
            if client.publish("b198.heal", "x".into()).await.is_ok() && client.flush().await.is_ok()
            {
                healed = true;
                break;
            }
        }
        let _ = Command::new("docker").args(["rm", "-f", name]).output();

        assert!(
            healed,
            "the client never recovered after NATS came up — the retry is not working; a \
             gateway that boots during a NATS restart would drop every span forever"
        );
    }

    /// S6 (2026-09-04): an OPEN fail-open must be visible on `/health`, and a
    /// healthy gateway must publish an EMPTY list rather than omitting the field —
    /// an absent field and "nothing wrong" are the two states this must not merge.
    ///
    /// Uses a real `note()` because the counters are process-global statics: the
    /// point is that the same call every fail-open path already makes is what
    /// surfaces here, with no second bookkeeping to forget.
    #[test]
    fn health_publishes_open_degradations() {
        use tracelane_shared::degradation::{Degradation, note};

        let before = health_body(true, 0, 0);
        assert!(
            before["degraded"].is_array(),
            "`degraded` must always be an array, never absent"
        );
        let before_n = before["degraded_open"]
            .as_u64()
            .expect("degraded_open is a number");

        note(Degradation::SemanticCacheUnavailable);
        let after = health_body(true, 0, 0);
        let listed = after["degraded"]
            .as_array()
            .expect("array")
            .iter()
            .any(|d| d["kind"] == "semantic_cache_unavailable");
        assert!(listed, "a noted degradation must appear in /health");
        assert!(
            after["degraded_open"].as_u64().expect("number") >= before_n.max(1),
            "degraded_open must count the open kinds"
        );
        let entry = after["degraded"]
            .as_array()
            .expect("array")
            .iter()
            .find(|d| d["kind"] == "semantic_cache_unavailable")
            .expect("entry");
        assert!(
            entry["count"].as_u64().expect("count") >= 1,
            "the entry carries its count"
        );
        assert!(
            !entry["open_for_secs"].is_null(),
            "the entry carries how long it has been open — the question a fail-open must answer"
        );
    }

    /// S7 (SRE audit 2026-09-04). `scripts/ops/tlane-status.sh` grepped the gateway log
    /// for `"PromptGuard FAILING OPEN"` — a string no code in this tree emits — so the
    /// count was pinned to 0, the watchdog read that zero, and every ops board printed a
    /// green PromptGuard for a sidecar production does not run. A rename disabled a
    /// control in silence.
    ///
    /// The count now comes from here. This test exists so the KEY cannot be dropped or
    /// renamed without something going red: the log-grep failed precisely because no
    /// test owned the name it depended on.
    #[test]
    fn health_publishes_prompt_guard_fail_opens() {
        // The counter is process-global and other tests in this binary advance it
        // concurrently, so "equals the live value" is a race (692 vs 693 in a full
        // gate, 2026-09-06). The property is that /health publishes the LIVE counter,
        // not a constant: the published value must lie inside the window read
        // immediately before and after the body was built.
        let before = crate::predictive::prompt_guard::fail_opens_total();
        let body = health_body(true, 0, 0);
        let after = crate::predictive::prompt_guard::fail_opens_total();
        let v = &body["prompt_guard_fail_opens"];
        assert!(
            v.is_u64(),
            "`prompt_guard_fail_opens` must be present and numeric on /health, \
             not absent — ops reads an absent key as unknown, and the whole point of \
             S7 is that a missing signal must never read as a healthy zero. Got: {v:?}"
        );
        let published = v.as_u64().expect("number");
        assert!(
            (before..=after).contains(&published),
            "/health must publish the live counter, not a constant \
             (published {published}, live window {before}..={after})"
        );

        // The follow-up defect, and the more embarrassing half. With only the counter
        // published, the ops board read `0` and printed "PromptGuard enforcing" — for a
        // sidecar prod does not run, because `PROMPT_GUARD_URL` is unset and the
        // predictor is omitted from the stack entirely. Zero fail-opens is trivially
        // true when the thing never executes. The flag is the denominator.
        let c = &body["prompt_guard_configured"];
        assert!(
            c.is_boolean(),
            "`prompt_guard_configured` must be present and boolean — without it a zero \
             count reads as health rather than as absence. Got: {c:?}"
        );
        assert_eq!(
            c.as_bool().expect("bool"),
            crate::predictive::prompt_guard::is_configured(),
            "/health must publish whether the sidecar is actually configured"
        );
    }

    // ── B-389: admission — the exact stack `run()` serves, driven in-process. ──

    async fn admission_body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body");
        serde_json::from_slice(&bytes).expect("response body is JSON")
    }

    fn admission_app(max_inflight: usize, timeout: std::time::Duration) -> Router {
        async fn park() -> &'static str {
            std::future::pending::<()>().await;
            "never"
        }
        async fn slow() -> &'static str {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            "late"
        }
        async fn quick() -> &'static str {
            "ok"
        }
        let inner = Router::new()
            .route("/park", get(park))
            .route("/slow", get(slow))
            .route("/quick", get(quick));
        with_admission(
            inner,
            AdmissionConfig {
                max_inflight,
                request_timeout: timeout,
            },
        )
        .route("/health", get(|| async { "alive" }))
    }

    #[tokio::test]
    async fn the_request_over_the_inflight_limit_is_shed_immediately_and_health_still_answers() {
        use tower::ServiceExt as _;
        let app = admission_app(2, std::time::Duration::from_secs(30));
        let before = crate::metrics::render();
        let shed_before = before
            .lines()
            .find_map(|l| l.strip_prefix("tracelane_gateway_load_shed_total "))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        // Two requests park inside the limit …
        let a = tokio::spawn(
            app.clone().oneshot(
                axum::http::Request::builder()
                    .uri("/park")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            ),
        );
        let b = tokio::spawn(
            app.clone().oneshot(
                axum::http::Request::builder()
                    .uri("/park")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            ),
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // … the third is refused at once, not queued.
        let started = std::time::Instant::now();
        let third = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/quick")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(third.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "shed must be immediate"
        );
        assert_eq!(
            third
                .headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap()),
            Some("1")
        );
        let body = admission_body_json(third).await;
        assert_eq!(body["error"], "overloaded");
        // /health is outside the stack.
        let h = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(h.status(), StatusCode::OK, "/health must answer under shed");
        let after = crate::metrics::render();
        let shed_after = after
            .lines()
            .find_map(|l| l.strip_prefix("tracelane_gateway_load_shed_total "))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        assert!(shed_after > shed_before, "the shed must be counted");
        a.abort();
        b.abort();
    }

    #[tokio::test]
    async fn a_handler_past_the_timeout_answers_408() {
        use tower::ServiceExt as _;
        let app = admission_app(64, std::time::Duration::from_millis(200));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/slow")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(admission_body_json(resp).await["error"], "request_timeout");
    }

    #[test]
    fn admission_config_defaults_and_refuses_zero_or_garbage() {
        let d = AdmissionConfig::from_values(None, None);
        assert_eq!(d.max_inflight, AdmissionConfig::DEFAULT_MAX_INFLIGHT);
        assert_eq!(
            d.request_timeout.as_secs(),
            AdmissionConfig::DEFAULT_REQUEST_TIMEOUT_SECS
        );
        let c = AdmissionConfig::from_values(Some("512"), Some("60"));
        assert_eq!(c.max_inflight, 512);
        assert_eq!(c.request_timeout.as_secs(), 60);
        // A limit of zero is an outage with a config key; garbage is a typo.
        assert_eq!(AdmissionConfig::from_values(Some("0"), Some("0")), d);
        assert_eq!(AdmissionConfig::from_values(Some("lots"), Some("-5")), d);
    }

    /// B-378: `/health` publishes the audit backlog, and a reading nobody has
    /// taken is UNHEALTHY — never a reassuring zero.
    #[test]
    fn health_publishes_the_audit_backlog_and_a_never_read_backlog_is_unhealthy() {
        let body = health_body(true, 0, 0);
        let b = &body["audit_backlog"];
        assert!(b.is_object(), "audit_backlog must be an object: {body}");
        for key in ["pending", "ack_pending", "read_secs_ago", "healthy"] {
            assert!(b.get(key).is_some(), "audit_backlog.{key} missing: {b}");
        }
        // In this process no head-writer has ever polled, so the reading is
        // absent and the verdict must say so.
        assert_eq!(b["read_secs_ago"], serde_json::Value::Null);
        assert_eq!(
            b["healthy"], false,
            "a backlog nobody has read must not report healthy"
        );
    }

    /// `/health` must distinguish "up" from "recording". Those were the same field.
    #[test]
    fn health_reports_capture_separately_from_liveness() {
        let healthy = health_body(true, 0, 0);
        assert_eq!(healthy["status"], "ok");
        assert_eq!(healthy["capture_healthy"], true);
        assert_eq!(healthy["capture_enabled"], true);
        assert_eq!(healthy["spans_dropped"], 0);

        // Capture never wired: still "ok" (liveness), but NOT healthy for capture.
        let blind = health_body(false, 0, 0);
        assert_eq!(
            blind["status"], "ok",
            "/health is the load-balancer liveness probe — failing it would turn a \
             recording outage into a serving outage"
        );
        assert_eq!(
            blind["capture_healthy"], false,
            "a gateway that records nothing must not report capture as healthy"
        );

        // Wired, but data was lost: healthy=false, and it is STICKY.
        let lost = health_body(true, 7, 0);
        assert_eq!(lost["capture_enabled"], true);
        assert_eq!(lost["spans_dropped"], 7);
        assert_eq!(
            lost["capture_healthy"], false,
            "'we lost 7 spans' does not stop being true when the cause clears"
        );
    }

    /// R17 — capture and ATTESTATION are independent, and the whole point is that a
    /// reader can tell which one is broken. The two assertions below are opposing on
    /// purpose: neither alone separates "the field exists" from "the field is wired
    /// to the right counter".
    #[test]
    fn health_reports_audit_attestation_separately_from_capture() {
        // Perfect capture, BROKEN attestation. This is the state that was invisible:
        // every span recorded, and the ledger silently not third-party verifiable.
        let unattested = health_body(true, 0, 3);
        assert_eq!(
            unattested["capture_healthy"], true,
            "capture is fine here — folding attestation into capture_healthy would \
             misreport WHICH half failed"
        );
        assert_eq!(
            unattested["audit_attestation_healthy"], false,
            "3 failed backfills means rows are unsigned/unanchored; the ledger is NOT \
             third-party verifiable and /health must say so"
        );
        assert_eq!(unattested["audit_backfill_failures"], 3);

        // And the inverse, so the first case cannot pass by the field being hardcoded:
        // capture broken, attestation fine.
        let uncaptured = health_body(true, 5, 0);
        assert_eq!(uncaptured["capture_healthy"], false);
        assert_eq!(
            uncaptured["audit_attestation_healthy"], true,
            "dropped spans do not make the ledger unverifiable — these are different \
             failures and must not move together"
        );

        // Liveness is unaffected by either: /health is the load-balancer probe.
        assert_eq!(health_body(true, 0, 9)["status"], "ok");
    }

    /// B-377: whatever is still in flight when the drain deadline passes is
    /// counted on the ONE loss counter `/health` reads — never assumed sent.
    #[tokio::test]
    async fn shutdown_drain_counts_unacked_publishes_as_lost() {
        let _g = crate::otlp_emit::DRAIN_TEST_LOCK.lock().await;
        let _release = crate::otlp_emit::fake_in_flight(2);
        let before = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::SpanPublishFailed,
        );
        // A tiny timeout so the test does not wait on the production bound.
        let left = crate::otlp_emit::drain_in_flight(std::time::Duration::from_millis(50)).await;
        assert_eq!(left, 2);
        for _ in 0..left {
            crate::otlp_emit::note_span_publish_failed();
        }
        let after = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::SpanPublishFailed,
        );
        assert_eq!(
            after - before,
            2,
            "two unacked publishes must be two counted losses"
        );
        // And the real drain path with nothing in flight and no client returns promptly.
        drop(_release);
        let t0 = std::time::Instant::now();
        drain_on_shutdown(None).await;
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    }

    /// INCLUDE_STR GUARD (B-385 2c) — a boot-path LITERAL: the refusal lives in
    /// `run()`, which no in-process test can drive without a Postgres URL.
    #[test]
    fn bench_flag_with_hosted_postgres_is_a_startup_refusal() {
        // Verifier finding 1: the request-time `entitlements.is_none()` check is
        // NOT a structural impossibility on a hosted node whose pool init failed
        // (server.rs:244-258 warns and continues). The startup refusal below is
        // what makes it one. Assert the guard exists verbatim — if it is removed,
        // the "structurally unreachable" claim silently becomes false again.
        let src = include_str!("server.rs");
        assert!(
            src.contains(concat!(
                "config.bench_mock_upstream\n",
                "        && (std::env::var(\"POSTGRES_URL\")"
            )),
            "the startup refusal for bench-flag + hosted Postgres is gone — condition 3 \
             is back to a request-time observation that a failed pool init can defeat"
        );
    }

    /// GWY-41 / B-227. `/v1/traces` is now bound TWICE, in two different
    /// routers, behind two different gates: `GET` in `trace_reads::routes()`
    /// (ClickHouse read, `CLICKHOUSE_URL`-gated) and `POST` here (OTLP write,
    /// unconditional). `Router::merge` PANICS when two routers define the same
    /// method on the same path, and a panic there is a boot panic — the gateway
    /// would not start at all.
    ///
    /// Two halves, because neither alone is discriminating:
    ///   (a) the runtime half proves axum actually combines disjoint methods on
    ///       one path and dispatches BOTH — if that were false the gateway could
    ///       not boot;
    ///   (b) the source half pins the two real literals, so adding `get()` to the
    ///       write route or `post()` to the read router fails here rather than at
    ///       boot in production.
    ///
    /// INCLUDE_STR GUARD (B-385 2c) — half (b) is a ROUTE-MOUNT LITERAL, kept.
    #[tokio::test]
    async fn both_methods_on_v1_traces_coexist() {
        // (a) runtime — merge, then dispatch each method.
        async fn read() -> &'static str {
            "read"
        }
        async fn write() -> &'static str {
            "write"
        }
        let reads = Router::new().route("/v1/traces", get(read));
        let writes = Router::new().route("/v1/traces", post(write));
        let app = reads.merge(writes);

        let server = axum_test::TestServer::new(app);
        assert_eq!(server.get("/v1/traces").await.text(), "read");
        assert_eq!(server.post("/v1/traces").await.text(), "write");

        // (b) source — both real bindings still exist, with the methods that make
        // (a) applicable. A future edit that gives either route the OTHER method
        // turns the merge into a panic, and this is what catches it.
        //
        // WHITESPACE IS STRIPPED FROM BOTH SIDES. The first version matched a
        // contiguous literal and went red the moment `cargo fmt` wrapped the
        // mount across four lines — a guard that fails on FORMATTING trains
        // people to edit the guard, which is worse than not having it. Stripping
        // whitespace keeps it sensitive to the one thing it is about (the METHOD
        // bound to the path) and blind to how rustfmt lays it out.
        fn squeeze(s: &str) -> String {
            s.chars().filter(|c| !c.is_whitespace()).collect()
        }
        let reads_src = squeeze(include_str!("trace_reads.rs"));
        let read_needle = format!(
            "{}{}",
            r#".route("/v1/traces","#, r#"get(list_traces_handler))"#
        );
        assert!(
            reads_src.contains(&squeeze(&read_needle)),
            "the read route moved or changed method — re-check the merge"
        );
        let server_src = squeeze(include_str!("server.rs"));
        // The needle is ASSEMBLED AT RUNTIME and never appears contiguously in this
        // file, so it cannot be satisfied by this assertion's own text. The first
        // version of this check was written as one literal and PASSED while the real
        // mount had been changed from `post` to `get` — `include_str!("server.rs")`
        // found the assertion itself. A probe that cannot tell the two answers apart
        // is not a probe.
        let needle = format!(
            "{}{}",
            r#".route("/v1/traces","#, r#"post(crate::trace_ingest::ingest_traces_handler)"#
        );
        assert!(
            server_src.contains(&squeeze(&needle)),
            "the write route moved or changed method — re-check the merge"
        );
    }

    /// B-230. Six routes authenticated a caller and then returned tenant data — or
    /// spent the tenant's provider budget — with NO scope check, so the A13
    /// vocabulary was unenforced on the surfaces it was written for. GWY-41 made it
    /// sharper by shipping an `ingest` scope that is default-on, i.e. a real
    /// credential in a customer's container image.
    ///
    /// INCLUDE_STR GUARD (B-385 2c) — kept for the FOUR read-route families that
    /// are NOT on the admission pipeline (each has its own state type and no
    /// harness yet). The chat / embeddings / messages half of this test is gone:
    /// those three run ONE pipeline, and the gate's position is proven by a run —
    /// `admission::tests::a_read_scoped_key_is_refused_at_scope_before_any_charge`
    /// refuses a `read`-scoped key with the quota and ledger counters untouched.
    ///
    /// Needles are ASSEMBLED AT RUNTIME so this test cannot be satisfied by its own
    /// source text; the first version of the sibling route guard passed while the
    /// thing it checked had been changed, for exactly that reason.
    #[test]
    fn every_b230_route_gates_on_scope_after_authenticating() {
        let auth_call = format!("{}{}", "validate_", "authorization");
        let read_gate = format!("{}{}", "allows_scope(crate::auth::scope::", "Scope::Read)");

        for (label, src, gate) in [
            (
                "tool-analytics",
                include_str!("tool_analytics.rs"),
                &read_gate,
            ),
            (
                "billing-usage",
                include_str!("billing/usage.rs"),
                &read_gate,
            ),
            (
                "audit-export/summary",
                include_str!("audit_export.rs"),
                &read_gate,
            ),
            (
                "audit-self-verify",
                include_str!("audit_self_verify.rs"),
                &read_gate,
            ),
        ] {
            let g = src
                .find(gate.as_str())
                // The ref stays in the COMMENT above, never in the message: this guard has no
                // test carve-out on purpose, because an exemption keyed on "looks like a
                // test" is a hole in a guard that exists to stop internal refs reaching a
                // customer.
                .unwrap_or_else(|| panic!("{label}: scope gate REMOVED — regression"));
            let a = src
                .find(auth_call.as_str())
                .unwrap_or_else(|| panic!("{label}: no authentication call found at all"));
            assert!(
                g > a,
                "{label}: the scope gate moved ABOVE authentication — it would read \
                 claims that do not exist yet"
            );
        }

        // The fifth prompt WRITE surface. `/observe` feeds the auto-rollback engine,
        // which moves the production routing pointer, and it used to authenticate
        // with no role check while its four siblings used the single-site helper.
        let prompts = include_str!("prompt_routes.rs");
        let observe = prompts
            .find("async fn observe")
            .or_else(|| prompts.find("fn observe_handler"))
            .expect("observe handler");
        let tail = &prompts[observe..];
        let actor = format!("{}{}", "actor_from_", "auth(&headers)");
        assert!(
            tail.contains(actor.as_str()),
            "/prompts/{{name}}/observe no longer authorizes the WRITE — a viewer could \
             move production prompt routing"
        );
    }
}

/// Endpoint env vars that do NOT resolve to loopback (B-239).
///
/// Pure over an iterator of `(name, value)` so the refusal is unit-testable
/// without touching the process environment — the same discipline as
/// `capture_boot_decision`. Selection is by NAME SHAPE (`*_URL` / `*_ENDPOINT`),
/// deliberately, so a variable added later is covered without editing this list.
pub fn bench_nonlocal_endpoints<I: Iterator<Item = (String, String)>>(vars: I) -> Vec<String> {
    let mut out: Vec<String> = vars
        .filter(|(k, _)| {
            let u = k.to_ascii_uppercase();
            u.ends_with("_URL") || u.ends_with("_ENDPOINT")
        })
        .filter(|(_, v)| !v.trim().is_empty())
        .filter(|(_, v)| !host_is_loopback(v))
        .map(|(k, v)| format!("{k}={}", redact_endpoint(&v)))
        .collect();
    out.sort();
    out
}

/// Host component of a URL-ish value, lowercased. Deliberately tolerant: a value
/// that cannot be parsed is treated as NOT loopback, because failing closed is
/// the safe direction for a boot refusal.
fn endpoint_host(value: &str) -> String {
    let v = value.trim();
    let after_scheme = v.split_once("://").map_or(v, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // IPv6 literal keeps its brackets' contents; otherwise strip a trailing :port.
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(h, _)| h)
    } else {
        host_port.rsplit_once(':').map_or(host_port, |(h, p)| {
            if p.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                host_port
            }
        })
    };
    host.to_ascii_lowercase()
}

fn host_is_loopback(value: &str) -> bool {
    let h = endpoint_host(value);
    h == "localhost"
        || h == "127.0.0.1"
        || h == "::1"
        || h == "0.0.0.0"
        || h.ends_with(".localhost")
        || h.starts_with("127.")
}

/// Never echo credentials from a connection string into a boot error.
fn redact_endpoint(value: &str) -> String {
    let h = endpoint_host(value);
    if h.is_empty() {
        "<unparseable>".to_string()
    } else {
        h
    }
}

#[cfg(test)]
mod bench_isolation_tests {
    use super::*;

    fn v(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
            .collect()
    }

    #[test]
    fn loopback_endpoints_are_allowed() {
        let got = bench_nonlocal_endpoints(
            v(&[
                ("NATS_URL", "nats://127.0.0.1:4222"),
                ("CLICKHOUSE_URL", "http://localhost:8123"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://[::1]:4318"),
            ])
            .into_iter(),
        );
        assert!(
            got.is_empty(),
            "loopback must not trip the refusal, got {got:?}"
        );
    }

    #[test]
    fn production_endpoints_are_refused() {
        let got = bench_nonlocal_endpoints(
            v(&[
                ("NATS_URL", "nats://nats.prod.internal:4222"),
                ("CLICKHOUSE_URL", "http://10.0.0.5:8123"),
            ])
            .into_iter(),
        );
        assert_eq!(
            got.len(),
            2,
            "both prod endpoints must be named, got {got:?}"
        );
    }

    /// THE PROPERTY THAT MAKES THIS STRUCTURAL: a variable nobody thought of.
    /// If this ever needs a code change to pass, the mechanism has regressed to
    /// a maintained list and B-239 can recur.
    #[test]
    fn an_endpoint_variable_that_did_not_exist_when_this_was_written_is_still_caught() {
        let got = bench_nonlocal_endpoints(
            v(&[("SOME_FUTURE_SERVICE_URL", "https://prod.example.com")]).into_iter(),
        );
        assert_eq!(
            got.len(),
            1,
            "a *_URL added later must be covered by default"
        );
    }

    #[test]
    fn credentials_are_never_echoed_into_the_boot_error() {
        let got = bench_nonlocal_endpoints(
            v(&[("POSTGRES_URL", "postgres://user:hunter2@db.prod:5432/x")]).into_iter(),
        );
        assert_eq!(got.len(), 1);
        assert!(
            !got[0].contains("hunter2"),
            "must not leak a password: {got:?}"
        );
        assert!(
            got[0].contains("db.prod"),
            "must still name the host: {got:?}"
        );
    }

    #[test]
    fn unparseable_values_fail_closed() {
        let got = bench_nonlocal_endpoints(v(&[("WEIRD_URL", "not a url at all")]).into_iter());
        assert_eq!(
            got.len(),
            1,
            "an unparseable endpoint must refuse, not pass"
        );
    }

    #[test]
    fn non_endpoint_variables_are_ignored() {
        let got = bench_nonlocal_endpoints(
            v(&[("RUST_LOG", "info"), ("SSL_CERT_FILE", "/etc/ssl/cert.pem")]).into_iter(),
        );
        assert!(
            got.is_empty(),
            "only *_URL / *_ENDPOINT are in scope, got {got:?}"
        );
    }
}
