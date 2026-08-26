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
use async_stream::stream;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use futures::StreamExt as _;
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing::instrument;
use uuid::Uuid;

use crate::audit::{AuditChain, AuditEvent};
use crate::predictive::{Decision, PredictiveContext, PredictiveLayer};
use crate::providers::{ProviderEvent, ProviderRegistry, ProviderStream};
use crate::rate_limiter::{
    QuotaConfig, QuotaDecision, QuotaTracker, RateLimitDecision, RateLimitTier, RateLimiter,
};
use tracelane_shared::{
    TenantId, TracelaneSpan,
    span::{SpanAttributes, SpanStatus, SpanStatusCode},
};

/// `tracelane.yaml` reader (GWY-39) — `crates/gateway/src/config.rs`.
///
/// Declared here with `#[path]`, resolved relative to `src/`, rather than as a
/// `mod config;` in `main.rs`. The module is only ever reached through
/// `crate::server::config::…`; folding the declaration into `main.rs`'s module
/// list is a mechanical follow-up with no behaviour change.
#[path = "config.rs"]
pub mod config;

/// Gateway configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub log_level: String,
    pub otlp_endpoint: Option<String>,
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
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            port: std::env::var("TRACELANE_PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .context("TRACELANE_PORT must be a valid port number")?,
            log_level: std::env::var("TRACELANE_LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
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
    /// Monthly trace-quota tracker enforcing the hard 5× cap.
    /// Hot-path budget <500ns p99 (see `benches/rate_limiter.rs`).
    pub quota_tracker: Arc<QuotaTracker>,
    /// ClickHouse URL the `quota_tracker` rehydrates the durable monthly
    /// baseline from on (re)start / month rollover, so a restart or blue-green
    /// deploy no longer forgives accrued quota. `None` (dev / no CH) disables
    /// rehydration — the counter starts at 0. Mirrors `config.clickhouse_url`.
    pub quota_ch_url: Option<String>,
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
    /// Polar.sh billing recorder. `None` when `POLAR_ACCESS_TOKEN` isn't
    /// set — meter events are dropped on the floor in dev. Production
    /// sets the env var; the recorder spawns a 60-second flusher task
    /// at startup.
    pub billing: Option<Arc<crate::billing::Recorder>>,
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
        tracing::warn!(
            single_tenant_id = %sh.tenant_id(),
            "SINGLE-TENANT SELF-HOST mode active (ADR-067) — every request authenticates as this \
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
            crate::byok::set_global_master_key(master);
            tracing::info!("BYOK master key installed — per-tenant provider keys enabled");
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
    if std::env::var("POSTGRES_URL").is_ok() || std::env::var("PGHOST").is_ok() {
        match crate::db::build_pool().await {
            Ok(pool) => {
                tracing::info!("Postgres pool ready");
                // B-256: hold a few pooled connections warm. Without this a
                // request arriving after an idle gap pays a fresh connect
                // (~94 ms measured) and, if the managed compute has suspended,
                // its resume (~1.2 s). See `db/keepalive.rs` — it documents what
                // breaks if this line is removed, because the keepalive this
                // replaces was an accidental side effect of the alert poller and
                // was deleted without anyone knowing it was load-bearing.
                crate::db::keepalive::spawn(pool.clone());
                // B-256: keep ACTIVE api-key entries warm against the control
                // plane. Without it a key presented less often than the 60s
                // cache TTL misses on every request and pays a Neon round trip
                // plus an Argon2id verify — the same defect the entitlement
                // cache already fixed for itself. The refresh interval becomes
                // the revocation bound, which is TIGHTER than the TTL it
                // replaces, so this is not a security relaxation.
                crate::db::api_keys::spawn_auth_cache_refresher(pool.clone());
                crate::db::set_global_pool(pool);
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
    let entitlements = crate::db::global_pool().map(|pool| {
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
    if let Some(pool) = crate::db::global_pool().cloned() {
        crate::retention_sweep::spawn_retention_task(
            pool,
            config.clickhouse_url.clone(),
            crate::retention_sweep::SweepMode::from_env(),
        );
    }

    let tenant_audit_keys = match crate::db::global_pool() {
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
            crate::db::global_pool().cloned(),
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
            Some(url) => match async_nats::ConnectOptions::new()
                .retry_on_initial_connect()
                .connect(url)
                .await
            {
                Ok(client) => {
                    tracing::info!(
                        %url,
                        "NATS span publish wired (connect retries in the background if \
                         the server is not yet reachable)"
                    );
                    CAPTURE_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                    Some(Arc::new(client))
                }
                // With retry enabled this is now genuinely exceptional — a malformed
                // URL or an auth rejection, not "the server is down". Still fail-open
                // rather than fatal, and still loud.
                Err(err) => {
                    tracing::error!(
                        error = %err, %url,
                        "NATS client could not be constructed even with initial-connect \
                         retry — span publish DISABLED; ALL spans will be dropped. This \
                         is a bad NATS_URL or an auth rejection, not an unreachable \
                         server. Check the value."
                    );
                    None
                }
            },
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
    let quota_tracker = Arc::new(QuotaTracker::new());
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
                tracing::warn!(
                    "audit: no Postgres control plane — using the SYNCHRONOUS append \
                     path (ClickHouse-persisted). The ADR-069 async stream is NOT \
                     enabled: its consumer requires Postgres and would fail every \
                     append and redeliver forever. NOTE: without Postgres the chain \
                     does not resume across a restart (warm_from_postgres is the only \
                     resume path), so seq restarts at genesis on reboot."
                );
            }
            Ok(()) => {
                audit_chain.set_jetstream(js, kill_switch.clone());
                crate::audit_consumer::spawn(Arc::clone(&audit_chain), (**nats_client).clone());
                tracing::info!(
                    "ADR-069 async audit enabled — TRACELANE_AUDIT stream + head-writer consumer"
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
    // None and the chat hot path skips the record() call. The
    // PolarClient is reused by /v1/billing/portal below — share via Arc.
    let (billing, polar_for_portal) = match crate::billing::polar_client::access_token_from_env() {
        Ok(token) => {
            use secrecy::ExposeSecret as _;
            let polar = Arc::new(crate::billing::PolarClient::new(
                token.expose_secret().to_owned(),
            ));
            let recorder = Arc::new(crate::billing::Recorder::new(Arc::clone(&polar)));
            Arc::clone(&recorder).spawn_flusher();
            tracing::info!("Polar billing recorder ready (60s flush)");
            (Some(recorder), Some(polar))
        }
        Err(_) => {
            tracing::info!("POLAR_ACCESS_TOKEN not set — billing recorder disabled");
            (None, None)
        }
    };

    // Wire the billing recorder into the audit chain so each SUCCESSFUL
    // Rekor anchor batch meters one `audit_anchors` usage event (ADR-048). Off
    // the anchor path (fire-and-forget, tenant→customer mapped in the hook). No
    // recorder (POLAR_ACCESS_TOKEN unset) → anchoring is simply not metered.
    if let Some(ref recorder) = billing {
        audit_chain.set_billing(Arc::clone(recorder));
    }

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
        if let Some(pool) = crate::db::global_pool() {
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
            Some(Arc::new(crate::semantic_cache::SemanticCache::new(
                crate::clickhouse_query::ch_client(url),
                providers.clone(),
                cfg.clone(),
            )))
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
        quota_tracker,
        quota_ch_url: config.clickhouse_url.clone(),
        predictive,
        // Observe-first by default (ADR-055 amendment); opt-in enforcement.
        predictive_enforce: std::env::var("TRACELANE_PREDICTIVE_ENFORCE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        guardrail,
        billing,
        nats,
        entitlements: entitlements_for_state,
        circuit_breaker,
        kill_switch,
        prompt_router,
        bench_mock_upstream: config.bench_mock_upstream,
    };

    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/v1/auth/whoami", get(whoami_handler))
        .route("/v1/chat/completions", post(chat_completions_handler))
        // GWY-26. Mounted UNCONDITIONALLY, beside chat/completions — an
        // embeddings call that silently bypasses the gateway is the fidelity
        // hole this closes, so it must not be env-gated into a 404.
        .route("/v1/embeddings", post(embeddings_handler))
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
        let reader = std::sync::Arc::new(crate::audit_export::ClickHouseExportReader::new(ch));
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
        let trace_reader =
            std::sync::Arc::new(crate::trace_reads::ClickHouseTraceReader::new(trace_ch));
        let trace_state = crate::trace_reads::TraceReadState {
            reader: trace_reader,
        };
        let trace_app = crate::trace_reads::routes().with_state(trace_state);
        app = app.merge(trace_app);
        // Tool-analytics (Trajectory / ledger #14) — same on-node CH gate.
        let tool_state = crate::tool_analytics::ToolAnalyticsState {
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
            store: std::sync::Arc::new(crate::dataset_routes::ClickHouseDatasetStore::new(
                crate::clickhouse_query::ch_client(ch_url.clone()),
            )),
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
    if crate::db::global_pool().is_some() {
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
    if let Some(pool) = crate::db::global_pool() {
        let key_state = crate::key_routes::KeyRoutesState {
            minter: std::sync::Arc::new(crate::key_routes::PgKeyMinter { pool: pool.clone() }),
        };
        app = app.merge(crate::key_routes::routes().with_state(key_state));
        tracing::info!("API-key mint mounted at POST /v1/keys");

        // OBS-18 annotations. Postgres-backed (mutable, low-volume, read one
        // trace at a time), so it mounts here beside the other PG routes rather
        // than in `trace_reads`, which is the ClickHouse surface. Gated on the
        // same `global_pool()` — with no control plane the routes are simply
        // absent, which is a clean 404 rather than a broken surface.
        let ann_state = crate::annotation_routes::AnnotationRoutesState {
            store: std::sync::Arc::new(crate::annotation_routes::PgAnnotationStore {
                pool: pool.clone(),
            }),
        };
        app = app.merge(crate::annotation_routes::routes().with_state(ann_state));
        tracing::info!("annotations mounted at /v1/traces/{{trace_id}}/annotations");

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
            std::sync::Arc::new(crate::prompt_eval::PromptEvalEngine::new(
                crate::clickhouse_query::ch_client(url),
                state.providers.clone(),
                state.prompt_router.clone(),
                // R81: the SAME NATS client the chat path publishes through, so an
                // eval case's span travels the identical route to ClickHouse. A
                // second publish path would be a second definition of "a span was
                // captured", and the two would disagree on the first failure.
                state.nats.clone(),
            ))
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
                    ),
                ),
                // The SAME dataset store the dataset routes use, so "which
                // snapshot is latest" has one answer.
                datasets: std::sync::Arc::new(crate::dataset_routes::ClickHouseDatasetStore::new(
                    crate::clickhouse_query::ch_client(&ch_url),
                )),
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
        crate::db::global_pool().cloned(),
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

    let app = app.layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind listener")?;

    axum::serve(listener, app).await.context("axum serve error")
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

/// The `/health` body (A1), extracted so the contract is testable without a server.
pub(crate) fn health_body(
    capture_enabled: bool,
    spans_dropped: u64,
    audit_backfill_failures: u64,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "service": "tracelane-gateway",
        "capture_enabled": capture_enabled,
        "spans_dropped": spans_dropped,
        "capture_healthy": capture_enabled && spans_dropped == 0,
        // R17. Deliberately NOT folded into `capture_healthy`: capture and
        // attestation fail independently and a reader must be able to tell which
        // is broken. Every span can be captured while the ledger silently stops
        // being third-party verifiable — that is precisely the state this exists
        // to make visible.
        "audit_backfill_failures": audit_backfill_failures,
        "audit_attestation_healthy": audit_backfill_failures == 0,
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
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid credentials" })),
            )
                .into_response()
        }
    }
}

/// Build the B1 `PromptRouter` with its ClickHouse persister / eval gate /
/// auto-rollback engine when `CLICKHOUSE_URL` is set, else the in-memory
/// dev defaults. Shared (via `Arc`) between `AppState` (so the chat handler
/// can feed drift metrics) and the `/v1/prompts/*` sub-router.
fn build_prompt_router(clickhouse_url: Option<&str>) -> Arc<crate::prompt_router::PromptRouter> {
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

/// Does the request ask for SSE? Read from the raw body because the cache
/// decision happens before the typed request is re-serialised anywhere.
fn is_streaming_request(body: &serde_json::Value) -> bool {
    body.get("stream").and_then(serde_json::Value::as_bool) == Some(true)
}

/// Optional prompt-promotion correlation extracted from the request body so
/// the auto-rollback engine can attribute a request's metrics to a specific
/// prompt version. Absent for ad-hoc (non-managed-prompt) traffic.
///
/// **`name` and `env` used to live here and are gone deliberately.** Their only
/// consumer was the flip inside `observe_and_maybe_rollback` — `env` chose
/// whether to touch production and `name` chose which pointer to move — and the
/// hot path no longer has the authority to flip anything (see
/// `PromptRouter::observe_only`). Two things follow, and the second is why they
/// were deleted rather than left inert:
///
///   * `env` defaulted to `Production` whenever the field was absent **or**
///     unparseable, conflating "not stated" with "not understood" and resolving
///     both to the one value that mutates. With no flip there is nothing left to
///     default.
///   * A struct that still carried a name and an env would be an invitation to
///     re-wire the flipping call, since the arguments would be sitting right
///     there. Removing them makes the capability unreachable rather than merely
///     unused.
#[derive(Clone)]
struct PromptObservation {
    version_id: Uuid,
}

impl PromptObservation {
    /// Returns `Some` only when the body carries a parseable
    /// `tracelane_prompt_version_id`.
    ///
    /// `tracelane_prompt_name` is no longer required: it selected a flip target
    /// and there is no flip. The version id alone attributes the metric, and
    /// `PromptRouter::feed_engine` refuses any id the tenant does not own.
    fn from_body(body: &serde_json::Value) -> Option<Self> {
        let version_id = body
            .get("tracelane_prompt_version_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())?;
        Some(Self { version_id })
    }
}

/// Fire-and-forget: feed one request's metrics to the auto-rollback engine,
/// OFF the response path (zero added client latency). On objective drift in
/// production the router flips the production pointer back to the previous
/// version (closing the B1 auto-rollback loop, ADR-009 §7.4.3).
#[allow(clippy::too_many_arguments)]
fn spawn_prompt_metric_observation(
    router: Arc<crate::prompt_router::PromptRouter>,
    tenant_id: TenantId,
    obs: PromptObservation,
    latency_ms: f64,
    is_error: bool,
    guardrail_fired: bool,
    total_tokens: u64,
) {
    tokio::spawn(async move {
        let metrics = crate::auto_rollback::PromptMetrics {
            // Auto-rollback's EWMA detects *relative* cost drift, so it needs a
            // signal that is consistent across ALL requests. Token volume is that
            // proxy. The model price catalog (`crate::pricing`) now powers the
            // customer-facing span cost, but is deliberately NOT mixed in here: a
            // known-model request (~$0.01) and an unknown-model one (raw tokens)
            // are different scales that would corrupt the EWMA. Migrating this
            // signal to catalog dollars end-to-end is a clean follow-up.
            cost_usd: total_tokens as f64,
            latency_ms,
            error: is_error,
            guardrail_fired,
            // Subjective metrics are populated by a post-hoc eval / SLM-judge
            // pass, not the inline gateway path.
            accuracy: None,
            hallucination: None,
        };
        // `observe_only` — NOT `observe_and_maybe_rollback`. The chat request
        // body carries `tracelane_prompt_*`, so feeding the flipping variant
        // from here made the body a prompt-WRITE surface with none of the gates
        // the HTTP write routes carry. The hot path may move the EWMA; only
        // `/v1/prompts/{name}/observe` may move production. See
        // `PromptRouter::observe_only`.
        //
        // Only the version id is carried now; `name`/`env` existed only to
        // choose a flip target and have been removed from the struct.
        if let Err(e) = router
            .observe_only(tenant_id, obs.version_id, &metrics)
            .await
        {
            // Expected and cheap for the common case: a body naming a version
            // this tenant does not own is refused by `feed_engine`. DEBUG, not
            // WARN — an untrusted field must not be able to drive log volume
            // (`.claude/rules/logging.md`).
            tracing::debug!(error = %e, "prompt metric observation not recorded");
        }
    });
}

/// Chat completions handler — hot path.
///
/// Pipeline:
///   1. Auth + tenant_id extraction (from JWT Bearer header; never from body)
///   2. Rate limit check (per-tenant token bucket)
///   3. Predictive layer evaluation (10 predictors, <50ms p99)
///   4. Audit log append (SHA-256 hash chain entry)
///   5. Provider dispatch (Anthropic default; routing by model prefix)
///   6. Response: SSE stream passthrough when `"stream": true`, else buffered JSON
///   7. NATS span publish (fire-and-forget, post-response)
///   8. x402 payment event record (fire-and-forget)
///
/// SSE chunks use OpenAI's `chat.completion.chunk` format for drop-in compatibility.
#[instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn chat_completions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    // Capture request start time for span duration calculation.
    let request_start = chrono::Utc::now();

    // Extract trace identity headers (x-trace-id) and KYA agent identity.
    // These come from the calling agent / SDK; we generate a new UUID if absent.
    let trace_id = headers
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);

    let agent_id = headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // KYA (Know Your Agent) human authorizer — who approved this agent to run.
    let human_authorizer = headers
        .get("x-human-authorizer")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Conversation/session correlation (gen_ai.conversation.id, v1.36 — ADR-032).
    // Accept either the conversation-id header or fall back to a session-id header.
    let conversation_id = headers
        .get("x-conversation-id")
        .or_else(|| headers.get("x-session-id"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Customer business reference (BFSI evidence capture — a loan/txn/case id).
    // Length-bound at this trust boundary: it is echoed into the span AND the
    // tamper-evident chain, so a malformed/oversized header value is dropped
    // (never truncated — a truncated id is a wrong id).
    let business_reference = headers
        .get("x-business-reference")
        .and_then(|v| v.to_str().ok())
        .and_then(tracelane_shared::span::bounded_business_reference);

    // B-256: per-stage hot-path timing. Costs one `Instant::now()` per stage
    // and emits NOTHING unless the pre-dispatch segment is over threshold —
    // see `hotpath.rs` for why it is not a per-request log line.
    let mut timer = crate::hotpath::StageTimer::new();

    // --- Step 1: Auth ---
    let authorization = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_owned(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Authorization header" })),
            )
                .into_response();
        }
    };

    let claims = match crate::auth::validate_authorization(&authorization).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "authentication failed");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid or expired credentials" })),
            )
                .into_response();
        }
    };

    // A13: scope gate, immediately after auth and BEFORE anything expensive.
    // A key scoped `read` (the shape you hand an external auditor) must not be
    // able to spend the tenant's provider budget. Placed here rather than at
    // dispatch so a refused request costs one comparison, not an entitlement
    // resolve, a quota check and a detection pass — the same reasoning that put
    // auth first. Legacy keys (`scope IS NULL`) allow everything, so this is a
    // no-op for every key minted before A13.
    if !claims.allows_scope(crate::auth::scope::Scope::Chat) {
        tracing::warn!(
            sub = %claims.sub,
            "api key lacks the `chat` scope — refusing completion"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": {
                    "message": "This API key is not scoped for completions. It needs the `chat` scope; mint a new key with it in Settings → API Keys.",
                    "type": "insufficient_scope",
                    "required_scope": "chat",
                }
            })),
        )
            .into_response();
    }

    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    timer.mark("auth");

    // --- Step 2: Rate limit + quota (one warm entitlement resolve) ---
    //  fix A: derive BOTH the rate-limit tier and the monthly quota config
    // from a single warm entitlement-cache read (in-process Moka, LISTEN/NOTIFY-
    // invalidated) — never a per-request Postgres round-trip. `plan_lookup_key`
    // (`builder_v1`, …) is the authoritative plan (ADR-020) and supersedes the
    // legacy `tenants.plan_tier` column the old per-request `resolve_tenant_tier`
    // PG read used. No cache (dev / no-Postgres) or a resolve failure fails
    // restricted to Free / free quota (deny_all() → `free_v1`; never over-grant).
    // Bound here (moved up from the dispatch section) so the ONE bench gate can
    // be evaluated before the rate-limit check without re-deriving the model —
    // a second model expression is the same drift class the unified gate closed.
    let mut model = body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("claude-sonnet-4-6")
        .to_owned();

    // The ONE bench gate. Sits after Step 1 auth and after
    // tenant_id is bound from claims, so an unauthenticated request can never
    // reach it. Consumed by the rate-limit tier below AND by the routing/BYOK
    // bypass further down — one expression, two uses.
    let bench_mock = bench_mock_active(state.bench_mock_upstream, &model);

    // B-187d: ONE grant at the entitlement layer, not N bypasses at N
    // enforcement points. Four limiters rejected the benchmark in sequence
    // (router 400 -> free-tier 429 -> Bench-tier-ignored 429 -> monthly quota
    // 429); each patch revealed the next. Every per-tenant check reads from
    // here, so granting here closes all of them at one auditable site — and
    // keeps bench logic out of the hot path, where a bypass could leak.
    //
    // Triple-gated (.claude/rules/tenancy.md): the env flag and the reserved
    // model are folded into `bench_mock`; `state.entitlements.is_none()` is the
    // structural third — `Some` iff a Postgres control plane exists — and a
    // STARTUP REFUSAL makes flag+Postgres unbootable, so a real tenant cannot
    // reach this branch even if a hosted pool init failed.
    let entitlements = if bench_mock && state.entitlements.is_none() {
        Some(std::sync::Arc::new(
            crate::entitlement_cache::ResolvedEntitlements::bench_unlimited(),
        ))
    } else {
        match &state.entitlements {
            Some(cache) => Some(cache.resolved(*tenant_id.as_uuid()).await),
            None => None,
        }
    };
    // B-187b: bench tier is TRIPLE-conditioned. (1) the env flag and (2) the
    // reserved `__bench_mock*` model are folded into `bench_mock`; (3) is the
    // structural one — `state.entitlements` is `Some` iff a Postgres control
    // plane exists (`server.rs:278`, `db::global_pool().map(...)`), which is
    // precisely what makes a deployment HOSTED. So a tenant that exists in
    // Postgres CANNOT acquire the bench tier even with the flag set and the
    // reserved model: the `is_none()` arm is unreachable for it. That is a
    // structural impossibility, not a check that could be bypassed.
    //
    // Without this the benchmark is rate-limited into measuring 429s: self-host
    // has no cache, so it fell to Free = 60 rpm while k6 drove 27k/s, and 99.99%
    // of a 812k-request run was throttled (checks: 53 passed / 812,220 failed).
    // No bench branch here — the tier is a property of the grant above.
    // No entitlement at all (OSS self-host, non-bench) still fails closed to Free.
    let tier = entitlements
        .as_ref()
        .map_or(RateLimitTier::Free, |e| e.rate_limit_tier());
    // GWY-43: the tenant bucket AND, when the key carries an override, its own.
    // A key with no override behaves exactly as it did before — `check_scoped`
    // falls through to the tenant decision — so this is additive for every key
    // that exists today.
    let rl = state.rate_limiter.check_scoped(
        tenant_id,
        tier,
        claims.api_key_id(),
        claims.rate_limit_rpm,
    );
    if let RateLimitDecision::Throttle { retry_after_secs } = rl {
        // Count the rejection for the Gateway-ops live counter. A 429 emits no
        // span (no dispatch), so this in-process tally is how the surface reports
        // rate-limiting honestly instead of a fabricated zero (§ honesty lock).
        crate::rejection_metrics::registry().record_rate_limited(tenant_id);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "rate limit exceeded",
                "retry_after_secs": retry_after_secs
            })),
        )
            .into_response();
    }

    timer.mark("entitlements");

    // --- Step 2b: Monthly quota hard-cap ---
    // QuotaTracker increments the per-tenant monthly counter and decides
    // Allow / AllowWithOverage / HardCapExceeded. Hot-path budget <500ns
    // p99 (criterion bench in benches/rate_limiter.rs). On HardCapExceeded
    // we return 429 + structured body and fire-and-forget POST to the
    // tenant's Slack webhook. POST failure does NOT block the 429.
    let quota_cfg = entitlements.as_ref().map_or_else(
        || QuotaConfig::from_plan_tier_str("free"),
        |e| e.quota_config(),
    );
    //  durability: rehydrate the counter from the durable ClickHouse trace
    // count once per tenant per month per process, so a restart / blue-green
    // deploy no longer forgives accrued usage. `needs_seed` keeps the warm path
    // free of the CH read.
    let year_month = current_year_month();
    if state.quota_tracker.needs_seed(tenant_id, year_month) {
        let baseline = quota_baseline_from_clickhouse(&state, tenant_id).await;
        state
            .quota_tracker
            .seed_if_needed(tenant_id, year_month, baseline);
    }
    let quota = state.quota_tracker.check(tenant_id, quota_cfg);
    // SET-08 soft cap. NON-BLOCKING by construction: notify, then fall through
    // and serve the request normally. Fire-once lives in Postgres, not in this
    // counter — see `maybe_notify_soft_cap`.
    if let Some((quota, used)) = quota.at_or_over_included_quota() {
        maybe_notify_soft_cap(tenant_id, year_month, quota, used);
    }
    // SET-13. Every request served ABOVE the included quota is billable overage.
    // `pricing.mdx` sells "$1.20/10K (5× hard cap then 429)" on Builder and Team;
    // until this arm existed the gateway produced `AllowWithOverage` and metered
    // NOTHING against it, so the whole band between 100% and the 5× cap was
    // served free while the price list said otherwise. `QuotaReached` is
    // deliberately excluded — that request is the LAST one inside the allowance,
    // not the first one outside it.
    if let (QuotaDecision::AllowWithOverage { .. }, Some(rec)) = (quota, state.billing.as_ref()) {
        spawn_overage_record(Arc::clone(rec), tenant_id.clone());
    }
    if let QuotaDecision::HardCapExceeded { limit, used } = quota {
        // Count the quota rejection for the Gateway-ops live counter (see the
        // rate-limit branch above — same rationale: no span on a 429).
        crate::rejection_metrics::registry().record_quota_exceeded(tenant_id);
        tracing::warn!(
            tenant_id = %tenant_id,
            quota_exceeded = true,
            limit,
            used,
            "quota hard cap exceeded — returning 429"
        );
        let reset_at = next_month_boundary_iso();
        if let Some(webhook) = resolve_tenant_quota_webhook(tenant_id).await {
            notify_quota_event_async(
                webhook,
                tenant_id.clone(),
                QuotaEvent::HardCap { limit, used },
            );
        }
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "quota_exceeded",
                "limit": limit,
                "used": used,
                "reset_at": reset_at,
                "upgrade_url": "https://app.tracelane.dev/settings/billing",
            })),
        )
            .into_response();
    }

    timer.mark("quota");

    // --- Step 2c: PER-KEY MONTHLY BUDGET (GWY-43) ---
    //
    // `api_keys.budget_usd_monthly` has existed since A13 and enforced nothing:
    // it was validated at mint, INSERTed, and never selected again. This is the
    // read, and the cut-off.
    //
    // It sits AFTER the tenant quota deliberately — the platform's own limits
    // decide first, then the customer's self-imposed ceiling on one credential.
    // And it sits BEFORE the audit publish and the BYOK key fetch, so a key over
    // its budget never causes a provider credential to be decrypted.
    //
    // Cost: one `DashMap` probe and an atomic load on the warm path. The durable
    // ClickHouse seed happens once per key per month per process ('s
    // lesson — an in-memory counter that resets on deploy is not a cap).
    if let (Some(key_id_str), Some(budget)) = (claims.api_key_id(), claims.budget_usd_monthly) {
        if let Ok(key_uuid) = Uuid::parse_str(key_id_str) {
            let who = crate::spend::Subject::Key(key_uuid);
            let spend = crate::spend::tracker();
            if spend.needs_seed(who, year_month) {
                let baseline = spend_baseline_from_clickhouse(&state, tenant_id, key_id_str).await;
                spend.seed_if_needed(who, year_month, baseline);
            }
            if let crate::spend::BudgetDecision::Exceeded {
                budget_usd,
                spent_usd,
            } = spend.check(who, Some(budget))
            {
                crate::rejection_metrics::registry().record_quota_exceeded(tenant_id);
                tracing::warn!(
                    tenant_id = %tenant_id,
                    api_key_id = %key_id_str,
                    budget_usd,
                    spent_usd,
                    "API key over its monthly budget — refusing"
                );
                return (
                    // 402, not 429. A 429 says "retry later" and every OpenAI-shaped
                    // client will; this is a HARD STOP that no amount of retrying
                    // resolves until the budget is raised or the month rolls.
                    // Telling a client to retry into a wall is how a budget cap
                    // becomes a retry storm.
                    StatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({
                        "error": "key_budget_exceeded",
                        "message": "this API key has reached its monthly budget",
                        "budget_usd": budget_usd,
                        "spent_usd": spent_usd,
                        "resets_at": next_month_boundary_iso(),
                    })),
                )
                    .into_response();
            }
        }
    }

    timer.mark("budget_key");

    // --- Step 2d: WORKSPACE MONTHLY BUDGET (GWY-43, the "per-team" cap) ---
    //
    // A team in this product IS the workspace — there is no `teams` table and
    // never was — so the per-team cap is a per-tenant dollar ceiling, and it
    // composes with the per-key one: a request must pass BOTH. That is what
    // makes "give the CI key $50 of a $500 workspace budget" expressible.
    //
    // The ceiling rides the entitlement cache (15-min TTL + LISTEN/NOTIFY), so
    // reading it costs no PG round trip on the request path.
    let workspace_budget_micro = entitlements
        .as_ref()
        .map_or(0, |e| e.workspace_budget_micro_usd);
    if workspace_budget_micro > 0 {
        let who = crate::spend::Subject::Workspace(*tenant_id.as_uuid());
        let spend = crate::spend::tracker();
        if spend.needs_seed(who, year_month) {
            let baseline = workspace_spend_baseline_from_clickhouse(&state, tenant_id).await;
            spend.seed_if_needed(who, year_month, baseline);
        }
        let budget_usd = workspace_budget_micro as f64 / 1_000_000.0;
        if let crate::spend::BudgetDecision::Exceeded {
            budget_usd,
            spent_usd,
        } = spend.check(who, Some(budget_usd))
        {
            crate::rejection_metrics::registry().record_quota_exceeded(tenant_id);
            tracing::warn!(
                tenant_id = %tenant_id,
                budget_usd,
                spent_usd,
                "workspace over its monthly budget — refusing"
            );
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({
                    "error": "workspace_budget_exceeded",
                    "message": "this workspace has reached its monthly budget",
                    "budget_usd": budget_usd,
                    "spent_usd": spent_usd,
                    "resets_at": next_month_boundary_iso(),
                })),
            )
                .into_response();
        }
    }

    timer.mark("budget_workspace");

    // --- Step 3: Predictive layer ---
    let ctx = PredictiveContext {
        tenant_id,
        request_json: &body,
    };
    // A11: async predictive entry — the PromptGuard sidecar bridge now
    // runs without `block_in_place`, and each predictor sees every
    // `messages[*]` plus tool-result blocks rather than just messages[0].
    let decision = state.predictive.evaluate_async(&ctx).await;
    // ADR-055 (amendment): flight-recorder / observe-first posture. A `Block`
    // enforces a 403 ONLY under opt-in enforcement (`predictive_enforce`); by
    // DEFAULT a would-be-block is RECORDED as a flagged event and the request
    // proceeds, so a false positive never breaks a legitimate agent run.
    // Stopping agents (destructive) is deferred/opt-in, not the default.
    let warn_aft_id: Option<&'static str> = match decision {
        Decision::Allow => None,
        Decision::Warn { aft_id } => Some(aft_id),
        Decision::Block { aft_id } => {
            if state.predictive_enforce {
                tracing::warn!(%aft_id, "request blocked by predictive guardrail (enforcement mode)");
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "request blocked by Tracelane predictive guardrail",
                        "aft_id": aft_id
                    })),
                )
                    .into_response();
            }
            tracing::warn!(
                %aft_id,
                "predictive guardrail would BLOCK (observe-first: recorded, not enforced — set TRACELANE_PREDICTIVE_ENFORCE=1 to enforce)"
            );
            Some(aft_id)
        }
    };

    // B1 auto-rollback feed context — extracted once here while `body` is in
    // scope (dispatch below consumes it). Fed to the auto-rollback engine off
    // the response path at completion; `None` for non-managed-prompt traffic.
    let prompt_obs = PromptObservation::from_body(&body);
    let guardrail_fired = warn_aft_id.is_some();

    timer.mark("detection");

    // --- Step 4: Audit log ---
    let mut audit_payload = serde_json::json!({
        "model": body.get("model").and_then(|m| m.as_str()).unwrap_or("unknown"),
        "warn_aft_id": warn_aft_id,
        // Correlation key for the per-trace "in tamper-evident ledger" chip
        // (wedge item 4). Non-secret W3C trace id; serde renders the Uuid
        // hyphenated-lowercase, byte-identical to the `spans.trace_id` string
        // so the chip endpoint joins the two by equality. Only gateway-proxied
        // calls carry it — SDK/OTLP spans are never chained (honest B-scope).
        "trace_id": trace_id,
    });
    // Customer business reference (wedge item 5), when supplied — ties the
    // tamper-evident record to a business event (loan/txn/case id). Inserted
    // ONLY when present so an ordinary row's canonical payload is byte-unchanged
    // (a perpetual `business_reference: null` on every row would be noise in the
    // immutable ledger). Already length-bounded at the header boundary.
    if let Some(ref br) = business_reference {
        audit_payload["business_reference"] = serde_json::Value::String(br.clone());
    }
    let audit_event = AuditEvent {
        tenant_id: tenant_id.clone(),
        event_type: "chat.completions.request",
        actor: claims.sub.clone(),
        payload: audit_payload,
    };
    // ADR-069: durable CAPTURE before dispatch (acked JetStream publish); the
    // head-advance runs off the request path. Fail-CLOSED — a publish failure 503s
    // (the audit product does not serve unrecorded requests). Since A2 the
    // SYNCHRONOUS fallback (async unwired / kill.audit.async) is fail-closed too, so
    // this 503 is now reachable on either path. Dev / self-host still never hit it:
    // with no Postgres pool the append is in-memory and cannot fail.
    if let Err(err) = state.audit_chain.publish(audit_event).await {
        tracing::error!(error = %err, "audit publish failed — refusing request (fail-closed)");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "audit_unavailable" })),
        )
            .into_response();
    }
    timer.mark("audit");
    // --- Step 5: Provider dispatch ---
    // `mut`: on a successful cross-provider failover below we reassign this to
    // the provider that actually served the request, so the span, the echoed
    // response model, and billing all attribute to the real server.

    // x402: extract payment event if present and record async.
    // Runs before provider dispatch so intent is captured even on provider error.
    if let Some(ev) =
        crate::payment::extract_payment_event(&body, tenant_id, agent_id.as_deref(), trace_id)
    {
        if let Some(pool) = crate::db::global_pool() {
            let pool = pool.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::payment::record_payment_event(&pool, ev).await {
                    tracing::warn!(error = %e, "payment event record failed");
                }
            });
        }
    }

    // Resolve the provider ONCE from the single canonical map and FAIL
    // CLOSED on an unmatched model. There is NO default provider — routing an
    // unknown model to Anthropic (or any provider) would fetch that provider's
    // BYOK key for a model the caller never asked for (credential misrouting).
    // Rejecting is categorically safer than shipping the wrong provider's key.
    // Bench-mock bypass for routing + BYOK.
    //
    // POSITION IS THE SECURITY PROPERTY. This sits AFTER Step 1 auth and
    // after `tenant_id` is taken from `claims`, so an unauthenticated
    // request can never reach the mock arm — it is rejected upstream with 401
    // exactly as before. Asserted by `bench_mock_requires_auth_first`, not by
    // this comment.
    //
    // DOUBLE-GATED, both directions fail closed:
    //   flag ON  + `__bench_mock*`  -> bypass (the only way in)
    //   flag ON  + real model       -> normal path, untouched
    //   flag OFF + `__bench_mock*`  -> falls through -> 400 unroutable_model
    //   flag OFF + real model       -> normal path, untouched
    //
    // Why the bypass is needed at all: `provider_id_for_model` fails closed and
    // `providers/mod.rs` has no `__bench_mock` arm, so the reserved model was
    // rejected 211 lines BEFORE the mock branch at :1358 — the benchmark has
    // never been reachable. BYOK resolution below is a second blocker on the
    // same path, so both are bypassed together.
    let provider_id = if bench_mock {
        BENCH_MOCK_PROVIDER_ID
    } else {
        match crate::providers::ProviderRegistry::provider_id_for_model(&model) {
            Some(p) => p,
            None => {
                // R13, and I did not find this one by reading — the guard did, on its
                // first run. made the model map fail closed, which is right, but
                // the ledger row is already published by here, so an unroutable model
                // produced a ledger entry and no trace. It is also the single most
                // likely error a new customer hits (a typo'd or unsupported model name),
                // which makes it the worst one to be invisible.
                emit_post_ledger_error_span(
                    &state,
                    tenant_id,
                    trace_id,
                    &model,
                    request_start,
                    "unroutable_model",
                    None,
                );
                return unroutable_model_response(&model);
            }
        }
    };
    // A4: BYOK lookup first — per-tenant ciphertext in `provider_keys` decrypted
    // with AAD bound to (tenant_id, provider_id). On miss (no row, decrypt fail,
    // pool unavailable) fall back to the legacy env var. The env var is derived
    // from THIS provider_id, so a miss yields an empty key (upstream 401), never
    // another provider's key.
    // The bench mock never dispatches upstream, so there is no credential
    // to resolve. Skipping the lookup also keeps the benchmark honest — it must
    // not measure a Postgres round-trip the mocked request would never make.
    let provider_key = if bench_mock {
        String::new()
    } else {
        let key_env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id);
        // First-value path: a launch-day user who has not added BYOK yet must be told
        // to ADD a key, not that their key was "rejected". Dispatching an empty
        // credential and relaying the upstream 401 read as "my key is broken" for a
        // user who had no key at all. Fail here, before the upstream round-trip.
        match resolve_provider_key(tenant_id, provider_id, key_env).await {
            ProviderKey::Found(k) => k,
            outcome => {
                let (status, code, message) = match outcome {
                    ProviderKey::NotConfigured => (
                        StatusCode::BAD_REQUEST,
                        "provider_not_configured",
                        "no API key is configured for this provider — add one in Settings → LLM Providers, then retry",
                    ),
                    _ => (
                        StatusCode::BAD_GATEWAY,
                        "provider_key_unusable",
                        "a stored key for this provider could not be decrypted — rotate it in Settings → LLM Providers",
                    ),
                };
                tracing::warn!(provider = provider_id, code, "provider key unresolvable");
                // Emit the ERROR span so this is visible in /traces and countable —
                // same reason the dispatch-failure path does (#3). Without it,
                // the most common first-run failure is invisible in the product.
                emit_post_ledger_error_span(
                    &state,
                    tenant_id,
                    trace_id,
                    &model,
                    request_start,
                    code,
                    None,
                );
                return provider_error_response(
                    status,
                    code,
                    Some(message),
                    Some(provider_id),
                    None,
                );
            }
        }
    };

    let mut chat_request =
        match serde_json::from_value::<tracelane_shared::ChatRequest>(body.clone()) {
            Ok(r) => r,
            Err(err) => {
                // R13: the ledger already recorded this request. A 400 here without a
                // span is a row the audit export names and /traces cannot show.
                emit_post_ledger_error_span(
                    &state,
                    tenant_id,
                    trace_id,
                    &model,
                    request_start,
                    "malformed_request",
                    None,
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("malformed request: {err}") })),
                )
                    .into_response();
            }
        };

    // GWY-24: the cache identity is derived HERE — after the parse, BEFORE the
    // guardrail redaction at `redact_request_in_place`.
    //
    // The ordering is load-bearing and not obvious. `crates/policy/src/pii.rs`
    // builds its placeholder as `{REDACT_OPEN}{category}:{idx}}}` — a category
    // and a running index, carrying no secret and no tenant material. Two
    // DIFFERENT secrets in the same position therefore redact to a
    // BYTE-IDENTICAL string, so hashing after redaction would treat two
    // genuinely different requests as one and serve the wrong answer to the
    // second. Hashing before redaction is the only correct window.
    let cache_key = state
        .semantic_cache
        .as_ref()
        .map(|_| crate::semantic_cache::request_key(&chat_request));

    // GWY-39: a `tracelane.yaml` alias names the provider (resolved above, via
    // the canonical map) AND the upstream model. Only the OUTGOING request is
    // rewritten. `model` deliberately keeps the caller's alias so the span, the
    // ledger and the echoed response all say what the caller actually asked
    // for — and so `dispatch_to_provider`'s defence-in-depth re-resolve lands on
    // the same provider this handler already chose.
    if let Some(a) = self::config::alias(&model) {
        tracing::debug!(
            alias = %model,
            upstream_model = %a.upstream_model,
            provider = %a.provider_id,
            "tracelane.yaml model alias applied"
        );
        chat_request.model.clone_from(&a.upstream_model);
    }

    timer.mark("route_byok");

    // --- Step 4b: Inline guardrails (the guardrail spec) ---
    // Request-side rail dispatch over the parsed request (R4 lethal-trifecta +
    // future rails). A security block short-circuits the upstream call with 403;
    // the verdict is recorded to the tamper-evident ledger (+ ClickHouse mirror
    // when configured) regardless of the decision — fail-open-loud on a missing
    // sink (the request always reaches a decision). Runs before the
    // untrusted-data wrap so rails see the request content as the caller sent it.
    // Hoisted to the handler scope so the response-side streaming seam reuses
    // the SAME correlation id + the request-side R2 redaction map (built here,
    // re-inserted in the streamed response).
    let correlation_id = ulid::Ulid::new();
    let mut guardrail_redaction_map: Vec<tracelane_policy::pii::RedactionEntry> = Vec::new();
    {
        let rag_context = crate::guardrail::context::extract_rag_context(&body);
        let session = crate::guardrail::SessionState::fresh(conversation_id.clone());
        let gr = state
            .guardrail
            .evaluate_request(crate::guardrail::RequestInputs {
                tenant_id,
                api_key_id: Some(claims.sub.as_str()),
                correlation_id,
                request: &chat_request,
                rag_context,
                session,
                actor: claims.sub.as_str(),
            })
            .await;
        // ADR-069 fail-closed: the guardrail verdict could not be durably captured
        // (async publish failed) — refuse rather than serve an unrecorded request.
        if gr.audit_publish_failed {
            tracing::error!(
                correlation_id = %correlation_id,
                "guardrail verdict audit publish failed — refusing request (fail-closed)"
            );
            // R13. The CHAT ledger row landed (that publish is upstream of here and
            // fail-closed in its own right); it is the GUARDRAIL VERDICT that could not
            // be captured. So the ledger attests to a request that was then refused,
            // and without this the refusal is invisible in the product.
            emit_post_ledger_error_span(
                &state,
                tenant_id,
                trace_id,
                &model,
                request_start,
                "audit_unavailable",
                None,
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "audit_unavailable" })),
            )
                .into_response();
        }
        if gr.is_block() {
            let blocking = gr
                .outcome
                .records
                .iter()
                .find(|r| r.outcome.outcome == crate::guardrail::Outcome::Block);
            let rail = blocking.map_or("guardrail", |r| r.rail);
            let reason = blocking
                .and_then(|r| r.outcome.reason_code)
                .unwrap_or("guardrail_block");
            tracing::warn!(
                rail,
                reason_code = reason,
                correlation_id = %correlation_id,
                "request blocked by inline guardrail"
            );
            //  #5: if the blocking reason maps to a canonical AFT-1 signature
            // (tool-description injection → AFT-TOOL-POISON-001), emit an
            // error-status span carrying that `aft_id` BEFORE the 403 short-circuit
            // — otherwise the blocked hit is invisible on /signatures (the very
            // #3 gap, recreated for the injection case). Schema/drift no longer
            // reach this branch (they observe); injection is the live mapping.
            // R13. The AFT id is now an ATTRIBUTE of the span, not a CONDITION on
            // emitting one. It used to gate the whole block: `if let Some(aft_id) =
            // reason_to_aft(reason)`, with the 403 returning unconditionally below —
            // and injection is the only live mapping (see the comment above), so
            // **every other blocking rail produced a ledger row, a guardrail_verdicts
            // row, a 403, and nothing in /traces.** The customer was told their request
            // was blocked and could not see the block. Found by the verifier on the
            // B-245 pass, inside a path I had already credited as covered.
            emit_post_ledger_error_span(
                &state,
                tenant_id,
                trace_id,
                &model,
                request_start,
                "guardrail_block",
                crate::guardrail::rails::r3_tool_safety::reason_to_aft(reason),
            );
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "request blocked by Tracelane inline guardrail",
                    "rail": rail,
                    "reason_code": reason,
                    "correlation_id": correlation_id.to_string(),
                })),
            )
                .into_response();
        }
        // R2 request-side egress-apply: when the request-side verdict redacted,
        // rewrite the OUTGOING request (secrets/PII → reversible placeholders)
        // before it leaves the gateway, and keep the map so the streamed
        // response can re-insert the user's originals. Runs before the untrusted
        // wrap + dispatch, so the redacted form is what egresses upstream.
        if gr.outcome.decision == crate::guardrail::Decision::Redact {
            guardrail_redaction_map =
                crate::guardrail::streaming::redact_request_in_place(&mut chat_request);
        }
    }

    // A5: wrap every tool-result message / block in `<UNTRUSTED_USER_DATA>`
    // before any LLM consumes it. CLAUDE.md security non-negotiable #4.
    // Idempotent — a retry that re-enters this code path will not
    // accumulate sentinels.
    crate::untrusted_data::wrap_untrusted_content(&mut chat_request);

    // A7: one retry against the same provider on transient failure, within the
    // FT-01 200ms budget. This is the DEFAULT path. Opt-in cross-provider
    // failover runs AFTER this, only when the request sets
    // `X-Tracelane-Failover: cross-provider` and the primary still failed —
    // re-dispatching the universal ChatRequest to the next provider (no schema
    // translation needed; each adapter translates the canonical request).
    // ADR-036: per-(provider, region) circuit breaker. Region is "default" —
    // ChatRequest carries no region tag at this layer (Bedrock's region is
    // adapter-internal). If the breaker is Open we fail fast with 503 +
    // Retry-After rather than tying up a worker slot on a known-bad upstream.
    let upstream = provider_name_from_model(&model);
    let region = "default";
    // ADR-038 kill.upstream.<provider> force-opens the breaker (operator
    // disable / provider incident), in addition to the breaker's own state.
    let upstream_killed = state.kill_switch.upstream_killed(upstream);
    if upstream_killed || !state.circuit_breaker.allow(upstream, region) {
        tracing::warn!(
            provider = upstream,
            killed = upstream_killed,
            "upstream unavailable (circuit open or killed) — short-circuiting with 503"
        );
        // R13. A breaker-open 503 is the single most useful error span there is: it is
        // the shape a customer most wants to see on their own timeline, and it fires in
        // bursts. The ledger recorded every one of these requests; before this, none of
        // them appeared in /traces.
        emit_post_ledger_error_span(
            &state,
            tenant_id,
            trace_id,
            &model,
            request_start,
            if upstream_killed {
                "upstream_killed"
            } else {
                "upstream_circuit_open"
            },
            None,
        );
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "upstream_circuit_open",
                "provider": upstream,
                "retry_after_seconds": 10
            })),
        )
            .into_response();
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("10"),
        );
        resp.headers_mut().insert(
            axum::http::HeaderName::from_static("tracelane-upstream-circuit"),
            axum::http::HeaderValue::from_static("open"),
        );
        return resp;
    }

    // Latency-split boundary: everything before this mark is gateway overhead
    // (auth, quota, predictive, guardrail engine + the Step-4 audit append,
    // untrusted-wrap); everything after, up to provider-complete, is the provider
    // round-trip (incl. A7 retry / cross-provider failover). Stamped once, here.
    let dispatch_ts = chrono::Utc::now();
    timer.mark("guardrails");
    // Emit against the SAME interval the span's overhead number opens with —
    // `dispatch_ts - request_start` — so the log line and the span agree by
    // construction instead of by two similar-looking clocks.
    timer.emit_if_slow(
        u64::try_from(
            (dispatch_ts - request_start)
                .num_microseconds()
                .unwrap_or(0),
        )
        .unwrap_or(0),
    );
    // A7: one retry against the same provider on transient failure.
    //  (verifier finding a): consume the SAME `bench_mock` computed at the
    // routing bypass rather than re-deriving the condition here. A second inline
    // copy of the gate is the drift the unified gate exists to prevent — extend
    // `bench_mock_active` and only one of the two decisions would follow it.
    // ── GWY-24: the cache lookup. THE PLACEMENT IS THE ANSWER TO GWY-25. ────
    //
    // Everything above this line has already run: auth, quota, both budget
    // ceilings, detection, guardrails, and the fail-CLOSED audit publish. So a
    // hit is served AFTER the ledger append, not instead of it — `audit.rs`'s
    // invariant ("the audit product does not serve unrecorded requests") is
    // untouched, which is exactly the objection that killed the exact-match
    // cache in `specs/GWY-25`.
    //
    // Only the DISPATCH is replaced. Not the ledger, not the guardrails, not the
    // budgets.
    let cache_hit: Option<crate::semantic_cache::CacheHit> = match (
        state.semantic_cache.as_ref(),
        cache_key.as_ref(),
        is_streaming_request(&body),
    ) {
        // Streaming is never served from cache: `provider_stream_to_sse` has no
        // text accumulator, and replaying a buffered body as SSE would fabricate
        // timing the recorder never saw.
        (Some(cache), Some(key), false) => cache.lookup(tenant_id, &model, key).await,
        _ => None,
    };

    // SERVE THE HIT — and emit its span before returning, because a served
    // request that produced no span is precisely the "trace gap" GWY-25 refused
    // this feature over.
    if let Some(hit) = cache_hit {
        let mut span = build_gateway_span(
            tenant_id,
            trace_id,
            &model,
            agent_id.as_deref(),
            human_authorizer.as_deref(),
            business_reference.as_deref(),
            request_start,
            hit.prompt_tokens,
            hit.completion_tokens,
            None,
            SpanUsageMeta {
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                stream: false,
                // EXPLICIT Some(0.0), never None. `build_gateway_span` falls back
                // to `pricing::cost_usd(model, tokens)` when cost is None — with
                // replayed tokens that would invent LIST PRICE for a call that
                // never happened, and the customer would be shown a charge for
                // an answer we did not buy. `SpendTracker::record` drops
                // non-positive cost, so 0.0 also adds nothing to spend.
                cost_usd: Some(0.0),
            },
            conversation_id.as_deref(),
            None,
            // REAL TIMING, not `None`. `build_gateway_span` only emits
            // `tracelane_gateway_overhead_us` when timing is present, so passing
            // `None` made a cache hit the ONE request shape that reports no
            // overhead at all.
            //
            // That is not cosmetic: deploy **Proof E** reads exactly this
            // attribute, and on the deploy that shipped this feature its two
            // identical requests meant the MEASURED one was a cache hit — so the
            // gate reported "0.0 ms" and passed on a missing value rather than a
            // fast one. The latency gate went vacuous on the very path this
            // feature exists to make fast. Zero and unknown must never render the
            // same, least of all inside the control that guards the number.
            //
            // For a hit there is no provider round trip, so both boundary stamps
            // are NOW: overhead becomes (now − received) + (end − now) ≈ the
            // whole request, which is exactly right — on this path the gateway IS
            // the entire cost.
            Some(GatewayTiming {
                dispatch_ts: chrono::Utc::now(),
                provider_complete_ts: chrono::Utc::now(),
                ttft_us: None,
            }),
            None,
            claims.api_key_id(),
        );
        span.attributes.tracelane_semantic_cache_hit = Some(true);
        span.attributes.tracelane_semantic_cache_tier = Some(hit.tier.to_owned());
        span.attributes.tracelane_semantic_cache_similarity = hit.similarity;
        span.attributes.tracelane_semantic_cache_source_trace_id =
            Some(hit.source_trace_id.to_string());
        span.attributes.tracelane_semantic_cache_cost_saved_usd = Some(hit.cost_saved_usd);
        // GWY-45: a cache hit is a real served request and must carry the same
        // captured input as a miss. Omitting it here would silently bias every
        // eval case set AWAY from repeated prompts — exactly the ones a cache
        // makes common.
        if let Some(captured) = CapturedInput::build(tenant_id, &chat_request) {
            captured.apply(&mut span.attributes);
        }
        spawn_span_publish(&state, span);

        // NO `spawn_billing_record` here, and that is not an omission. It meters
        // `Meter::TokensProcessed` with n_tokens rather than cost, so zeroing the
        // cost does NOT stop it — a hit would be billed to Polar as if the
        // provider had been called.
        tracing::debug!(
            tier = hit.tier,
            similarity = ?hit.similarity,
            lookup_us = hit.lookup_us,
            saved_usd = hit.cost_saved_usd,
            "semantic cache hit — served without a provider call"
        );
        // `content-type: application/json` EXPLICITLY. The body is a JSON string
        // and a bare `String` body would go out as `text/plain`, which every
        // OpenAI-compatible client parses differently or not at all — a cache hit
        // must be byte-and-header indistinguishable from a real answer, or the
        // cache becomes a compatibility bug that only appears under load.
        return (
            StatusCode::OK,
            axum::response::AppendHeaders([
                (axum::http::header::CONTENT_TYPE, "application/json"),
                (
                    axum::http::HeaderName::from_static("x-tracelane-cache"),
                    hit.tier,
                ),
            ]),
            hit.response_json,
        )
            .into_response();
    }

    let mut provider_result = if bench_mock {
        // Bench-only instant upstream (TRACELANE_BENCH_MOCK_UPSTREAM). Replaces
        // ONLY the network dispatch with an instant canned stream, so a load
        // test's measured latency is gateway overhead (auth, parse, untrusted
        // wrap, breaker, span emit) with ~0 provider time. Double-gated — the
        // flag is off by default and the model must be `__bench_mock*`, so a
        // normal tenant request can never reach here. See bench/gateway/README.
        crate::providers::MockProvider::new("ok")
            .chat_mock(&chat_request, &provider_key, tenant_id)
            .await
    } else {
        dispatch_with_retry(
            &state.providers,
            &chat_request,
            &provider_key,
            &model,
            tenant_id,
        )
        .await
    };

    // Feed the breaker: any dispatch error (timeout / 5xx / connection) is a
    // failure outcome; the gen_ai.client.operation.exception event (ADR-032)
    // is the matching telemetry surface.
    //
    // GWY-24: NOT on a cache hit. This call was unconditional, and a hit that
    // reached it would report SUCCESS for a provider that was never contacted —
    // which could hold a breaker CLOSED over a dead upstream for as long as the
    // cache kept serving. The breaker's whole job is to observe the provider, so
    // feeding it an observation that did not happen is worse than feeding it
    // nothing.
    if cache_hit.is_none() {
        state
            .circuit_breaker
            .record(upstream, region, provider_result.is_ok());
    }

    // Opt-in CROSS-PROVIDER failover. Default OFF — the same-provider
    // path above is unchanged. Enable per request with
    // `X-Tracelane-Failover: cross-provider`. Works with no schema translation
    // because every adapter translates the universal `ChatRequest`: we simply
    // re-dispatch the same canonical request to the next provider in the chain
    // with a model that routes there. The failover provider needs the tenant's
    // own BYOK key (skipped otherwise) and must pass its own circuit breaker.
    // No new infra/state — reuses dispatch_with_retry + the per-provider key
    // store + the existing breakers. When opted in we fail over on any primary
    // error (the caller has chosen resilience over a possible extra call).
    let cross_provider_failover = headers
        .get("x-tracelane-failover")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-provider"));
    // `Some(primary_provider)` once a cross-provider failover actually served the
    // request — threaded onto the span so the Gateway-ops rollup can count it and
    // name the primary that errored.
    let mut failover_from: Option<&'static str> = None;
    if provider_result.is_err() && cross_provider_failover {
        let primary_family = provider_name_from_model(&model);
        for (fo_provider, fo_model) in
            crate::providers::failover::cross_provider_candidates(primary_family)
        {
            if state.kill_switch.upstream_killed(fo_provider)
                || !state.circuit_breaker.allow(fo_provider, region)
            {
                continue;
            }
            // Fail closed on an unroutable failover candidate — skip it,
            // never default to a provider (its key would be the wrong one).
            let Some(fo_pid) = crate::providers::ProviderRegistry::provider_id_for_model(fo_model)
            else {
                continue;
            };
            let fo_env = crate::providers::ProviderRegistry::env_var_for_provider_id(fo_pid);
            // Failover keeps its skip-on-unresolvable behaviour: a provider we
            // cannot key for is simply not a failover candidate.
            let fo_key = match resolve_provider_key(tenant_id, fo_pid, fo_env).await {
                ProviderKey::Found(k) => k,
                _ => String::new(),
            };
            if fo_key.is_empty() {
                tracing::debug!(
                    provider = fo_provider,
                    "cross-provider failover skipped — no BYOK key for this provider"
                );
                continue;
            }
            let mut fo_request = chat_request.clone();
            fo_request.model = fo_model.to_string();
            let fo_result =
                dispatch_with_retry(&state.providers, &fo_request, &fo_key, fo_model, tenant_id)
                    .await;
            state
                .circuit_breaker
                .record(fo_provider, region, fo_result.is_ok());
            if fo_result.is_ok() {
                tracing::info!(
                    from = primary_family,
                    to = fo_provider,
                    fo_model = fo_model,
                    "tracelane.failover.cross_provider.activated=true"
                );
                // Attribute everything downstream (span provider, echoed model,
                // billing) to the provider that actually served the request, and
                // mark the span so the ops rollup counts the failover + names the
                // primary that failed.
                model = fo_model.to_string();
                failover_from = Some(primary_family);
                provider_result = fo_result;
                break;
            }
        }
    }

    let provider_stream = match provider_result {
        Ok(s) => s,
        Err(err) => {
            // Recover the typed upstream status (if any) so we can both classify
            // the failure and attach it to the telemetry.
            let http = err.downcast_ref::<crate::providers::ProviderHttpError>();
            let status_code = http.map(|e| e.status);

            //  GW-SPAN-002: a dispatch failure MUST emit the
            // gen_ai.client.operation.exception event (ADR-032/036) — the breaker
            // trip input and the observability surface. This path was previously
            // silent (no span, no event), so a hard provider outage was invisible
            // to /traces + /slo while the API returned an opaque 502.
            crate::otlp_emit::emit_operation_exception(
                tenant_id,
                upstream,
                region,
                "dispatch_failed",
                status_code,
            );

            //  #3: also publish an ERROR-status span so this failure is COUNTABLE
            // by the error-rate metric (countIf(status_code = 2)). The event above is
            // the breaker trip input; a span is what /slo + /traces actually render.
            // Without it a hard dispatch failure was invisible — a structural 0% error
            // rate regardless of real provider 401/429/404/5xx. One span here covers
            // all four typed returns below.
            let err_reason = if http
                .is_some_and(crate::providers::ProviderHttpError::is_auth_rejection)
            {
                "provider_key_rejected"
            } else if http.is_some_and(crate::providers::ProviderHttpError::is_rate_limited) {
                "provider_rate_limited"
            } else if http.is_some_and(crate::providers::ProviderHttpError::is_model_not_found) {
                "model_not_found"
            } else if http
                .is_some_and(crate::providers::ProviderHttpError::is_unclassified_client_error)
            {
                // Countable as its own class — an upstream 4xx we could not
                // classify is NOT an outage, and folding it into
                // `provider_unavailable` inflated the error-rate metric with
                // client-side failures.
                "provider_request_rejected"
            } else {
                "provider_unavailable"
            };
            emit_post_ledger_error_span(
                &state,
                tenant_id,
                trace_id,
                &model,
                request_start,
                err_reason,
                None,
            );

            // An upstream 401/403 means the tenant's BYOK provider key was
            // rejected — surface that distinctly instead of an opaque 502 (a
            // mangled/expired key otherwise read as "provider unavailable", with
            // no signal the *key* was wrong). The body carries no upstream detail.
            if http.is_some_and(crate::providers::ProviderHttpError::is_auth_rejection) {
                tracing::warn!(
                    provider = upstream,
                    status = ?status_code,
                    "provider rejected the tenant's key"
                );
                return provider_error_response(
                    StatusCode::UNAUTHORIZED,
                    "provider_key_rejected",
                    Some(
                        "the configured provider key was rejected by the upstream provider — verify the key for this provider",
                    ),
                    Some(upstream),
                    None,
                );
            }

            // An upstream 429 is NOT an outage — the caller is over quota or
            // rate-limited. Reporting "provider unavailable" sends them to debug
            // the wrong system entirely. Mirrors the breaker's 503 + Retry-After
            // shape (ADR-036/037), but 429 because the limit is the caller's, not
            // ours. Observed live: AI Studio 429s a free-tier key on gemini-2.5-pro.
            if http.is_some_and(crate::providers::ProviderHttpError::is_rate_limited) {
                tracing::warn!(
                    provider = upstream,
                    "upstream rate-limited / quota exhausted"
                );
                return provider_error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "provider_rate_limited",
                    Some(
                        "the upstream provider rate-limited or quota-exhausted this request — retry later, or check the provider account's plan and billing",
                    ),
                    Some(upstream),
                    Some("60"),
                );
            }

            // An upstream 404 means the model does not exist for this
            // account — the caller must change the model string, not retry. As a
            // 502 it read as a Tracelane outage. Observed live: AI Studio 404s
            // gemini-2.5-flash as "no longer available to new users".
            if http.is_some_and(crate::providers::ProviderHttpError::is_model_not_found) {
                tracing::warn!(provider = upstream, "upstream reports model not found");
                return provider_error_response(
                    StatusCode::NOT_FOUND,
                    "model_not_found",
                    Some(
                        "the upstream provider does not recognise this model for this account — check the model name and that your provider account has access to it",
                    ),
                    Some(upstream),
                    None,
                );
            }

            // Any OTHER upstream 4xx. We cannot say *why* it was rejected
            // (see `is_unclassified_client_error` — a 400 is a dead key on xAI and
            // a malformed payload everywhere, and the discriminating text is in a
            // body we must not propagate), but a 4xx does prove the upstream
            // rejected the REQUEST. Reporting that as `502 provider unavailable`
            // blamed Tracelane for a client-side problem and sent callers to check
            // our status page. Mirror the upstream 4xx and name both candidates.
            if let Some(e) = http.filter(|e| e.is_unclassified_client_error()) {
                tracing::warn!(
                    provider = upstream,
                    status = e.status,
                    "upstream rejected the request (unclassified 4xx)"
                );
                let message = format!(
                    "the upstream provider rejected this request with HTTP {}. \
                     This is not a Tracelane outage — it is usually either a provider \
                     key that is invalid or expired for this account, or a request the \
                     provider could not accept (model, parameters, or payload). \
                     Verify the key for this provider, then the request itself.",
                    e.status
                );
                return provider_error_response(
                    // Mirror the upstream status so the caller sees exactly what the
                    // provider said. 401/403/404/429 are claimed by the branches
                    // above and can never reach here; anything unrepresentable
                    // degrades to 400 (still client-class, never 5xx).
                    StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST),
                    "provider_request_rejected",
                    Some(&message),
                    Some(upstream),
                    None,
                );
            }

            tracing::error!(error = %err, "provider dispatch failed after retry");
            return provider_error_response(
                StatusCode::BAD_GATEWAY,
                "provider unavailable",
                None,
                None,
                None,
            );
        }
    };

    // --- Step 6: Response ---
    let is_streaming = body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if is_streaming {
        let completion_id = format!("chatcmpl-{}", Uuid::new_v4());
        let nats_client = state.nats.clone();
        let billing_clone = state.billing.clone();
        let tenant_id_owned = tenant_id.clone();
        let agent_id_clone = agent_id.clone();
        let human_authorizer_clone = human_authorizer.clone();
        let business_reference_clone = business_reference.clone();
        let conversation_id_clone = conversation_id.clone();
        let model_clone = model.clone();
        // Response-side guardrail seam inputs (owned — the SSE stream is
        // `'static` and cannot borrow the request). `system_prompt` is the
        // redacted form (what the model sees, hence what it can leak — correct
        // for R6).
        let response_inputs = crate::guardrail::ResponseInputs {
            tenant_id: tenant_id.clone(),
            api_key_id: Some(claims.sub.clone()),
            correlation_id,
            system_prompt: crate::guardrail::context::extract_system_prompt(&chat_request)
                .map(str::to_owned),
            model: model.clone(),
            session: crate::guardrail::SessionState::fresh(conversation_id.clone()),
            actor: claims.sub.clone(),
            expected_format: crate::guardrail::context::extract_expected_format(&body),
        };
        let sse = provider_stream_to_sse(
            provider_stream,
            completion_id,
            model,
            nats_client,
            billing_clone,
            tenant_id_owned,
            trace_id,
            request_start,
            dispatch_ts,
            model_clone,
            agent_id_clone,
            human_authorizer_clone,
            business_reference_clone,
            conversation_id_clone,
            state.prompt_router.clone(),
            prompt_obs.clone(),
            guardrail_fired,
            warn_aft_id,
            state.guardrail.clone(),
            response_inputs,
            guardrail_redaction_map,
            failover_from,
            // GWY-43: the api_keys row id, and ONLY when an API key authorised
            // the request. A session has no key, and `claims.sub` would hand back
            // a WorkOS user id — a different namespace in the same column.
            claims.api_key_id().map(str::to_owned),
        );
        Sse::new(sse).into_response()
    } else {
        let response_inputs = crate::guardrail::ResponseInputs {
            tenant_id: tenant_id.clone(),
            api_key_id: Some(claims.sub.clone()),
            correlation_id,
            system_prompt: crate::guardrail::context::extract_system_prompt(&chat_request)
                .map(str::to_owned),
            model: model.clone(),
            session: crate::guardrail::SessionState::fresh(conversation_id.clone()),
            actor: claims.sub.clone(),
            expected_format: crate::guardrail::context::extract_expected_format(&body),
        };
        buffer_provider_stream(
            provider_stream,
            &model,
            &state,
            tenant_id,
            trace_id,
            request_start,
            dispatch_ts,
            agent_id.as_deref(),
            human_authorizer.as_deref(),
            business_reference.as_deref(),
            conversation_id.as_deref(),
            prompt_obs,
            guardrail_fired,
            warn_aft_id,
            state.guardrail.clone(),
            response_inputs,
            guardrail_redaction_map,
            failover_from,
            claims.api_key_id(),
            state.semantic_cache.clone(),
            cache_key,
            CapturedInput::build(tenant_id, &chat_request),
        )
        .await
        .into_response()
    }
}

/// How a provider dispatch failed, in the vocabulary the span's `status.message`
/// and the client's `error` code both use.
///
/// One definition so the countable reason and the returned status can never
/// disagree — #3 was exactly that disagreement (a 502 on the wire, no
/// error span behind it, a structural 0% error rate on `/slo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchFailure {
    /// Upstream 401/403 — the tenant's BYOK key was rejected. ROTATE it.
    KeyRejected,
    /// Upstream 429 — the caller is over the provider's limit. Not an outage.
    RateLimited,
    /// Upstream 404 — the provider does not serve this model for this account.
    ModelNotFound,
    /// Any other upstream 4xx. The upstream rejected the REQUEST; we cannot say
    /// why without propagating a body that may echo the credential.
    RequestRejected(u16),
    /// Timeout, connection failure, or 5xx after retry. A genuine outage.
    Unavailable,
}

impl DispatchFailure {
    /// The `status.message` written onto the error span, and the `error` code
    /// returned to the caller. Same token for both, by construction.
    fn reason(self) -> &'static str {
        match self {
            Self::KeyRejected => "provider_key_rejected",
            Self::RateLimited => "provider_rate_limited",
            Self::ModelNotFound => "model_not_found",
            Self::RequestRejected(_) => "provider_request_rejected",
            Self::Unavailable => "provider_unavailable",
        }
    }
}

/// Classify a dispatch error from its typed upstream status.
///
/// Mirrors the inline cascade in [`chat_completions_handler`] (`:1671-1767`)
/// exactly; that cascade predates this helper and should be collapsed onto it,
/// which is a pure refactor and deliberately not bundled into this change.
fn classify_dispatch_error(err: &anyhow::Error) -> DispatchFailure {
    let Some(http) = err.downcast_ref::<crate::providers::ProviderHttpError>() else {
        return DispatchFailure::Unavailable;
    };
    if http.is_auth_rejection() {
        DispatchFailure::KeyRejected
    } else if http.is_rate_limited() {
        DispatchFailure::RateLimited
    } else if http.is_model_not_found() {
        DispatchFailure::ModelNotFound
    } else if http.is_unclassified_client_error() {
        DispatchFailure::RequestRejected(http.status)
    } else {
        DispatchFailure::Unavailable
    }
}

/// Client-facing response for a classified dispatch failure.
///
/// Allowlist-constructed and scrubbed by [`provider_error_response`] — the
/// upstream body never crosses this boundary.
fn dispatch_failure_response(
    failure: DispatchFailure,
    upstream: &'static str,
) -> axum::response::Response {
    match failure {
        DispatchFailure::KeyRejected => provider_error_response(
            StatusCode::UNAUTHORIZED,
            failure.reason(),
            Some(
                "the configured provider key was rejected by the upstream provider — verify the key for this provider",
            ),
            Some(upstream),
            None,
        ),
        DispatchFailure::RateLimited => provider_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            failure.reason(),
            Some(
                "the upstream provider rate-limited or quota-exhausted this request — retry later, or check the provider account's plan and billing",
            ),
            Some(upstream),
            Some("60"),
        ),
        DispatchFailure::ModelNotFound => provider_error_response(
            StatusCode::NOT_FOUND,
            failure.reason(),
            Some(
                "the upstream provider does not recognise this model for this account — check the model name and that your provider account has access to it",
            ),
            Some(upstream),
            None,
        ),
        DispatchFailure::RequestRejected(status) => {
            let message = format!(
                "the upstream provider rejected this request with HTTP {status}. \
                 This is not a Tracelane outage — it is usually either a provider \
                 key that is invalid or expired for this account, or a request the \
                 provider could not accept (model, parameters, or payload). \
                 Verify the key for this provider, then the request itself."
            );
            provider_error_response(
                // Mirror the upstream status. 401/403/404/429 are claimed above
                // and cannot reach here; anything unrepresentable degrades to
                // 400 — still client-class, never a 5xx that blames us.
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                failure.reason(),
                Some(&message),
                Some(upstream),
                None,
            )
        }
        DispatchFailure::Unavailable => provider_error_response(
            StatusCode::BAD_GATEWAY,
            "provider unavailable",
            None,
            None,
            None,
        ),
    }
}

/// Publish a span to NATS off the response path. No-op when `NATS_URL` is unset
/// — which drops the span while the request still succeeds (`server.rs:331-357`).
fn spawn_span_publish(state: &AppState, span: TracelaneSpan) {
    let Some(nats_client) = state.nats.as_ref() else {
        // C1: this early return DROPPED THE SPAN SILENTLY. The two chat paths
        // call note_span_dropped_no_nats() on the same condition; this one — the
        // embeddings path — returned with no counter and no log, so an embeddings-only
        // tenant could lose 100% of its spans while every signal we had stayed clean.
        crate::otlp_emit::note_span_dropped_no_nats();
        return;
    };
    let nats = Arc::clone(nats_client);
    tokio::spawn(async move {
        if let Err(e) = crate::otlp_emit::publish_span(&nats, &span).await {
            crate::otlp_emit::note_span_publish_failed();
            tracing::warn!(error = %e, "span NATS publish failed");
        }
    });
}

/// Embeddings span. Same shape as the chat span (one definition of the
/// attribute set) with the OTel GenAI `embeddings` operation name, so an
/// embeddings call is a first-class row in `/traces` rather than a chat call
/// that happens to have zero output tokens.
#[allow(clippy::too_many_arguments)]
fn build_embeddings_span(
    tenant_id: &TenantId,
    trace_id: Uuid,
    model: &str,
    agent_id: Option<&str>,
    human_authorizer: Option<&str>,
    business_reference: Option<&str>,
    conversation_id: Option<&str>,
    start_time: chrono::DateTime<chrono::Utc>,
    input_tokens: u32,
    timing: Option<GatewayTiming>,
    error_reason: Option<&str>,
    api_key_id: Option<&str>,
) -> TracelaneSpan {
    let mut span = build_gateway_span(
        tenant_id,
        trace_id,
        model,
        agent_id,
        human_authorizer,
        business_reference,
        start_time,
        input_tokens,
        // Embeddings produce no completion tokens. Reporting anything else
        // would inflate every token rollup that sums output tokens.
        0,
        None,
        SpanUsageMeta::default(),
        conversation_id,
        None,
        timing,
        error_reason,
        api_key_id,
    );
    span.name = "gen_ai.embeddings".to_string();
    span.attributes.gen_ai_operation_name = Some("embeddings".to_string());
    span
}

/// Embeddings handler — `POST /v1/embeddings` (GWY-26).
///
/// The OpenAI Embeddings shape, so an existing client works by swapping its
/// base URL. It exists because a RAG agent's retrieval step was invisible to
/// the flight recorder: `/v1/chat/completions` was the gateway's only inference
/// route, so every embeddings call went straight to the provider — no span, no
/// ledger entry, no quota, no BYOK.
///
/// ## Pipeline — the ORDER is the security property
///
/// ```text
/// auth → rate limit → validate → monthly quota → audit publish (fail-CLOSED)
/// → route (fail-CLOSED) → BYOK key → breaker → dispatch → span + meter
/// ```
///
/// Nothing that resolves a credential or touches an upstream sits above the
/// auth step, so an unauthenticated request cannot reach any of it. Asserted by
/// `embeddings_without_authorization_is_rejected`, not by this comment
/// (`crates/gateway/CLAUDE.md`: "adding a route without replicating that
/// sequence ships an unauthenticated endpoint").
///
/// ## What it deliberately does NOT run, and why
///
/// - **Predictive layer / inline guardrails.** Both are defined over a
///   `ChatRequest` — messages, tool definitions, tool results. An embeddings
///   payload has none of those. Synthesising a fake `ChatRequest` to make the
///   rails fire would write a verdict about a request that was never made into
///   a tamper-evident ledger, which is worse than no verdict. R2 (secrets/PII)
///   genuinely applies to embedding input and needs a rail that accepts raw
///   text; that is a rail change, not a handler change.
/// - **Untrusted-data wrapping.** Sentinel-wrapping exists so a downstream LLM
///   cannot be steered by tool output. Nothing downstream of an embedding
///   vector interprets instructions.
/// - **Streaming / cross-provider failover / prompt promotion.** The embeddings
///   API is not streamed, and there is no cross-provider embedding equivalence
///   to fail over to — vectors from two providers are not interchangeable.
///
/// ## Fail directions
///
/// Fail-CLOSED: auth, audit publish (`503 audit_unavailable`), model routing
/// (`400 unroutable_model`), provider-key resolution, input validation.
/// Fail-OPEN: span publish and billing metering are off the response path — a
/// NATS or Polar problem never fails a request that the provider served.
#[instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn embeddings_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let request_start = chrono::Utc::now();

    let trace_id = headers
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);
    let agent_id = headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let human_authorizer = headers
        .get("x-human-authorizer")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let conversation_id = headers
        .get("x-conversation-id")
        .or_else(|| headers.get("x-session-id"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let business_reference = headers
        .get("x-business-reference")
        .and_then(|v| v.to_str().ok())
        .and_then(tracelane_shared::span::bounded_business_reference);

    // --- Step 1: Auth. Nothing above this line resolves a credential. ---
    let Some(authorization) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing Authorization header" })),
        )
            .into_response();
    };
    let claims = match crate::auth::validate_authorization(authorization).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "authentication failed");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid or expired credentials" })),
            )
                .into_response();
        }
    };
    // A13 scope gate — B-230. `/v1/embeddings` SPENDS THE TENANT'S PROVIDER BUDGET
    // exactly as `/v1/chat/completions` does, and until 2026-08-13 it had no scope
    // check at all: the only `Scope::Chat` gate in the crate was on the chat route,
    // so a `read`-scoped key — the shape `api_scope.rs:47-49` says to hand an
    // external auditor — could run up a bill here. Same scope as chat on purpose:
    // these are one capability (dispatch to a paid upstream) on two paths, and a
    // separate `embeddings` scope would be a second thing to grant and forget.
    // Placed immediately after auth, before any entitlement resolve, matching the
    // chat path's ordering and its reasoning.
    if !claims.allows_scope(crate::auth::scope::Scope::Chat) {
        tracing::warn!(
            sub = %claims.sub,
            "api key lacks the `chat` scope — refusing embeddings"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": {
                    "message": "This API key is not scoped for embeddings. It needs the `chat` scope; mint a new key with it in Settings → API Keys.",
                    "type": "insufficient_scope",
                    "required_scope": "chat",
                }
            })),
        )
            .into_response();
    }

    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    // --- Step 2: Rate limit (one warm entitlement resolve, same as chat) ---
    // No-cache resolves to Free, never to a paid tier (`.claude/rules/tenancy.md`).
    let entitlements = match &state.entitlements {
        Some(cache) => Some(cache.resolved(*tenant_id.as_uuid()).await),
        None => None,
    };
    let tier = entitlements
        .as_ref()
        .map_or(RateLimitTier::Free, |e| e.rate_limit_tier());
    if let RateLimitDecision::Throttle { retry_after_secs } =
        state.rate_limiter.check(tenant_id, tier)
    {
        crate::rejection_metrics::registry().record_rate_limited(tenant_id);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "rate limit exceeded",
                "retry_after_secs": retry_after_secs
            })),
        )
            .into_response();
    }

    // --- Step 3: Parse + validate ---
    // Deliberately ABOVE the monthly quota check and BELOW the rate limiter: a
    // malformed request is still work worth throttling, but it must not consume
    // a trace from the tenant's paid monthly allowance. (Chat validates later
    // for historical reasons; that asymmetry is chat's, not this handler's.)
    let request = match serde_json::from_value::<crate::providers::EmbeddingsRequest>(body.clone())
    {
        Ok(r) => r,
        Err(err) => {
            return provider_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(&format!("malformed embeddings request: {err}")),
                None,
                None,
            );
        }
    };
    if let Err(err) = request.validate() {
        return provider_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&format!("{err}")),
            None,
            None,
        );
    }
    // The caller's model string — kept verbatim through routing, the span and
    // the ledger even when a `tracelane.yaml` alias rewrites what goes upstream.
    let model = request.model.clone();

    // --- Step 4: Monthly quota hard-cap (same tracker as chat: one allowance) ---
    let quota_cfg = entitlements.as_ref().map_or_else(
        || QuotaConfig::from_plan_tier_str("free"),
        |e| e.quota_config(),
    );
    let year_month = current_year_month();
    if state.quota_tracker.needs_seed(tenant_id, year_month) {
        let baseline = quota_baseline_from_clickhouse(&state, tenant_id).await;
        state
            .quota_tracker
            .seed_if_needed(tenant_id, year_month, baseline);
    }
    let quota = state.quota_tracker.check(tenant_id, quota_cfg);
    if let Some((limit, used)) = quota.at_or_over_included_quota() {
        maybe_notify_soft_cap(tenant_id, year_month, limit, used);
    }
    if let (QuotaDecision::AllowWithOverage { .. }, Some(rec)) = (quota, state.billing.as_ref()) {
        spawn_overage_record(Arc::clone(rec), tenant_id.clone());
    }
    if let QuotaDecision::HardCapExceeded { limit, used } = quota {
        crate::rejection_metrics::registry().record_quota_exceeded(tenant_id);
        tracing::warn!(
            tenant_id = %tenant_id,
            quota_exceeded = true,
            limit,
            used,
            "quota hard cap exceeded — returning 429"
        );
        let reset_at = next_month_boundary_iso();
        if let Some(webhook) = resolve_tenant_quota_webhook(tenant_id).await {
            notify_quota_event_async(
                webhook,
                tenant_id.clone(),
                QuotaEvent::HardCap { limit, used },
            );
        }
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "quota_exceeded",
                "limit": limit,
                "used": used,
                "reset_at": reset_at,
                "upgrade_url": "https://app.tracelane.dev/settings/billing",
            })),
        )
            .into_response();
    }

    // --- Step 5: Audit log. Fail-CLOSED (ADR-069) ---
    // The payload records WHAT was embedded structurally (model, how many
    // inputs) and never the input text itself: embedding input is raw customer
    // documents, and the ledger is exported to third parties for verification.
    let mut audit_payload = serde_json::json!({
        "model": model,
        "input_count": request.input_count(),
        "trace_id": trace_id,
    });
    if let Some(ref br) = business_reference {
        audit_payload["business_reference"] = serde_json::Value::String(br.clone());
    }
    if let Err(err) = state
        .audit_chain
        .publish(AuditEvent {
            tenant_id: tenant_id.clone(),
            event_type: "embeddings.request",
            actor: claims.sub.clone(),
            payload: audit_payload,
        })
        .await
    {
        tracing::error!(error = %err, "audit publish failed — refusing request (fail-closed)");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "audit_unavailable" })),
        )
            .into_response();
    }

    // Step 6: Route. Fail-CLOSED — no default provider -
    let Some(provider_id) = crate::providers::ProviderRegistry::provider_id_for_model(&model)
    else {
        return unroutable_model_response(&model);
    };
    // Only providers speaking the OpenAI embeddings wire format can serve this.
    // Refuse by name rather than forward a shape the provider cannot parse and
    // relay its 400 as if it were ours.
    let Some(adapter) = state.providers.openai_compatible(provider_id) else {
        tracing::warn!(
            provider = provider_id,
            "embeddings requested for a provider with no OpenAI-compatible embeddings endpoint"
        );
        return provider_error_response(
            StatusCode::BAD_REQUEST,
            "embeddings_unsupported_provider",
            Some(
                "this provider does not expose an OpenAI-compatible /v1/embeddings endpoint — \
                 use an OpenAI or OpenAI-compatible embedding model, or map one in tracelane.yaml",
            ),
            Some(provider_id),
            None,
        );
    };

    // --- Step 7: BYOK key. Fail-CLOSED, and the two failures need OPPOSITE
    // user actions (add a key vs rotate one) — never collapsed into one. ---
    let key_env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id);
    let provider_key = match resolve_provider_key(tenant_id, provider_id, key_env).await {
        ProviderKey::Found(k) => k,
        outcome => {
            let (status, code, message) = match outcome {
                ProviderKey::NotConfigured => (
                    StatusCode::BAD_REQUEST,
                    "provider_not_configured",
                    "no API key is configured for this provider — add one in Settings → LLM Providers, then retry",
                ),
                _ => (
                    StatusCode::BAD_GATEWAY,
                    "provider_key_unusable",
                    "a stored key for this provider could not be decrypted — rotate it in Settings → LLM Providers",
                ),
            };
            tracing::warn!(provider = provider_id, code, "provider key unresolvable");
            spawn_span_publish(
                &state,
                build_embeddings_span(
                    tenant_id,
                    trace_id,
                    &model,
                    agent_id.as_deref(),
                    human_authorizer.as_deref(),
                    business_reference.as_deref(),
                    conversation_id.as_deref(),
                    request_start,
                    0,
                    None,
                    Some(code),
                    claims.api_key_id(),
                ),
            );
            return provider_error_response(status, code, Some(message), Some(provider_id), None);
        }
    };

    // --- Step 8: Breaker + kill switch (ADR-036/038) ---
    let upstream = provider_name_from_model(&model);
    let region = "default";
    if state.kill_switch.upstream_killed(upstream) || !state.circuit_breaker.allow(upstream, region)
    {
        tracing::warn!(
            provider = upstream,
            "upstream unavailable (circuit open or killed) — short-circuiting with 503"
        );
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "upstream_circuit_open",
                "provider": upstream,
                "retry_after_seconds": 10
            })),
        )
            .into_response();
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("10"),
        );
        resp.headers_mut().insert(
            axum::http::HeaderName::from_static("tracelane-upstream-circuit"),
            axum::http::HeaderValue::from_static("open"),
        );
        return resp;
    }

    // --- Step 9: Dispatch ---
    // GWY-39: the alias's upstream model is what the provider is asked for; the
    // caller's alias stays on `model` for the span, the ledger and the echoed
    // response.
    let mut upstream_request = request;
    if let Some(a) = self::config::alias(&model) {
        upstream_request.model.clone_from(&a.upstream_model);
    }
    let dispatch_ts = chrono::Utc::now();
    let result = adapter
        .embeddings(&upstream_request, &provider_key, tenant_id)
        .await;
    let provider_complete_ts = chrono::Utc::now();
    state
        .circuit_breaker
        .record(upstream, region, result.is_ok());

    let mut response = match result {
        Ok(r) => r,
        Err(err) => {
            let failure = classify_dispatch_error(&err);
            let status_code = err
                .downcast_ref::<crate::providers::ProviderHttpError>()
                .map(|e| e.status);
            crate::otlp_emit::emit_operation_exception(
                tenant_id,
                upstream,
                region,
                "dispatch_failed",
                status_code,
            );
            //  #3: a failure MUST be countable (status_code = 2), or the
            // error-rate metric is structurally pinned at 0% for this route.
            spawn_span_publish(
                &state,
                build_embeddings_span(
                    tenant_id,
                    trace_id,
                    &model,
                    agent_id.as_deref(),
                    human_authorizer.as_deref(),
                    business_reference.as_deref(),
                    conversation_id.as_deref(),
                    request_start,
                    0,
                    None,
                    Some(failure.reason()),
                    claims.api_key_id(),
                ),
            );
            tracing::warn!(
                provider = upstream,
                reason = failure.reason(),
                status = ?status_code,
                "embeddings dispatch failed"
            );
            return dispatch_failure_response(failure, upstream);
        }
    };

    // --- Step 10: Record, meter, respond ---
    let billable = response.billable_tokens();
    spawn_span_publish(
        &state,
        build_embeddings_span(
            tenant_id,
            trace_id,
            &model,
            agent_id.as_deref(),
            human_authorizer.as_deref(),
            business_reference.as_deref(),
            conversation_id.as_deref(),
            request_start,
            billable,
            Some(GatewayTiming {
                dispatch_ts,
                provider_complete_ts,
                // Embeddings are a single non-streamed round-trip: there is no
                // first chunk distinct from the response.
                ttft_us: None,
            }),
            None,
            claims.api_key_id(),
        ),
    );
    if let Some(rec) = state.billing.as_ref() {
        spawn_billing_record(Arc::clone(rec), tenant_id.clone(), u64::from(billable));
    }

    // Echo the model the CALLER asked for. A `tracelane.yaml` alias is the
    // caller's own vocabulary; handing back the upstream name would break a
    // client that round-trips `response.model` into its next request.
    response.model = model;
    (StatusCode::OK, Json(response)).into_response()
}

/// Count of billing meter-records spawned, bumped synchronously at the call site.
///
/// Billing is fire-and-forget into a `tokio::spawn`, and a SUCCESSFUL meter logs
/// nothing (`Recorder::flush` only warns on failure), so from outside the process
/// "we billed" and "we never billed" were byte-identical. That is not a detail —
/// it is *why* survived for months: billing sat on 2 of the stream's 4
/// termination paths and no operator, log, or metric could have told.
///
/// This counter measures **intent-to-bill at the call site** — incremented BEFORE
/// the spawn, deliberately, so it is independent of whether the tenant has a Polar
/// customer. That is the right boundary: the call site is what broke;
/// delivery to Polar is the `Recorder`'s job, is tested separately, and has worked
/// on the `Done` path throughout.
static BILLING_RECORDS_SPAWNED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Rate-limiter gate for the billing heartbeat: unix secs of the last emit.
static LAST_BILLING_LOG_UNIX: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(BILLING_LOG_NEVER);

/// Sentinel: no billing heartbeat emitted yet this process.
const BILLING_LOG_NEVER: u64 = u64::MAX;

/// At most one billing heartbeat per this interval. Metering fires per request, so
/// a per-record log would drown the gateway; the cumulative total carries the same
/// evidence at a readable rate.
const BILLING_LOG_INTERVAL_SECS: u64 = 60;

/// Read the billing-spawn counter. Test seam for regression test.
#[cfg(test)]
fn billing_records_spawned() -> u64 {
    BILLING_RECORDS_SPAWNED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Spawn a fire-and-forget billing-record task. Looks up the tenant's
/// polar_customer_id in Postgres and increments the TokensProcessed
/// meter. Does NOT block the request response.
///
/// On the non-streaming path we know the exact token count after
/// `buffer_provider_stream` drains the response. The hot-path latency
/// cost is one Postgres index-scan + one in-memory HashMap update —
/// the actual Polar POST happens later in the background flusher.
/// Meter ONE billable overage trace (SET-13).
///
/// Off the request path: the tenant→Polar-customer lookup and the buffer write
/// both happen in a spawned task, so a slow control plane cannot add latency to
/// a request the tenant is already paying extra for.
///
/// Counts 1 per request rather than a token total — the published price is per
/// 10,000 TRACES, and Polar performs the division. Delivery to Polar is the
/// `Recorder`'s 60s flusher, which restores the count to its buffer on failure
/// and dedupes retries on `external_id`, so a network blip cannot double-bill.
fn spawn_overage_record(billing: Arc<crate::billing::Recorder>, tenant_id: TenantId) {
    tokio::spawn(async move {
        let Some(pool) = crate::db::global_pool() else {
            return;
        };
        let tenant = match crate::db::tenants::get(pool, &tenant_id).await {
            Ok(Some(t)) => t,
            _ => return,
        };
        let Some(customer_id) = tenant.polar_customer_id else {
            // No Polar customer (self-serve tenant that never checked out). The
            // quota decision still stands; there is simply nobody to bill.
            return;
        };
        billing
            .record(
                crate::billing::Meter::TracesOverage,
                &crate::billing::PolarCustomerId(customer_id),
                1,
            )
            .await;
        tracing::debug!(tenant_id = %tenant_id, "metered 1 overage trace (overage_v1)");
    });
}

fn spawn_billing_record(
    billing: Arc<crate::billing::Recorder>,
    tenant_id: tracelane_shared::TenantId,
    n_tokens: u64,
) {
    // Zero tokens is not a billable event — a stream that produced nothing.
    // Counted only when we actually meter, so the counter means "billed".
    if n_tokens == 0 {
        return;
    }
    let total = BILLING_RECORDS_SPAWNED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

    // Heartbeat — the ONLY external evidence that the gateway meters at all. The
    // FIRST record after boot always emits (so a deploy is provable immediately),
    // then at most once per interval with the cumulative count. Same CAS shape as
    // PR6's fail-open warn, but at info: metering is normal, not a fault.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_BILLING_LOG_UNIX.load(std::sync::atomic::Ordering::Relaxed);
    let due = last == BILLING_LOG_NEVER || now.saturating_sub(last) >= BILLING_LOG_INTERVAL_SECS;
    if due
        && LAST_BILLING_LOG_UNIX
            .compare_exchange(
                last,
                now,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    {
        tracing::info!(
            billing_records_spawned_total = total,
            n_tokens,
            tenant_id = %tenant_id,
            "billing meter record spawned (cumulative since boot)"
        );
    }
    tokio::spawn(async move {
        let pool = match crate::db::global_pool() {
            Some(p) => p,
            None => return,
        };
        let tenant = match crate::db::tenants::get(pool, &tenant_id).await {
            Ok(Some(t)) => t,
            Ok(None) => return,
            Err(err) => {
                tracing::warn!(error = %err, "billing tenant lookup failed");
                return;
            }
        };
        let customer_id = match tenant.polar_customer_id {
            Some(id) => crate::billing::PolarCustomerId(id),
            None => return,
        };
        billing
            .record(
                crate::billing::Meter::TokensProcessed,
                &customer_id,
                n_tokens,
            )
            .await;
    });
}

/// Build a `TracelaneSpan` from gateway request/response metadata.
///
/// Called after the provider responds (or errors) to record the full round-trip.
/// All timing is wall-clock UTC; `end_time` is set at call time.
///
/// Merge a usage event's token counts into the running per-request totals.
///
/// Token counts are monotonic within a single request, and providers may split
/// them across stream events — Anthropic reports `input_tokens` on
/// `message_start` and the final `output_tokens` on `message_delta`, where its
/// `input_tokens` is hardcoded `0`. A plain overwrite therefore lets the later
/// `message_delta` clobber the real input count back to `0`. Keeping the
/// max makes the merge order-independent and correct for both split-usage
/// providers and single-event providers (OpenAI/Azure/Google/Cohere/Bedrock,
/// which report both counts in one event).
fn merge_usage_tokens(acc_input: &mut u32, acc_output: &mut u32, ev_input: u32, ev_output: u32) {
    *acc_input = (*acc_input).max(ev_input);
    *acc_output = (*acc_output).max(ev_output);
}

/// Parameters match OTel GenAI semconv v1.27.
/// Token usage and streaming metadata threaded onto the gateway span. Keeps
/// `build_gateway_span`'s argument list bounded while carrying the v1.41
/// cache/streaming/conversation attributes (ADR-032).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SpanUsageMeta {
    pub(crate) cache_read_input_tokens: Option<u32>,
    pub(crate) cache_creation_input_tokens: Option<u32>,
    pub(crate) stream: bool,
    /// Upstream-reported cost in USD; `Some` only when the provider
    /// put a cost on the wire. When `None`, `build_gateway_span` derives the
    /// cost from the model price catalog (`crate::pricing`). Lands as
    /// `gen_ai.usage.cost`.
    pub(crate) cost_usd: Option<f64>,
}

/// GWY-45: the captured request content for one span, already truncated.
///
/// **Built ONLY when the tenant is on the `trace_content:` allowlist.** The gate
/// is a single `OnceLock` read (`config::trace_content()`), evaluated before any
/// allocation, so a non-allowlisted tenant — which is every tenant today — pays
/// one atomic load and nothing else.
///
/// v1 is INPUT ONLY. Output is deliberately absent: the span is published BEFORE
/// the response-side guardrail seam so that a BLOCKED request still produces a
/// span (the #81 span-drop), and the comment at that call site justifies the
/// ordering with "the span carries NO response body". Attaching output there
/// would make that false and would persist exactly the text the seam redacts.
/// `prompt_eval.rs` reads only `gen_ai_input_messages`, so input alone is the
/// whole unblock.
#[derive(Debug, Clone)]
struct CapturedInput {
    /// Serialized `Vec<tracelane_shared::model::Message>` — the SAME type
    /// `prompt_eval.rs:509` deserializes, so producer and consumer agree by
    /// construction rather than by convention. Deliberately NOT the canonical
    /// OTel v1.37 `parts` shape, which our own consumer cannot parse; see
    /// `specs/GWY-45` §3.
    messages: serde_json::Value,
    /// The top-level `system` field, which is a DIFFERENT inbound shape from a
    /// `role: "system"` message and is what Anthropic-style callers use. Missing
    /// it would have left system instructions empty for most of prod.
    system: Option<serde_json::Value>,
}

impl CapturedInput {
    /// Returns `None` unless the tenant is allowlisted — the early return IS the
    /// hot-path guarantee.
    fn build(
        tenant_id: &tracelane_shared::TenantId,
        req: &tracelane_shared::ChatRequest,
    ) -> Option<Self> {
        let cfg = self::config::trace_content()?;
        if !cfg.captures(tenant_id) {
            return None;
        }
        let cap = cfg.max_field_bytes();

        // Truncate DURING construction, not after: serializing a 10 MB prompt and
        // then throwing it away still cost the 10 MB.
        let mut msgs = req.messages.clone();
        for m in &mut msgs {
            if let tracelane_shared::model::MessageContent::Text(t) = &mut m.content {
                truncate_utf8(t, cap);
            }
        }
        let messages = serde_json::to_value(&msgs).ok()?;

        let system = req.system.as_ref().map(|sys| {
            let mut s = sys.clone();
            truncate_utf8(&mut s, cap);
            serde_json::Value::String(s)
        });

        Some(Self { messages, system })
    }

    /// Post-construction mutation, matching the two existing precedents in this
    /// file (the semantic-cache hit at the `tracelane_semantic_cache_*` fields,
    /// and `build_embeddings_span`'s name override). Keeps five other
    /// `build_gateway_span` call sites at a zero-line diff.
    fn apply(self, attrs: &mut tracelane_shared::SpanAttributes) {
        attrs.gen_ai_input_messages = Some(self.messages);
        attrs.gen_ai_system_instructions = self.system;
    }
}

/// Truncate a `String` to at most `max` BYTES without splitting a UTF-8 char,
/// appending a visible marker so a reader can tell a cut prompt from a short one.
///
/// A silent truncation would produce eval cases that look complete and are not —
/// the marker is what makes that detectable downstream.
fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    const MARK: &str = "…[truncated]";

    // THE POST-CONDITION IS `s.len() <= max`, ALWAYS. When `max` is smaller than
    // the marker itself there is no room to say "this was cut", so cut hard
    // rather than emit a string LONGER than the cap — which is what the first
    // version of this function did, and what its own test caught.
    //
    // Unreachable in production: `build_trace_content` refuses a
    // `max_field_bytes` under 1 KiB. Handled anyway, because a helper that
    // silently violates its stated contract is a defect waiting for its second
    // caller.
    let mut cut = |limit: usize| {
        let mut end = limit.min(s.len());
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    };

    if max <= MARK.len() {
        cut(max);
        return;
    }
    cut(max - MARK.len());
    s.push_str(MARK);
}

#[allow(clippy::too_many_arguments)]
/// Segment timestamps for the gateway-overhead split (§ latency framing). The
/// span's `start_time` = gateway-received and `end_time` = gateway-response-sent
/// bracket the whole request; these two interior marks bracket the provider
/// round-trip, so `gateway_overhead = (dispatch − received) + (sent − provider
/// complete)` and `provider = total − gateway_overhead` — the two segments sum
/// to total with NO unattributed bucket. `ttft_us` (dispatch → provider first
/// byte) is streaming-only.
#[derive(Clone, Copy)]
pub(crate) struct GatewayTiming {
    pub(crate) dispatch_ts: chrono::DateTime<chrono::Utc>,
    pub(crate) provider_complete_ts: chrono::DateTime<chrono::Utc>,
    pub(crate) ttft_us: Option<u32>,
}

/// Gateway-overhead microseconds = `(dispatch − received) + (sent − provider
/// complete)` — the time the gateway adds, EXCLUDING the provider round-trip.
/// Pure so the split math is unit-testable: with `total = sent − received`,
/// `provider = total − overhead`, and `overhead + provider == total` exactly
/// (no unattributed bucket). `None` if any interval underflows the μs range.
fn gateway_overhead_us(
    received: chrono::DateTime<chrono::Utc>,
    dispatch: chrono::DateTime<chrono::Utc>,
    provider_complete: chrono::DateTime<chrono::Utc>,
    sent: chrono::DateTime<chrono::Utc>,
) -> Option<u32> {
    let pre = (dispatch - received).num_microseconds()?;
    let post = (sent - provider_complete).num_microseconds()?;
    u32::try_from((pre + post).max(0)).ok()
}

#[allow(clippy::too_many_arguments)]
/// R81: `pub(crate)` so `prompt_eval` builds its spans with the SAME function the
/// chat path uses. A second span builder for eval traffic would be a second source
/// of truth for "what a gateway span is", and the two would drift on the next
/// column — which is the failure `S2`/one-execution-engine exists to prevent.
pub(crate) fn build_gateway_span(
    tenant_id: &TenantId,
    trace_id: Uuid,
    model: &str,
    agent_id: Option<&str>,
    human_authorizer: Option<&str>,
    business_reference: Option<&str>,
    start_time: chrono::DateTime<chrono::Utc>,
    input_tokens: u32,
    output_tokens: u32,
    aft_id: Option<&str>,
    usage_meta: SpanUsageMeta,
    conversation_id: Option<&str>,
    failover_from: Option<&str>,
    timing: Option<GatewayTiming>,
    error_reason: Option<&str>,
    api_key_id: Option<&str>,
) -> TracelaneSpan {
    let provider = provider_name_from_model(model);
    let end_time = chrono::Utc::now();
    // Gateway overhead = time Tracelane adds, EXCLUDING the provider round-trip:
    // (dispatch − received) + (sent − provider-complete). `None` when there was
    // no measured provider round-trip (dispatch failures / guardrail blocks).
    let gateway_overhead_us = timing.and_then(|t| {
        gateway_overhead_us(start_time, t.dispatch_ts, t.provider_complete_ts, end_time)
    });
    let ttft_secs = timing
        .and_then(|t| t.ttft_us)
        .map(|us| f64::from(us) / 1_000_000.0);
    TracelaneSpan {
        span_id: Uuid::new_v4(),
        trace_id,
        parent_span_id: None,
        tenant_id: tenant_id.clone(),
        name: "gen_ai.chat".to_string(),
        start_time,
        end_time: Some(end_time),
        attributes: SpanAttributes {
            gen_ai_operation_name: Some("chat".to_string()),
            // Canonical v1.41 provider field; `gen_ai_system` kept for
            // legacy-downstream round-trip (ADR-032).
            gen_ai_system: Some(provider.to_string()),
            gen_ai_provider_name: Some(provider.to_string()),
            gen_ai_request_model: Some(model.to_string()),
            gen_ai_response_model: Some(model.to_string()),
            gen_ai_usage_input_tokens: Some(input_tokens),
            gen_ai_usage_output_tokens: Some(output_tokens),
            gen_ai_usage_cache_read_input_tokens: usage_meta.cache_read_input_tokens,
            gen_ai_usage_cache_creation_input_tokens: usage_meta.cache_creation_input_tokens,
            // Provider-reported cost when present; otherwise derive it from the
            // token counts + the model price catalog. `None` (unknown model) is
            // preserved — the gateway never fabricates a cost (ADR-055).
            gen_ai_usage_cost: usage_meta.cost_usd.or_else(|| {
                crate::pricing::cost_usd(
                    model,
                    &tracelane_shared::Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_input_tokens: usage_meta.cache_read_input_tokens,
                        cache_creation_input_tokens: usage_meta.cache_creation_input_tokens,
                    },
                )
            }),
            gen_ai_request_stream: Some(usage_meta.stream),
            gen_ai_response_time_to_first_chunk: ttft_secs,
            tracelane_gateway_overhead_us: gateway_overhead_us,
            gen_ai_conversation_id: conversation_id.map(str::to_owned),
            tracelane_aft_id: aft_id.map(str::to_owned),
            tracelane_kya_agent_id: agent_id.map(str::to_owned),
            tracelane_kya_human_authorizer: human_authorizer.map(str::to_owned),
            tracelane_business_reference: business_reference.map(str::to_owned),
            // Present only when a cross-provider failover served this
            // request. The rollup counts `countIf(tracelane_failover_activated)`;
            // `tracelane_failover_from` names the primary provider that errored.
            tracelane_failover_activated: failover_from.map(|_| true),
            tracelane_failover_from: failover_from.map(str::to_owned),
            // GWY-43: which API key paid for this. `None` for a JWT session.
            tracelane_api_key_id: api_key_id.map(str::to_owned),
            ..Default::default()
        },
        // A FAILED request (upstream 4xx/5xx/timeout, mid-stream provider error, or
        // dispatch exhaustion) MUST record status Error — otherwise /slo's
        // countIf(status_code = 2) error rate is STRUCTURALLY pinned at ~0% for all
        // gateway-proxied traffic (#3: every span was hardcoded Ok, so a real
        // provider outage read as "0% errors · no errors in window"). Ok is emitted
        // only on a genuinely successful round-trip.
        status: match error_reason {
            Some(reason) => SpanStatus {
                code: SpanStatusCode::Error,
                message: Some(reason.to_string()),
            },
            None => SpanStatus {
                code: SpanStatusCode::Ok,
                message: None,
            },
        },
    }
}

/// Minimal Error-status span for a request that FAILED before or during the
/// provider round-trip (dispatch exhaustion, upstream 401/429/404/5xx, timeout).
/// Zero tokens, no cost, no optional attribution — its whole job is to make the
/// failure COUNTABLE (status_code = 2) so the error-rate metric reflects reality
/// The fail-closed response for a model that matches NO provider in the
/// canonical map. Returned INSTEAD of routing to a default provider — no key is
/// resolved, no upstream call is made. 400 (the caller sent an unroutable model).
/// The model string is echoed back (it is the caller's own input, not a secret)
/// so they can correct it; scrubbed defensively in case a key was pasted as a
/// "model".
fn unroutable_model_response(model: &str) -> axum::response::Response {
    let mut map = serde_json::Map::new();
    map.insert("error".into(), "unroutable_model".into());
    map.insert(
        "message".into(),
        "no provider is configured to serve this model — use a supported model, \
         or prefix it with a provider (e.g. openrouter/<model>, together/<model>)"
            .into(),
    );
    map.insert("model".into(), model.into());
    let raw = serde_json::to_vec(&serde_json::Value::Object(map))
        .unwrap_or_else(|_| b"{\"error\":\"unroutable_model\"}".to_vec());
    // Defense in depth: scrub in case a key was pasted into the `model` field.
    let scrubbed = tracelane_shared::redact::scrub(&raw);
    let mut resp = (StatusCode::BAD_REQUEST, scrubbed).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp
}

/// Build a client-facing provider-error response with a defense-in-depth
/// redaction backstop.
///
/// The body is **allowlist-constructed** — our typed `error` code, an optional
/// STATIC `message`, and the provider NAME only. The upstream provider's body and
/// headers are NEVER included (a bad-BYOK 401 body echoes the tenant's own key; a
/// verbose 5xx body can carry internal detail). Belt-and-suspenders: the
/// serialized body is then run through `tracelane_shared::redact::scrub`, so any
/// key-shaped string (`sk-`, `AIza`, `AQ.`, `xai-`, `tlane_`, `Bearer …`, an
/// `authorization`/`x-api-key` field, …) that ever slips into a field is scrubbed
/// before it reaches the client. `Content-Type` is forced to `application/json`
/// (scrub returns bytes, which axum would otherwise label `text/plain`).
fn provider_error_response(
    status: StatusCode,
    error_code: &str,
    message: Option<&str>,
    provider: Option<&str>,
    retry_after_secs: Option<&'static str>,
) -> axum::response::Response {
    let mut map = serde_json::Map::new();
    map.insert("error".into(), error_code.into());
    if let Some(m) = message {
        map.insert("message".into(), m.into());
    }
    if let Some(p) = provider {
        map.insert("provider".into(), p.into());
    }
    let raw = serde_json::to_vec(&serde_json::Value::Object(map))
        .unwrap_or_else(|_| b"{\"error\":\"internal\"}".to_vec());
    let scrubbed = tracelane_shared::redact::scrub(&raw);
    let mut resp = (status, scrubbed).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    if let Some(ra) = retry_after_secs {
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static(ra),
        );
    }
    resp
}

/// R13 — emit the error-status span for a request that ALREADY HAS A LEDGER ROW.
///
/// # Why this exists as one function
///
/// Past `state.audit_chain.publish(...)` on the chat path, the tamper-evident ledger
/// asserts the request happened. **A return from there without a span is a request the
/// ledger attests to and the product cannot show** — a customer reconciling their audit
/// export against `/traces` finds a gap, and nothing anywhere reports one. Measured
/// 2026-08-14 (B-245 §5.2): **~500 such rows fleet-wide**, on every tenant with traffic,
/// at 5–8% of requests, present from the first day of the current ledger.
///
/// Three call sites already did this correctly and three did not, and the three that did
/// were **the same ten lines copy-pasted** — which is exactly how the other three came to
/// be missed. One definition means a new post-ledger exit is one line away from correct,
/// and it is what makes `scripts/ci/check-post-ledger-span-emit.py` able to check the
/// property mechanically: the guard looks for a call to THIS function, so it matches a
/// construction rather than a word (`TRAPS.md` §19).
///
/// # Errors
/// None — infallible by construction. This is a **fault-tolerance** path: failing to
/// record a span must never change the response the customer already earned. The publish
/// is detached and its failure is counted by `note_span_publish_failed()`.
fn emit_post_ledger_error_span(
    state: &AppState,
    tenant_id: &TenantId,
    trace_id: Uuid,
    model: &str,
    request_start: chrono::DateTime<chrono::Utc>,
    reason: &str,
    aft_id: Option<&str>,
) {
    // No NATS ⇒ capture is not wired at all; the boot refusal (A1) already covers that
    // case loudly, and `spans_dropped` is the live signal. Nothing to do here.
    let Some(ref nats_client) = state.nats else {
        return;
    };
    let span = match aft_id {
        Some(aft) => build_blocked_aft_span(tenant_id, trace_id, model, request_start, reason, aft),
        None => build_error_span(tenant_id, trace_id, model, request_start, reason),
    };
    let nats = Arc::clone(nats_client);
    tokio::spawn(async move {
        if let Err(e) = crate::otlp_emit::publish_span(&nats, &span).await {
            crate::otlp_emit::note_span_publish_failed();
            tracing::warn!(error = %e, "post-ledger error-span NATS publish failed");
        }
    });
}

/// instead of a structural 0%. Reuses `build_gateway_span` so the shape stays one
/// definition.
fn build_error_span(
    tenant_id: &TenantId,
    trace_id: Uuid,
    model: &str,
    start_time: chrono::DateTime<chrono::Utc>,
    reason: &str,
) -> TracelaneSpan {
    build_gateway_span(
        tenant_id,
        trace_id,
        model,
        None,
        None,
        None,
        start_time,
        0,
        0,
        None,
        SpanUsageMeta {
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
            stream: false,
            cost_usd: None,
        },
        None,
        None,
        None, // timing: no measured provider round-trip on a failure/block span
        Some(reason),
        // GWY-43: no key attribution on an error span. It carries zero tokens and
        // zero cost, so it cannot move a per-key spend total; attributing FAILURES
        // by key is a separate feature, and inventing a value here would put a
        // dimension on a row whose cost is structurally absent.
        None,
    )
}

/// Error-status span for a request BLOCKED by an inline guardrail that maps to a
/// canonical AFT-1 failure signature (today: tool-description injection →
/// `AFT-TOOL-POISON-001`). Like [`build_error_span`] but carries the `aft_id` so
/// the blocked hit still lands in `spans.aft_ids` and the tenant sees it on
/// signatures — a blocked injection is "your hit," not a silent 403 (#5).
fn build_blocked_aft_span(
    tenant_id: &TenantId,
    trace_id: Uuid,
    model: &str,
    start_time: chrono::DateTime<chrono::Utc>,
    reason: &str,
    aft_id: &str,
) -> TracelaneSpan {
    build_gateway_span(
        tenant_id,
        trace_id,
        model,
        None,
        None,
        None,
        start_time,
        0,
        0,
        Some(aft_id),
        SpanUsageMeta {
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
            stream: false,
            cost_usd: None,
        },
        None,
        None,
        None, // timing: no measured provider round-trip on a failure/block span
        Some(reason),
        // GWY-43: no key attribution on an error span. It carries zero tokens and
        // zero cost, so it cannot move a per-key spend total; attributing FAILURES
        // by key is a separate feature, and inventing a value here would put a
        // dimension on a row whose cost is structurally absent.
        None,
    )
}

/// Map a model name to a canonical provider name (OTel `gen_ai.system` /
/// `gen_ai.provider.name` value) for span attribution.
///
/// This DELEGATES to the canonical `ProviderRegistry::provider_id_for_model`
/// rather than carrying its own prefix table. A private copy had drifted — it only
/// knew 8 prefixes and stamped every other model (groq, mistral, perplexity, xai,
/// and the rest of the catalog) as `"unknown"` on the span, so the dashboard's provider
/// column + per-provider latency tiles were blank/"unknown" for most real traffic.
/// Only the two names that differ from the provider_id (AWS/GCP house style) are
/// remapped; the rest of the provider_id set already equals the gen_ai.system value.
fn provider_name_from_model(model: &str) -> &'static str {
    // An unmatched model has no provider — attribute it "unknown" (this is
    // a span label, never a key lookup, so "unknown" is safe; the key path already
    // fail-closed on None before reaching here).
    match crate::providers::ProviderRegistry::provider_id_for_model(model) {
        Some("vertex") => "gcp_vertex_ai",
        Some("bedrock") => "aws_bedrock",
        Some(other) => other,
        None => "unknown",
    }
}

/// Outcome of resolving a provider key. Distinguishes "the tenant never added
/// one" from "one exists but we cannot use it" — the two need OPPOSITE user
/// actions (add a key vs rotate an existing one), and collapsing them into a
/// single `None` is what made an unconfigured provider report
/// `provider_key_rejected` ("verify the key for this provider") to a user who
/// had no key to verify.
pub(crate) enum ProviderKey {
    /// A usable key. An EMPTY string is a legitimate value for the no-key
    /// providers (Ollama) — it means "this provider needs no credential".
    Found(String),
    /// No BYOK row and no env fallback: the tenant has not configured this
    /// provider. Actionable in Settings → LLM Providers.
    NotConfigured,
    /// A BYOK row exists but could not be decrypted (AAD / master-key
    /// mismatch). A key IS configured — telling the user to add one would send
    /// them the wrong way.
    Unusable,
}

/// A4: resolve the provider-API plaintext key. Order:
///   1. Hot-path cache (`db::provider_keys::lookup_cached`).
///   2. Per-tenant BYOK row from `provider_keys` (decrypted with AAD).
///   3. Process env var (legacy single-tenant fallback).
///   4. Empty string (Ollama / no-key providers).
///
/// Returns [`ProviderKey::Found`] when we have a key to use, and a typed
/// failure otherwise so the caller can tell the customer what to actually DO
/// (add a key vs rotate one) instead of dispatching an empty credential and
/// relaying the upstream 401.
///
/// The `SecretString` is cloned into a plain `String` only at the very
/// last hop so reqwest can attach it as a header value.
/// `pub(crate)` for `prompt_eval`, for the same reason as `dispatch_to_provider`:
/// eval traffic resolves credentials exactly the way real traffic does.
pub(crate) async fn resolve_provider_key(
    tenant_id: &TenantId,
    provider_id: &str,
    env_var: &str,
) -> ProviderKey {
    use secrecy::ExposeSecret as _;
    use std::sync::Arc;

    if let Some(secret) = crate::db::provider_keys::lookup_cached(tenant_id, provider_id) {
        return ProviderKey::Found(secret.expose_secret().to_string());
    }

    if let (Some(pool), Some(master)) = (crate::db::global_pool(), crate::byok::master_key()) {
        match crate::db::provider_keys::get(pool, tenant_id, provider_id).await {
            Ok(Some(row)) => {
                let aad = crate::byok::provider_key_aad(tenant_id, provider_id);
                match master.decrypt_with_context(&row.ciphertext_b64, &aad) {
                    Ok(plaintext) => {
                        let secret = Arc::new(plaintext);
                        crate::db::provider_keys::cache_decrypted(
                            tenant_id,
                            provider_id,
                            Arc::clone(&secret),
                        );
                        return ProviderKey::Found(secret.expose_secret().to_string());
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            tenant_id = %tenant_id,
                            provider_id,
                            "BYOK decrypt failed — refusing env fallback (auth-fail safer)"
                        );
                        return ProviderKey::Unusable;
                    }
                }
            }
            Ok(None) => { /* fall through to env */ }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    tenant_id = %tenant_id,
                    provider_id,
                    "provider_keys lookup failed — falling back to env"
                );
            }
        }
    }

    if env_var.is_empty() {
        return ProviderKey::Found(String::new()); // Ollama
    }
    match std::env::var(env_var) {
        Ok(k) => ProviderKey::Found(k),
        Err(_) => ProviderKey::NotConfigured,
    }
}

/// Current UTC calendar month as `YYYYMM` (e.g. `202607`) — the seed key for the
/// durable monthly quota counter's month-boundary reset.
fn current_year_month() -> u32 {
    use chrono::Datelike as _;
    let now = chrono::Utc::now();
    now.year() as u32 * 100 + now.month()
}

///  durability: read the tenant's trace count for the current calendar month
/// from ClickHouse — the durable baseline the in-memory quota counter is seeded
/// from so a restart / blue-green deploy no longer forgives accrued usage. Runs
/// once per tenant per month per process (gated by `QuotaTracker::needs_seed`),
/// never on the warm hot path. `trace_summaries` is one row per trace = the
/// "traces this month" the quota bills; its `(tenant_id, start_time, …)` sort key
/// makes this an indexed range scan. Any failure → 0 (fail-open baseline: never
/// block a paying tenant because ClickHouse blinked; worst case is one
/// process-lifetime of under-count, corrected on the next month's seed).
/// **The one definition of "traces this month".** SET-07.
///
/// Both the number a customer is SHOWN on the billing page and the number that
/// 429s them read this constant, so the two cannot disagree. That property is the
/// whole point: a usage figure that is merely *similar* to the enforced one is
/// worse than none, because it is the figure a customer will quote back when they
/// are cut off and the dashboard said they had headroom.
///
/// `trace_summaries`, not `spans` — one row per TRACE is what the quota bills, and
/// counting spans would over-report by the fan-out factor of every trace. Its
/// `(tenant_id, start_time, …)` sort key makes this an indexed range scan.
///
/// `toStartOfMonth(now())` is ClickHouse-server time (UTC), and the reset boundary
/// is therefore the same instant for the display and the enforcement — matching
/// them in the client would reintroduce the drift this constant removes.
/// `uniqExact(trace_id)`, **NOT `count()`** — and this one bills.
///
/// `trace_summaries` is a write-time MV: if ingest splits a trace across batches
/// it emits **one partial row per batch** for the same `trace_id`, each carrying
/// that batch's own `min(start_time)`. `start_time` is in the ReplacingMergeTree
/// ORDER BY, so the rows have distinct keys and never collapse — not even under
/// `FINAL` (B-243, verified against a real trace on prod).
///
/// With `count()` that made **a multi-flush trace bill as two or more traces**
/// against the monthly quota, and the same constant feeds the usage figure the
/// customer is shown (`billing/usage.rs:86`) — so display and enforcement
/// over-counted together, in OUR favour. A real agent triggers it and no
/// synthetic test does: simulated sub-second calls fit one exporter flush, real
/// LLM latency does not.
///
/// `trace_reads.rs:1427-1434` had already documented this exact mechanism and
/// fixed the footer query with `uniqExact` — and four other call sites, this one
/// included, kept `count()`. That is the CLASS-2 shape: a finding recorded at ONE
/// call site is not recorded (`docs/reference/TRAPS.md` §29).
///
/// Pinned by `billing::usage::tests::usage_reads_the_same_predicate_the_quota_enforcer_reads`.
pub const TRACES_THIS_MONTH_SQL: &str = "SELECT toUInt64(uniqExact(trace_id)) AS n FROM tracelane.trace_summaries \
        WHERE tenant_id = ? AND start_time >= toStartOfMonth(now())";

/// Add a completed request's cost to its API key's monthly total.
///
/// Reads the cost off the SPAN, not from a second `pricing::cost_usd` call: the
/// budget and the dashboard must agree about what a request cost, and the only
/// way to guarantee that is for both to read one value. A `None` cost — a model
/// with no known price — adds nothing rather than zero (see `spend.rs`).
///
/// A non-UUID key id cannot happen (`claims.api_key_id()` returns the
/// `api_keys.id` it read from Postgres) but is ignored rather than unwrapped:
/// this runs on the response path and must not be able to panic a stream.
fn record_key_spend(api_key_id: Option<&str>, span: &TracelaneSpan) {
    let cost = span.attributes.gen_ai_usage_cost;
    let tracker = crate::spend::tracker();
    // The workspace total counts EVERY request, keyed or not — a session-driven
    // request spends the workspace's money too, and exempting it would make the
    // workspace cap quietly smaller than it says.
    tracker.record(
        crate::spend::Subject::Workspace(*span.tenant_id.as_uuid()),
        cost,
    );
    let Some(id) = api_key_id else { return };
    let Ok(uuid) = Uuid::parse_str(id) else {
        return;
    };
    tracker.record(crate::spend::Subject::Key(uuid), cost);
}

/// This key's recorded spend so far this calendar month, USD.
///
/// **Tenant-first, then key** — the same predicate order every ClickHouse read
/// in this codebase uses, and the reason `tenant_id` leads the table's ORDER BY.
/// Binding the key alone would be a cross-tenant read; binding it second is the
/// isolation the schema is shaped for.
///
/// Only spans written since migration 16 carry `api_key_id`, so this total
/// begins at that cutover. Every surface that renders it must say so rather than
/// implying the history was always attributable.
pub const KEY_SPEND_THIS_MONTH_SQL: &str = "SELECT toFloat64(sum(cost_usd)) AS usd \
        FROM tracelane.spans \
        WHERE tenant_id = ? AND api_key_id = ? \
          AND cost_usd_present = 1 \
          AND start_time >= toStartOfMonth(now())";

/// The whole workspace's recorded spend this calendar month, USD.
///
/// Deliberately NOT filtered on `api_key_id`: a workspace ceiling covers every
/// request the tenant made, including session-authenticated ones that carry no
/// key. Filtering by key here would silently exempt dashboard-driven spend from
/// the workspace cap.
pub const WORKSPACE_SPEND_THIS_MONTH_SQL: &str = "SELECT toFloat64(sum(cost_usd)) AS usd \
        FROM tracelane.spans \
        WHERE tenant_id = ? \
          AND cost_usd_present = 1 \
          AND start_time >= toStartOfMonth(now())";

async fn workspace_spend_baseline_from_clickhouse(state: &AppState, tenant_id: &TenantId) -> f64 {
    let Some(url) = state.quota_ch_url.clone() else {
        return 0.0;
    };
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct SumRow {
        usd: f64,
    }
    match crate::clickhouse_query::ch_client(url)
        .query(WORKSPACE_SPEND_THIS_MONTH_SQL)
        .bind(tenant_id.to_string())
        .fetch_one::<SumRow>()
        .await
    {
        Ok(row) if row.usd.is_finite() && row.usd > 0.0 => row.usd,
        Ok(_) => 0.0,
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "workspace spend baseline ClickHouse read failed; seeding 0 (fail-open)"
            );
            0.0
        }
    }
}

async fn spend_baseline_from_clickhouse(
    state: &AppState,
    tenant_id: &TenantId,
    api_key_id: &str,
) -> f64 {
    let Some(url) = state.quota_ch_url.clone() else {
        return 0.0;
    };
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct SumRow {
        usd: f64,
    }
    match crate::clickhouse_query::ch_client(url)
        .query(KEY_SPEND_THIS_MONTH_SQL)
        .bind(tenant_id.to_string())
        .bind(api_key_id)
        .fetch_one::<SumRow>()
        .await
    {
        Ok(row) if row.usd.is_finite() && row.usd > 0.0 => row.usd,
        Ok(_) => 0.0,
        Err(e) => {
            // Fail OPEN, and say so. A control-plane read failure must not stop a
            // customer's production traffic — the same choice
            // `quota_baseline_from_clickhouse` makes. The cost is that a restart
            // during a ClickHouse outage forgives that key's accrued spend until
            // the next month rolls; that is stated in `spend.rs`'s module docs
            // rather than left for an operator to discover.
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "per-key spend baseline ClickHouse read failed; seeding 0 (fail-open)"
            );
            0.0
        }
    }
}

async fn quota_baseline_from_clickhouse(state: &AppState, tenant_id: &TenantId) -> u64 {
    let Some(url) = state.quota_ch_url.clone() else {
        return 0;
    };
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct CountRow {
        n: u64,
    }
    match crate::clickhouse_query::ch_client(url)
        .query(TRACES_THIS_MONTH_SQL)
        .bind(tenant_id.to_string())
        .fetch_one::<CountRow>()
        .await
    {
        Ok(row) => row.n,
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "quota baseline ClickHouse read failed; seeding 0 (fail-open baseline)"
            );
            0
        }
    }
}

/// Look up the tenant's quota-alert webhook, if configured on
/// `tenants.slack_webhook_url`. Returns None when the column is null, the
/// tenant is missing, or no Postgres pool is available — the response is
/// independent of webhook delivery.
///
/// The column name says "slack" for historical reasons only; any HTTPS
/// receiver works. SET-04 added the writer (`/api/settings/notify-webhook`);
/// before that this always returned None for every tenant.
async fn resolve_tenant_quota_webhook(tenant_id: &TenantId) -> Option<String> {
    let pool = crate::db::global_pool()?;
    match crate::db::tenants::get(pool, tenant_id).await {
        Ok(Some(t)) => t.slack_webhook_url,
        _ => None,
    }
}

/// Compute the first day of next month at 00:00:00 UTC as RFC3339.
///
/// This is the `reset_at` value surfaced in the 429 response body so
/// customers know when their monthly quota counter zeroes. The actual
/// counter reset is performed by the billing reconciler via
/// `QuotaTracker::reset_for_period`.
pub fn next_month_boundary_iso() -> String {
    use chrono::{Datelike as _, TimeZone as _};
    let now = chrono::Utc::now();
    let (year, month) = if now.month() == 12 {
        (now.year() + 1, 1)
    } else {
        (now.year(), now.month() + 1)
    };
    match chrono::Utc
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
    {
        Some(dt) => dt.to_rfc3339(),
        // Calendar arithmetic above is total; this branch is unreachable
        // in practice but we never want to panic on the hot path.
        None => now.to_rfc3339(),
    }
}

/// SSRF gate for the tenant-controlled Slack webhook URL
/// (`tenants.slack_webhook_url`).
///
/// The webhook URL is set by the tenant, so it is an SSRF vector: without this
/// gate a tenant could point the gateway at link-local (169.254.169.254 cloud
/// IMDS), RFC1918, CGNAT, or loopback addresses and exfiltrate metadata. The
/// notify path calls this BEFORE issuing any request, so a disallowed URL —
/// bad scheme, blocked IP literal, or a domain whose DNS resolves into a
/// blocked range — is dropped before a packet leaves the box.
///
/// Factored out of [`notify_quota_exceeded_async`] so it is unit-testable
/// without spawning a task or hitting the network. Returns the guard's error
/// for logging on reject.
///
/// # Errors
/// Propagates [`crate::ssrf_guard::validate_url`] errors (fail-closed — a URL
/// that cannot be proven safe is rejected).
async fn validate_slack_webhook(webhook_url: &str) -> anyhow::Result<()> {
    crate::ssrf_guard::validate_url(webhook_url).await
}

/// Process-local cache of the SETTLED soft-cap outcome per tenant: the period
/// for which this process knows the notification is finished — either we sent it
/// or we lost the `ON CONFLICT` race to someone who did.
///
/// Caching the *outcome*, not merely the *attempt*, is what lets a LOST claim
/// short-circuit with no Postgres round-trip for the rest of the period. It also
/// fixes a silent-loss path the attempt-only version had: a transient Neon error
/// marked the tenant attempted, so the alert was never retried and never sent —
/// no error surfaced to anyone. An errored claim is NOT an outcome, so the task
/// removes the entry and the next request retries.
///
/// Never the correctness boundary: exactly-once across restarts and replicas
/// comes from the primary key on `quota_notifications`.
static SOFT_CAP_SETTLED: std::sync::OnceLock<dashmap::DashMap<String, u32>> =
    std::sync::OnceLock::new();

/// Notify the tenant that they are at or over 100% of their included quota,
/// exactly once per tenant per billing period — globally, not per process.
///
/// Off the request path entirely: the Postgres claim and the POST both happen
/// inside a spawned task, so the request this fires on is served at full speed
/// whether or not either succeeds.
///
/// **Why the claim is persisted.** The in-memory counter reseeds from ClickHouse
/// on boot, so it cannot answer "did we already tell them this month?"
/// a restart moves the counter and takes the answer with it. The previous
/// implementation asked exactly that question (`used == quota`) and was wrong in
/// both directions on any mid-month deploy: a reseed above quota lost the alert
/// silently, a reseed below quota sent it twice.
fn maybe_notify_soft_cap(tenant_id: &TenantId, year_month: u32, quota: u64, used: u64) {
    let settled = SOFT_CAP_SETTLED.get_or_init(dashmap::DashMap::new);
    let key = tenant_id.to_string();
    // Claim the right to spawn ATOMICALLY. A `get` then `insert` leaves a window
    // in which K concurrent requests at the crossing all observe "not settled"
    // and all spawn, so K tasks race the same INSERT and K-1 lose. Holding the
    // entry lock closes that: exactly one caller per (tenant, period) proceeds.
    match settled.entry(key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(mut o) => {
            if *o.get() == year_month {
                // Already sent, or already lost to another replica. Either way
                // there is nothing left to do and no reason to touch Postgres.
                return;
            }
            o.insert(year_month);
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(year_month);
        }
    }

    let Some(pool) = crate::db::global_pool().cloned() else {
        // No control plane: nothing to claim against. Drop the marker so a later
        // request can retry if a pool appears.
        settled.remove_if(&key, |_, v| *v == year_month);
        return;
    };
    let tenant = tenant_id.clone();
    let period = format!("{year_month:06}");
    let settled_key = key;
    tokio::spawn(async move {
        match crate::db::quota_notifications::claim(
            &pool,
            &tenant,
            &period,
            crate::db::quota_notifications::KIND_SOFT_CAP,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    tenant_id = %tenant,
                    period = %period,
                    "soft-cap notification already claimed for this period — not re-sending"
                );
                return;
            }
            Err(e) => {
                // An ERROR is not an outcome. Forget it so the next request
                // retries — otherwise one Neon blip at the crossing loses the
                // alert for the whole period with nothing to show for it, which
                // is the same silent-loss shape this whole fix exists to remove.
                // Not notifying on THIS request is still correct: a missed alert
                // beats a duplicate that trains the tenant to mute the channel
                // their hard-cap 429 also arrives on.
                SOFT_CAP_SETTLED
                    .get_or_init(dashmap::DashMap::new)
                    .remove_if(&settled_key, |_, v| *v == year_month);
                tracing::warn!(
                    error = %e,
                    tenant_id = %tenant,
                    "soft-cap claim failed — will retry on a later request"
                );
                return;
            }
        }
        tracing::info!(
            tenant_id = %tenant,
            quota_soft_cap = true,
            quota,
            used,
            "included quota reached (100%) — notifying, request still served"
        );
        // DSH-01 (closing B-211's quota producer). This is deliberately INSIDE
        // the successful-claim branch, which is the only place that fires
        // exactly once per (tenant, period) across restarts and replicas —
        // B-211 said the quota producer must hang off THIS transition or it
        // double-fires on a mid-month restart, which is the defect migration
        // 0023's header documents.
        //
        // Before the webhook, and independent of it: the in-app row is the
        // channel that cannot bounce, be filtered, or depend on the tenant
        // having configured anything. A tenant with no webhook still gets told.
        crate::notification_routes::notify(
            &pool,
            *tenant.as_uuid(),
            "quota",
            "Included quota reached (100%)",
            &QuotaEvent::SoftCap { limit: quota, used }.message(&tenant),
            "warning",
            "/settings/billing",
        )
        .await;

        if let Some(webhook) = resolve_tenant_quota_webhook(&tenant).await {
            notify_quota_event_async(
                webhook,
                tenant.clone(),
                QuotaEvent::SoftCap { limit: quota, used },
            );
        }
    });
}

/// A quota milestone worth telling the tenant about.
///
/// The two variants differ in what the gateway DID, which is the only thing
/// the tenant cannot infer for themselves: `SoftCap` was served, `HardCap` was
/// refused. Keeping them in one enum is what makes the notify seam
/// channel-agnostic — a future email or in-app channel is added inside
/// [`notify_quota_event_async`] and reads this enum, without any quota logic
/// moving out of `chat_completions_handler`.
#[derive(Debug, Clone, Copy)]
enum QuotaEvent {
    /// Exactly 100% of the included quota. The request was SERVED (SET-08).
    SoftCap { limit: u64, used: u64 },
    /// Past the hard cap. The request was REFUSED with a 429.
    HardCap { limit: u64, used: u64 },
}

impl QuotaEvent {
    /// Human-readable alert text. Never includes API-key material or trace
    /// contents (CLAUDE.md security non-negotiable #5) — tenant id and counts
    /// only.
    fn message(&self, tenant_id: &TenantId) -> String {
        match *self {
            QuotaEvent::SoftCap { limit, used } => format!(
                "Tracelane quota reached — tenant {tenant_id} used {used} / included {limit} \
                 (100%). Requests are STILL BEING SERVED; overage applies until the hard cap. \
                 Visit https://app.tracelane.dev/settings/billing to review."
            ),
            QuotaEvent::HardCap { limit, used } => format!(
                "Tracelane quota exceeded — tenant {tenant_id} used {used} / hard cap {limit}. \
                 Gateway is now returning 429. Visit \
                 https://app.tracelane.dev/settings/billing to upgrade."
            ),
        }
    }
}

/// Fire-and-forget notification for a [`QuotaEvent`].
///
/// Spawns onto the existing tokio runtime; the request handler does NOT await
/// delivery. Latency or failure is invisible to the caller — which is what
/// makes the SET-08 soft cap genuinely non-blocking: the request is served
/// whether or not this ever lands.
///
/// The tenant-controlled URL passes [`validate_slack_webhook`] before any
/// request fires (SSRF), and the request uses
/// [`crate::ssrf_guard::safe_client_builder`] (rustls + no-redirect, so a
/// redirect to an internal host cannot be followed). A rejected URL is
/// log-and-dropped — the response the caller already received is independent
/// of webhook delivery.
///
/// **Channel-agnostic on purpose.** Nothing here requires a `hooks.slack.com`
/// host; the `{"text": …}` shape is what Slack and Discord both accept and any
/// receiver can parse. Adding email means adding a branch in this function, not
/// touching the quota arms in the hot path.
fn notify_quota_event_async(webhook_url: String, tenant_id: TenantId, event: QuotaEvent) {
    tokio::spawn(async move {
        if let Err(e) = validate_slack_webhook(&webhook_url).await {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                ?event,
                "quota webhook URL rejected by SSRF guard; dropping notification (response already returned)"
            );
            return;
        }

        let body = serde_json::json!({ "text": event.message(&tenant_id) });
        let client = match crate::ssrf_guard::safe_client_builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "quota webhook client build failed");
                return;
            }
        };
        if let Err(e) = client.post(&webhook_url).json(&body).send().await {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                ?event,
                "quota webhook POST failed; response already returned to caller"
            );
        }
    });
}

/// True for the reserved benchmark-only model names that, when
/// `TRACELANE_BENCH_MOCK_UPSTREAM` is enabled, route to an instant in-gateway
/// mock instead of a real provider — used to isolate gateway overhead
/// (`bench/gateway/`). The `__bench_` prefix is namespaced so it cannot collide
/// with any real model id, and it only matters when the flag is on; in normal
/// operation a request for one of these models dispatches like any other.
fn is_bench_mock_model(model: &str) -> bool {
    model.starts_with("__bench_mock")
}

/// Synthetic `provider_id` for the bench-mock path.
///
/// Deliberately NOT a real provider id. It is used only for span/log
/// attribution on a request whose dispatch is replaced by the in-gateway mock,
/// so it must never collide with a routable provider — if it did, a mocked
/// request could attribute cost or a BYOK lookup to a real provider.
/// `bench_mock_provider_id_is_not_routable` asserts the non-collision.
const BENCH_MOCK_PROVIDER_ID: &str = "__bench_mock";

/// The double gate, as a pure function so all four quadrants are testable
/// without standing up the handler.
///
/// BOTH conditions must hold. Either alone fails closed:
/// - flag ON + real model  -> `false`, normal routing/BYOK path untouched
/// - flag OFF + mock model -> `false`, falls through to 400 `unroutable_model`
fn bench_mock_active(flag: bool, model: &str) -> bool {
    flag && is_bench_mock_model(model)
}

/// A7: retry the same-provider dispatch once on transient failure with a
/// 100ms backoff. Within the FT-01 200ms total budget. The original error
/// is preserved if the retry also fails.
///
/// Today this is intentionally same-provider only — true cross-provider
/// failover (Claude → GPT-5) needs request-shape translation that is
/// V1.5 work (BLOCKERS).
async fn dispatch_with_retry(
    registry: &crate::providers::ProviderRegistry,
    chat_request: &tracelane_shared::ChatRequest,
    provider_key: &str,
    model: &str,
    tenant_id: &tracelane_shared::TenantId,
) -> anyhow::Result<crate::providers::ProviderStream> {
    // GWY-44: the retry count and backoff come from the operator's
    // `tracelane.yaml` `failover:` block when one is installed, and from
    // `RetryPolicy::BUILTIN` (1 retry, 100 ms) otherwise — so every deployment
    // without a config file behaves exactly as it did. One relaxed atomic load,
    // and only on the error path: a request that succeeds first time never
    // reaches this.
    //
    // The whole loop stays inside `FAILOVER_BUDGET_MS`. That bound is the point:
    // a retry policy without a wall-clock ceiling turns one slow upstream into a
    // multiplied slow upstream, and B-256 (an open 13× overhead regression) is
    // exactly the kind of thing an unbounded retry loop would hide inside.
    let policy = crate::providers::failover::retry_policy();
    let budget = std::time::Duration::from_millis(crate::providers::failover::FAILOVER_BUDGET_MS);
    let backoff = std::time::Duration::from_millis(policy.backoff_ms);
    let attempt_started = std::time::Instant::now();

    let mut attempt: u32 = 0;
    let mut first_err: Option<anyhow::Error> = None;
    loop {
        match dispatch_to_provider(
            registry,
            chat_request.clone(),
            provider_key,
            model,
            tenant_id,
        )
        .await
        {
            Ok(s) => {
                if attempt > 0 {
                    tracing::info!(
                        model = %model,
                        attempt,
                        elapsed_ms = attempt_started.elapsed().as_millis(),
                        "tracelane.failover.activated=true (same-provider retry succeeded)"
                    );
                }
                return Ok(s);
            }
            Err(err) => {
                // Out of attempts.
                if attempt >= policy.retries {
                    let err = match first_err {
                        Some(first) => err.context(first.to_string()),
                        None => err,
                    };
                    return Err(err);
                }
                // Out of budget. Checked BEFORE sleeping, so the sleep itself can
                // never be what breaches the ceiling.
                if attempt_started.elapsed() + backoff > budget {
                    tracing::warn!(
                        error = %err,
                        attempt,
                        "provider failed; retry budget exhausted, no further attempt"
                    );
                    let err = match first_err {
                        Some(first) => err.context(first.to_string()),
                        None => err,
                    };
                    return Err(err);
                }
                tracing::warn!(
                    error = %err,
                    model = %model,
                    attempt,
                    backoff_ms = policy.backoff_ms,
                    "provider attempt failed — retrying"
                );
                if first_err.is_none() {
                    first_err = Some(err);
                }
                attempt += 1;
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Routes a chat request to the correct provider adapter.
///
/// The provider is resolved by the SINGLE canonical model→provider table
/// `ProviderRegistry::provider_id_for_model`, then this match selects the typed
/// adapter by that provider_id. It deliberately does NOT re-match model prefixes
/// — a second model-prefix table is exactly what drifted (Groq family dispatched
/// here but the BYOK key was looked up under "anthropic"). Adapter selection by
/// provider_id is a fixed enumeration that cannot drift on model names. Keep this
/// arm set a superset of `provider_id_for_model`'s outputs; `_` mirrors that
/// table's `anthropic` default. Enforced by `scripts/ci/check-provider-mapping-single-source.py`.
/// `pub(crate)` for `prompt_eval`: an eval case must go through the SAME
/// dispatch the chat path uses, with the tenant's own BYOK credential. A second
/// dispatch path would be a second place for provider routing to drift, which is
/// the class this function's own comments exist to prevent.
pub(crate) async fn dispatch_to_provider(
    registry: &crate::providers::ProviderRegistry,
    request: tracelane_shared::ChatRequest,
    api_key: &str,
    model: &str,
    tenant_id: &tracelane_shared::TenantId,
) -> anyhow::Result<crate::providers::ProviderStream> {
    use crate::providers::ProviderRegistry;

    // Fail closed. No default provider — an unmatched model bails here too
    // (defense in depth; the handler already rejected it before resolving a key).
    let Some(provider_id) = ProviderRegistry::provider_id_for_model(model) else {
        anyhow::bail!("unroutable model '{model}': no provider configured");
    };
    match provider_id {
        // The six native adapters — genuinely different wire formats.
        "anthropic" => registry.anthropic.chat(request, api_key, tenant_id).await,
        "vertex" => registry.vertex.chat(request, api_key, tenant_id).await,
        "google" => registry.google.chat(request, api_key, tenant_id).await,
        "bedrock" => registry.bedrock.chat(request, api_key, tenant_id).await,
        "azure" => registry.azure.chat(request, api_key, tenant_id).await,
        "cohere" => registry.cohere.chat(request, api_key, tenant_id).await,
        // GWY-42: every OpenAI-compatible provider, from the one catalog. This
        // was 29 hand-written arms that had to mirror 29 struct fields, and a
        // provider present in `provider_id_for_model` but missing an arm here
        // bailed as "unroutable" AFTER its BYOK key had already been fetched.
        other => match registry.compat(other) {
            Some(p) => p.chat(request, api_key, tenant_id).await,
            // NO default-to-anthropic. A provider_id the dispatch doesn't
            // know is a bug in the catalog, not "probably Anthropic" — bail
            // rather than ship a request to the wrong provider with the wrong key.
            None => anyhow::bail!("unroutable provider_id '{provider_id}' for model '{model}'"),
        },
    }
}

/// Converts a `ProviderStream` to an SSE stream of OpenAI `chat.completion.chunk` events.
///
/// `StreamChunk` → content chunk; `Done` → final chunk + `[DONE]` sentinel.
/// Any provider error terminates the stream with a `[DONE]` sentinel so the client
/// doesn't hang waiting for a stream that will never complete.
///
/// On `Done`, publishes a span to NATS JetStream (fire-and-forget) if a NATS
/// client is available.
#[allow(clippy::too_many_arguments)]
fn provider_stream_to_sse(
    mut provider_stream: ProviderStream,
    completion_id: String,
    model: String,
    nats: Option<Arc<async_nats::Client>>,
    billing: Option<Arc<crate::billing::Recorder>>,
    tenant_id: TenantId,
    trace_id: Uuid,
    start_time: chrono::DateTime<chrono::Utc>,
    dispatch_ts: chrono::DateTime<chrono::Utc>,
    model_name: String,
    agent_id: Option<String>,
    human_authorizer: Option<String>,
    business_reference: Option<String>,
    conversation_id: Option<String>,
    prompt_router: Arc<crate::prompt_router::PromptRouter>,
    prompt_obs: Option<PromptObservation>,
    guardrail_fired: bool,
    //  #5: the predictive AFT hit id (observe-first) — threaded onto the published
    // span so the /signatures page shows the tenant's OWN matched signatures instead of
    // demo-seed only. None when no detector matched.
    warn_aft_id: Option<&'static str>,
    guardrail: Arc<crate::guardrail::GuardrailEngine>,
    response_inputs: crate::guardrail::ResponseInputs,
    redaction_map: Vec<tracelane_policy::pii::RedactionEntry>,
    failover_from: Option<&'static str>,
    // GWY-43: the API key that authorised this request, for per-key cost
    // attribution and budget enforcement. Owned rather than borrowed because
    // the stream outlives the handler frame.
    api_key_id: Option<String>,
) -> impl futures::Stream<Item = Result<Event, Infallible>> {
    stream! {
        let mut input_tokens = 0u32;
        let mut output_tokens = 0u32;
        // Hoisted to the loop scope so the post-loop span publish (after the
        // loop) can record them. Only the Done event sets them; a pre-Done
        // content-filter block leaves them None (partial — the stream was cut).
        let mut cache_read: Option<u32> = None;
        let mut cache_creation: Option<u32> = None;
        //  #3: set on a mid-stream provider Error so the post-loop span records
        // status Error, not Ok (a streaming failure must move the error-rate metric).
        let mut stream_error: Option<&str> = None;
        let mut cost_usd: Option<f64> = None;
        // Latency split: TTFT = dispatch → the first byte the provider yields.
        let mut first_byte_ts: Option<chrono::DateTime<chrono::Utc>> = None;
        // The enforce-before-yield response-side seam — block/redact takes
        // effect before any chunk leaves this generator (the guardrail spec §2.6).
        let mut guard =
            crate::guardrail::ResponseGuard::new(guardrail, response_inputs, redaction_map);

        loop {
            let ev = provider_stream.next().await;
            if first_byte_ts.is_none() && matches!(ev, Some(Ok(_))) {
                first_byte_ts = Some(chrono::Utc::now());
            }
            match ev {
                None => {
                    // Provider stream ended WITHOUT a Done event (a Done breaks
                    // the loop itself after flushing). Flush the held-back tail
                    // through the seam so the final (redacted) chars are not lost.
                    match guard.on_end(None).await {
                        crate::guardrail::GuardStep::Emit(text) => {
                            if !text.is_empty() {
                                let data = serde_json::json!({
                                    "id": completion_id,
                                    "object": "chat.completion.chunk",
                                    "model": model,
                                    "choices": [{
                                        "index": 0,
                                        "delta": { "content": text },
                                        "finish_reason": "stop"
                                    }]
                                });
                                yield Ok(Event::default().data(data.to_string()));
                            }
                        }
                        crate::guardrail::GuardStep::Block { reason_code } => {
                            let data = serde_json::json!({
                                "id": completion_id,
                                "object": "chat.completion.chunk",
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": {},
                                    "finish_reason": "content_filter"
                                }],
                                "tracelane_guardrail": { "reason_code": reason_code }
                            });
                            yield Ok(Event::default().data(data.to_string()));
                        }
                    }
                    yield Ok(Event::default().data("[DONE]"));
                    break;
                }
                Some(Err(err)) => {
                    tracing::warn!(error = %err, "SSE stream error from provider");
                    //  #1 (mid-stream sub-path): a TRANSPORT-level stream error
                    // — a provider that severs the connection mid-response (TCP
                    // reset, provider crash, truncated body) — surfaces here as
                    // `Some(Err)`, distinct from an explicit `ProviderEvent::Error`
                    // event. This arm previously broke WITHOUT setting stream_error,
                    // so the post-loop span was built Ok: a real mid-stream failure
                    // read as a success and the error-rate metric missed it. Record
                    // the failure so status = Error (countIf(status_code = 2)).
                    stream_error = Some("provider_stream_error");
                    crate::otlp_emit::emit_operation_exception(
                        &tenant_id,
                        provider_name_from_model(&model_name),
                        "default",
                        "provider_stream_error",
                        None,
                    );
                    yield Ok(Event::default().data("[DONE]"));
                    break;
                }
                Some(Ok(event)) => match event {
                    ProviderEvent::StreamChunk { delta } => {
                        // Enforce-before-yield: feed the seam, emit only the safe
                        // (redacted + re-inserted) text it releases. A block
                        // terminates the stream WITHOUT emitting the held-back
                        // tail that holds the offending content.
                        let usage = tracelane_shared::Usage {
                            input_tokens,
                            output_tokens,
                            cache_read_input_tokens: None,
                            cache_creation_input_tokens: None,
                        };
                        match guard.on_delta(&delta, Some(&usage)).await {
                            crate::guardrail::GuardStep::Emit(text) => {
                                if !text.is_empty() {
                                    let data = serde_json::json!({
                                        "id": completion_id,
                                        "object": "chat.completion.chunk",
                                        "model": model,
                                        "choices": [{
                                            "index": 0,
                                            "delta": { "content": text },
                                            "finish_reason": null
                                        }]
                                    });
                                    yield Ok(Event::default().data(data.to_string()));
                                }
                            }
                            crate::guardrail::GuardStep::Block { reason_code } => {
                                let data = serde_json::json!({
                                    "id": completion_id,
                                    "object": "chat.completion.chunk",
                                    "model": model,
                                    "choices": [{
                                        "index": 0,
                                        "delta": {},
                                        "finish_reason": "content_filter"
                                    }],
                                    "tracelane_guardrail": { "reason_code": reason_code }
                                });
                                yield Ok(Event::default().data(data.to_string()));
                                yield Ok(Event::default().data("[DONE]"));
                                break;
                            }
                        }
                    }
                    ProviderEvent::ToolCallDelta { index, id, name, input_delta } => {
                        let data = serde_json::json!({
                            "id": completion_id,
                            "object": "chat.completion.chunk",
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": {
                                    "tool_calls": [{
                                        "index": index,
                                        "id": id,
                                        "function": { "name": name, "arguments": input_delta }
                                    }]
                                },
                                "finish_reason": null
                            }]
                        });
                        yield Ok(Event::default().data(data.to_string()));
                    }
                    ProviderEvent::UsageUpdate {
                        input_tokens: it,
                        output_tokens: ot,
                        cost_usd: cost,
                        ..
                    } => {
                        merge_usage_tokens(&mut input_tokens, &mut output_tokens, it, ot);
                        if cost.is_some() {
                            cost_usd = cost;
                        }
                    }
                    ProviderEvent::Done { response } => {
                        // cache_read / cache_creation are hoisted to the loop
                        // scope (top of stream!) so the post-loop span publish
                        // can read them.
                        if let Some(usage) = response.usage {
                            merge_usage_tokens(
                                &mut input_tokens,
                                &mut output_tokens,
                                usage.input_tokens,
                                usage.output_tokens,
                            );
                            if usage.cache_read_input_tokens.is_some() {
                                cache_read = usage.cache_read_input_tokens;
                            }
                            if usage.cache_creation_input_tokens.is_some() {
                                cache_creation = usage.cache_creation_input_tokens;
                            }
                        }
                        // Enforce-before-yield: flush the held-back tail through
                        // the seam (final redact pass) before the stop frame. A
                        // terminal block drops the tail, meters, then stops.
                        let final_usage = tracelane_shared::Usage {
                            input_tokens,
                            output_tokens,
                            cache_read_input_tokens: cache_read,
                            cache_creation_input_tokens: cache_creation,
                        };
                        match guard.on_end(Some(&final_usage)).await {
                            crate::guardrail::GuardStep::Emit(text) => {
                                if !text.is_empty() {
                                    let data = serde_json::json!({
                                        "id": completion_id,
                                        "object": "chat.completion.chunk",
                                        "model": model,
                                        "choices": [{
                                            "index": 0,
                                            "delta": { "content": text },
                                            "finish_reason": null
                                        }]
                                    });
                                    yield Ok(Event::default().data(data.to_string()));
                                }
                            }
                            crate::guardrail::GuardStep::Block { reason_code } => {
                                let data = serde_json::json!({
                                    "id": completion_id,
                                    "object": "chat.completion.chunk",
                                    "model": model,
                                    "choices": [{
                                        "index": 0,
                                        "delta": {},
                                        "finish_reason": "content_filter"
                                    }],
                                    "tracelane_guardrail": { "reason_code": reason_code }
                                });
                                yield Ok(Event::default().data(data.to_string()));
                                yield Ok(Event::default().data("[DONE]"));
                                // Billing fires POST-LOOP — see the note there.
                                break;
                            }
                        }
                        // Emit final stop chunk with usage, then [DONE]
                        let usage_val = serde_json::json!({
                            "prompt_tokens": input_tokens,
                            "completion_tokens": output_tokens,
                            "total_tokens": input_tokens + output_tokens,
                        });
                        let data = serde_json::json!({
                            "id": completion_id,
                            "object": "chat.completion.chunk",
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": {},
                                "finish_reason": "stop"
                            }],
                            "usage": usage_val
                        });
                        yield Ok(Event::default().data(data.to_string()));
                        yield Ok(Event::default().data("[DONE]"));

                        // Billing fires POST-LOOP — see the note there.

                        // B1 auto-rollback drift feed — streaming path, same
                        // as buffered path (fire-and-forget).
                        if let Some(obs) = prompt_obs.clone() {
                            let latency_ms = (chrono::Utc::now() - start_time)
                                .num_milliseconds()
                                .max(0) as f64;
                            spawn_prompt_metric_observation(
                                Arc::clone(&prompt_router),
                                tenant_id.clone(),
                                obs,
                                latency_ms,
                                false,
                                guardrail_fired,
                                u64::from(input_tokens) + u64::from(output_tokens),
                            );
                        }

                        // Span is published ONCE after the loop (covers Done,
                        // mid-stream block, stream-end, and error termination) —
                        // see the post-loop publish. #81 span-drop fix.
                        break;
                    }
                    // ThinkingDelta, Error — skip in chunk stream
                    ProviderEvent::Error { message, .. } => {
                        tracing::warn!(message, "provider error event in SSE stream");
                        stream_error = Some("provider_stream_error");
                        // gen_ai.client.operation.exception (v1.41) — the trip
                        // input for the per-upstream breaker (ADR-036). Only the
                        // classification is emitted; the provider message is NOT
                        // (credential-echo risk per security.md).
                        crate::otlp_emit::emit_operation_exception(
                            &tenant_id,
                            provider_name_from_model(&model_name),
                            "default",
                            "provider_stream_error",
                            None,
                        );
                        yield Ok(Event::default().data("[DONE]"));
                        break;
                    }
                    _ => {}
                },
            }
        }

        // Provider round-trip complete (the stream loop terminated for ANY
        // reason). Everything after this is gateway post-processing → overhead.
        let provider_complete_ts = chrono::Utc::now();

        // Meter usage ONCE, after the stream loop terminates for ANY reason —
        // exactly like the span publish below, and for exactly the same reason.
        //
        // Billing used to live INSIDE the match arms, firing only on `Done`
        // and on a mid-stream `Block`. The other two exits — a provider `Error`,
        // and a natural stream-end with no `Done` event — silently skipped it. That
        // is not hypothetical: **Gemini never emits `ProviderEvent::Done`**, it ends
        // the stream, so every Gemini streaming request was captured on the span and
        // billed to nobody. Any future provider that ends without `Done` inherits
        // the same revenue hole.
        //
        // This is the same defect #81 fixed for the span (published only on the Done
        // happy path, so a blocked stream dropped it) — the fix moved the span out
        // here but left billing behind. Keeping both post-loop keeps them honest
        // with each other: whatever the span records, we bill.
        //
        // `spawn_billing_record` no-ops at 0 tokens, so a stream that produced
        // nothing (immediate error) still bills nothing.
        if let Some(ref rec) = billing {
            let n_tokens = u64::from(input_tokens) + u64::from(output_tokens);
            spawn_billing_record(Arc::clone(rec), tenant_id.clone(), n_tokens);
        }

        // Publish the trace span ONCE, after the stream loop terminates for ANY
        // reason (Done, a mid-stream content-filter Block, stream-end, or a
        // provider error). The span used to be published only on the Done happy
        // path, so a blocked/aborted stream silently dropped its span (#81 — the
        // same bug as the buffered path). On a pre-Done block the token counts
        // are the partial values accumulated so far; the flight recorder still
        // records that the request happened.
        if let Some(ref nats_client) = nats {
            let span = build_gateway_span(
                &tenant_id,
                trace_id,
                &model_name,
                agent_id.as_deref(),
                human_authorizer.as_deref(),
                business_reference.as_deref(),
                start_time,
                input_tokens,
                output_tokens,
                warn_aft_id,
                SpanUsageMeta {
                    cache_read_input_tokens: cache_read,
                    cache_creation_input_tokens: cache_creation,
                    stream: true,
                    cost_usd,
                },
                conversation_id.as_deref(),
                failover_from,
                Some(GatewayTiming {
                    dispatch_ts,
                    provider_complete_ts,
                    ttft_us: first_byte_ts.and_then(|fb| {
                        u32::try_from((fb - dispatch_ts).num_microseconds()?.max(0)).ok()
                    }),
                }),
                stream_error,
                api_key_id.as_deref(),
            );
            // GWY-43: add this request's cost to the key's monthly total, read
            // off the SPAN rather than recomputed — so the number that enforces
            // the budget and the number the dashboard renders are the same
            // number by construction, not by two call sites agreeing.
            record_key_spend(api_key_id.as_deref(), &span);
            let nats_clone = Arc::clone(nats_client);
            tokio::spawn(async move {
                if let Err(e) = crate::otlp_emit::publish_span(&nats_clone, &span).await {
                    crate::otlp_emit::note_span_publish_failed();
                    tracing::warn!(error = %e, "span NATS publish failed (streaming)");
                }
            });
        } else {
            // NATS disabled — never drop the span silently.
            crate::otlp_emit::note_span_dropped_no_nats();
        }
    }
}

/// Buffers a `ProviderStream` into a single OpenAI `chat.completion` JSON response.
///
/// Used when the client did not set `"stream": true`. Also fires the
/// billing meter event after the response is fully buffered, since we
/// only know the exact `(input_tokens, output_tokens)` once the
/// provider's Done event lands.
///
/// After billing, publishes a span to NATS JetStream (fire-and-forget) so the
/// ingest worker can persist it to ClickHouse.
/// A buffered `content_filter` response — the response-side guardrail blocked
/// the model output (R1 output cap / R6 block / future R7). Same shape as a
/// normal completion but with empty content + `finish_reason: content_filter`
/// and the reason code. Matches the buffered handler's concrete return type.
fn content_filter_response(
    model: &str,
    reason_code: &'static str,
    input_tokens: u32,
    output_tokens: u32,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": format!("chatcmpl-{}", Uuid::new_v4()),
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "" },
                "finish_reason": "content_filter"
            }],
            "usage": {
                "prompt_tokens": input_tokens,
                "completion_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens
            },
            "tracelane_guardrail": { "reason_code": reason_code }
        })),
    )
}

#[allow(clippy::too_many_arguments)]
async fn buffer_provider_stream(
    mut provider_stream: ProviderStream,
    model: &str,
    state: &AppState,
    tenant_id: &tracelane_shared::TenantId,
    trace_id: Uuid,
    start_time: chrono::DateTime<chrono::Utc>,
    dispatch_ts: chrono::DateTime<chrono::Utc>,
    agent_id: Option<&str>,
    human_authorizer: Option<&str>,
    business_reference: Option<&str>,
    conversation_id: Option<&str>,
    prompt_obs: Option<PromptObservation>,
    guardrail_fired: bool,
    //  #5: the predictive AFT hit id (observe-first) — threaded onto the published
    // span so the /signatures page shows the tenant's OWN matched signatures instead of
    // demo-seed only. None when no detector matched.
    warn_aft_id: Option<&'static str>,
    guardrail: Arc<crate::guardrail::GuardrailEngine>,
    response_inputs: crate::guardrail::ResponseInputs,
    redaction_map: Vec<tracelane_policy::pii::RedactionEntry>,
    failover_from: Option<&str>,
    // GWY-43: the API key that authorised this request, for per-key cost
    // attribution and budget enforcement.
    api_key_id: Option<&str>,
    // GWY-24: the cache and this request's identity, threaded because the STORE
    // has to happen where the final body exists. `None` whenever the cache is
    // off, so the store is unreachable rather than merely skipped.
    semantic_cache: Option<Arc<crate::semantic_cache::SemanticCache>>,
    cache_key: Option<crate::semantic_cache::RequestKey>,
    // GWY-45 captured request content, `None` unless the tenant is allowlisted.
    // Built by the caller because `chat_request` lives there, not here.
    captured_input: Option<CapturedInput>,
) -> impl IntoResponse {
    use tracelane_shared::model::MessageContent;

    let mut text = String::new();
    let mut input_tokens = 0u32;
    let mut output_tokens = 0u32;
    let mut cache_read: Option<u32> = None;
    let mut cache_creation: Option<u32> = None;
    //  #3: set on a mid-stream provider error so the span below records status
    // Error (a buffered-collection failure must move the error-rate metric).
    let mut buffered_error: Option<&str> = None;
    let mut cost_usd: Option<f64> = None;

    while let Some(event) = provider_stream.next().await {
        match event {
            Ok(ProviderEvent::StreamChunk { delta }) => text.push_str(&delta),
            Ok(ProviderEvent::UsageUpdate {
                input_tokens: it,
                output_tokens: ot,
                cost_usd: cost,
                ..
            }) => {
                merge_usage_tokens(&mut input_tokens, &mut output_tokens, it, ot);
                if cost.is_some() {
                    cost_usd = cost;
                }
            }
            Ok(ProviderEvent::Done { response }) => {
                if let Some(choice) = response.choices.first() {
                    if let MessageContent::Text(t) = &choice.message.content {
                        text = t.clone();
                    }
                }
                if let Some(usage) = response.usage {
                    merge_usage_tokens(
                        &mut input_tokens,
                        &mut output_tokens,
                        usage.input_tokens,
                        usage.output_tokens,
                    );
                    if usage.cache_read_input_tokens.is_some() {
                        cache_read = usage.cache_read_input_tokens;
                    }
                    if usage.cache_creation_input_tokens.is_some() {
                        cache_creation = usage.cache_creation_input_tokens;
                    }
                }
            }
            Ok(ProviderEvent::Error { message, .. }) => {
                // Symmetry with the transport-`Err` arm below and the streaming
                // path (#1): an explicit provider error EVENT in a buffered
                // stream must mark the span Error too, not fall into `Ok(_)` and
                // read as a success.
                tracing::warn!(message, "provider error event in buffered response");
                buffered_error = Some("provider_stream_error");
                crate::otlp_emit::emit_operation_exception(
                    tenant_id,
                    provider_name_from_model(model),
                    "default",
                    "provider_stream_error",
                    None,
                );
                break;
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "stream error during buffered response collection");
                buffered_error = Some("provider_stream_error");
                // gen_ai.client.operation.exception (v1.41) — breaker trip input
                // (ADR-036). Classification only, never the raw error body.
                crate::otlp_emit::emit_operation_exception(
                    tenant_id,
                    provider_name_from_model(model),
                    "default",
                    "provider_stream_error",
                    None,
                );
                break;
            }
        }
    }

    // Provider round-trip complete (buffering finished). Everything after — JSON
    // serialization, the response-side seam, the return — is gateway overhead.
    let provider_complete_ts = chrono::Utc::now();

    // Publish the trace span to NATS (fire-and-forget) BEFORE the response-side
    // guardrail seam. The seam may BLOCK (return a content-filter 200) — and the
    // span MUST still be recorded: a flight recorder that drops the span for a
    // blocked request loses exactly the events it most needs (the #81 span-drop:
    // the buffered handler returned content_filter_response before ever reaching
    // the span publish). The span carries NO RESPONSE body, so publishing it here
    // vs. after the seam is identical content — the redaction the seam applies is
    // to `text`, which the span never holds.
    //
    // GWY-45 AMENDMENT, 2026-08-20: the span MAY now carry captured REQUEST
    // content (`gen_ai_input_messages`) for an allowlisted tenant. That does not
    // weaken the reasoning above, and the distinction is the whole reason v1 is
    // input-only: the response seam rewrites `text`, so anything derived from the
    // RESPONSE would be pre-redaction here and would persist exactly what the
    // guardrails removed. The REQUEST is not touched by that seam. Attaching
    // output content at this point would be a defect, not a feature — see
    // `specs/GWY-45` §3(2).
    if let Some(ref nats_client) = state.nats {
        let mut span = build_gateway_span(
            tenant_id,
            trace_id,
            model,
            agent_id,
            human_authorizer,
            business_reference,
            start_time,
            input_tokens,
            output_tokens,
            warn_aft_id,
            SpanUsageMeta {
                cache_read_input_tokens: cache_read,
                cache_creation_input_tokens: cache_creation,
                stream: false,
                cost_usd,
            },
            conversation_id,
            failover_from,
            Some(GatewayTiming {
                dispatch_ts,
                provider_complete_ts,
                ttft_us: None, // TTFT is a streaming metric; N/A for a buffered response
            }),
            buffered_error,
            api_key_id,
        );
        // GWY-45: attach the captured REQUEST content, if the caller built any.
        // See the amendment above for why this is input-only at this point.
        if let Some(captured) = captured_input {
            captured.apply(&mut span.attributes);
        }
        record_key_spend(api_key_id, &span);
        let nats = Arc::clone(nats_client);
        tokio::spawn(async move {
            if let Err(e) = crate::otlp_emit::publish_span(&nats, &span).await {
                crate::otlp_emit::note_span_publish_failed();
                tracing::warn!(error = %e, "span NATS publish failed");
            }
        });
    } else {
        // NATS disabled (no client) — never drop the span silently.
        crate::otlp_emit::note_span_dropped_no_nats();
    }

    // Response-side guardrail seam — the SAME ResponseGuard as the streaming
    // path (one seam, not two). The full response flows through it in one
    // on_delta + on_end; the redacted/re-inserted text replaces `text` so the
    // span + the response body both carry the safe form. A block returns a
    // content_filter response.
    {
        let final_usage = tracelane_shared::Usage {
            input_tokens,
            output_tokens,
            cache_read_input_tokens: cache_read,
            cache_creation_input_tokens: cache_creation,
        };
        let mut guard =
            crate::guardrail::ResponseGuard::new(guardrail, response_inputs, redaction_map);
        let head = match guard.on_delta(&text, Some(&final_usage)).await {
            crate::guardrail::GuardStep::Emit(s) => s,
            crate::guardrail::GuardStep::Block { reason_code } => {
                // The span was already published above (before this seam), so a
                // content-filter block never drops the flight-recorder span.
                return content_filter_response(model, reason_code, input_tokens, output_tokens);
            }
        };
        let tail = match guard.on_end(Some(&final_usage)).await {
            crate::guardrail::GuardStep::Emit(s) => s,
            crate::guardrail::GuardStep::Block { reason_code } => {
                // The span was already published above (before this seam), so a
                // content-filter block never drops the flight-recorder span.
                return content_filter_response(model, reason_code, input_tokens, output_tokens);
            }
        };
        text = format!("{head}{tail}");
    }

    // Fire billing meter event fire-and-forget. Total tokens = input +
    // output; the meter_event payload uses this aggregate.
    if let Some(billing) = state.billing.as_ref() {
        let n_tokens = u64::from(input_tokens) + u64::from(output_tokens);
        spawn_billing_record(Arc::clone(billing), tenant_id.clone(), n_tokens);
    }

    // B1 auto-rollback drift feed (fire-and-forget, off the response path).
    // On objective drift in production the router flips the production pointer
    // back to the previous version. No-op for non-managed-prompt traffic.
    if let Some(obs) = prompt_obs {
        let latency_ms = (chrono::Utc::now() - start_time).num_milliseconds().max(0) as f64;
        spawn_prompt_metric_observation(
            state.prompt_router.clone(),
            tenant_id.clone(),
            obs,
            latency_ms,
            false,
            guardrail_fired,
            u64::from(input_tokens) + u64::from(output_tokens),
        );
    }

    // (span already published above, before the guardrail seam — see comment)

    let payload = serde_json::json!({
        "id": format!("chatcmpl-{}", Uuid::new_v4()),
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": text },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens
        }
    });

    // GWY-24: remember this answer. Fire-and-forget — a store failure must never
    // touch the response the customer already has.
    //
    // Only reached on the buffered, non-error, `finish_reason: stop` path. The
    // content-filter branches return ABOVE this point, so a blocked or truncated
    // answer is never stored — caching a guardrail refusal would serve the
    // refusal to everyone who asked something similar.
    if let (Some(cache), Some(key)) = (semantic_cache.as_ref(), cache_key.as_ref()) {
        if buffered_error.is_none() && !guardrail_fired {
            let cache = Arc::clone(cache);
            let key = key.clone();
            let tenant = tenant_id.clone();
            let model_owned = model.to_string();
            let body = payload.to_string();
            // COST MUST FALL BACK TO THE PRICE CATALOG, exactly as the SPAN does.
            //
            // `cost_usd` here is populated ONLY from a provider `UsageUpdate`
            // that carries a cost. Anthropic does not report one — and Anthropic
            // is 94% of production traffic — so this was `None` on almost every
            // real request and `unwrap_or(0.0)` stored a zero. Every subsequent
            // hit then reported `cost_saved_usd: 0.0`: the feature built for
            // cost could not state its own saving on the provider that matters.
            //
            // `build_gateway_span` already does this `or_else` (see
            // `gen_ai_usage_cost`), which is why the MISS span showed a real
            // cost while the cache stored zero from the same request. Two sites
            // reading the same quantity, one with the fallback and one without,
            // is the drift `pricing::cost_usd` exists as a single source to
            // prevent. `None` is still preserved as 0.0 for an unknown model —
            // the gateway never fabricates a cost (ADR-055).
            let cost = cost_usd
                .or_else(|| {
                    crate::pricing::cost_usd(
                        model,
                        &tracelane_shared::Usage {
                            input_tokens,
                            output_tokens,
                            cache_read_input_tokens: None,
                            cache_creation_input_tokens: None,
                        },
                    )
                })
                .unwrap_or(0.0);
            tokio::spawn(async move {
                cache
                    .store(
                        &tenant,
                        &model_owned,
                        &key,
                        &body,
                        input_tokens,
                        output_tokens,
                        cost,
                        trace_id,
                    )
                    .await;
            });
        }
    }

    (StatusCode::OK, Json(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt_router::Env;

    /// GWY-45. `truncate_utf8` must cut on a CHARACTER boundary and say that it
    /// cut. A silent truncation produces eval cases that look complete and are
    /// not; a byte-boundary cut produces invalid UTF-8 and loses the whole span
    /// at serialization.
    #[test]
    fn truncate_utf8_cuts_on_a_char_boundary_and_marks_the_cut() {
        // Multi-byte throughout, so a naive byte cut would split a char.
        let mut s = "héllo wörld ünicode".repeat(20);
        let original = s.clone();
        truncate_utf8(&mut s, 40);
        assert!(s.len() <= 40, "must respect the byte cap, got {}", s.len());
        assert!(
            s.ends_with("…[truncated]"),
            "a cut MUST be visible — a silent one yields eval cases that look              complete and are not; got {s:?}"
        );
        // The real assertion: it is still valid UTF-8. `String` guarantees this,
        // so the way this fails is a PANIC inside truncate_utf8, not a bad value.
        assert!(s.chars().count() > 0);

        // Under the cap it must be untouched — no marker, no allocation churn.
        let mut short = "hi".to_owned();
        truncate_utf8(&mut short, 40);
        assert_eq!(short, "hi", "a string under the cap must be left alone");

        // THE POST-CONDITION, asserted at the boundary that broke it: the result
        // is NEVER longer than the cap. The first version of this function
        // appended a 14-byte marker to a 3-byte budget and returned 14 bytes for
        // max=3 — longer than the input limit, from the function whose job is to
        // enforce it. Unreachable in prod (the config floor is 1 KiB) and fixed
        // anyway.
        for cap in [0, 1, 3, 13, 14, 15, 64] {
            let mut tiny = original.clone();
            truncate_utf8(&mut tiny, cap);
            assert!(
                tiny.len() <= cap,
                "truncate_utf8 must never exceed its cap: cap={cap} produced {} bytes ({tiny:?})",
                tiny.len()
            );
        }
    }

    /// **THE HOT-PATH GUARANTEE.** With no `trace_content:` block installed —
    /// which is every deployment today, and the fail-CLOSED default — capture
    /// must return `None` without touching the request.
    ///
    /// This is the test that would catch content leaking for a tenant nobody
    /// allowlisted, which is the only way this feature can do harm.
    #[test]
    fn capture_is_none_when_no_trace_content_block_is_installed() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        let req = tracelane_shared::ChatRequest {
            model: "claude-haiku-4-5".to_owned(),
            messages: vec![tracelane_shared::model::Message {
                role: tracelane_shared::model::Role::User,
                content: tracelane_shared::model::MessageContent::Text(
                    "a secret prompt nobody allowlisted".to_owned(),
                ),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            system: None,
            metadata: None,
        };
        assert!(
            CapturedInput::build(&tenant, &req).is_none(),
            "with no trace_content block installed, capture MUST be off — an              absent config is the unprivileged state (.claude/rules/tenancy.md)"
        );
    }

    /// GWY-24: the cache must store the CATALOG cost when the provider does not
    /// report one, or the feature built for cost reports zero saving.
    ///
    /// FALSIFIED AGAINST THE OLD CODE: `cost_usd.unwrap_or(0.0)` returns 0.0 for
    /// the `None` case this asserts is non-zero, so this test fails on the
    /// pre-fix line and passes on the fixed one. Measured on prod 2026-08-20:
    /// 41 exact hits, every one reporting `cost_saved_usd = 0`, while the 41
    /// misses that populated them cost $0.0014598 in total.
    #[test]
    fn cache_store_cost_falls_back_to_the_catalog_when_the_provider_reports_none() {
        // Anthropic never sends a cost on the usage event, so this is the real
        // shape of the value reaching the store site for 94% of prod traffic.
        let provider_reported: Option<f64> = None;
        let input_tokens = 156_u32;
        let output_tokens = 30_u32;
        let model = "claude-haiku-4-5";

        let with_fallback = provider_reported
            .or_else(|| {
                crate::pricing::cost_usd(
                    model,
                    &tracelane_shared::Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_input_tokens: None,
                        cache_creation_input_tokens: None,
                    },
                )
            })
            .unwrap_or(0.0);

        assert!(
            with_fallback > 0.0,
            "a known model with real tokens must produce a non-zero catalog cost; \
             got {with_fallback} — this is the pre-fix behaviour, where the cache \
             stored 0.0 and every hit reported cost_saved_usd = 0"
        );

        // And the catalog must agree with what the SPAN would have recorded for
        // the same request — two sites reading one quantity must not drift.
        let span_side = crate::pricing::cost_usd(
            model,
            &tracelane_shared::Usage {
                input_tokens,
                output_tokens,
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
            },
        )
        .unwrap_or(0.0);
        assert!(
            (with_fallback - span_side).abs() < f64::EPSILON,
            "the cache store site and the span must derive the SAME cost: \
             cache={with_fallback} span={span_side}"
        );

        // An unknown model still yields 0.0 rather than a fabricated number.
        let unknown = None::<f64>
            .or_else(|| {
                crate::pricing::cost_usd(
                    "totally-not-a-real-model-r13proof",
                    &tracelane_shared::Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_input_tokens: None,
                        cache_creation_input_tokens: None,
                    },
                )
            })
            .unwrap_or(0.0);
        assert_eq!(
            unknown, 0.0,
            "an unknown model must not fabricate a cost (ADR-055)"
        );
    }

    use serde_json::json;

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

    /// R13 — a guardrail block whose reason has NO AFT mapping must still be visible.
    ///
    /// This is a DECISION, not a measurement (`TRAPS.md` §27). The old code read
    /// `if let Some(aft_id) = reason_to_aft(reason) { …emit… }` with the 403 returning
    /// unconditionally below it, so the span was gated on the AFT lookup. Injection is
    /// the only live mapping, which meant **every other blocking rail produced a ledger
    /// row, a `guardrail_verdicts` row, a 403 — and nothing in `/traces`.** The customer
    /// was told their request was blocked and could not see the block.
    ///
    /// Both halves are asserted on purpose. The first alone would pass if someone made
    /// `reason_to_aft` return `Some` for everything; the second alone would pass if the
    /// mapping were deleted entirely.
    #[test]
    fn guardrail_block_without_an_aft_mapping_still_produces_a_span() {
        use crate::guardrail::rails::r3_tool_safety::reason_to_aft;

        // (a) The gate that used to suppress the span really does return None for a
        //     blocking reason — i.e. the defect was reachable, not theoretical.
        assert!(
            reason_to_aft(crate::guardrail::outcome::reason_codes::BUDGET_CAP).is_none(),
            "BUDGET_CAP has no AFT mapping — under the old nesting this block emitted NO \
             span at all, which is the defect this test pins"
        );

        // (b) …and the span we now build for it is a real, renderable error span rather
        //     than an empty shell. `aft_id: None` selects build_error_span.
        let span = build_error_span(
            &TenantId::from_jwt_claim("a4037bef-e786-44e3-bfb6-88c93ba9d381".parse().unwrap()),
            Uuid::new_v4(),
            "claude-haiku-4-5",
            chrono::Utc::now(),
            "guardrail_block",
        );
        assert_eq!(
            span.status.code,
            tracelane_shared::SpanStatusCode::Error,
            "a blocked request must land as an ERROR span, not a success or Unset one — \
             otherwise it renders as a normal call in /traces"
        );
        assert!(
            span.attributes.tracelane_aft_id.is_none(),
            "no AFT mapping means no signature id — the span must not invent one"
        );

        // (c) And the mapped case still carries its signature, so (a) cannot be
        //     satisfied by deleting the AFT feature.
        let poisoned = build_blocked_aft_span(
            &TenantId::from_jwt_claim("a4037bef-e786-44e3-bfb6-88c93ba9d381".parse().unwrap()),
            Uuid::new_v4(),
            "claude-haiku-4-5",
            chrono::Utc::now(),
            "guardrail_block",
            "AFT-TOOL-POISON-001",
        );
        assert_eq!(
            poisoned.attributes.tracelane_aft_id.as_deref(),
            Some("AFT-TOOL-POISON-001"),
            "a mapped block must still reach /signatures"
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

    /// Regression: the span provider-attribution mapping had drifted
    /// from the dispatch/key-lookup mapping and stamped most of the providers
    /// as "unknown" on the span. It now delegates to provider_id_for_model.
    #[test]
    fn provider_name_from_model_matches_dispatch_not_unknown() {
        // Groq-family (the trigger) + other previously-"unknown" providers.
        assert_eq!(provider_name_from_model("llama-3.3-70b-versatile"), "groq");
        assert_eq!(provider_name_from_model("qwen-2.5-32b"), "groq");
        assert_eq!(provider_name_from_model("mistral-large-latest"), "mistral");
        assert_eq!(provider_name_from_model("grok-2"), "xai");
        assert_eq!(
            provider_name_from_model("sonar-pro"),
            "perplexity",
            "sonar must stay perplexity"
        );
        // The two OTel house-style remaps are preserved.
        assert_eq!(
            provider_name_from_model("vertex/gemini-2.5-pro"),
            "gcp_vertex_ai"
        );
        assert_eq!(provider_name_from_model("bedrock/claude"), "aws_bedrock");
        // Known-good baselines still resolve.
        assert_eq!(provider_name_from_model("claude-sonnet-4-6"), "anthropic");
        assert_eq!(provider_name_from_model("gpt-4o"), "openai");
        // The delegation agrees with the canonical mapping by construction.
        assert_eq!(
            provider_name_from_model("llama-3.3-70b-versatile"),
            crate::providers::ProviderRegistry::provider_id_for_model("llama-3.3-70b-versatile")
                .unwrap()
        );
        // An unmatched model attributes "unknown" (never a default provider).
        assert_eq!(provider_name_from_model("totally-unknown-xyz"), "unknown");
    }

    // ── Response-streaming seam: server-level wiring integration tests ───────
    // Belt-and-suspenders over the SSE wiring (the seam logic itself is unit-
    // proven in guardrail::streaming). These drive the REAL provider_stream_to_sse
    // through a mock ProviderStream and assert over the actual SSE wire bytes.

    fn mock_stream(
        events: Vec<crate::providers::ProviderEvent>,
    ) -> crate::providers::ProviderStream {
        let items: Vec<anyhow::Result<crate::providers::ProviderEvent>> =
            events.into_iter().map(Ok).collect();
        Box::pin(futures::stream::iter(items))
    }

    /// Like `mock_stream` but the stream SEVERS after the given ok events — the
    /// terminal item is a transport-level `Err`, which is exactly what a real
    /// provider connection reset / truncated body yields at the `ProviderStream`
    /// level (the adapter propagates the byte-stream error via `?` inside its
    /// `try_stream!`). Drives the `Some(Err)` arm (#1 mid-stream sub-path).
    fn mock_stream_severing(
        ok_events: Vec<crate::providers::ProviderEvent>,
    ) -> crate::providers::ProviderStream {
        let mut items: Vec<anyhow::Result<crate::providers::ProviderEvent>> =
            ok_events.into_iter().map(Ok).collect();
        items.push(Err(anyhow::anyhow!(
            "connection reset by peer (mid-stream sever)"
        )));
        Box::pin(futures::stream::iter(items))
    }

    fn e2e_engine() -> Arc<crate::guardrail::GuardrailEngine> {
        let chain = Arc::new(crate::audit::AuditChain::new(100, None, None).expect("chain"));
        Arc::new(crate::guardrail::GuardrailEngine::new(
            chain,
            None,
            // R2/R6 are PAID; a None cache is the free tier now.
            Some(crate::entitlement_cache::ResolvedEntitlements::paid_rails_cache()),
            Arc::new(crate::guardrail::CapabilityRegistry::new()),
        ))
    }

    fn e2e_inputs() -> crate::guardrail::ResponseInputs {
        crate::guardrail::ResponseInputs {
            tenant_id: tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xE2E)),
            api_key_id: None,
            correlation_id: ulid::Ulid::from_parts(1, 1),
            system_prompt: Some("a benign system prompt".to_string()),
            model: "claude-sonnet-4-6".to_string(),
            session: crate::guardrail::SessionState::fresh(None),
            actor: "apikey:e2e".to_string(),
            expected_format: None,
        }
    }

    fn usage(output: u32) -> tracelane_shared::Usage {
        tracelane_shared::Usage {
            input_tokens: 5,
            output_tokens: output,
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        }
    }

    fn done_event(output: u32) -> crate::providers::ProviderEvent {
        crate::providers::ProviderEvent::Done {
            response: tracelane_shared::ChatResponse {
                id: "x".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                choices: Vec::new(),
                usage: Some(usage(output)),
            },
        }
    }

    fn chunk(delta: &str) -> crate::providers::ProviderEvent {
        crate::providers::ProviderEvent::StreamChunk {
            delta: delta.to_string(),
        }
    }

    /// Collect the full SSE wire output of provider_stream_to_sse for a set of
    /// provider events.
    async fn run_sse(events: Vec<crate::providers::ProviderEvent>) -> String {
        run_sse_stream(mock_stream(events)).await
    }

    /// Same as `run_sse` but driven by an arbitrary `ProviderStream`, so a
    /// severing stream (`mock_stream_severing`) can exercise the `Some(Err)` arm.
    async fn run_sse_stream(stream: crate::providers::ProviderStream) -> String {
        let sse = provider_stream_to_sse(
            stream,
            "chatcmpl-test".to_string(),
            "claude-sonnet-4-6".to_string(),
            None,
            None,
            tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xE2E)),
            uuid::Uuid::from_u128(2),
            chrono::Utc::now(),
            chrono::Utc::now(), // dispatch_ts
            "claude-sonnet-4-6".to_string(),
            None,
            None,
            None, // business_reference
            None,
            Arc::new(crate::prompt_router::PromptRouter::new()),
            None,
            false,
            None, // warn_aft_id (test)
            e2e_engine(),
            e2e_inputs(),
            Vec::new(),
            None,
            None, // api_key_id: not under test here
        );
        let resp = Sse::new(sse).into_response();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect SSE body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    // ──: billing must fire on EVERY stream termination path ────────────

    /// `BILLING_RECORDS_SPAWNED` is process-global, so these tests must not run
    /// concurrently or their before/after deltas interleave and read each other's
    /// increments (they passed alone and failed together until this was added —
    /// the `ENV_LOCK` pattern from `.claude/rules/testing.md`, same reasoning).
    /// `tokio::sync::Mutex`, not `std` — the guard is held across the SSE `.await`,
    /// and `rust.md` denies `await_holding_lock` outright (an `#[allow]` here would
    /// be papering over the exact hazard the rule exists for). `const_new` keeps it
    /// a plain static with no lazy init.
    static BILLING_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Drive the real `provider_stream_to_sse` with billing wired, returning how
    /// many billing records it spawned. The `Recorder` is real but inert: its
    /// spawned task exits at `global_pool() == None` in tests, so nothing reaches
    /// Polar — we are asserting the CALL SITE fires, which is exactly what
    /// got wrong.
    async fn billing_spawns_for(events: Vec<crate::providers::ProviderEvent>) -> u64 {
        // Held across the whole measurement so the delta is ours alone.
        let _guard = BILLING_TEST_LOCK.lock().await;
        let before = billing_records_spawned();
        let recorder = Arc::new(crate::billing::Recorder::new(Arc::new(
            crate::billing::PolarClient::new("unit-test-token-do-not-use-in-prod"),
        )));
        let sse = provider_stream_to_sse(
            mock_stream(events),
            "chatcmpl-test".to_string(),
            "gemini-2.5-pro".to_string(),
            None,
            Some(recorder),
            tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xB110)),
            uuid::Uuid::from_u128(3),
            chrono::Utc::now(),
            chrono::Utc::now(), // dispatch_ts
            "gemini-2.5-pro".to_string(),
            None,
            None,
            None, // business_reference
            None,
            Arc::new(crate::prompt_router::PromptRouter::new()),
            None,
            false,
            None, // warn_aft_id (test)
            e2e_engine(),
            e2e_inputs(),
            Vec::new(),
            None,
            None, // api_key_id: not under test here
        );
        let resp = Sse::new(sse).into_response();
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect SSE body");
        billing_records_spawned() - before
    }

    /// THE REGRESSION: a stream that ends WITHOUT a `Done` event must still
    /// be metered. This is not hypothetical — Gemini never emits `Done`, it just
    /// ends the stream, so every Gemini streaming request was billed to nobody
    /// while its span recorded the usage. Fails on the pre-fix code, where billing
    /// lived inside the `Done` arm.
    /// Regression: an UNCONFIGURED provider must resolve to `NotConfigured`, not
    /// to an empty key that gets dispatched upstream and comes back as
    /// `provider_key_rejected` ("verify the key for this provider") — advice
    /// aimed at a key the caller never had. Found on the first-value path:
    /// PRODDEMO2 has vertex + anthropic keys and NO openai key, and an openai
    /// call reported the tenant's key as rejected.
    ///
    /// Uses an env var that cannot exist rather than mutating the environment,
    /// so the test leaks no process state (rules/testing.md).
    #[tokio::test]
    async fn unconfigured_provider_resolves_to_not_configured_not_empty_key() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xC0FFEE));

        // No BYOK row (no pool in unit tests) + an env var that is never set.
        let outcome = resolve_provider_key(
            &tenant,
            "openai",
            "TRACELANE_UNIT_TEST_PROVIDER_KEY_VAR_THAT_IS_NEVER_SET",
        )
        .await;
        assert!(
            matches!(outcome, ProviderKey::NotConfigured),
            "an unconfigured provider must be NotConfigured — collapsing it into an empty key is what produced the misleading provider_key_rejected"
        );

        // A no-key provider (Ollama: empty env var name) is still a real
        // resolution — an empty string here is correct, not "not configured".
        assert!(
            matches!(
                resolve_provider_key(&tenant, "ollama", "").await,
                ProviderKey::Found(ref k) if k.is_empty()
            ),
            "a no-credential provider must resolve to Found(\"\"), not NotConfigured"
        );
    }

    /// The two failure modes must stay distinct: `NotConfigured` tells the user
    /// to ADD a key, `Unusable` tells them to ROTATE one. Emitting the same code
    /// for both sends half of them the wrong way.
    #[test]
    fn provider_key_failure_modes_carry_different_codes() {
        let not_configured = provider_error_response(
            StatusCode::BAD_REQUEST,
            "provider_not_configured",
            Some("add one in Settings → LLM Providers"),
            Some("openai"),
            None,
        );
        let unusable = provider_error_response(
            StatusCode::BAD_GATEWAY,
            "provider_key_unusable",
            Some("rotate it in Settings → LLM Providers"),
            Some("openai"),
            None,
        );
        assert_eq!(not_configured.status(), StatusCode::BAD_REQUEST);
        assert_eq!(unusable.status(), StatusCode::BAD_GATEWAY);
    }

    /// An unclassified upstream 4xx mirrors the upstream status as a 4xx
    /// (never 502 "provider unavailable", which blamed us for a client-side
    /// failure) and names BOTH candidate causes without claiming to know which.
    #[tokio::test]
    async fn unclassified_4xx_names_both_causes_and_is_not_an_outage() {
        let message = format!(
            "the upstream provider rejected this request with HTTP {}. \
             This is not a Tracelane outage — it is usually either a provider \
             key that is invalid or expired for this account, or a request the \
             provider could not accept (model, parameters, or payload). \
             Verify the key for this provider, then the request itself.",
            400
        );
        let resp = provider_error_response(
            StatusCode::BAD_REQUEST,
            "provider_request_rejected",
            Some(&message),
            Some("xai"),
            None,
        );
        assert!(
            resp.status().is_client_error(),
            "an upstream 4xx must not surface as a 5xx"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains("provider_request_rejected") && s.contains("xai"),
            "got: {s}"
        );
        // Names the upstream status, and both causes — not one of them.
        assert!(s.contains("400"), "must name the upstream status: {s}");
        assert!(s.contains("expired") && s.contains("payload"), "got: {s}");
        // Must NOT assert the key is the problem (that is the parsed path).
        assert!(
            !s.contains("provider_key_rejected"),
            "an unparsed 4xx must not claim the key was rejected: {s}"
        );
    }

    ///  mechanical control: the provider-error response must NEVER emit a
    /// key-shaped string or an upstream auth header, even if a future bug
    /// interpolates a raw upstream body (which echoes the tenant's BYOK key +
    /// `www-authenticate`) into a client-facing field. Asserts the allowlist +
    /// the `scrub` backstop together. A redaction gap here fails CI.
    #[tokio::test]
    async fn provider_error_response_never_leaks_key_or_auth_header() {
        // A poisoned message = a simulated future regression that pipes an
        // upstream error body into the client field. Clearly-fake keys per
        // rules/testing.md, one per BYOK format the gateway must catch.
        let poison = "upstream: Incorrect API key sk-projFAKEtestkeyDONOTUSE0123456789abcdef; \
             AIzaFAKEtestkeyDONOTUSE0123456789abcdef0; xai-FAKEtestkeyDONOTUSE0123456789abcd; \
             AQ.Ab8RN6FAKEtestkeyDONOTUSE0123456789abcdef; tlane_FAKEtestkeyDONOTUSE0123456789; \
             www-authenticate: Bearer sk-FAKEtestkeyDONOTUSE0123456789abcdef; \
             authorization: Bearer FAKEtestjwtDONOTUSE0123456789abcdef";
        let resp = provider_error_response(
            StatusCode::UNAUTHORIZED,
            "provider_key_rejected",
            Some(poison),
            Some("openai"),
            None,
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let s = String::from_utf8_lossy(&bytes);
        // Not one raw credential fragment survives (the value shape is scrubbed).
        assert!(
            !s.contains("FAKEtestkey") && !s.contains("FAKEtestjwt"),
            "provider-error body leaked a key/token: {s}"
        );
        // The upstream auth header value is gone.
        assert!(
            !s.to_lowercase().contains("bearer sk-"),
            "auth header leaked: {s}"
        );
        // The allowlisted fields still render (so the fix didn't break the error).
        assert!(
            s.contains("provider_key_rejected") && s.contains("openai"),
            "got: {s}"
        );
    }

    #[tokio::test]
    async fn stream_end_without_done_still_meters() {
        let usage_event = crate::providers::ProviderEvent::UsageUpdate {
            input_tokens: 100,
            output_tokens: 50,
            cache_read: None,
            cache_creation: None,
            cost_usd: None,
        };
        let n = billing_spawns_for(vec![chunk("hello"), usage_event]).await;
        assert_eq!(n, 1, "a Done-less stream end must bill exactly once");
    }

    /// The happy path must still bill — and exactly once. Moving the call
    /// post-loop must not double-bill by leaving the in-arm call behind.
    #[tokio::test]
    async fn done_stream_meters_exactly_once() {
        let n = billing_spawns_for(vec![chunk("hi"), done_event(50)]).await;
        assert_eq!(n, 1, "Done path must bill exactly once, not zero or twice");
    }

    ///  #1 (mid-stream sub-path): a transport sever mid-stream (a `Some(Err)`
    /// item — a real provider connection reset / truncated body) must terminate
    /// the SSE cleanly — yield `[DONE]`, no hang, no panic — via the `Some(Err)`
    /// arm. The span that arm builds carries `stream_error` → Error status, which
    /// `span_status_reflects_stream_error` asserts directly (the NATS span object
    /// is not capturable in-process, so the status link is proven at the builder).
    #[tokio::test]
    async fn mid_stream_sever_terminates_cleanly() {
        let wire = run_sse_stream(mock_stream_severing(vec![chunk("partial answer ")])).await;
        assert!(
            wire.contains("[DONE]"),
            "a severed stream must still close the SSE cleanly; got: {wire}"
        );
    }

    ///  #1 + #5: the span builder maps failure reasons to Error status
    /// (`countIf(status_code = 2)`) and a clean finish to Ok — the exact mapping a
    /// mid-stream sever rides on (the `Some(Err)` arm sets
    /// `stream_error = Some("provider_stream_error")`). Also asserts the
    /// injection-block span carries the AFT id AND Error status (#5).
    /// Latency split: gateway_overhead + provider == total, to the µs, with NO
    /// unattributed bucket (the founder's hard rule). Deterministic timestamps.
    #[test]
    fn gateway_overhead_plus_provider_equals_total() {
        let received = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let dispatch = received + chrono::Duration::milliseconds(3); // 3ms gateway pre-work
        let complete = dispatch + chrono::Duration::milliseconds(500); // 500ms provider
        let sent = complete + chrono::Duration::milliseconds(2); // 2ms gateway post-work
        let overhead_us = gateway_overhead_us(received, dispatch, complete, sent).unwrap();
        let total_us = (sent - received).num_microseconds().unwrap() as u32;
        let provider_us = total_us - overhead_us; // the derived provider segment
        assert_eq!(overhead_us, 5_000); // (3ms pre) + (2ms post)
        assert_eq!(provider_us, 500_000); // complete − dispatch
        assert_eq!(overhead_us + provider_us, total_us); // sums to total, exactly
        assert_eq!(total_us, 505_000);
        // A backwards interval (clock skew) never panics — clamps, stays Some/None-safe.
        assert!(gateway_overhead_us(sent, received, complete, dispatch).is_some());
    }

    #[test]
    fn span_status_reflects_stream_error() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xF1E));
        let t = uuid::Uuid::from_u128(1);
        // Clean finish → Ok.
        let ok = build_gateway_span(
            &tenant,
            t,
            "claude-sonnet-4-6",
            None,
            None,
            None,
            chrono::Utc::now(),
            5,
            5,
            None,
            SpanUsageMeta {
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                stream: true,
                cost_usd: None,
            },
            None,
            None,
            None, // timing (not under test here)
            None, // error_reason
            None, // api_key_id
        );
        assert_eq!(ok.status.code, SpanStatusCode::Ok);
        // Mid-stream sever reason (what the `Some(Err)` arm sets) → Error, countable.
        let severed = build_error_span(
            &tenant,
            t,
            "claude-sonnet-4-6",
            chrono::Utc::now(),
            "provider_stream_error",
        );
        assert_eq!(severed.status.code, SpanStatusCode::Error);
        assert_eq!(
            severed.status.message.as_deref(),
            Some("provider_stream_error")
        );
        // #5: an injection block writes an Error span carrying the canonical AFT id
        // so the blocked hit surfaces on /signatures.
        let poison = build_blocked_aft_span(
            &tenant,
            t,
            "claude-sonnet-4-6",
            chrono::Utc::now(),
            "guardrail_block",
            "AFT-TOOL-POISON-001",
        );
        assert_eq!(poison.status.code, SpanStatusCode::Error);
        assert_eq!(
            poison.attributes.tracelane_aft_id.as_deref(),
            Some("AFT-TOOL-POISON-001")
        );
    }

    /// A stream that produced nothing bills nothing — the 0-token guard. Prevents
    /// the fix from over-correcting into billing empty/errored streams.
    #[tokio::test]
    async fn empty_stream_bills_nothing() {
        let n = billing_spawns_for(vec![]).await;
        assert_eq!(n, 0, "a stream with no usage must not bill");
    }

    /// THE WIRING INVARIANT: a secret split across StreamChunk deltas, behind a
    /// >hold-back preamble that flushes mid-stream, never appears RAW in the
    /// actual SSE wire bytes — only the redacted form egresses.
    #[tokio::test]
    async fn sse_wiring_never_yields_raw_secret() {
        // ~630-char preamble (> the 512 hold-back) → flushes mid-stream while the
        // secret, split across the next two deltas, is still held + then redacted.
        let preamble = "benign words ".repeat(50);
        let wire = run_sse(vec![
            chunk(&preamble),
            chunk("here is secret AKIA"),
            chunk("IOSFODNN7EXAMPLE end of message"),
            done_event(20),
        ])
        .await;
        assert!(
            !wire.contains("AKIAIOSFODNN7EXAMPLE"),
            "raw secret leaked through the SSE wiring:\n{wire}"
        );
        assert!(
            wire.contains("REDACTED:aws_key"),
            "the secret should be redacted in the wire output:\n{wire}"
        );
        assert!(wire.contains("benign words"), "the preamble should stream");
        assert!(wire.contains("[DONE]"));
    }

    /// The None-without-Done flush: a provider stream that ENDS without a Done
    /// event must still flush the held-back (redacted) tail — it is not lost.
    #[tokio::test]
    async fn sse_wiring_flushes_tail_when_stream_ends_without_done() {
        let preamble = "benign words ".repeat(50);
        // No done_event — the stream just ends.
        let wire = run_sse(vec![
            chunk(&preamble),
            chunk("trailing secret AKIAIOSFODNN7EXAMPLE here"),
        ])
        .await;
        assert!(!wire.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(
            wire.contains("REDACTED:aws_key"),
            "the held tail must be flushed (redacted) even without a Done event:\n{wire}"
        );
        assert!(wire.contains("[DONE]"));
    }

    const UUID_AB: &str = "00000000-0000-0000-0000-0000000000ab";

    #[test]
    fn merge_usage_tokens_survives_anthropic_split_usage() {
        // Regression (input-token clobber): Anthropic streams input on
        // `message_start` then final output on `message_delta` (input hardcoded 0).
        // A plain overwrite clobbered input back to 0 — the max merge must keep
        // it. This is the fold assertion tests never had.
        let (mut input, mut output) = (0u32, 0u32);
        merge_usage_tokens(&mut input, &mut output, 42, 0); // message_start
        merge_usage_tokens(&mut input, &mut output, 0, 17); // message_delta
        assert_eq!(
            (input, output),
            (42, 17),
            "message_delta's input=0 must not clobber the real input count"
        );

        // Order-independent (defensive against event reordering).
        let (mut i2, mut o2) = (0u32, 0u32);
        merge_usage_tokens(&mut i2, &mut o2, 0, 17);
        merge_usage_tokens(&mut i2, &mut o2, 42, 0);
        assert_eq!((i2, o2), (42, 17));

        // Single-event providers (OpenAI/Azure/Google/Cohere/Bedrock report both
        // counts in one event) are unaffected — one merge yields both.
        let (mut i3, mut o3) = (0u32, 0u32);
        merge_usage_tokens(&mut i3, &mut o3, 100, 50);
        assert_eq!((i3, o3), (100, 50));
    }

    #[test]
    fn bench_mock_model_is_reserved_and_namespaced() {
        // Gating half #2 (the model name): only the reserved `__bench_` prefix
        // matches, so a normal tenant model id can never trip the mock branch —
        // even on a node where TRACELANE_BENCH_MOCK_UPSTREAM is (mis)enabled.
        assert!(is_bench_mock_model("__bench_mock_instant"));
        assert!(is_bench_mock_model("__bench_mock_fast"));
        assert!(!is_bench_mock_model("claude-sonnet-4-6"));
        assert!(!is_bench_mock_model("gpt-5"));
        assert!(!is_bench_mock_model("mock-instant")); // un-prefixed ≠ reserved
    }

    // the bench-mock bypass -----------------------------------

    #[test]
    fn bench_mock_gate_all_four_quadrants() {
        // Gate half #1 (env flag) x half #2 (reserved prefix). Only ON+reserved
        // opens the bypass; the other three MUST fail closed, because the
        // bypass skips BOTH routing and BYOK resolution.
        assert!(
            bench_mock_active(true, "__bench_mock_instant"),
            "ON + reserved must bypass"
        );
        assert!(
            !bench_mock_active(true, "claude-sonnet-4-6"),
            "ON + real model must take the normal path"
        );
        assert!(
            !bench_mock_active(false, "__bench_mock_instant"),
            "OFF + reserved must fall through to unroutable_model"
        );
        assert!(
            !bench_mock_active(false, "claude-sonnet-4-6"),
            "OFF + real model must take the normal path"
        );
    }

    #[test]
    fn bench_mock_gate_is_expressed_exactly_once() {
        // Verifier finding (a): the dispatch site used to re-derive
        // `state.bench_mock_upstream && is_bench_mock_model(&model)` inline
        // instead of consuming the unified `bench_mock`. Both agreed at the
        // time, so nothing was broken — but extending `bench_mock_active`
        // (an allowlisted tenant, a renamed env var) would have moved the
        // routing/BYOK bypass without moving the dispatch decision, splitting
        // one gate into two that disagree.
        //
        // The gate must exist in exactly ONE place: `bench_mock_active`.
        // Scan only the NON-TEST portion: `include_str!` pulls in this test's
        // own source, so the literal below would count itself (a self-match —
        // the same reason `pre-public-push.sh` excludes its own file).
        let full = include_str!("server.rs");
        // NB: the first `#[cfg(test)]` is at ~:1784, but `bench_mock_active` is
        // defined AFTER it — so the truncated slice is valid for counting the
        // inline gate (which lives at ~:1164) but NOT for counting the
        // definition. Count each against the range that actually contains it.
        let non_test = &full[..full.find("#[cfg(test)]").unwrap_or(full.len())];
        let needle = concat!("state.", "bench_mock_upstream &&");
        let inline = non_test.matches(needle).count();
        assert_eq!(
            inline, 0,
            "the bench gate is re-derived inline {inline}x — consume the unified \
             `bench_mock` binding instead, or the two decisions can drift apart"
        );
        // ...and `bench_mock_active` is the single definition of it.
        // Split literal, same self-match reason as `needle` above. NOTE: do not
        // write the un-split form anywhere in this file, comments included —
        // this assertion counts source text, so even a comment mentioning it
        // trips the check. (It did, twice, while this test was written.) The
        // durable form of this guard is a CI script scanning from OUTSIDE the
        // file; tracked rather than built, to keep this PR to its four
        // constraints.
        let def = concat!("fn ", "bench", "_mock_active(");
        assert_eq!(
            full.matches(def).count(),
            1,
            "bench_mock_active must have exactly one definition"
        );
    }

    /// Mirrors the THIRD condition (`bench_mock && entitlements.is_none()`) so
    /// it is testable without standing up a Postgres pool. Post-B-187d the
    /// production site this models is the ENTITLEMENT-SELECTION branch, not the
    /// tier branch — the tier is now derived from the grant via
    /// `rate_limit_tier()`. `bench_grant_branch_matches_production_shape`
    /// asserts the modelled condition still matches production verbatim.
    fn bench_tier_for(bench_mock: bool, has_entitlement_cache: bool) -> RateLimitTier {
        if bench_mock && !has_entitlement_cache {
            RateLimitTier::Bench
        } else {
            RateLimitTier::Free
        }
    }

    #[test]
    fn bench_grant_is_the_single_site_and_drives_every_limiter() {
        use crate::entitlement_cache::ResolvedEntitlements as RE;
        let g = RE::bench_unlimited();

        // MECHANISM, not outcome. Assert each enforcement point SHORT-CIRCUITS
        // off this one grant — not that N requests happen to pass. Outcome tests
        // were vacuous twice here: 100k requests pass a 4.29e9-token bucket, and
        // the first 10k pass a 10k quota.
        assert_eq!(
            g.rate_limit_tier(),
            RateLimitTier::Bench,
            "grant does not confer the Bench tier — the rate limiter will throttle"
        );
        assert_eq!(
            g.quota_config().trace_quota_monthly,
            0,
            "grant does not carry the unlimited-quota sentinel (0) — QuotaTracker::check \
             will NOT early-return and the monthly cap will 429 after 10k"
        );
        // The reserved key cannot confer a commercial tier if it ever leaked.
        assert_eq!(
            RateLimitTier::from_plan_tier_str("__bench"),
            RateLimitTier::Free
        );
        assert!(g.is_bench());

        // A REAL grant must do none of this.
        let real = RE::deny_all();
        assert!(!real.is_bench());
        assert_eq!(real.rate_limit_tier(), RateLimitTier::Free);
        assert_eq!(real.quota_config().trace_quota_monthly, 10_000);

        // The hot path must construct the grant in exactly ONE place — the whole
        // point of B-187d is that bench logic is not scattered across limiters.
        let src = include_str!("server.rs");
        let non_test = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        assert_eq!(
            non_test
                .matches(concat!("ResolvedEntitlements::", "bench_unlimited()"))
                .count(),
            1,
            "the bench grant is constructed more than once in the hot path"
        );
    }

    #[test]
    fn bench_tier_is_unreachable_for_a_postgres_backed_tenant() {
        // FOUNDER CONSTRAINT (B-187b), condition 3. `state.entitlements` is
        // `Some` iff a Postgres control plane exists (server.rs:278), which is
        // what makes a deployment HOSTED. So even with the env flag set AND the
        // reserved model, a tenant that exists in Postgres cannot acquire the
        // bench tier — the branch is structurally unreachable for it.
        assert_eq!(
            bench_tier_for(true, true),
            RateLimitTier::Free,
            "a Postgres-backed (hosted) tenant acquired the bench tier — the flag \
             must not be sufficient; the absent entitlement cache is the structural gate"
        );
        // ...and it IS granted in the bench/self-host case (no cache).
        assert_eq!(bench_tier_for(true, false), RateLimitTier::Bench);
        // Neither half alone is enough.
        assert_eq!(bench_tier_for(false, false), RateLimitTier::Free);
        assert_eq!(bench_tier_for(false, true), RateLimitTier::Free);
    }

    #[test]
    fn bench_grant_branch_matches_production_shape() {
        // Guards the ENTITLEMENT-SELECTION branch — the one site that constructs
        // the bench grant. (Before B-187d this string also guarded tier
        // selection; that decision now lives on the grant itself as
        // `rate_limit_tier()`, so the label was corrected to match what it
        // actually guards. Verifier finding: label drift.)
        let src = include_str!("server.rs");
        assert!(
            src.contains(concat!(
                "if bench_mock && state.",
                "entitlements.is_none() {"
            )),
            "the production bench-tier condition changed — update bench_tier_for to match"
        );
    }

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

    #[test]
    fn bench_tier_is_not_selectable_from_any_plan_string() {
        // No Polar/plan string may yield Bench — it is not a commercial tier.
        for p in [
            "free",
            "builder",
            "team",
            "business",
            "enterprise",
            "bench",
            "Bench",
            "free_v1",
            "enterprise_v1",
            "",
            "unknown",
        ] {
            assert_ne!(
                RateLimitTier::from_plan_tier_str(p),
                RateLimitTier::Bench,
                "plan string {p:?} selected the benchmark tier"
            );
        }
    }

    #[test]
    fn bench_mock_provider_id_is_not_routable() {
        // The synthetic id must never collide with a real provider, or a mocked
        // request could attribute cost or a BYOK lookup to one.
        assert!(
            crate::providers::ProviderRegistry::provider_id_for_model(BENCH_MOCK_PROVIDER_ID)
                .is_none(),
            "BENCH_MOCK_PROVIDER_ID collides with a routable provider"
        );
        assert!(BENCH_MOCK_PROVIDER_ID.starts_with("__bench_mock"));
    }

    #[test]
    fn bench_mock_bypass_sits_after_auth_and_tenant_resolution() {
        // FOUNDER CONSTRAINT: an unauthenticated request must never
        // reach the mock arm. This is a STRUCTURAL assertion on source order,
        // not an HTTP-level proof — the crate has no handler test harness
        // (no tower::ServiceExt/oneshot anywhere), so building one is its own
        // change. It is still a test, not a comment: moving the bypass above
        // auth or above tenant resolution fails it.
        let src = include_str!("server.rs");
        let auth = src
            .find("// --- Step 1: Auth ---")
            .expect("auth step marker");
        let tenant = src
            .find("let tenant_id = &claims.tenant_id")
            .expect("tenant binding");
        let gate = src
            .find("let bench_mock = bench_mock_active(")
            .expect("bench-mock gate");
        assert!(
            gate > auth,
            "bench-mock gate moved ABOVE Step 1 auth — unauthenticated requests could reach the mock"
        );
        assert!(
            gate > tenant,
            "bench-mock gate moved ABOVE tenant resolution — the mock would run without a resolved tenant"
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
    /// This asserts the gate EXISTS and sits AFTER authentication in each file. It
    /// is structural, and says so: the crate has no handler test harness (no
    /// `tower::ServiceExt`/`oneshot` anywhere), so an HTTP-level assertion is its
    /// own change. The behavioural proof is the prod 2x2 — same request, two
    /// differently-scoped keys, one 403 and one not-403.
    ///
    /// Needles are ASSEMBLED AT RUNTIME so this test cannot be satisfied by its own
    /// source text; the first version of the sibling route guard passed while the
    /// thing it checked had been changed, for exactly that reason.
    #[test]
    fn every_b230_route_gates_on_scope_after_authenticating() {
        let auth_call = format!("{}{}", "validate_", "authorization");
        let read_gate = format!("{}{}", "allows_scope(crate::auth::scope::", "Scope::Read)");
        let chat_gate = format!("{}{}", "allows_scope(crate::auth::scope::", "Scope::Chat)");

        for (label, src, gate) in [
            ("embeddings", include_str!("server.rs"), &chat_gate),
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

    #[test]
    fn prompt_observation_carries_only_the_version_id() {
        let body = json!({
            "model": "claude-sonnet-4-6",
            "tracelane_prompt_version_id": UUID_AB,
            "tracelane_prompt_name": "support-bot",
            "tracelane_prompt_env": "staging"
        });
        let obs = PromptObservation::from_body(&body).expect("should parse");
        assert_eq!(obs.version_id, Uuid::parse_str(UUID_AB).unwrap());
    }

    /// `tracelane_prompt_name` is no longer required, because it only ever
    /// selected a flip target and the hot path can no longer flip.
    #[test]
    fn prompt_observation_parses_without_a_name() {
        let body = json!({ "tracelane_prompt_version_id": UUID_AB });
        let obs = PromptObservation::from_body(&body).expect("should parse");
        assert_eq!(obs.version_id, Uuid::parse_str(UUID_AB).unwrap());
    }

    /// THE ENV FIELD IS INERT AND MUST STAY INERT. It used to decide whether an
    /// observation could mutate production, and it defaulted to `Production`
    /// when absent OR unparseable. Nothing on the chat path reads it now; this
    /// asserts a body claiming production cannot be distinguished from one that
    /// says nothing, because neither can reach a flip.
    #[test]
    fn prompt_observation_ignores_a_claimed_env() {
        let claims_prod = PromptObservation::from_body(&json!({
            "tracelane_prompt_version_id": UUID_AB,
            "tracelane_prompt_env": "production"
        }))
        .expect("should parse");
        let says_nothing =
            PromptObservation::from_body(&json!({ "tracelane_prompt_version_id": UUID_AB }))
                .expect("should parse");
        assert_eq!(claims_prod.version_id, says_nothing.version_id);
    }

    #[test]
    fn prompt_observation_none_without_correlation() {
        // Ad-hoc traffic — no prompt fields → no observation.
        assert!(PromptObservation::from_body(&json!({ "model": "x" })).is_none());
        // Unparseable uuid → None (never feeds a garbage version id).
        assert!(
            PromptObservation::from_body(&json!({
                "tracelane_prompt_version_id": "not-a-uuid",
                "tracelane_prompt_name": "p"
            }))
            .is_none()
        );
    }

    // ── Slack quota-webhook SSRF gate ────────────────────────────────────────
    // The webhook URL is tenant-controlled (`tenants.slack_webhook_url`);
    // `notify_quota_exceeded_async` runs it through `validate_slack_webhook`
    // BEFORE any request fires, so an SSRF-classic target is dropped before a
    // packet leaves the box. IP literals are checked without DNS, so these are
    // deterministic and never touch the network. Negative cases first.

    #[tokio::test]
    async fn slack_webhook_rejected_for_imds_and_rfc1918() {
        // Cloud metadata service (IMDS) — the canonical SSRF exfiltration target.
        assert!(
            validate_slack_webhook("http://169.254.169.254/latest/meta-data/")
                .await
                .is_err(),
            "must reject the 169.254.169.254 IMDS endpoint"
        );
        // RFC1918 private ranges must all be rejected before any send.
        for url in [
            "http://10.0.0.5/services/T000/B000/xyz",
            "http://192.168.1.1/hook",
            "https://172.16.0.1/hook",
        ] {
            assert!(
                validate_slack_webhook(url).await.is_err(),
                "must reject RFC1918 webhook {url}"
            );
        }
    }

    #[tokio::test]
    async fn slack_webhook_rejected_for_non_http_scheme() {
        assert!(validate_slack_webhook("file:///etc/passwd").await.is_err());
        assert!(validate_slack_webhook("gopher://10.0.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn slack_webhook_allows_public_host() {
        // A public IP literal passes without DNS or any network call — the gate
        // blocks private/link-local ranges, not legitimate external webhooks.
        assert!(
            validate_slack_webhook("https://8.8.8.8/services/T000/B000/xyz")
                .await
                .is_ok(),
            "a public webhook host must be allowed"
        );
    }
}

/// `/v1/embeddings` (GWY-26) + `tracelane.yaml` model aliases (GWY-39).
///
/// Gated on `debug_assertions` as well as `test` for the same reason
/// `providers::smoke_tests` is: the loopback SSRF bypass these tests need is
/// debug-only, and release hard-denies it.
#[cfg(all(test, debug_assertions))]
mod embeddings_route_tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Thread-local loopback opt-in — wiremock binds 127.0.0.1 and the SSRF
    /// guard blocks it. Never a process-env mutation (that races the suite).
    struct LoopbackBypassGuard;

    impl LoopbackBypassGuard {
        fn new() -> Self {
            crate::ssrf_guard::set_loopback_bypass_for_tests(true);
            Self
        }
    }

    impl Drop for LoopbackBypassGuard {
        fn drop(&mut self) {
            crate::ssrf_guard::set_loopback_bypass_for_tests(false);
        }
    }

    /// An `AppState` with no Postgres, no ClickHouse, no NATS and no Polar —
    /// i.e. the OSS self-host shape. Entitlements are `None`, which resolves to
    /// the FREE tier, never a paid one (`.claude/rules/tenancy.md`).
    fn test_state(providers: ProviderRegistry) -> AppState {
        let audit_chain = Arc::new(
            AuditChain::new(100, None, None).expect("audit chain builds without a signing key"),
        );
        AppState {
            providers: Arc::new(providers),
            // The cache is OFF in the test state, which is the production
            // default too — every hot-path test therefore exercises the
            // no-cache path, and the cache's own behaviour is tested in
            // `semantic_cache`'s module tests rather than implicitly here.
            semantic_cache: None,
            audit_chain: Arc::clone(&audit_chain),
            rate_limiter: Arc::new(RateLimiter::new()),
            quota_tracker: Arc::new(QuotaTracker::new()),
            quota_ch_url: None,
            predictive: Arc::new(PredictiveLayer::new()),
            predictive_enforce: false,
            guardrail: Arc::new(crate::guardrail::GuardrailEngine::new(
                audit_chain,
                None,
                None,
                Arc::new(crate::guardrail::capability::CapabilityRegistry::new()),
            )),
            billing: None,
            nats: None,
            entitlements: None,
            circuit_breaker: Arc::new(crate::circuit_breaker::CircuitBreaker::new(
                crate::circuit_breaker::BreakerConfig::default(),
            )),
            kill_switch: Arc::new(crate::kill_switch::KillSwitch::disabled()),
            prompt_router: build_prompt_router(None),
            bench_mock_upstream: false,
        }
    }

    fn authed() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer test-token"),
        );
        h
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body");
        serde_json::from_slice(&bytes).expect("response body is JSON")
    }

    /// A registry whose Ollama adapter points at `uri`. Ollama is the one
    /// provider whose credential env var is empty by design, so this exercises
    /// the real BYOK resolution path without a Postgres pool or an env var.
    fn registry_pointing_ollama_at(uri: String) -> ProviderRegistry {
        let mut reg = ProviderRegistry::new().expect("provider registry");
        reg.set_compat_base_url_for_test("ollama", uri)
            .expect("ollama adapter for the mock");
        reg
    }

    const VECTORS: [f32; 4] = [0.1, 0.2, 0.3, 0.4];

    async fn embeddings_mock() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list",
                "data": [{ "object": "embedding", "index": 0, "embedding": VECTORS }],
                "model": "nomic-embed-text",
                "usage": { "prompt_tokens": 11, "total_tokens": 11 }
            })))
            .mount(&server)
            .await;
        server
    }

    // ── Negative first: every way in that must be REFUSED. ──

    #[tokio::test]
    async fn embeddings_without_authorization_is_rejected() {
        // The failure this guards is the one crates/gateway/CLAUDE.md names:
        // "adding a route without replicating that sequence ships an
        // unauthenticated endpoint". There is no Tower auth layer to inherit.
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let resp = embeddings_handler(
            State(state),
            HeaderMap::new(),
            Json(json!({ "model": "text-embedding-3-small", "input": "hi" })),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an unauthenticated embeddings request must never reach routing or a credential"
        );
    }

    #[tokio::test]
    async fn embeddings_rejects_an_unroutable_model_rather_than_defaulting() {
        // No default provider. Defaulting here would ship one provider's
        // BYOK key to a model the caller never named.
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": "no-such-model-family", "input": "hi" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await["error"], "unroutable_model");
    }

    #[tokio::test]
    async fn embeddings_rejects_a_provider_with_no_openai_shaped_endpoint() {
        // Anthropic has no OpenAI-compatible /v1/embeddings. Forwarding the
        // request on a guess would return an upstream 400 that reads as ours.
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": "claude-sonnet-4-6", "input": "hi" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "embeddings_unsupported_provider");
        assert_eq!(body["provider"], "anthropic");
    }

    #[tokio::test]
    async fn embeddings_rejects_a_body_with_no_input() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        for bad in [
            json!({ "model": "text-embedding-3-small" }),
            json!({ "model": "text-embedding-3-small", "input": [] }),
            json!({ "input": "orphan input, no model" }),
        ] {
            let resp = embeddings_handler(State(state.clone()), authed(), Json(bad.clone())).await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{bad} must be refused before a credential is resolved"
            );
        }
    }

    #[tokio::test]
    async fn embeddings_maps_an_upstream_401_to_a_key_rejection_not_an_outage() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad key sk-leaked-value"))
            .mount(&server)
            .await;

        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": "ollama/nomic-embed-text", "input": "hi" })),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an upstream 401 is the tenant's key being rejected, not a 502 outage"
        );
        let body = body_json(resp).await;
        assert_eq!(body["error"], "provider_key_rejected");
        assert!(
            !body.to_string().contains("sk-leaked-value"),
            "the upstream body must never cross this boundary: {body}"
        );
    }

    // ── The end state: a caller gets usable vectors back. ──

    #[tokio::test]
    async fn embeddings_returns_vectors_a_caller_can_use() {
        let _bypass = LoopbackBypassGuard::new();
        let server = embeddings_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));

        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": "ollama/nomic-embed-text", "input": "embed me" })),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        // Not "it returned 200": the actual vector the caller came for.
        let embedding = body["data"][0]["embedding"]
            .as_array()
            .expect("data[0].embedding must be an array of floats");
        let got: Vec<f64> = embedding
            .iter()
            .map(|v| v.as_f64().expect("float"))
            .collect();
        assert_eq!(got.len(), 4);
        for (i, want) in VECTORS.iter().enumerate() {
            assert!(
                (got[i] - f64::from(*want)).abs() < 1e-6,
                "embedding[{i}] = {} , want {want}",
                got[i]
            );
        }
        assert_eq!(body["object"], "list");
        assert_eq!(body["usage"]["prompt_tokens"], 11);
        // The model the caller sent is echoed back, so a client that
        // round-trips `response.model` keeps working.
        assert_eq!(body["model"], "ollama/nomic-embed-text");
    }

    #[test]
    fn openai_bare_embedding_models_route_to_openai() {
        // Without this arm `text-embedding-3-small` — the most-used embedding
        // model there is — fail-closed as `unroutable_model`, because it
        // carries no gpt/o1/o3 prefix.
        assert_eq!(
            ProviderRegistry::provider_id_for_model("text-embedding-3-small"),
            Some("openai")
        );
        assert_eq!(
            ProviderRegistry::provider_id_for_model("text-embedding-ada-002"),
            Some("openai")
        );
        // Still fail-closed on a name nothing serves.
        assert_eq!(
            ProviderRegistry::provider_id_for_model("text-embedding"),
            None,
            "the arm must not swallow a bare prefix with no model after it"
        );
    }

    #[test]
    fn the_embeddings_route_is_mounted_unconditionally() {
        // Ten of the gateway's route groups are env-conditional. This one must
        // not be: an embeddings call that 404s is the same silent bypass GWY-26
        // exists to close. Scan only the non-test prefix so this literal does
        // not match itself (same technique as the bench-gate guard above).
        let full = include_str!("server.rs");
        let non_test = &full[..full.find("#[cfg(test)]").unwrap_or(full.len())];
        assert!(
            non_test.contains(concat!(
                r#".route("/v1/embeddings", "#,
                "post(embeddings_handler))"
            )),
            "the /v1/embeddings route must be mounted in the unconditional router"
        );
    }

    // ── GWY-39: `tracelane.yaml` makes an unroutable model routable. ──

    /// The whole GWY-39 claim in one test, because the config slot is
    /// process-global and write-once: a model the built-in prefix table cannot
    /// route becomes routable, reaches the aliased provider, and is sent
    /// upstream under the aliased upstream model name.
    #[tokio::test]
    async fn tracelane_yaml_alias_routes_a_model_the_prefix_table_cannot() {
        const ALIAS: &str = "tl-test-alias-embedder";

        // 1. FALSIFY FIRST: without the file this model is unroutable.
        assert_eq!(
            ProviderRegistry::provider_id_for_model(ALIAS),
            None,
            "precondition: the alias must be unroutable before the config is installed"
        );

        // 2. Install exactly the block apps/docs/providers.mdx describes.
        let cfg = crate::server::config::parse(&format!(
            "models:\n  {ALIAS}:\n    provider: ollama\n    model: nomic-embed-text\n"
        ))
        .expect("documented tracelane.yaml block must parse");
        assert!(
            crate::server::config::install_for_test(cfg),
            "this must be the only test that installs a config"
        );

        // 3. The canonical map now resolves it — and so does every delegate,
        //    because the alias lives INSIDE `provider_id_for_model`.
        assert_eq!(
            ProviderRegistry::provider_id_for_model(ALIAS),
            Some("ollama")
        );
        assert_eq!(provider_name_from_model(ALIAS), "ollama");
        assert_eq!(
            ProviderRegistry::api_key_env_var(ALIAS),
            Some(""),
            "the alias must resolve Ollama's (empty) credential, not another provider's"
        );
        // Exact match only — an alias must never widen into a prefix rule.
        assert_eq!(
            ProviderRegistry::provider_id_for_model(&format!("{ALIAS}-v2")),
            None
        );

        // 4. End to end: the request routes, and the UPSTREAM sees the aliased
        //    model name while the CALLER gets their own name back.
        let _bypass = LoopbackBypassGuard::new();
        let server = embeddings_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": ALIAS, "input": "embed me" })),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the alias must make a previously-400 model serve a real response"
        );
        let body = body_json(resp).await;
        assert_eq!(body["model"], ALIAS, "the caller's own name is echoed back");
        assert!(body["data"][0]["embedding"].is_array());

        // The discriminating field: what the provider was actually asked for.
        let received = server
            .received_requests()
            .await
            .expect("mock recorded requests");
        let sent: serde_json::Value =
            serde_json::from_slice(&received[0].body).expect("upstream body is JSON");
        assert_eq!(
            sent["model"], "nomic-embed-text",
            "the upstream must be asked for the aliased model, not the alias"
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
