//! Axum HTTP server — router, state, and handlers.
//!
//! Exposes:
//!   GET  /health                    — unauthenticated liveness probe
//!   POST /v1/chat/completions       — OpenAI-compatible chat endpoint
//!
//! AppState bundles all shared components:
//!   providers    — ProviderRegistry (35 routable: 7 native adapters + 28 OpenAI-compatible + failover chain)
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
    pub audit_chain: Arc<AuditChain>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Monthly trace-quota tracker enforcing the hard 5× cap.
    /// Hot-path budget <500ns p99 (see `benches/rate_limiter.rs`).
    pub quota_tracker: Arc<QuotaTracker>,
    /// B-109: ClickHouse URL the `quota_tracker` rehydrates the durable monthly
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
    // Soft dependency: if NATS_URL is unset or connection fails, we log and
    // continue. Spans still reach structured logs; ingest loss is acceptable
    // in dev. Production must set NATS_URL.
    let nats = if let Some(ref url) = config.nats_url {
        match async_nats::connect(url.as_str()).await {
            Ok(client) => {
                tracing::info!(%url, "NATS connected — span publish enabled");
                Some(Arc::new(client))
            }
            Err(err) => {
                tracing::error!(
                    error = %err, %url,
                    "NATS connection FAILED — span publish disabled; ALL spans will be \
                     dropped until NATS is reachable. Check NATS_URL / network."
                );
                None
            }
        }
    } else {
        tracing::warn!(
            "NATS_URL not set — span publish DISABLED; ALL spans will be dropped \
             (observability blind). Set NATS_URL in production; expected only in dev."
        );
        None
    };

    let rate_limiter = Arc::new(RateLimiter::new());
    let quota_tracker = Arc::new(QuotaTracker::new());
    // Operational kill-switch (ADR-038) — built first so the predictive layer
    // can consult `kill.predictive.*` per request.
    let kill_switch = Arc::new(crate::kill_switch::KillSwitch::from_env());
    let predictive = Arc::new(PredictiveLayer::new().with_kill_switch(kill_switch.clone()));

    // ADR-069: async audit append (B-119). Create the JetStream context + the
    // durable TRACELANE_AUDIT stream BEFORE serving (so the first publish lands),
    // enable the acked-publish path on the audit chain, and spawn the sole
    // head-writer consumer. On any setup failure the audit path stays SYNCHRONOUS
    // (fail-safe): publish() falls back to append() when no JetStream is wired.
    if let Some(ref nats_client) = nats {
        let js = async_nats::jetstream::new((**nats_client).clone());
        match crate::audit_consumer::ensure_audit_stream(&js).await {
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

    // Rekor anchor batch meters one `audit_anchors` usage event (ADR-048). Off
    // the anchor path (fire-and-forget, tenant→customer mapped in the hook). No
    // recorder (POLAR_ACCESS_TOKEN unset) → anchoring is simply not metered.
    if let Some(ref recorder) = billing {
        audit_chain.set_billing(Arc::clone(recorder));
    }

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
        }
        tracing::info!(
            rails = engine.rail_count(),
            "inline guardrails engine ready"
        );
        Arc::new(engine)
    };

    let state = AppState {
        providers,
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
        entitlements,
        circuit_breaker,
        kill_switch,
        prompt_router,
        bench_mock_upstream: config.bench_mock_upstream,
    };

    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/v1/auth/whoami", get(whoami_handler))
        .route("/v1/chat/completions", post(chat_completions_handler))
        .with_state(state.clone());

    // Polar webhook — own narrow state so the handler doesn't pull the
    // full AppState. Mounted only when POLAR_WEBHOOK_SECRET is set;
    // without a configured secret we cannot verify signatures so the
    // route stays unmounted (better than 503-ing every request).
    if let Some(wh_cfg) = crate::billing::WebhookConfig::from_env() {
        let wh_state = crate::billing::WebhookState {
            config: Arc::new(wh_cfg),
        };
        let wh_app = Router::new()
            .route("/v1/webhooks/polar", post(crate::billing::webhook::handler))
            .with_state(wh_state);
        app = app.merge(wh_app);
        tracing::info!("Polar webhook handler mounted at /v1/webhooks/polar");
    } else {
        tracing::info!("POLAR_WEBHOOK_SECRET not set — webhook handler not mounted");
    }

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

    // WorkOS webhook — same secret-or-skip pattern as the Polar webhook above.
    // Provisions tenants from organization.created and users from
    // user.created / dsync.user.created. Without WORKOS_WEBHOOK_SECRET
    // the route stays absent.
    if let Some(wh_cfg) = crate::auth::workos_webhook::WorkOsWebhookConfig::from_env() {
        let wh_state = crate::auth::workos_webhook::WorkOsWebhookState {
            config: Arc::new(wh_cfg),
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
        let self_verify_app = crate::audit_self_verify::routes().with_state(export_state);
        app = app.merge(self_verify_app);
        tracing::info!("Audit self-verify mounted at /v1/audit/self-verify");

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
        tracing::info!(
            "Trace reads mounted at /v1/traces, /v1/traces/{{id}}/spans, /v1/slo, /v1/query/signatures"
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
    }

    // because the Cloudflare Workers runtime can't run the web minter's WASM
    // Argon2; RustCrypto Argon2 runs natively here. Same pepper + params, so
    // minted keys stay verify-compatible with `lookup_tenant_by_key_body`.
    if let Some(pool) = crate::db::global_pool() {
        let key_state = crate::key_routes::KeyRoutesState {
            minter: std::sync::Arc::new(crate::key_routes::PgKeyMinter { pool: pool.clone() }),
        };
        app = app.merge(crate::key_routes::routes().with_state(key_state));
        tracing::info!("API-key mint mounted at POST /v1/keys");
    }

    // built once (build_prompt_router) and lives in AppState so the chat
    // handler can feed drift metrics into it; here we mount the same shared
    // Arc behind the /v1/prompts/* sub-router. The write workflow
    // (promote/rollback/observe) is gated on FeatureKey::PromptPromotionWrite
    // the gate fails closed inside the handlers (503 on writes).
    {
        let prompt_state = crate::prompt_routes::PromptRoutesState {
            router: state.prompt_router.clone(),
            entitlements: state.entitlements.clone(),
            audit_chain: state.audit_chain.clone(),
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

#[instrument]
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "service": "tracelane-gateway" }))
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

/// Optional prompt-promotion correlation extracted from the request body so
/// the auto-rollback engine can attribute a request's metrics to a specific
/// prompt version. Absent for ad-hoc (non-managed-prompt) traffic.
#[derive(Clone)]
struct PromptObservation {
    version_id: Uuid,
    name: String,
    env: crate::prompt_router::Env,
}

impl PromptObservation {
    /// Returns `Some` only when the body carries both a parseable
    /// `tracelane_prompt_version_id` and a `tracelane_prompt_name`. `env`
    /// defaults to production.
    fn from_body(body: &serde_json::Value) -> Option<Self> {
        let version_id = body
            .get("tracelane_prompt_version_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())?;
        let name = body
            .get("tracelane_prompt_name")
            .and_then(|v| v.as_str())?
            .to_string();
        let env = body
            .get("tracelane_prompt_env")
            .and_then(|v| v.as_str())
            .and_then(parse_prompt_env)
            .unwrap_or(crate::prompt_router::Env::Production);
        Some(Self {
            version_id,
            name,
            env,
        })
    }
}

fn parse_prompt_env(s: &str) -> Option<crate::prompt_router::Env> {
    use crate::prompt_router::Env;
    match s {
        "dev" => Some(Env::Dev),
        "staging" => Some(Env::Staging),
        "production" => Some(Env::Production),
        "canary" => Some(Env::Canary),
        _ => None,
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
        if let Err(e) = router
            .observe_and_maybe_rollback(tenant_id, &obs.name, obs.env, obs.version_id, &metrics)
            .await
        {
            tracing::warn!(error = %e, "auto-rollback metric observation failed");
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

    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    // --- Step 2: Rate limit + quota (one warm entitlement resolve) ---
    // B-119 fix A: derive BOTH the rate-limit tier and the monthly quota config
    // from a single warm entitlement-cache read (in-process Moka, LISTEN/NOTIFY-
    // invalidated) — never a per-request Postgres round-trip. `plan_lookup_key`
    // (`builder_v1`, …) is the authoritative plan (ADR-020) and supersedes the
    // legacy `tenants.plan_tier` column the old per-request `resolve_tenant_tier`
    // PG read used. No cache (dev / no-Postgres) or a resolve failure fails
    // restricted to Free / free quota (deny_all() → `free_v1`; never over-grant).
    let entitlements = match &state.entitlements {
        Some(cache) => Some(cache.resolved(*tenant_id.as_uuid()).await),
        None => None,
    };
    let tier = entitlements.as_ref().map_or(RateLimitTier::Free, |e| {
        RateLimitTier::from_plan_tier_str(e.plan_lookup_key.trim_end_matches("_v1"))
    });
    let rl = state.rate_limiter.check(tenant_id, tier);
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
    // B-109 durability: rehydrate the counter from the durable ClickHouse trace
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
        if let Some(webhook) = resolve_tenant_slack_webhook(tenant_id).await {
            notify_quota_exceeded_async(webhook, tenant_id.clone(), limit, used);
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
    // (the audit product does not serve unrecorded requests). publish() falls back
    // to the synchronous fail-open append when async is unwired / kill.audit.async,
    // so dev / self-host / the operator lever never 503.
    if let Err(err) = state.audit_chain.publish(audit_event).await {
        tracing::error!(error = %err, "audit publish failed — refusing request (fail-closed)");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "audit_unavailable" })),
        )
            .into_response();
    }
    // --- Step 5: Provider dispatch ---
    // `mut`: on a successful cross-provider failover below we reassign this to
    // the provider that actually served the request, so the span, the echoed
    let mut model = body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("claude-sonnet-4-6")
        .to_owned();

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

    // B-127: resolve the provider ONCE from the single canonical map and FAIL
    // CLOSED on an unmatched model. There is NO default provider — routing an
    // unknown model to Anthropic (or any provider) would fetch that provider's
    // BYOK key for a model the caller never asked for (credential misrouting).
    // Rejecting is categorically safer than shipping the wrong provider's key.
    let Some(provider_id) = crate::providers::ProviderRegistry::provider_id_for_model(&model)
    else {
        return unroutable_model_response(&model);
    };
    // A4: BYOK lookup first — per-tenant ciphertext in `provider_keys` decrypted
    // with AAD bound to (tenant_id, provider_id). On miss (no row, decrypt fail,
    // pool unavailable) fall back to the legacy env var. The env var is derived
    // from THIS provider_id, so a miss yields an empty key (upstream 401), never
    // another provider's key.
    let key_env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id);
    let provider_key = resolve_provider_key(tenant_id, provider_id, key_env)
        .await
        .unwrap_or_default();

    let mut chat_request =
        match serde_json::from_value::<tracelane_shared::ChatRequest>(body.clone()) {
            Ok(r) => r,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("malformed request: {err}") })),
                )
                    .into_response();
            }
        };

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
            // B-118 #5: if the blocking reason maps to a canonical AFT-1 signature
            // (tool-description injection → AFT-TOOL-POISON-001), emit an
            // error-status span carrying that `aft_id` BEFORE the 403 short-circuit
            // — otherwise the blocked hit is invisible on /signatures (the very
            // #3 gap, recreated for the injection case). Schema/drift no longer
            // reach this branch (they observe); injection is the live mapping.
            if let Some(aft_id) = crate::guardrail::rails::r3_tool_safety::reason_to_aft(reason) {
                if let Some(ref nats_client) = state.nats {
                    let span = build_blocked_aft_span(
                        tenant_id,
                        trace_id,
                        &model,
                        request_start,
                        "guardrail_block",
                        aft_id,
                    );
                    let nats = Arc::clone(nats_client);
                    tokio::spawn(async move {
                        if let Err(e) = crate::otlp_emit::publish_span(&nats, &span).await {
                            tracing::warn!(error = %e, "blocked-aft span NATS publish failed");
                        }
                    });
                }
            }
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
    // A7: one retry against the same provider on transient failure.
    let mut provider_result = if state.bench_mock_upstream && is_bench_mock_model(&model) {
        // Bench-only instant upstream (TRACELANE_BENCH_MOCK_UPSTREAM). Replaces
        // ONLY the network dispatch with an instant canned stream, so a load
        // test's measured latency is gateway overhead (auth, parse, untrusted
        // wrap, breaker, span emit) with ~0 provider time. Double-gated — the
        // flag is off by default and the model must be `__bench_mock*`, so a
        // normal tenant request can never reach here. See bench/gateway/README.
        crate::providers::MockProvider::new("ok")
            .chat_mock(chat_request.clone(), &provider_key, tenant_id)
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
    state
        .circuit_breaker
        .record(upstream, region, provider_result.is_ok());

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
            // B-127: fail closed on an unroutable failover candidate — skip it,
            // never default to a provider (its key would be the wrong one).
            let Some(fo_pid) = crate::providers::ProviderRegistry::provider_id_for_model(fo_model)
            else {
                continue;
            };
            let fo_env = crate::providers::ProviderRegistry::env_var_for_provider_id(fo_pid);
            let fo_key = resolve_provider_key(tenant_id, fo_pid, fo_env)
                .await
                .unwrap_or_default();
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

            // B-118 #3: also publish an ERROR-status span so this failure is COUNTABLE
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
            } else {
                "provider_unavailable"
            };
            if let Some(ref nats_client) = state.nats {
                let span = build_error_span(tenant_id, trace_id, &model, request_start, err_reason);
                let nats = Arc::clone(nats_client);
                tokio::spawn(async move {
                    if let Err(e) = crate::otlp_emit::publish_span(&nats, &span).await {
                        tracing::warn!(error = %e, "error-span NATS publish failed");
                    }
                });
            }

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

            // B-113: an upstream 429 is NOT an outage — the caller is over quota or
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

            // B-113: an upstream 404 means the model does not exist for this
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
        )
        .await
        .into_response()
    }
}

/// Count of billing meter-records spawned, bumped synchronously at the call site.
///
/// Billing is fire-and-forget into a `tokio::spawn`, and a SUCCESSFUL meter logs
/// nothing (`Recorder::flush` only warns on failure), so from outside the process
/// "we billed" and "we never billed" were byte-identical. That is not a detail —
/// it is *why* B-110 survived for months: billing sat on 2 of the stream's 4
/// termination paths and no operator, log, or metric could have told.
///
/// This counter measures **intent-to-bill at the call site** — incremented BEFORE
/// the spawn, deliberately, so it is independent of whether the tenant has a Polar
/// customer. That is the right boundary: the call site is what B-110 broke;
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

/// Read the billing-spawn counter. Test seam for B-110's regression test.
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
struct SpanUsageMeta {
    cache_read_input_tokens: Option<u32>,
    cache_creation_input_tokens: Option<u32>,
    stream: bool,
    /// put a cost on the wire. When `None`, `build_gateway_span` derives the
    /// cost from the model price catalog (`crate::pricing`). Lands as
    /// `gen_ai.usage.cost`.
    cost_usd: Option<f64>,
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
struct GatewayTiming {
    dispatch_ts: chrono::DateTime<chrono::Utc>,
    provider_complete_ts: chrono::DateTime<chrono::Utc>,
    ttft_us: Option<u32>,
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
fn build_gateway_span(
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
            // request. The rollup counts `countIf(tracelane_failover_activated)`;
            // `tracelane_failover_from` names the primary provider that errored.
            tracelane_failover_activated: failover_from.map(|_| true),
            tracelane_failover_from: failover_from.map(str::to_owned),
            ..Default::default()
        },
        // A FAILED request (upstream 4xx/5xx/timeout, mid-stream provider error, or
        // dispatch exhaustion) MUST record status Error — otherwise /slo's
        // countIf(status_code = 2) error rate is STRUCTURALLY pinned at ~0% for all
        // gateway-proxied traffic (B-118 #3: every span was hardcoded Ok, so a real
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
/// B-127: the fail-closed response for a model that matches NO provider in the
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

/// B-125: build a client-facing provider-error response with a defense-in-depth
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
    )
}

/// Error-status span for a request BLOCKED by an inline guardrail that maps to a
/// canonical AFT-1 failure signature (today: tool-description injection →
/// `AFT-TOOL-POISON-001`). Like [`build_error_span`] but carries the `aft_id` so
/// the blocked hit still lands in `spans.aft_ids` and the tenant sees it on
/// /signatures — a blocked injection is "your hit," not a silent 403 (B-118 #5).
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
    )
}

/// Map a model name to a canonical provider name (OTel `gen_ai.system` /
/// `gen_ai.provider.name` value) for span attribution.
///
/// B-126: this DELEGATES to the canonical `ProviderRegistry::provider_id_for_model`
/// rather than carrying its own prefix table. A private copy had drifted — it only
/// knew 8 providers and stamped every other model (groq, mistral, perplexity, xai,
/// and ~24 more of the 35) as `"unknown"` on the span, so the dashboard's provider
/// column + per-provider latency tiles were blank/"unknown" for most real traffic.
/// Only the two names that differ from the provider_id (AWS/GCP house style) are
/// remapped; the rest of the provider_id set already equals the gen_ai.system value.
fn provider_name_from_model(model: &str) -> &'static str {
    // B-127: an unmatched model has no provider — attribute it "unknown" (this is
    // a span label, never a key lookup, so "unknown" is safe; the key path already
    // fail-closed on None before reaching here).
    match crate::providers::ProviderRegistry::provider_id_for_model(model) {
        Some("vertex") => "gcp_vertex_ai",
        Some("bedrock") => "aws_bedrock",
        Some(other) => other,
        None => "unknown",
    }
}

/// A4: resolve the provider-API plaintext key. Order:
///   1. Hot-path cache (`db::provider_keys::lookup_cached`).
///   2. Per-tenant BYOK row from `provider_keys` (decrypted with AAD).
///   3. Process env var (legacy single-tenant fallback).
///   4. Empty string (Ollama / no-key providers).
///
/// Returns `Some(plaintext)` when we have a key to use; `None` only
/// when there genuinely is no provider key resolvable (caller will
/// surface a provider 401 to the customer).
///
/// The `SecretString` is cloned into a plain `String` only at the very
/// last hop so reqwest can attach it as a header value.
async fn resolve_provider_key(
    tenant_id: &TenantId,
    provider_id: &str,
    env_var: &str,
) -> Option<String> {
    use secrecy::ExposeSecret as _;
    use std::sync::Arc;

    if let Some(secret) = crate::db::provider_keys::lookup_cached(tenant_id, provider_id) {
        return Some(secret.expose_secret().to_string());
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
                        return Some(secret.expose_secret().to_string());
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            tenant_id = %tenant_id,
                            provider_id,
                            "BYOK decrypt failed — refusing env fallback (auth-fail safer)"
                        );
                        return None;
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
        return Some(String::new()); // Ollama
    }
    std::env::var(env_var).ok()
}

/// Current UTC calendar month as `YYYYMM` (e.g. `202607`) — the seed key for the
/// durable monthly quota counter's month-boundary reset (B-109).
fn current_year_month() -> u32 {
    use chrono::Datelike as _;
    let now = chrono::Utc::now();
    now.year() as u32 * 100 + now.month()
}

/// B-109 durability: read the tenant's trace count for the current calendar month
/// from ClickHouse — the durable baseline the in-memory quota counter is seeded
/// from so a restart / blue-green deploy no longer forgives accrued usage. Runs
/// once per tenant per month per process (gated by `QuotaTracker::needs_seed`),
/// never on the warm hot path. `trace_summaries` is one row per trace = the
/// "traces this month" the quota bills; its `(tenant_id, start_time, …)` sort key
/// makes this an indexed range scan. Any failure → 0 (fail-open baseline: never
/// block a paying tenant because ClickHouse blinked; worst case is one
/// process-lifetime of under-count, corrected on the next month's seed).
async fn quota_baseline_from_clickhouse(state: &AppState, tenant_id: &TenantId) -> u64 {
    let Some(url) = state.quota_ch_url.clone() else {
        return 0;
    };
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct CountRow {
        n: u64,
    }
    const SQL: &str = "SELECT count() AS n FROM tracelane.trace_summaries \
        WHERE tenant_id = ? AND start_time >= toStartOfMonth(now())";
    match crate::clickhouse_query::ch_client(url)
        .query(SQL)
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

/// Look up the Slack webhook URL for hard-cap quota alerts, if configured
/// on `tenants.slack_webhook_url`. Returns None when the column is null,
/// the tenant is missing, or no Postgres pool is available — the 429
/// response is independent of webhook delivery.
async fn resolve_tenant_slack_webhook(tenant_id: &TenantId) -> Option<String> {
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
fn next_month_boundary_iso() -> String {
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

/// Fire-and-forget Slack POST when a tenant hits the hard quota cap.
///
/// Spawns onto the existing tokio runtime; the request handler does NOT
/// await the POST. Webhook latency or failure is invisible to the caller.
/// The POST body is the minimum needed for the receiver to render an
/// actionable alert; intentionally never includes API-key material or
/// trace contents (CLAUDE.md security non-negotiable #5).
///
/// The tenant-controlled URL passes [`validate_slack_webhook`] before any
/// request fires (SSRF), and the request uses
/// [`crate::ssrf_guard::safe_client_builder`] (rustls + no-redirect, so a
/// redirect to an internal host cannot be followed). A rejected URL is
/// log-and-dropped — the 429 the caller already received is independent of
/// webhook delivery.
fn notify_quota_exceeded_async(webhook_url: String, tenant_id: TenantId, limit: u64, used: u64) {
    tokio::spawn(async move {
        if let Err(e) = validate_slack_webhook(&webhook_url).await {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "slack webhook URL rejected by SSRF guard; dropping notification (429 already returned)"
            );
            return;
        }

        let body = serde_json::json!({
            "text": format!(
                "Tracelane quota exceeded — tenant {} used {} / hard cap {}. \
                 Gateway is now returning 429. Visit \
                 https://app.tracelane.dev/settings/billing to upgrade.",
                tenant_id, used, limit
            )
        });
        let client = match crate::ssrf_guard::safe_client_builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "slack webhook client build failed");
                return;
            }
        };
        if let Err(e) = client.post(&webhook_url).json(&body).send().await {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "slack webhook POST failed; 429 already returned to caller"
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

/// A7: retry the same-provider dispatch once on transient failure with a
/// 100ms backoff. Within the FT-01 200ms total budget. The original error
/// is preserved if the retry also fails.
///
/// Today this is intentionally same-provider only — true cross-provider
/// failover (Claude → GPT-5) needs request-shape translation that is
async fn dispatch_with_retry(
    registry: &crate::providers::ProviderRegistry,
    chat_request: &tracelane_shared::ChatRequest,
    provider_key: &str,
    model: &str,
    tenant_id: &tracelane_shared::TenantId,
) -> anyhow::Result<crate::providers::ProviderStream> {
    let attempt_started = std::time::Instant::now();
    match dispatch_to_provider(
        registry,
        chat_request.clone(),
        provider_key,
        model,
        tenant_id,
    )
    .await
    {
        Ok(s) => Ok(s),
        Err(first_err) => {
            let backoff = std::time::Duration::from_millis(100);
            if attempt_started.elapsed() + backoff
                > std::time::Duration::from_millis(crate::providers::failover::FAILOVER_BUDGET_MS)
            {
                tracing::warn!(error = %first_err, "provider failed; budget exhausted, no retry");
                return Err(first_err);
            }
            tracing::warn!(
                error = %first_err,
                model = %model,
                "provider attempt failed — retrying once after 100ms"
            );
            tokio::time::sleep(backoff).await;
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
                    tracing::info!(
                        model = %model,
                        elapsed_ms = attempt_started.elapsed().as_millis(),
                        "tracelane.failover.activated=true (same-provider retry succeeded)"
                    );
                    Ok(s)
                }
                Err(second_err) => Err(second_err.context(first_err.to_string())),
            }
        }
    }
}

/// Routes a chat request to the correct provider adapter.
///
/// B-126: the provider is resolved by the SINGLE canonical model→provider table
/// `ProviderRegistry::provider_id_for_model`, then this match selects the typed
/// adapter by that provider_id. It deliberately does NOT re-match model prefixes
/// — a second model-prefix table is exactly what drifted (Groq family dispatched
/// here but the BYOK key was looked up under "anthropic"). Adapter selection by
/// provider_id is a fixed enumeration that cannot drift on model names. Keep this
/// arm set a superset of `provider_id_for_model`'s outputs; `_` mirrors that
/// table's `anthropic` default. Enforced by `scripts/ci/check-provider-mapping-single-source.py`.
async fn dispatch_to_provider(
    registry: &crate::providers::ProviderRegistry,
    request: tracelane_shared::ChatRequest,
    api_key: &str,
    model: &str,
    tenant_id: &tracelane_shared::TenantId,
) -> anyhow::Result<crate::providers::ProviderStream> {
    use crate::providers::ProviderRegistry;

    // B-127: fail closed. No default provider — an unmatched model bails here too
    // (defense in depth; the handler already rejected it before resolving a key).
    let Some(provider_id) = ProviderRegistry::provider_id_for_model(model) else {
        anyhow::bail!("unroutable model '{model}': no provider configured");
    };
    match provider_id {
        "anthropic" => registry.anthropic.chat(request, api_key, tenant_id).await,
        "openai" => registry.openai.chat(request, api_key, tenant_id).await,
        "vertex" => registry.vertex.chat(request, api_key, tenant_id).await,
        "google" => registry.google.chat(request, api_key, tenant_id).await,
        "bedrock" => registry.bedrock.chat(request, api_key, tenant_id).await,
        "azure" => registry.azure.chat(request, api_key, tenant_id).await,
        "cohere" => registry.cohere.chat(request, api_key, tenant_id).await,
        "mistral" => registry.mistral.chat(request, api_key, tenant_id).await,
        "perplexity" => registry.perplexity.chat(request, api_key, tenant_id).await,
        "deepseek" => registry.deepseek.chat(request, api_key, tenant_id).await,
        "xai" => registry.xai.chat(request, api_key, tenant_id).await,
        "nvidia" => registry.nvidia_nim.chat(request, api_key, tenant_id).await,
        "cerebras" => registry.cerebras.chat(request, api_key, tenant_id).await,
        "sambanova" => registry.sambanova.chat(request, api_key, tenant_id).await,
        "lepton" => registry.lepton.chat(request, api_key, tenant_id).await,
        "lambda" => registry.lambda.chat(request, api_key, tenant_id).await,
        "novita" => registry.novita.chat(request, api_key, tenant_id).await,
        "ai21" => registry.ai21.chat(request, api_key, tenant_id).await,
        "hyperbolic" => registry.hyperbolic.chat(request, api_key, tenant_id).await,
        "deepinfra" => registry.deepinfra.chat(request, api_key, tenant_id).await,
        "cloudflare" => registry.cloudflare.chat(request, api_key, tenant_id).await,
        "ollama" => registry.ollama.chat(request, api_key, tenant_id).await,
        "baseten" => registry.baseten.chat(request, api_key, tenant_id).await,
        "huggingface" => registry.huggingface.chat(request, api_key, tenant_id).await,
        "anyscale" => registry.anyscale.chat(request, api_key, tenant_id).await,
        "modal" => registry.modal.chat(request, api_key, tenant_id).await,
        "predibase" => registry.predibase.chat(request, api_key, tenant_id).await,
        "moonshot" => registry.moonshot.chat(request, api_key, tenant_id).await,
        "upstage" => registry.upstage.chat(request, api_key, tenant_id).await,
        "yi" => registry.yi.chat(request, api_key, tenant_id).await,
        "aleph-alpha" => registry.aleph_alpha.chat(request, api_key, tenant_id).await,
        "groq" => registry.groq.chat(request, api_key, tenant_id).await,
        "together" => registry.together.chat(request, api_key, tenant_id).await,
        "fireworks" => registry.fireworks.chat(request, api_key, tenant_id).await,
        "openrouter" => registry.openrouter.chat(request, api_key, tenant_id).await,
        // B-127: NO default-to-anthropic. A provider_id the dispatch doesn't know
        // is a bug in the map, not "probably Anthropic" — bail rather than ship a
        // request to the wrong provider with the wrong key.
        _ => anyhow::bail!("unroutable provider_id '{provider_id}' for model '{model}'"),
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
    // B-118 #5: the predictive AFT hit id (observe-first) — threaded onto the published
    // span so the /signatures page shows the tenant's OWN matched signatures instead of
    // demo-seed only. None when no detector matched.
    warn_aft_id: Option<&'static str>,
    guardrail: Arc<crate::guardrail::GuardrailEngine>,
    response_inputs: crate::guardrail::ResponseInputs,
    redaction_map: Vec<tracelane_policy::pii::RedactionEntry>,
    failover_from: Option<&'static str>,
) -> impl futures::Stream<Item = Result<Event, Infallible>> {
    stream! {
        let mut input_tokens = 0u32;
        let mut output_tokens = 0u32;
        // Hoisted to the loop scope so the post-loop span publish (after the
        // loop) can record them. Only the Done event sets them; a pre-Done
        // content-filter block leaves them None (partial — the stream was cut).
        let mut cache_read: Option<u32> = None;
        let mut cache_creation: Option<u32> = None;
        // B-118 #3: set on a mid-stream provider Error so the post-loop span records
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
                    // B-118 #1 (mid-stream sub-path): a TRANSPORT-level stream error
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
                                // Billing fires POST-LOOP (B-110) — see the note there.
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

                        // Billing fires POST-LOOP (B-110) — see the note there.

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
        // B-110: billing used to live INSIDE the match arms, firing only on `Done`
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
            );
            let nats_clone = Arc::clone(nats_client);
            tokio::spawn(async move {
                if let Err(e) = crate::otlp_emit::publish_span(&nats_clone, &span).await {
                    tracing::warn!(error = %e, "span NATS publish failed (streaming)");
                }
            });
        } else {
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
    // B-118 #5: the predictive AFT hit id (observe-first) — threaded onto the published
    // span so the /signatures page shows the tenant's OWN matched signatures instead of
    // demo-seed only. None when no detector matched.
    warn_aft_id: Option<&'static str>,
    guardrail: Arc<crate::guardrail::GuardrailEngine>,
    response_inputs: crate::guardrail::ResponseInputs,
    redaction_map: Vec<tracelane_policy::pii::RedactionEntry>,
    failover_from: Option<&str>,
) -> impl IntoResponse {
    use tracelane_shared::model::MessageContent;

    let mut text = String::new();
    let mut input_tokens = 0u32;
    let mut output_tokens = 0u32;
    let mut cache_read: Option<u32> = None;
    let mut cache_creation: Option<u32> = None;
    // B-118 #3: set on a mid-stream provider error so the span below records status
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
                // path (B-118 #1): an explicit provider error EVENT in a buffered
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
    // the span publish). The span carries NO response body (only tenant/model/
    // tokens), so publishing it here vs. after the seam is identical content —
    // the redaction the seam applies is to `text`, which the span never holds.
    if let Some(ref nats_client) = state.nats {
        let span = build_gateway_span(
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
        );
        let nats = Arc::clone(nats_client);
        tokio::spawn(async move {
            if let Err(e) = crate::otlp_emit::publish_span(&nats, &span).await {
                tracing::warn!(error = %e, "span NATS publish failed");
            }
        });
    } else {
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

    (
        StatusCode::OK,
        Json(serde_json::json!({
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
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt_router::Env;
    use serde_json::json;

    /// Regression: the span provider-attribution mapping had drifted
    /// from the dispatch/key-lookup mapping and stamped most of the providers
    /// as "unknown" on the span. It now delegates to provider_id_for_model.
    #[test]
    fn provider_name_from_model_matches_dispatch_not_unknown() {
        // Groq-family (the B-126 trigger) + other previously-"unknown" providers.
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
        // B-127: an unmatched model attributes "unknown" (never a default provider).
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
    /// `try_stream!`). Drives the `Some(Err)` arm (B-118 #1 mid-stream sub-path).
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
            None,
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
        );
        let resp = Sse::new(sse).into_response();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect SSE body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    // ── B-110: billing must fire on EVERY stream termination path ────────────

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
    /// Polar — we are asserting the CALL SITE fires, which is exactly what B-110
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
        );
        let resp = Sse::new(sse).into_response();
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect SSE body");
        billing_records_spawned() - before
    }

    /// THE B-110 REGRESSION: a stream that ends WITHOUT a `Done` event must still
    /// be metered. This is not hypothetical — Gemini never emits `Done`, it just
    /// ends the stream, so every Gemini streaming request was billed to nobody
    /// while its span recorded the usage. Fails on the pre-fix code, where billing
    /// lived inside the `Done` arm.
    /// B-125 mechanical control: the provider-error response must NEVER emit a
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

    /// B-118 #1 (mid-stream sub-path): a transport sever mid-stream (a `Some(Err)`
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

    /// B-118 #1 + #5: the span builder maps failure reasons to Error status
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

    #[test]
    fn prompt_observation_parses_full_body() {
        let body = json!({
            "model": "claude-sonnet-4-6",
            "tracelane_prompt_version_id": UUID_AB,
            "tracelane_prompt_name": "support-bot",
            "tracelane_prompt_env": "staging"
        });
        let obs = PromptObservation::from_body(&body).expect("should parse");
        assert_eq!(obs.name, "support-bot");
        assert_eq!(obs.env, Env::Staging);
        assert_eq!(obs.version_id, Uuid::parse_str(UUID_AB).unwrap());
    }

    #[test]
    fn prompt_observation_defaults_env_to_production() {
        let body = json!({
            "tracelane_prompt_version_id": UUID_AB,
            "tracelane_prompt_name": "p"
        });
        let obs = PromptObservation::from_body(&body).expect("should parse");
        assert_eq!(obs.env, Env::Production);
    }

    #[test]
    fn prompt_observation_none_without_correlation() {
        // Ad-hoc traffic — no prompt fields → no observation.
        assert!(PromptObservation::from_body(&json!({ "model": "x" })).is_none());
        // version id present but name missing → None.
        assert!(
            PromptObservation::from_body(&json!({ "tracelane_prompt_version_id": UUID_AB }))
                .is_none()
        );
        // Unparseable uuid → None (never feeds a garbage version id).
        assert!(
            PromptObservation::from_body(&json!({
                "tracelane_prompt_version_id": "not-a-uuid",
                "tracelane_prompt_name": "p"
            }))
            .is_none()
        );
    }

    #[test]
    fn parse_prompt_env_known_and_unknown() {
        assert_eq!(parse_prompt_env("dev"), Some(Env::Dev));
        assert_eq!(parse_prompt_env("staging"), Some(Env::Staging));
        assert_eq!(parse_prompt_env("production"), Some(Env::Production));
        assert_eq!(parse_prompt_env("canary"), Some(Env::Canary));
        assert_eq!(parse_prompt_env("bogus"), None);
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
