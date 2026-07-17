//! Tracelane gateway binary entry point.
//!
//! Initialises structured logging (JSON in prod, pretty in dev), loads config
//! from environment, then delegates to `server::run()`.
//!
//! Set `TRACELANE_LOG_FORMAT=json` for structured production logs.

// Many modules contain scaffolded items awaiting wiring in upcoming milestones.
// Suppress dead_code and unused_imports globally for this binary crate during
// the active development phase.
#![allow(
    dead_code,
    unused_imports,
    clippy::needless_return,
    clippy::collapsible_match,
    clippy::collapsible_if,
    clippy::manual_is_multiple_of
)]

use anyhow::Context as _;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};

mod admin_audit;
mod alerts;
mod audit;
mod audit_export;
mod audit_format;
mod audit_keys;
mod audit_pubkey;
mod audit_retention;
mod audit_self_verify;
mod auth;
mod billing;
mod byok;
mod byok_api;
mod canary;
mod circuit_breaker;
mod clickhouse_query;
mod db;
mod entitlement_cache;
mod guardrail;
mod key_routes;
mod kill_switch;
mod otlp_emit;
mod payment;
mod predictive;
mod pricing;
mod providers;
mod rate_limiter;
mod rejection_metrics;
mod retention_sweep;
// Credential redaction now lives in tracelane_shared::redact so ingest
// can install the same byte-scan layer (A10). Local alias keeps existing
// call sites stable.
use tracelane_shared::redact;
mod server;
mod ssrf_guard;
mod tool_analytics;
mod trace_reads;
mod untrusted_data;

// B1 Prompt Promotion + Eval Gates + Auto-Rollback (ADR-009).
// Always compiled in V1 — product access is gated at runtime via
// `workspace_entitlements` (deny-overrides-grant), NOT a `cfg(feature)`
// flag (CLAUDE.md bans cfg(feature) for product gating). auto_rollback +
// prompt_router carry the EWMA + routing-pointer logic; prompt_routes
// plugs the HTTP endpoints into the server router.
mod auto_rollback;
mod prompt_history;
mod prompt_router;
mod prompt_routes;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = server::Config::from_env().context("failed to load gateway config")?;

    tracing::info!(
        port = config.port,
        log_level = %config.log_level,
        "tracelane gateway starting"
    );

    server::run(config).await.context("gateway server error")
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,gateway=debug,tracelane=debug"));

    // JSON in prod (TRACELANE_LOG_FORMAT=json), pretty in dev.
    // All writers are wrapped in RedactingMakeWriter to scrub credentials
    // (Authorization, x-api-key, sk-*, org-*, AKIA*) before they hit disk.
    let use_json = std::env::var("TRACELANE_LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false);

    if use_json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .json()
                    .with_writer(redact::RedactingMakeWriter::new(std::io::stdout)),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .pretty()
                    .with_writer(redact::RedactingMakeWriter::new(std::io::stdout)),
            )
            .init();
    }
}
