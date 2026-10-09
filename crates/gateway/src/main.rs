//! Tracelane gateway binary entry point.
//!
//! Initialises structured logging (JSON in prod, pretty in dev), loads config
//! from environment, then delegates to `server::run()`.
//!
//! Set `TRACELANE_LOG_FORMAT=json` for structured production logs.

use anyhow::Context as _;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};

// B-385: the ONE admission pipeline the three dispatch routes run.
mod admin_audit;
mod admission;
mod agent_loops;
mod alerts;
mod annotation_routes;
mod anthropic_messages;
mod audit;
mod audit_consumer;
mod audit_export;
mod audit_format;
mod audit_keys;
mod audit_ledger_range;
mod audit_pubkey;
mod audit_retention;
mod audit_self_verify;
mod auth;
mod billing;
mod budgets;
mod byok;
mod byok_api;
mod byok_rotate;
mod circuit_breaker;
mod clickhouse_query;
mod control_plane;
mod control_routes;
mod controls;
mod dataset_routes;
mod db;
mod entitlement_cache;
mod experiment_routes;
mod files_batches;
mod gemini_native;
mod guardrail;
mod incident_routes;
mod media_common;
mod media_routes;
mod multipart_scan;
mod openai_responses;
mod outcome_routes;
mod passthrough;
mod realtime;
mod regression_routes;
// B-385 (2c): the in-process handler harness. Test-only by construction, and
// `debug_assertions`-gated like `providers::smoke_tests` — the loopback SSRF
// bypass it drives exists only in debug builds (`ssrf_guard.rs` says why a
// bare `cfg(test)` would break the bench profile).
#[cfg(all(test, debug_assertions))]
mod handler_harness;
// OG-34 / OG-36: the admin-plane gate on the existing control routes (uses the harness).
#[cfg(all(test, debug_assertions))]
mod og36_control_route_tests;
// `OG-91` layer 1: real-client request shapes (Claude Code, Codex, Gemini CLI) replayed through the
// real relays against a scripted upstream. Same cfg gate as the harness it drives.
#[cfg(all(test, debug_assertions))]
mod client_conformance_tests;
// `OG-20`: the per-key policy on every dispatch route, at the one step that enforces it.
mod health_probe;
mod hotpath;
#[cfg(all(test, debug_assertions))]
mod key_policy_route_tests;
// OG-21 / OG-22 / OG-25: limits, budgets, pause and blocks at the admission steps.
mod key_routes;
mod kill_switch;
mod kms;
mod kya_identity;
mod kya_routes;
mod limits;
mod metrics;
mod model_alias_routes;
mod models_list;
mod notification_routes;
#[cfg(all(test, debug_assertions))]
mod og51_cache_tests;
#[cfg(all(test, debug_assertions))]
mod og_controls_tests;
mod otel_export;
mod otel_export_routes;
// OG-11: the routing document through the real handlers.
#[cfg(all(test, debug_assertions))]
mod og11_routing_tests;
mod otlp_emit;
mod payment;
mod preauth_limiter;
mod predictive;
mod pricing;
mod project_routes;
mod provider_key_validate;
mod providers;
mod rate_limiter;
mod rejection_metrics;
mod request_support;
mod rescue;
mod retention_sweep;
#[cfg(all(test, debug_assertions))]
mod rev5_tests;
#[cfg(all(test, debug_assertions))]
mod rev6_tests;
/// `OG-11`/`OG-12`/`OG-13`: the workspace routing document and the dispatch plan.
mod routing;
mod spend_causes;
mod spend_spikes;
mod workspace_capture_routes;
mod workspace_glance;
// Credential redaction now lives in tracelane_shared::redact so ingest
// can install the same byte-scan layer (A10). Local alias keeps existing
// call sites stable.
use tracelane_shared::redact;
mod generation_issues;
mod server;
mod spans_stream;
mod spend;
mod spend_alerts;
mod ssrf_guard;
mod strict_json;
mod tool_analytics;
mod tool_fingerprint;
mod trace_context;
mod trace_ingest;
mod trace_reads;
mod unit_pricing;
mod untrusted_data;
mod usage_breakdown;

// B1 Prompt Promotion + Eval Gates + Auto-Rollback (ADR-009).
// Always compiled in V1 — product access is gated at runtime via
// `workspace_entitlements` (deny-overrides-grant), NOT a `cfg(feature)`
// flag (CLAUDE.md bans cfg(feature) for product gating). auto_rollback +
// prompt_router carry the EWMA + routing-pointer logic; prompt_routes
// plugs the HTTP endpoints into the server router.
mod auto_rollback;
mod cache_controls;
mod cache_routes;
mod offpath;
mod online_eval;
mod online_eval_routes;
mod openapi_route;
mod prompt_eval;
mod prompt_history;
mod prompt_router;
mod prompt_routes;
mod semantic_cache;
mod zdr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--selftest-workspace-glance") {
        anyhow::ensure!(
            billing::rating::WorkspaceGlancePolicy::selftest(),
            "workspace glance defaults differ from plans.v3.json or stale value passed"
        );
        println!("workspace glance defaults match seed; planted stale value refused");
        return Ok(());
    }
    crate::kya_identity::initialize()?;
    // SRE register #45 — the container HEALTHCHECK (`gateway --health-probe`).
    // Before tracing and before config: a probe must not depend on anything but
    // the port, and must not emit a log line every 30 s.
    if std::env::args().nth(1).as_deref() == Some("--health-probe") {
        let port = std::env::var("TRACELANE_PORT").unwrap_or_else(|_| "8080".into());
        return health_probe::run(&format!("http://127.0.0.1:{port}/health")).await;
    }

    init_tracing();

    // B-383 (a): `gateway byok-rotate [--dry-run]` — re-wrap every BYOK row under
    // the active KEK, then exit. Same env, same pool, no listener.
    if std::env::args().nth(1).as_deref() == Some("byok-rotate") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        return byok_rotate::main(&rest).await;
    }

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
