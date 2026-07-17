//! OTLP HTTP receiver — accepts spans from SDK-instrumented agents.
//!
//! Listens on `0.0.0.0:{port}` and handles:
//! - `POST /v1/traces` — OTLP JSON or protobuf trace export
//!
//! Decoded spans are forwarded to the batch writer via an mpsc channel.
//! The receiver never touches ClickHouse directly; all writes go through
//! the channel to maintain backpressure.
//!
//! Target throughput: ≥50K spans/sec on a single Hetzner CCX23 node.
//!
//! ## mTLS (INGEST-002)
//!
//! When a `ServerConfig` is provided to [`run_mtls`] the receiver does
//! manual TLS termination: each TCP accept is followed by a rustls
//! handshake; the peer's leaf certificate is extracted from
//! `peer_certificates()[0]` and injected into the per-request
//! `PeerCertDer` extension. The `require_spiffe_auth` middleware (see
//! `auth.rs`) then verifies the SVID and injects `TenantId`.
//!
//! When no `ServerConfig` is provided ([`run`]), the receiver runs in
//! plaintext mode — used only for local dev. Production deployments
//! must always use [`run_mtls`].

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context as _, Result};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header::HeaderName},
    middleware as axum_middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HttpBuilder,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message as _;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, mpsc},
};
use tokio_rustls::TlsAcceptor;
use tower::Service as _;
use tower_http::trace::TraceLayer;
use tracing::instrument;

use tracelane_shared::TracelaneSpan;

use crate::auth::{AuthResult, PeerCertDer, record_auth_result, require_spiffe_auth};
use crate::cardinality::{CardinalityTracker, Classification, record_overflow};
use crate::disk_guard::{DiskGuard, record_disk_shed};
use crate::limits::{
    self, IngestLimits, RejectReason, WARNING_ENFORCEMENT_DATE, check_payload_pre_decode,
    check_span_post_decode, record_reject,
};
use crate::quota::{QuotaDecision, QuotaNotifier, QuotaTracker, current_period, reset_at_rfc3339};
use crate::tenant_config::TenantConfigCache;
use crate::tls::HANDSHAKE_TIMEOUT;

/// ADR-029 reject reason header. Carries a stable enum string the SDK
/// can match on programmatically.
const TRACELANE_REJECT_REASON_HEADER: &str = "tracelane-reject-reason";
/// ADR-029 soft-warning header — surfaces a future tightening of the
/// limits before enforcement.
const TRACELANE_WARNING_HEADER: &str = "tracelane-warning";

/// Concurrent in-flight mTLS connections allowed by `run_mtls`. The
/// `Semaphore` is acquired before each `tokio::spawn` so a connection
/// flood (SYN flood / rapid reconnect) cannot OOM the process by
/// spawning unbounded tasks.
const MAX_CONCURRENT_CONNECTIONS: usize = 4096;

#[derive(Clone)]
struct ReceiverState {
    span_tx: Arc<mpsc::Sender<crate::span_envelope::SpanEnvelope>>,
    /// ADR-030: per-workspace HyperLogLog++ attribute-key cardinality
    /// tracker. Cheap to clone (internally Arc<DashMap<...>>). V1 ship
    /// path: in-memory only; V1.1 will pass a Postgres-backed clone
    /// constructed via `CardinalityTracker::hydrate_from_postgres`.
    cardinality: CardinalityTracker,
    /// FT-08: disk-pressure flag. `is_shedding()` is a single atomic load on
    /// the hot path; a background task refreshes it.
    disk: DiskGuard,
    /// ADR-048 D4.1: per-tenant config cache — supplies the ingest quota cap +
    /// billing contact (shared with the ClickHouse writer, which reads the
    /// sampling policy from the same cache).
    tenant_cfg: Arc<TenantConfigCache>,
    /// ADR-048 D4.2: per-tenant monthly span quota (the SDK/OTLP-direct cost
    /// backstop).
    quota: Arc<QuotaTracker>,
    /// ADR-048 D5: dedup'd quota-breach notifier.
    notifier: Arc<QuotaNotifier>,
    /// ADR-067 single-tenant self-host: when `Some`, EVERY decoded span is
    /// attributed to this one operator-configured tenant, overriding both the
    /// SPIFFE peer extension AND the resource-attribute fallback. This is what
    /// makes the SPIRE-less path safe: there is exactly one tenant, so a
    /// body-supplied `tracelane.tenant_id` cannot spoof another. `None` = the
    /// hosted path (SPIFFE peer extension, unchanged).
    single_tenant: Option<tracelane_shared::TenantId>,
}

fn build_router(state: ReceiverState) -> Router {
    Router::new()
        .route("/v1/traces", post(traces_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// Start the OTLP HTTP receiver in **plaintext** mode (dev only).
///
/// # Errors
/// Returns `Err` if the socket cannot be bound.
pub async fn run(
    port: u16,
    span_tx: mpsc::Sender<crate::span_envelope::SpanEnvelope>,
    disk: DiskGuard,
    tenant_cfg: Arc<TenantConfigCache>,
    quota: Arc<QuotaTracker>,
    notifier: Arc<QuotaNotifier>,
    single_tenant: Option<tracelane_shared::TenantId>,
) -> Result<()> {
    let state = ReceiverState {
        span_tx: Arc::new(span_tx),
        cardinality: CardinalityTracker::new(),
        disk,
        tenant_cfg,
        quota,
        notifier,
        single_tenant: single_tenant.clone(),
    };
    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    if single_tenant.is_some() {
        tracing::info!(
            %addr,
            "OTLP HTTP receiver listening (PLAINTEXT, single-tenant self-host — every span \
             stamped with the fixed tenant; ADR-067)"
        );
    } else {
        tracing::warn!(%addr, "OTLP HTTP receiver listening (PLAINTEXT — dev only)");
    }

    let listener = TcpListener::bind(addr)
        .await
        .context("failed to bind OTLP receiver port")?;

    axum::serve(listener, app)
        .await
        .context("OTLP receiver error")
}

/// Start the OTLP HTTP receiver in **mTLS** mode.
///
/// Each connection is required to present a valid SPIFFE X.509-SVID
/// chaining to the SPIRE trust bundle. The leaf certificate is
/// extracted post-handshake and inserted as `PeerCertDer` into the
/// request extensions for the `require_spiffe_auth` middleware to
/// consume.
///
/// # Errors
/// Returns `Err` only on bind failure. Per-connection TLS / handshake
/// failures are logged and dropped without affecting the loop.
#[instrument(
    skip(span_tx, server_config, disk, tenant_cfg, quota, notifier),
    fields(port)
)]
pub async fn run_mtls(
    port: u16,
    span_tx: mpsc::Sender<crate::span_envelope::SpanEnvelope>,
    server_config: Arc<rustls::ServerConfig>,
    disk: DiskGuard,
    tenant_cfg: Arc<TenantConfigCache>,
    quota: Arc<QuotaTracker>,
    notifier: Arc<QuotaNotifier>,
) -> Result<()> {
    let state = ReceiverState {
        span_tx: Arc::new(span_tx),
        cardinality: CardinalityTracker::new(),
        disk,
        tenant_cfg,
        quota,
        notifier,
        // mTLS is the hosted, multi-tenant ingest path — tenant comes from the
        // verified SPIFFE peer, never a fixed single tenant (ADR-067's guard
        // refuses to co-enable SPIRE + single-tenant self-host).
        single_tenant: None,
    };
    let app = build_router(state).layer(axum_middleware::from_fn(require_spiffe_auth));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, "OTLP HTTPS receiver listening (mTLS enforced)");

    let listener = TcpListener::bind(addr)
        .await
        .context("failed to bind OTLP receiver port")?;
    let acceptor = TlsAcceptor::from(server_config);
    let http = HttpBuilder::new(TokioExecutor::new());
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        // Acquire BEFORE accept so we apply backpressure at the TCP
        // listener level when at capacity, rather than spawning a task
        // that's immediately blocked.
        let permit = match conn_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                tracing::error!("connection semaphore closed; receiver shutting down");
                return Ok(());
            }
        };

        let (tcp, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                drop(permit);
                tracing::warn!(error = %e, "accept failed; continuing");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let http = http.clone();

        tokio::spawn(async move {
            serve_one(tcp, peer_addr, acceptor, app, http).await;
            drop(permit);
        });
    }
}

async fn serve_one(
    tcp: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    app: Router,
    http: HttpBuilder<TokioExecutor>,
) {
    // Handshake with a timeout to defend against slowloris.
    let tls_stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer_addr, error = %e, "TLS handshake failed");
            // ADR-028: TLS-layer failure means no SVID reached the app layer.
            record_auth_result(AuthResult::NoSvid);
            return;
        }
        Err(_) => {
            tracing::warn!(peer = %peer_addr, timeout_secs = HANDSHAKE_TIMEOUT.as_secs(), "TLS handshake timeout");
            record_auth_result(AuthResult::NoSvid);
            return;
        }
    };

    // Pull the leaf cert out of the completed handshake. Client auth is
    // mandatory in our ServerConfig, so rustls returns at least one cert
    // on a normal handshake. The `None` branch is reachable for resumed
    // sessions if no cert was stashed on the session, so we fail closed
    // there too rather than asserting an invariant.
    let peer_cert_der = match tls_stream.get_ref().1.peer_certificates() {
        Some(certs) if !certs.is_empty() => Bytes::copy_from_slice(certs[0].as_ref()),
        _ => {
            // warn, not info: with mandatory client auth this indicates an
            // neighboring handshake-failure paths so it alerts.
            tracing::warn!(peer = %peer_addr, "post-handshake: no peer certificate available; dropping");
            record_auth_result(AuthResult::NoSvid);
            return;
        }
    };

    // Bridge hyper's `Incoming` body to axum's `Body`, and inject
    // `PeerCertDer` into every request on this connection. Each request
    // gets a fresh clone of the Router (cheap — internally an Arc).
    let app = Arc::new(app);
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let app = app.clone();
        let peer_cert_der = peer_cert_der.clone();
        async move {
            let (parts, body) = req.into_parts();
            let mut req = Request::from_parts(parts, Body::new(body));
            req.extensions_mut().insert(PeerCertDer(peer_cert_der));
            let mut svc = (*app).clone();
            svc.call(req).await
        }
    });

    let io = TokioIo::new(tls_stream);
    if let Err(e) = http.serve_connection(io, svc).await {
        // Cancelled / EOF / GOAWAY are routine; log at debug.
        tracing::debug!(peer = %peer_addr, error = %e, "HTTP connection closed");
    }
}

/// Handle `POST /v1/traces`.
///
/// Accepts OTLP protobuf (`application/x-protobuf`). JSON OTLP is out
/// of scope for V1 — every SDK we ship and every collector we expect
/// to peer with uses protobuf.
///
/// Pipeline:
/// 1. Decode the body via `otlp_decode::decode_otlp_protobuf`.
/// 2. Resolve tenant identity from the SPIFFE-verified
///    `Extension<TenantId>` (mTLS path) or the fallback resource
///    attribute `tracelane.tenant_id` (plaintext dev path).
/// 3. Forward each decoded span to the bounded span_tx channel.
///    `try_send` failure (full channel) returns 503 — backpressure
///    propagates to the SDK which is expected to retry with backoff.
///
/// Returns 200 OK with an empty `ExportTraceServiceResponse` on
/// success (per OTLP §3.2). Returns 401 if no tenant can be
/// resolved, 400 on malformed body, 503 on backpressure.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn traces_handler(
    State(state): State<ReceiverState>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    // Resolve the tenant every span in this batch is attributed to.
    //
    // ADR-067 single-tenant self-host (`state.single_tenant = Some`): the fixed
    // operator-configured tenant OVERRIDES everything — the SPIFFE peer
    // extension AND the resource-attribute `tracelane.tenant_id` fallback are
    // both ignored. Feeding it in as `peer_tenant` means `otlp_decode`'s
    // release-mode tenant-isolation guard is satisfied by a validated identity
    // (the operator's config), never by a body-supplied value — so the hosted
    // security posture in `resolve_tenant` is untouched.
    //
    // Hosted (`None`): the tenant is the SPIFFE-verified `TenantId` the
    // `require_spiffe_auth` middleware inserted into request extensions, exactly
    // as before.
    let peer_tenant: Option<tracelane_shared::TenantId> =
        state.single_tenant.clone().or_else(|| {
            req.extensions()
                .get::<tracelane_shared::TenantId>()
                .cloned()
        });

    // FT-08: disk-pressure shed. Checked FIRST (before reading the body) so a
    // full node sheds cheaply. Single atomic load — no syscall per request.
    // The process does NOT panic or crash; it returns 507 + storage.disk_full
    // so the SDK backs off, while already-ingested data and the ClickHouse
    // read path are unaffected.
    if state.disk.is_shedding() {
        return disk_full_response(peer_tenant.as_ref());
    }

    // ADR-029: resolve per-workspace limits. V1 returns defaults; V1.1
    // will swap to an entitlements-backed lookup once ingest carries a
    // Postgres pool.
    let cap = IngestLimits::for_workspace(&());

    // Pre-decode body-size guard: rejects a 10 MiB base64 dump in <1 µs
    // without ever allocating the protobuf struct. Cap is `max_batch_bytes
    // = max_span_bytes * 8` (8 MiB default).
    //
    // `to_bytes` itself enforces the cap as a fast-path: passing the
    // computed limit instead of a hard-coded 8 MiB makes a future
    // Enterprise tier override (10 MiB span * 8 = 80 MiB batch) a
    // constructor-only change.
    let body = match axum::body::to_bytes(req.into_body(), cap.max_batch_bytes()).await {
        Ok(b) => b,
        Err(_) => {
            return reject_response(
                RejectReason::BatchTooLarge,
                cap.max_batch_bytes() as u64,
                None,
                peer_tenant.as_ref(),
            );
        }
    };

    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "empty body"})),
        )
            .into_response();
    }

    // Belt-and-braces: the `to_bytes` cap should have caught this, but
    // explicit before-decode check makes the criterion bench point at a
    // single named path (`check_payload_pre_decode`) and protects
    // against a future refactor that drops the to_bytes cap.
    if let Err(reason) = check_payload_pre_decode(body.len(), &cap) {
        return reject_response(
            reason,
            cap.max_batch_bytes() as u64,
            Some(body.len() as u64),
            peer_tenant.as_ref(),
        );
    }

    // ADR-029 + ADR-030 post-decode pass — single decode, walk to
    // enforce size caps + cardinality cap, then map. Decoded once;
    // the previous Patch 2 implementation decoded twice and that
    // ~10 µs spend is reclaimed here (queued in Patch 2 TASKLOG as
    // the V1.1 optimisation; collected now alongside the ADR-030
    // mutation requirement).
    let mut pb_req = match ExportTraceServiceRequest::decode(body.as_ref()) {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, "OTLP protobuf decode failed (pre-cap pass)");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": err.to_string()})),
            )
                .into_response();
        }
    };

    // ADR-030: cardinality observation needs a workspace UUID. In
    // production (SPIFFE mTLS), this comes from `peer_tenant`. In
    // debug/plaintext mode there is no SPIFFE peer and we skip
    // cardinality enforcement — release builds require mTLS so this
    // branch is debug-only (matches `otlp_decode::resolve_tenant`'s
    // own debug-only fallback for tenant resolution).
    let workspace_uuid: Option<uuid::Uuid> = peer_tenant.as_ref().map(|t| *t.as_uuid());

    let mut any_warning_band = false;
    for rs in pb_req.resource_spans.iter_mut() {
        for ss in rs.scope_spans.iter_mut() {
            for span in ss.spans.iter_mut() {
                // ADR-029 size pass.
                match check_span_post_decode(span, &cap) {
                    Ok(post) => {
                        if post.in_warning_band {
                            any_warning_band = true;
                        }
                    }
                    Err(reason) => {
                        let observed = match reason {
                            RejectReason::TooManyAttributes => span.attributes.len() as u64,
                            _ => span.encoded_len() as u64,
                        };
                        let limit = match reason {
                            RejectReason::SpanTooLarge => cap.max_span_bytes as u64,
                            RejectReason::AttributeTooLarge => cap.max_attribute_value_bytes as u64,
                            RejectReason::TooManyAttributes => cap.max_attributes_per_span as u64,
                            RejectReason::BatchTooLarge => cap.max_batch_bytes() as u64,
                        };
                        return reject_response(
                            reason,
                            limit,
                            Some(observed),
                            peer_tenant.as_ref(),
                        );
                    }
                }

                // ADR-030 cardinality pass. Only runs when we have an
                // mTLS-attributed tenant; debug-plaintext skips. We
                // walk attributes mutably so an Overflow classification
                // rewrites the key in place to "_overflow" before the
                // span is mapped to TracelaneSpan.
                if let Some(ws_uuid) = workspace_uuid {
                    for kv in span.attributes.iter_mut() {
                        match state.cardinality.observe_and_classify(
                            ws_uuid,
                            &kv.key,
                            cap.max_attr_key_cardinality,
                        ) {
                            Classification::Accepted => {}
                            Classification::Overflow => {
                                let bucket = limits::workspace_bucket(&ws_uuid);
                                record_overflow(bucket);
                                kv.key = "_overflow".to_string();
                            }
                        }
                    }
                }
            }
        }
    }

    // All spans within caps. Map the (possibly mutated) decoded
    // request directly — no second protobuf decode.
    let spans = match crate::otlp_decode::map_otlp_to_tracelane_spans(pb_req, peer_tenant.as_ref())
    {
        Ok(s) => s,
        Err(err) => {
            // Distinguish "no tenant attributable" (401) from "bad
            // protobuf" (400). The decode error context strings carry
            // enough info for this — if the SPIFFE peer was missing
            // AND the resource attribute path failed, that's an auth
            // failure, not a malformed-body failure.
            let msg = err.to_string();
            let is_auth = msg.contains("no SPIFFE peer")
                || msg.contains("is not a valid UUID")
                || msg.contains(crate::otlp_decode::TRACELANE_TENANT_ID_ATTR);
            tracing::warn!(error = %err, "OTLP decode failed");
            let status = if is_auth {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            };
            return (status, Json(serde_json::json!({"error": msg}))).into_response();
        }
    };

    if let Some(t) = spans.first().map(|s| &s.tenant_id) {
        tracing::Span::current().record("tenant_id", tracing::field::display(t));
    }

    // ADR-048 D4.2/D5: per-tenant ingest quota — the cost backstop for the
    // SDK/OTLP-direct path (which bypasses the gateway request quota). Resolve
    // the tenant's monthly span cap from the config cache and HARD-REJECT the
    // whole batch with a typed 429 once the cap is reached (never a silent drop —
    // the #81 class). Fire one dedup'd billing-contact email (fire-and-forget;
    // must not block the 429). `cap == 0` ⇒ unlimited (default until the Postgres
    // resolver supplies a real per-tenant cap).
    if let Some(tenant_uuid) = spans.first().map(|s| *s.tenant_id.as_uuid()) {
        let period = current_period();
        let cfg = state.tenant_cfg.config_for(tenant_uuid).await;
        if let QuotaDecision::Exceeded { used, limit } = state.quota.check_and_add(
            tenant_uuid,
            spans.len() as u64,
            cfg.monthly_span_quota,
            period,
        ) {
            state
                .notifier
                .notify(tenant_uuid, cfg.billing_email.clone(), used, limit);
            return quota_exceeded_response(used, limit, period);
        }
    }

    let n_total = spans.len();
    let mut n_dropped = 0usize;
    for span in spans {
        // OTLP spans carry no ack (push delivery, already 200-ack'd to the SDK).
        if state
            .span_tx
            .try_send(crate::span_envelope::SpanEnvelope::otlp(span))
            .is_err()
        {
            // Bounded channel full — backpressure. We could await
            // until capacity frees, but that holds the request open
            // and amplifies the queue depth. Better: fast-fail and
            // let the SDK retry.
            n_dropped += 1;
        }
    }

    if n_dropped > 0 {
        tracing::warn!(
            n_dropped,
            n_total,
            "OTLP receiver dropped spans due to channel backpressure"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "partial_success": {
                    "rejected_spans": n_dropped,
                    "error_message": "ingest pipeline backpressure",
                }
            })),
        )
            .into_response();
    }

    tracing::debug!(spans = n_total, "OTLP batch ingested");

    // Successful response. Attach the soft-warning header when any
    // span in the batch was over `max_span_bytes / 2` (ADR-029
    // §Soft-warning window).
    let mut resp = (StatusCode::OK, Json(serde_json::json!({}))).into_response();
    if any_warning_band {
        let value = format!("limit-payload-size; enforcement-date={WARNING_ENFORCEMENT_DATE}");
        if let Ok(val) = HeaderValue::from_str(&value) {
            resp.headers_mut()
                .insert(HeaderName::from_static(TRACELANE_WARNING_HEADER), val);
        }
    }
    resp
}

/// Build the ADR-029 reject response.
///
/// Sets `Tracelane-Reject-Reason: <enum>` and a JSON body of shape
/// `{error, reason, limit, observed}`. `observed` is omitted for
/// pre-decode rejects where the figure isn't relevant.
fn reject_response(
    reason: RejectReason,
    limit: u64,
    observed: Option<u64>,
    peer_tenant: Option<&tracelane_shared::TenantId>,
) -> Response {
    let bucket = peer_tenant.map(|t| limits::workspace_bucket(t.as_uuid()));
    record_reject(reason, bucket);

    let status = StatusCode::from_u16(reason.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut body = serde_json::json!({
        "error": "payload_rejected",
        "reason": reason.label(),
        "limit": limit,
    });
    if let Some(o) = observed {
        body["observed"] = serde_json::json!(o);
    }
    let mut resp = (status, Json(body)).into_response();
    if let Ok(val) = HeaderValue::from_str(reason.label()) {
        resp.headers_mut()
            .insert(HeaderName::from_static(TRACELANE_REJECT_REASON_HEADER), val);
    }
    resp
}

/// ADR-048 D5 quota-exceeded response: typed `429 Too Many Requests` with the
/// `{error, limit, used, reset_at, upgrade_url}` body the SDK reacts to. The
/// `reset_at` is the start of next month; `upgrade_url` is env-overridable.
fn quota_exceeded_response(used: u64, limit: u64, period: u32) -> Response {
    let upgrade_url = std::env::var("TRACELANE_UPGRADE_URL")
        .unwrap_or_else(|_| "https://app.tracelane.dev/settings/billing".into());
    let body = serde_json::json!({
        "error": "quota_exceeded",
        "limit": limit,
        "used": used,
        "reset_at": reset_at_rfc3339(period),
        "upgrade_url": upgrade_url,
    });
    (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response()
}

/// FT-08 shed response: `507 Insufficient Storage` with
/// `Tracelane-Reject-Reason: disk_full` and a structured body. Records the
/// shed counter and emits a debug trace (the transition-to-full alert is
/// emitted once by the disk guard, not per request, to avoid log flooding).
fn disk_full_response(peer_tenant: Option<&tracelane_shared::TenantId>) -> Response {
    record_disk_shed();
    tracing::debug!(
        tenant_id = peer_tenant.map(|t| t.to_string()).as_deref().unwrap_or("-"),
        "storage.disk_full=true — shedding OTLP batch with 507 (FT-08)",
    );
    let body = serde_json::json!({
        "error": "insufficient_storage",
        "reason": "disk_full",
        "storage.disk_full": true,
        "retryable": true,
    });
    let mut resp = (StatusCode::INSUFFICIENT_STORAGE, Json(body)).into_response();
    if let Ok(val) = HeaderValue::from_str("disk_full") {
        resp.headers_mut()
            .insert(HeaderName::from_static(TRACELANE_REJECT_REASON_HEADER), val);
    }
    resp
}

#[cfg(test)]
mod tests {
    //! End-to-end HTTP receiver tests via `tower::ServiceExt::oneshot`.
    //! These exercise the full receiver pipeline (decode → tenant
    //! resolution → channel dispatch → response) without booting a
    //! TLS listener. The mTLS-layer tests live in `auth.rs`.

    use super::*;
    use axum::body::{Body as AxumBody, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode};
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue as ProtoAnyValue, KeyValue as ProtoKeyValue, any_value::Value as ProtoValue,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span as ProtoSpan};
    use prost::Message;
    use tower::ServiceExt as _;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap())
    }

    fn sample_protobuf_body(resource_tenant: Option<&str>) -> Vec<u8> {
        let mut resource_attrs = vec![];
        if let Some(t) = resource_tenant {
            resource_attrs.push(ProtoKeyValue {
                key: crate::otlp_decode::TRACELANE_TENANT_ID_ATTR.into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::StringValue(t.into())),
                }),
            });
        }
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: resource_attrs,
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![ProtoSpan {
                        trace_id: vec![1u8; 16],
                        span_id: vec![2u8; 8],
                        name: "chat".into(),
                        start_time_unix_nano: 1_700_000_000_000_000_000,
                        end_time_unix_nano: 1_700_000_001_000_000_000,
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        req.encode_to_vec()
    }

    /// Build a `POST /v1/traces` request carrying the SPIFFE peer tenant as a
    /// request `Extension<TenantId>` — the production mTLS path (what
    /// `require_spiffe_auth` injects post-handshake). Profile-agnostic: the
    /// peer path resolves in BOTH debug and release, unlike the
    /// Use this for tests that need *a* tenant but aren't specifically
    /// exercising the debug fallback.
    fn req_with_peer(body: Vec<u8>) -> HttpRequest<AxumBody> {
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .header("content-type", "application/x-protobuf")
            .body(AxumBody::from(body))
            .unwrap();
        req.extensions_mut().insert(tenant());
        req
    }

    /// Build a `Router` wired to a 16-slot mpsc so tests can assert
    /// what landed on the channel after the receiver decoded.
    fn test_router() -> (
        axum::Router,
        tokio::sync::mpsc::Receiver<crate::span_envelope::SpanEnvelope>,
    ) {
        // Healthy disk: min_free=0 can never shed.
        let disk = DiskGuard::new(std::env::temp_dir(), 0);
        router_with_disk(disk)
    }

    /// Build a router with an explicit `DiskGuard` so FT-08 can drive the
    /// shed path with a guard forced into the full state.
    fn router_with_disk(
        disk: DiskGuard,
    ) -> (
        axum::Router,
        tokio::sync::mpsc::Receiver<crate::span_envelope::SpanEnvelope>,
    ) {
        router_with_disk_and_quota(disk, 0)
    }

    /// Build a router with an explicit disk guard AND a uniform default span
    /// quota (`0` = unlimited) so the quota 429 path can be driven.
    fn router_with_disk_and_quota(
        disk: DiskGuard,
        default_quota: u64,
    ) -> (
        axum::Router,
        tokio::sync::mpsc::Receiver<crate::span_envelope::SpanEnvelope>,
    ) {
        router_with_disk_quota_single_tenant(disk, default_quota, None)
    }

    /// Build a router with an explicit disk guard, default quota, AND an optional
    /// single-tenant self-host override (ADR-067). `Some(t)` stamps every span
    /// with `t` regardless of peer extension / resource attribute.
    fn router_with_disk_quota_single_tenant(
        disk: DiskGuard,
        default_quota: u64,
        single_tenant: Option<TenantId>,
    ) -> (
        axum::Router,
        tokio::sync::mpsc::Receiver<crate::span_envelope::SpanEnvelope>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let state = ReceiverState {
            span_tx: Arc::new(tx),
            cardinality: crate::cardinality::CardinalityTracker::new(),
            disk,
            tenant_cfg: Arc::new(TenantConfigCache::default_with_quota(default_quota)),
            quota: Arc::new(QuotaTracker::new()),
            notifier: Arc::new(QuotaNotifier::new(
                None,
                "alerts@tracelane.dev".into(),
                "https://app.tracelane.dev/settings/billing".into(),
            )),
            single_tenant,
        };
        let app = build_router(state);
        (app, rx)
    }

    /// A router with a finite default span quota for the quota tests.
    fn router_with_quota(
        default_quota: u64,
    ) -> (
        axum::Router,
        tokio::sync::mpsc::Receiver<crate::span_envelope::SpanEnvelope>,
    ) {
        let disk = DiskGuard::new(std::env::temp_dir(), 0);
        router_with_disk_and_quota(disk, default_quota)
    }

    /// FT-08: when the disk guard is shedding, a valid OTLP batch is rejected
    /// with `507 Insufficient Storage` + `Tracelane-Reject-Reason: disk_full`,
    /// the spans are NOT dispatched to the writer channel, and the process
    /// does not panic. A threshold above total capacity (`u64::MAX`)
    /// faithfully simulates a full disk.
    #[tokio::test]
    async fn ft08_disk_full_sheds_batch_with_507() {
        let full_disk = DiskGuard::new(std::env::temp_dir(), u64::MAX);
        assert!(full_disk.is_shedding(), "test precondition: guard is full");
        let before = crate::disk_guard::disk_shed_total();

        let (app, mut rx) = router_with_disk(full_disk);
        let body = sample_protobuf_body(Some("11111111-2222-3333-4444-555555555555"));
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .header("content-type", "application/x-protobuf")
            .body(AxumBody::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(
            resp.headers()
                .get(TRACELANE_REJECT_REASON_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("disk_full"),
        );
        // The batch was shed, not written.
        assert!(
            rx.try_recv().is_err(),
            "no span may reach the writer when shedding"
        );
        assert!(
            crate::disk_guard::disk_shed_total() > before,
            "shed counter must increment",
        );
    }

    /// FT-08 recovery: a healthy disk admits the batch normally (200 + span
    /// dispatched) — the shed path does not regress the happy path.
    #[tokio::test]
    async fn ft08_healthy_disk_admits_batch() {
        let (app, mut rx) = test_router();
        // Peer path (mTLS) so this admits-happy-path test runs in debug AND
        let resp = app
            .oneshot(req_with_peer(sample_protobuf_body(None)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(rx.try_recv().is_ok(), "healthy disk must admit the span");
    }

    /// DEBUG-ONLY: exercises the resource-attribute tenant fallback (dev path),
    /// which release hard-rejects. The release equivalent — that the fallback
    /// is refused, and a peer still wins — is covered by
    /// `otlp_decode::tests::release_build_rejects_resource_attribute_tenant_fallback`
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn e2e_protobuf_with_resource_tenant_dispatches_span() {
        let (app, mut rx) = test_router();
        let body = sample_protobuf_body(Some("11111111-2222-3333-4444-555555555555"));
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .header("content-type", "application/x-protobuf")
            .body(AxumBody::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let span = rx.try_recv().expect("a span must reach the channel").span;
        assert_eq!(span.name, "chat");
        assert_eq!(span.tenant_id, tenant());
    }

    #[tokio::test]
    async fn e2e_protobuf_with_peer_tenant_extension_wins() {
        let (mut app, mut rx) = test_router();

        // Inject the peer tenant via request extension — same path
        // SPIFFE mTLS uses post-handshake. The resource attribute
        // here is a DIFFERENT tenant id; the extension must win.
        let body = sample_protobuf_body(Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .header("content-type", "application/x-protobuf")
            .body(AxumBody::from(body))
            .unwrap();
        req.extensions_mut().insert(tenant());

        let resp = <axum::Router as tower::ServiceExt<_>>::oneshot(app.clone(), req)
            .await
            .unwrap();
        let _ = &mut app;
        assert_eq!(resp.status(), StatusCode::OK);

        let span = rx.try_recv().unwrap().span;
        assert_eq!(span.tenant_id, tenant(), "peer extension must win");
    }

    /// ADR-048 D4.2/D5: once a tenant reaches its monthly span cap, the receiver
    /// HARD-REJECTS the next batch with a typed 429 `quota_exceeded` and does NOT
    /// dispatch it — the observable end-state (a real reject AT the cap, not a
    /// counter increment). The first under-cap batch still flows (200 + dispatch).
    #[tokio::test]
    async fn quota_exceeded_hard_rejects_with_429_and_does_not_dispatch() {
        let (app, mut rx) = router_with_quota(1); // cap = 1 span / month
        // Peer path (mTLS) — same tenant across both batches so the quota

        // First batch (1 span): under cap → 200, span reaches the writer channel.
        let r1 = app
            .clone()
            .oneshot(req_with_peer(sample_protobuf_body(None)))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        assert!(rx.try_recv().is_ok(), "under-cap span must be dispatched");

        // Second batch: tenant is now AT the cap → 429, nothing dispatched.
        let r2 = app
            .oneshot(req_with_peer(sample_protobuf_body(None)))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = to_bytes(r2.into_body(), 2048).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "quota_exceeded");
        assert_eq!(v["limit"], 1);
        assert_eq!(v["used"], 1);
        assert!(
            v["reset_at"].as_str().is_some_and(|s| !s.is_empty()),
            "429 body must advertise reset_at"
        );
        assert!(
            v["upgrade_url"].as_str().is_some(),
            "429 body must carry upgrade_url"
        );
        assert!(
            rx.try_recv().is_err(),
            "an over-quota batch must NOT reach the writer channel"
        );
    }

    /// Unlimited default (cap 0) never 429s — non-regressing on a fresh deploy.
    #[tokio::test]
    async fn quota_cap_zero_never_rejects() {
        let (app, mut rx) = router_with_quota(0);
        for _ in 0..5 {
            // Peer path (mTLS) so the cap-0 quota test runs in both profiles.
            let r = app
                .clone()
                .oneshot(req_with_peer(sample_protobuf_body(None)))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK);
        }
        // All five dispatched.
        for _ in 0..5 {
            assert!(rx.try_recv().is_ok());
        }
    }

    /// ADR-067: single-tenant self-host stamps the ONE configured tenant on every
    /// span, overriding a resource-attribute `tracelane.tenant_id` that claims a
    /// DIFFERENT tenant. Runs in BOTH debug and release (no peer extension, no
    /// resource-attr fallback needed — the override feeds the tenant in as the
    /// validated `peer_tenant`), so it also proves the SPIRE-less path admits a
    /// plaintext batch that the hosted release path would 401.
    #[tokio::test]
    async fn self_host_single_tenant_overrides_and_admits_plaintext_batch() {
        let fixed = TenantId::from_self_host_config(
            Uuid::parse_str("99999999-9999-4999-8999-999999999999").unwrap(),
        );
        let disk = DiskGuard::new(std::env::temp_dir(), 0);
        let (app, mut rx) = router_with_disk_quota_single_tenant(disk, 0, Some(fixed.clone()));

        // Body claims a DIFFERENT tenant via the resource attribute; no peer
        // extension is attached (plaintext self-host).
        let body = sample_protobuf_body(Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .header("content-type", "application/x-protobuf")
            .body(AxumBody::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "self-host must admit the batch"
        );

        let span = rx.try_recv().expect("a span must reach the channel").span;
        assert_eq!(
            span.tenant_id, fixed,
            "self-host must stamp the fixed tenant, ignoring the body's resource attribute"
        );
    }

    #[tokio::test]
    async fn e2e_rejects_request_without_any_tenant_attribution() {
        let (app, _rx) = test_router();
        let body = sample_protobuf_body(None);
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .header("content-type", "application/x-protobuf")
            .body(AxumBody::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn e2e_rejects_empty_body() {
        let (app, _rx) = test_router();
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .body(AxumBody::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn e2e_rejects_malformed_protobuf() {
        let (app, _rx) = test_router();
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .header("content-type", "application/x-protobuf")
            .body(AxumBody::from(&b"definitely not protobuf"[..]))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn e2e_response_body_is_empty_export_trace_service_response() {
        // OTLP §3.2 mandates the success body is an
        // `ExportTraceServiceResponse` — a `partial_success` JSON or
        // an empty object. We return `{}`; downstream consumers (the
        // OTel collector + every SDK we ship) all accept this.
        let (app, _rx) = test_router();
        // Peer path (mTLS) so the response-shape assertion runs in both profiles.
        let resp = app
            .oneshot(req_with_peer(sample_protobuf_body(None)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("body must be valid JSON");
        assert!(parsed.is_object());
    }
}
