//! Prometheus exposition for the gateway (B-389, 2026-09-12).
//!
//! # Why this exists
//!
//! The independent review (2026-09-12) put it plainly: the gateway exposed
//! **zero** Prometheus series while ingest exposed five, and `/health` is a
//! point-in-time JSON snapshot that only the on-node watchdog reads. Rate,
//! errors and latency over time — the three questions a production readiness
//! review asks first — had no answer that did not involve reading logs.
//!
//! Same shape as `crates/ingest/src/metrics_server.rs`, deliberately: a second
//! loopback listener (`TRACELANE_METRICS_ADDR`, default `127.0.0.1:9465` —
//! ingest owns 9464), hand-rendered text (no `prometheus` crate; the ingest
//! precedent and the supply-chain rule both argue against a dependency for
//! ~150 lines), fail-OPEN (a bind failure logs and parks; the product is the
//! proxy, not the scrape).
//!
//! **NOT mounted on the `:8080` router.** That port is fronted by Caddy → the
//! world, and a metrics endpoint is an unauthenticated read surface. Compose
//! publishes the metrics port on `127.0.0.1` only.
//!
//! # What is NOT here
//!
//! No tenant label on any series — the ingest rule, for the same reason: an
//! unauthenticated surface must carry nothing tenant-scoped, and a per-tenant
//! series is a tenancy decision, not a metrics decision. Route labels are the
//! MATCHED axum template (`/v1/traces/{trace_id}/spans`), never the raw path:
//! a raw path puts trace ids and caller-controlled strings into a label set.
//!
//! Every series is emitted on every scrape with all its label values, zeros
//! included — the `rate()`-on-an-absent-series trap (`metrics_server.rs`).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::{Router, extract::MatchedPath, http::header, response::IntoResponse, routing::get};
use tokio::net::TcpListener;

/// Default bind. Loopback; ingest's exporter sits on 9464.
const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9465";

/// The routes that get their own label. Anything else is `other`, so a scan of
/// random paths cannot grow the label set (bounded cardinality by construction).
const ROUTES: [&str; 12] = [
    "/health",
    "/v1/chat/completions",
    "/v1/messages",
    "/v1/messages/count_tokens",
    "/v1/embeddings",
    "/v1/traces",
    "/v1/traces/{trace_id}/spans",
    "/v1/sessions",
    "/v1/audit/export",
    "/v1/audit/self-verify",
    "/v1/prompts",
    "/v1/keys",
];
const OTHER: usize = ROUTES.len();
const ROUTE_SLOTS: usize = ROUTES.len() + 1;

const STATUS_CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

/// Histogram buckets for the head-of-response time, in seconds. For a stream
/// this is time-to-first-byte; the body is not under it.
const BUCKETS_S: [f64; 14] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

struct RouteStats {
    requests: [AtomicU64; 5],
    /// Cumulative bucket counts (Prometheus `le` semantics) + `+Inf`.
    buckets: [AtomicU64; 15],
    sum_us: AtomicU64,
    count: AtomicU64,
}

impl RouteStats {
    const fn new() -> Self {
        Self {
            requests: [const { AtomicU64::new(0) }; 5],
            buckets: [const { AtomicU64::new(0) }; 15],
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

static ROUTE_STATS: [RouteStats; ROUTE_SLOTS] = [
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
    RouteStats::new(),
];
const _: () = assert!(ROUTE_STATS.len() == ROUTE_SLOTS);

static INFLIGHT: AtomicU64 = AtomicU64::new(0);
static LOAD_SHED_TOTAL: AtomicU64 = AtomicU64::new(0);
static REQUEST_TIMEOUT_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Which slot a matched route template maps to.
#[must_use]
pub(crate) fn route_slot(matched: Option<&str>) -> usize {
    matched
        .and_then(|m| ROUTES.iter().position(|r| *r == m))
        .unwrap_or(OTHER)
}

fn status_class(status: u16) -> usize {
    match status / 100 {
        1 => 0,
        2 => 1,
        3 => 2,
        4 => 3,
        _ => 4,
    }
}

/// Record one finished request. Called by the middleware; pure bookkeeping.
pub(crate) fn record(slot: usize, status: u16, elapsed_us: u64) {
    let s = &ROUTE_STATS[slot.min(OTHER)];
    s.requests[status_class(status)].fetch_add(1, Ordering::Relaxed);
    let secs = elapsed_us as f64 / 1_000_000.0;
    for (i, le) in BUCKETS_S.iter().enumerate() {
        if secs <= *le {
            s.buckets[i].fetch_add(1, Ordering::Relaxed);
        }
    }
    s.buckets[BUCKETS_S.len()].fetch_add(1, Ordering::Relaxed);
    s.sum_us.fetch_add(elapsed_us, Ordering::Relaxed);
    s.count.fetch_add(1, Ordering::Relaxed);
}

/// Counted by the admission layer when it sheds a request (503).
pub(crate) fn note_load_shed() {
    LOAD_SHED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Counted by the admission layer when a request times out (408).
pub(crate) fn note_request_timeout() {
    REQUEST_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// The `:8080` router's request middleware: in-flight gauge, per-route
/// counters and the head-of-response histogram. Two atomics and an `Instant`
/// per request; nothing here allocates on the hot path except the label
/// lookup, which is a 12-entry scan.
pub(crate) async fn track(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let slot = route_slot(
        req.extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
    );
    INFLIGHT.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let resp = next.run(req).await;
    INFLIGHT.fetch_sub(1, Ordering::Relaxed);
    let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    record(slot, resp.status().as_u16(), elapsed_us);
    resp
}

fn route_label(slot: usize) -> &'static str {
    ROUTES.get(slot).copied().unwrap_or("other")
}

/// Render the Prometheus text exposition format (v0.0.4).
#[must_use]
pub fn render() -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(16 * 1024);

    out.push_str("# HELP tracelane_gateway_http_requests_total Requests finished, by matched route template and status class.\n# TYPE tracelane_gateway_http_requests_total counter\n");
    for (slot, stats) in ROUTE_STATS.iter().enumerate() {
        for (ci, class) in STATUS_CLASSES.iter().enumerate() {
            let _ = writeln!(
                out,
                "tracelane_gateway_http_requests_total{{route=\"{}\",status_class=\"{}\"}} {}",
                route_label(slot),
                class,
                stats.requests[ci].load(Ordering::Relaxed)
            );
        }
    }

    out.push_str("# HELP tracelane_gateway_http_request_duration_seconds Head-of-response time by matched route (time to first byte for a stream).\n# TYPE tracelane_gateway_http_request_duration_seconds histogram\n");
    for (slot, s) in ROUTE_STATS.iter().enumerate() {
        let r = route_label(slot);
        for (i, le) in BUCKETS_S.iter().enumerate() {
            let _ = writeln!(
                out,
                "tracelane_gateway_http_request_duration_seconds_bucket{{route=\"{r}\",le=\"{le}\"}} {}",
                s.buckets[i].load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "tracelane_gateway_http_request_duration_seconds_bucket{{route=\"{r}\",le=\"+Inf\"}} {}",
            s.buckets[BUCKETS_S.len()].load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "tracelane_gateway_http_request_duration_seconds_sum{{route=\"{r}\"}} {}",
            s.sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0
        );
        let _ = writeln!(
            out,
            "tracelane_gateway_http_request_duration_seconds_count{{route=\"{r}\"}} {}",
            s.count.load(Ordering::Relaxed)
        );
    }

    let gauge = |out: &mut String, name: &str, help: &str, v: u64| {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
    };
    let counter = |out: &mut String, name: &str, help: &str, v: u64| {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}"
        );
    };

    gauge(
        &mut out,
        "tracelane_gateway_http_inflight",
        "Requests currently inside the router.",
        INFLIGHT.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "tracelane_gateway_load_shed_total",
        "Requests refused with 503 by the concurrency limit.",
        LOAD_SHED_TOTAL.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "tracelane_gateway_request_timeout_total",
        "Requests cut with 408 by the head-of-response timeout.",
        REQUEST_TIMEOUT_TOTAL.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "tracelane_gateway_auth_throttled_total",
        "Requests refused with 429 before authentication because their source exceeded the failed-auth budget.",
        crate::preauth_limiter::AUTH_THROTTLED_TOTAL.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "tracelane_gateway_auth_negative_cache_hits_total",
        "API-key lookups answered as a miss from the negative cache without a store round trip.",
        crate::db::api_keys::AUTH_NEGATIVE_HIT_TOTAL.load(Ordering::Relaxed),
    );

    use tracelane_shared::degradation::{Degradation, count};
    counter(
        &mut out,
        "tracelane_gateway_spans_dropped_total",
        "Spans lost because publish was unavailable or failed (the /health spans_dropped figure).",
        count(Degradation::SpansDroppedNoNats) + count(Degradation::SpanPublishFailed),
    );
    gauge(
        &mut out,
        "tracelane_gateway_span_publish_in_flight",
        "Span publishes awaiting their JetStream ack.",
        crate::otlp_emit::in_flight() as u64,
    );
    counter(
        &mut out,
        "tracelane_gateway_streams_finalized_on_drop_total",
        "Streams whose client hung up mid-stream; the span was recorded by the Drop finalizer.",
        crate::server::STREAMS_FINALIZED_ON_DROP.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "tracelane_gateway_requests_cancelled_in_dispatch_total",
        "Requests whose client hung up while the provider was still being awaited.",
        crate::server::REQUESTS_CANCELLED_IN_DISPATCH.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "tracelane_gateway_auth_stale_served_total",
        "Requests served from a stale auth cache while the control plane was re-checked.",
        crate::db::api_keys::AUTH_STALE_SERVED_TOTAL.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "tracelane_gateway_entitlement_stale_served_total",
        "Requests served from a stale entitlement cache while the control plane was re-checked.",
        crate::entitlement_cache::STALE_SERVED_TOTAL.load(Ordering::Relaxed),
    );
    // ADR-069 property 3 — the "loud" audit-publish counters, which existed
    // since the async ledger shipped and were read by NOTHING until B-390
    // removed the crate-wide dead-code allow.
    let (audit_ok, audit_failed) = crate::audit::audit_publish_stats();
    out.push_str("# HELP tracelane_gateway_audit_publish_total Ledger events handed to JetStream, by outcome (a failed publish is a 503 to the caller).\n# TYPE tracelane_gateway_audit_publish_total counter\n");
    let _ = writeln!(
        out,
        "tracelane_gateway_audit_publish_total{{outcome=\"ok\"}} {audit_ok}"
    );
    let _ = writeln!(
        out,
        "tracelane_gateway_audit_publish_total{{outcome=\"failed\"}} {audit_failed}"
    );
    counter(
        &mut out,
        "tracelane_gateway_prompt_guard_fail_opens_total",
        "PromptGuard sidecar calls that failed open.",
        crate::predictive::prompt_guard::fail_opens_total(),
    );

    out.push_str("# HELP tracelane_gateway_degraded_total Fail-open occurrences by kind (see /health.degraded).\n# TYPE tracelane_gateway_degraded_total counter\n");
    for kind in Degradation::all() {
        let _ = writeln!(
            out,
            "tracelane_gateway_degraded_total{{kind=\"{}\"}} {}",
            kind.as_str(),
            count(kind)
        );
    }

    let b = crate::audit_consumer::backlog_snapshot();
    out.push_str("# HELP tracelane_gateway_audit_backlog Audit JetStream backlog by state.\n# TYPE tracelane_gateway_audit_backlog gauge\n");
    let _ = writeln!(
        out,
        "tracelane_gateway_audit_backlog{{state=\"pending\"}} {}",
        b.pending
    );
    let _ = writeln!(
        out,
        "tracelane_gateway_audit_backlog{{state=\"ack_pending\"}} {}",
        b.ack_pending
    );
    gauge(
        &mut out,
        "tracelane_gateway_audit_backlog_healthy",
        "1 when the audit backlog is under threshold AND the reading is fresh; 0 otherwise (stale counts as unhealthy).",
        u64::from(b.healthy),
    );
    out
}

async fn metrics_handler() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render(),
    )
}

/// Resolve the bind address; a malformed value falls back with a warning
/// (fail-open, like the rest of this module).
fn resolve_addr() -> SocketAddr {
    let raw = std::env::var("TRACELANE_METRICS_ADDR")
        .unwrap_or_else(|_| DEFAULT_METRICS_ADDR.to_string());
    match raw.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            tracing::warn!(
                value = %raw,
                error = %e,
                default = DEFAULT_METRICS_ADDR,
                "TRACELANE_METRICS_ADDR is not a valid socket address — using the default"
            );
            DEFAULT_METRICS_ADDR
                .parse()
                .expect("compile-time constant address parses")
        }
    }
}

/// Serve `/metrics` until the process exits. **Never returns `Err`** — an
/// observability listener must not take the proxy down with it.
pub async fn run() {
    let addr = resolve_addr();
    if !addr.ip().is_loopback() {
        tracing::warn!(
            %addr,
            "gateway /metrics is bound to a NON-LOOPBACK address — it is unauthenticated \
             and carries process-wide counters; make sure only your scraper can reach it"
        );
    }
    let app = Router::new().route("/metrics", get(metrics_handler));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                %addr,
                error = %e,
                "failed to bind the gateway metrics port — /metrics is UNAVAILABLE for the \
                 life of this process; the proxy is unaffected"
            );
            std::future::pending::<()>().await;
            unreachable!()
        }
    };
    tracing::info!(%addr, "gateway metrics listening (/metrics, Prometheus text format)");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(error = %e, "gateway metrics server stopped — /metrics is now UNAVAILABLE");
    }
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_series_is_present_with_zeros_before_any_traffic() {
        let text = render();
        for r in ROUTES.iter().chain(std::iter::once(&"other")) {
            for c in STATUS_CLASSES {
                assert!(
                    text.contains(&format!(
                        "tracelane_gateway_http_requests_total{{route=\"{r}\",status_class=\"{c}\"}} "
                    )),
                    "missing series for {r}/{c}"
                );
            }
            assert!(text.contains(&format!(
                "tracelane_gateway_http_request_duration_seconds_bucket{{route=\"{r}\",le=\"+Inf\"}} "
            )));
        }
        for name in [
            "tracelane_gateway_http_inflight ",
            "tracelane_gateway_load_shed_total ",
            "tracelane_gateway_request_timeout_total ",
            "tracelane_gateway_auth_throttled_total ",
            "tracelane_gateway_auth_negative_cache_hits_total ",
            "tracelane_gateway_spans_dropped_total ",
            "tracelane_gateway_span_publish_in_flight ",
            "tracelane_gateway_streams_finalized_on_drop_total ",
            "tracelane_gateway_requests_cancelled_in_dispatch_total ",
            "tracelane_gateway_audit_backlog{state=\"pending\"} ",
            "tracelane_gateway_audit_backlog_healthy ",
            "tracelane_gateway_audit_publish_total{outcome=\"ok\"} ",
            "tracelane_gateway_audit_publish_total{outcome=\"failed\"} ",
        ] {
            assert!(text.contains(name), "missing {name}");
        }
        // Every degradation kind, zeros included.
        for kind in tracelane_shared::degradation::Degradation::all() {
            assert!(text.contains(&format!(
                "tracelane_gateway_degraded_total{{kind=\"{}\"}} ",
                kind.as_str()
            )));
        }
        // No tenant-shaped label anywhere: no `tenant_id=` label key and no
        // UUID-shaped value. (`tenant_config_fault` is a degradation KIND name
        // and carries no tenant.)
        assert!(
            !text.contains("tenant_id="),
            "a tenant label on an unauthenticated surface"
        );
        let uuid_like = regex_lite_uuid(&text);
        assert!(
            !uuid_like,
            "a UUID-shaped value on an unauthenticated surface:\n{text}"
        );
    }

    /// `8-4-4-4-12` hex with dashes, without pulling in a regex crate.
    fn regex_lite_uuid(text: &str) -> bool {
        text.split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
            .any(|tok| {
                tok.len() == 36
                    && tok.split('-').map(str::len).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
            })
    }

    #[test]
    fn record_increments_exactly_one_counter_and_the_right_buckets() {
        let slot = route_slot(Some("/v1/keys"));
        assert_eq!(ROUTES[slot], "/v1/keys");
        let before_2xx = ROUTE_STATS[slot].requests[1].load(Ordering::Relaxed);
        let before_4xx = ROUTE_STATS[slot].requests[3].load(Ordering::Relaxed);
        let before_le_10ms = ROUTE_STATS[slot].buckets[2].load(Ordering::Relaxed);
        let before_le_1ms = ROUTE_STATS[slot].buckets[0].load(Ordering::Relaxed);
        let before_inf = ROUTE_STATS[slot].buckets[BUCKETS_S.len()].load(Ordering::Relaxed);
        record(slot, 201, 7_000); // 7 ms
        assert_eq!(
            ROUTE_STATS[slot].requests[1].load(Ordering::Relaxed),
            before_2xx + 1
        );
        assert_eq!(
            ROUTE_STATS[slot].requests[3].load(Ordering::Relaxed),
            before_4xx
        );
        assert_eq!(
            ROUTE_STATS[slot].buckets[0].load(Ordering::Relaxed),
            before_le_1ms,
            "7 ms is not <= 1 ms"
        );
        assert_eq!(
            ROUTE_STATS[slot].buckets[2].load(Ordering::Relaxed),
            before_le_10ms + 1,
            "7 ms is <= 10 ms"
        );
        assert_eq!(
            ROUTE_STATS[slot].buckets[BUCKETS_S.len()].load(Ordering::Relaxed),
            before_inf + 1
        );
    }

    #[test]
    fn unmatched_and_unknown_routes_fold_into_other() {
        assert_eq!(route_slot(None), OTHER);
        assert_eq!(
            route_slot(Some("/v1/traces/abc-123/spans")),
            OTHER,
            "a RAW path never gets its own label"
        );
        assert_eq!(route_slot(Some("/definitely/not/a/route")), OTHER);
        assert_eq!(
            ROUTES[route_slot(Some("/v1/traces/{trace_id}/spans"))],
            "/v1/traces/{trace_id}/spans"
        );
    }

    #[test]
    fn histogram_buckets_are_monotone_after_traffic() {
        let slot = route_slot(Some("/v1/prompts"));
        for us in [500, 3_000, 40_000, 2_000_000] {
            record(slot, 200, us);
        }
        let s = &ROUTE_STATS[slot];
        let mut prev = 0;
        for b in &s.buckets {
            let v = b.load(Ordering::Relaxed);
            assert!(v >= prev, "cumulative buckets must not decrease");
            prev = v;
        }
    }

    #[test]
    fn status_classes_cover_every_code() {
        assert_eq!(status_class(100), 0);
        assert_eq!(status_class(204), 1);
        assert_eq!(status_class(301), 2);
        assert_eq!(status_class(429), 3);
        assert_eq!(status_class(503), 4);
        assert_eq!(status_class(999), 4);
    }
}
