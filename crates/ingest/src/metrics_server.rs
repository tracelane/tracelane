//! Prometheus exposition for ingest's process-local counters.
//!
//! # Why this exists (A10 / PLT-N1, 2026-08-11)
//!
//! `apps/docs/security/spiffe-ingest.mdx:207-217` publishes two "Recommended
//! Prometheus alerts" against `tracelane_ingest_auth_total`. Until this module,
//! **nothing in the ingest binary exposed a `/metrics` endpoint**, so a self-host
//! operator could wire those rules exactly as documented and get an alert that can
//! never fire — a monitored-looking system that is not monitored. That is a worse
//! failure than no advice at all, because the absence is invisible: a rule matching
//! zero series is silent, not an error.
//!
//! The counters, the five stable label strings and [`auth_metric_snapshot`] all
//! already existed and were built for exactly this — `auth.rs:118-121` says the
//! snapshot is for "(eventually) the Prometheus exporter". This is that exporter,
//! so the published PromQL becomes true **as written**, with no doc edit.
//!
//! # Fail direction: OPEN (CLAUDE.md §10)
//!
//! This is an observability path, not a security path. `run()` therefore **never
//! returns `Err`** — it logs and parks instead. `main.rs` folds six futures into
//! `tokio::try_join!`, where any `Err` aborts *all* of them; a metrics port already
//! in use must not take span ingestion down with it. Spans are the product; the
//! scrape is a convenience.
//!
//! # Exposure
//!
//! Binds `TRACELANE_METRICS_ADDR`, default `127.0.0.1:9464` (the OpenTelemetry
//! Prometheus-exporter convention). Loopback by default so enabling it cannot
//! silently publish a new listener to the world.
//!
//! A non-loopback bind is **warned, not refused** — deliberately. Inside a
//! container, `127.0.0.1` is unreachable from a Prometheus running anywhere else,
//! so refusing would make the endpoint unusable in precisely the deployment the
//! documentation targets. The warning names the exposure so the choice is recorded.
//!
//! # What is NOT here
//!
//! Only ingest-auth counters. No tenant identifiers, no per-tenant series, no span
//! contents — a metrics endpoint is a read surface, and one that is unauthenticated
//! by default must carry nothing tenant-scoped. Adding a per-tenant series here is
//! a tenancy decision, not a metrics decision.

use std::net::SocketAddr;

use axum::{Router, http::header, response::IntoResponse, routing::get};
use tokio::net::TcpListener;

use crate::auth::{AuthResult, auth_metric_snapshot};

/// Default bind. Loopback, and the conventional OTel Prometheus port.
const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9464";

/// The five buckets, in `auth_metric_snapshot()` index order. Kept adjacent to
/// the snapshot call so a reordering there is visible here.
const RESULTS: [AuthResult; 5] = [
    AuthResult::Ok,
    AuthResult::WrongTrustDomain,
    AuthResult::InvalidPath,
    AuthResult::ExpiredSvid,
    AuthResult::NoSvid,
];

/// Render the Prometheus text exposition format (v0.0.4).
///
/// Always emits **all five** series, including zeros. A counter that is absent
/// until first incremented is the classic `rate()` trap: the published
/// `rate(...{result="no_svid"}[5m]) > 1` rule would have no series to evaluate on a
/// healthy system, and would only appear at the moment it fires — indistinguishable,
/// to anyone reading the dashboard beforehand, from a rule that is wired wrong.
pub fn render() -> String {
    let counts = auth_metric_snapshot();
    let mut out = String::with_capacity(512);
    out.push_str("# HELP tracelane_ingest_auth_total SPIFFE authentication outcomes at the ingest OTLP receiver.\n");
    out.push_str("# TYPE tracelane_ingest_auth_total counter\n");
    for (result, count) in RESULTS.iter().zip(counts.iter()) {
        out.push_str("tracelane_ingest_auth_total{result=\"");
        out.push_str(result.label());
        out.push_str("\"} ");
        out.push_str(&count.to_string());
        out.push('\n');
    }
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

/// Resolve the bind address from the environment.
///
/// A malformed `TRACELANE_METRICS_ADDR` falls back to the default **with a warning**
/// rather than failing — same fail-open reasoning as the rest of this module.
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

/// Serve `/metrics` until the process exits.
///
/// # Errors
/// Never. The return type is `anyhow::Result<()>` only so this composes with the
/// other `try_join!` arms in `main.rs`; on any failure it logs and parks forever so
/// a metrics problem cannot abort span ingestion. See the module docs.
pub async fn run() -> anyhow::Result<()> {
    let addr = resolve_addr();

    if !addr.ip().is_loopback() {
        tracing::warn!(
            %addr,
            "ingest /metrics is bound to a NON-LOOPBACK address — it is unauthenticated \
             and reachable by anything that can route to this host. Restrict it at the \
             firewall or the container network."
        );
    }

    let app = Router::new().route("/metrics", get(metrics_handler));

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            // Fail OPEN: ingest keeps running without a scrape endpoint.
            tracing::error!(
                %addr,
                error = %e,
                "failed to bind the ingest metrics port — /metrics is UNAVAILABLE for the \
                 lifetime of this process. Span ingestion is unaffected. Any Prometheus rule \
                 on tracelane_ingest_auth_total will match no series."
            );
            std::future::pending::<()>().await;
            unreachable!("pending() never resolves");
        }
    };

    tracing::info!(%addr, "ingest metrics listening (/metrics, Prometheus text format)");

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(error = %e, "ingest metrics server stopped — /metrics is now UNAVAILABLE");
        std::future::pending::<()>().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_carries_all_five_labels_even_at_zero() {
        let out = render();
        for label in [
            "ok",
            "wrong_trust_domain",
            "invalid_path",
            "expired_svid",
            "no_svid",
        ] {
            assert!(
                out.contains(&format!(
                    "tracelane_ingest_auth_total{{result=\"{label}\"}}"
                )),
                "missing series for result={label}; a rate() rule on it would match nothing:\n{out}"
            );
        }
    }

    #[test]
    fn exposition_has_help_and_type_lines() {
        let out = render();
        assert!(out.contains("# HELP tracelane_ingest_auth_total"));
        assert!(out.contains("# TYPE tracelane_ingest_auth_total counter"));
    }

    /// The metric name and label strings are a PUBLISHED contract
    /// (`apps/docs/security/spiffe-ingest.mdx`). Renaming either silently breaks
    /// every operator's alert rules, so the exact documented query strings are
    /// asserted here as literals.
    #[test]
    fn published_promql_selectors_match_the_exposition() {
        let out = render();
        // From the docs, verbatim:
        //   rate(tracelane_ingest_auth_total{result="no_svid"}[5m]) > 1
        //   increase(tracelane_ingest_auth_total{result="wrong_trust_domain"}[15m]) > 0
        assert!(out.contains(r#"tracelane_ingest_auth_total{result="no_svid"}"#));
        assert!(out.contains(r#"tracelane_ingest_auth_total{result="wrong_trust_domain"}"#));
    }

    /// A metrics endpoint is an unauthenticated read surface by default. Nothing
    /// tenant-scoped may appear in it.
    #[test]
    fn exposition_carries_no_tenant_scoped_series() {
        let out = render();
        assert!(
            !out.contains("tenant"),
            "tenant-scoped data in /metrics:\n{out}"
        );
    }

    #[test]
    fn every_line_is_wellformed_exposition() {
        for line in render().lines() {
            assert!(
                line.starts_with('#') || line.starts_with("tracelane_ingest_auth_total{"),
                "malformed exposition line: {line}"
            );
            if !line.starts_with('#') {
                let value = line.rsplit(' ').next().expect("line has a value field");
                assert!(
                    value.parse::<u64>().is_ok(),
                    "counter value is not an integer: {line}"
                );
            }
        }
    }

    #[test]
    fn malformed_addr_falls_back_instead_of_failing() {
        // Fail-open: a typo in the env var must not be able to stop ingest.
        // (Env is process-global; this asserts the parse branch, not the var.)
        assert!("not-an-addr".parse::<SocketAddr>().is_err());
        assert!(DEFAULT_METRICS_ADDR.parse::<SocketAddr>().is_ok());
    }

    /// The end-to-end proof, and the only test here that could catch a `render()`
    /// that returned a constant: serve the real router on a real socket, scrape it
    /// over real TCP, and assert the counter **moves** in response to a real
    /// `record_auth_result` call. Every assertion above passes against a hardcoded
    /// string; this one does not.
    #[tokio::test]
    async fn live_scrape_reflects_a_real_auth_event() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        let app = Router::new().route("/metrics", get(metrics_handler));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        // `scrape` is defined inline so both reads go through the identical path —
        // a difference between them is then the counter, never the client.
        async fn scrape(addr: SocketAddr) -> String {
            let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
            sock.write_all(
                b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write request");
            let mut buf = String::new();
            sock.read_to_string(&mut buf).await.expect("read response");
            buf
        }

        let before = scrape(addr).await;
        assert!(
            before.contains("200 OK"),
            "metrics endpoint did not return 200:\n{before}"
        );
        assert!(
            before.contains("text/plain; version=0.0.4"),
            "wrong content-type — Prometheus requires the versioned text format:\n{before}"
        );

        let read_bucket = |body: &str, label: &str| -> u64 {
            body.lines()
                .find(|l| {
                    l.starts_with(&format!(
                        "tracelane_ingest_auth_total{{result=\"{label}\"}}"
                    ))
                })
                .and_then(|l| l.rsplit(' ').next().map(str::to_owned))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or_else(|| panic!("no {label} series in scrape:\n{body}"))
        };

        let start = read_bucket(&before, "wrong_trust_domain");
        crate::auth::record_auth_result(AuthResult::WrongTrustDomain);
        let after = scrape(addr).await;
        let end = read_bucket(&after, "wrong_trust_domain");

        assert_eq!(
            end,
            start + 1,
            "the scrape did not observe the auth event — /metrics is not reading live \
             counters (before={start}, after={end})"
        );
    }

    #[test]
    fn default_bind_is_loopback() {
        let addr: SocketAddr = DEFAULT_METRICS_ADDR.parse().expect("valid");
        assert!(
            addr.ip().is_loopback(),
            "the default must not publish a listener beyond this host"
        );
    }
}
