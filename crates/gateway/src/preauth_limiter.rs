//! Pre-auth throttle: a source that keeps failing authentication is refused
//! BEFORE its next request reaches the auth store (B-383 f, 2026-09-12).
//!
//! # Why
//!
//! Every `tlane_` string a caller sends costs a peppered-HMAC lookup and, on a
//! miss, a Neon round trip (bounded now by the negative cache in
//! `db::api_keys`, which remembers a miss for 30 s). Nothing stopped a source
//! from sending a NEW random key per request, which the negative cache cannot
//! absorb. This layer counts 401s per source over a one-minute window and, past
//! [`DEFAULT_FAILURES_PER_MINUTE`], answers 429 without calling the handler at
//! all — no HMAC, no lookup, no Postgres.
//!
//! # What it is not
//!
//! Not a request rate limit (that is per-tenant, after auth, in
//! `rate_limiter.rs`) and not a security gate a valid key ever meets: only 401
//! responses count, a 200 never does, and a valid key from a throttled source
//! is refused only for the remainder of that source's window — the price of
//! sharing an egress IP with a scanner, stated rather than hidden.
//!
//! # The source
//!
//! Behind Caddy the peer address is always Caddy's, so the source is
//! `cf-connecting-ip` (Cloudflare fronts the edge), else the first hop of
//! `x-forwarded-for`, else `unknown` — one bucket shared by every caller that
//! arrives without either header, which can only happen on a direct on-node
//! request. Fail-OPEN by construction (`.claude/rules/security.md` §10): a
//! limiter that cannot count lets the request through to the real auth.
//!
//! **Precondition, stated (security review M-2, 2026-09-12):** `cf-connecting-ip`
//! is only trustworthy because the origin accepts :443 from Cloudflare's edge
//! ranges alone (Hetzner firewall `tl-fw`, `infra/prod/docker-compose.yml`) and
//! Cloudflare overwrites the header with the true client address. On a
//! deployment whose origin is reachable directly, a client can send a fresh
//! `cf-connecting-ip` per request and this throttle keys on whatever it says —
//! a self-host without that origin lock should key on its own terminator's
//! peer address instead. The `x-forwarded-for` fallback is for on-node probes
//! and is forgeable by construction; it is never the key for edge traffic.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;

/// Failed authentications a single source may accumulate per window before
/// its next request is refused. Sixty is one per second sustained — an order
/// of magnitude above any client retrying a stale key, an order below a scan.
pub const DEFAULT_FAILURES_PER_MINUTE: u32 = 60;
/// The counting window.
pub const WINDOW: Duration = Duration::from_secs(60);
/// Sources tracked at once. Past this the stale half is evicted; a scanner
/// rotating source addresses spends its own budget growing the map, not ours.
const MAX_SOURCES: usize = 100_000;

/// Requests refused by this layer (the `/metrics` series).
pub static AUTH_THROTTLED_TOTAL: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct Bucket {
    window_start: Instant,
    failures: u32,
}

/// The per-source failure ledger. `Clone` is cheap (one `Arc`).
#[derive(Clone)]
pub struct PreAuthLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    limit: u32,
    buckets: DashMap<String, Bucket>,
}

impl PreAuthLimiter {
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            inner: Arc::new(Inner {
                limit: limit.max(1),
                buckets: DashMap::new(),
            }),
        }
    }

    /// `TRACELANE_AUTH_FAILURES_PER_MINUTE`, else the default; garbage or zero
    /// falls back with a warning (fail-open: a typo must not throttle everyone).
    #[must_use]
    pub fn from_env() -> Self {
        let limit = std::env::var("TRACELANE_AUTH_FAILURES_PER_MINUTE")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| {
                if std::env::var("TRACELANE_AUTH_FAILURES_PER_MINUTE").is_ok() {
                    tracing::warn!(
                        default = DEFAULT_FAILURES_PER_MINUTE,
                        "TRACELANE_AUTH_FAILURES_PER_MINUTE is not a positive integer — using the default"
                    );
                }
                DEFAULT_FAILURES_PER_MINUTE
            });
        Self::new(limit)
    }

    /// Is this source over its window's budget right now? Pure with respect to
    /// the request; the window rolls here.
    pub fn is_throttled(&self, source: &str, now: Instant) -> bool {
        match self.inner.buckets.get_mut(source) {
            None => false,
            Some(mut b) => {
                if now.duration_since(b.window_start) >= WINDOW {
                    b.window_start = now;
                    b.failures = 0;
                    false
                } else {
                    b.failures >= self.inner.limit
                }
            }
        }
    }

    /// Record one failed authentication from `source`.
    pub fn note_failure(&self, source: &str, now: Instant) {
        if self.inner.buckets.len() >= MAX_SOURCES {
            // Evict everything whose window has passed; if that frees nothing
            // (a burst of fresh sources), the newest simply is not tracked —
            // fail-open, never a refusal born of the ledger being full.
            self.inner
                .buckets
                .retain(|_, b| now.duration_since(b.window_start) < WINDOW);
            if self.inner.buckets.len() >= MAX_SOURCES {
                return;
            }
        }
        let mut b = self
            .inner
            .buckets
            .entry(source.to_owned())
            .or_insert(Bucket {
                window_start: now,
                failures: 0,
            });
        if now.duration_since(b.window_start) >= WINDOW {
            b.window_start = now;
            b.failures = 0;
        }
        b.failures = b.failures.saturating_add(1);
    }
}

/// The source key for a request: `cf-connecting-ip`, else the first hop of
/// `x-forwarded-for`, else `unknown`.
#[must_use]
pub fn source_of(headers: &HeaderMap) -> String {
    if let Some(v) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        let v = v.trim();
        if !v.is_empty() {
            return v.to_owned();
        }
    }
    if let Some(first) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|first| !first.is_empty())
    {
        return first.to_owned();
    }
    "unknown".to_owned()
}

/// The middleware: refuse a throttled source before the handler; count a 401
/// after it.
pub async fn layer(State(limiter): State<PreAuthLimiter>, req: Request, next: Next) -> Response {
    let source = source_of(req.headers());
    let now = Instant::now();
    if limiter.is_throttled(&source, now) {
        AUTH_THROTTLED_TOTAL.fetch_add(1, Ordering::Relaxed);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            axum::Json(serde_json::json!({
                "error": "auth_throttled",
                "message": "too many failed authentications from this source; retry after 60 s"
            })),
        )
            .into_response();
    }
    let resp = next.run(req).await;
    if resp.status() == StatusCode::UNAUTHORIZED {
        limiter.note_failure(&source, Instant::now());
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limit_plus_one_is_throttled_and_the_window_rolls() {
        let l = PreAuthLimiter::new(3);
        let t0 = Instant::now();
        assert!(!l.is_throttled("1.2.3.4", t0));
        for _ in 0..3 {
            l.note_failure("1.2.3.4", t0);
        }
        assert!(
            l.is_throttled("1.2.3.4", t0),
            "3 failures against a limit of 3"
        );
        assert!(
            !l.is_throttled("5.6.7.8", t0),
            "another source is untouched"
        );
        // The window rolls: a minute later the source is clean again.
        assert!(!l.is_throttled("1.2.3.4", t0 + WINDOW));
    }

    #[test]
    fn source_prefers_cf_then_first_forwarded_hop_then_unknown() {
        let mut h = HeaderMap::new();
        assert_eq!(source_of(&h), "unknown");
        h.insert("x-forwarded-for", "10.0.0.9, 172.16.0.1".parse().unwrap());
        assert_eq!(source_of(&h), "10.0.0.9");
        h.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        assert_eq!(source_of(&h), "203.0.113.7");
    }

    #[tokio::test]
    async fn a_401_counts_and_a_200_never_does_and_the_throttle_is_429_without_the_handler() {
        use axum::{Router, routing::get};
        use std::sync::atomic::AtomicU32;
        use tower::ServiceExt as _;
        static HANDLER_CALLS: AtomicU32 = AtomicU32::new(0);
        async fn deny() -> StatusCode {
            HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            StatusCode::UNAUTHORIZED
        }
        async fn allow() -> StatusCode {
            HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            StatusCode::OK
        }
        let limiter = PreAuthLimiter::new(2);
        let app = Router::new()
            .route("/deny", get(deny))
            .route("/allow", get(allow))
            .layer(axum::middleware::from_fn_with_state(limiter, layer));
        let req = |path: &str| {
            axum::http::Request::builder()
                .uri(path)
                .header("x-forwarded-for", "198.51.100.4")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        // Two 401s fill the budget; the third request is refused before the handler.
        assert_eq!(
            app.clone().oneshot(req("/deny")).await.unwrap().status(),
            401
        );
        assert_eq!(
            app.clone().oneshot(req("/deny")).await.unwrap().status(),
            401
        );
        let calls = HANDLER_CALLS.load(Ordering::SeqCst);
        let third = app.clone().oneshot(req("/allow")).await.unwrap();
        assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(third.headers().get("retry-after").unwrap(), "60");
        assert_eq!(
            HANDLER_CALLS.load(Ordering::SeqCst),
            calls,
            "a throttled request must not reach the handler"
        );
        // A different source is unaffected, and its 200 does not count.
        let other = axum::http::Request::builder()
            .uri("/allow")
            .header("x-forwarded-for", "198.51.100.5")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(app.clone().oneshot(other).await.unwrap().status(), 200);
    }
}
