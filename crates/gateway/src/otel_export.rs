//! `OG-50` — push a workspace's spans to the customer's own OpenTelemetry collector over
//! OTLP/HTTP. Spec: `specs/OG-50-otel-export.md`.
//!
//! ## The shape
//!
//! ```text
//! spawn_publish ──► offer(&span) ──► [directory probe: one HashMap lookup]
//!                                        │ no export for the tenant: return (no clone, no alloc)
//!                                        ▼
//!                       sample (trace id) · only_errors · ENCODE (content stripped here)
//!                                        ▼
//!                       per-export bounded queue ──► one worker per export (lazy, idle-stops)
//!                       full ⇒ DROP the newest, count it                │
//!                                                      batch ► re-validate URL (SSRF, DNS-pinned)
//!                                                           ► POST application/x-protobuf
//!                                                           ► bounded retry ► count delivered / failed
//! ```
//!
//! ## What this is NOT
//!
//! **Not the ledger and not a durable queue.** Delivery is in-memory, at-most-once with
//! bounded retry, and lost on a restart or deploy; the API says `"delivery": "best_effort"`.
//! ClickHouse stays the record. Spans an SDK sends straight to ingest never pass the
//! gateway and are not exported.
//!
//! ## Fail direction (CLAUDE.md §10)
//!
//! **Capture is fail-OPEN with respect to export**: [`offer`] is synchronous, does no I/O,
//! never blocks and never fails; a slow, down or refusing collector can only cost the
//! customer their copy of a span — counted (`dropped` / `failed`, the `otel_export_dropped`
//! degradation, `GET /v1/exports/otel`), never silent. **Security paths fail CLOSED**: a URL
//! the SSRF guard refuses, a header map that does not open (tampered, wrong tenant, no master
//! key), an entitlement that is absent — none of them exports.
//!
//! ## Secrets
//!
//! Header values (a credential for the customer's collector) live sealed in Postgres
//! (`db::otel_exports`, AAD `otel-export:<tenant>:<id>`) and in memory only as
//! `SecretString`; they are applied with `HeaderValue::set_sensitive(true)` and appear in no
//! log line, error string or API response (header NAMES only).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use axum::http::{HeaderName, HeaderValue};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use tokio::sync::{Notify, mpsc};
use tracelane_shared::otlp::encode::{OtlpSpan, encode_span, request_bytes, span_encoded_len};
use tracelane_shared::{SpanStatusCode, TracelaneSpan};
use uuid::Uuid;

// ── Reference table (CLAUDE.md §23) ──────────────────────────────────────────────────────

/// The `otel_export` block of `crates/gateway/translation_policy.v1.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtelExportConfig {
    /// Spans one export may have waiting.
    pub queue_spans: usize,
    /// Spans waiting across ALL exports of the process.
    pub queued_spans_total_max: usize,
    pub batch_max_spans: usize,
    pub batch_flush_ms: u64,
    /// The largest request body.
    pub max_request_bytes: usize,
    pub timeout_secs: u64,
    pub max_retries: u32,
    /// Consecutive failed batches before the worker backs off (never disables).
    pub degraded_after_failures: u32,
    pub max_cooldown_secs: u64,
    pub idle_stop_secs: u64,
    pub status_flush_secs: u64,
    pub directory_refresh_secs: u64,
    pub max_headers: usize,
    pub max_header_value_bytes: usize,
    pub forbidden_headers: Vec<String>,
    pub retry_base_ms: u64,
    pub retry_cap_ms: u64,
    /// The longest `Retry-After` honoured.
    pub retry_after_max_secs: u64,
    pub max_url_bytes: usize,
    /// DNS validation bound.
    pub validate_timeout_secs: u64,
}

fn fallback() -> OtelExportConfig {
    OtelExportConfig {
        queue_spans: 2048,
        queued_spans_total_max: 100_000,
        batch_max_spans: 512,
        batch_flush_ms: 5000,
        max_request_bytes: 4_194_304,
        timeout_secs: 10,
        max_retries: 3,
        degraded_after_failures: 5,
        max_cooldown_secs: 900,
        idle_stop_secs: 300,
        status_flush_secs: 60,
        directory_refresh_secs: 60,
        max_headers: 8,
        max_header_value_bytes: 4096,
        forbidden_headers: [
            "host",
            "content-length",
            "content-type",
            "content-encoding",
            "transfer-encoding",
            "connection",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        retry_base_ms: 500,
        retry_cap_ms: 8000,
        retry_after_max_secs: 30,
        max_url_bytes: 2048,
        validate_timeout_secs: 3,
    }
}

fn parse_table(raw: &str) -> Option<OtelExportConfig> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let v = v.get("otel_export")?;
    let n = |k: &str| v.get(k).and_then(Value::as_u64).filter(|n| *n >= 1);
    let u = |k: &str| n(k).and_then(|n| usize::try_from(n).ok());
    Some(OtelExportConfig {
        queue_spans: u("queue_spans")?,
        queued_spans_total_max: u("queued_spans_total_max")?,
        batch_max_spans: u("batch_max_spans")?,
        batch_flush_ms: n("batch_flush_ms")?,
        max_request_bytes: u("max_request_bytes")?,
        timeout_secs: n("timeout_secs")?,
        max_retries: u32::try_from(v.get("max_retries")?.as_u64()?).ok()?,
        degraded_after_failures: u32::try_from(n("degraded_after_failures")?).ok()?,
        max_cooldown_secs: n("max_cooldown_secs")?,
        idle_stop_secs: n("idle_stop_secs")?,
        status_flush_secs: n("status_flush_secs")?,
        directory_refresh_secs: n("directory_refresh_secs")?,
        max_headers: u("max_headers")?,
        max_header_value_bytes: u("max_header_value_bytes")?,
        forbidden_headers: v
            .get("forbidden_headers")?
            .as_array()?
            .iter()
            .map(|h| h.as_str().map(str::to_ascii_lowercase))
            .collect::<Option<Vec<_>>>()?,
        retry_base_ms: n("retry_base_ms")?,
        retry_cap_ms: n("retry_cap_ms")?,
        retry_after_max_secs: n("retry_after_max_secs")?,
        max_url_bytes: u("max_url_bytes")?,
        validate_timeout_secs: n("validate_timeout_secs")?,
    })
}

/// The bounds, parsed once. Used ONLY if the shipped block does not parse (the
/// `og50_the_shipped_block_parses…` test makes that unreachable in a tested build): the
/// documented values, never "unbounded".
pub(crate) fn config() -> &'static OtelExportConfig {
    static C: OnceLock<OtelExportConfig> = OnceLock::new();
    C.get_or_init(|| {
        parse_table(include_str!("../translation_policy.v1.json")).unwrap_or_else(|| {
            tracing::warn!(
                "translation_policy.v1.json otel_export block did not parse — using the documented defaults"
            );
            fallback()
        })
    })
}

/// The batch flush interval: the table's, except in unit tests, which shorten it (a test cannot
/// wait five real seconds per assertion). Test-only; compiled out of every other build.
fn flush_ms() -> u64 {
    #[cfg(test)]
    {
        let o = timing::FLUSH_MS.load(Ordering::Relaxed);
        if o > 0 {
            return o;
        }
    }
    config().batch_flush_ms
}

/// The retry / cooldown base, with the same test-only override.
fn retry_base_ms() -> u64 {
    #[cfg(test)]
    {
        let o = timing::RETRY_BASE_MS.load(Ordering::Relaxed);
        if o > 0 {
            return o;
        }
    }
    config().retry_base_ms
}

#[cfg(test)]
pub(crate) mod timing {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// 0 = use the reference table.
    pub(crate) static FLUSH_MS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static RETRY_BASE_MS: AtomicU64 = AtomicU64::new(0);
    /// Short flush and backoff for tests. Idempotent; only ever SHORTENS.
    pub(crate) fn fast() {
        FLUSH_MS.store(20, Ordering::Relaxed);
        RETRY_BASE_MS.store(5, Ordering::Relaxed);
    }
}

// ── Headers: validate · seal · open ──────────────────────────────────────────────────────

/// A header name the customer may set: an HTTP token, lower-cased, not forbidden.
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_'
                        | b'.'
                        | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'^'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Validate a `headers` object from a request body. Returns `(name, value)` pairs with names
/// lower-cased. **No value is ever echoed in a refusal** — only the field and the rule.
///
/// # Errors
/// `(field, message)` for a `400 invalid_field`: too many headers, a non-string value, a
/// forbidden or malformed name, an oversized or non-visible-ASCII value, a duplicate name.
pub(crate) fn validate_headers(
    map: &serde_json::Map<String, Value>,
) -> Result<Vec<(String, String)>, (String, String)> {
    let cfg = config();
    if map.len() > cfg.max_headers {
        return Err((
            "headers".into(),
            format!("at most {} headers", cfg.max_headers),
        ));
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, value) in map {
        let lower = name.to_ascii_lowercase();
        let field = format!("headers.{lower}");
        if !valid_header_name(&lower) {
            return Err((
                "headers".into(),
                "a header name must be an HTTP token (letters, digits, `-` and similar)".into(),
            ));
        }
        if cfg.forbidden_headers.contains(&lower) {
            return Err((
                field,
                "this header is set by the exporter and cannot be overridden".into(),
            ));
        }
        let Some(v) = value.as_str() else {
            return Err((field, "a header value must be a string".into()));
        };
        if v.len() > cfg.max_header_value_bytes {
            return Err((
                field,
                format!(
                    "a header value is at most {} bytes",
                    cfg.max_header_value_bytes
                ),
            ));
        }
        // Visible ASCII and space only: no CR / LF / control byte can smuggle a second header.
        if !v.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
            || HeaderValue::from_str(v).is_err()
        {
            return Err((field, "a header value must be visible ASCII".into()));
        }
        if out.iter().any(|(n, _)| *n == lower) {
            return Err((
                field,
                "a header name appears twice (names are case-insensitive)".into(),
            ));
        }
        out.push((lower, v.to_owned()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Seal a header map under `key`, AAD-bound to `(tenant, export id)`. `None` for an empty map.
///
/// # Errors
/// The cipher failed.
pub(crate) fn seal_headers(
    key: &crate::byok::ByokMasterKey,
    tenant: Uuid,
    id: Uuid,
    headers: &[(String, String)],
) -> anyhow::Result<Option<String>> {
    if headers.is_empty() {
        return Ok(None);
    }
    let map: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    let plain = SecretString::from(Value::Object(map).to_string());
    key.encrypt_with_context(&plain, &crate::db::otel_exports::aad(tenant, id))
        .map(Some)
}

/// A header map opened for use on the wire: names parsed, values still secret.
pub(crate) type HeaderSet = Vec<(HeaderName, SecretString)>;

/// Open a sealed header map. **Fail-CLOSED**: a blob that does not open (the wrong tenant or
/// export — the GCM tag — a rotated-away key, a corrupt value) is an error, and the export
/// does not deliver.
///
/// # Errors
/// A stable class, never a value: `secret_unavailable`.
pub(crate) fn open_headers(
    key: Option<&crate::byok::ByokMasterKey>,
    tenant: Uuid,
    id: Uuid,
    enc: Option<&str>,
) -> Result<HeaderSet, &'static str> {
    let Some(enc) = enc else {
        return Ok(Vec::new());
    };
    let key = key.ok_or("secret_unavailable")?;
    let plain = key
        .decrypt_with_context(enc, &crate::db::otel_exports::aad(tenant, id))
        .map_err(|_| "secret_unavailable")?;
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(plain.expose_secret()) else {
        return Err("secret_unavailable");
    };
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let (Ok(name), Some(v)) = (HeaderName::from_bytes(k.as_bytes()), v.as_str()) else {
            return Err("secret_unavailable");
        };
        out.push((name, SecretString::from(v.to_owned())));
    }
    Ok(out)
}

// ── URL validation (create time) ─────────────────────────────────────────────────────────

/// Why a URL is refused at create. The message never contains the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UrlRefusal {
    /// Not an `https` URL with a host, or too long, or with userinfo / a fragment, or a path
    /// that does not end `/v1/traces`.
    Invalid(&'static str),
    /// The SSRF guard refused it (private, loopback, metadata or link-local address).
    SsrfBlocked,
}

/// The syntactic half of URL validation: pure, no DNS.
pub(crate) fn check_url_syntax(raw: &str) -> Result<reqwest::Url, UrlRefusal> {
    if raw.len() > config().max_url_bytes {
        return Err(UrlRefusal::Invalid("the URL is too long"));
    }
    let url =
        reqwest::Url::parse(raw.trim()).map_err(|_| UrlRefusal::Invalid("not a valid URL"))?;
    if url.scheme() != "https" {
        return Err(UrlRefusal::Invalid("the URL must be https://"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(UrlRefusal::Invalid("the URL needs a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlRefusal::Invalid(
            "the URL must not carry a username or password — send credentials as a header",
        ));
    }
    if url.fragment().is_some() {
        return Err(UrlRefusal::Invalid("the URL must not carry a #fragment"));
    }
    if !url.path().ends_with("/v1/traces") {
        return Err(UrlRefusal::Invalid(
            "the URL path must end /v1/traces (OTLP/HTTP traces)",
        ));
    }
    Ok(url)
}

/// Full create-time validation: syntax, then the SSRF guard (DNS-resolved). Returns the
/// canonical URL string.
///
/// # Errors
/// [`UrlRefusal`].
pub(crate) async fn validate_url(raw: &str) -> Result<String, UrlRefusal> {
    let url = check_url_syntax(raw)?;
    match tokio::time::timeout(
        Duration::from_secs(config().validate_timeout_secs),
        crate::ssrf_guard::validate_url(url.as_str()),
    )
    .await
    {
        Ok(Ok(())) => Ok(url.to_string()),
        Ok(Err(_)) => Err(UrlRefusal::SsrfBlocked),
        Err(_) => Err(UrlRefusal::Invalid("the host did not resolve in time")),
    }
}

// ── Delivery ─────────────────────────────────────────────────────────────────────────────

/// One delivery attempt's failure: a stable class (never a URL, never a header value) and
/// whether a retry may help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SendError {
    pub class: String,
    pub retryable: bool,
    pub retry_after: Option<Duration>,
}

fn classify_transport(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        return "timeout";
    }
    let mut chain = String::new();
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        chain.push_str(&err.to_string().to_ascii_lowercase());
        chain.push(' ');
        cur = err.source();
    }
    if chain.contains("dns") || chain.contains("lookup") || chain.contains("resolve") {
        "dns"
    } else if chain.contains("certificate") || chain.contains("tls") || chain.contains("handshake")
    {
        "tls"
    } else if e.is_connect() {
        "connect"
    } else {
        "transport"
    }
}

/// ONE delivery attempt: re-validate the URL (SSRF, DNS-pinned — a customer's DNS may have
/// changed since create), POST the protobuf body with the customer's headers, and read only
/// the STATUS. The response body is never read, stored or returned.
pub(crate) async fn send_once(
    url: &str,
    headers: &HeaderSet,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<(), SendError> {
    let cfg = config();
    let pinned = match tokio::time::timeout(
        Duration::from_secs(cfg.validate_timeout_secs),
        crate::ssrf_guard::validate_url_pinned(url),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            let blocked = e.to_string().contains("SSRF");
            return Err(SendError {
                class: if blocked { "ssrf_blocked" } else { "dns" }.to_owned(),
                retryable: !blocked,
                retry_after: None,
            });
        }
        Err(_) => {
            return Err(SendError {
                class: "dns".to_owned(),
                retryable: true,
                retry_after: None,
            });
        }
    };
    let client = pinned
        .pin(crate::ssrf_guard::safe_client_builder())
        .timeout(timeout)
        .build()
        .map_err(|_| SendError {
            class: "transport".to_owned(),
            retryable: false,
            retry_after: None,
        })?;
    let mut req = client
        .post(url)
        .header(axum::http::header::CONTENT_TYPE, "application/x-protobuf");
    for (name, value) in headers {
        let Ok(mut v) = HeaderValue::from_str(value.expose_secret()) else {
            return Err(SendError {
                class: "secret_unavailable".to_owned(),
                retryable: false,
                retry_after: None,
            });
        };
        v.set_sensitive(true);
        req = req.header(name.clone(), v);
    }
    let resp = req.body(body).send().await.map_err(|e| {
        let e = e.without_url();
        SendError {
            class: classify_transport(&e).to_owned(),
            retryable: true,
            retry_after: None,
        }
    })?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let retryable = matches!(status.as_u16(), 408 | 429) || status.is_server_error();
    Err(SendError {
        class: format!("http_{}", status.as_u16()),
        retryable,
        retry_after: retryable
            .then(|| crate::providers::retry_after::retry_after_from(resp.headers()))
            .flatten(),
    })
}

/// Full-jitter backoff for attempt `n` (0-based): uniform in `[0, min(cap, base · 2ⁿ)]`,
/// raised to a bounded `Retry-After` when the receiver sent one.
pub(crate) fn backoff(n: u32, retry_after: Option<Duration>, jitter: f64) -> Duration {
    let cfg = config();
    let ceiling = retry_base_ms()
        .saturating_mul(1u64 << n.min(16))
        .min(cfg.retry_cap_ms.max(retry_base_ms()));
    let jittered = Duration::from_millis((ceiling as f64 * jitter.clamp(0.0, 1.0)) as u64);
    match retry_after {
        Some(ra) => jittered.max(ra.min(Duration::from_secs(cfg.retry_after_max_secs))),
        None => jittered,
    }
}

fn jitter() -> f64 {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 8];
    if ring::rand::SystemRandom::new().fill(&mut b).is_err() {
        return 0.5;
    }
    (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}

/// The cooldown after `failures` consecutive failed batches: nothing below
/// `degraded_after_failures`, then base · 2^(failures − threshold), capped.
pub(crate) fn cooldown(failures: u32) -> Duration {
    let cfg = config();
    if failures < cfg.degraded_after_failures {
        return Duration::ZERO;
    }
    let over = failures - cfg.degraded_after_failures;
    Duration::from_millis(
        retry_base_ms()
            .saturating_mul(2)
            .saturating_mul(1u64 << over.min(20))
            .min(cfg.max_cooldown_secs.saturating_mul(1000)),
    )
}

// ── Per-export state ─────────────────────────────────────────────────────────────────────

/// An export's live counters and status. Shared across config changes (a PATCH keeps them).
#[derive(Default)]
pub(crate) struct Stats {
    delivered: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicU64,
    consecutive_failures: AtomicU32,
    /// Unix seconds of the last 2xx; 0 = never.
    last_success: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// The export's sealed headers could not be opened (no master key, a tampered or foreign
    /// blob): it delivers NOTHING - fail-CLOSED - and says so (`status` degraded,
    /// `last_error_class` `secret_unavailable`), instead of vanishing from the list.
    blocked: AtomicBool,
    /// Changed since the last flush.
    dirty: AtomicBool,
}

impl Stats {
    fn status(&self) -> &'static str {
        if self.blocked.load(Ordering::Relaxed)
            || self.consecutive_failures.load(Ordering::Relaxed) >= config().degraded_after_failures
        {
            "degraded"
        } else if self.last_success.load(Ordering::Relaxed) > 0 {
            "ok"
        } else {
            "never_delivered"
        }
    }

    pub(crate) fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    pub(crate) fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    fn note_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
        self.dirty.store(true, Ordering::Relaxed);
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::OtelExportDropped,
        );
    }
}

/// A live snapshot of one export, for the list route (fresher than the flushed row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Live {
    pub status: &'static str,
    pub delivered: u64,
    pub dropped: u64,
    pub failed: u64,
    pub queue_depth: Option<usize>,
    pub last_error_class: Option<String>,
}

pub(crate) struct Export {
    id: Uuid,
    tenant: Uuid,
    url: String,
    headers: HeaderSet,
    include_content: bool,
    sample_ratio: f64,
    only_errors: bool,
    version: chrono::DateTime<chrono::Utc>,
    tx: mpsc::Sender<OtlpSpan>,
    rx: Mutex<Option<mpsc::Receiver<OtlpSpan>>>,
    running: AtomicBool,
    /// Removed or disabled: a worker discards whatever it still holds (counted).
    retired: AtomicBool,
    stats: Arc<Stats>,
}

/// A trace is exported whole or not at all: the decision is a pure function of the trace id.
pub(crate) fn sampled(trace_id: Uuid, ratio: f64) -> bool {
    if ratio >= 1.0 {
        return true;
    }
    if ratio <= 0.0 {
        return false;
    }
    // HASHED, not read off the id: a v4 UUID's bytes are not uniform (its variant bits are fixed),
    // and reading them directly sampled NOTHING at 0.5 — found by the test below, which draws
    // v4 ids exactly as the gateway mints them.
    let h = blake3::hash(trace_id.as_bytes());
    let b = h.as_bytes();
    let n = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    ((n >> 11) as f64 / (1u64 << 53) as f64) < ratio
}

impl Export {
    fn new(
        sealed: &crate::db::otel_exports::Sealed,
        headers: HeaderSet,
        stats: Arc<Stats>,
    ) -> Self {
        Self::with_capacity(sealed, headers, stats, config().queue_spans)
    }

    fn with_capacity(
        sealed: &crate::db::otel_exports::Sealed,
        headers: HeaderSet,
        stats: Arc<Stats>,
        capacity: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            id: sealed.id,
            tenant: sealed.tenant_id,
            url: sealed.url.clone(),
            headers,
            include_content: sealed.include_content,
            sample_ratio: sealed.sample_ratio,
            only_errors: sealed.only_errors,
            version: sealed.updated_at,
            tx,
            rx: Mutex::new(Some(rx)),
            running: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            stats,
        }
    }

    fn live(&self) -> Live {
        let depth = self.tx.max_capacity() - self.tx.capacity();
        Live {
            status: self.stats.status(),
            delivered: self.stats.delivered(),
            dropped: self.stats.dropped(),
            failed: self.stats.failed(),
            // `null` when idle (no worker, nothing waiting).
            queue_depth: (self.running.load(Ordering::Relaxed) || depth > 0).then_some(depth),
            last_error_class: self.stats.last_error.lock().ok().and_then(|g| g.clone()),
        }
    }

    /// Queue one span for this export. Synchronous, no I/O; a full queue (or the global
    /// ceiling) DROPS the newest span and counts it.
    fn offer(self: &Arc<Self>, hub: &Hub, span: &TracelaneSpan) {
        if self.only_errors && span.status.code != SpanStatusCode::Error {
            return;
        }
        if !sampled(span.trace_id, self.sample_ratio) {
            return;
        }
        if self.stats.blocked.load(Ordering::Relaxed) {
            // Counted, never silent: the customer asked for these spans and is not getting them.
            self.stats.note_dropped(1);
            return;
        }
        if hub.total_queued.load(Ordering::Relaxed) >= hub.total_max {
            hub.dropped_global_full.fetch_add(1, Ordering::Relaxed);
            self.stats.note_dropped(1);
            return;
        }
        // Content is stripped HERE, while encoding: a span the export may not carry content
        // for is never copied with its content.
        #[cfg(test)]
        ENCODES.with(|c| c.set(c.get() + 1));
        let encoded = encode_span(span, self.include_content);
        match self.tx.try_send(encoded) {
            Ok(()) => {
                hub.total_queued.fetch_add(1, Ordering::Relaxed);
                self.ensure_worker();
            }
            Err(_) => {
                hub.dropped_queue_full.fetch_add(1, Ordering::Relaxed);
                self.stats.note_dropped(1);
            }
        }
    }

    fn ensure_worker(self: &Arc<Self>) {
        if self.running.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.running.store(false, Ordering::Release);
            return;
        };
        let rx = self.rx.lock().ok().and_then(|mut g| g.take());
        let Some(rx) = rx else {
            self.running.store(false, Ordering::Release);
            return;
        };
        let me = Arc::clone(self);
        handle.spawn(async move { me.run(rx).await });
    }

    /// The worker: batch → deliver → repeat, until idle for `idle_stop_secs`.
    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<OtlpSpan>) {
        let cfg = config();
        let hub = hub();
        loop {
            let first = match tokio::time::timeout(
                Duration::from_secs(cfg.idle_stop_secs),
                rx.recv(),
            )
            .await
            {
                Ok(Some(s)) => s,
                // Every sender is gone (cannot happen while this task holds `self`) or idle:
                // park the receiver so the next offer restarts a worker.
                Ok(None) | Err(_) => {
                    if let Ok(mut g) = self.rx.lock() {
                        *g = Some(rx);
                    }
                    self.running.store(false, Ordering::Release);
                    // An offer between the timeout and the store saw `running` and did not
                    // start a worker: close that window.
                    if self.tx.capacity() < self.tx.max_capacity() {
                        self.ensure_worker();
                    }
                    return;
                }
            };
            let mut bytes = span_encoded_len(&first);
            let mut batch = vec![first];
            let deadline = Instant::now() + Duration::from_millis(flush_ms());
            while batch.len() < cfg.batch_max_spans && bytes < cfg.max_request_bytes {
                let left = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(left, rx.recv()).await {
                    Ok(Some(s)) => {
                        let len = span_encoded_len(&s);
                        if bytes + len > cfg.max_request_bytes && !batch.is_empty() {
                            // Over the body cap: ship what we have, start the next batch with this.
                            hub.total_queued.fetch_sub(batch.len(), Ordering::Relaxed);
                            let full = std::mem::replace(&mut batch, vec![s]);
                            bytes = len;
                            self.deliver(full).await;
                            continue;
                        }
                        bytes += len;
                        batch.push(s);
                    }
                    _ => break,
                }
            }
            hub.total_queued.fetch_sub(batch.len(), Ordering::Relaxed);
            self.deliver(batch).await;
            let wait = cooldown(self.stats.consecutive_failures.load(Ordering::Relaxed));
            if !wait.is_zero() {
                // Backed off, never disabled: the queue keeps filling and dropping the newest.
                tokio::time::sleep(wait).await;
            }
        }
    }

    /// Deliver one batch with bounded retry, and account for it.
    async fn deliver(&self, batch: Vec<OtlpSpan>) {
        let n = batch.len() as u64;
        if self.retired.load(Ordering::Acquire) {
            // The export was removed or disabled after these spans were queued: they go nowhere.
            self.stats.note_dropped(n);
            return;
        }
        let cfg = config();
        let body = request_bytes(batch);
        let mut last: Option<SendError> = None;
        for attempt in 0..=cfg.max_retries {
            match send_once(
                &self.url,
                &self.headers,
                body.clone(),
                Duration::from_secs(cfg.timeout_secs),
            )
            .await
            {
                Ok(()) => {
                    self.stats.delivered.fetch_add(n, Ordering::Relaxed);
                    self.stats.consecutive_failures.store(0, Ordering::Relaxed);
                    self.stats.last_success.store(unix_now(), Ordering::Relaxed);
                    if let Ok(mut g) = self.stats.last_error.lock() {
                        *g = None;
                    }
                    self.stats.dirty.store(true, Ordering::Relaxed);
                    tracelane_shared::degradation::resolve(
                        tracelane_shared::degradation::Degradation::OtelExportDropped,
                    );
                    return;
                }
                Err(e) => {
                    let retry = e.retryable && attempt < cfg.max_retries;
                    let wait = backoff(attempt, e.retry_after, jitter());
                    last = Some(e);
                    if !retry {
                        break;
                    }
                    tokio::time::sleep(wait).await;
                }
            }
        }
        self.stats.failed.fetch_add(n, Ordering::Relaxed);
        self.stats
            .consecutive_failures
            .fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.stats.last_error.lock() {
            *g = last.map(|e| e.class);
        }
        self.stats.dirty.store(true, Ordering::Relaxed);
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::OtelExportDropped,
        );
    }
}

fn unix_now() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

// ── The hub: the directory and the tap ───────────────────────────────────────────────────

type Directory = HashMap<Uuid, Vec<Arc<Export>>>;

pub(crate) struct Hub {
    directory: ArcSwap<Directory>,
    /// Spans waiting across every export's queue.
    total_queued: AtomicUsize,
    /// The ceiling on `total_queued` (the reference table's; a test hub may hold less).
    total_max: usize,
    dropped_queue_full: AtomicU64,
    dropped_global_full: AtomicU64,
    /// A write happened: rebuild the directory now.
    refresh: Notify,
}

impl Hub {
    fn new(total_max: usize) -> Self {
        Self {
            directory: ArcSwap::from_pointee(HashMap::new()),
            total_queued: AtomicUsize::new(0),
            total_max,
            dropped_queue_full: AtomicU64::new(0),
            dropped_global_full: AtomicU64::new(0),
            refresh: Notify::new(),
        }
    }
}

fn hub() -> &'static Hub {
    static H: OnceLock<Hub> = OnceLock::new();
    H.get_or_init(|| Hub::new(config().queued_spans_total_max))
}

static STARTED: AtomicBool = AtomicBool::new(false);

// Test-only: how many spans were encoded for an export. A tenant with no export must leave
// it unmoved — the proof that the tap's fast path clones and encodes nothing.
#[cfg(test)]
thread_local! {
    // Per-thread (each test owns its thread): parallel tests' exports must not move it.
    static ENCODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// **The tap.** Called once per span the gateway publishes (`otlp_emit::spawn_publish`) and
/// once per span of an SDK batch (`trace_ingest`), AFTER the NATS publish is handed off and
/// independent of its result. Synchronous, no I/O, never fails, never blocks. A workspace
/// with no export costs one `HashMap` probe: no clone, no allocation.
pub(crate) fn offer(span: &TracelaneSpan) {
    if !STARTED.load(Ordering::Relaxed) {
        return;
    }
    let hub = hub();
    let dir = hub.directory.load();
    let Some(exports) = dir.get(span.tenant_id.as_uuid()) else {
        return;
    };
    for e in exports {
        e.offer(hub, span);
    }
}

/// Ask the background task to rebuild the directory now (after a write).
pub(crate) fn refresh_now() {
    if STARTED.load(Ordering::Relaxed) {
        hub().refresh.notify_one();
    }
}

/// The live counters of one export, if the directory holds it.
pub(crate) fn live(tenant: Uuid, id: Uuid) -> Option<Live> {
    if !STARTED.load(Ordering::Relaxed) {
        return None;
    }
    hub()
        .directory
        .load()
        .get(&tenant)?
        .iter()
        .find(|e| e.id == id)
        .map(|e| e.live())
}

/// Process-wide drop counters for `/health`-style display: `(queue_full, global_full)`.
pub(crate) fn drop_counters() -> (u64, u64) {
    let h = hub();
    (
        h.dropped_queue_full.load(Ordering::Relaxed),
        h.dropped_global_full.load(Ordering::Relaxed),
    )
}

/// Build the next directory from the enabled rows. A tenant whose plan does not grant
/// `f_otel_export` (or with no entitlement read at all — no control plane) exports NOTHING:
/// fail-CLOSED. An export whose sealed headers do not open is skipped and its status says so.
async fn build_directory(
    rows: Vec<crate::db::otel_exports::Sealed>,
    entitlements: Option<&Arc<crate::entitlement_cache::EntitlementCache>>,
    old: &Directory,
) -> Directory {
    let mut granted: HashMap<Uuid, bool> = HashMap::new();
    let mut out: Directory = HashMap::new();
    for row in rows {
        // The directory read already filters on `enabled`; a row that says otherwise is not exported.
        if !row.enabled {
            continue;
        }
        let ok = match granted.get(&row.tenant_id) {
            Some(g) => *g,
            None => {
                let g = match entitlements {
                    Some(c) => c.resolved(row.tenant_id).await.f_otel_export,
                    None => false,
                };
                granted.insert(row.tenant_id, g);
                g
            }
        };
        if !ok {
            continue;
        }
        let previous = old
            .get(&row.tenant_id)
            .and_then(|v| v.iter().find(|e| e.id == row.id));
        // Unchanged config: keep the live export (its queue and worker).
        if let Some(p) = previous
            && p.version == row.updated_at
        {
            out.entry(row.tenant_id).or_default().push(Arc::clone(p));
            continue;
        }
        let stats = previous.map_or_else(|| Arc::new(Stats::default()), |p| Arc::clone(&p.stats));
        match open_headers(
            crate::byok::master_key(),
            row.tenant_id,
            row.id,
            row.headers_enc.as_deref(),
        ) {
            Ok(headers) => {
                stats.blocked.store(false, Ordering::Relaxed);
                out.entry(row.tenant_id)
                    .or_default()
                    .push(Arc::new(Export::new(&row, headers, stats)));
            }
            // Fail CLOSED, visibly: the export stays in the directory BLOCKED, so the list and
            // the flushed row say `secret_unavailable` rather than the export silently vanishing.
            Err(class) => {
                stats.blocked.store(true, Ordering::Relaxed);
                if let Ok(mut g) = stats.last_error.lock() {
                    *g = Some(class.to_owned());
                }
                stats.dirty.store(true, Ordering::Relaxed);
                out.entry(row.tenant_id)
                    .or_default()
                    .push(Arc::new(Export::new(&row, Vec::new(), stats)));
            }
        }
    }
    out
}

/// Swap in a new directory and retire the exports that left it.
fn install(next: Directory) {
    let hub = hub();
    let old = hub.directory.swap(Arc::new(next));
    let now = hub.directory.load();
    for (tenant, exports) in old.iter() {
        for e in exports {
            let kept = now
                .get(tenant)
                .is_some_and(|v| v.iter().any(|n| Arc::ptr_eq(n, e)));
            if !kept {
                e.retired.store(true, Ordering::Release);
            }
        }
    }
}

/// Start the ONE background task: rebuild the directory every `directory_refresh_secs` and on
/// every write, and flush counters + status at most every `status_flush_secs`. Started at boot
/// when a Postgres control plane exists.
pub(crate) fn spawn(
    pool: crate::db::DbPool,
    entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
) {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    // The tap: every span `otlp_emit::spawn_publish` spawns and every accepted SDK batch.
    crate::otlp_emit::set_span_tap(offer);
    let cfg = config();
    tokio::spawn(async move {
        let mut refresh = tokio::time::interval(Duration::from_secs(cfg.directory_refresh_secs));
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut flush = tokio::time::interval(Duration::from_secs(cfg.status_flush_secs));
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = refresh.tick() => rebuild(&pool, entitlements.as_ref()).await,
                () = hub().refresh.notified() => rebuild(&pool, entitlements.as_ref()).await,
                _ = flush.tick() => flush_status(&pool).await,
            }
        }
    });
}

async fn rebuild(
    pool: &crate::db::DbPool,
    entitlements: Option<&Arc<crate::entitlement_cache::EntitlementCache>>,
) {
    match crate::db::otel_exports::directory(pool).await {
        Ok(rows) => {
            let old = hub().directory.load_full();
            install(build_directory(rows, entitlements, &old).await);
        }
        // Keep the previous directory: an unreadable control plane must not stop exports that
        // were already running, and must not start ones that were never granted.
        Err(e) => tracing::debug!(error = %format!("{e:#}"), "otel export directory read failed"),
    }
}

async fn flush_status(pool: &crate::db::DbPool) {
    let dir = hub().directory.load();
    let mut updates = Vec::new();
    for exports in dir.values() {
        for e in exports {
            if !e.stats.dirty.swap(false, Ordering::AcqRel) {
                continue;
            }
            let last = e.stats.last_success.load(Ordering::Relaxed);
            updates.push(crate::db::otel_exports::StatusUpdate {
                id: e.id,
                tenant_id: e.tenant,
                status: e.stats.status(),
                last_success_at: (last > 0)
                    .then(|| chrono::DateTime::from_timestamp(i64::try_from(last).unwrap_or(0), 0))
                    .flatten(),
                last_error_class: e.stats.last_error.lock().ok().and_then(|g| g.clone()),
                delivered: i64::try_from(e.stats.delivered()).unwrap_or(i64::MAX),
                dropped: i64::try_from(e.stats.dropped()).unwrap_or(i64::MAX),
                failed: i64::try_from(e.stats.failed()).unwrap_or(i64::MAX),
            });
        }
    }
    if let Err(e) = crate::db::otel_exports::flush_status(pool, &updates).await {
        // Not recorded as done: the dirty bits are set again so the next tick retries.
        for exports in dir.values() {
            for ex in exports {
                if updates.iter().any(|u| u.id == ex.id) {
                    ex.stats.dirty.store(true, Ordering::Relaxed);
                }
            }
        }
        tracing::debug!(error = %format!("{e:#}"), "otel export status flush failed");
    }
}

// ── The test delivery ────────────────────────────────────────────────────────────────────

/// What `POST /v1/exports/otel/{id}/test` reports: a class and a latency — never the
/// response body, never the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TestResult {
    pub ok: bool,
    /// `ok`, `ssrf_blocked`, `dns`, `tls`, `connect`, `timeout`, `transport`, `http_<status>`,
    /// `secret_unavailable`.
    pub class: String,
    pub latency_ms: u64,
}

/// One synthetic span to the export's own URL with its own headers, ONE attempt, no retry.
pub(crate) async fn test_delivery(
    tenant: Uuid,
    id: Uuid,
    url: &str,
    headers_enc: Option<&str>,
) -> TestResult {
    let started = Instant::now();
    let elapsed = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let headers = match open_headers(crate::byok::master_key(), tenant, id, headers_enc) {
        Ok(h) => h,
        Err(class) => {
            return TestResult {
                ok: false,
                class: class.to_owned(),
                latency_ms: elapsed(),
            };
        }
    };
    let body = request_bytes(vec![encode_span(&synthetic_span(tenant), false)]);
    match send_once(
        url,
        &headers,
        body,
        Duration::from_secs(config().timeout_secs),
    )
    .await
    {
        Ok(()) => TestResult {
            ok: true,
            class: "ok".into(),
            latency_ms: elapsed(),
        },
        Err(e) => TestResult {
            ok: false,
            class: e.class,
            latency_ms: elapsed(),
        },
    }
}

/// The span a test delivery sends: nothing of the customer's, an obvious name.
fn synthetic_span(tenant: Uuid) -> TracelaneSpan {
    let now = chrono::Utc::now();
    TracelaneSpan {
        span_id: Uuid::new_v4(),
        trace_id: Uuid::new_v4(),
        parent_span_id: None,
        tenant_id: tracelane_shared::TenantId::from_jwt_claim(tenant),
        name: "tracelane.export.test".to_owned(),
        start_time: now,
        end_time: Some(now),
        attributes: tracelane_shared::SpanAttributes::default(),
        status: tracelane_shared::SpanStatus {
            code: SpanStatusCode::Ok,
            message: None,
        },
    }
}

// ── Test support ─────────────────────────────────────────────────────────────────────────

/// Install an export for `tenant` straight into the directory (no Postgres): MERGES, so
/// tests with distinct tenants do not disturb each other. Returns the export's id.
#[cfg(test)]
pub(crate) fn install_for_test(
    tenant: Uuid,
    url: &str,
    headers: Vec<(&str, &str)>,
    include_content: bool,
    sample_ratio: f64,
    only_errors: bool,
) -> Uuid {
    STARTED.store(true, Ordering::Release);
    crate::otlp_emit::set_span_tap(offer);
    let id = Uuid::new_v4();
    let sealed = crate::db::otel_exports::Sealed {
        id,
        tenant_id: tenant,
        url: url.to_owned(),
        headers_enc: None,
        enabled: true,
        include_content,
        sample_ratio,
        only_errors,
        updated_at: chrono::Utc::now(),
    };
    let set: HeaderSet = headers
        .into_iter()
        .map(|(k, v)| {
            (
                HeaderName::from_bytes(k.as_bytes()).expect("test header name"),
                SecretString::from(v.to_owned()),
            )
        })
        .collect();
    let export = Arc::new(Export::new(&sealed, set, Arc::new(Stats::default())));
    let hub = hub();
    hub.directory.rcu(|cur| {
        let mut next = (**cur).clone();
        next.entry(tenant).or_default().push(Arc::clone(&export));
        next
    });
    id
}

/// Remove every test export of `tenant` (and retire them).
#[cfg(test)]
pub(crate) fn remove_for_test(tenant: Uuid) {
    let hub = hub();
    let old = hub.directory.rcu(|cur| {
        let mut next = (**cur).clone();
        next.remove(&tenant);
        next
    });
    if let Some(v) = old.get(&tenant) {
        for e in v {
            e.retired.store(true, Ordering::Release);
        }
    }
}

// ── Tests (specs/OG-50-otel-export.md §7) ────────────────────────────────────────────────

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::handler_harness::{
        LoopbackBypassGuard, authed, registry_pointing_ollama_at, test_state,
    };
    use crate::server::{AppState, chat_completions_handler, embeddings_handler};
    use axum::extract::{Json, State};
    use serde_json::json;
    use tracelane_shared::TenantId;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SECRET_PROMPT: &str = "the-secret-prompt-text-7731";

    fn tenant_claims(tenant: Uuid) -> crate::auth::test_claims::Guard {
        let mut c = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
        c.tenant_id = TenantId::from_jwt_claim(tenant);
        crate::auth::test_claims::Guard::set(c)
    }

    /// An OTLP receiver (the customer's collector): `status` for every POST /v1/traces.
    async fn receiver(status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/traces"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        server
    }

    async fn requests(server: &MockServer) -> Vec<wiremock::Request> {
        server.received_requests().await.unwrap_or_default()
    }

    /// Wait (bounded) until `cond` holds — polling a condition, never a fixed sleep.
    async fn until<F, Fut>(what: &str, mut cond: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        for _ in 0..600 {
            if cond().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    fn spans_in(reqs: &[wiremock::Request], tenant: Uuid) -> Vec<TracelaneSpan> {
        let t = TenantId::from_jwt_claim(tenant);
        reqs.iter()
            .flat_map(|r| {
                tracelane_shared::otlp::decode::decode_otlp_protobuf(&r.body, Some(&t))
                    .expect("our own export decodes")
            })
            .collect()
    }

    /// A chat rig: an Ollama mock that answers one completion, capture ON for the workspace
    /// when `capture` (so the span carries the prompt), and no response cache.
    struct Chat {
        /// Held so the provider mock outlives the test body.
        #[allow(dead_code)]
        upstream: MockServer,
        state: AppState,
        _bypass: LoopbackBypassGuard,
    }

    impl Chat {
        async fn new(capture: bool) -> Self {
            let bypass = LoopbackBypassGuard::new();
            let upstream = crate::handler_harness::chat_ok_mock().await;
            Mock::given(method("POST"))
                .and(path("/v1/embeddings"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "object":"list","model":"ollama/nomic-embed-text",
                    "data":[{"object":"embedding","index":0,"embedding":[0.1]}],
                    "usage":{"prompt_tokens":1,"total_tokens":1}})))
                .mount(&upstream)
                .await;
            let mut state = test_state(registry_pointing_ollama_at(upstream.uri()));
            let mut e = crate::entitlement_cache::ResolvedEntitlements::deny_all();
            e.content_capture = crate::db::workspace_capture::WorkspaceCapture {
                input: capture,
                output: capture,
            };
            state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
                Arc::new(move |_t| {
                    let e = e.clone();
                    Box::pin(async move { Ok(e) })
                }),
            )));
            Self {
                upstream,
                state,
                _bypass: bypass,
            }
        }

        async fn chat(&self, trace: Uuid, stream: bool) -> StatusCode {
            let mut h = authed();
            h.insert("x-trace-id", trace.to_string().parse().unwrap());
            let r = chat_completions_handler(
                State(self.state.clone()),
                h,
                Json(json!({"model":"ollama/llama3","stream":stream,
                    "messages":[{"role":"user","content":SECRET_PROMPT}]})),
            )
            .await;
            let s = r.status();
            let _ = axum::body::to_bytes(r.into_body(), usize::MAX).await;
            s
        }

        async fn embed(&self, trace: Uuid) -> StatusCode {
            let mut h = authed();
            h.insert("x-trace-id", trace.to_string().parse().unwrap());
            let r = embeddings_handler(
                State(self.state.clone()),
                h,
                Json(json!({"model":"ollama/nomic-embed-text","input":"hello"})),
            )
            .await;
            r.status()
        }
    }

    use axum::http::StatusCode;

    // ── Config ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn og50_the_shipped_block_parses_and_equals_the_documented_fallback() {
        let c = parse_table(include_str!("../translation_policy.v1.json")).expect("parses");
        assert_eq!(&c, config());
        assert_eq!(
            c,
            fallback(),
            "the documented fallback equals the shipped table"
        );
        assert!(parse_table(r#"{"otel_export":{"queue_spans":0}}"#).is_none());
        assert!(c.forbidden_headers.iter().any(|h| h == "content-type"));
    }

    // ── Spec §7 row 2: an end-to-end export ──────────────────────────────────────────────

    #[tokio::test]
    async fn og50_a_chat_request_arrives_at_the_customers_collector_with_its_headers() {
        timing::fast();
        let tenant = Uuid::new_v4();
        let _c = tenant_claims(tenant);
        let rx = receiver(200).await;
        let rig = Chat::new(true).await;
        install_for_test(
            tenant,
            &format!("{}/v1/traces", rx.uri()),
            vec![
                ("authorization", "Bearer s3cr3t-token"),
                ("x-scope-orgid", "acme"),
            ],
            false,
            1.0,
            false,
        );
        let trace = Uuid::new_v4();
        assert_eq!(rig.chat(trace, false).await, StatusCode::OK);
        until("the span to reach the collector", || async {
            !requests(&rx).await.is_empty()
        })
        .await;
        let reqs = requests(&rx).await;
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(
            r.headers.get("content-type").unwrap(),
            "application/x-protobuf"
        );
        assert_eq!(
            r.headers.get("authorization").unwrap(),
            "Bearer s3cr3t-token"
        );
        assert_eq!(r.headers.get("x-scope-orgid").unwrap(), "acme");
        let spans = spans_in(&reqs, tenant);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].trace_id, trace,
            "the caller's trace id, byte for byte"
        );
        assert_eq!(
            spans[0].attributes.gen_ai_request_model.as_deref(),
            Some("ollama/llama3")
        );
        // The recorded span (what NATS and ClickHouse get) is untouched by the export.
        let recorded = crate::otlp_emit::test_sink::for_trace(trace);
        assert_eq!(recorded.len(), 1);
        // The wire carries the LOW 8 bytes of the recorded span id (the decoder's inverse).
        assert_eq!(
            recorded[0].span_id.as_bytes()[8..],
            spans[0].span_id.as_bytes()[8..]
        );
        remove_for_test(tenant);
    }

    /// Spec §7 row 3: every span a route publishes passes the tap — the export count equals the
    /// recorded-span count across chat, a stream and embeddings.
    #[tokio::test]
    async fn og50_the_tap_count_equals_the_span_count_across_routes() {
        timing::fast();
        let tenant = Uuid::new_v4();
        let _c = tenant_claims(tenant);
        let rx = receiver(200).await;
        let rig = Chat::new(false).await;
        install_for_test(
            tenant,
            &format!("{}/v1/traces", rx.uri()),
            vec![],
            false,
            1.0,
            false,
        );
        let traces: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        assert_eq!(rig.chat(traces[0], false).await, StatusCode::OK);
        assert_eq!(rig.chat(traces[1], true).await, StatusCode::OK);
        assert_eq!(rig.embed(traces[2]).await, StatusCode::OK);
        let recorded: usize = traces
            .iter()
            .map(|t| crate::otlp_emit::test_sink::for_trace(*t).len())
            .sum();
        assert_eq!(recorded, 3, "one span per request was built");
        until("all three spans to arrive", || async {
            spans_in(&requests(&rx).await, tenant).len() >= 3
        })
        .await;
        let got = spans_in(&requests(&rx).await, tenant);
        assert_eq!(got.len(), 3, "exported == built");
        for t in &traces {
            assert!(got.iter().any(|s| s.trace_id == *t), "trace {t} exported");
        }
        remove_for_test(tenant);
    }

    /// A route that published a span some other way would be a finding: only `otlp_emit` and
    /// `trace_ingest` may publish span bytes, and both call the tap.
    #[test]
    fn og50_only_the_two_tap_sites_publish_spans() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut hits: Vec<String> = Vec::new();
        fn walk(dir: &std::path::Path, hits: &mut Vec<String>, root: &std::path::Path) {
            for e in std::fs::read_dir(dir).expect("src readable").flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, hits, root);
                } else if p.extension().is_some_and(|x| x == "rs")
                    && let Ok(text) = std::fs::read_to_string(&p)
                {
                    // Non-test half only; a doc comment naming the function is not a call.
                    let code = text.split("#[cfg(test)]").next().unwrap_or_default();
                    if code
                        .lines()
                        .filter(|l| !l.trim_start().starts_with("//"))
                        .any(|l| {
                            l.contains("publish_span_bytes(")
                                && !l.contains("fn publish_span_bytes")
                        })
                    {
                        hits.push(p.strip_prefix(root).unwrap().display().to_string());
                    }
                }
            }
        }
        walk(&root, &mut hits, &root);
        hits.sort();
        assert_eq!(hits, vec!["otlp_emit.rs", "trace_ingest.rs"]);
        for f in ["otlp_emit.rs", "trace_ingest.rs"] {
            let text = std::fs::read_to_string(root.join(f)).unwrap();
            assert!(text.contains("tap_span("), "{f} must call the tap");
        }
        // And the production registration exists: `spawn` hands `offer` to `otlp_emit`.
        let me = std::fs::read_to_string(root.join("otel_export.rs")).unwrap();
        assert!(me.contains("set_span_tap(offer)"));
    }

    // ── Spec §7 row 4: a bad collector never touches the request ─────────────────────────

    #[tokio::test]
    async fn og50_a_failing_collector_costs_the_customer_a_copy_never_a_request() {
        timing::fast();
        let tenant = Uuid::new_v4();
        let _c = tenant_claims(tenant);
        let rx = receiver(500).await;
        let rig = Chat::new(false).await;
        let id = install_for_test(
            tenant,
            &format!("{}/v1/traces", rx.uri()),
            vec![],
            false,
            1.0,
            false,
        );
        let started = Instant::now();
        for _ in 0..5 {
            assert_eq!(
                rig.chat(Uuid::new_v4(), false).await,
                StatusCode::OK,
                "the request is unaffected"
            );
            let want = rig_failed(tenant, id) + 1;
            until("a failed batch to be counted", || async {
                rig_failed(tenant, id) >= want
            })
            .await;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "no request waited on the export"
        );
        let l = live(tenant, id).expect("live");
        assert_eq!(l.failed, 5, "five spans lost after their retries");
        assert_eq!(l.delivered, 0);
        assert_eq!(l.status, "degraded", "five consecutive failed batches");
        assert_eq!(l.last_error_class.as_deref(), Some("http_500"));
        // 5 batches x (1 attempt + max_retries retries) reached the collector.
        assert_eq!(
            requests(&rx).await.len(),
            5 * (1 + config().max_retries as usize)
        );
        // NEVER auto-disabled: the collector recovers and the next batch is delivered.
        rx.reset().await;
        Mock::given(method("POST"))
            .and(path("/v1/traces"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&rx)
            .await;
        rig.chat(Uuid::new_v4(), false).await;
        until("the export to recover", || async {
            live(tenant, id).is_some_and(|l| l.delivered == 1)
        })
        .await;
        let l = live(tenant, id).unwrap();
        assert_eq!(l.status, "ok");
        assert_eq!(l.last_error_class, None);
        remove_for_test(tenant);
    }

    fn rig_failed(tenant: Uuid, id: Uuid) -> u64 {
        live(tenant, id).map_or(0, |l| l.failed)
    }

    #[tokio::test]
    async fn og50_a_slow_collector_never_slows_the_request() {
        timing::fast();
        let tenant = Uuid::new_v4();
        let _c = tenant_claims(tenant);
        let rx = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/traces"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
            .mount(&rx)
            .await;
        let rig = Chat::new(false).await;
        install_for_test(
            tenant,
            &format!("{}/v1/traces", rx.uri()),
            vec![],
            false,
            1.0,
            false,
        );
        let t = Instant::now();
        assert_eq!(rig.chat(Uuid::new_v4(), false).await, StatusCode::OK);
        assert!(
            t.elapsed() < Duration::from_millis(1500),
            "the request took {:?} with a collector that answers in 3 s",
            t.elapsed()
        );
        remove_for_test(tenant);
    }

    // ── Spec §7 row 5: overflow drops the newest and counts it ───────────────────────────

    fn sealed_for(tenant: Uuid, url: &str) -> crate::db::otel_exports::Sealed {
        crate::db::otel_exports::Sealed {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            url: url.to_owned(),
            headers_enc: None,
            enabled: true,
            include_content: false,
            sample_ratio: 1.0,
            only_errors: false,
            updated_at: chrono::Utc::now(),
        }
    }

    fn a_span(tenant: Uuid, status: SpanStatusCode) -> TracelaneSpan {
        let mut s = synthetic_span(tenant);
        s.status.code = status;
        s
    }

    #[tokio::test]
    async fn og50_a_full_queue_drops_the_newest_and_counts_it_and_the_global_ceiling_holds() {
        let tenant = Uuid::new_v4();
        // Per-export queue of 3: of 10 offers made without yielding, 3 queue and 7 drop.
        let hub = Hub::new(1_000);
        let stats = Arc::new(Stats::default());
        let e = Arc::new(Export::with_capacity(
            &sealed_for(tenant, "https://example.com/v1/traces"),
            Vec::new(),
            Arc::clone(&stats),
            3,
        ));
        e.retired.store(true, Ordering::Release); // a worker that does start sends nothing
        for _ in 0..10 {
            e.offer(&hub, &a_span(tenant, SpanStatusCode::Ok));
        }
        assert_eq!(stats.dropped(), 7);
        assert_eq!(hub.total_queued.load(Ordering::Relaxed), 3);
        assert_eq!(hub.dropped_queue_full.load(Ordering::Relaxed), 7);
        // Global ceiling of 2 across exports: memory stays bounded whatever the queue sizes.
        let hub = Hub::new(2);
        let (a, b) = (Arc::new(Stats::default()), Arc::new(Stats::default()));
        let ea = Arc::new(Export::with_capacity(
            &sealed_for(tenant, "https://a.example.com/v1/traces"),
            Vec::new(),
            Arc::clone(&a),
            100,
        ));
        let eb = Arc::new(Export::with_capacity(
            &sealed_for(tenant, "https://b.example.com/v1/traces"),
            Vec::new(),
            Arc::clone(&b),
            100,
        ));
        ea.retired.store(true, Ordering::Release);
        eb.retired.store(true, Ordering::Release);
        for _ in 0..3 {
            ea.offer(&hub, &a_span(tenant, SpanStatusCode::Ok));
            eb.offer(&hub, &a_span(tenant, SpanStatusCode::Ok));
        }
        assert_eq!(
            hub.total_queued.load(Ordering::Relaxed),
            2,
            "never past the ceiling"
        );
        assert_eq!(hub.dropped_global_full.load(Ordering::Relaxed), 4);
        assert_eq!(a.dropped() + b.dropped(), 4);
    }

    #[tokio::test]
    async fn og50_sampling_is_per_trace_and_only_errors_filters_ok_spans() {
        // The decision is a pure function of the trace id: a trace is whole or absent.
        let t = Uuid::new_v4();
        for ratio in [0.1, 0.5, 0.9] {
            let first = sampled(t, ratio);
            assert!((0..50).all(|_| sampled(t, ratio) == first));
        }
        assert!(sampled(t, 1.0) && !sampled(t, 0.0));
        let kept = (0..4000).filter(|_| sampled(Uuid::new_v4(), 0.5)).count();
        assert!((1700..2300).contains(&kept), "about half: {kept}");
        // only_errors: an OK span is not queued, an error span is.
        let tenant = Uuid::new_v4();
        let hub = Hub::new(1_000);
        let mut sealed = sealed_for(tenant, "https://example.com/v1/traces");
        sealed.only_errors = true;
        let stats = Arc::new(Stats::default());
        let e = Arc::new(Export::with_capacity(&sealed, Vec::new(), stats, 10));
        e.retired.store(true, Ordering::Release);
        e.offer(&hub, &a_span(tenant, SpanStatusCode::Ok));
        e.offer(&hub, &a_span(tenant, SpanStatusCode::Unset));
        assert_eq!(hub.total_queued.load(Ordering::Relaxed), 0);
        e.offer(&hub, &a_span(tenant, SpanStatusCode::Error));
        assert_eq!(hub.total_queued.load(Ordering::Relaxed), 1);
    }

    // ── Spec §7 row 6: SSRF ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn og50_ssrf_is_refused_at_create_and_on_every_delivery() {
        for url in [
            "https://169.254.169.254/v1/traces",
            "https://127.0.0.1/v1/traces",
            "https://localhost/v1/traces",
            "https://10.0.0.5/v1/traces",
            "https://[::1]/v1/traces",
        ] {
            assert_eq!(
                validate_url(url).await,
                Err(UrlRefusal::SsrfBlocked),
                "{url}"
            );
        }
        for url in ["http://example.com/v1/traces", "https://example.com/other"] {
            assert!(
                matches!(validate_url(url).await, Err(UrlRefusal::Invalid(_))),
                "{url}"
            );
        }
        // Delivery re-validates: an export whose URL now resolves to a blocked address (or whose
        // row was written another way) never sends, and the class never carries the URL.
        let e = send_once(
            "https://169.254.169.254/v1/traces",
            &Vec::new(),
            vec![1, 2, 3],
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(e.class, "ssrf_blocked");
        assert!(!e.retryable, "a blocked address is terminal");
        assert!(!format!("{e:?}").contains("169.254"));
        // The test-delivery route reports the same class.
        let r = test_delivery(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "https://169.254.169.254/v1/traces",
            None,
        )
        .await;
        assert!(!r.ok);
        assert_eq!(r.class, "ssrf_blocked");
    }

    #[tokio::test]
    async fn og50_a_redirect_is_not_followed_and_is_terminal() {
        let _bypass = LoopbackBypassGuard::new();
        let rx = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/traces"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "http://169.254.169.254/steal"),
            )
            .mount(&rx)
            .await;
        let e = send_once(
            &format!("{}/v1/traces", rx.uri()),
            &Vec::new(),
            vec![0],
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(e.class, "http_302");
        assert!(!e.retryable);
        assert_eq!(
            requests(&rx).await.len(),
            1,
            "the Location was not followed"
        );
    }

    #[tokio::test]
    async fn og50_a_retryable_status_honours_a_bounded_retry_after() {
        let _bypass = LoopbackBypassGuard::new();
        let rx = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/traces"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "3600"))
            .mount(&rx)
            .await;
        let e = send_once(
            &format!("{}/v1/traces", rx.uri()),
            &Vec::new(),
            vec![0],
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(e.class, "http_429");
        assert!(e.retryable);
        // The header is the receiver's; the wait is bounded by the table.
        let wait = backoff(0, e.retry_after, 0.0);
        assert!(wait <= Duration::from_secs(config().retry_after_max_secs));
        assert_eq!(wait, Duration::from_secs(config().retry_after_max_secs));
    }

    #[test]
    fn og50_backoff_is_full_jitter_capped_and_the_cooldown_doubles_to_its_ceiling() {
        let cfg = config();
        for n in 0..10 {
            let hi = backoff(n, None, 1.0);
            assert!(hi <= Duration::from_millis(cfg.retry_cap_ms));
            assert_eq!(
                backoff(n, None, 0.0),
                Duration::ZERO,
                "full jitter reaches zero"
            );
        }
        assert!(cooldown(0).is_zero() && cooldown(cfg.degraded_after_failures - 1).is_zero());
        let first = cooldown(cfg.degraded_after_failures);
        assert!(!first.is_zero());
        assert_eq!(cooldown(cfg.degraded_after_failures + 1), first * 2);
        assert_eq!(cooldown(10_000), Duration::from_secs(cfg.max_cooldown_secs));
    }

    // ── Spec §7 row 7: content ───────────────────────────────────────────────────────────

    async fn exported_text(capture: bool, include_content: bool) -> String {
        timing::fast();
        let tenant = Uuid::new_v4();
        let _c = tenant_claims(tenant);
        let rx = receiver(200).await;
        let rig = Chat::new(capture).await;
        install_for_test(
            tenant,
            &format!("{}/v1/traces", rx.uri()),
            vec![],
            include_content,
            1.0,
            false,
        );
        let trace = Uuid::new_v4();
        rig.chat(trace, false).await;
        // The span the workspace's capture policy recorded: is the prompt on it?
        let recorded = crate::otlp_emit::test_sink::for_trace(trace);
        let on_span = serde_json::to_string(&recorded[0].attributes).unwrap();
        assert_eq!(
            on_span.contains(SECRET_PROMPT),
            capture,
            "capture {capture}: the recorded span holds the prompt exactly when capture is on"
        );
        until("the export", || async { !requests(&rx).await.is_empty() }).await;
        let bytes: Vec<u8> = requests(&rx)
            .await
            .iter()
            .flat_map(|r| r.body.clone())
            .collect();
        remove_for_test(tenant);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn og50_include_content_false_ships_no_text_even_when_capture_is_on() {
        assert!(!exported_text(true, false).await.contains(SECRET_PROMPT));
    }

    #[tokio::test]
    async fn og50_include_content_true_ships_the_text_only_when_capture_stored_it() {
        assert!(exported_text(true, true).await.contains(SECRET_PROMPT));
        // Capture OFF: the span holds no text, so there is none to export whatever the flag says.
        assert!(!exported_text(false, true).await.contains(SECRET_PROMPT));
    }

    // ── Spec §7 row 8: secrets ───────────────────────────────────────────────────────────

    fn test_key() -> crate::byok::ByokMasterKey {
        crate::byok::ByokMasterKey::from_values(
            Some("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="),
            None,
            None,
        )
        .expect("valid key")
        .expect("a key")
    }

    #[test]
    fn og50_headers_are_sealed_aad_bound_and_a_pasted_blob_does_not_open() {
        let key = test_key();
        let (tenant, id) = (Uuid::new_v4(), Uuid::new_v4());
        let headers = vec![(
            "authorization".to_owned(),
            "Bearer super-secret-value".to_owned(),
        )];
        let enc = seal_headers(&key, tenant, id, &headers)
            .unwrap()
            .expect("sealed");
        assert!(!enc.contains("super-secret-value") && !enc.contains("authorization"));
        let open = open_headers(Some(&key), tenant, id, Some(&enc)).expect("opens");
        assert_eq!(open[0].0.as_str(), "authorization");
        assert_eq!(open[0].1.expose_secret(), "Bearer super-secret-value");
        // A row's blob pasted into ANOTHER export (or another tenant's) fails the GCM tag.
        assert_eq!(
            open_headers(Some(&key), tenant, Uuid::new_v4(), Some(&enc)).err(),
            Some("secret_unavailable")
        );
        assert_eq!(
            open_headers(Some(&key), Uuid::new_v4(), id, Some(&enc)).err(),
            Some("secret_unavailable")
        );
        // No master key (or a corrupt blob) fails CLOSED: the export does not deliver.
        assert!(open_headers(None, tenant, id, Some(&enc)).is_err());
        assert!(open_headers(Some(&key), tenant, id, Some("AAAA")).is_err());
        // No headers: nothing sealed, nothing to open.
        assert_eq!(seal_headers(&key, tenant, id, &[]).unwrap(), None);
        assert!(open_headers(None, tenant, id, None).unwrap().is_empty());
    }

    #[test]
    fn og50_header_validation_refuses_forbidden_malformed_oversized_and_never_echoes_a_value() {
        let ok = |v: Value| validate_headers(v.as_object().unwrap());
        let good = ok(json!({"Authorization":"Bearer abc","X-Scope-OrgID":"acme"})).unwrap();
        assert_eq!(good[0].0, "authorization", "names are lower-cased");
        let bad_cases = [
            json!({"content-type":"text/plain"}),
            json!({"Host":"evil.example.com"}),
            json!({"content-length":"1"}),
            json!({"x-a":"line1\r\nx-b: smuggled"}),
            json!({"x-a":"ünï"}),
            json!({"bad name":"v"}),
            json!({"x-a":5}),
            json!({"x-a":"y".repeat(config().max_header_value_bytes + 1)}),
        ];
        for b in bad_cases {
            let (field, message) = ok(b.clone()).unwrap_err();
            let shown = format!("{field} {message}");
            assert!(
                !shown.contains("smuggled") && !shown.contains("evil.example"),
                "{shown}"
            );
        }
        let many: serde_json::Map<String, Value> = (0..=config().max_headers)
            .map(|i| (format!("x-h{i}"), json!("v")))
            .collect();
        assert!(validate_headers(&many).is_err());
        let dup = ok(json!({"X-A":"1","x-a":"2"}));
        assert!(dup.is_err(), "names are case-insensitive");
    }

    /// Spec §7 row 10: a tenant with no export pays one directory probe — nothing is cloned,
    /// encoded or queued for it (no allocation count is claimed, only that the encode is
    /// never reached).
    #[tokio::test]
    async fn og50_a_tenant_with_no_export_costs_one_probe_and_encodes_nothing() {
        let exporting = Uuid::new_v4();
        let rx = receiver(200).await;
        install_for_test(
            exporting,
            &format!("{}/v1/traces", rx.uri()),
            vec![],
            false,
            1.0,
            false,
        );
        let quiet = Uuid::new_v4();
        let before = ENCODES.with(std::cell::Cell::get);
        for _ in 0..100 {
            offer(&a_span(quiet, SpanStatusCode::Error));
        }
        assert_eq!(
            ENCODES.with(std::cell::Cell::get),
            before,
            "nothing was encoded for a tenant with no export"
        );
        // …while the exporting tenant's span IS encoded (the counter is not dead).
        offer(&a_span(exporting, SpanStatusCode::Ok));
        assert_eq!(ENCODES.with(std::cell::Cell::get), before + 1);
        remove_for_test(exporting);
    }

    // ── Spec §7 row 9: the directory is fail-closed ──────────────────────────────────────

    fn plan_cache(granted: Vec<Uuid>) -> Arc<crate::entitlement_cache::EntitlementCache> {
        Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
            move |t| {
                let mut e = crate::entitlement_cache::ResolvedEntitlements::deny_all();
                e.f_otel_export = granted.contains(&t);
                e.max_exports = 3;
                Box::pin(async move { Ok(e) })
            },
        )))
    }

    #[tokio::test]
    async fn og50_only_a_tenant_whose_plan_grants_export_is_in_the_directory() {
        let (paid, free) = (Uuid::new_v4(), Uuid::new_v4());
        let rows = || {
            vec![
                sealed_for(paid, "https://a.example.com/v1/traces"),
                sealed_for(free, "https://b.example.com/v1/traces"),
            ]
        };
        let cache = plan_cache(vec![paid]);
        let dir = build_directory(rows(), Some(&cache), &HashMap::new()).await;
        assert!(dir.contains_key(&paid));
        assert!(!dir.contains_key(&free), "no entitlement, no export");
        // No entitlement read at all (no control plane): NOTHING exports.
        let dir = build_directory(rows(), None, &HashMap::new()).await;
        assert!(dir.is_empty());
        // An export whose sealed headers cannot be opened (here: no master key in the test
        // process) is BLOCKED: kept in the directory so it is visible, delivering nothing,
        // counting what it drops.
        let mut sealed = sealed_for(paid, "https://a.example.com/v1/traces");
        sealed.headers_enc = Some("not-a-real-blob".into());
        let dir = build_directory(vec![sealed], Some(&cache), &HashMap::new()).await;
        let blocked = Arc::clone(&dir[&paid][0]);
        assert_eq!(blocked.stats.status(), "degraded");
        assert_eq!(
            blocked.stats.last_error.lock().unwrap().as_deref(),
            Some("secret_unavailable")
        );
        let hub = Hub::new(100);
        blocked.offer(&hub, &a_span(paid, SpanStatusCode::Ok));
        assert_eq!(
            hub.total_queued.load(Ordering::Relaxed),
            0,
            "nothing queued"
        );
        assert_eq!(blocked.stats.dropped(), 1, "and the loss is counted");
        // An unchanged row keeps its live export (and queue); a changed one replaces it,
        // keeping the counters.
        let row = sealed_for(paid, "https://a.example.com/v1/traces");
        let first = build_directory(vec![row.clone()], Some(&cache), &HashMap::new()).await;
        let again = build_directory(vec![row.clone()], Some(&cache), &first).await;
        assert!(Arc::ptr_eq(&first[&paid][0], &again[&paid][0]));
        let mut changed = row;
        changed.updated_at += chrono::Duration::seconds(1);
        let replaced = build_directory(vec![changed], Some(&cache), &first).await;
        assert!(!Arc::ptr_eq(&first[&paid][0], &replaced[&paid][0]));
        assert!(Arc::ptr_eq(
            &first[&paid][0].stats,
            &replaced[&paid][0].stats
        ));
    }

    #[tokio::test]
    async fn og50_an_export_that_leaves_the_directory_is_retired() {
        let tenant = Uuid::new_v4();
        let export = Arc::new(Export::new(
            &sealed_for(tenant, "https://a.example.com/v1/traces"),
            Vec::new(),
            Arc::new(Stats::default()),
        ));
        let mut dir = Directory::new();
        dir.insert(tenant, vec![Arc::clone(&export)]);
        // `install` writes the process-wide directory; use a private swap to prove retirement.
        let hub = Hub::new(10);
        hub.directory.store(Arc::new(dir));
        let old = hub.directory.swap(Arc::new(Directory::new()));
        for e in old.values().flatten() {
            e.retired.store(true, Ordering::Release);
        }
        assert!(export.retired.load(Ordering::Acquire));
        // A retired export's worker drops what it still holds, and counts it.
        export
            .deliver(vec![encode_span(
                &a_span(tenant, SpanStatusCode::Ok),
                false,
            )])
            .await;
        assert_eq!(export.stats.dropped(), 1);
        assert_eq!(export.stats.delivered(), 0);
    }
}
