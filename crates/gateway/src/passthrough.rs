//! `OG-08` — scoped raw provider passthrough: `ANY /v1/passthrough/{provider}/{*path}`.
//!
//! A team needs a provider endpoint the gateway has not modelled yet (vector stores, a
//! brand-new route) and wants to reach it with its ONE gateway key, rate-limited and recorded
//! — without handing developers the raw provider key. **Not budget-metered** (security review
//! 2026-10-02, H2): the body is opaque and never priced, so a key or workspace WITH a budget is
//! refused `402 unpriced_under_budget` — passthrough is for unbudgeted keys only.
//!
//! ## What is deliberately NOT here
//!
//! **No request guardrails, no usage extraction, no cost.** The body is opaque, so R2/R3/R8
//! and the per-model budgets cannot see it. That is exactly why the `passthrough` scope exists
//! and why a legacy `NULL`-scope key does NOT hold it (`tracelane_shared::api_scope`): it must be
//! granted by name, per key, and `admin` does not imply it. The API docs and the key-grant UI
//! say so in the same words.
//!
//! ## Pipeline
//!
//! `auth → scope passthrough → (parse = path normalisation) → entitlements → rate limit →
//! key budget → workspace budget (a budgeted caller is refused: unpriceable) → audit
//! (fail-CLOSED)` — the ONE admission pipeline
//! (`admission::admit::<Passthrough>`), with `SCOPE = passthrough` and `INSPECTS_BODY = false`.
//! Then: BYOK key for `{provider}` → forward → stream the answer back.
//!
//! ## Upstream URL
//!
//! `{base_url}/{normalised path}?{query}`. [`normalise_path`] refuses `..`, `//`, `\`, a scheme,
//! `@`, control characters and percent-encoded slash / dot / backslash / NUL / percent
//! (`%2e %2f %5c %00 %25`, any case) with `400 invalid_passthrough_path` — on the RAW
//! (still-encoded) path, because axum's `Path` extractor would decode `%2e%2e` into `..`
//! before this code saw it. The assembled URL is then checked to still sit on the provider's
//! own scheme, host, port and base path, and goes through the SSRF guard.
//!
//! ## Headers
//!
//! Request: the caller's `Authorization`, `x-api-key`, `x-goog-api-key`, any `*api-key*` /
//! `*authorization*` header, `cookie`, hop-by-hop headers (and any header the caller's
//! `Connection` names), forwarding headers and anything carrying a `tlane_` value are dropped;
//! the PROVIDER's own auth header is set from the tenant's BYOK key. Response: `set-cookie`
//! and hop-by-hop headers are dropped.
//!
//! ## Errors
//!
//! A provider 4xx/5xx is relayed verbatim — that is what passthrough means — EXCEPT
//! 401 / 403 / 407, whose bodies can echo the credential: those become our own
//! `401 provider_key_rejected` and the body is never read (the D7 rule, `OG-10`).
//!
//! ## Fail directions (CLAUDE.md §10)
//!
//! Fail-CLOSED: auth, scope, path, provider, BYOK, SSRF, the audit publish, the body cap.
//! Fail-OPEN: span publish and spend recording (off the response path).

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use futures::{Stream, StreamExt as _};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::admission::{Malformed, Parsed, Refusal, Route};
use crate::openai_responses::coded;
use crate::providers::translation_policy::{self, PassthroughPolicy};
use crate::server::{
    AppState, CallerIdentity, GatewayTiming, SpanUsageMeta, build_gateway_span, spawn_span_publish,
};

/// The methods the route serves. Everything else is a 405 before anything is resolved.
const ALLOWED_METHODS: [Method; 5] = [
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
];

/// Longest `{provider}` segment we will even look up.
const MAX_PROVIDER_LEN: usize = 64;

/// Span attribute values the CALLER supplies (the path) are bounded to this many bytes.
const MAX_SPAN_PATH_BYTES: usize = 512;

// ── Path normalisation ───────────────────────────────────────────────────────

/// Validate the RAW (still percent-encoded) path after `/v1/passthrough/{provider}/` and return
/// it as it will be appended to the provider's base URL.
///
/// Nothing is DECODED here and nothing is rewritten: a path is either exactly what the caller
/// sent or it is refused. A refusal beats a "fix" because a normaliser that resolves `..`
/// is the thing an attacker wants to disagree with the upstream about.
///
/// # Errors
/// Fail-CLOSED: a `&'static str` reason (never echoing the input) for anything outside the
/// accepted shape.
pub(crate) fn normalise_path(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Err("the path is empty");
    }
    if raw.len() > 2048 {
        return Err("the path is longer than 2048 bytes");
    }
    if raw.starts_with('/') || raw.contains("//") {
        return Err("empty path segments (`//`) are refused");
    }
    if raw.contains("..") {
        return Err("`..` is refused");
    }
    if raw.contains('\\') {
        return Err("a backslash is refused");
    }
    if raw.contains('@') {
        return Err("`@` is refused");
    }
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .ok_or("a truncated percent-escape")?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return Err("a malformed percent-escape");
                }
                // Encoded dot, slash, backslash, NUL and percent are how a traversal is smuggled
                // past a filter that checks the decoded form (case-insensitive).
                let lower = [hex[0].to_ascii_lowercase(), hex[1].to_ascii_lowercase()];
                if matches!(&lower, b"2e" | b"2f" | b"5c" | b"00" | b"25") {
                    return Err("an encoded `.`, `/`, `\\`, NUL or `%` is refused");
                }
                i += 3;
                continue;
            }
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'/'
            | b':'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'=' => {}
            _ => return Err("a character outside the URL path alphabet"),
        }
        i += 1;
    }
    // A lone `.` segment is dot-segment resolution the upstream would apply (`a/./b`).
    if raw.split('/').any(|seg| seg == ".") {
        return Err("a `.` segment is refused");
    }
    // A scheme in the first segment (`http:`, `file:`) is an absolute-URL smuggle. `:` is legal
    // LATER in a path (Gemini's `models/x:generateContent`), so only the first segment counts.
    if let Some(first) = raw.split('/').next()
        && let Some((scheme, _)) = first.split_once(':')
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return Err("a URL scheme is refused");
    }
    Ok(raw.to_owned())
}

/// Split the raw request path into `(provider, path)`. `None` when the shape is not
/// `/v1/passthrough/{provider}/{path}`.
fn split_request_path(uri_path: &str) -> Option<(&str, &str)> {
    let rest = uri_path.strip_prefix("/v1/passthrough/")?;
    rest.split_once('/')
}

/// Does the query string carry a `key` / `api_key` parameter? Credentials never ride in a URL
/// (`OG-02` D6): URLs reach access logs and proxies, and a client `key=` would be forwarded to
/// the provider. Parsed, case-insensitive.
fn credentials_in_url(raw_query: Option<&str>) -> bool {
    raw_query.is_some_and(|q| {
        q.split('&').any(|pair| {
            let name = pair.split('=').next().unwrap_or("");
            name.eq_ignore_ascii_case("key")
                || name.eq_ignore_ascii_case("api_key")
                || name.eq_ignore_ascii_case("api-key")
        })
    })
}

// ── The admission route ──────────────────────────────────────────────────────

/// The passthrough's contribution to the ONE admission pipeline.
pub(crate) struct Passthrough;

/// What the handler hands to PARSE: the raw provider segment and the raw path.
pub(crate) struct PassthroughInput {
    pub provider: String,
    pub raw_path: String,
    pub method: Method,
}

/// How the provider's own credential is presented upstream.
#[derive(Debug, Clone)]
enum UpstreamAuth {
    /// `Authorization: Bearer <key>` — every OpenAI-compatible catalog row.
    Bearer,
    /// A native provider's own header (`x-api-key`, `x-goog-api-key`) plus defaults.
    Header {
        name: HeaderName,
        defaults: Vec<(HeaderName, HeaderValue)>,
    },
}

/// What PARSE produced.
pub(crate) struct PassthroughParsed {
    provider_id: String,
    method: Method,
    path: String,
    auth: UpstreamAuth,
    /// `passthrough:{provider}` — the label the admission error span carries.
    label: String,
    /// The opaque body has nothing a detector can read.
    view: Value,
}

impl Parsed for PassthroughParsed {
    fn model(&self) -> &str {
        &self.label
    }
    fn request_json(&self) -> &Value {
        &self.view
    }
    /// `OG-20`: the body is OPAQUE — only the provider (the path's) is known. A model or
    /// token rule therefore refuses (`policy_unenforceable`); the body size is the
    /// request's `Content-Length`, or unknown (and refused under a body cap) without one.
    fn policy_request(&self) -> tracelane_shared::key_policy::PolicyRequest {
        use tracelane_shared::key_policy::{Fact, PolicyRequest, Subject};
        PolicyRequest {
            subjects: vec![Subject {
                provider: Some(self.provider_id.clone()),
                ..Subject::unknown()
            }],
            body_bytes: Fact::Unknown,
        }
    }
}

fn invalid_path(reason: &str) -> Malformed {
    Malformed {
        code: "invalid_passthrough_path",
        message: format!("the passthrough path was refused: {reason}"),
        detail: None,
    }
}

/// Resolve `{provider}` to how its key is presented. Catalog rows are Bearer; the native
/// providers named in the reference table use their own header; every other id is refused.
fn resolve_auth(provider: &str) -> Result<UpstreamAuth, Malformed> {
    if provider.is_empty()
        || provider.len() > MAX_PROVIDER_LEN
        || !provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(Malformed {
            code: "unsupported_provider",
            message: "the provider id is not valid".into(),
            detail: None,
        });
    }
    if let Some(policy) = translation_policy::passthrough_policy()
        && let Some(n) = policy.native.iter().find(|n| n.id == provider)
    {
        let name = HeaderName::from_bytes(n.auth_header.as_bytes()).map_err(|_| Malformed {
            code: "unsupported_provider",
            message: "the provider's auth header is not configured".into(),
            detail: None,
        })?;
        let defaults = n
            .default_headers
            .iter()
            .filter_map(|(k, v)| {
                Some((
                    HeaderName::from_bytes(k.as_bytes()).ok()?,
                    HeaderValue::from_str(v).ok()?,
                ))
            })
            .collect();
        return Ok(UpstreamAuth::Header { name, defaults });
    }
    if crate::providers::catalog::by_id(provider).is_some() {
        return Ok(UpstreamAuth::Bearer);
    }
    Err(Malformed {
        code: "unsupported_provider",
        message: format!(
            "`{provider}` is not served by the passthrough — use a catalog provider id, \
             `anthropic` or `google` (Bedrock, Vertex and Azure cannot be reached by a static header)"
        ),
        detail: None,
    })
}

impl Route for Passthrough {
    type Body = PassthroughInput;
    type Parsed = PassthroughParsed;
    const NAME: &'static str = "passthrough";
    const AUDIT_EVENT_TYPE: &'static str = "passthrough.request";
    const CACHE: crate::admission::CacheScope = crate::admission::CacheScope::Unsupported;
    // OG-11 (provider objects are account-scoped: the `default` key only).
    const ROUTING: crate::routing::RoutingScope = crate::routing::RoutingScope {
        wire: crate::routing::Wire::Passthrough,
        virtual_models: crate::routing::VirtualSupport::No,
        key_pool: crate::routing::PoolSupport::DefaultOnly,
        fallthrough: false,
        timeouts: true,
    };
    /// The one route that needs a scope a legacy key does not hold.
    const SCOPE: crate::auth::scope::Scope = crate::auth::scope::Scope::Passthrough;
    const INSPECTS_BODY: bool = false;

    /// `Authorization: Bearer tlane_…`, or the key header an Anthropic / Gemini SDK sends
    /// (`x-api-key`, `x-goog-api-key`). The value goes to the SAME `validate_authorization`.
    fn credential(headers: &HeaderMap) -> Option<String> {
        let non_empty = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
        };
        if let Some(v) = non_empty("authorization") {
            return Some(v.to_owned());
        }
        let raw = non_empty("x-api-key").or_else(|| non_empty("x-goog-api-key"))?;
        Some(format!(
            "Bearer {}",
            raw.strip_prefix("Bearer ").unwrap_or(raw)
        ))
    }

    /// Path normalisation + provider resolution — BEFORE the first charge.
    fn parse(input: PassthroughInput) -> Result<PassthroughParsed, Malformed> {
        let path = normalise_path(&input.raw_path).map_err(invalid_path)?;
        let auth = resolve_auth(&input.provider)?;
        Ok(PassthroughParsed {
            label: format!("passthrough:{}", input.provider),
            provider_id: input.provider,
            method: input.method,
            path,
            auth,
            view: json!({}),
        })
    }

    /// The SHAPE — provider, method, normalised path. Never a body, never a query.
    fn audit_payload(
        parsed: &PassthroughParsed,
        trace_id: Uuid,
        _warn_aft_id: Option<&'static str>,
    ) -> Value {
        json!({
            "provider": parsed.provider_id,
            "method": parsed.method.as_str(),
            "path": truncate(&parsed.path, MAX_SPAN_PATH_BYTES),
            "trace_id": trace_id,
        })
    }

    /// `H2` (security review 2026-10-02): an opaque body to an arbitrary provider path cannot
    /// be priced, so a key or workspace with a budget is refused (402) rather than spending
    /// money the budget never sees.
    fn pricing(parsed: &PassthroughParsed) -> crate::admission::Pricing {
        crate::admission::unpriced(
            &parsed.label,
            "a raw passthrough body is opaque to the gateway and is never priced",
        )
    }

    fn refuse(refusal: Refusal) -> Response {
        match refusal {
            Refusal::InsufficientScope => coded_with(
                StatusCode::FORBIDDEN,
                "insufficient_scope",
                "This API key is not scoped for raw provider passthrough. It needs the \
                 `passthrough` scope, which is granted explicitly per key (no other scope \
                 implies it, and keys minted before scopes existed do not have it); mint a new \
                 key with it in Settings → API Keys.",
                &[("required_scope", json!("passthrough"))],
            ),
            other => crate::openai_responses::Responses::refuse(other),
        }
    }
}

/// `coded` plus extra top-level error fields.
fn coded_with(status: StatusCode, code: &str, message: &str, extra: &[(&str, Value)]) -> Response {
    crate::openai_responses::openai_error(status, code, message, None, extra)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

// ── Header filtering ─────────────────────────────────────────────────────────

/// Hop-by-hop headers (RFC 9110 §7.6.1) — never forwarded in either direction.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Request headers that never reach the provider.
fn is_withheld_request_header(name: &str) -> bool {
    is_hop_by_hop(name)
        || matches!(
            name,
            "host"
                | "content-length"
                | "expect"
                | "authorization"
                | "cookie"
                | "x-api-key"
                | "x-goog-api-key"
                | "accept-encoding"
                | "forwarded"
                | "x-real-ip"
                | "x-trace-id"
                | "traceparent"
                | "tracestate"
        )
        || name.contains("api-key")
        || name.contains("api_key")
        || name.contains("authorization")
        || name.starts_with("x-forwarded-")
        || name.starts_with("cf-")
        || name.starts_with("x-tracelane-")
}

/// The header names a message's own `Connection` header declares hop-by-hop.
fn connection_named(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// The caller's headers that DO reach the provider (content-type, accept, `anthropic-beta`,
/// idempotency keys, …). A value carrying a Tracelane key shape is withheld whatever its name.
fn forwarded_request_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    let named = connection_named(headers);
    headers
        .iter()
        .filter(|(n, v)| {
            !is_withheld_request_header(n.as_str())
                && !named.iter().any(|c| c == n.as_str())
                && !v.as_bytes().windows(6).any(|w| w == b"tlane_")
        })
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect()
}

/// Response headers relayed to the caller: everything but hop-by-hop headers (and any the
/// provider's `Connection` names) and cookies — a provider session must not land in a caller's
/// browser jar through our host.
fn relayed_response_headers(
    headers: &reqwest::header::HeaderMap,
) -> Vec<(HeaderName, HeaderValue)> {
    let named: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    headers
        .iter()
        .filter(|(n, _)| {
            let n = n.as_str();
            !is_hop_by_hop(n)
                && n != "set-cookie"
                && n != "set-cookie2"
                && !named.iter().any(|c| c == n)
        })
        .filter_map(|(n, v)| {
            Some((
                HeaderName::from_bytes(n.as_str().as_bytes()).ok()?,
                HeaderValue::from_bytes(v.as_bytes()).ok()?,
            ))
        })
        .collect()
}

// ── Upstream URL + client ────────────────────────────────────────────────────

/// The provider's origin: the catalog row's `base_url`, or the native adapter's.
fn provider_base(state: &AppState, provider_id: &str) -> Option<String> {
    match provider_id {
        "anthropic" => Some(state.providers.anthropic.base_url().to_owned()),
        "google" => Some(state.providers.google.base_url().to_owned()),
        other => state.providers.compat(other).map(|p| p.base_url.clone()),
    }
}

/// `{base}/{path}?{query}`, then proven to still sit on the provider's own scheme, host, port
/// and base path — defence in depth behind [`normalise_path`].
///
/// # Errors
/// Fail-CLOSED on an unparseable URL or one that left the provider's origin.
fn upstream_url(base: &str, path: &str, query: Option<&str>) -> anyhow::Result<reqwest::Url> {
    let base_url = reqwest::Url::parse(base.trim_end_matches('/'))?;
    let mut s = format!("{}/{path}", base.trim_end_matches('/'));
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        s.push('?');
        s.push_str(q);
    }
    let url = reqwest::Url::parse(&s)?;
    anyhow::ensure!(
        url.scheme() == base_url.scheme()
            && url.host_str() == base_url.host_str()
            && url.port_or_known_default() == base_url.port_or_known_default()
            && url.username().is_empty()
            && url.password().is_none()
            && url
                .path()
                .starts_with(base_url.path().trim_end_matches('/')),
        "the assembled URL left the provider's origin"
    );
    Ok(url)
}

/// One process-wide client: redirects off, TLS via rustls, and NO total timeout — a long
/// download must not be cut at 300 s. The time-to-response-head bound is a `tokio::time::timeout`
/// at the call site (→ 504); `read_timeout` bounds each read once the body is streaming.
fn upstream_client(policy: &PassthroughPolicy) -> anyhow::Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let built = crate::ssrf_guard::safe_client_builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(policy.upstream_timeout_secs))
        .build()?;
    Ok(CLIENT.get_or_init(|| built))
}

// ── The handler ──────────────────────────────────────────────────────────────

/// How the caller is authenticated. `Production` is the only variant a release build has.
enum Authn {
    Production,
    /// TEST-ONLY: a deliberately scoped key is not constructible through
    /// `validate_authorization` in a unit test (it reads Postgres / WorkOS).
    #[cfg(test)]
    Claims(crate::auth::Claims),
}

/// `ANY /v1/passthrough/{provider}/{*path}`.
///
/// # Errors
/// Every refusal is OpenAI-shaped JSON. Fail-CLOSED: method, `key=` in the URL, auth, the
/// `passthrough` scope, the path, the provider, rate limit, budgets, the audit publish, BYOK,
/// SSRF, the body cap.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
pub async fn passthrough_handler(State(state): State<AppState>, req: Request) -> Response {
    serve(state, req, Authn::Production).await
}

#[cfg(test)]
async fn passthrough_with_claims(
    state: AppState,
    req: Request,
    claims: crate::auth::Claims,
) -> Response {
    serve(state, req, Authn::Claims(claims)).await
}

async fn serve(state: AppState, req: Request, authn: Authn) -> Response {
    let (parts, body) = req.into_parts();
    if !ALLOWED_METHODS.contains(&parts.method) {
        let mut resp = coded(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "the passthrough serves GET, POST, PUT, PATCH and DELETE",
        );
        resp.headers_mut().insert(
            axum::http::header::ALLOW,
            HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE"),
        );
        return resp;
    }
    // BEFORE anything is resolved: a credential in the URL is refused (and would otherwise be
    // forwarded to the provider).
    if credentials_in_url(parts.uri.query()) {
        tracing::warn!("a `key` query parameter was sent to the passthrough — refusing");
        return coded(
            StatusCode::UNAUTHORIZED,
            "credentials_in_url_refused",
            "credentials in the URL are refused — send your key in the `Authorization` header; \
             a key in a URL reaches access logs and proxies",
        );
    }
    let Some(policy) = translation_policy::passthrough_policy() else {
        // The embedded table did not parse (a unit test makes that a red build). A relay with
        // no body cap and no timeout is not served.
        return coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "passthrough_unavailable",
            "the passthrough policy table is unavailable",
        );
    };
    // The raw, still-encoded path (axum's `Path` would hand back `..` for `%2e%2e`).
    let (provider, raw_path) = split_request_path(parts.uri.path()).unwrap_or(("", ""));
    let input = PassthroughInput {
        provider: provider.to_owned(),
        raw_path: raw_path.to_owned(),
        method: parts.method.clone(),
    };
    let admitted = match authn {
        Authn::Production => {
            crate::admission::admit::<Passthrough>(&state, &parts.headers, input).await
        }
        #[cfg(test)]
        Authn::Claims(claims) => {
            crate::admission::admit_with_claims::<Passthrough>(
                &state,
                &parts.headers,
                input,
                claims,
            )
            .await
        }
    };
    match admitted {
        Ok(admitted) => forward(state, parts, body, admitted, policy).await,
        Err(refusal) => Passthrough::refuse(refusal),
    }
}

/// Counts the request body as it streams upstream and refuses it past the cap.
#[derive(Default)]
struct BodyMeter {
    bytes: AtomicU64,
    exceeded: AtomicBool,
}

fn metered(
    body: Body,
    cap: u64,
    meter: Arc<BodyMeter>,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    body.into_data_stream().map(move |chunk| match chunk {
        Ok(b) => {
            let total = meter
                .bytes
                .fetch_add(b.len() as u64, Ordering::Relaxed)
                .saturating_add(b.len() as u64);
            if total > cap {
                meter.exceeded.store(true, Ordering::Relaxed);
                Err(std::io::Error::other(
                    "request body over the passthrough cap",
                ))
            } else {
                Ok(b)
            }
        }
        Err(e) => Err(std::io::Error::other(e)),
    })
}

// The send deadline includes caller-controlled upload time, even after EOF.
// It never independently measures how long the upstream had to respond.
fn head_timeout_outcome() -> crate::circuit_breaker::Outcome {
    crate::circuit_breaker::Outcome::CredentialFault
}

/// Does this request carry a body worth streaming? (`GET` / `DELETE` normally do not.)
fn has_body(headers: &HeaderMap) -> bool {
    headers.contains_key(axum::http::header::TRANSFER_ENCODING)
        || headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .is_some_and(|n| n > 0)
}

/// Everything after admission. Every exit has a ledger row behind it, so every refusal goes
/// through `dispatch_guard.abort` and the success path hands the record to [`SpanFinalizer`].
async fn forward(
    state: AppState,
    parts: axum::http::request::Parts,
    body: Body,
    admitted: crate::admission::Admitted<Passthrough>,
    policy: &'static PassthroughPolicy,
) -> Response {
    let crate::admission::Admitted {
        claims,
        identity,
        request_start,
        trace_id,
        inbound_parent,
        parsed,
        entitlements,
        correlation_id,
        mut dispatch_guard,
        ..
    } = admitted;
    let tenant_id = claims.tenant_id.clone();
    tracing::Span::current().record("tenant_id", tenant_id.to_string());
    let PassthroughParsed {
        provider_id,
        method,
        path,
        auth,
        ..
    } = parsed;

    // Cheap, header-only cap check first: an honest oversize upload never opens a connection.
    let declared = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > policy.max_request_body_bytes) {
        dispatch_guard.abort("payload_too_large", None);
        return too_large(policy);
    }

    // BYOK. Fail-CLOSED; the TENANT's own key — never another tenant's, never the operator's.
    let (key, _) = crate::openai_responses::provider_key(&tenant_id, &provider_id).await;
    let key = match key {
        Ok(k) => k,
        Err((status, code, message)) => {
            tracing::warn!(provider = %provider_id, code, "provider key unresolvable");
            dispatch_guard.abort(code, None);
            return coded(status, code, &message);
        }
    };

    let Some(base) = provider_base(&state, &provider_id) else {
        dispatch_guard.abort("unsupported_provider", None);
        return coded(
            StatusCode::BAD_REQUEST,
            "unsupported_provider",
            "the provider is not served by the passthrough",
        );
    };
    let url = match upstream_url(&base, &path, parts.uri.query()) {
        Ok(u) => u,
        Err(err) => {
            tracing::warn!(error = %err, provider = %provider_id, "passthrough URL refused");
            dispatch_guard.abort("invalid_passthrough_path", None);
            return coded(
                StatusCode::BAD_REQUEST,
                "invalid_passthrough_path",
                "the passthrough path was refused: it does not resolve to the provider",
            );
        }
    };
    if let Err(err) = crate::ssrf_guard::validate_url(url.as_str()).await {
        tracing::warn!(error = %err, provider = %provider_id, "passthrough upstream refused by the SSRF guard");
        dispatch_guard.abort("ssrf_blocked", None);
        return coded(
            StatusCode::BAD_GATEWAY,
            "provider_unavailable",
            "the provider did not serve this request",
        );
    }

    // OG-13: the adapter's region and THIS tenant's credential (`default` label only —
    // passthrough objects are account-scoped, OG-11).
    let region = state.providers.upstream_region(&provider_id).to_owned();
    let breaker_cred = crate::server::breaker_cred(
        &tenant_id,
        &provider_id,
        "default",
        entitlements.as_deref().map(|e| e.routing.as_ref()),
    );
    let killed = state.kill_switch.upstream_killed(&provider_id);
    if killed
        || !state
            .circuit_breaker
            .allow(&provider_id, &region, &breaker_cred)
    {
        dispatch_guard.abort(
            if killed {
                "upstream_killed"
            } else {
                "upstream_circuit_open"
            },
            None,
        );
        let mut resp = coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_circuit_open",
            "the provider is temporarily unavailable through this gateway",
        );
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_static("10"),
        );
        return resp;
    }

    let client = match upstream_client(policy) {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(error = %err, "passthrough client could not be built");
            dispatch_guard.abort("internal_error", None);
            return coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the request could not be prepared for the provider",
            );
        }
    };

    // ── Build the upstream request ──
    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut req = client.request(reqwest_method, url);
    let forwarded = forwarded_request_headers(&parts.headers);
    for (name, value) in &forwarded {
        req = req.header(name.as_str(), value.as_bytes());
    }
    // The provider's own credential, from the tenant's BYOK key — exposed exactly once, at the
    // header build. An empty key (a keyless provider) sets no header at all.
    let secret = key.expose_secret();
    match &auth {
        UpstreamAuth::Bearer => {
            if !secret.is_empty() {
                req = req.bearer_auth(secret);
            }
        }
        UpstreamAuth::Header { name, defaults } => {
            for (n, v) in defaults {
                if !forwarded.iter().any(|(fname, _)| fname == n) {
                    req = req.header(n.as_str(), v.as_bytes());
                }
            }
            if !secret.is_empty()
                && let Ok(mut v) = HeaderValue::from_str(secret)
            {
                v.set_sensitive(true);
                req = req.header(name.as_str(), v);
            }
        }
    }
    let meter = Arc::new(BodyMeter::default());
    if has_body(&parts.headers) {
        if let Some(n) = declared {
            req = req.header("content-length", n);
        }
        req = req.body(reqwest::Body::wrap_stream(metered(
            body,
            policy.max_request_body_bytes,
            Arc::clone(&meter),
        )));
    }

    let dispatch_ts = chrono::Utc::now();
    // `without_url`: a reqwest error renders the request URL (ONE GATEWAY D6).
    let sent = tokio::time::timeout(
        std::time::Duration::from_secs(policy.upstream_timeout_secs),
        crate::routing::deadlines::Budget::for_request(
            entitlements.as_deref(),
            &provider_id,
            "",
            request_start,
        )
        .with_breaker(&state.circuit_breaker, &provider_id, &region, &breaker_cred)
        .scope(crate::routing::deadlines::send(req)),
    )
    .await;
    let upstream = match sent {
        Err(_elapsed) => {
            // The inherited whole-head bound cancelled the configured transport before
            // it could observe an outcome itself.
            // The caller can consume this whole-send budget uploading, including
            // finishing just before expiry. It is never shared provider evidence.
            state.circuit_breaker.record(
                &provider_id,
                &region,
                &breaker_cred,
                head_timeout_outcome(),
            );
            let timeout = crate::routing::deadlines::Timeout {
                phase: "headers",
                limit_ms: policy.upstream_timeout_secs.saturating_mul(1000),
            };
            timeout.record_guard(&mut dispatch_guard, &provider_id);
            dispatch_guard.abort("upstream_timeout", None);
            return timeout.response();
        }
        Ok(Err(err)) => {
            if meter.exceeded.load(Ordering::Relaxed) {
                dispatch_guard.abort("payload_too_large", None);
                return too_large(policy);
            }
            tracing::warn!(error = %err, provider = %provider_id, "passthrough dispatch failed");
            record_breaker(
                &state,
                &provider_id,
                &region,
                &breaker_cred,
                None,
                entitlements.as_deref(),
            );
            if let Some(timeout) = crate::routing::deadlines::Timeout::find(err.as_ref()) {
                timeout.record_guard(&mut dispatch_guard, &provider_id);
                dispatch_guard.abort("upstream_timeout", None);
                return timeout.response();
            }
            dispatch_guard.abort("provider_unavailable", None);
            return coded(
                StatusCode::BAD_GATEWAY,
                "provider_unavailable",
                "the provider did not serve this request",
            );
        }
        Ok(Ok(r)) => r,
    };
    let status = upstream.status().as_u16();
    record_breaker(
        &state,
        &provider_id,
        &region,
        &breaker_cred,
        Some(status),
        entitlements.as_deref(),
    );
    if meter.exceeded.load(Ordering::Relaxed) {
        // The provider answered before the stream was cut; the cap still holds.
        dispatch_guard.abort("payload_too_large", None);
        return too_large(policy);
    }

    // D7 (OG-10): 401 / 403 / 407 bodies can echo the credential. Never read, never relayed.
    if matches!(status, 401 | 403 | 407) {
        drop(upstream);
        dispatch_guard.abort("provider_key_rejected", None);
        return coded(
            StatusCode::UNAUTHORIZED,
            "provider_key_rejected",
            &format!(
                "the stored {provider_id} key was rejected by {provider_id} — verify or rotate \
                 it in Settings → LLM providers"
            ),
        );
    }

    // Everything else is relayed, streamed. From here the finalizer owns the record.
    //
    // Re-review L-1 (2026-10-02): an ERROR body (status >= 400) is the one place a
    // provider tends to echo request details back — including, on some providers, the
    // credential. Passthrough exists so a developer never holds the provider key, so an
    // error body is buffered (capped), the tenant's own key is stripped verbatim, the rest
    // scrubbed, and only then relayed. Success bodies stay a byte-faithful stream.
    let is_error = status >= 400;
    let mut headers = relayed_response_headers(upstream.headers());
    if is_error {
        headers.retain(|(n, _)| n.as_str() != "content-length" && n.as_str() != "content-encoding");
    }
    let inner: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>> =
        if is_error {
            let mut body = upstream
                .bytes()
                .await
                .map(|b| b.to_vec())
                .unwrap_or_default();
            body.truncate(ERROR_BODY_CAP_BYTES);
            crate::openai_responses::strip_verbatim(&mut body, key.expose_secret().as_bytes());
            let clean = Bytes::from(tracelane_shared::redact::scrub(&body));
            Box::pin(futures::stream::once(async move { Ok(clean) }))
        } else {
            Box::pin(upstream.bytes_stream())
        };
    let finalizer = SpanFinalizer {
        state,
        tenant_id,
        trace_id,
        parent_span_id: inbound_parent,
        identity,
        request_start,
        dispatch_ts,
        api_key_id: claims.api_key_id().map(str::to_owned),
        provider_id,
        method: method.as_str().to_owned(),
        path,
        status,
        meter,
        bytes_out: 0,
        error_reason: None,
        timeout: None,
        finished: false,
    };
    dispatch_guard.disarm();
    let relay = Relay {
        inner,
        fin: finalizer,
    };
    let mut resp = Response::new(Body::from_stream(relay));
    *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let h = resp.headers_mut();
    for (n, v) in headers {
        h.append(n, v);
    }
    if let Ok(v) = HeaderValue::from_str(&correlation_id.to_string()) {
        h.insert("x-tracelane-correlation-id", v);
    }
    resp
}

fn too_large(policy: &PassthroughPolicy) -> Response {
    coded_with(
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
        "the request body is over the passthrough size cap",
        &[("max_bytes", json!(policy.max_request_body_bytes))],
    )
}

/// The breaker's own rule (`server::breaker_outcome`): any 4xx, 429 included (F4), is one
/// tenant's problem. Delegates rather than restates — this was a third copy of the rule.
fn record_breaker(
    state: &AppState,
    provider_id: &str,
    region: &str,
    cred: &crate::circuit_breaker::Cred,
    status: Option<u16>,
    entitlements: Option<&crate::entitlement_cache::ResolvedEntitlements>,
) {
    if let Some(ok) = crate::openai_responses::breaker_observation(status) {
        crate::routing::deadlines::record_legacy(
            &state.circuit_breaker,
            provider_id,
            region,
            cred,
            ok,
            entitlements,
            "",
        );
    }
}

// ── The record ───────────────────────────────────────────────────────────────

/// Records the passthrough span exactly once: when the response stream ends, errors, or — if the
/// caller hangs up — on `Drop`. Provider, method, normalised path, status, latency and bytes.
/// **No content, ever** (spec §3), and no usage or cost: the body is opaque.
struct SpanFinalizer {
    state: AppState,
    tenant_id: TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    identity: CallerIdentity,
    request_start: chrono::DateTime<chrono::Utc>,
    dispatch_ts: chrono::DateTime<chrono::Utc>,
    api_key_id: Option<String>,
    provider_id: String,
    method: String,
    path: String,
    status: u16,
    meter: Arc<BodyMeter>,
    bytes_out: u64,
    error_reason: Option<&'static str>,
    timeout: Option<crate::routing::deadlines::Timeout>,
    finished: bool,
}

impl SpanFinalizer {
    fn finish(&mut self, cancelled: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        let error_reason = if cancelled {
            Some("client_cancelled")
        } else if self.error_reason.is_some() {
            self.error_reason
        } else if self.status >= 400 {
            Some("upstream_error_status")
        } else {
            None
        };
        let mut span = build_gateway_span(
            &self.tenant_id,
            self.trace_id,
            self.parent_span_id,
            "passthrough",
            &self.identity,
            self.request_start,
            0,
            0,
            None,
            SpanUsageMeta::default(),
            None,
            Some(GatewayTiming {
                dispatch_ts: self.dispatch_ts,
                provider_complete_ts: chrono::Utc::now(),
                ttft_us: None,
            }),
            error_reason,
            self.api_key_id.as_deref(),
        );
        if let Some(timeout) = self.timeout {
            span.attributes.tracelane_dispatch_attempts =
                Some(vec![timeout.attempt(&self.provider_id, "")]);
        }
        span.name = "gateway.passthrough".to_owned();
        let a = &mut span.attributes;
        a.gen_ai_operation_name = Some("passthrough".to_owned());
        a.gen_ai_system = Some(self.provider_id.clone());
        a.gen_ai_provider_name = Some(self.provider_id.clone());
        // Opaque body: no model, no tokens, no cost — never a fabricated zero.
        a.gen_ai_request_model = None;
        a.gen_ai_usage_input_tokens = None;
        a.gen_ai_usage_output_tokens = None;
        a.gen_ai_usage_cost = None;
        a.tracelane_usage_cost_origin = None;
        a.tracelane_gateway_overhead_us = None;
        let latency_ms = (chrono::Utc::now() - self.request_start)
            .num_milliseconds()
            .max(0);
        for (k, v) in [
            ("tracelane.passthrough.provider", json!(self.provider_id)),
            ("tracelane.passthrough.method", json!(self.method)),
            (
                "tracelane.passthrough.path",
                json!(truncate(&self.path, MAX_SPAN_PATH_BYTES)),
            ),
            ("tracelane.passthrough.status", json!(self.status)),
            (
                "tracelane.passthrough.bytes_in",
                json!(self.meter.bytes.load(Ordering::Relaxed)),
            ),
            ("tracelane.passthrough.bytes_out", json!(self.bytes_out)),
            ("tracelane.passthrough.latency_ms", json!(latency_ms)),
        ] {
            a.extra.insert(k.to_owned(), v);
        }
        spawn_span_publish(&self.state, span);
    }
}

impl Drop for SpanFinalizer {
    fn drop(&mut self) {
        // A caller that hangs up drops the stream: record the abandonment.
        self.finish(true);
    }
}

/// The provider's response body, relayed chunk for chunk, counting bytes.
/// L-1: the most of an upstream ERROR body passthrough buffers to strip the key from
/// (the D7 relays use the same 64 KiB bound). An invariant of the relay, not a tunable.
const ERROR_BODY_CAP_BYTES: usize = 64 * 1024;

struct Relay {
    inner: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    fin: SpanFinalizer,
}

impl Stream for Relay {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(b))) => {
                self.fin.bytes_out += b.len() as u64;
                Poll::Ready(Some(Ok(b)))
            }
            Poll::Ready(Some(Err(e))) => {
                self.fin.timeout = crate::routing::deadlines::Timeout::find(&e);
                self.fin.error_reason =
                    Some(if crate::routing::deadlines::Timeout::find(&e).is_some() {
                        "upstream_timeout"
                    } else {
                        "upstream_stream_error"
                    });
                self.fin.finish(false);
                Poll::Ready(Some(Err(std::io::Error::other(e.without_url()))))
            }
            Poll::Ready(None) => {
                self.fin.finish(false);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tracelane_shared::api_scope::Scope;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::handler_harness::LoopbackBypassGuard;
    use crate::otlp_emit::test_sink as span_capture;

    // ── Fixtures ─────────────────────────────────────────────────────────────

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::new_v4())
    }

    fn claims_with(t: &TenantId, key_scope: crate::auth::scope::KeyScope) -> crate::auth::Claims {
        crate::auth::Claims {
            tenant_id: t.clone(),
            sub: format!("apikey:{}", Uuid::new_v4()),
            auth_method: crate::auth::AuthMethod::ApiKey,
            role: None,
            key_scope,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
            budget_reset: crate::spend::BudgetReset::Monthly,
            governance: None,
        }
    }

    /// A key that EXPLICITLY holds `passthrough`.
    fn granted(t: &TenantId) -> crate::auth::Claims {
        scoped(t, &[Scope::Passthrough])
    }

    fn scoped(t: &TenantId, scopes: &[Scope]) -> crate::auth::Claims {
        claims_with(
            t,
            crate::auth::scope::KeyScope::Scoped(scopes.iter().copied().collect::<BTreeSet<_>>()),
        )
    }

    fn state_for(base: &str) -> AppState {
        let mut reg = crate::providers::ProviderRegistry::new().expect("registry");
        reg.set_compat_base_url_for_test("openai", base.to_owned())
            .expect("openai");
        reg.anthropic = crate::providers::AnthropicProvider::for_base_url(base).expect("anthropic");
        crate::handler_harness::test_state_with_chain(
            reg,
            crate::handler_harness::in_memory_chain(),
        )
    }

    fn key_for(t: &TenantId, provider: &str) -> String {
        format!(
            "unit-test-{provider}-key-{}-do-not-use",
            &t.to_string()[..8]
        )
    }

    fn install_byok(t: &TenantId, provider: &'static str) {
        crate::db::provider_keys::cache_decrypted(
            t,
            provider,
            std::sync::Arc::new(secrecy::SecretString::from(key_for(t, provider))),
        );
    }

    /// A request with the caller's gateway credential, which must never reach the provider.
    fn request(method: Method, uri: &str, body: &'static [u8]) -> Request {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", "Bearer tlane_unit_test_gateway_key")
            .header("cookie", "session=client-cookie")
            .header("x-api-key", "tlane_second_credential")
            .header("x-custom-header", "kept")
            .header("x-forwarded-for", "203.0.113.9");
        if !body.is_empty() {
            b = b
                .header("content-type", "application/json")
                .header("content-length", body.len().to_string());
        }
        b.body(Body::from(body)).expect("request")
    }

    fn traced(mut req: Request, trace: Uuid) -> Request {
        req.headers_mut().insert(
            "x-trace-id",
            HeaderValue::from_str(&trace.to_string()).expect("hdr"),
        );
        req
    }

    async fn body_bytes(resp: Response) -> Bytes {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body")
    }

    async fn body_json(resp: Response) -> Value {
        serde_json::from_slice(&body_bytes(resp).await).expect("JSON body")
    }

    async fn nothing_reached(server: &MockServer) -> bool {
        server
            .received_requests()
            .await
            .is_some_and(|r| r.is_empty())
    }

    // ── Path normalisation ───────────────────────────────────────────────────

    #[tokio::test]
    async fn review_r3_stalled_upload_never_opens_shared_breaker() {
        use crate::circuit_breaker::{BreakerConfig, CircuitBreaker, Cred};
        let config = BreakerConfig::default();
        let breaker = CircuitBreaker::new(config);
        for owner in 1..=config.provider_min_open_credentials {
            let cred = Cred::byok(&Uuid::from_u128(owner as u128), "openai", "default");
            for _ in 0..config.consecutive_failure_threshold {
                let meter = Arc::new(BodyMeter::default());
                let body =
                    Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>());
                let stream = metered(body, 1024, meter.clone());
                tokio::pin!(stream);
                assert!(
                    tokio::time::timeout(std::time::Duration::ZERO, stream.next())
                        .await
                        .is_err()
                );
                breaker.record("openai", "default", &cred, head_timeout_outcome());
            }
        }
        let healthy = Cred::byok(&Uuid::from_u128(100), "openai", "default");
        assert!(
            breaker.allow("openai", "default", &healthy),
            "unfinished caller uploads must not shed another tenant"
        );
    }

    #[tokio::test]
    async fn review_r4_late_completed_upload_never_opens_shared_breaker() {
        use crate::circuit_breaker::{BreakerConfig, CircuitBreaker, Cred};
        let config = BreakerConfig::default();
        let breaker = CircuitBreaker::new(config);
        for owner in 1..=config.provider_min_open_credentials {
            let cred = Cred::byok(&Uuid::from_u128(owner as u128), "openai", "default");
            for _ in 0..config.consecutive_failure_threshold {
                let meter = Arc::new(BodyMeter::default());
                let stream = metered(Body::from("complete upload"), 1024, meter.clone());
                tokio::pin!(stream);
                while let Some(chunk) = stream.next().await {
                    chunk.unwrap();
                }
                breaker.record("openai", "default", &cred, head_timeout_outcome());
            }
        }
        let healthy = Cred::byok(&Uuid::from_u128(100), "openai", "default");
        assert!(
            breaker.allow("openai", "default", &healthy),
            "an upload finishing just before the send deadline must not shed another tenant"
        );
    }

    #[test]
    fn normalise_accepts_ordinary_provider_paths_unchanged() {
        for ok in [
            "v1/vector_stores",
            "v1/files/file-abc123/content",
            "v1beta/models/gemini-2.5-pro:generateContent",
            "v1/models/gpt-5.5",
            "v1/files/a%20b.txt",
            "v1/batches/",
        ] {
            assert_eq!(
                normalise_path(ok).as_deref(),
                Ok(ok),
                "{ok} must be accepted unchanged"
            );
        }
        // `?` never reaches here from a URI; if it did it is outside the alphabet.
        assert!(normalise_path("v1/items?x").is_err());
    }

    #[test]
    fn normalise_refuses_every_traversal_and_smuggling_shape() {
        for bad in [
            "",
            "..",
            "../x",
            "v1/../x",
            "v1/..",
            "a..b",
            "%2e%2e/x",
            "%2E%2E/x",
            "v1/%2e%2E/secret",
            "v1/.%2e/secret",
            "a%2fb",
            "a%2Fb",
            "a%5cb",
            "a%5Cb",
            "a%00b",
            "a%252e%252e/b",
            "a%zz",
            "a%2",
            "a\\b",
            "a//b",
            "/x",
            "v1/./x",
            "http://evil.example/x",
            "https:evil",
            "file:///etc/passwd",
            "user@evil.example/x",
            "v1/files@evil",
            "v1/files\nx",
            "v1/files x",
            "v1/files\u{0}",
            "v1/файл",
        ] {
            assert!(normalise_path(bad).is_err(), "{bad:?} must be refused");
        }
        // `:` is legal after the first segment (Gemini), and a first segment that is not a
        // scheme-shaped token is not a scheme.
        assert!(normalise_path("v1beta/models/x:streamGenerateContent").is_ok());
        assert!(normalise_path("9a:b").is_ok());
    }

    #[test]
    fn the_upstream_url_cannot_leave_the_provider_origin() {
        let ok = upstream_url("https://api.example.com", "v1/files", Some("limit=2")).expect("url");
        assert_eq!(ok.as_str(), "https://api.example.com/v1/files?limit=2");
        let with_base = upstream_url("https://api.example.com/openai/", "v1/x", None).expect("url");
        assert_eq!(with_base.as_str(), "https://api.example.com/openai/v1/x");
        // Defence in depth: the path is always appended after a `/`, so even one that slipped
        // past `normalise_path` (`@evil.example/x`) stays a PATH on the provider's host.
        let smuggled =
            upstream_url("https://api.example.com", "@evil.example/x", None).expect("url");
        assert_eq!(smuggled.host_str(), Some("api.example.com"));
        assert_eq!(smuggled.path(), "/@evil.example/x");
    }

    #[test]
    fn the_request_split_reads_the_raw_path() {
        assert_eq!(
            split_request_path("/v1/passthrough/openai/v1/files"),
            Some(("openai", "v1/files"))
        );
        // The raw, still-encoded form survives — axum's `Path` would have decoded it.
        assert_eq!(
            split_request_path("/v1/passthrough/openai/v1/%2e%2e/x"),
            Some(("openai", "v1/%2e%2e/x"))
        );
        assert_eq!(split_request_path("/v1/passthrough/openai"), None);
        assert_eq!(split_request_path("/v1/other/openai/x"), None);
    }

    #[test]
    fn a_key_query_parameter_is_detected_by_parsing_not_substring() {
        assert!(credentials_in_url(Some("key=abc")));
        assert!(credentials_in_url(Some("limit=2&KEY=abc")));
        assert!(credentials_in_url(Some("api_key=abc")));
        assert!(!credentials_in_url(Some("monkey=1&x=key")));
        assert!(!credentials_in_url(Some("limit=2")));
        assert!(!credentials_in_url(None));
    }

    #[test]
    fn header_filters_drop_client_auth_hop_by_hop_and_cookies_both_ways() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("authorization", "Bearer tlane_x"),
            ("x-api-key", "tlane_y"),
            ("x-goog-api-key", "tlane_z"),
            ("openai-api-key", "k"),
            ("cookie", "a=b"),
            ("connection", "keep-alive, x-secret-hop"),
            ("x-secret-hop", "1"),
            ("transfer-encoding", "chunked"),
            ("te", "trailers"),
            ("upgrade", "websocket"),
            ("proxy-authorization", "Basic abc"),
            ("x-forwarded-for", "1.2.3.4"),
            ("cf-connecting-ip", "1.2.3.4"),
            ("x-tracelane-user-id", "u"),
            ("x-note", "carries tlane_abcdef inside"),
            ("openai-beta", "assistants=v2"),
            ("content-type", "application/json"),
            ("idempotency-key", "abc"),
        ] {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).expect("name"),
                HeaderValue::from_str(v).expect("value"),
            );
        }
        let mut kept: Vec<String> = forwarded_request_headers(&h)
            .into_iter()
            .map(|(n, _)| n.as_str().to_owned())
            .collect();
        kept.sort();
        assert_eq!(
            kept,
            vec!["content-type", "idempotency-key", "openai-beta"],
            "only provider-meaningful headers survive"
        );

        let mut up = reqwest::header::HeaderMap::new();
        for (k, v) in [
            ("set-cookie", "s=1; HttpOnly"),
            ("set-cookie2", "s=2"),
            ("connection", "close, x-hop"),
            ("x-hop", "1"),
            ("transfer-encoding", "chunked"),
            ("keep-alive", "timeout=5"),
            ("content-type", "application/json"),
            ("x-request-id", "req_1"),
            ("openai-processing-ms", "12"),
        ] {
            up.append(
                reqwest::header::HeaderName::from_bytes(k.as_bytes()).expect("name"),
                reqwest::header::HeaderValue::from_str(v).expect("value"),
            );
        }
        let relayed: BTreeSet<String> = relayed_response_headers(&up)
            .into_iter()
            .map(|(n, _)| n.as_str().to_owned())
            .collect();
        assert_eq!(
            relayed,
            BTreeSet::from([
                "content-type".to_owned(),
                "openai-processing-ms".to_owned(),
                "x-request-id".to_owned()
            ])
        );
    }

    // ── The guard blocks (spec §7 row 2) ─────────────────────────────────────

    /// A legacy `NULL`-scope key — the population that holds EVERY other scope — is refused,
    /// the refusal names `passthrough`, and nothing is sent upstream or ledgered.
    #[tokio::test]
    async fn a_legacy_null_scope_key_is_403_and_nothing_is_sent() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let t = tenant();
        install_byok(&t, "openai");
        let state = state_for(&server.uri());
        let resp = passthrough_with_claims(
            state.clone(),
            request(Method::GET, "/v1/passthrough/openai/v1/vector_stores", b""),
            claims_with(&t, crate::auth::scope::KeyScope::LegacyFullSurface),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], json!("insufficient_scope"));
        assert_eq!(j["error"]["required_scope"], json!("passthrough"));
        assert!(nothing_reached(&server).await);
        assert_eq!(state.audit_chain.in_memory_seq(&t), 0, "no ledger row");
        assert!(span_capture::for_tenant(&t).is_empty());
    }

    /// H2 (security review 2026-10-02): a passthrough body is never priced, so a key with a
    /// budget is refused 402 `unpriced_under_budget` and nothing is sent or ledgered.
    #[tokio::test]
    async fn h2_a_budgeted_key_is_refused_passthrough_with_402() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let t = tenant();
        install_byok(&t, "openai");
        let state = state_for(&server.uri());
        let mut claims = granted(&t);
        claims.budget_usd_monthly = Some(25.0);
        let resp = passthrough_with_claims(
            state.clone(),
            request(Method::GET, "/v1/passthrough/openai/v1/vector_stores", b""),
            claims,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], json!("unpriced_under_budget"));
        assert!(nothing_reached(&server).await);
        assert_eq!(state.audit_chain.in_memory_seq(&t), 0, "no ledger row");
    }

    /// OG-20: a passthrough key's policy — a provider rule on the PATH's provider is
    /// judged; a model rule cannot be (the body is opaque) and refuses. Nothing is sent,
    /// nothing is ledgered.
    #[tokio::test]
    async fn og20_policy_gates_passthrough_and_nothing_is_sent() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let t = tenant();
        install_byok(&t, "openai");
        let state = state_for(&server.uri());
        let with = |doc: Value| {
            let mut c = granted(&t);
            c.governance = tracelane_shared::key_policy::Governance::from_columns(
                None,
                None,
                None,
                Some(&doc),
            )
            .map(std::sync::Arc::new);
            c
        };
        for (doc, code) in [
            (
                json!({"providers": {"deny": ["openai"]}}),
                "policy_provider_denied",
            ),
            (
                json!({"models": {"allow": ["gpt-4o"]}}),
                "policy_unenforceable",
            ),
            (json!({"max_output_tokens": 10}), "policy_unenforceable"),
        ] {
            let resp = passthrough_with_claims(
                state.clone(),
                request(Method::GET, "/v1/passthrough/openai/v1/vector_stores", b""),
                with(doc),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{code}");
            let j = body_json(resp).await;
            assert_eq!(j["error"]["code"], json!(code), "{j}");
        }
        assert!(nothing_reached(&server).await);
        assert_eq!(state.audit_chain.in_memory_seq(&t), 0, "no ledger row");
    }

    #[tokio::test]
    async fn chat_admin_read_and_ingest_keys_are_403_none_implies_passthrough() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let t = tenant();
        install_byok(&t, "openai");
        for scopes in [
            vec![Scope::Chat],
            vec![Scope::Admin],
            vec![Scope::Read],
            vec![Scope::Ingest],
            vec![Scope::Chat, Scope::Read, Scope::Ingest, Scope::Admin],
        ] {
            let resp = passthrough_with_claims(
                state_for(&server.uri()),
                request(Method::GET, "/v1/passthrough/openai/v1/vector_stores", b""),
                scoped(&t, &scopes),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{scopes:?}");
            assert_eq!(
                body_json(resp).await["error"]["required_scope"],
                json!("passthrough"),
                "{scopes:?}"
            );
        }
        assert!(nothing_reached(&server).await);
    }

    #[tokio::test]
    async fn no_credential_is_401_and_a_key_in_the_url_is_refused_first() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let state = state_for(&server.uri());
        let bare = Request::builder()
            .method(Method::GET)
            .uri("/v1/passthrough/openai/v1/files")
            .body(Body::empty())
            .expect("req");
        let resp = passthrough_handler(State(state.clone()), bare).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(resp).await["error"]["code"],
            json!("missing_credentials")
        );
        let t = tenant();
        install_byok(&t, "openai");
        let resp = passthrough_with_claims(
            state,
            request(Method::GET, "/v1/passthrough/openai/v1/files?key=abc", b""),
            granted(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(resp).await["error"]["code"],
            json!("credentials_in_url_refused")
        );
        assert!(nothing_reached(&server).await);
    }

    #[tokio::test]
    async fn traversal_variants_are_400_and_nothing_is_sent_or_ledgered() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let t = tenant();
        install_byok(&t, "openai");
        let state = state_for(&server.uri());
        for tail in [
            "..",
            "../secret",
            "v1/../secret",
            "%2e%2e/secret",
            "%2E%2E/secret",
            "v1/%2e%2e/secret",
            "v1/%2E./secret",
            "v1%2fsecret",
            "v1%2Fsecret",
            "v1%5csecret",
            "v1/a%00b",
            "v1//files",
            "http://evil.example/x",
            "user@evil.example/x",
            "v1/./files",
        ] {
            let uri = format!("/v1/passthrough/openai/{tail}");
            let resp = passthrough_with_claims(
                state.clone(),
                request(Method::GET, &uri, b""),
                granted(&t),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{tail}");
            assert_eq!(
                body_json(resp).await["error"]["code"],
                json!("invalid_passthrough_path"),
                "{tail}"
            );
        }
        assert!(nothing_reached(&server).await);
        assert_eq!(
            state.audit_chain.in_memory_seq(&t),
            0,
            "a refused path is refused BEFORE the first charge and the ledger row"
        );
    }

    #[tokio::test]
    async fn an_unsupported_provider_and_a_disallowed_method_are_refused() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let t = tenant();
        for provider in ["bedrock", "vertex", "azure", "no-such-provider", "OPENAI"] {
            let resp = passthrough_with_claims(
                state_for(&server.uri()),
                request(
                    Method::GET,
                    &format!("/v1/passthrough/{provider}/v1/x"),
                    b"",
                ),
                granted(&t),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{provider}");
            assert_eq!(
                body_json(resp).await["error"]["code"],
                json!("unsupported_provider"),
                "{provider}"
            );
        }
        for m in [Method::HEAD, Method::OPTIONS, Method::TRACE] {
            let resp = passthrough_with_claims(
                state_for(&server.uri()),
                request(m.clone(), "/v1/passthrough/openai/v1/x", b""),
                granted(&t),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{m}");
        }
        assert!(nothing_reached(&server).await);
    }

    // ── It works (spec §7 row 1) ─────────────────────────────────────────────

    /// A GET and a POST reach `{base}/path` with the BYOK key. The client's `Authorization`,
    /// `x-api-key`, cookie and forwarding headers are NOT forwarded; a custom header and the
    /// content type ARE; the query and the body arrive unchanged; the provider's `set-cookie`
    /// never reaches the caller.
    #[tokio::test]
    async fn get_and_post_reach_the_provider_with_the_byok_key_and_only_safe_headers() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/vector_stores"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("set-cookie", "provider_session=abc; HttpOnly")
                    .insert_header("x-request-id", "req_42")
                    .set_body_raw(r#"{"data":[]}"#, "application/json"),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/vector_stores"))
            .respond_with(
                ResponseTemplate::new(201).set_body_raw(r#"{"id":"vs_1"}"#, "application/json"),
            )
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t, "openai");
        let state = state_for(&server.uri());

        let resp = passthrough_with_claims(
            state.clone(),
            request(
                Method::GET,
                "/v1/passthrough/openai/v1/vector_stores?limit=2",
                b"",
            ),
            granted(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("set-cookie").is_none(),
            "a provider cookie must not land in the caller's jar through our host"
        );
        assert_eq!(
            resp.headers().get("x-request-id").map(|v| v.as_bytes()),
            Some(&b"req_42"[..])
        );
        assert!(resp.headers().get("x-tracelane-correlation-id").is_some());
        assert_eq!(
            body_bytes(resp).await,
            Bytes::from_static(br#"{"data":[]}"#)
        );

        let post_body: &'static [u8] = br#"{ "name":"kb",  "metadata":{"k":"v"} }"#;
        let resp = passthrough_with_claims(
            state.clone(),
            request(
                Method::POST,
                "/v1/passthrough/openai/v1/vector_stores",
                post_body,
            ),
            granted(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            body_bytes(resp).await,
            Bytes::from_static(br#"{"id":"vs_1"}"#)
        );

        let reqs = server.received_requests().await.expect("log");
        assert_eq!(reqs.len(), 2);
        for r in &reqs {
            assert_eq!(
                r.headers
                    .get("authorization")
                    .map(|v| v.as_bytes().to_vec()),
                Some(format!("Bearer {}", key_for(&t, "openai")).into_bytes()),
                "the provider sees the TENANT's BYOK key, never the caller's credential"
            );
            for gone in ["cookie", "x-api-key", "x-forwarded-for"] {
                assert!(
                    r.headers.get(gone).is_none(),
                    "{gone} must not be forwarded"
                );
            }
            assert_eq!(
                r.headers.get("x-custom-header").map(|v| v.as_bytes()),
                Some(&b"kept"[..])
            );
            assert!(
                !format!("{:?}", r.headers).contains("tlane_"),
                "no Tracelane credential crosses to the provider"
            );
        }
        assert_eq!(reqs[0].url.query(), Some("limit=2"));
        assert_eq!(reqs[1].body, post_body, "the body is relayed byte for byte");
        assert_eq!(
            reqs[1].headers.get("content-type").map(|v| v.as_bytes()),
            Some(&b"application/json"[..])
        );
        assert_eq!(
            state.audit_chain.in_memory_seq(&t),
            2,
            "one ledger row per admitted request"
        );
    }

    #[tokio::test]
    async fn the_span_records_provider_method_path_status_bytes_and_no_content() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let answer = r#"{"id":"file-1","secret":"RESPONSE-CONTENT"}"#;
        Mock::given(method("POST"))
            .and(path("/v1/files"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(answer, "application/json"))
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t, "openai");
        let trace = Uuid::new_v4();
        let sent: &'static [u8] = br#"{"purpose":"REQUEST-CONTENT"}"#;
        let req = traced(
            request(Method::POST, "/v1/passthrough/openai/v1/files", sent),
            trace,
        );
        let resp = passthrough_with_claims(state_for(&server.uri()), req, granted(&t)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_bytes(resp).await; // the span is recorded when the stream ends

        let spans = span_capture::for_trace(trace);
        assert_eq!(spans.len(), 1, "exactly one span: {spans:?}");
        let s = &spans[0];
        assert_eq!(s.name, "gateway.passthrough");
        let a = &s.attributes;
        assert_eq!(
            a.extra.get("tracelane.passthrough.provider"),
            Some(&json!("openai"))
        );
        assert_eq!(
            a.extra.get("tracelane.passthrough.method"),
            Some(&json!("POST"))
        );
        assert_eq!(
            a.extra.get("tracelane.passthrough.path"),
            Some(&json!("v1/files"))
        );
        assert_eq!(
            a.extra.get("tracelane.passthrough.status"),
            Some(&json!(200))
        );
        assert_eq!(
            a.extra.get("tracelane.passthrough.bytes_in"),
            Some(&json!(sent.len()))
        );
        assert_eq!(
            a.extra.get("tracelane.passthrough.bytes_out"),
            Some(&json!(answer.len()))
        );
        assert!(a.extra.contains_key("tracelane.passthrough.latency_ms"));
        // Usage is unknown and cost is unpriced — never a fabricated zero.
        assert!(a.gen_ai_usage_cost.is_none());
        assert!(a.gen_ai_usage_input_tokens.is_none());
        let dump = serde_json::to_string(s).expect("span json");
        assert!(
            !dump.contains("REQUEST-CONTENT") && !dump.contains("RESPONSE-CONTENT"),
            "no content capture, ever"
        );
        assert_eq!(s.status.code, tracelane_shared::span::SpanStatusCode::Ok);
    }

    // ── Isolation (spec §7 row 3) and the D7 rule ───────────────────────────

    #[tokio::test]
    async fn only_the_callers_tenant_key_is_ever_used() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("{}", "application/json"))
            .mount(&server)
            .await;
        let (a, b) = (tenant(), tenant());
        install_byok(&a, "openai");
        let state = state_for(&server.uri());

        // Tenant B holds the grant but has NO openai key: refused, and A's key is not borrowed.
        let resp = passthrough_with_claims(
            state.clone(),
            request(Method::GET, "/v1/passthrough/openai/v1/models", b""),
            granted(&b),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            body_json(resp).await["error"]["code"],
            json!("provider_not_configured")
        );
        assert!(nothing_reached(&server).await);

        let resp = passthrough_with_claims(
            state,
            request(Method::GET, "/v1/passthrough/openai/v1/models", b""),
            granted(&a),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let reqs = server.received_requests().await.expect("log");
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0]
                .headers
                .get("authorization")
                .map(|v| v.as_bytes().to_vec()),
            Some(format!("Bearer {}", key_for(&a, "openai")).into_bytes())
        );
    }

    /// D7 (OG-10): a 401 / 403 / 407 body can echo the credential — it is replaced, never relayed.
    #[tokio::test]
    async fn a_provider_key_rejection_is_replaced_and_the_body_never_echoed() {
        let _bypass = LoopbackBypassGuard::new();
        let t = tenant();
        install_byok(&t, "openai");
        for status in [401u16, 403, 407] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status).set_body_raw(
                    format!(
                        r#"{{"error":"Incorrect API key provided: {}"}}"#,
                        key_for(&t, "openai")
                    ),
                    "application/json",
                ))
                .mount(&server)
                .await;
            let resp = passthrough_with_claims(
                state_for(&server.uri()),
                request(Method::GET, "/v1/passthrough/openai/v1/models", b""),
                granted(&t),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{status}");
            let raw = body_bytes(resp).await;
            let text = String::from_utf8_lossy(&raw);
            assert!(text.contains("provider_key_rejected"), "{status}");
            assert!(
                !text.contains(&key_for(&t, "openai")) && !text.contains("Incorrect API key"),
                "the provider's body must not be relayed: {text}"
            );
        }
    }

    /// Re-review L-1 (2026-10-02): an upstream ERROR body that echoes the tenant's own
    /// provider key is relayed WITHOUT it — passthrough exists so a developer never holds
    /// the provider key. Status and the rest of the body are kept.
    #[tokio::test]
    async fn an_error_body_echoing_the_tenants_key_is_relayed_without_it() {
        let _bypass = LoopbackBypassGuard::new();
        let t = tenant();
        install_byok(&t, "openai");
        let key = key_for(&t, "openai");
        let body = format!(r#"{{"error":{{"message":"bad request for key {key}"}}}}"#);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(400).set_body_raw(body.clone(), "application/json"))
            .mount(&server)
            .await;
        let req = request(Method::GET, "/v1/passthrough/openai/v1/models/x", b"");
        let resp = passthrough_with_claims(state_for(&server.uri()), req, granted(&t)).await;
        assert_eq!(resp.status().as_u16(), 400);
        let got = String::from_utf8(body_bytes(resp).await.to_vec()).expect("utf8");
        assert!(!got.contains(&key), "the tenant key leaked: {got}");
        assert!(
            got.contains("bad request for key"),
            "the rest is kept: {got}"
        );
    }

    /// Every OTHER provider status is relayed verbatim — that is what passthrough means.
    #[tokio::test]
    async fn other_provider_errors_are_relayed_with_their_status_and_body() {
        let _bypass = LoopbackBypassGuard::new();
        let t = tenant();
        install_byok(&t, "openai");
        for (status, body) in [
            (400u16, r#"{"error":{"code":"invalid_value"}}"#),
            (404, r#"{"error":{"code":"not_found"}}"#),
            (429, r#"{"error":{"code":"rate_limit"}}"#),
            (500, r#"{"error":{"code":"server_error"}}"#),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status).set_body_raw(body, "application/json"))
                .mount(&server)
                .await;
            let trace = Uuid::new_v4();
            let req = traced(
                request(Method::GET, "/v1/passthrough/openai/v1/models/x", b""),
                trace,
            );
            let resp = passthrough_with_claims(state_for(&server.uri()), req, granted(&t)).await;
            assert_eq!(resp.status().as_u16(), status);
            assert_eq!(body_bytes(resp).await, Bytes::from(body));
            let spans = span_capture::for_trace(trace);
            assert_eq!(spans.len(), 1);
            assert_eq!(
                spans[0].status.code,
                tracelane_shared::span::SpanStatusCode::Error,
                "an upstream error status is an Error span ({status})"
            );
            assert_eq!(
                spans[0]
                    .attributes
                    .extra
                    .get("tracelane.passthrough.status"),
                Some(&json!(status))
            );
        }
    }

    /// A native provider: the provider's OWN header carries the BYOK key, the caller's key
    /// (which arrived in the same header name!) is not forwarded, and the documented default
    /// header is added.
    #[tokio::test]
    async fn anthropic_gets_x_api_key_from_byok_and_never_the_callers_value() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("{}", "application/json"))
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t, "anthropic");
        // The Anthropic SDK sends the gateway key in `x-api-key`.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/passthrough/anthropic/v1/models")
            .header("x-api-key", "tlane_unit_test_gateway_key")
            .body(Body::empty())
            .expect("req");
        let resp = passthrough_with_claims(state_for(&server.uri()), req, granted(&t)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let reqs = server.received_requests().await.expect("log");
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0]
                .headers
                .get("x-api-key")
                .map(|v| v.as_bytes().to_vec()),
            Some(key_for(&t, "anthropic").into_bytes())
        );
        assert_eq!(
            reqs[0]
                .headers
                .get("anthropic-version")
                .map(|v| v.as_bytes()),
            Some(&b"2023-06-01"[..])
        );
        assert!(reqs[0].headers.get("authorization").is_none());
    }

    // ── Caps (spec §5) ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_declared_oversize_body_is_413_before_any_connection() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let t = tenant();
        install_byok(&t, "openai");
        let cap = translation_policy::passthrough_policy()
            .expect("policy")
            .max_request_body_bytes;
        let mut req = request(Method::POST, "/v1/passthrough/openai/v1/files", b"{}");
        req.headers_mut().insert(
            "content-length",
            HeaderValue::from_str(&(cap + 1).to_string()).expect("hdr"),
        );
        let resp = passthrough_with_claims(state_for(&server.uri()), req, granted(&t)).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], json!("payload_too_large"));
        assert_eq!(j["error"]["max_bytes"], json!(cap));
        assert!(nothing_reached(&server).await);
    }

    /// An upload that omits its length is cut at the cap, mid-stream, and the caller gets the
    /// 413 — the cap is enforced on the bytes, not on the header.
    #[tokio::test]
    async fn a_streamed_body_over_the_cap_is_cut_and_answered_413() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t, "openai");
        let cap = translation_policy::passthrough_policy()
            .expect("policy")
            .max_request_body_bytes;
        let chunk = Bytes::from(vec![0u8; 1 << 20]);
        let n = usize::try_from(cap >> 20).expect("chunks") + 2;
        let stream =
            futures::stream::iter((0..n).map(move |_| Ok::<Bytes, std::io::Error>(chunk.clone())));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/passthrough/openai/v1/files")
            .header("authorization", "Bearer tlane_unit_test_gateway_key")
            .header("transfer-encoding", "chunked")
            .body(Body::from_stream(stream))
            .expect("req");
        let resp = passthrough_with_claims(state_for(&server.uri()), req, granted(&t)).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// The route is wired through a real router with the real admission: an unauthenticated
    /// call to the mounted path is 401 (no credential), not 404 and not a forward.
    #[tokio::test]
    async fn the_mounted_route_authenticates_before_anything_else() {
        use tower::ServiceExt as _;
        let server = MockServer::start().await;
        let app = axum::Router::new()
            .route(
                "/v1/passthrough/{provider}/{*path}",
                axum::routing::any(passthrough_handler),
            )
            .with_state(state_for(&server.uri()));
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/v1/passthrough/openai/v1/files/file-1")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(nothing_reached(&server).await);
    }
}
