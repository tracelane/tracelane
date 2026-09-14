//! B-385 — ONE typed admission pipeline for the three dispatch routes.
//!
//! `POST /v1/chat/completions`, `POST /v1/embeddings` and `POST /v1/messages` each
//! used to run the same cascade by hand, and the three copies had diverged: the
//! chat route charged the monthly quota and published the ledger row BEFORE it
//! parsed the body, `/v1/messages` parsed first, and a B-368 identity fix landed in
//! one copy of three. A request without `model` was charged and ledgered on one
//! route and refused for free on another (spec `B-385` §0).
//!
//! ## The order is a TYPE, not a comment
//!
//! ```text
//! auth → scope → PARSE → entitlements → rate limit
//!      → key budget → workspace budget → predictive (OBSERVE-first)
//!      → audit publish (fail-CLOSED)            ── then the guard is ARMED
//! ```
//!
//! [`Step`] is that order; [`ORDER`] lists it; a `const _` assertion below refuses
//! to compile a reordering that puts the first charge ahead of the parse or the
//! ledger row ahead of the charge; and [`Progress::enter`] refuses at runtime to
//! run the steps in any other sequence. The key-budget step takes the parsed
//! request's `model`, so it cannot be called before the parse — that is the
//! property, held by construction rather than by a comment that says `Step 2b`
//! above `Step 4`.
//!
//! **BILL-01 / ADR-076 (2026-09-13) deleted the monthly trace-count quota
//! step entirely.** There is no more "included quota" as a request-blocking
//! concept and no more per-request Postgres/ClickHouse round trip to seed one
//! — ADR-076 §0.4 is explicit that ingest is NEVER blocked by billing state.
//! Usage is now six independent per-unit METERS (`billing::meters`), recorded
//! off the hot path into an in-process accumulator and never consulted before
//! a response.
//!
//! ## What each route contributes
//!
//! [`Route`] is the seam. A route supplies ONLY what genuinely differs between the
//! three wires: which header carries the credential, how its body deserialises,
//! what its ledger payload looks like, and how a refusal is rendered on its wire
//! (OpenAI-shaped vs Anthropic-shaped). Everything else — the tenant seam, the
//! limiter, the trackers, the predictors, the fail-closed publish — runs here,
//! once, in one order.
//!
//! ## Refusals
//!
//! [`Refusal`] is the typed 401 / 403 / 400 / 429 / 402 / 503 the cascade already
//! produced, one variant per reason. The status codes, error codes and messages
//! on each wire are byte-identical to what the three hand-written cascades sent;
//! the tests in `handler_harness.rs` and `anthropic_messages.rs` assert them.
//! `Err(Refusal)` ALWAYS means no ledger row landed: the publish is the last
//! step, and nothing refuses after it.
//!
//! ## Fail directions (CLAUDE.md §10)
//!
//! Fail-CLOSED: auth, scope, parse, the audit publish (`503 audit_unavailable`).
//! Fail-OPEN, deliberately: the entitlement resolve (no cache ⇒ the conservative
//! 60 rpm / no allowances, never a paid tier — `.claude/rules/tenancy.md`), the
//! predictive layer (observe-first, ADR-055 amendment).

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::audit::AuditEvent;
use crate::auth::Claims;
use crate::entitlement_cache::ResolvedEntitlements;
use crate::rate_limiter::RateLimitDecision;
use crate::server::{AppState, CallerIdentity, DispatchGuard};

// ── The order ────────────────────────────────────────────────────────────────

/// The admission steps, in the ONE order every dispatch route runs them. The
/// discriminants are the order; [`ORDER`] is the same fact as a list, and the
/// `const _` below proves the two agree and that PARSE precedes the first
/// charge, which precedes the ledger row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub(crate) enum Step {
    /// The credential is validated. Nothing above this resolves anything.
    Auth = 0,
    /// A13: the `chat` scope. One comparison, before any entitlement resolve.
    Scope = 1,
    /// The route's own deserialisation. BEFORE the first charge, by construction.
    Parse = 2,
    /// One warm entitlement-cache read (never a per-request Postgres round trip).
    Entitlements = 3,
    /// The per-minute token bucket — tenant, and the key's own override (GWY-43).
    RateLimit = 4,
    /// GWY-43: the credential's own monthly USD ceiling. THIS is the first
    /// charge (BILL-01 deleted the trace-count quota that used to hold this
    /// position).
    KeyBudget = 5,
    /// GWY-43: the workspace's monthly USD ceiling.
    WorkspaceBudget = 6,
    /// The predictive layer. OBSERVE-first: a would-be block is recorded and the
    /// request proceeds unless `TRACELANE_PREDICTIVE_ENFORCE=1`.
    Predictive = 7,
    /// The tamper-evident ledger row. Fail-CLOSED; last, so an `Err` from this
    /// pipeline always means "no row landed".
    Audit = 8,
}

/// Every step, in order. `run` marks each one as it enters it, and
/// [`Progress::enter`] refuses a step that is not strictly later than the last.
pub(crate) const ORDER: [Step; 9] = [
    Step::Auth,
    Step::Scope,
    Step::Parse,
    Step::Entitlements,
    Step::RateLimit,
    Step::KeyBudget,
    Step::WorkspaceBudget,
    Step::Predictive,
    Step::Audit,
];

// B-385 (2b): parse-before-charge, and charge-before-ledger, as compile-time facts.
// Reorder the enum so that a charge precedes the parse and this file does not build.
const _: () = {
    assert!(
        (Step::Parse as u8) < (Step::KeyBudget as u8),
        "PARSE must precede the first charge (the key-budget check)"
    );
    assert!(
        (Step::KeyBudget as u8) < (Step::Audit as u8),
        "the charge must precede the ledger row, so a refused request is never ledgered"
    );
    assert!(
        (Step::Auth as u8) < (Step::Scope as u8) && (Step::Scope as u8) < (Step::Parse as u8),
        "auth, then scope, then parse — a refused credential must cost one comparison"
    );
    // ORDER is complete and strictly increasing — the list and the enum agree.
    assert!(
        ORDER.len() == 9,
        "every Step must appear in ORDER exactly once"
    );
    let mut i = 1;
    while i < ORDER.len() {
        assert!(
            (ORDER[i - 1] as u8) < (ORDER[i] as u8),
            "ORDER must be strictly increasing"
        );
        i += 1;
    }
    assert!(ORDER[0] as u8 == 0, "ORDER must start at the first step");
};

/// Where the pipeline is. `enter` is the runtime half of the order assertion: a
/// step that is not strictly later than the last one entered is a programming
/// error in this file, and it panics in debug builds rather than letting two
/// copies of a step, or a step out of sequence, run silently.
struct Progress {
    last: Option<Step>,
    #[cfg(test)]
    log: Vec<Step>,
}

impl Progress {
    const fn new() -> Self {
        Self {
            last: None,
            #[cfg(test)]
            log: Vec::new(),
        }
    }

    fn enter(&mut self, step: Step) {
        debug_assert!(
            self.last.is_none_or(|last| last < step),
            "admission step {step:?} entered after {:?} — the order is a type, not a suggestion",
            self.last
        );
        self.last = Some(step);
        #[cfg(test)]
        self.log.push(step);
    }
}

// ── The route seam ───────────────────────────────────────────────────────────

/// What PARSE produced, as the pipeline needs to see it.
pub(crate) trait Parsed {
    /// The model the CALLER asked for — verbatim, before any alias rewrite.
    fn model(&self) -> &str;
    /// The request as JSON, for the predictive layer (which reads `messages[*]`
    /// off the raw body) and for the body half of the caller identity (OBS-20).
    fn request_json(&self) -> &serde_json::Value;
}

/// One dispatch route's contribution to the pipeline. Implemented by
/// [`Chat`], [`Embeddings`] (in this file) and `anthropic_messages::Messages`.
pub(crate) trait Route: Sized {
    /// The body as the axum extractor handed it to the handler.
    type Body;
    /// What [`Route::parse`] produces.
    type Parsed: Parsed;
    /// For log lines — never a user-visible string.
    const NAME: &'static str;
    /// The ledger row's `event_type`.
    const AUDIT_EVENT_TYPE: &'static str;

    /// The credential, as `Bearer …`. `None` ⇒ 401 with the wire's own wording.
    fn credential(headers: &HeaderMap) -> Option<String>;

    /// The route's own deserialisation + validation. The `Err` carries the
    /// error code and message the wire renders (each route already words its
    /// own).
    ///
    /// # Errors
    /// Fail-CLOSED: any shape the route cannot serve is refused here, BEFORE the
    /// first charge.
    fn parse(body: Self::Body) -> Result<Self::Parsed, Malformed>;

    /// The ONE bench gate (`.claude/rules/tenancy.md`). Chat only; every other
    /// route keeps the default `false`, deliberately — a second bypass site is
    /// precisely what that rule forbids.
    fn bench_mock(_state: &AppState, _parsed: &Self::Parsed) -> bool {
        false
    }

    /// The ledger payload — the SHAPE of the request, never the prompt (the ledger
    /// is exported to third parties). `business_reference` is added by the
    /// pipeline, uniformly, only when present.
    fn audit_payload(
        parsed: &Self::Parsed,
        trace_id: Uuid,
        warn_aft_id: Option<&'static str>,
    ) -> serde_json::Value;

    /// Render a refusal on this wire. Status, error code and message per reason
    /// are the ones the route always sent.
    fn refuse(refusal: Refusal) -> Response;
}

// ── Refusals ─────────────────────────────────────────────────────────────────

/// A body the route could not serve: the wire's error `code` and the message.
/// The OpenAI chat wire renders only the message; the embeddings and Anthropic
/// wires render both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Malformed {
    pub code: &'static str,
    pub message: String,
}

/// Why admission refused. One variant per reason, rendered per wire by
/// [`Route::refuse`]. `Err(Refusal)` from the pipeline always means NO ledger row
/// landed — the publish is the last step.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Refusal {
    /// 401 — no credential in the headers this route reads.
    MissingCredentials,
    /// 401 when the credential is wrong, 503 when the store that checks it is
    /// down (`auth::failure`, B-391 c).
    AuthFailed {
        status: StatusCode,
        message: &'static str,
    },
    /// 403 — the key lacks the `chat` scope (A13).
    InsufficientScope,
    /// 400 — the route could not deserialise or validate the body.
    Malformed(Malformed),
    /// 429 — the per-minute bucket is empty.
    RateLimited { retry_after_secs: u32 },
    /// 402 — the key's own monthly USD ceiling (GWY-43).
    KeyBudgetExceeded { budget_usd: f64, spent_usd: f64 },
    /// 402 — the workspace's monthly USD ceiling (GWY-43).
    WorkspaceBudgetExceeded { budget_usd: f64, spent_usd: f64 },
    /// 403 — the predictive layer blocked AND enforcement is on.
    PredictiveBlock { aft_id: &'static str },
    /// 503 — the ledger could not record the request (fail-CLOSED, ADR-069).
    AuditUnavailable,
}

impl Refusal {
    /// The HTTP status every wire answers for this reason. The wires differ in
    /// body shape, never in status.
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::MissingCredentials => StatusCode::UNAUTHORIZED,
            Self::AuthFailed { status, .. } => *status,
            Self::InsufficientScope | Self::PredictiveBlock { .. } => StatusCode::FORBIDDEN,
            Self::Malformed(_) => StatusCode::BAD_REQUEST,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::KeyBudgetExceeded { .. } | Self::WorkspaceBudgetExceeded { .. } => {
                StatusCode::PAYMENT_REQUIRED
            }
            Self::AuditUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// The OpenAI-shaped wire (`/v1/chat/completions`, `/v1/embeddings`): the exact
/// bodies the two hand-written cascades sent. `surface` is the one word that
/// differed between them in the scope refusal ("completions" / "embeddings");
/// `malformed` is the one refusal whose body shape differed.
fn openai_refusal(
    refusal: Refusal,
    surface: &'static str,
    malformed: fn(Malformed) -> Response,
) -> Response {
    use axum::Json;
    use serde_json::json;
    let status = refusal.status();
    match refusal {
        Refusal::MissingCredentials => (
            status,
            Json(json!({ "error": "missing Authorization header" })),
        )
            .into_response(),
        Refusal::AuthFailed { message, .. } => {
            (status, Json(json!({ "error": message }))).into_response()
        }
        Refusal::InsufficientScope => (
            status,
            Json(json!({
                "error": {
                    "message": format!(
                        "This API key is not scoped for {surface}. It needs the `chat` scope; \
                         mint a new key with it in Settings → API Keys."
                    ),
                    "type": "insufficient_scope",
                    "required_scope": "chat",
                }
            })),
        )
            .into_response(),
        Refusal::Malformed(m) => malformed(m),
        Refusal::RateLimited { retry_after_secs } => {
            let mut resp = (
                status,
                Json(json!({
                    "error": "rate limit exceeded",
                    "retry_after_secs": retry_after_secs
                })),
            )
                .into_response();
            insert_retry_after(&mut resp, retry_after_secs);
            resp
        }
        Refusal::KeyBudgetExceeded {
            budget_usd,
            spent_usd,
        } => (
            // 402, not 429. A 429 says "retry later" and every OpenAI-shaped
            // client will; this is a HARD STOP that no amount of retrying
            // resolves until the budget is raised or the month rolls.
            // Telling a client to retry into a wall is how a budget cap
            // becomes a retry storm.
            status,
            Json(json!({
                "error": "key_budget_exceeded",
                "message": "this API key has reached its monthly budget",
                "budget_usd": budget_usd,
                "spent_usd": spent_usd,
                "resets_at": crate::server::next_month_boundary_iso(),
            })),
        )
            .into_response(),
        Refusal::WorkspaceBudgetExceeded {
            budget_usd,
            spent_usd,
        } => (
            status,
            Json(json!({
                "error": "workspace_budget_exceeded",
                "message": "this workspace has reached its monthly budget",
                "budget_usd": budget_usd,
                "spent_usd": spent_usd,
                "resets_at": crate::server::next_month_boundary_iso(),
            })),
        )
            .into_response(),
        Refusal::PredictiveBlock { aft_id } => (
            status,
            Json(json!({
                "error": "request blocked by Tracelane predictive guardrail",
                "aft_id": aft_id
            })),
        )
            .into_response(),
        Refusal::AuditUnavailable => {
            (status, Json(json!({ "error": "audit_unavailable" }))).into_response()
        }
    }
}

/// `Retry-After` on every 429 the pipeline produces (B-385 2c). The Anthropic
/// wire always carried it; the OpenAI-shaped routes carried only the body field.
pub(crate) fn insert_retry_after(resp: &mut Response, secs: u32) {
    if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut()
            .insert(axum::http::header::RETRY_AFTER, v);
    }
}

// ── Admitted ─────────────────────────────────────────────────────────────────

/// Everything a handler used after its hand-written cascade, in one value. The
/// `dispatch_guard` is ARMED (B-375 b): from here until the handler records a
/// span — or hands the record to a `StreamFinalizer` — a client that hangs up
/// drops the handler future, and the guard's `Drop` records the cancellation.
/// Every refusal the handler makes after this point must therefore either
/// `abort(..)` the guard (which records the reason and disarms) or record its
/// own span and `disarm()`.
pub(crate) struct Admitted<R: Route> {
    /// The validated claims. `claims.tenant_id` IS the tenant — from the
    /// credential, never from a request body (CLAUDE.md §4).
    pub claims: Claims,
    /// All five caller-supplied identity values, read ONCE and bounded ONCE —
    /// headers first, then the body half (OBS-20) off the parsed request.
    pub identity: CallerIdentity,
    pub request_start: chrono::DateTime<chrono::Utc>,
    pub trace_id: Uuid,
    pub inbound_parent: Option<Uuid>,
    pub parsed: R::Parsed,
    /// `None` only when there is no control plane (dev / OSS self-host).
    pub entitlements: Option<Arc<ResolvedEntitlements>>,
    /// The ONE bench gate's verdict. `false` on every route but chat.
    pub bench_mock: bool,
    pub warn_aft_id: Option<&'static str>,
    /// Shared by the request-side guardrail verdict and the response-side seam.
    pub correlation_id: ulid::Ulid,
    pub dispatch_guard: DispatchGuard,
    /// B-256 per-stage timing. The pipeline marks its stages; the chat handler
    /// keeps marking and emits at the dispatch boundary.
    pub timer: crate::hotpath::StageTimer,
    #[cfg(test)]
    pub steps: Vec<Step>,
}

// ── The pipeline ─────────────────────────────────────────────────────────────

/// Run the whole cascade from the raw headers and body.
///
/// # Errors
/// `Err(Refusal)` on any refusal; see [`Refusal`]. No ledger row has landed when
/// this returns `Err`.
#[tracing::instrument(skip_all, fields(route = R::NAME, tenant_id = tracing::field::Empty))]
pub(crate) async fn admit<R: Route>(
    state: &AppState,
    headers: &HeaderMap,
    body: R::Body,
) -> Result<Admitted<R>, Refusal> {
    // Captured BEFORE auth so the span's overhead number opens at the moment the
    // request arrived, not after the credential check.
    let request_start = chrono::Utc::now();
    let mut progress = Progress::new();
    progress.enter(Step::Auth);
    let Some(authorization) = R::credential(headers) else {
        return Err(Refusal::MissingCredentials);
    };
    let claims = match crate::auth::validate_authorization(&authorization).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "authentication failed");
            // B-391 (c): 503 when the auth store is down, 401 when the
            // credential is wrong (`crate::auth::failure`).
            let (status, message) = crate::auth::failure(&err);
            return Err(Refusal::AuthFailed { status, message });
        }
    };
    run::<R>(state, headers, body, claims, request_start, progress).await
}

/// The cascade from the scope gate down, with a caller-supplied credential.
///
/// TEST-ONLY. Exists so a test can drive the pipeline with a DELIBERATELY-SCOPED
/// key: `validate_authorization` reads Postgres or WorkOS, so a `read`-only key
/// is not constructible through it in a unit test, and the A13 refusal would
/// otherwise be asserted by description rather than by a run. Production has
/// exactly one way in: [`admit`].
///
/// # Errors
/// As [`admit`].
#[cfg(test)]
pub(crate) async fn admit_with_claims<R: Route>(
    state: &AppState,
    headers: &HeaderMap,
    body: R::Body,
    claims: Claims,
) -> Result<Admitted<R>, Refusal> {
    let request_start = chrono::Utc::now();
    let mut progress = Progress::new();
    // The caller authenticated; the step is accounted for so the order check
    // and the step log both read the same sequence as `admit`.
    progress.enter(Step::Auth);
    run::<R>(state, headers, body, claims, request_start, progress).await
}

/// The steps after `Auth`, in [`ORDER`]. One function, three callers.
#[tracing::instrument(skip_all, fields(route = R::NAME, tenant_id = tracing::field::Empty))]
async fn run<R: Route>(
    state: &AppState,
    headers: &HeaderMap,
    body: R::Body,
    claims: Claims,
    request_start: chrono::DateTime<chrono::Utc>,
    mut progress: Progress,
) -> Result<Admitted<R>, Refusal> {
    // Trace identity — W3C `traceparent` first (joins the caller's own trace and
    // parents our span under theirs, ADR-075 / B-311), then the legacy
    // `x-trace-id`, then a fresh UUID.
    let (trace_id, inbound_parent) = crate::trace_context::resolve_trace_identity(headers);
    // B-256: per-stage hot-path timing. Costs one `Instant::now()` per stage and
    // emits NOTHING unless the pre-dispatch segment is over threshold.
    let mut timer = crate::hotpath::StageTimer::new();

    // ── Scope (A13). Immediately after auth and BEFORE anything expensive. ──
    // A key scoped `read` (the shape you hand an external auditor) must not be
    // able to spend the tenant's provider budget. Here rather than at dispatch
    // so a refused request costs one comparison, not an entitlement resolve and
    // a detection pass. Legacy keys (`scope IS NULL`) allow everything, so this
    // is a no-op for every key minted before A13.
    progress.enter(Step::Scope);
    if !claims.allows_scope(crate::auth::scope::Scope::Chat) {
        tracing::warn!(
            sub = %claims.sub,
            route = R::NAME,
            "api key lacks the `chat` scope — refusing"
        );
        return Err(Refusal::InsufficientScope);
    }
    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());
    timer.mark("auth");

    // ── PARSE. Before the first charge, by construction: `Step::KeyBudget`
    // below reads `claims.api_key_id()`/`claims.budget_usd_monthly`, but the
    // MODEL used by the predictive layer and the ledger payload does not exist
    // until here. ──
    progress.enter(Step::Parse);
    let parsed = R::parse(body).map_err(Refusal::Malformed)?;
    // All five caller-supplied identity values, read ONCE and bounded ONCE
    // (`CallerIdentity::from_headers`). Three of them used to be read raw while
    // `x-business-reference` was bounded — B-368 — and the block was duplicated
    // across the three handlers, which is what let the two rules diverge.
    // `or_body_end_user` runs on the RAW body, before any redaction and before
    // the GWY-39 alias rewrite, so the span records what the CALLER sent.
    let identity = CallerIdentity::from_headers(headers).or_body_end_user(parsed.request_json());
    timer.mark("parse");

    // ── Entitlements (one warm resolve) ──
    // Derive the rate-limit RPM from a single warm entitlement-cache read —
    // never a per-request Postgres round trip. `plan_lookup_key` is the
    // authoritative plan (ADR-076). No cache (dev / no-Postgres) or a resolve
    // failure fails restricted to the conservative 60 rpm (never over-grant).
    //
    // B-187d: ONE grant at the entitlement layer, not N bypasses at N
    // enforcement points. Triple-gated (`.claude/rules/tenancy.md`): the env
    // flag and the reserved model are folded into `R::bench_mock`; the
    // structural third is `state.entitlements.is_none()` — `Some` iff a Postgres
    // control plane exists — and a STARTUP REFUSAL makes flag+Postgres
    // unbootable, so a real tenant cannot reach this branch even if a hosted
    // pool init failed.
    progress.enter(Step::Entitlements);
    let bench_mock = R::bench_mock(state, &parsed);
    let entitlements = if bench_mock && state.entitlements.is_none() {
        Some(Arc::new(ResolvedEntitlements::bench_unlimited()))
    } else {
        match &state.entitlements {
            Some(cache) => Some(cache.resolved(*tenant_id.as_uuid()).await),
            None => None,
        }
    };
    // No entitlement at all (OSS self-host, non-bench) fails closed to the
    // conservative 60 rpm unless the self-host OPERATOR is running with no
    // declared cap (B-386 / B-357/F8: read once at boot into
    // `state.no_control_plane_rate_limit_rpm`, no longer a process global).
    // With a control plane, `rate_limit_rpm` comes straight from
    // `ResolvedEntitlements` (BILL-01 §2.6); `None` there means unlimited too
    // (Enterprise, or the bench grant).
    let rpm = entitlements
        .as_ref()
        .map_or(state.no_control_plane_rate_limit_rpm, |e| e.rate_limit_rpm);

    // ── Rate limit: the tenant bucket AND, when the key carries an override, its
    // own (GWY-43). A key with no override behaves exactly as before. ──
    progress.enter(Step::RateLimit);
    if let RateLimitDecision::Throttle { retry_after_secs } =
        state
            .rate_limiter
            .check_scoped(tenant_id, rpm, claims.api_key_id(), claims.rate_limit_rpm)
    {
        // Count the rejection for the Gateway-ops live counter. A 429 emits no
        // span (no dispatch), so this in-process tally is how the surface reports
        // rate-limiting honestly instead of a fabricated zero.
        state.rejection_metrics.record_rate_limited(tenant_id);
        return Err(Refusal::RateLimited { retry_after_secs });
    }
    timer.mark("entitlements");

    // BILL-01 / ADR-076: the monthly trace-count hard-cap step that used to
    // live here is DELETED — ingest is never blocked by billing state. Usage
    // now accrues into six independent per-unit meters
    // (`crate::billing::meters::global()`), recorded off this path entirely.
    // The calendar key the two budget steps below seed against still needs
    // computing here.
    let year_month = crate::server::current_year_month();

    // ── Per-key budget (GWY-43, cadence added by BILL-01 A3) ──
    // THIS is the first charge. BEFORE the audit publish and the BYOK fetch,
    // so a key over its budget never causes a provider credential to be
    // decrypted. One `DashMap` probe on the warm path; the durable ClickHouse
    // seed happens once per key per window-period per process.
    //
    // The window key is the key's OWN cadence (`claims.budget_reset`:
    // daily/weekly/monthly), not the shared calendar-month `year_month` the
    // workspace step below uses — a key opted into `daily` resets every UTC
    // day regardless of what month it is.
    progress.enter(Step::KeyBudget);
    if let (Some(key_id_str), Some(budget)) = (claims.api_key_id(), claims.budget_usd_monthly)
        && let Ok(key_uuid) = Uuid::parse_str(key_id_str)
    {
        let who = crate::spend::Subject::Key(key_uuid);
        let spend = crate::spend::tracker();
        let cadence = claims.budget_reset;
        let key_window = crate::spend::window_key(cadence, chrono::Utc::now());
        if spend.needs_seed(who, key_window) {
            let baseline = crate::server::spend_baseline_from_clickhouse(
                state, tenant_id, key_id_str, cadence,
            )
            .await;
            spend.seed_if_needed(who, key_window, baseline);
        }
        if let crate::spend::BudgetDecision::Exceeded {
            budget_usd,
            spent_usd,
        } = spend.check(who, Some(budget))
        {
            state.rejection_metrics.record_budget_exceeded(tenant_id);
            tracing::warn!(
                tenant_id = %tenant_id,
                api_key_id = %key_id_str,
                budget_usd,
                spent_usd,
                "API key over its monthly budget — refusing"
            );
            return Err(Refusal::KeyBudgetExceeded {
                budget_usd,
                spent_usd,
            });
        }
    }
    timer.mark("budget_key");

    // ── Workspace monthly budget (GWY-43, the "per-team" cap) ──
    // A team in this product IS the workspace, so the per-team cap is a
    // per-tenant dollar ceiling that composes with the per-key one: a request
    // must pass BOTH. The ceiling rides the entitlement cache, so reading it
    // costs no PG round trip.
    progress.enter(Step::WorkspaceBudget);
    let workspace_budget_micro = entitlements
        .as_ref()
        .map_or(0, |e| e.workspace_budget_micro_usd);
    if workspace_budget_micro > 0 {
        let who = crate::spend::Subject::Workspace(*tenant_id.as_uuid());
        let spend = crate::spend::tracker();
        if spend.needs_seed(who, year_month) {
            let baseline =
                crate::server::workspace_spend_baseline_from_clickhouse(state, tenant_id).await;
            spend.seed_if_needed(who, year_month, baseline);
        }
        let budget_usd = workspace_budget_micro as f64 / 1_000_000.0;
        if let crate::spend::BudgetDecision::Exceeded {
            budget_usd,
            spent_usd,
        } = spend.check(who, Some(budget_usd))
        {
            state.rejection_metrics.record_budget_exceeded(tenant_id);
            tracing::warn!(
                tenant_id = %tenant_id,
                budget_usd,
                spent_usd,
                "workspace over its monthly budget — refusing"
            );
            return Err(Refusal::WorkspaceBudgetExceeded {
                budget_usd,
                spent_usd,
            });
        }
    }
    timer.mark("budget_workspace");

    // ── Predictive layer. OBSERVE-FIRST (ADR-055 amendment). ──
    // The predictors read `messages[*]` off the raw body, which is the same field
    // name on both wires. A `Block` enforces a 403 ONLY under opt-in enforcement
    // (`predictive_enforce`); by DEFAULT a would-be-block is RECORDED as a
    // flagged event and the request proceeds, so a false positive never breaks a
    // legitimate agent run.
    progress.enter(Step::Predictive);
    let decision = state
        .predictive
        .evaluate_async(&crate::predictive::PredictiveContext {
            tenant_id,
            request_json: parsed.request_json(),
        })
        .await;
    let warn_aft_id: Option<&'static str> = match decision {
        crate::predictive::Decision::Allow => None,
        crate::predictive::Decision::Warn { aft_id } => Some(aft_id),
        crate::predictive::Decision::Block { aft_id } => {
            if state.predictive_enforce {
                tracing::warn!(%aft_id, "request blocked by predictive guardrail (enforcement mode)");
                return Err(Refusal::PredictiveBlock { aft_id });
            }
            tracing::warn!(
                %aft_id,
                "predictive guardrail would BLOCK (observe-first: recorded, not enforced — set TRACELANE_PREDICTIVE_ENFORCE=1 to enforce)"
            );
            Some(aft_id)
        }
    };
    timer.mark("detection");

    // ── Audit log. Fail-CLOSED (ADR-069). LAST, so `Err` never means "ledgered". ──
    // Durable CAPTURE before dispatch (acked JetStream publish); the head-advance
    // runs off the request path. A publish failure 503s — the audit product does
    // not serve unrecorded requests. Since A2 the SYNCHRONOUS fallback is
    // fail-closed too. Dev / self-host never hit it: with no Postgres pool the
    // append is in-memory and cannot fail.
    progress.enter(Step::Audit);
    let mut audit_payload = R::audit_payload(&parsed, trace_id, warn_aft_id);
    // Customer business reference (wedge item 5), when supplied — ties the
    // tamper-evident record to a business event. Inserted ONLY when present so an
    // ordinary row's canonical payload is byte-unchanged (a perpetual
    // `business_reference: null` on every row would be noise in the immutable
    // ledger). Already length-bounded at the header boundary.
    if let Some(ref br) = identity.business_reference {
        audit_payload["business_reference"] = serde_json::Value::String(br.clone());
    }
    let audit_event = AuditEvent {
        tenant_id: tenant_id.clone(),
        event_type: R::AUDIT_EVENT_TYPE,
        actor: claims.sub.clone(),
        payload: audit_payload,
    };
    if let Err(err) = state.audit_chain.publish(audit_event).await {
        tracing::error!(error = %err, "audit publish failed — refusing request (fail-closed)");
        return Err(Refusal::AuditUnavailable);
    }
    timer.mark("audit");

    // The ledger row exists. From here every exit must leave a span (R13), and a
    // client that hangs up must leave one too (B-375 b): arm the guard NOW, not
    // at the dispatch boundary — the BYOK lookup and the guardrail verdict both
    // await, and a cancel inside either used to record nothing.
    let dispatch_guard = DispatchGuard::arm(
        state,
        tenant_id,
        trace_id,
        inbound_parent,
        parsed.model(),
        &identity,
        request_start,
    );
    Ok(Admitted {
        identity,
        request_start,
        trace_id,
        inbound_parent,
        parsed,
        entitlements,
        bench_mock,
        warn_aft_id,
        correlation_id: ulid::Ulid::new(),
        dispatch_guard,
        timer,
        #[cfg(test)]
        steps: progress.log,
        claims,
    })
}

// ── The two OpenAI-shaped routes ─────────────────────────────────────────────

/// `POST /v1/chat/completions`.
pub(crate) struct Chat;

/// What the chat route parsed: the raw body (the predictors, the prompt
/// observation and the guardrail RAG context all read it) and the typed request.
pub(crate) struct ChatParsed {
    pub body: serde_json::Value,
    pub request: tracelane_shared::ChatRequest,
}

impl Parsed for ChatParsed {
    fn model(&self) -> &str {
        &self.request.model
    }
    fn request_json(&self) -> &serde_json::Value {
        &self.body
    }
}

impl Route for Chat {
    type Body = serde_json::Value;
    type Parsed = ChatParsed;
    const NAME: &'static str = "chat";
    const AUDIT_EVENT_TYPE: &'static str = "chat.completions.request";

    fn credential(headers: &HeaderMap) -> Option<String> {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    fn parse(body: serde_json::Value) -> Result<ChatParsed, Malformed> {
        let request = serde_json::from_value::<tracelane_shared::ChatRequest>(body.clone())
            .map_err(|err| Malformed {
                code: "invalid_request",
                message: format!("malformed request: {err}"),
            })?;
        Ok(ChatParsed { body, request })
    }

    /// The ONE bench gate. Sits after auth and after `tenant_id` is bound from
    /// claims (the pipeline's order), so an unauthenticated request can never
    /// reach it. Consumed by the entitlement grant above AND by the routing /
    /// BYOK / dispatch bypasses in the chat handler — one expression, all uses.
    fn bench_mock(state: &AppState, parsed: &ChatParsed) -> bool {
        crate::server::bench_mock_active(state.bench_mock_upstream, &parsed.request.model)
    }

    fn audit_payload(
        parsed: &ChatParsed,
        trace_id: Uuid,
        warn_aft_id: Option<&'static str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "model": parsed.request.model,
            "warn_aft_id": warn_aft_id,
            // Correlation key for the per-trace "in tamper-evident ledger" chip
            // (wedge item 4). Non-secret W3C trace id; serde renders the Uuid
            // hyphenated-lowercase, byte-identical to the `spans.trace_id`
            // string so the chip endpoint joins the two by equality.
            "trace_id": trace_id,
        })
    }

    fn refuse(refusal: Refusal) -> Response {
        // The chat wire's malformed body carries the message only — the shape
        // it always sent.
        openai_refusal(refusal, "completions", |m| {
            (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": m.message })),
            )
                .into_response()
        })
    }
}

/// `POST /v1/embeddings`.
pub(crate) struct Embeddings;

pub(crate) struct EmbeddingsParsed {
    pub body: serde_json::Value,
    pub request: crate::providers::EmbeddingsRequest,
}

impl Parsed for EmbeddingsParsed {
    fn model(&self) -> &str {
        &self.request.model
    }
    fn request_json(&self) -> &serde_json::Value {
        &self.body
    }
}

impl Route for Embeddings {
    type Body = serde_json::Value;
    type Parsed = EmbeddingsParsed;
    const NAME: &'static str = "embeddings";
    const AUDIT_EVENT_TYPE: &'static str = "embeddings.request";

    fn credential(headers: &HeaderMap) -> Option<String> {
        Chat::credential(headers)
    }

    fn parse(body: serde_json::Value) -> Result<EmbeddingsParsed, Malformed> {
        let request = serde_json::from_value::<crate::providers::EmbeddingsRequest>(body.clone())
            .map_err(|err| Malformed {
            code: "invalid_request",
            message: format!("malformed embeddings request: {err}"),
        })?;
        request.validate().map_err(|err| Malformed {
            code: "invalid_request",
            message: format!("{err}"),
        })?;
        Ok(EmbeddingsParsed { body, request })
    }

    /// The payload records WHAT was embedded structurally (model, how many
    /// inputs) and never the input text itself: embedding input is raw customer
    /// documents, and the ledger is exported to third parties for verification.
    fn audit_payload(
        parsed: &EmbeddingsParsed,
        trace_id: Uuid,
        _warn_aft_id: Option<&'static str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "model": parsed.request.model,
            "input_count": parsed.request.input_count(),
            "trace_id": trace_id,
        })
    }

    fn refuse(refusal: Refusal) -> Response {
        openai_refusal(refusal, "embeddings", |m| {
            crate::server::provider_error_response(
                StatusCode::BAD_REQUEST,
                m.code,
                Some(&m.message),
                None,
                None,
            )
        })
    }
}

// `debug_assertions` as well as `test`: the harness these tests drive is gated
// that way (`main.rs`, `ssrf_guard.rs`).
#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::handler_harness::{authed, dev_tenant, test_state};
    use crate::providers::ProviderRegistry;
    use serde_json::json;
    use std::collections::BTreeSet;

    fn chat_body() -> serde_json::Value {
        json!({ "model": "ollama/llama3", "messages": [{"role": "user", "content": "hi"}] })
    }

    /// A key scoped to exactly `scopes` — the shape A13 exists for.
    fn scoped_claims(scopes: &[crate::auth::scope::Scope]) -> Claims {
        Claims {
            key_scope: crate::auth::scope::KeyScope::Scoped(
                scopes.iter().copied().collect::<BTreeSet<_>>(),
            ),
            ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey)
        }
    }

    // ── The order, observed ──

    #[tokio::test]
    async fn a_full_admission_runs_every_step_in_order() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let a = admit::<Chat>(&state, &authed(), chat_body())
            .await
            .unwrap_or_else(|r| panic!("admission refused: {r:?}"));
        assert_eq!(
            a.steps,
            ORDER.to_vec(),
            "the steps run must be ORDER, exactly"
        );
        assert_eq!(a.parsed.model(), "ollama/llama3");
        // The ledger row landed, once, and the guard is armed.
        assert_eq!(state.audit_chain.in_memory_seq(&dev_tenant()), 1);
        let mut a = a;
        a.dispatch_guard.disarm();
    }

    #[tokio::test]
    async fn a_malformed_body_stops_at_parse_and_charges_nothing() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let r = admit::<Chat>(&state, &authed(), json!({ "messages": [] })).await;
        assert!(
            matches!(r, Err(Refusal::Malformed(ref m)) if m.message.starts_with("malformed request:")),
            "{:?}",
            r.as_ref().err()
        );
        assert_eq!(state.audit_chain.in_memory_seq(&dev_tenant()), 0);
    }

    /// B-230 / A13, behaviourally: a `read`-scoped key is refused at SCOPE — after
    /// auth, before the entitlement resolve, the parse and the ledger.
    /// This replaces the string-offset half of the old
    /// `every_b230_route_gates_on_scope_after_authenticating` for the routes on
    /// the pipeline.
    #[tokio::test]
    async fn a_read_scoped_key_is_refused_at_scope_before_any_charge() {
        use crate::auth::scope::Scope;
        let state = test_state(ProviderRegistry::new().expect("registry"));
        for body in [chat_body(), json!({ "not even": "a chat body" })] {
            let r =
                admit_with_claims::<Chat>(&state, &authed(), body, scoped_claims(&[Scope::Read]))
                    .await;
            assert!(
                matches!(r, Err(Refusal::InsufficientScope)),
                "{:?}",
                r.err()
            );
        }
        // Embeddings, same gate, same position.
        let r = admit_with_claims::<Embeddings>(
            &state,
            &authed(),
            json!({ "model": "text-embedding-3-small", "input": "hi" }),
            scoped_claims(&[Scope::Read]),
        )
        .await;
        assert!(
            matches!(r, Err(Refusal::InsufficientScope)),
            "{:?}",
            r.err()
        );
        assert_eq!(state.audit_chain.in_memory_seq(&dev_tenant()), 0);
        // ...and a `chat`-scoped key passes the gate.
        let a = admit_with_claims::<Chat>(
            &state,
            &authed(),
            chat_body(),
            scoped_claims(&[Scope::Chat]),
        )
        .await
        .unwrap_or_else(|r| panic!("a chat-scoped key must pass the scope gate: {r:?}"));
        let mut a = a;
        a.dispatch_guard.disarm();
    }

    #[tokio::test]
    async fn no_credential_is_refused_before_anything_runs() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let r = admit::<Chat>(&state, &HeaderMap::new(), chat_body()).await;
        assert!(matches!(r, Err(Refusal::MissingCredentials)));
        let r = admit::<Embeddings>(
            &state,
            &HeaderMap::new(),
            json!({ "model": "text-embedding-3-small", "input": "hi" }),
        )
        .await;
        assert!(matches!(r, Err(Refusal::MissingCredentials)));
        assert_eq!(state.audit_chain.in_memory_seq(&dev_tenant()), 0);
    }

    // ── The bench gate (B-187b/d), behaviourally instead of by string offset ──

    /// An unauthenticated request for the reserved model NEVER reaches the bench
    /// grant — auth is a strictly earlier step. Replaces
    /// `bench_mock_bypass_sits_after_auth_and_tenant_resolution`.
    #[tokio::test]
    async fn the_bench_grant_is_unreachable_without_a_credential() {
        let mut state = test_state(ProviderRegistry::new().expect("registry"));
        state.bench_mock_upstream = true;
        let body =
            json!({ "model": "__bench_mock", "messages": [{"role": "user", "content": "x"}] });
        let r = admit::<Chat>(&state, &HeaderMap::new(), body).await;
        assert!(matches!(r, Err(Refusal::MissingCredentials)));
    }

    /// Condition 3 of the triple gate, behaviourally: with NO control plane the
    /// flag + reserved model yield the bench grant; with a control plane present
    /// the same request does NOT. Replaces `bench_grant_branch_matches_production_shape`,
    /// which pinned the `if` condition as a string.
    #[tokio::test]
    async fn the_bench_grant_needs_the_flag_the_model_and_no_control_plane() {
        let body =
            || json!({ "model": "__bench_mock", "messages": [{"role": "user", "content": "x"}] });
        let real = || chat_body();

        // (flag, model) with no control plane → the grant.
        let mut state = test_state(ProviderRegistry::new().expect("registry"));
        state.bench_mock_upstream = true;
        let mut a = admit::<Chat>(&state, &authed(), body())
            .await
            .unwrap_or_else(|r| panic!("{r:?}"));
        assert!(a.bench_mock);
        assert!(
            a.entitlements.as_ref().is_some_and(|e| e.is_bench()),
            "flag + reserved model + no control plane must confer the bench grant"
        );
        a.dispatch_guard.disarm();

        // Flag on, REAL model → no grant.
        let mut a = admit::<Chat>(&state, &authed(), real())
            .await
            .unwrap_or_else(|r| panic!("{r:?}"));
        assert!(!a.bench_mock);
        assert!(
            a.entitlements.is_none(),
            "a real model must not be granted the bench tier"
        );
        a.dispatch_guard.disarm();

        // Flag OFF, reserved model → no grant.
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let mut a = admit::<Chat>(&state, &authed(), body())
            .await
            .unwrap_or_else(|r| panic!("{r:?}"));
        assert!(!a.bench_mock);
        assert!(a.entitlements.is_none());
        a.dispatch_guard.disarm();

        // Flag on, reserved model, but a CONTROL PLANE exists → the structural
        // third condition denies the grant even though the other two hold.
        let mut state = test_state(ProviderRegistry::new().expect("registry"));
        state.bench_mock_upstream = true;
        let real_tenant: crate::entitlement_cache::ResolveFn =
            Arc::new(|_t| Box::pin(async { Ok(ResolvedEntitlements::deny_all()) }));
        state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
            real_tenant,
        )));
        let mut a = admit::<Chat>(&state, &authed(), body())
            .await
            .unwrap_or_else(|r| panic!("{r:?}"));
        assert!(
            a.bench_mock,
            "the gate itself still fires — it is the GRANT that is denied"
        );
        assert!(
            a.entitlements.as_ref().is_some_and(|e| !e.is_bench()),
            "a tenant with a control plane must never acquire the bench tier"
        );
        a.dispatch_guard.disarm();
    }

    /// Embeddings never has a bench arm — the default `false`, observed.
    #[tokio::test]
    async fn embeddings_has_no_bench_arm() {
        let mut state = test_state(ProviderRegistry::new().expect("registry"));
        state.bench_mock_upstream = true;
        let mut a = admit::<Embeddings>(
            &state,
            &authed(),
            json!({ "model": "__bench_mock", "input": "x" }),
        )
        .await
        .unwrap_or_else(|r| panic!("{r:?}"));
        assert!(!a.bench_mock);
        assert!(a.entitlements.is_none());
        a.dispatch_guard.disarm();
    }

    // ── Refusal rendering: the bytes each wire sends ──

    #[test]
    fn every_refusal_has_the_status_the_cascade_always_sent() {
        let cases = [
            (Refusal::MissingCredentials, 401),
            (
                Refusal::AuthFailed {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    message: "auth store unavailable",
                },
                503,
            ),
            (Refusal::InsufficientScope, 403),
            (
                Refusal::Malformed(Malformed {
                    code: "invalid_request",
                    message: "x".into(),
                }),
                400,
            ),
            (
                Refusal::RateLimited {
                    retry_after_secs: 3,
                },
                429,
            ),
            (
                Refusal::KeyBudgetExceeded {
                    budget_usd: 1.0,
                    spent_usd: 2.0,
                },
                402,
            ),
            (
                Refusal::WorkspaceBudgetExceeded {
                    budget_usd: 1.0,
                    spent_usd: 2.0,
                },
                402,
            ),
            (Refusal::PredictiveBlock { aft_id: "AFT-X" }, 403),
            (Refusal::AuditUnavailable, 503),
        ];
        for (r, want) in cases {
            assert_eq!(r.status().as_u16(), want, "{r:?}");
            assert_eq!(
                Chat::refuse(r.clone()).status().as_u16(),
                want,
                "chat {r:?}"
            );
            assert_eq!(
                Embeddings::refuse(r.clone()).status().as_u16(),
                want,
                "embeddings {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_429_carries_retry_after_on_the_openai_wire() {
        let resp = Chat::refuse(Refusal::RateLimited {
            retry_after_secs: 7,
        });
        assert_eq!(
            resp.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("7")
        );
        let body = crate::handler_harness::body_json(resp).await;
        assert_eq!(body["error"], "rate limit exceeded");
        assert_eq!(body["retry_after_secs"], 7);
    }

    #[tokio::test]
    async fn the_scope_refusal_names_the_surface() {
        let chat =
            crate::handler_harness::body_json(Chat::refuse(Refusal::InsufficientScope)).await;
        assert_eq!(
            chat["error"]["message"],
            "This API key is not scoped for completions. It needs the `chat` scope; mint a new key with it in Settings → API Keys."
        );
        assert_eq!(chat["error"]["type"], "insufficient_scope");
        assert_eq!(chat["error"]["required_scope"], "chat");
        let emb =
            crate::handler_harness::body_json(Embeddings::refuse(Refusal::InsufficientScope)).await;
        assert_eq!(
            emb["error"]["message"],
            "This API key is not scoped for embeddings. It needs the `chat` scope; mint a new key with it in Settings → API Keys."
        );
    }

    #[tokio::test]
    async fn the_malformed_refusal_keeps_each_wire_s_own_shape() {
        let chat = crate::handler_harness::body_json(Chat::refuse(Refusal::Malformed(Malformed {
            code: "invalid_request",
            message: "malformed request: x".into(),
        })))
        .await;
        assert_eq!(chat["error"], "malformed request: x");
        let emb =
            crate::handler_harness::body_json(Embeddings::refuse(Refusal::Malformed(Malformed {
                code: "invalid_request",
                message: "malformed embeddings request: y".into(),
            })))
            .await;
        assert_eq!(emb["error"], "invalid_request");
        assert_eq!(emb["message"], "malformed embeddings request: y");
    }
}
