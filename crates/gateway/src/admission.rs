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
//! auth (+ OG-20 source_ips) → scope → PARSE → entitlements → CONTROLS (OG-25)
//!      → rate limit → POLICY (OG-20) → LIMITS (OG-21) → key budget → workspace budget
//!      → BUDGETS (OG-22) → predictive (OBSERVE-first)
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
    /// `OG-25`: the workspace's own controls, off the entitlement read — a paused
    /// workspace (`423`), a blocked model / provider / end user (`403`). BEFORE the rate
    /// limit, so a refused request costs no bucket token. Fail-CLOSED.
    Controls = 4,
    /// The per-minute token bucket — tenant, and the key's own override (GWY-43).
    RateLimit = 5,
    /// `OG-20`: the key.s (and its project.s) policy — model / provider allow-deny,
    /// token and body caps, required labels — against what the route parsed. After
    /// the bucket (a stolen key flooding denied requests is still throttled), BEFORE
    /// the first charge and the ledger row. Fail-CLOSED. (`source_ips` is enforced
    /// earlier still, at authentication.)
    Policy = 6,
    /// `OG-21`: RPM / TPM buckets of the workspace, project and key layers (and their
    /// per-end-user and per-model buckets) — all must have room, charged all-or-none.
    /// After the policy (a denied model never charges a bucket), before the first USD
    /// charge. Fail-CLOSED.
    Limits = 7,
    /// GWY-43: the credential.s own monthly USD ceiling. THIS is the first
    /// charge (BILL-01 deleted the trace-count quota that used to hold this
    /// position).
    KeyBudget = 8,
    /// GWY-43: the workspace.s monthly USD ceiling.
    WorkspaceBudget = 9,
    /// `OG-22`: the policy budgets (workspace / project / key / end user; hard or soft;
    /// calendar or rolling). A hard budget with UNKNOWN spend refuses. Fail-CLOSED.
    Budgets = 10,
    /// The predictive layer. OBSERVE-first: a would-be block is recorded and the
    /// request proceeds unless `TRACELANE_PREDICTIVE_ENFORCE=1`.
    Predictive = 11,
    /// The tamper-evident ledger row. Fail-CLOSED; last, so an `Err` from this
    /// pipeline always means "no row landed".
    Audit = 12,
}

/// Every step, in order. `run` marks each one as it enters it, and
/// [`Progress::enter`] refuses a step that is not strictly later than the last.
pub(crate) const ORDER: [Step; 13] = [
    Step::Auth,
    Step::Scope,
    Step::Parse,
    Step::Entitlements,
    Step::Controls,
    Step::RateLimit,
    Step::Policy,
    Step::Limits,
    Step::KeyBudget,
    Step::WorkspaceBudget,
    Step::Budgets,
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
        (Step::Parse as u8) < (Step::Policy as u8)
            && (Step::Policy as u8) < (Step::KeyBudget as u8),
        "OG-20: the policy reads the PARSED request and refuses before the first charge"
    );
    assert!(
        (Step::KeyBudget as u8) < (Step::Audit as u8),
        "the charge must precede the ledger row, so a refused request is never ledgered"
    );
    assert!(
        (Step::Auth as u8) < (Step::Scope as u8) && (Step::Scope as u8) < (Step::Parse as u8),
        "auth, then scope, then parse — a refused credential must cost one comparison"
    );
    assert!(
        (Step::Entitlements as u8) < (Step::Controls as u8)
            && (Step::Controls as u8) < (Step::RateLimit as u8),
        "OG-25: a paused / blocked request is refused before it costs a bucket token"
    );
    assert!(
        (Step::Policy as u8) < (Step::Limits as u8)
            && (Step::Limits as u8) < (Step::KeyBudget as u8)
            && (Step::Budgets as u8) < (Step::Audit as u8),
        "OG-21 / OG-22: limits after the policy, budgets before the ledger row"
    );
    // ORDER is complete and strictly increasing — the list and the enum agree.
    assert!(
        ORDER.len() == 13,
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
    /// `OG-20`: what this route knows about the request, for a key policy. Called ONLY
    /// when the caller carries a policy, so a route may compute here (an estimate, a
    /// re-encoding) without costing anyone else anything.
    ///
    /// The DEFAULT knows nothing — every fact `Unknown` — so a policy rule on a route
    /// that never described itself REFUSES (`policy_unenforceable`). Fail-CLOSED by
    /// construction: a new dispatch route cannot silently ignore a key's policy.
    fn policy_request(&self) -> PolicyRequest {
        PolicyRequest {
            subjects: vec![Subject::unknown()],
            body_bytes: Fact::Unknown,
        }
    }
}

use tracelane_shared::key_policy::{Fact, PolicyRequest, Subject};

/// `OG-20`: the estimated input tokens of a chat-shaped request — the R1 estimator
/// (`guardrail::context::estimate_input_tokens`, ~4 bytes per token), so the policy and
/// the R1 rail agree on what "input tokens" means.
pub(crate) fn chat_input_estimate(req: &tracelane_shared::ChatRequest) -> u64 {
    u64::from(crate::guardrail::context::estimate_input_tokens(req))
}

/// `OG-20`: the caller's declared output cap on a chat-shaped request
/// (`max_completion_tokens` over `max_tokens`, as `OG-03` reads them).
pub(crate) fn chat_output_cap(req: &tracelane_shared::ChatRequest) -> Option<u64> {
    req.max_completion_tokens.or(req.max_tokens).map(u64::from)
}

/// `OG-20`: ~4 bytes per token over plain texts (embeddings input, media prompts) — the
/// same ratio as the R1 estimator.
pub(crate) fn text_input_estimate<'a>(texts: impl IntoIterator<Item = &'a str>) -> u64 {
    texts.into_iter().map(|t| t.len() as u64).sum::<u64>() / 4
}

/// `OG-20`: one generating call on a chat-shaped request.
pub(crate) fn chat_subject(
    req: &tracelane_shared::ChatRequest,
    workspace_alias: bool,
    provider: Option<&str>,
) -> Subject {
    Subject {
        line: None,
        model: Fact::Known(req.model.clone()),
        workspace_alias,
        provider: provider.map(str::to_owned),
        input_tokens: Fact::Known(chat_input_estimate(req)),
        output_cap: Fact::Known(chat_output_cap(req)),
    }
}

/// `OG-51`: what a route does with the response cache. A REQUIRED associated const of
/// [`Route`], so a new route that does not say does not compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheScope {
    /// The route reads from and stores into the response cache (chat, non-streaming).
    Serves,
    /// The route cannot cache, and answers `x-tracelane-cache: use` / `ttl=N` itself, right
    /// after admission, in its own wire's error shape (`CacheControl::resolve` with
    /// `supported = false`): messages, responses, embeddings.
    Refuses,
    /// The route cannot cache; `use` / `ttl=N` is refused by admission, in
    /// [`run`] (`403 cache_control_not_entitled`, else `409 cache_control_unsupported_route`).
    /// `bypass` is an accepted no-op, and no header at all changes nothing.
    Unsupported,
}

/// `OG-51`: the refusal admission owes a `use` / `ttl=N` request on a route that cannot
/// cache. `None` = nothing to refuse (no header, `bypass`, a malformed value — which no
/// non-chat route has ever read — or the route handles it itself).
pub(crate) fn cache_header_refusal(
    scope: CacheScope,
    headers: &HeaderMap,
    entitlements: Option<&ResolvedEntitlements>,
) -> Option<ControlDenial> {
    if scope != CacheScope::Unsupported {
        return None;
    }
    let control = crate::semantic_cache::CacheControl::parse(headers).ok()?;
    if !matches!(
        control,
        crate::semantic_cache::CacheControl::Use | crate::semantic_cache::CacheControl::Ttl(_)
    ) {
        return None;
    }
    let (status, code, message) = if entitlements
        .is_some_and(|e| e.f_cache_control && e.cache_ttl_hours > 0)
    {
        (
            409,
            "cache_control_unsupported_route",
            "this route does not use the response cache; `x-tracelane-cache: use` and `ttl=` are \
             for /v1/chat/completions (non-streaming)",
        )
    } else {
        (
            403,
            "cache_control_not_entitled",
            "response-cache control is not part of this workspace's plan",
        )
    };
    Some(ControlDenial {
        status,
        code,
        message: message.to_owned(),
        detail: Vec::new(),
        retry_after_secs: None,
    })
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
    /// `OG-51`: what this route does with the response cache. Required — see [`CacheScope`].
    const CACHE: CacheScope;
    /// The scope the key must carry (A13). `chat` for every generating route;
    /// `OG-08`'s passthrough names `passthrough`, which a legacy `NULL`-scope key
    /// does NOT hold (`KeyScope::allows`). A route that needs a different scope
    /// says so here — the cascade never compares slugs itself.
    const SCOPE: crate::auth::scope::Scope = crate::auth::scope::Scope::Chat;
    /// Whether the body is something the predictive layer can read. `false` for an
    /// OPAQUE body (`OG-08` passthrough: no request guardrails, said in the API docs)
    /// — the `Predictive` step is still entered, in order, and simply observes nothing.
    const INSPECTS_BODY: bool = true;
    /// `OG-11`: what this route may do with the workspace routing document — virtual
    /// models (which providers), key pools, fallthrough. REQUIRED, with no default, so a
    /// new dispatch route does not build until it declares one (`OG-11` §2, the wire
    /// table).
    const ROUTING: crate::routing::RoutingScope;

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

    /// `OG-11`: called once inside `Step::Entitlements`, after the routing plan is made
    /// (`plan` is `None` when routing does not apply). A route whose PARSE had to defer
    /// a refusal until the workspace's virtual models were known (a name its own
    /// provider map does not route — messages, responses, gemini) completes or refuses
    /// here; a native relay rewrites its body to the first candidate. Still before the
    /// first charge and the ledger row. The default changes nothing (chat and embeddings
    /// select their target in the handler).
    ///
    /// # Errors
    /// Fail-CLOSED: the refusal the parse deferred.
    fn apply_route(
        _parsed: &mut Self::Parsed,
        _plan: Option<&mut crate::routing::RoutePlan>,
    ) -> Result<(), Malformed> {
        Ok(())
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

    /// `H2` (security review 2026-10-02): can the gateway price what this request will
    /// spend? Consulted ONLY for a caller with a key or workspace budget; an unbudgeted
    /// caller is never refused for this (its cost stays `None`, never 0). The default
    /// prices the request's model (alias-resolved) against the token price tables — the
    /// shape of every generating route. A route that bills in other units, or cannot be
    /// priced at all, overrides it.
    fn pricing(parsed: &Self::Parsed) -> Pricing {
        token_pricing(parsed.model())
    }

    /// Re-review H-3 (2026-10-02): the pricing check as admission runs it, with the
    /// caller's resolved entitlements in hand. The default is [`Route::pricing`]; a route
    /// whose model is rewritten AFTER admission by a WORKSPACE alias (chat, embeddings)
    /// overrides this to price the alias TARGET — pricing the name the caller sent let an
    /// alias onto an unpriced model escape the budget, and refused an ordinary alias
    /// (`fast`) that points at a priced model.
    fn pricing_for(parsed: &Self::Parsed, entitlements: Option<&ResolvedEntitlements>) -> Pricing {
        let _ = entitlements;
        Self::pricing(parsed)
    }
}

/// Re-review H-3: [`token_pricing`] on the model that will actually be dispatched — the
/// WORKSPACE alias target when one applies (the `tracelane.yaml` alias is resolved inside
/// `token_pricing`).
pub(crate) fn token_pricing_after_workspace_alias(
    model: &str,
    entitlements: Option<&ResolvedEntitlements>,
) -> Pricing {
    let target = entitlements
        .and_then(|e| crate::db::model_aliases::resolve(&e.model_aliases, model))
        .unwrap_or(model);
    token_pricing(target)
}

/// `H2`: what the gateway knows, BEFORE dispatch, about the cost of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pricing {
    /// A price exists for what will be spent.
    Priced,
    /// The request spends no provider money (a file upload).
    NotSpending,
    /// The gateway cannot price it: refused 402 for a budgeted caller.
    Unpriced { code: &'static str, message: String },
}

/// The 402 code for an unpriceable request under a budget.
pub(crate) const UNPRICED_UNDER_BUDGET: &str = "unpriced_under_budget";

/// `H2`: the standard refusal wording for a model the gateway cannot price.
pub(crate) fn unpriced(model: &str, why: &str) -> Pricing {
    let model: String = model.chars().take(128).collect();
    Pricing::Unpriced {
        code: UNPRICED_UNDER_BUDGET,
        message: format!(
            "`{model}` cannot be priced by this gateway ({why}), and this key or workspace has \
             a budget: spend the gateway cannot price would never count against it. Use a \
             priced model, or remove the budget."
        ),
    }
}

/// `H2`: the token-price check of [`Route::pricing`]'s default — the model a `tracelane.yaml`
/// alias names upstream, against the verified cards and the generated catalog prices.
pub(crate) fn token_pricing(model: &str) -> Pricing {
    token_pricing_with_alias(model, crate::server::config::alias(model))
}

fn token_pricing_with_alias(
    model: &str,
    alias: Option<&crate::server::config::ModelAlias>,
) -> Pricing {
    let zero = tracelane_shared::Usage {
        input_tokens: 0,
        output_tokens: 0,
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    };
    if crate::pricing::cost_usd_for_routed_model(model, alias, &zero).is_some() {
        Pricing::Priced
    } else {
        unpriced(model, "no token price for it in the price table")
    }
}

/// `H2`: does this caller carry a budget the gateway enforces — the key's own, or the
/// workspace's? No entitlement cache (no control plane) ⇒ no workspace budget
/// (`.claude/rules/tenancy.md`: there is no ceiling to protect, so nothing to refuse for).
pub(crate) fn caller_is_budgeted(
    claims: &Claims,
    entitlements: Option<&ResolvedEntitlements>,
) -> bool {
    (claims.api_key_id().is_some() && claims.budget_usd_monthly.is_some())
        || entitlements.is_some_and(|e| e.workspace_budget_micro_usd > 0)
        || has_hard_policy_budget(claims, entitlements)
}

/// `OG-22`: does any policy layer (workspace, project, key) carry a HARD budget? Such a
/// caller may only spend what the gateway can price (the H2 rule), or unpriced spend
/// would run past it unseen. A soft budget refuses nothing, so it does not count here.
pub(crate) fn has_hard_policy_budget(
    claims: &Claims,
    entitlements: Option<&ResolvedEntitlements>,
) -> bool {
    let hard = |p: &tracelane_shared::key_policy::KeyPolicy| {
        p.budget.as_ref().is_some_and(crate::budgets::is_hard)
            || p.end_user_budget
                .as_ref()
                .is_some_and(crate::budgets::is_hard)
    };
    entitlements
        .and_then(|e| e.controls.policy())
        .is_some_and(hard)
        || claims
            .governance
            .as_deref()
            .is_some_and(|g| g.policies().any(|(_, p)| hard(p)))
}

/// `H3` (security review 2026-10-02): proof that the entitlement resolve and the
/// per-minute rate limit ALREADY ran for this request, BEFORE its body was read. Only
/// [`pre_body_gate`] constructs one; [`admit_authenticated`] takes it and then does not
/// charge the bucket a second time.
#[derive(Debug)]
pub(crate) struct PreBodyGate {
    /// Final re-review `M-4`: the caller's plan tier, resolved once here (one warm cache read;
    /// no control plane ⇒ `Free`, `.claude/rules/tenancy.md`) for the body budget's share.
    plan: crate::clickhouse_query::PlanTier,
}

impl PreBodyGate {
    /// The caller's plan tier — fail-closed to `Free` with no control plane.
    pub(crate) fn plan(&self) -> crate::clickhouse_query::PlanTier {
        self.plan
    }
}

/// `H3`: entitlements + rate limit for a route whose body runs to hundreds of megabytes,
/// run right after authentication and BEFORE a byte of the body is read — a throttled
/// caller must not be able to make the gateway buffer one. The SAME bucket and the same
/// RPM resolution [`run`] uses (no control plane ⇒ the conservative no-control-plane
/// RPM, never unlimited).
///
/// # Errors
/// `Refusal::InsufficientScope` / `Refusal::RateLimited`. Fail-CLOSED.
pub(crate) async fn pre_body_gate<R: Route>(
    state: &AppState,
    claims: &Claims,
) -> Result<PreBodyGate, Refusal> {
    if !claims.allows_scope(R::SCOPE) {
        return Err(Refusal::InsufficientScope);
    }
    // OG-25: a paused workspace never makes the gateway buffer a large body (one warm
    // cache read; no control plane ⇒ nothing can be paused).
    if let Some(cache) = state.entitlements.as_ref()
        && let Err(crate::controls::ControlRefusal::Paused { since }) =
            crate::controls::check_paused(
                &cache.resolved(*claims.tenant_id.as_uuid()).await.controls,
            )
    {
        return Err(Refusal::Control(paused_denial(since)));
    }
    charge_rate_limit(state, claims)
        .await
        .map_err(|retry_after_secs| Refusal::RateLimited { retry_after_secs })?;
    // LAST review Low 2: an UNKNOWN plan key is Free here (fail-CLOSED, tenancy.md), not the
    // cap layer's Builder default — the tier decides who may hold more of the shared buffer.
    let plan = match state.entitlements.as_ref() {
        None => crate::clickhouse_query::PlanTier::Free,
        Some(cache) => crate::clickhouse_query::PlanTier::from_known_plan_key(
            &cache
                .resolved(*claims.tenant_id.as_uuid())
                .await
                .plan_lookup_key,
        )
        .unwrap_or(crate::clickhouse_query::PlanTier::Free),
    };
    Ok(PreBodyGate { plan })
}

/// One charge of the tenant's per-minute bucket (and the key's own override), outside the
/// dispatch pipeline: the entitlement-resolved RPM — one warm cache read — or, with no
/// control plane, the operator's declared cap / the conservative default (never unlimited).
/// Used by [`pre_body_gate`] and by companion reads (`GET /v1/models`, M3).
///
/// # Errors
/// `Err(retry_after_secs)` when the bucket is empty. Fail-CLOSED.
pub(crate) async fn charge_rate_limit(state: &AppState, claims: &Claims) -> Result<(), u32> {
    let tenant_id = &claims.tenant_id;
    let rpm = match &state.entitlements {
        Some(cache) => cache.resolved(*tenant_id.as_uuid()).await.rate_limit_rpm,
        // No control plane: the operator's declared cap, else the conservative default.
        None => state.no_control_plane_rate_limit_rpm,
    };
    if let RateLimitDecision::Throttle { retry_after_secs } =
        state
            .rate_limiter
            .check_scoped(tenant_id, rpm, claims.api_key_id(), claims.rate_limit_rpm)
    {
        state.rejection_metrics.record_admission_refusal(
            tenant_id,
            claims.api_key_id(),
            crate::rejection_metrics::RejectionReason::RateLimited,
            chrono::Utc::now(),
        );
        return Err(retry_after_secs);
    }
    Ok(())
}

// ── Refusals ─────────────────────────────────────────────────────────────────

/// A body the route could not serve: the wire's error `code` and the message.
/// The OpenAI chat wire renders only the message; the embeddings and Anthropic
/// wires render both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Malformed {
    pub code: &'static str,
    pub message: String,
    /// `OG-03`: a ready-made error body (`{"error":{"code","param",…}}`) for refusals that
    /// name a field or part. `None` keeps each wire's historical shape.
    pub detail: Option<serde_json::Value>,
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
    /// 402 — `H2` (security review 2026-10-02): the caller has a key or workspace budget
    /// and the gateway cannot price what this request would spend, so the budget could
    /// never see it. `code` is `unpriced_under_budget` (or `batch_unbudgetable`); the
    /// message names the model and says why.
    Unpriced { code: &'static str, message: String },
    /// 403 (413 for the body cap) — `OG-20`: the key's or its project's policy refuses
    /// this request (`policy_model_denied`, `policy_ip_denied`, …). The denial carries
    /// its code, the rule, the layer and — for a batch file — the line.
    Policy(tracelane_shared::key_policy::Denial),
    /// `OG-21` / `OG-22` / `OG-25`: a workspace control refused — `423 workspace_paused`,
    /// `429 rpm_limit_*` / `tpm_limit_*`, `402 budget_exceeded_*`, `503
    /// budget_spend_unknown` / `budget_capacity`. Each wire renders the code, the message
    /// and the detail pairs in its own shape, plus `Retry-After` when set.
    Control(ControlDenial),
}

/// A workspace-control refusal, wire-neutral.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ControlDenial {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub detail: Vec<(&'static str, serde_json::Value)>,
    pub retry_after_secs: Option<u32>,
}

impl ControlDenial {
    /// `{"error": code, "message", …detail}` — the OpenAI-shaped body.
    pub(crate) fn body(&self) -> serde_json::Value {
        let mut v = serde_json::json!({ "error": self.code, "message": self.message });
        for (k, val) in &self.detail {
            v[*k] = val.clone();
        }
        v
    }

    /// Add `Retry-After` when this refusal carries one.
    pub(crate) fn finish(&self, mut resp: Response) -> Response {
        if let Some(s) = self.retry_after_secs {
            insert_retry_after(&mut resp, s);
        }
        resp
    }
}

/// `OG-25`: `423 workspace_paused`.
pub(crate) fn paused_denial(since: chrono::DateTime<chrono::Utc>) -> ControlDenial {
    ControlDenial {
        status: 423,
        code: "workspace_paused",
        message: crate::controls::paused_message(since),
        detail: vec![("paused_at", serde_json::json!(since.to_rfc3339()))],
        retry_after_secs: None,
    }
}

/// `OG-21`: a limit refusal, `429` + `Retry-After`.
pub(crate) fn limit_denial(d: &crate::limits::LimitDenial) -> ControlDenial {
    let detail = d
        .detail()
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| {
                    let k: &'static str = match k.as_str() {
                        "limit" => "limit",
                        "requested" => "requested",
                        "scope" => "scope",
                        "retry_after_secs" => "retry_after_secs",
                        "model_pattern" => "model_pattern",
                        _ => return None,
                    };
                    Some((k, v.clone()))
                })
                .collect()
        })
        .unwrap_or_default();
    ControlDenial {
        status: 429,
        code: d.code,
        message: d.message(),
        detail,
        retry_after_secs: Some(d.retry_after_secs),
    }
}

/// `OG-22`: `503 budget_spend_unknown` — a hard budget whose spend cannot be read.
pub(crate) fn spend_unknown_denial(scope: &str) -> ControlDenial {
    let backoff_ms = crate::controls::config().budget_seed_retry_backoff_ms;
    ControlDenial {
        status: 503,
        code: "budget_spend_unknown",
        message: format!(
            "this {scope}'s spend could not be read, and it has a HARD budget — the gateway \
             refuses rather than let spend it cannot count past the ceiling; retry shortly"
        ),
        detail: vec![("scope", serde_json::json!(scope))],
        retry_after_secs: Some(u32::try_from(backoff_ms.div_ceil(1000)).unwrap_or(5).max(1)),
    }
}

/// `OG-20`: a failed credential validation as a [`Refusal`] — a policy refusal raised at
/// authentication (`source_ips`, an unparseable stored policy) keeps its code; anything
/// else is the `auth::failure` 401 / 429 / 503.
pub(crate) fn auth_refusal(err: &anyhow::Error) -> Refusal {
    if let Some(d) = crate::auth::policy_refusal(err) {
        return Refusal::Policy(d.clone());
    }
    let (status, message) = crate::auth::failure(err);
    Refusal::AuthFailed { status, message }
}

/// `OG-20`: the response body every OpenAI-shaped wire renders for a policy refusal:
/// `{"error": code, "message", "rule", "policy", "line"?, "limit"?, …}`.
pub(crate) fn policy_body(d: &tracelane_shared::key_policy::Denial) -> serde_json::Value {
    let mut body = d.extra();
    body["error"] = serde_json::Value::String(d.code.to_owned());
    body["message"] = serde_json::Value::String(d.message.clone());
    body
}

/// `OG-20`: the denial's structured fields for the wires that take `(name, value)`
/// pairs beside their own code and message (Responses, Gemini, Anthropic, media).
pub(crate) fn policy_pairs(
    d: &tracelane_shared::key_policy::Denial,
) -> Vec<(&'static str, serde_json::Value)> {
    let mut v = vec![
        ("rule", serde_json::json!(d.rule)),
        ("policy", serde_json::json!(d.origin.as_str())),
    ];
    if let Some(line) = d.line {
        v.push(("line", serde_json::json!(line)));
    }
    for (k, val) in &d.detail {
        v.push((k, val.clone()));
    }
    v
}

/// The HTTP status of a policy denial (403, or 413 for the body cap).
pub(crate) fn policy_status(d: &tracelane_shared::key_policy::Denial) -> StatusCode {
    StatusCode::from_u16(d.status).unwrap_or(StatusCode::FORBIDDEN)
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
            Self::KeyBudgetExceeded { .. }
            | Self::WorkspaceBudgetExceeded { .. }
            | Self::Unpriced { .. } => StatusCode::PAYMENT_REQUIRED,
            Self::AuditUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Policy(d) => policy_status(d),
            Self::Control(c) => {
                StatusCode::from_u16(c.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
            }
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
        Refusal::Unpriced { code, message } => {
            (status, Json(json!({ "error": code, "message": message }))).into_response()
        }
        Refusal::Policy(d) => (status, Json(policy_body(&d))).into_response(),
        Refusal::Control(c) => c.finish((status, Json(c.body())).into_response()),
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
    pub attempt_security: Arc<crate::routing::attempt::Context>,
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
    /// `OG-11`: how this request is dispatched — `None` when routing does not apply
    /// (no document, or the model is not one of its virtual models).
    pub route_plan: Option<Arc<crate::routing::RoutePlan>>,
    /// The ONE bench gate's verdict. `false` on every route but chat.
    pub bench_mock: bool,
    pub warn_aft_id: Option<&'static str>,
    /// Shared by the request-side guardrail verdict and the response-side seam.
    pub correlation_id: ulid::Ulid,
    pub dispatch_guard: DispatchGuard,
    /// B-256 per-stage timing. Opened BEFORE credential validation (B-568 I1), so
    /// its first stage is `authenticate`; the pipeline marks its stages; each of
    /// the three handlers keeps marking and emits at its dispatch boundary. It also
    /// carries the cold-start fact the handlers add their BYOK miss to (I5).
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
    admit_via::<R, _, _>(
        state,
        headers,
        body,
        |credential| async move { crate::auth::validate_authorization_traced(&credential).await },
        None,
    )
    .await
}

/// `OG-06`: [`admit`] for a route that must AUTHENTICATE BEFORE it reads its body — the
/// media / files routes carry bodies up to hundreds of megabytes, and buffering those for
/// an unauthenticated caller is a memory-exhaustion lever the JSON routes (a 2 MB default
/// extractor limit) never had. The handler validates the credential FIRST (one call to
/// [`crate::auth::validate_authorization_traced`], the same validator [`admit`] uses),
/// reads the bounded body, then hands the already-validated claims here; every later
/// step — scope, parse, entitlements, rate limit, budgets, predictive, the fail-CLOSED
/// audit publish — is [`run`], unchanged, so the order is still the one `Step` type.
///
/// The credential must have been validated by the caller; there is no other entry that
/// takes claims in a non-test build, and the only caller is `crate::media_common`.
///
/// # Errors
/// As [`admit`].
pub(crate) async fn admit_authenticated<R: Route>(
    state: &AppState,
    headers: &HeaderMap,
    body: R::Body,
    claims: Claims,
    auth_path: crate::auth::AuthPath,
    gate: PreBodyGate,
) -> Result<Admitted<R>, Refusal> {
    admit_via::<R, _, _>(
        state,
        headers,
        body,
        |_credential| async move { Ok((claims, auth_path)) },
        Some(gate),
    )
    .await
}

/// [`admit`] with the credential validator as a parameter. Production passes
/// `validate_authorization_traced` and nothing else; a test passes a validator
/// that takes a known time, so the claim "the timer covers authentication"
/// (B-568 I1) is asserted by a run rather than by reading the code.
async fn admit_via<R, F, Fut>(
    state: &AppState,
    headers: &HeaderMap,
    body: R::Body,
    validate: F,
    gate: Option<PreBodyGate>,
) -> Result<Admitted<R>, Refusal>
where
    R: Route,
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<(Claims, crate::auth::AuthPath)>>,
{
    // Captured BEFORE auth so the span's overhead number opens at the moment the
    // request arrived, not after the credential check.
    let request_start = chrono::Utc::now();
    // B-568 I1: the stage timer opens on the NEXT line, so its stages cover the
    // same interval the span's overhead number does — authentication included.
    // Until 2026-09-27 it was created inside `run`, after this await, and a cold
    // key lookup (pool checkout + SELECT + Argon2id) showed up only as
    // `unaccounted_us`. Costs nothing new: the `Instant::now()` moved, it was not
    // added.
    let mut timer = crate::hotpath::StageTimer::new();
    timer.set_route(R::NAME);
    let mut progress = Progress::new();
    progress.enter(Step::Auth);
    let Some(authorization) = R::credential(headers) else {
        return Err(Refusal::MissingCredentials);
    };
    let (claims, auth_path) = match validate(authorization).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "authentication failed");
            // B-391 (c): 503 when the auth store is down, 401 when the
            // credential is wrong (`crate::auth::failure`).
            return Err(auth_refusal(&err));
        }
    };
    timer.set_auth(auth_path.label(), auth_path.is_cold());
    timer.mark("authenticate");
    run::<R>(
        state,
        headers,
        body,
        claims,
        request_start,
        progress,
        timer,
        gate,
    )
    .await
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
    let mut timer = crate::hotpath::StageTimer::new();
    timer.set_route(R::NAME);
    timer.set_auth(crate::auth::AuthPath::Static.label(), false);
    timer.mark("authenticate");
    let mut progress = Progress::new();
    // The caller authenticated; the step is accounted for so the order check
    // and the step log both read the same sequence as `admit`.
    progress.enter(Step::Auth);
    run::<R>(
        state,
        headers,
        body,
        claims,
        request_start,
        progress,
        timer,
        None,
    )
    .await
}

/// `OG-20`: evaluate `gov` against what the route parsed. The model resolution is the
/// one dispatch will use: a WORKSPACE alias (chat, embeddings — the routes that rewrite
/// one) to its target, then the operator `tracelane.yaml` alias, then the provider that
/// name routes to (`ProviderRegistry::provider_id_for_model`, fail-closed `None`). The
/// body size is the request's `Content-Length` when it sent one, else the route's own
/// measure. Labels are read (bounded, as the span will record them) only when a layer
/// requires one.
///
/// # Errors
/// The first rule that fails — fail-CLOSED.
pub(crate) fn enforce_policy<P: Parsed>(
    state: &AppState,
    headers: &HeaderMap,
    gov: &tracelane_shared::key_policy::Governance,
    parsed: &P,
    entitlements: Option<&ResolvedEntitlements>,
    plan: Option<&crate::routing::RoutePlan>,
) -> Result<(), tracelane_shared::key_policy::Denial> {
    // OG-11: every target of a virtual model is judged — any denied target refuses.
    let mut request = crate::routing::expand(parsed.policy_request(), plan);
    if let Some(len) = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        request.body_bytes = Fact::Known(len);
    }
    let resolve = |model: &str, workspace_alias: bool| {
        routed_policy_resolve(model, workspace_alias, entitlements, plan)
    };
    let labels = || {
        crate::server::request_labels::read(headers, &state.rate_card.load().policy.request_labels)
            .0
    };
    gov.evaluate(&request, &resolve, &labels)
}

/// `OG-20`: every name `model` is known by on its way to the wire, and its provider.
pub(crate) fn policy_resolve(
    model: &str,
    workspace_alias: bool,
    entitlements: Option<&ResolvedEntitlements>,
) -> tracelane_shared::key_policy::Resolved {
    let mut names = vec![model.to_owned()];
    let mut target = model.to_owned();
    let mut allow_names = Vec::new();
    if workspace_alias
        && let Some(t) =
            entitlements.and_then(|e| crate::db::model_aliases::resolve(&e.model_aliases, model))
    {
        target = t.to_owned();
        names.push(target.clone());
    }
    allow_names.push(target.clone());
    if let Some(a) = crate::server::config::alias(&target)
        && a.upstream_model != target
    {
        names.push(a.upstream_model.clone());
        allow_names.push(a.upstream_model.clone());
    }
    tracelane_shared::key_policy::Resolved {
        names,
        allow_names,
        provider: crate::providers::ProviderRegistry::provider_id_for_model(&target)
            .map(str::to_owned),
    }
}

/// Preserve the requested routing name for denies and per-model limits. An allow-list
/// still judges each concrete target independently; a virtual name cannot grant it.
pub(crate) fn routed_policy_resolve(
    model: &str,
    workspace_alias: bool,
    entitlements: Option<&ResolvedEntitlements>,
    plan: Option<&crate::routing::RoutePlan>,
) -> tracelane_shared::key_policy::Resolved {
    let mut resolved = policy_resolve(model, workspace_alias, entitlements);
    if let Some(plan) = plan
        && plan.policy_targets.iter().any(|target| target == model)
    {
        for name in std::iter::once(&plan.requested).chain(&plan.policy_aliases) {
            if !resolved.names.contains(name) {
                resolved.names.push(name.clone());
            }
        }
    }
    resolved
}

/// The steps after `Auth`, in [`ORDER`]. One function, three callers.
///
/// `timer` arrives already carrying the `authenticate` stage (B-568 I1). B-256:
/// each further stage costs one `Instant::now()`, and the timer emits NOTHING
/// unless the pre-dispatch segment is over threshold.
#[tracing::instrument(skip_all, fields(route = R::NAME, tenant_id = tracing::field::Empty))]
// The pre-body gate is one more input to the same one pipeline; splitting `run` to stay
// under the lint would split the order the `Step` type proves.
#[allow(clippy::too_many_arguments)]
async fn run<R: Route>(
    state: &AppState,
    headers: &HeaderMap,
    body: R::Body,
    claims: Claims,
    request_start: chrono::DateTime<chrono::Utc>,
    mut progress: Progress,
    mut timer: crate::hotpath::StageTimer,
    gate: Option<PreBodyGate>,
) -> Result<Admitted<R>, Refusal> {
    // Trace identity — W3C `traceparent` first (joins the caller's own trace and
    // parents our span under theirs, ADR-075 / B-311), then the legacy
    // `x-trace-id`, then a fresh UUID.
    let (trace_id, inbound_parent) = crate::trace_context::resolve_trace_identity(headers);

    // ── Scope (A13). Immediately after auth and BEFORE anything expensive. ──
    // A key scoped `read` (the shape you hand an external auditor) must not be
    // able to spend the tenant's provider budget. Here rather than at dispatch
    // so a refused request costs one comparison, not an entitlement resolve and
    // a detection pass. Legacy keys (`scope IS NULL`) allow everything, so this
    // is a no-op for every key minted before A13.
    progress.enter(Step::Scope);
    if !claims.allows_scope(R::SCOPE) {
        tracing::warn!(
            sub = %claims.sub,
            route = R::NAME,
            scope = R::SCOPE.as_slug(),
            "api key lacks the required scope — refusing"
        );
        return Err(Refusal::InsufficientScope);
    }
    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());
    // Renamed from `auth` (B-568 I1): this stage is the scope comparison and
    // nothing else; credential validation is the `authenticate` stage before it.
    timer.mark("scope");

    // ── PARSE. Before the first charge, by construction: `Step::KeyBudget`
    // below reads `claims.api_key_id()`/`claims.budget_usd_monthly`, but the
    // MODEL used by the predictive layer and the ledger payload does not exist
    // until here. ──
    progress.enter(Step::Parse);
    let mut parsed = R::parse(body).map_err(Refusal::Malformed)?;
    // All five caller-supplied identity values, read ONCE and bounded ONCE
    // (`CallerIdentity::from_headers`). Three of them used to be read raw while
    // `x-business-reference` was bounded — B-368 — and the block was duplicated
    // across the three handlers, which is what let the two rules diverge.
    // `or_body_end_user` runs on the RAW body, before any redaction and before
    // the GWY-39 alias rewrite, so the span records what the CALLER sent.
    let mut identity = CallerIdentity::from_headers(headers)
        .or_body_end_user(parsed.request_json())
        // RI-05 / B-444: the caller's model string, BEFORE the alias rewrite in
        // chat.rs and untouched by failover — `gen_ai_request_model`'s source.
        .with_requested_model(parsed.request_json());
    // OG-23: the key's project and environment, from the CLAIMS (the auth SELECT) —
    // never a header — so the span attributes the request (and its spend) to them.
    if let Some(g) = claims.governance.as_deref() {
        identity.project_id = g.project_id.map(|p| p.to_string());
        identity.key_environment.clone_from(&g.environment);
    }
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
            Some(cache) => {
                // B-568 I5: a blocking resolve (a tenant never resolved in this
                // process, or a forced re-resolve) is a control-plane round trip.
                let (resolved, blocked) = cache.resolved_traced(*tenant_id.as_uuid()).await;
                if blocked {
                    timer.note_cold();
                }
                Some(resolved)
            }
            None => None,
        }
    };
    // OG-51: `x-tracelane-cache: use` / `ttl=N` on a route that cannot cache is a refusal, not a
    // silent no-op. Inside the Entitlements step (the plan is read here) and before any charge,
    // so `Step`'s order is untouched.
    if let Some(d) = cache_header_refusal(R::CACHE, headers, entitlements.as_deref()) {
        return Err(Refusal::Control(d));
    }
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
    // OG-11: the routing plan, off the same warm entitlement read — still inside the
    // Entitlements step, so a refusal here (an unparseable document, a virtual model the
    // wire cannot serve, a name the route's parse deferred) costs no bucket token, no
    // charge and no ledger row. No document (or no control plane) → `None` and nothing
    // else changes.
    let mut route_plan: Option<Arc<crate::routing::RoutePlan>> = match entitlements.as_deref() {
        Some(e) if !matches!(*e.routing, crate::routing::RoutingState::None) => {
            let mut est = if crate::routing::needs_estimate(&e.routing, parsed.model()) {
                estimate(&parsed.policy_request())
            } else {
                crate::routing::Estimate::default()
            };
            // M1: the latency strategy orders by THIS tenant's own observations.
            est.owner = Some(*claims.tenant_id.as_uuid());
            let mut rng = crate::routing::thread_rng;
            let labels = crate::server::request_labels::read(
                headers,
                &state.rate_card.load().policy.request_labels,
            );
            let facts = crate::routing::conditions::Facts::request(
                headers,
                &labels,
                &identity,
                &claims,
                parsed.request_json(),
                trace_id,
            );
            crate::routing::conditions::plan(
                &R::ROUTING,
                parsed.model(),
                &e.routing,
                est,
                &mut rng,
                &facts,
            )
            .map_err(crate::routing::PlanError::into_refusal)?
            .map(Arc::new)
        }
        _ => None,
    };
    R::apply_route(
        &mut parsed,
        route_plan
            .as_mut()
            .filter(|p| p.dispatches())
            .map(Arc::make_mut),
    )
    .map_err(Refusal::Malformed)?;

    // ── Controls (OG-25). The workspace's own pause and block lists, off the warm
    // entitlement read; nothing to do (one `bool`) for a workspace that set none. No
    // control plane ⇒ no controls (nothing can have been configured). Before the rate
    // limit, so a paused or blocked request costs no bucket token. Fail-CLOSED. ──
    progress.enter(Step::Controls);
    let controls = entitlements.as_ref().map(|e| Arc::clone(&e.controls));
    let mut policy_request: Option<PolicyRequest> = None;
    if let Some(c) = controls.as_deref().filter(|c| c.restricts()) {
        let request = policy_request.get_or_insert_with(|| {
            crate::routing::expand(parsed.policy_request(), route_plan.as_deref())
        });
        let resolve = |m: &str, ws: bool| {
            routed_policy_resolve(m, ws, entitlements.as_deref(), route_plan.as_deref())
        };
        if let Err(r) =
            crate::controls::check_request(c, request, identity.end_user_id.as_deref(), &resolve)
        {
            state.rejection_metrics.record_admission_refusal(
                tenant_id,
                claims.api_key_id(),
                crate::rejection_metrics::RejectionReason::PolicyDenied,
                chrono::Utc::now(),
            );
            return Err(match r {
                crate::controls::ControlRefusal::Paused { since } => {
                    Refusal::Control(paused_denial(since))
                }
                crate::controls::ControlRefusal::Blocked(d) => Refusal::Policy(d),
            });
        }
    }
    // rev5 M6: the WORKSPACE policy's model / provider rules bind every request (every
    // key, minted before or after the policy, and every session); its `source_ips` bind
    // every API key (authentication already refused one outside them on every route —
    // this is the same check, on the address admission sees). Same codes as a key policy,
    // `policy: "workspace"`.
    if let Some(ws) = controls
        .as_deref()
        .and_then(crate::controls::WorkspaceControls::policy)
        .filter(|p| p.models.is_some() || p.providers.is_some() || !p.source_ips.is_empty())
    {
        let origin = tracelane_shared::key_policy::Origin::Workspace;
        let checked = if claims.api_key_id().is_some() {
            ws.check_source(origin, crate::db::api_keys::current_client_ip())
        } else {
            Ok(())
        }
        .and_then(|()| {
            let request = policy_request.get_or_insert_with(|| {
                crate::routing::expand(parsed.policy_request(), route_plan.as_deref())
            });
            let resolve = |m: &str, w: bool| {
                routed_policy_resolve(m, w, entitlements.as_deref(), route_plan.as_deref())
            };
            ws.check_request(origin, request, &resolve)
        });
        if let Err(d) = checked {
            state.rejection_metrics.record_admission_refusal(
                tenant_id,
                claims.api_key_id(),
                crate::rejection_metrics::RejectionReason::PolicyDenied,
                chrono::Utc::now(),
            );
            return Err(Refusal::Policy(d));
        }
    }

    // ── Rate limit: the tenant bucket AND, when the key carries an override, its
    // own (GWY-43). A key with no override behaves exactly as before. ──
    progress.enter(Step::RateLimit);
    // H3: a route that read its body only after `pre_body_gate` already charged the
    // bucket for this request; charging it again would halve the caller's limit.
    if gate.is_none()
        && let RateLimitDecision::Throttle { retry_after_secs } = state.rate_limiter.check_scoped(
            tenant_id,
            rpm,
            claims.api_key_id(),
            claims.rate_limit_rpm,
        )
    {
        // Count the rejection for the Gateway-ops live counter, AND bucket it for
        // the RI-05 / M2 aggregate span (`tracelane.admission.rejected`, rolled up
        // per minute by `rejection_metrics::spawn`) — a 429 emits no per-request
        // span (no dispatch), so this is how the load the limiter is shedding
        // still leaves a record, without one span per rejected request.
        state.rejection_metrics.record_admission_refusal(
            tenant_id,
            claims.api_key_id(),
            crate::rejection_metrics::RejectionReason::RateLimited,
            chrono::Utc::now(),
        );
        return Err(Refusal::RateLimited { retry_after_secs });
    }
    timer.mark("entitlements");

    // ── Policy (OG-20). After the bucket, before the first charge and the ledger row.
    // A key with no policy pays one `Option` check; the route's facts are computed only
    // for a key that has one. Fail-CLOSED: a rule the route cannot evaluate refuses.
    progress.enter(Step::Policy);
    if let Some(gov) = claims.governance.as_deref().filter(|g| g.has_policy())
        && let Err(denial) = enforce_policy(
            state,
            headers,
            gov,
            &parsed,
            entitlements.as_deref(),
            route_plan.as_deref(),
        )
    {
        state.rejection_metrics.record_admission_refusal(
            tenant_id,
            claims.api_key_id(),
            crate::rejection_metrics::RejectionReason::PolicyDenied,
            chrono::Utc::now(),
        );
        return Err(Refusal::Policy(denial));
    }

    // ── Limits (OG-21). RPM / TPM buckets of every layer that sets `limits` — all must
    // have room, charged all-or-none in one critical section. A TPM reservation is
    // parked for its span, which reconciles it (`server::record_key_spend`). ──
    progress.enter(Step::Limits);
    let ws_policy = controls
        .as_deref()
        .and_then(crate::controls::WorkspaceControls::policy);
    // rev5 L6: where a per-end-user rule applies (a `limits.per_end_user` or an
    // `end_user_budget` on any layer), one key may introduce only so many DISTINCT
    // end-user ids per window — the id is caller-asserted (header over body `user`), and
    // rotating it would otherwise fill the workspace's end-user capacity for everyone.
    if let Some(u) = identity.end_user_id.as_deref() {
        let per_user = |p: &tracelane_shared::key_policy::KeyPolicy| {
            p.end_user_budget.is_some()
                || p.limits.as_ref().is_some_and(|l| l.per_end_user.is_some())
        };
        let applies = ws_policy.is_some_and(per_user)
            || claims
                .governance
                .as_deref()
                .is_some_and(|g| g.policies().any(|(_, p)| per_user(p)));
        if applies
            && let Err(retry) = crate::limits::end_user_cap().admit(
                *tenant_id.as_uuid(),
                claims.api_key_id(),
                crate::limits::end_user_hash(u),
                std::time::Instant::now(),
            )
        {
            state.rejection_metrics.record_admission_refusal(
                tenant_id,
                claims.api_key_id(),
                crate::rejection_metrics::RejectionReason::RateLimited,
                chrono::Utc::now(),
            );
            return Err(Refusal::Control(ControlDenial {
                status: 429,
                code: "end_user_id_cap",
                message: format!(
                    "this credential has introduced the most distinct end-user ids allowed in \
                     the current window ({}) — an id already seen keeps working; a new one is \
                     refused until the window resets",
                    crate::controls::config().end_user_ids_per_key_per_window
                ),
                detail: vec![(
                    "limit",
                    serde_json::json!(crate::controls::config().end_user_ids_per_key_per_window),
                )],
                retry_after_secs: Some(u32::try_from(retry).unwrap_or(u32::MAX)),
            }));
        }
    }
    let has_limits = ws_policy.is_some_and(|p| p.limits.is_some())
        || claims
            .governance
            .as_deref()
            .is_some_and(|g| g.policies().any(|(_, p)| p.limits.is_some()));
    if has_limits {
        let request = policy_request.get_or_insert_with(|| {
            crate::routing::expand(parsed.policy_request(), route_plan.as_deref())
        });
        let checks = match limit_checks(
            &claims,
            ws_policy,
            request,
            identity.end_user_id.as_deref(),
            entitlements.as_deref(),
            route_plan.as_deref(),
        ) {
            Ok(c) => c,
            Err(denial) => {
                state.rejection_metrics.record_admission_refusal(
                    tenant_id,
                    claims.api_key_id(),
                    crate::rejection_metrics::RejectionReason::PolicyDenied,
                    chrono::Utc::now(),
                );
                return Err(Refusal::Policy(denial));
            }
        };
        let table = crate::limits::table();
        let now = std::time::Instant::now();
        match table.admit(*tenant_id.as_uuid(), &checks, now) {
            Ok(debits) => table.park(
                trace_id,
                crate::limits::Reservation::new(
                    *tenant_id.as_uuid(),
                    debits,
                    claims.api_key_id().map(str::to_owned),
                    parsed.model().to_owned(),
                    identity.end_user_id.clone(),
                ),
                now,
            ),
            Err(d) => {
                state.rejection_metrics.record_admission_refusal(
                    tenant_id,
                    claims.api_key_id(),
                    crate::rejection_metrics::RejectionReason::RateLimited,
                    chrono::Utc::now(),
                );
                return Err(Refusal::Control(limit_denial(&d)));
            }
        }
    }

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
            // OG-22: a failed read is UNKNOWN spend — the hard cap refuses (it used to
            // seed 0 and let traffic through). A recent failure is not re-read per request.
            let baseline = if spend.seed_backing_off(who) {
                None
            } else {
                crate::server::spend_baseline_from_clickhouse(
                    crate::budgets::SpendSource::of(state),
                    tenant_id,
                    key_id_str,
                    cadence,
                )
                .await
            };
            let Some(baseline) = baseline else {
                spend.note_seed_failed(who);
                return Err(Refusal::Control(spend_unknown_denial("API key")));
            };
            spend.seed_if_needed(who, key_window, baseline);
        }
        if let crate::spend::BudgetDecision::Exceeded {
            budget_usd,
            spent_usd,
        } = spend.check(who, Some(budget))
        {
            state.rejection_metrics.record_admission_refusal(
                tenant_id,
                Some(key_id_str),
                crate::rejection_metrics::RejectionReason::KeyBudgetExceeded,
                chrono::Utc::now(),
            );
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
            // OG-22: as the key budget above — unknown spend refuses the hard cap.
            let baseline = if spend.seed_backing_off(who) {
                None
            } else {
                crate::server::workspace_spend_baseline_from_clickhouse(
                    crate::budgets::SpendSource::of(state),
                    tenant_id,
                )
                .await
            };
            let Some(baseline) = baseline else {
                spend.note_seed_failed(who);
                return Err(Refusal::Control(spend_unknown_denial("workspace")));
            };
            spend.seed_if_needed(who, year_month, baseline);
        }
        let budget_usd = workspace_budget_micro as f64 / 1_000_000.0;
        if let crate::spend::BudgetDecision::Exceeded {
            budget_usd,
            spent_usd,
        } = spend.check(who, Some(budget_usd))
        {
            // Whichever key made THIS request, if any — the workspace cap can be
            // tripped by any key in the tenant, so this attributes the triple to
            // the one that happened to trip it, same as the KeyBudget site above.
            state.rejection_metrics.record_admission_refusal(
                tenant_id,
                claims.api_key_id(),
                crate::rejection_metrics::RejectionReason::WorkspaceBudgetExceeded,
                chrono::Utc::now(),
            );
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
    // ── H2 (security review 2026-10-02): a budgeted caller may only spend what the
    // gateway can price. Unpriced spend never reaches the tracker the two checks above
    // read, so it would run past either budget unseen. Unbudgeted callers are untouched.
    // OG-11: a routed request may be served by ANY of its targets, so every target must
    // be priced (`routing::pricing`); one unpriced target refuses a budgeted caller.
    if caller_is_budgeted(&claims, entitlements.as_deref())
        && let Pricing::Unpriced { code, message } = match route_plan.as_deref() {
            Some(plan) => crate::routing::pricing(plan, entitlements.as_deref()),
            None => R::pricing_for(&parsed, entitlements.as_deref()),
        }
    {
        tracing::warn!(
            tenant_id = %tenant_id,
            route = R::NAME,
            code,
            "unpriceable request under a budget — refusing"
        );
        return Err(Refusal::Unpriced { code, message });
    }

    // ── Budgets (OG-22). Every policy budget that applies — workspace, project, key, and
    // each layer's per-end-user budget for this request's end user. Hard: refuse at the
    // ceiling, and refuse when the spend is UNKNOWN. Soft: never refuses (OG-24 alerts). ──
    progress.enter(Step::Budgets);
    for a in applicable_budgets(&claims, ws_policy, identity.end_user_id.as_deref()) {
        if let Err(r) = check_budget(crate::budgets::SpendSource::of(state), tenant_id, &a).await {
            state.rejection_metrics.record_admission_refusal(
                tenant_id,
                claims.api_key_id(),
                crate::rejection_metrics::RejectionReason::WorkspaceBudgetExceeded,
                chrono::Utc::now(),
            );
            return Err(r);
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
    let decision = if R::INSPECTS_BODY {
        state
            .predictive
            .evaluate_async(&crate::predictive::PredictiveContext {
                tenant_id,
                request_json: parsed.request_json(),
            })
            .await
    } else {
        // OG-08: an opaque body — nothing for a detector to read.
        crate::predictive::Decision::Allow
    };
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
    // fail-closed too, and since B-493 (2026-09-21) that includes dev / self-host:
    // with no Postgres pool the append is in-memory and its ClickHouse row rides a
    // bounded writer queue — a full queue (ClickHouse refusing `audit_log` writes)
    // refuses the append with the same 503, and the refused event consumes no seq.
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
    // B-568 I5: what admission knows so far (auth cold branch, JWT bridge miss,
    // blocking entitlement resolve). The handler adds its own BYOK miss.
    identity.cold_start = timer.is_cold();

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
    let attempt_security = Arc::new(crate::routing::attempt::Context::new(
        state,
        &claims,
        headers,
        parsed.policy_request(),
        route_plan.clone(),
        identity.end_user_id.clone(),
        R::credential(headers)
            .filter(|value| value.trim_start().starts_with("Bearer tlane_"))
            .map(|value| Arc::new(secrecy::SecretString::from(value))),
    ));
    Ok(Admitted {
        attempt_security,
        identity,
        request_start,
        trace_id,
        inbound_parent,
        parsed,
        entitlements,
        route_plan,
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

// ── OG-21 / OG-22 helpers ────────────────────────────────────────────────────

/// `OG-21`: what one request takes from the TPM buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenCost {
    /// Input estimate + declared output cap (or the default reserve).
    Known(u64),
    /// The route cannot estimate it — a TPM rule refuses (`policy_unenforceable`).
    Unknown,
    /// A batch file: its lines run asynchronously, outside any minute — not reserved.
    NotCounted,
}

/// `OG-11`: the cost strategy's token estimate — the request's input estimate and its
/// declared output cap (the default reserve when it declared none).
fn estimate(req: &PolicyRequest) -> crate::routing::Estimate {
    let s = req.subjects.first();
    let input_tokens = match s.map(|s| &s.input_tokens) {
        Some(Fact::Known(n)) => *n,
        _ => 0,
    };
    let output_tokens = match s.map(|s| &s.output_cap) {
        Some(Fact::Known(Some(n))) => *n,
        _ => crate::controls::config().default_output_reserve_tokens,
    };
    crate::routing::Estimate {
        input_tokens,
        output_tokens,
        owner: None,
    }
}

/// `OG-21`: the TPM reservation of `req`.
pub(crate) fn token_cost(req: &PolicyRequest, default_reserve: u64) -> TokenCost {
    if req.subjects.iter().any(|s| s.line.is_some()) {
        return TokenCost::NotCounted;
    }
    let mut n: u64 = 0;
    for s in &req.subjects {
        match s.input_tokens {
            Fact::Known(v) => n = n.saturating_add(v),
            Fact::NotApplicable => {}
            Fact::Unknown => return TokenCost::Unknown,
        }
        match s.output_cap {
            Fact::Known(Some(v)) => n = n.saturating_add(v),
            Fact::Known(None) => n = n.saturating_add(default_reserve),
            Fact::NotApplicable => {}
            Fact::Unknown => return TokenCost::Unknown,
        }
    }
    TokenCost::Known(n)
}

/// `OG-21`: every bucket this request must fit in, from each layer's `limits`.
///
/// # Errors
/// `policy_unenforceable` when a `tpm` rule meets a route that cannot estimate, or a
/// `per_model` rule meets one that cannot name its model. Fail-CLOSED.
pub(crate) fn limit_checks(
    claims: &Claims,
    workspace: Option<&tracelane_shared::key_policy::KeyPolicy>,
    request: &PolicyRequest,
    end_user: Option<&str>,
    entitlements: Option<&ResolvedEntitlements>,
    plan: Option<&crate::routing::RoutePlan>,
) -> Result<Vec<crate::limits::Check>, tracelane_shared::key_policy::Denial> {
    use crate::limits::{BucketKey, Check, Dim, Kind, Scope};
    use tracelane_shared::key_policy::{Origin, Rate, deny_matches, unenforceable};
    let mut layers: Vec<(Origin, Scope, &tracelane_shared::key_policy::Limits)> = Vec::new();
    if let Some(l) = workspace.and_then(|p| p.limits.as_ref()) {
        layers.push((Origin::Workspace, Scope::Workspace, l));
    }
    if let Some(g) = claims.governance.as_deref() {
        for (origin, p) in g.policies() {
            let Some(l) = p.limits.as_ref() else { continue };
            let scope = match origin {
                Origin::Project => g.project_id.map(Scope::Project),
                Origin::Key => claims
                    .api_key_id()
                    .and_then(|k| Uuid::parse_str(k).ok())
                    .map(Scope::Key),
                Origin::Workspace => None,
            };
            if let Some(scope) = scope {
                layers.push((origin, scope, l));
            }
        }
    }
    let cost = token_cost(
        request,
        crate::controls::config().default_output_reserve_tokens,
    );
    let mut names: Option<Vec<String>> = Some(Vec::new());
    for sub in &request.subjects {
        match &sub.model {
            Fact::Known(m) => {
                let r = routed_policy_resolve(m, sub.workspace_alias, entitlements, plan);
                if let Some(v) = names.as_mut() {
                    v.extend(r.names);
                    v.extend(r.allow_names);
                }
            }
            Fact::NotApplicable => {}
            Fact::Unknown => names = None,
        }
    }
    let eu = end_user.map(crate::limits::end_user_hash);
    let mut checks = Vec::new();
    let mut push = |origin: Origin,
                    scope: Scope,
                    dim: Dim,
                    rate: &Rate,
                    rule: &'static str|
     -> Result<(), tracelane_shared::key_policy::Denial> {
        if let Some(rpm) = rate.rpm {
            checks.push(Check {
                key: BucketKey {
                    scope,
                    dim: dim.clone(),
                    kind: Kind::Rpm,
                },
                limit: rpm,
                cost: 1,
            });
        }
        if let Some(tpm) = rate.tpm {
            match cost {
                TokenCost::Known(n) => checks.push(Check {
                    key: BucketKey {
                        scope,
                        dim,
                        kind: Kind::Tpm,
                    },
                    limit: tpm,
                    cost: n,
                }),
                TokenCost::NotCounted => {}
                TokenCost::Unknown => return Err(unenforceable(origin, rule, None)),
            }
        }
        Ok(())
    };
    for (origin, scope, l) in layers {
        push(origin, scope, Dim::All, &l.rate, "limits.tpm")?;
        if let (Some(r), Some(h)) = (&l.per_end_user, eu) {
            push(origin, scope, Dim::EndUser(h), r, "limits.per_end_user")?;
        }
        if !l.per_model.is_empty() {
            let Some(names) = names.as_ref() else {
                return Err(unenforceable(origin, "limits.per_model", None));
            };
            for m in &l.per_model {
                // rev6 M3 residual: by every name the request carries AND its provider-facing
                // (prefix-stripped) names — the helper deny and block lists use — so
                // `azure/gpt-4o` is inside a `gpt-4o*` limit. A limit is a ceiling: matching
                // more names is the fail-closed direction.
                if names
                    .iter()
                    .any(|n| deny_matches(std::slice::from_ref(&m.model), n))
                {
                    push(
                        origin,
                        scope,
                        Dim::Model(m.model.clone()),
                        &m.rate,
                        "limits.per_model",
                    )?;
                }
            }
        }
    }
    Ok(checks)
}

/// `OG-22`: every policy budget that applies to this request.
pub(crate) fn applicable_budgets(
    claims: &Claims,
    workspace: Option<&tracelane_shared::key_policy::KeyPolicy>,
    end_user: Option<&str>,
) -> Vec<crate::budgets::Applicable> {
    use crate::limits::Scope;
    use tracelane_shared::key_policy::Origin;
    let mut layers: Vec<(Origin, Scope, &tracelane_shared::key_policy::KeyPolicy)> = Vec::new();
    if let Some(p) = workspace {
        layers.push((Origin::Workspace, Scope::Workspace, p));
    }
    if let Some(g) = claims.governance.as_deref() {
        for (origin, p) in g.policies() {
            let scope = match origin {
                Origin::Project => g.project_id.map(Scope::Project),
                Origin::Key => claims
                    .api_key_id()
                    .and_then(|k| Uuid::parse_str(k).ok())
                    .map(Scope::Key),
                Origin::Workspace => None,
            };
            if let Some(scope) = scope {
                layers.push((origin, scope, p));
            }
        }
    }
    let mut out = Vec::new();
    for (origin, scope, p) in layers {
        if let Some(b) = &p.budget {
            out.push(crate::budgets::Applicable {
                origin,
                scope,
                end_user: None,
                budget: b.clone(),
            });
        }
        if let (Some(b), Some(u)) = (&p.end_user_budget, end_user) {
            out.push(crate::budgets::Applicable {
                origin,
                scope,
                end_user: Some(u.to_owned()),
                budget: b.clone(),
            });
        }
    }
    out
}

/// `OG-22`: one budget's decision — seeding its counter first when it must.
///
/// # Errors
/// `402 budget_exceeded_*` for a hard budget at its ceiling; `503 budget_spend_unknown`
/// for a hard budget whose spend cannot be read; `503 budget_capacity`. A soft budget
/// never refuses. Fail-CLOSED.
pub(crate) async fn check_budget(
    src: crate::budgets::SpendSource<'_>,
    tenant_id: &tracelane_shared::TenantId,
    a: &crate::budgets::Applicable,
) -> Result<(), Refusal> {
    use crate::budgets::{Prep, table};
    let hard = crate::budgets::is_hard(&a.budget);
    let t = *tenant_id.as_uuid();
    let now = chrono::Utc::now();
    let at = std::time::Instant::now();
    let label = a.subject_label();
    let spent = match table().prepare(t, a, now, at) {
        Prep::Ready { spent } => spent,
        Prep::NeedsSeed { period } => {
            match crate::budgets::baseline(src, tenant_id, a, period, now).await {
                Some(seed) => table().seed(t, a, period, &seed, now).unwrap_or(0),
                None => {
                    table().seed_failed(t, a, at);
                    if hard {
                        return Err(Refusal::Control(spend_unknown_denial(label)));
                    }
                    return Ok(());
                }
            }
        }
        Prep::Backoff => {
            if hard {
                return Err(Refusal::Control(spend_unknown_denial(label)));
            }
            return Ok(());
        }
        Prep::Capacity => {
            if hard {
                return Err(Refusal::Control(ControlDenial {
                    status: 503,
                    code: "budget_capacity",
                    message: "too many end users are being tracked for budgets in this workspace \
                              right now; retry shortly"
                        .to_owned(),
                    detail: vec![],
                    retry_after_secs: Some(60),
                }));
            }
            return Ok(());
        }
    };
    if hard && spent >= a.budget.micro_usd {
        let code = match label {
            "workspace" => "budget_exceeded_workspace",
            "project" => "budget_exceeded_project",
            "key" => "budget_exceeded_key",
            _ => "budget_exceeded_end_user",
        };
        return Err(Refusal::Control(ControlDenial {
            status: 402,
            code,
            message: format!(
                "this {}'s {} {} budget is spent",
                label.replace('_', " "),
                a.budget.window.as_str(),
                a.origin.as_str()
            ),
            detail: vec![
                ("policy", serde_json::json!(a.origin.as_str())),
                ("window", serde_json::json!(a.budget.window.as_str())),
                ("budget_usd", serde_json::json!(a.budget.usd())),
                ("spent_usd", serde_json::json!(spent as f64 / 1_000_000.0)),
                (
                    "resets_at",
                    serde_json::json!(
                        crate::budgets::resets_at(a.budget.window, now).map(|t| t.to_rfc3339())
                    ),
                ),
            ],
            retry_after_secs: None,
        }));
    }
    Ok(())
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
    /// One generating call; the WORKSPACE alias applies (chat rewrites it at entry).
    /// The body size here is the compact re-encoding — used only when the request
    /// carried no `Content-Length` (`enforce_policy` prefers the header).
    fn policy_request(&self) -> PolicyRequest {
        PolicyRequest {
            subjects: vec![chat_subject(&self.request, true, None)],
            body_bytes: json_len(&self.body),
        }
    }
}

/// `OG-20`: the compact JSON re-encoding's length of a body the extractor already parsed.
pub(crate) fn json_len(v: &serde_json::Value) -> Fact<u64> {
    serde_json::to_vec(v).map_or(Fact::Unknown, |b| Fact::Known(b.len() as u64))
}

/// `OG-20`: ~4 bytes per token over every string leaf of `v` (an embeddings `input`).
pub(crate) fn json_text_estimate(v: &serde_json::Value) -> u64 {
    fn walk(v: &serde_json::Value, n: &mut u64) {
        match v {
            serde_json::Value::String(s) => *n += s.len() as u64,
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, n)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, n)),
            _ => {}
        }
    }
    let mut n = 0;
    walk(v, &mut n);
    n / 4
}

impl Route for Chat {
    /// Re-review H-3: price the WORKSPACE alias target, the model actually dispatched.
    fn pricing_for(parsed: &Self::Parsed, entitlements: Option<&ResolvedEntitlements>) -> Pricing {
        token_pricing_after_workspace_alias(parsed.model(), entitlements)
    }

    type Body = serde_json::Value;
    type Parsed = ChatParsed;
    const NAME: &'static str = "chat";
    const AUDIT_EVENT_TYPE: &'static str = "chat.completions.request";
    const CACHE: crate::admission::CacheScope = crate::admission::CacheScope::Serves;
    const ROUTING: crate::routing::RoutingScope = crate::routing::RoutingScope {
        wire: crate::routing::Wire::Chat,
        virtual_models: crate::routing::VirtualSupport::AnyProvider,
        key_pool: crate::routing::PoolSupport::Pool,
        fallthrough: true,
        timeouts: true,
    };

    fn credential(headers: &HeaderMap) -> Option<String> {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    fn parse(body: serde_json::Value) -> Result<ChatParsed, Malformed> {
        let mut request = serde_json::from_value::<tracelane_shared::ChatRequest>(body.clone())
            .map_err(|err| Malformed {
                code: "invalid_request",
                message: format!("malformed request: {err}"),
                detail: None,
            })?;
        // OG-03: drop what the gateway owns from the unmodelled-field bag, then refuse
        // what no provider could serve (n > 1, a bad stop / response_format / effort, a
        // data URI that is not an allowlisted type or does not decode) BEFORE anything
        // is charged. Provider-specific support is judged later, once the provider is
        // final (`request_support::check_supported`).
        crate::request_support::normalize_extra(&mut request);
        crate::request_support::validate_shape(&request)
            .map_err(crate::request_support::Unsupported::into_malformed)?;
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
            // OG-03: a refusal that names a field or part carries its own structured body.
            let body = m
                .detail
                .unwrap_or_else(|| serde_json::json!({ "error": m.message }));
            (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
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
    /// The WORKSPACE alias applies (embeddings rewrites it); no output tokens to cap.
    fn policy_request(&self) -> PolicyRequest {
        PolicyRequest {
            subjects: vec![Subject {
                line: None,
                model: Fact::Known(self.request.model.clone()),
                workspace_alias: true,
                provider: None,
                input_tokens: Fact::Known(json_text_estimate(&self.request.input)),
                output_cap: Fact::NotApplicable,
            }],
            body_bytes: json_len(&self.body),
        }
    }
}

impl Route for Embeddings {
    /// Re-review H-3: price the WORKSPACE alias target, the model actually dispatched.
    fn pricing_for(parsed: &Self::Parsed, entitlements: Option<&ResolvedEntitlements>) -> Pricing {
        token_pricing_after_workspace_alias(parsed.model(), entitlements)
    }

    type Body = serde_json::Value;
    type Parsed = EmbeddingsParsed;
    const NAME: &'static str = "embeddings";
    const AUDIT_EVENT_TYPE: &'static str = "embeddings.request";
    const CACHE: crate::admission::CacheScope = crate::admission::CacheScope::Refuses;
    // OG-11: one concrete target only — vector dimensions must not change mid-index.
    const ROUTING: crate::routing::RoutingScope = crate::routing::RoutingScope {
        wire: crate::routing::Wire::Embeddings,
        virtual_models: crate::routing::VirtualSupport::SingleTarget,
        key_pool: crate::routing::PoolSupport::Pool,
        fallthrough: false,
        timeouts: true,
    };

    fn credential(headers: &HeaderMap) -> Option<String> {
        Chat::credential(headers)
    }

    fn parse(body: serde_json::Value) -> Result<EmbeddingsParsed, Malformed> {
        let request = serde_json::from_value::<crate::providers::EmbeddingsRequest>(body.clone())
            .map_err(|err| Malformed {
            code: "invalid_request",
            message: format!("malformed embeddings request: {err}"),
            detail: None,
        })?;
        request.validate().map_err(|err| Malformed {
            code: "invalid_request",
            message: format!("{err}"),
            detail: None,
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

    #[test]
    fn h2_operator_alias_to_unpriced_reseller_is_refused_for_budgeted_keys() {
        let alias = crate::server::config::ModelAlias {
            provider_id: "openrouter".to_owned(),
            upstream_model: "gpt-5.6-sol".to_owned(),
        };
        assert!(matches!(
            token_pricing_with_alias("gpt-5.6-sol", Some(&alias)),
            Pricing::Unpriced { .. }
        ));
    }

    /// Re-review H-3 (2026-10-02): the budget pricing check judges the WORKSPACE alias
    /// TARGET — an ordinary alias onto a priced model passes (it was refused, a regression
    /// that broke GWY-27 aliases for every budgeted workspace), and an alias whose name is a
    /// priced model but whose target is unpriced is refused (it escaped the budget).
    #[test]
    fn h3_budget_pricing_judges_the_workspace_alias_target() {
        let mut aliases = std::collections::BTreeMap::new();
        aliases.insert("fast".to_owned(), "gpt-6-luna".to_owned());
        aliases.insert(
            "gpt-6-astra".to_owned(),
            "no-such-unpriced-model-xyz".to_owned(),
        );
        let ent = crate::entitlement_cache::ResolvedEntitlements {
            model_aliases: std::sync::Arc::new(aliases),
            ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
        };
        assert_eq!(
            token_pricing_after_workspace_alias("fast", Some(&ent)),
            Pricing::Priced,
            "an alias onto a priced model must pass"
        );
        assert!(
            matches!(
                token_pricing_after_workspace_alias("gpt-6-astra", Some(&ent)),
                Pricing::Unpriced { .. }
            ),
            "a priced NAME aliased onto an unpriced TARGET must be refused"
        );
        // No alias → the requested model itself.
        assert_eq!(
            token_pricing_after_workspace_alias("gpt-6-astra", None),
            Pricing::Priced
        );
    }
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

    // ── B-568 I1: the stage timer covers authentication ──

    /// The pre-dispatch stages must account for the WHOLE interval the span's
    /// overhead number opens with — `request_start` onwards — including the
    /// credential check. The validator here takes a known 5 ms; if the timer were
    /// created after it (the pre-B-568 shape) those 5 ms would land in
    /// `unaccounted_us`, which is exactly the blind spot the prod slow lines had.
    #[tokio::test]
    async fn the_stage_timer_opens_before_authentication() {
        const AUTH_US: u64 = 5_000;
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let a = admit_via::<Chat, _, _>(
            &state,
            &authed(),
            chat_body(),
            |_cred| async {
                tokio::time::sleep(std::time::Duration::from_micros(AUTH_US)).await;
                Ok((
                    crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey),
                    crate::auth::AuthPath::ApiKey(crate::db::api_keys::LookupPath::Cold),
                ))
            },
            None,
        )
        .await
        .unwrap_or_else(|r| panic!("admission refused: {r:?}"));
        let overhead_us = u64::try_from(
            (chrono::Utc::now() - a.request_start)
                .num_microseconds()
                .unwrap_or(0),
        )
        .unwrap_or(0);
        let accounted = a.timer.accounted_us();
        assert!(
            overhead_us.saturating_sub(accounted) < 1_000,
            "stages accounted {accounted} us of {overhead_us} us — the rest is \
             unaccounted, so authentication is outside the timer"
        );
        let authenticate = a
            .timer
            .stages()
            .find(|(name, _)| *name == "authenticate")
            .map(|(_, us)| u64::from(us));
        assert!(
            authenticate.is_some_and(|us| us >= AUTH_US),
            "the first stage must be `authenticate` and carry the validator's time, got {authenticate:?}"
        );
        // The branch that answered is carried, and a cold branch marks the request cold.
        assert!(
            a.timer.is_cold(),
            "a cold auth branch must mark the request cold"
        );
        assert!(a.identity.cold_start, "and the span identity must carry it");
        let mut a = a;
        a.dispatch_guard.disarm();
    }

    /// The negative: a warm branch leaves the request warm (nothing else in this
    /// fixture goes to a control plane — there is none).
    #[tokio::test]
    async fn a_warm_auth_branch_leaves_the_request_warm() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let a = admit_via::<Chat, _, _>(
            &state,
            &authed(),
            chat_body(),
            |_cred| async {
                Ok((
                    crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey),
                    crate::auth::AuthPath::ApiKey(crate::db::api_keys::LookupPath::Warm),
                ))
            },
            None,
        )
        .await
        .unwrap_or_else(|r| panic!("admission refused: {r:?}"));
        assert!(!a.timer.is_cold());
        assert!(!a.identity.cold_start);
        let mut a = a;
        a.dispatch_guard.disarm();
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
                    detail: None,
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
            detail: None,
        })))
        .await;
        assert_eq!(chat["error"], "malformed request: x");
        let emb =
            crate::handler_harness::body_json(Embeddings::refuse(Refusal::Malformed(Malformed {
                code: "invalid_request",
                message: "malformed embeddings request: y".into(),
                detail: None,
            })))
            .await;
        assert_eq!(emb["error"], "invalid_request");
        assert_eq!(emb["message"], "malformed embeddings request: y");
    }
}
