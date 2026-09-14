//! Tracelane span model.
//!
//! `TracelaneSpan` captures OTel core fields plus OpenInference semantic
//! conventions (`llm.*`, `gen_ai.*`) and Tracelane-specific attributes
//! (`tracelane.*`). This is the canonical schema stored in ClickHouse.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::tenant::TenantId;

/// A Tracelane span following OTel GenAI + OpenInference + tracelane.* semconv.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracelaneSpan {
    pub span_id: Uuid,
    pub trace_id: Uuid,
    pub parent_span_id: Option<Uuid>,
    pub tenant_id: TenantId,
    pub name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub attributes: SpanAttributes,
    pub status: SpanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpanAttributes {
    // OTel GenAI semconv
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_request_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_usage_input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_usage_output_tokens: Option<u32>,

    // OTel GenAI semconv — added fields (§3.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_operation_name: Option<String>,
    /// Canonical provider field (v1.37, replaces `gen_ai.system`). The store
    /// normalizes legacy `gen_ai.system` into this column on write (ADR-032).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_provider_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_response_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_agent_name: Option<String>,

    // OTel GenAI semconv v1.40/v1.41 additions (ADR-032)
    /// Prompt-cache read tokens (`gen_ai.usage.cache_read.input_tokens`, v1.40).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_usage_cache_read_input_tokens: Option<u32>,
    /// Prompt-cache write tokens (`gen_ai.usage.cache_creation.input_tokens`, v1.40).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_usage_cache_creation_input_tokens: Option<u32>,
    /// Reasoning/thinking tokens (`gen_ai.usage.reasoning.output_tokens`, v1.41).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_usage_reasoning_output_tokens: Option<u32>,
    /// Upstream-reported request cost in USD (`gen_ai.usage.cost`;).
    /// Only set when the provider reports cost on the wire (e.g. OpenRouter);
    /// never computed from a local price table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_usage_cost: Option<f64>,
    /// Whether the request was streamed (`gen_ai.request.stream`, v1.41).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_request_stream: Option<bool>,
    /// Time-to-first-chunk in seconds for streaming (`gen_ai.response.time_to_first_chunk`, v1.41).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_response_time_to_first_chunk: Option<f64>,
    /// Gateway-overhead microseconds — the time Tracelane ADDS, EXCLUDING the
    /// upstream provider round-trip: `(dispatch − received) + (sent − provider
    /// complete)`. With `duration_us` (total) this splits latency into the two
    /// segments that sum to total: `provider = total − gateway_overhead`, no
    /// unattributed bucket. `None` on spans without a measured provider round-trip
    /// (dispatch failures, guardrail blocks). This is the SRE metric — the gateway
    /// budget is p99 < 15ms; total `duration_us` is dominated by provider gen time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_gateway_overhead_us: Option<u32>,

    // ── GWY-24 semantic cache ────────────────────────────────────────────────
    //
    // THE NAMES ALL CARRY `semantic_`, DELIBERATELY. `trace_reads.rs` already
    // computes `cache_hits` from `gen_ai_usage_cache_read_input_tokens` — the
    // PROVIDER's own prompt cache — and renders it as "Cache hit rate" on
    // /gateway and /dashboard. A bare `tracelane_cache_hit` would read as that
    // same metric to anyone looking at the tile, and the two would be silently
    // conflated into one number that means neither thing.
    /// `true` on a served hit, `false` when the cache was consulted and missed,
    /// absent when the cache is off. Three states, because "missed" and "not
    /// enabled" are different facts and a hit rate computed over the wrong
    /// denominator is worse than none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_semantic_cache_hit: Option<bool>,
    /// `exact` or `semantic`. A byte match and a 1.000 similarity are different
    /// facts; the exact tier reports no similarity at all rather than a
    /// flattering 1.000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_semantic_cache_tier: Option<String>,
    /// R81 — the eval run this span belongs to, or `None` for ordinary traffic.
    ///
    /// **This is what makes eval traffic SEPARABLE**, and it is not cosmetic:
    /// `/v1/costs` reads spans, so before this existed an eval run's provider
    /// spend was invisible to the surface a customer checks before an invoice.
    /// It is also what lets a tenant's own dashboards EXCLUDE eval traffic —
    /// without it, running an evaluation silently inflates the numbers the
    /// evaluation exists to inform.
    ///
    /// `EVL-05`'s spec promised this in §2.4b and the code did not do it: the
    /// engine dispatched in-process and published no span at all. Confirmed four
    /// ways — a live prod query returning 0, and three independent spec drafters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_eval_run_id: Option<String>,
    /// `EVL-02` — the experiment this span's arm belongs to, or `None`.
    ///
    /// **A SECOND attribute rather than a widened first one**, and the reason is
    /// that they answer different questions. `tracelane_eval_run_id` says *which
    /// run* produced this call and is present on every eval span; this says
    /// *which comparison* the run was an arm of, and is absent for a standalone
    /// run. Folding the two into one id would make "exclude eval traffic" and
    /// "show me what this experiment cost" the same query, and they are not: an
    /// experiment is N runs, and a run can exist with no experiment.
    ///
    /// Read with `JSONExtractString(attributes, 'tracelane_experiment_id')`,
    /// NEVER a `MATERIALIZED` column — spec `EVL-02` §2.3b: a materialized column
    /// is computed on INSERT and would be empty for every span already written,
    /// so the first spans a measurement feature ever emitted would be invisible
    /// to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_experiment_id: Option<String>,
    /// `EVL-23` (item 10) — `"case"` or `"judge"`, on eval spans only.
    ///
    /// **A THIRD attribute rather than a widened second one**, for the same
    /// reason there are already two: it answers a different question. A judge
    /// call is an ordinary provider call that costs the tenant real money, and
    /// without this the only way to tell what the JUDGE cost from what the run
    /// cost is to guess from the model name — which fails the moment someone
    /// judges with the model under test. `/v1/costs` splits on it, so "what did
    /// grading cost me" is answerable rather than folded into "what did the eval
    /// cost me".
    ///
    /// Absent on every non-eval span, so `JSONExtractString(attributes,
    /// 'tracelane_eval_role')` is `''` for production traffic and the split is
    /// exact both ways.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_eval_role: Option<String>,
    /// `1 - cosineDistance`, present only for a semantic hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_semantic_cache_similarity: Option<f32>,
    /// The trace whose answer was reused. THE flight-recorder link, and the
    /// reason this cache is compatible with an audit product at all: "which
    /// answer did you serve me, and where did it come from" stays answerable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_semantic_cache_source_trace_id: Option<String>,
    /// What the ORIGINAL call cost — i.e. what this hit saved. Reported
    /// separately from `gen_ai_usage_cost`, which is 0 for a hit, so a saving is
    /// never presented as a charge or vice versa.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_semantic_cache_cost_saved_usd: Option<f64>,
    /// The Tracelane API key that authorised this request (GWY-43).
    ///
    /// **This is the dimension cost attribution needs and did not have.** Spans
    /// carried tenant, model and provider, so "spend by model" was answerable
    /// and "spend by key" or "spend by team" was not — not hard, *impossible*,
    /// because the fact was never recorded. That is the same shape as
    /// `OBS-N1` (a read path with no writer): the dashboard could not have
    /// shown it however well it were built.
    ///
    /// `None` for a session-authenticated (JWT) request, which has no API key —
    /// distinct from "unattributed", and the read paths must not conflate them.
    /// Never the key itself, only its row id: the key material is never stored
    /// anywhere in plaintext (`db/api_keys.rs` keeps an HMAC lookup hash plus an
    /// Argon2id verifier and nothing else).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_api_key_id: Option<String>,
    /// Agent version, for B1 prompt-promotion correlation (`gen_ai.agent.version`, v1.40).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_agent_version: Option<String>,
    /// Conversation/session correlation id (`gen_ai.conversation.id`, v1.36).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_conversation_id: Option<String>,

    // Structured message capture (v1.37+, replaces deprecated per-message events).
    // Populated only when content capture is enabled (TRACELANE_TRACE_CONTENT);
    // off by default for privacy. Stored as JSON arrays/object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_system_instructions: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_input_messages: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_output_messages: Option<Value>,

    // Tracelane predictive attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_predictive_rug_pull_detected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_predictive_stuck_loop: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_predictive_captcha_detected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_predictive_anomaly_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_aft_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_intervention: Option<Intervention>,

    // Cross-provider failover. Set only on a request that the primary
    // provider failed and a `X-Tracelane-Failover: cross-provider` fallback
    // then served. The span is attributed to the SERVING provider (so its
    // per-provider request/latency counts are honest); these two mark that it
    // arrived via failover and name the primary that errored. The Gateway-ops
    // rollup counts `countIf(tracelane_failover_activated)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_failover_activated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_failover_from: Option<String>,

    // Lethal trifecta taint attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_taint_reads_private_data: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_taint_sees_untrusted_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_taint_can_exfiltrate: Option<bool>,

    // MCP attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_mcp_tool_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_mcp_server_url: Option<String>,

    // KYA (Know Your Agent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_kya_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_kya_human_authorizer: Option<String>,

    /// Customer-supplied business reference (BFSI evidence capture — a loan
    /// application id, transaction ref, case number, …). Set via the OTLP span
    /// attribute `tracelane.business_reference` or, on a gateway-proxied call,
    /// the `x-business-reference` header. Free-form but LENGTH-BOUNDED at the
    /// trust boundary (`bounded_business_reference`) — it is customer-controlled
    /// text, so it is capped before it enters a span or the tamper-evident chain.
    /// Redacted through `tracelane_policy::pii::redact_json` before both ClickHouse
    /// and audit-chain persistence, so a structured secret/PII value a customer
    /// mistakenly supplies is scrubbed. It is otherwise PERMANENT once chained —
    /// customers should use a stable business identifier, not free-form text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_business_reference: Option<String>,

    /// `OBS-20`. The CUSTOMER'S OWN END USER — the person on the other side of
    /// the customer's application, whom Tracelane has never authenticated and
    /// never will. Answers *"who initiated this trace"*.
    ///
    /// **This is a FOURTH population and deliberately not called `actor`.** That
    /// word is already taken three times over, each time for someone else:
    /// `AuditEvent::actor` is `claims.sub` (on prod traffic literally
    /// `apikey:<uuid>`, a machine); `admin_audit_log.actor_user_id` is a WorkOS
    /// user — our customer's *employee*, in the dashboard; and
    /// `tracelane_kya_human_authorizer` two fields above is KYA — *who approved
    /// this agent to run*, not who asked it a question. A fourth meaning of
    /// "actor" guarantees a query that mixes machines with humans.
    ///
    /// Stored under the JSON key `user_id`, which is `user.id` with the dots
    /// swapped for underscores — the registry-name rule GWY-48 states below.
    /// `user.id` is simultaneously the OTel registry spelling, OpenInference's
    /// reserved attribute and one of Langfuse's two accepted spellings, so one
    /// decoder arm lights up three ecosystems with no customer work.
    ///
    /// Supplied by the caller and by nobody else. There is NO derivation and no
    /// fallback: for an API-key request the gateway knows `claims.sub =
    /// "apikey:<id>"` and no email or name at all, so a synthesised "user" would
    /// really be a credential and would make every aggregate silently wrong.
    /// Absent means absent.
    ///
    /// LENGTH-BOUNDED at the trust boundary (`bounded_end_user_id`) — the same
    /// treatment as `tracelane_business_reference` above, and deliberately NOT
    /// the treatment of the two KYA fields, which take the raw header unbounded.
    ///
    /// **It is redacted, and that is the interesting part.** Ingest runs
    /// `tracelane_policy::pii::redact_json` over the whole attribute blob and
    /// `email` is one of its categories, so a customer who sends
    /// `alice@acme.com` — the most likely thing a customer will do — gets
    /// `[REDACTED:email]` stored on every span. That is not exempted here: the
    /// alternative is durably storing customer PII we promise to scrub. The read
    /// surfaces render the placeholder as its own explained state instead, so a
    /// working policy cannot be mistaken for a broken feature.
    ///
    /// NOT written into the audit ledger. `ADR-068` rests on a full-ledger scan
    /// finding **0** actors containing `@`, and a ledger row cannot be erased
    /// without breaking its hash chain, so an end-user identity there would be
    /// permanent and would falsify the ground truth that decision depends on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    // x402 / AP2 / ACP payment protocol
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_intent: Option<String>, // "payment.intent": declared intent to pay
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_mandate: Option<String>, // "payment.mandate": signed mandate ID (AP2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_settled: Option<bool>, // "payment.settled": x402 settlement confirmed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_amount_usd: Option<f64>, // payment amount in USD cents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_recipient: Option<String>, // recipient address/account

    // ── GWY-48 request configuration · OBS-53 confidence · OBS-52 flags ──────
    //
    // WHY THESE ARE NOT BEHIND THE CONTENT GATE, stated once so it is not
    // re-argued: 1-4 are numbers the DEVELOPER chose, not text the END USER
    // wrote, and an `f32` cannot carry a prompt. The `trace_content:` allowlist
    // exists to gate customer message text; putting a temperature behind it
    // would ship the whole feature invisible on prod, where that allowlist is
    // empty for every tenant.
    //
    // NAMING RULE, load-bearing: an attribute that HAS a name in the OTel GenAI
    // registry uses that name; one that does NOT gets a `tracelane.request.*`
    // name. Inventing a key inside `gen_ai.request.*` would assert a convention
    // that does not exist. (As everywhere in this struct, the stored JSON key is
    // the Rust FIELD NAME — `gen_ai_request_top_p` — which is this repo's
    // encoding of the dotted convention, not a deviation from it.)
    //
    // ZERO IS NOT UNKNOWN, on every one of them: absent means the client sent
    // nothing. `0.0` is a legal temperature and `0` a legal tool count, so a
    // default is never substituted for an absence. Same class as
    // `cost_usd_present` in the ClickHouse schema.
    /// `gen_ai.request.temperature` (registry, verbatim). What the CLIENT sent
    /// for THIS request — never the provider's default when none was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_request_temperature: Option<f32>,
    /// `gen_ai.request.top_p` (registry, verbatim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_request_top_p: Option<f32>,
    /// `gen_ai.request.max_tokens` (registry, verbatim). What the client sent —
    /// **not** what the provider applied. Anthropic substitutes 4096 when this is
    /// absent, and the span records the ABSENCE, which is the fact `OBS-52` needs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_request_max_tokens: Option<u32>,
    /// `gen_ai.request.seed` (registry, verbatim). Recorded even when the target
    /// provider has no seed concept — that is the client's misconfiguration made
    /// visible, not a claim the provider honoured it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_ai_request_seed: Option<u64>,
    /// `tracelane.request.tool_choice_mode` — no registry name exists. A CLOSED
    /// set: `auto` | `none` | `required` | `function`. Absent is NOT `auto`; the
    /// provider's default is the provider's business.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_request_tool_choice_mode: Option<String>,
    /// The tool named by `tool_choice: {"type":"function",…}`, length-bounded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_request_tool_choice_function: Option<String>,
    /// How many tool definitions the request OFFERED — not how many were called
    /// (that is `gen_ai.tool.name` on tool spans). **Always the TRUE count**, so
    /// `tool_count > len(tool_names)` is the visible signal the name list was cut.
    /// `0` means an explicitly empty array, which is a different (and suspicious)
    /// fact from the key being absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_request_tool_count: Option<u32>,
    /// The offered tools' NAMES, in wire order, bounded. Never their schemas and
    /// never their descriptions. Ungated on R3's precedent, which already stores
    /// tool names per tenant with no content gate and says so in writing
    /// (`gateway/src/db/observed_tools.rs`); `pii::redact_json` at ingest is the
    /// backstop for a customer who puts an address in a tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_request_tool_names: Option<Vec<String>>,
    /// `blake3` over the SORTED per-tool `def_hash` values, where `def_hash` is
    /// `guardrail::capability::def_hash` — the SAME function R3 pins against, so a
    /// customer can join this span to `observed_tools.def_hash` and get "which
    /// tool, when, approved or not" out of a table that already exists. It changes
    /// when a schema or a description changes, which is the whole point; a hash of
    /// the names would not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_request_tool_definitions_hash: Option<String>,
    /// Provider-specific deployment / fine-tune identity parsed from the model
    /// string (an OpenAI `ft:…`, an Azure deployment, a Bedrock ARN). `None` — not
    /// `""` — for a plain model id, because an empty string renders as a value and
    /// would make "this is a plain model" indistinguishable from "we failed to
    /// parse".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_request_deployment_id: Option<String>,
    /// `OBS-53`. Arithmetic mean of the per-token `logprob` the provider returned.
    /// **NOT a probability, NOT a calibrated confidence, and NOT comparable
    /// between models** — every surface that renders it must say so. Present only
    /// when the CLIENT asked for logprobs on an OpenAI-compatible provider; the
    /// gateway never turns them on by itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_response_logprob_mean: Option<f64>,
    /// `OBS-53`. The least-confident token's `logprob`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_response_logprob_min: Option<f64>,
    /// `OBS-53`. How many tokens the summary covers, so a sampled summary is never
    /// presented as a whole-response one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_response_logprob_token_count: Option<u32>,
    /// `OBS-52`. A CLOSED vocabulary of misconfiguration flags —
    /// `temperature_out_of_range` | `top_p_out_of_range` | `missing_max_tokens`.
    ///
    /// **Absent means two different things and the read side must not conflate
    /// them:** nothing flagged, or nothing could be checked. The presence of the
    /// GWY-48 attributes above is what distinguishes them, so "no flags" must
    /// never be rendered as "healthy" on a span carrying no request config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracelane_misconfig_flags: Option<Vec<String>>,

    /// Catch-all for additional attributes
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

/// Max stored length of a customer-supplied `business_reference` (unicode
/// scalar values). A real reference (loan id, txn ref, case number) is short;
/// anything longer is abuse/misuse, not a reference, and is dropped rather than
/// truncated (a truncated id is a WRONG id — silent corruption is worse than
/// absence). Generous cap so no legitimate reference is ever rejected.
pub const MAX_BUSINESS_REFERENCE_LEN: usize = 256;

/// Normalize + length-bound a customer-supplied business reference at a trust
/// boundary (OTLP ingest, gateway header). Trims surrounding whitespace, drops
/// empty, and drops anything over [`MAX_BUSINESS_REFERENCE_LEN`] scalar values.
/// Returns the value to store, or `None` to store nothing.
///
/// # Examples
/// ```
/// # use tracelane_shared::span::bounded_business_reference as b;
/// assert_eq!(b("  LOAN-2026-00042 "), Some("LOAN-2026-00042".to_string()));
/// assert_eq!(b("   "), None);
/// assert_eq!(b(&"x".repeat(257)), None); // over the cap → dropped, not truncated
/// ```
pub fn bounded_business_reference(raw: &str) -> Option<String> {
    bounded_identifier(raw, MAX_BUSINESS_REFERENCE_LEN)
}

/// Max stored length of a customer-supplied end-user id (`OBS-20`, unicode
/// scalar values).
///
/// Generous on purpose, and the generosity is the safety property: an
/// over-length id is DROPPED and the request still succeeds, so the cap must sit
/// far enough above any legitimate value that dropping never happens in
/// practice. Every upstream that has an opinion is stricter than this —
/// Anthropic caps `metadata.user_id` at 512, OpenAI's `safety_identifier` at 64
/// — so 256 accepts everything they do while still refusing a payload.
pub const MAX_END_USER_ID_LEN: usize = 256;

/// Normalize + length-bound a customer-supplied end-user id at a trust boundary
/// (gateway header, request body, OTLP ingest). Trims, drops empty, and DROPS
/// rather than truncates above [`MAX_END_USER_ID_LEN`].
///
/// Dropping is not laziness: a truncated id is a *wrong* id, and a wrong id
/// silently attributes one person's traces to another. Absence is recoverable;
/// misattribution is not.
///
/// # Examples
/// ```
/// # use tracelane_shared::span::bounded_end_user_id as b;
/// assert_eq!(b("  u_4471 "), Some("u_4471".to_string()));
/// assert_eq!(b(""), None);
/// assert_eq!(b(&"x".repeat(257)), None); // over the cap → dropped, not truncated
/// ```
pub fn bounded_end_user_id(raw: &str) -> Option<String> {
    bounded_identifier(raw, MAX_END_USER_ID_LEN)
}

/// Shared shape behind [`bounded_business_reference`] and [`bounded_end_user_id`]:
/// trim, drop empty, drop over `max` scalar values.
///
/// Deliberately private and deliberately counting `chars()` — a byte length
/// would reject a shorter non-ASCII id than an ASCII one, which is a bug that
/// only shows up for customers outside the Latin alphabet.
fn bounded_identifier(raw: &str, max: usize) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.chars().count() > max {
        None
    } else {
        Some(t.to_string())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Intervention {
    Allow,
    Warn,
    Block,
}

/// OTel GenAI operation type (gen_ai.operation.name values).
///
/// v1.41 adds the agentic operations `execute_tool`, `invoke_agent`, and
/// `invoke_workflow` (ADR-032). `execute_tool` spans must also carry the tool
/// name in the span name; `invoke_agent` is split into client + internal spans.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GenAiOperation {
    #[serde(rename = "chat")]
    Chat,
    #[serde(rename = "embeddings")]
    Embeddings,
    #[serde(rename = "completion")]
    Completion,
    #[serde(rename = "execute_tool")]
    ExecuteTool,
    #[serde(rename = "invoke_agent")]
    InvokeAgent,
    #[serde(rename = "invoke_workflow")]
    InvokeWorkflow,
}

impl GenAiOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Embeddings => "embeddings",
            Self::Completion => "completion",
            Self::ExecuteTool => "execute_tool",
            Self::InvokeAgent => "invoke_agent",
            Self::InvokeWorkflow => "invoke_workflow",
        }
    }
}

/// Reserved for V2: gen_ai.guardrail.decision event attributes.
/// No adapter writes these in V1. Schema accepts them for forwards-compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailDecision {
    pub decision: Intervention,
    pub reason: String,
    pub latency_ms: f32,
    pub confidence: f32,
    pub ruleset_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanStatus {
    pub code: SpanStatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpanStatusCode {
    Unset,
    Ok,
    Error,
}

impl Default for SpanStatus {
    fn default() -> Self {
        Self {
            code: SpanStatusCode::Unset,
            message: None,
        }
    }
}

#[cfg(test)]
mod gwy48_tests {
    use super::*;

    /// **THE DEPLOY QUESTION, ANSWERED BY A CONTROL RATHER THAN BY REASONING.**
    ///
    /// GWY-48 adds fields to `SpanAttributes`, which lives in `crates/shared` and is
    /// therefore compiled into BOTH the gateway (the producer) and ingest (the sole
    /// span writer). If the gateway ships first, ingest is running a binary whose
    /// `SpanAttributes` has no such fields — so the question that decides whether the
    /// feature works before ingest redeploys is: **does an older ingest DROP the new
    /// attributes, or carry them through?**
    ///
    /// It carries them, because `extra` is `#[serde(flatten)]`: an unknown key
    /// deserialises into the catch-all and re-serialises under the same name. This
    /// test stands in for the older binary with a struct that has ONLY the catch-all,
    /// so the property is proven rather than assumed.
    ///
    /// **What it does NOT cover, stated so nobody over-reads it:** the four new OTLP
    /// decode arms run INSIDE ingest (`crates/ingest/src/otlp_receiver.rs` →
    /// `otlp_decode`), so an SDK-emitted `gen_ai.request.temperature` is still dropped
    /// until ingest itself is redeployed. Gateway-path attributes survive; OTLP-path
    /// attributes do not.
    #[test]
    fn a_gateway_span_survives_an_ingest_that_predates_these_fields() {
        /// Stands in for the pre-GWY-48 `SpanAttributes`: no named fields, one
        /// flattened catch-all — the only part of the real struct that matters here.
        #[derive(Serialize, Deserialize)]
        struct OldAttributes {
            #[serde(flatten)]
            extra: std::collections::HashMap<String, Value>,
        }

        let mut attrs = SpanAttributes {
            gen_ai_request_temperature: Some(0.7),
            gen_ai_request_max_tokens: Some(512),
            tracelane_request_tool_count: Some(3),
            ..Default::default()
        };
        attrs.tracelane_request_tool_names = Some(vec!["a".into(), "b".into()]);

        let on_the_wire = serde_json::to_string(&attrs).expect("gateway serialises");
        let old: OldAttributes = serde_json::from_str(&on_the_wire).expect("old ingest parses");
        let rewritten = serde_json::to_string(&old).expect("old ingest re-serialises");

        for key in [
            "gen_ai_request_temperature",
            "gen_ai_request_max_tokens",
            "tracelane_request_tool_count",
            "tracelane_request_tool_names",
        ] {
            assert!(
                rewritten.contains(key),
                "`{key}` was DROPPED by a pre-GWY-48 ingest — that would make the \
                 feature depend on an ingest redeploy it does not otherwise need. \
                 Got: {rewritten}"
            );
        }
        // And the values survive, not just the keys.
        let back: SpanAttributes = serde_json::from_str(&rewritten).expect("reparses");
        assert_eq!(back.gen_ai_request_temperature, Some(0.7));
        assert_eq!(back.tracelane_request_tool_count, Some(3));
    }
}
