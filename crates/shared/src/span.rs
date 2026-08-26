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
    let t = raw.trim();
    if t.is_empty() || t.chars().count() > MAX_BUSINESS_REFERENCE_LEN {
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
