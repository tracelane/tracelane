//! `GuardrailContext` — the single source of truth a rail reads
//! (the guardrail spec §2.1). This is the fix for the launch-audit root
//! cause: the predictive layer only ever saw `tenant_id` + the raw chat body,
//! so 9 predictors gated on fields that were never injected. This context
//! carries every §2.1 signal — system prompt, typed messages, capability-tagged
//! tool defs, model-proposed tool calls, tool **results** (the indirect-
//! injection insertion point), RAG provenance, token estimate, session/taint
//! state, and (response-side) the streaming buffer + usage.
//!
//! Borrowed, not owned, wherever possible (§2.1): rails read slices of the
//! already-parsed `ChatRequest` rather than fresh copies. The few owned pieces
//! (`tool_defs`, `tool_calls`, `tool_results`, `rag_context`, `session`) are
//! thin per-request vectors of borrows / small state.
//!
//! Identity invariant (§0; P0.2): `tenant_id` is the resolved internal
//! `tenants.id` UUID (`TenantId(Uuid)` newtype, resolved in auth). A raw WorkOS
//! `org_id` is structurally unable to reach a store read — [`GuardrailContext::ch_tenant_key`]
//! is the only sanctioned ClickHouse key and debug-asserts a non-nil UUID.
//!
//! Population rules (§2.1): request-side rails see everything except
//! `response_buf`/`usage`; response-side rails additionally see the streaming
//! buffer. A field with no signal is `None`/empty — a rail that needs an absent
//! signal records `not_applicable`, never `fail_open`.

use std::time::Duration;

use tracelane_shared::{ChatRequest, ContentPart, Message, MessageContent, Role, TenantId, Usage};
use ulid::Ulid;

use crate::guardrail::capability::{CapabilityRegistry, RegistryPosture, ToolDef};

/// Default rolling window for session cost/loop signals (§2.2 `[IMPL-CHOICE]`).
pub const DEFAULT_SESSION_WINDOW: Duration = Duration::from_secs(60);

/// Minimum streaming lookback so entities/secret tokens straddling an SSE chunk
/// boundary are not missed (§2.6 `[IMPL-CHOICE]` ≥ 64 chars).
pub const MIN_LOOKBACK_CHARS: usize = 64;

/// Provenance of a retrieved / ingested chunk (§2.1 `rag_context`). Untrusted
/// is the **safe default** when unspecified (fail-closed for R4 taint): a
/// workspace marks its own trusted KB explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    Trusted,
    Untrusted,
}

impl Provenance {
    #[must_use]
    pub fn is_untrusted(self) -> bool {
        matches!(self, Provenance::Untrusted)
    }
}

/// A retrieval chunk + provenance (§2.1). Borrowed from the request body.
#[derive(Debug, Clone)]
pub struct RetrievedChunk<'r> {
    pub content: &'r str,
    pub provenance: Provenance,
    pub source: Option<&'r str>,
}

/// A model-proposed tool call (args), gathered across the request's messages
/// from both the OpenAI-style `message.tool_calls` and the Anthropic-style
/// `ContentPart::ToolUse` shapes (§2.1 `tool_calls`).
#[derive(Debug, Clone)]
pub struct ProposedToolCall<'r> {
    pub id: &'r str,
    pub name: &'r str,
    pub input: &'r serde_json::Value,
}

/// A tool result re-entering the model — the indirect-injection insertion
/// point (§2.1 `tool_results`; R4 taint ingress, R8 indirect injection).
#[derive(Debug, Clone)]
pub struct IncomingToolResult<'r> {
    pub tool_call_id: Option<&'r str>,
    pub content: &'r str,
}

/// Why a session became tainted, for the R4 ledger explanation (§2.4). Every
/// source is untrusted by construction (that is what taints), so the variants
/// name the *carrier*, not the trust level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSource {
    /// An untrusted tool result re-entered the model.
    ToolResult { tool_call_id: Option<String> },
    /// An untrusted RAG chunk was retrieved.
    RagChunk { source: Option<String> },
    /// A `SEES_UNTRUSTED_CONTENT` tool ran.
    ContentTool { tool: String },
}

/// R4 taint-engine state (§2.4). Carried into a request from the session and
/// advanced as untrusted content / private reads are observed.
#[derive(Debug, Clone, Default)]
pub struct TaintState {
    /// Untrusted content has entered the session.
    pub tainted: bool,
    /// For the ledger explanation (bounded).
    pub taint_sources: Vec<TaintSource>,
    /// A `READS_PRIVATE_DATA` tool has run this session.
    pub private_data_read: bool,
}

/// Cost / loop session signals (§2.2). `spend_cents_in_window` is `None` on a
/// cache miss — R1 fails **closed** on unknown spend under a hard budget cap
/// (`BUDGET_STATE_UNKNOWN`), rather than silently allowing.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_id: Option<String>,
    pub calls_in_window: u32,
    pub spend_cents_in_window: Option<u64>,
    pub window: Duration,
    pub taint: TaintState,
}

impl SessionState {
    /// A fresh, clean session with unknown spend (cache cold). Used request-side
    /// before the session cache is consulted, and in tests.
    #[must_use]
    pub fn fresh(session_id: Option<String>) -> Self {
        Self {
            session_id,
            calls_in_window: 0,
            spend_cents_in_window: None,
            window: DEFAULT_SESSION_WINDOW,
            taint: TaintState::default(),
        }
    }
}

/// Streaming-aware response accumulator (§2.6). Rails scan [`Self::accumulated`]
/// for full matches and [`Self::lookback_window`] for entities straddling SSE
/// chunk boundaries. The lookback is clamped to ≥ [`MIN_LOOKBACK_CHARS`].
#[derive(Debug, Clone)]
pub struct ResponseBuffer {
    full: String,
    lookback: usize,
}

impl ResponseBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::with_lookback(MIN_LOOKBACK_CHARS)
    }

    #[must_use]
    pub fn with_lookback(lookback: usize) -> Self {
        Self {
            full: String::new(),
            lookback: lookback.max(MIN_LOOKBACK_CHARS),
        }
    }

    /// Append a streamed chunk.
    pub fn push_chunk(&mut self, chunk: &str) {
        self.full.push_str(chunk);
    }

    /// The full accumulated response so far.
    #[must_use]
    pub fn accumulated(&self) -> &str {
        &self.full
    }

    /// The trailing window used to catch an entity/secret split across the
    /// previous and current chunk (last `lookback` chars, on a char boundary).
    #[must_use]
    pub fn lookback_window(&self) -> &str {
        let len = self.full.len();
        if len <= self.lookback {
            return &self.full;
        }
        // Walk back to a char boundary so we never slice mid-UTF-8.
        let mut start = len - self.lookback;
        while start > 0 && !self.full.is_char_boundary(start) {
            start -= 1;
        }
        &self.full[start..]
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.full.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
    }
}

impl Default for ResponseBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Owned response-side inputs. Unlike the request-side path (which borrows the
/// parsed `ChatRequest`), the response/streaming path produces a `'static`
/// stream that cannot borrow the request — so the response-relevant signals are
/// owned here and moved into the stream. Populated once before the response is
/// driven; [`GuardrailContext::from_response`] borrows from it per evaluation.
#[derive(Debug, Clone)]
pub struct ResponseInputs {
    pub tenant_id: TenantId,
    pub api_key_id: Option<String>,
    pub correlation_id: Ulid,
    /// The request's system prompt — R6 compares the response against it.
    pub system_prompt: Option<String>,
    pub model: String,
    pub session: SessionState,
    /// Audit actor (JWT `sub`) recorded with the response-side verdict.
    pub actor: String,
    /// The output format the request asked for (OpenAI `response_format`) — R5
    /// validates the response against it. `None` = no declared format → R5 is
    /// not applicable.
    pub expected_format: Option<ExpectedFormat>,
}

/// A declared response format (R5, §3 R5). Derived from the request's
/// `response_format`: `json` true means the response must be valid JSON;
/// `schema` carries an optional JSON Schema to validate against.
#[derive(Debug, Clone)]
pub struct ExpectedFormat {
    pub json: bool,
    pub schema: Option<serde_json::Value>,
}

/// Extract the declared output format from a request body's OpenAI-style
/// `response_format` (`{"type":"json_object"}` or `{"type":"json_schema",
/// "json_schema":{"schema":{…}}}`). `"text"` / absent / unknown → `None` (no
/// format constraint → R5 not applicable).
#[must_use]
pub fn extract_expected_format(body: &serde_json::Value) -> Option<ExpectedFormat> {
    let rf = body.get("response_format")?;
    match rf.get("type").and_then(serde_json::Value::as_str)? {
        "json_object" => Some(ExpectedFormat {
            json: true,
            schema: None,
        }),
        "json_schema" => Some(ExpectedFormat {
            json: true,
            schema: rf
                .get("json_schema")
                .and_then(|js| js.get("schema"))
                .cloned(),
        }),
        _ => None,
    }
}

/// The single context every rail reads (§2.1). Lifetime `'r` is the per-request
/// scope — the parsed `ChatRequest` and raw body outlive the context.
pub struct GuardrailContext<'r> {
    // ── identity (resolved, never org_id) ──────────────────────────────────
    /// Resolved internal `tenants.id` UUID. In V1 the spec's `workspace_id`
    /// collapses to the tenant (one workspace per tenant; entitlements key on
    /// the tenant UUID) — see [`Self::workspace_id`].
    pub tenant_id: &'r TenantId,
    /// One id per request; threads to the ledger verdict + spans (§2.1).
    pub correlation_id: Ulid,
    /// The API-key id / subject (ADR-042 `apikey:<uuid>` or WorkOS `sub`) —
    /// never the secret.
    pub api_key_id: Option<&'r str>,

    // ── request-side signals ───────────────────────────────────────────────
    pub system_prompt: Option<&'r str>,
    pub messages: &'r [Message],
    pub tool_defs: Vec<ToolDef<'r>>,
    pub tool_calls: Vec<ProposedToolCall<'r>>,
    pub tool_results: Vec<IncomingToolResult<'r>>,
    pub rag_context: Vec<RetrievedChunk<'r>>,
    /// The capability registry's posture for this request (permissive vs
    /// enforcing). Recorded in the R4 verdict; drives the safe-default for
    /// tools referenced but not declared in the request.
    pub registry_posture: RegistryPosture,
    pub est_input_tokens: u32,
    pub model: &'r str,
    pub provider: &'static str,

    // ── session / cumulative signals ───────────────────────────────────────
    pub session: SessionState,

    // ── response-side signals (populated post-dispatch / per chunk) ─────────
    pub response_buf: Option<&'r ResponseBuffer>,
    pub usage: Option<&'r Usage>,
    /// R5: the declared output format (response-side only; `None` request-side).
    pub expected_format: Option<&'r ExpectedFormat>,
}

impl<'r> GuardrailContext<'r> {
    /// Build the request-side context from a parsed `ChatRequest`, resolved
    /// identity, the workspace capability registry, any RAG chunks (extracted
    /// from the request body via [`extract_rag_context`]), and the session
    /// state read from the session cache. Response fields start `None`.
    #[must_use]
    pub fn from_request(
        tenant_id: &'r TenantId,
        api_key_id: Option<&'r str>,
        correlation_id: Ulid,
        request: &'r ChatRequest,
        registry: &CapabilityRegistry,
        rag_context: Vec<RetrievedChunk<'r>>,
        session: SessionState,
    ) -> Self {
        let tool_defs = request
            .tools
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|t| registry.tool_def(t))
            .collect();
        Self {
            tenant_id,
            correlation_id,
            api_key_id,
            system_prompt: extract_system_prompt(request),
            messages: &request.messages,
            tool_defs,
            tool_calls: collect_tool_calls(&request.messages),
            tool_results: collect_tool_results(&request.messages),
            rag_context,
            registry_posture: registry.posture(),
            est_input_tokens: estimate_input_tokens(request),
            model: &request.model,
            provider: crate::providers::ProviderRegistry::provider_id_for_model(&request.model),
            session,
            response_buf: None,
            usage: None,
            expected_format: None,
        }
    }

    /// Attach response-side signals for the response/streaming pass (§2.6).
    #[must_use]
    pub fn with_response(mut self, buf: &'r ResponseBuffer, usage: Option<&'r Usage>) -> Self {
        self.response_buf = Some(buf);
        self.usage = usage;
        self
    }

    /// Build a response-side context from owned [`ResponseInputs`] + the
    /// accumulated response buffer. Request-side collections are empty —
    /// response rails read `response_buf` / `usage` / `system_prompt` and a few
    /// identity/model signals, not the request body. Used by the response /
    /// streaming path, where a `'static` stream cannot borrow the request.
    #[must_use]
    pub fn from_response(
        inputs: &'r ResponseInputs,
        response_buf: &'r ResponseBuffer,
        usage: Option<&'r Usage>,
    ) -> Self {
        Self {
            tenant_id: &inputs.tenant_id,
            correlation_id: inputs.correlation_id,
            api_key_id: inputs.api_key_id.as_deref(),
            system_prompt: inputs.system_prompt.as_deref(),
            messages: &[],
            tool_defs: Vec::new(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            rag_context: Vec::new(),
            // No tools evaluated response-side (R4 is request-side).
            registry_posture: RegistryPosture::Permissive,
            est_input_tokens: 0,
            model: &inputs.model,
            provider: crate::providers::ProviderRegistry::provider_id_for_model(&inputs.model),
            session: inputs.session.clone(),
            response_buf: Some(response_buf),
            usage,
            expected_format: inputs.expected_format.as_ref(),
        }
    }

    /// The workspace scope for entitlement checks. V1: equals the tenant
    /// (single workspace per tenant; `workspace_entitlements` keys on the
    /// tenant UUID). Kept as a method so a future multi-workspace split is a
    /// one-line change, not a context-shape migration.
    #[must_use]
    pub fn workspace_id(&self) -> &TenantId {
        self.tenant_id
    }

    /// The ONLY sanctioned ClickHouse partition key for this request — the
    /// resolved internal tenant UUID, hyphenated. A raw WorkOS `org_id` cannot
    /// reach here (`tenant_id` is a `TenantId(Uuid)` newtype resolved in auth;
    /// §0, P0.2). Debug builds assert a non-nil UUID as a runtime backstop to
    /// the `check-tenant-id-provenance.sh` CI grep.
    #[must_use]
    pub fn ch_tenant_key(&self) -> String {
        let uuid = self.tenant_id.as_uuid();
        debug_assert!(
            !uuid.is_nil(),
            "guardrail ClickHouse key must be a resolved non-nil tenant UUID, never an org_id"
        );
        uuid.to_string()
    }

    /// Is this session tainted by untrusted content (R4 convenience)?
    #[must_use]
    pub fn is_tainted(&self) -> bool {
        self.session.taint.tainted
    }
}

/// Extract the system prompt (§2.1): prefer the top-level `system` field
/// (Anthropic style), else the first `System`-role message's text (OpenAI
/// style). `None` if neither is present.
#[must_use]
pub fn extract_system_prompt(request: &ChatRequest) -> Option<&str> {
    if let Some(s) = request.system.as_deref() {
        return Some(s);
    }
    request
        .messages
        .iter()
        .find(|m| m.role == Role::System)
        .and_then(|m| match &m.content {
            MessageContent::Text(s) => Some(s.as_str()),
            MessageContent::Parts(parts) => parts.iter().find_map(|p| match p {
                ContentPart::Text { text, .. } => Some(text.as_str()),
                _ => None,
            }),
        })
}

/// Gather model-proposed tool calls from both message shapes (§2.1).
#[must_use]
pub fn collect_tool_calls(messages: &[Message]) -> Vec<ProposedToolCall<'_>> {
    let mut out = Vec::new();
    for m in messages {
        if let Some(tcs) = &m.tool_calls {
            for tc in tcs {
                out.push(ProposedToolCall {
                    id: &tc.id,
                    name: &tc.name,
                    input: &tc.input,
                });
            }
        }
        if let MessageContent::Parts(parts) = &m.content {
            for p in parts {
                if let ContentPart::ToolUse { id, name, input } = p {
                    out.push(ProposedToolCall { id, name, input });
                }
            }
        }
    }
    out
}

/// Gather tool results re-entering the model from both shapes — `Role::Tool`
/// messages and `ContentPart::ToolResult` blocks (§2.1).
#[must_use]
pub fn collect_tool_results(messages: &[Message]) -> Vec<IncomingToolResult<'_>> {
    let mut out = Vec::new();
    for m in messages {
        if m.role == Role::Tool {
            if let MessageContent::Text(s) = &m.content {
                out.push(IncomingToolResult {
                    tool_call_id: m.tool_call_id.as_deref(),
                    content: s,
                });
            }
        }
        if let MessageContent::Parts(parts) = &m.content {
            for p in parts {
                if let ContentPart::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } = p
                {
                    out.push(IncomingToolResult {
                        tool_call_id: Some(tool_use_id),
                        content,
                    });
                }
            }
        }
    }
    out
}

/// Pre-dispatch input-token estimate (§2.1 `est_input_tokens`). Heuristic:
/// ~4 chars/token over the system prompt, all message text/tool-result content,
/// proposed tool-call payloads, and tool definitions. Cheap and allocation-light
/// — R1 uses it for the input-token cap; it is an estimate, not the billed count.
#[must_use]
pub fn estimate_input_tokens(request: &ChatRequest) -> u32 {
    let mut chars = request.system.as_deref().map_or(0, str::len);
    for m in &request.messages {
        chars += content_char_len(&m.content);
        if let Some(tcs) = &m.tool_calls {
            for tc in tcs {
                chars += tc.name.len() + tc.input.to_string().len();
            }
        }
    }
    if let Some(tools) = &request.tools {
        for t in tools {
            chars += t.name.len()
                + t.description.as_deref().map_or(0, str::len)
                + t.input_schema.to_string().len();
        }
    }
    u32::try_from(chars / 4).unwrap_or(u32::MAX)
}

fn content_char_len(content: &MessageContent) -> usize {
    match content {
        MessageContent::Text(s) => s.len(),
        MessageContent::Parts(parts) => parts
            .iter()
            .map(|p| match p {
                ContentPart::Text { text, .. } => text.len(),
                ContentPart::ToolResult { content, .. } => content.len(),
                ContentPart::ToolUse { name, input, .. } => name.len() + input.to_string().len(),
                ContentPart::ImageUrl { .. } => 0,
            })
            .sum(),
    }
}

/// Extract RAG provenance chunks from a Tracelane request extension
/// (`tracelane_rag_context: [{content, provenance, source}]`) on the raw body.
/// The universal `ChatRequest` carries no native RAG field, so SDKs pass
/// retrieval provenance through this namespaced extension. Unspecified
/// provenance defaults to **untrusted** (fail-closed for R4 taint).
#[must_use]
pub fn extract_rag_context(body: &serde_json::Value) -> Vec<RetrievedChunk<'_>> {
    let Some(arr) = body.get("tracelane_rag_context").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|c| {
            let content = c.get("content")?.as_str()?;
            let provenance = match c.get("provenance").and_then(serde_json::Value::as_str) {
                Some("trusted") => Provenance::Trusted,
                // Anything else (incl. absent / "untrusted" / typo) → untrusted.
                _ => Provenance::Untrusted,
            };
            let source = c.get("source").and_then(serde_json::Value::as_str);
            Some(RetrievedChunk {
                content,
                provenance,
                source,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tracelane_shared::{Tool, ToolCall};
    use uuid::Uuid;

    fn fixed_ulid() -> Ulid {
        Ulid::from_parts(1_718_000_000_000, 42)
    }

    /// A representative agent-loop request: system prompt, a user turn, an
    /// assistant tool_use, and a tool result re-entering the model, plus a
    /// declared tool. Exercises every §2.1 request-side signal.
    fn representative_request() -> ChatRequest {
        ChatRequest {
            model: "claude-sonnet-4-6".to_string(),
            system: Some("You are a careful assistant.".to_string()),
            messages: vec![
                Message {
                    role: Role::User,
                    content: MessageContent::Text("Fetch https://example.com".to_string()),
                    tool_call_id: None,
                    tool_calls: None,
                },
                Message {
                    role: Role::Assistant,
                    content: MessageContent::Parts(vec![ContentPart::ToolUse {
                        id: "call_1".to_string(),
                        name: "web_fetch".to_string(),
                        input: json!({ "url": "https://example.com" }),
                    }]),
                    tool_call_id: None,
                    tool_calls: None,
                },
                Message {
                    role: Role::Tool,
                    content: MessageContent::Text("<html>hello</html>".to_string()),
                    tool_call_id: Some("call_1".to_string()),
                    tool_calls: None,
                },
            ],
            tools: Some(vec![Tool {
                name: "web_fetch".to_string(),
                description: Some("Fetch a URL".to_string()),
                input_schema: json!({ "type": "object" }),
            }]),
            max_tokens: Some(1024),
            temperature: None,
            stream: None,
            metadata: None,
        }
    }

    /// P0.1 done-test: a context built from a representative request has every
    /// §2.1 field populated, or correctly absent.
    #[test]
    fn from_request_populates_every_field() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(0xABCD));
        let req = representative_request();
        let mut reg = CapabilityRegistry::new();
        reg.register(
            "web_fetch",
            crate::guardrail::CapabilitySet::SEES_UNTRUSTED_CONTENT,
        );
        let body = json!({
            "tracelane_rag_context": [
                { "content": "external doc", "provenance": "untrusted", "source": "kb://x" }
            ]
        });
        let rag = extract_rag_context(&body);

        let ctx = GuardrailContext::from_request(
            &tenant,
            Some("apikey:abc"),
            fixed_ulid(),
            &req,
            &reg,
            rag,
            SessionState::fresh(Some("sess-1".to_string())),
        );

        // identity
        assert_eq!(ctx.tenant_id.as_uuid(), &Uuid::from_u128(0xABCD));
        assert_eq!(ctx.correlation_id, fixed_ulid());
        assert_eq!(ctx.api_key_id, Some("apikey:abc"));
        // request-side
        assert_eq!(ctx.system_prompt, Some("You are a careful assistant."));
        assert_eq!(ctx.messages.len(), 3);
        assert_eq!(ctx.tool_defs.len(), 1);
        assert_eq!(ctx.tool_defs[0].name, "web_fetch");
        assert_eq!(
            ctx.tool_defs[0].capability,
            crate::guardrail::capability::ToolCapability::Known(
                crate::guardrail::CapabilitySet::SEES_UNTRUSTED_CONTENT
            )
        );
        assert_eq!(ctx.tool_calls.len(), 1);
        assert_eq!(ctx.tool_calls[0].name, "web_fetch");
        assert_eq!(ctx.tool_results.len(), 1);
        assert_eq!(ctx.tool_results[0].content, "<html>hello</html>");
        assert_eq!(ctx.tool_results[0].tool_call_id, Some("call_1"));
        assert_eq!(ctx.rag_context.len(), 1);
        assert!(ctx.rag_context[0].provenance.is_untrusted());
        assert_eq!(ctx.rag_context[0].source, Some("kb://x"));
        assert!(ctx.est_input_tokens > 0);
        assert_eq!(ctx.model, "claude-sonnet-4-6");
        assert_eq!(ctx.provider, "anthropic");
        // session
        assert_eq!(ctx.session.session_id.as_deref(), Some("sess-1"));
        assert!(
            ctx.session.spend_cents_in_window.is_none(),
            "cold cache → unknown"
        );
        assert!(!ctx.is_tainted());
        // response-side correctly absent request-side
        assert!(ctx.response_buf.is_none());
        assert!(ctx.usage.is_none());
    }

    #[test]
    fn with_response_attaches_streaming_signals() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(1));
        let req = representative_request();
        let reg = CapabilityRegistry::new();
        let mut buf = ResponseBuffer::new();
        buf.push_chunk("partial output");
        let usage = Usage {
            input_tokens: 10,
            output_tokens: 5,
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        };
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            fixed_ulid(),
            &req,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        )
        .with_response(&buf, Some(&usage));
        assert_eq!(ctx.response_buf.unwrap().accumulated(), "partial output");
        assert_eq!(ctx.usage.unwrap().output_tokens, 5);
    }

    #[test]
    fn from_response_builds_response_context() {
        let inputs = ResponseInputs {
            tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(0x5)),
            api_key_id: Some("apikey:r".to_string()),
            correlation_id: fixed_ulid(),
            system_prompt: Some("You are helpful.".to_string()),
            model: "claude-sonnet-4-6".to_string(),
            session: SessionState::fresh(Some("s".to_string())),
            actor: "apikey:r".to_string(),
            expected_format: None,
        };
        let mut buf = ResponseBuffer::new();
        buf.push_chunk("the model said this");
        let usage = Usage {
            input_tokens: 3,
            output_tokens: 9,
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        };
        let ctx = GuardrailContext::from_response(&inputs, &buf, Some(&usage));
        assert_eq!(ctx.tenant_id.as_uuid(), &Uuid::from_u128(0x5));
        assert_eq!(ctx.system_prompt, Some("You are helpful."));
        assert_eq!(ctx.model, "claude-sonnet-4-6");
        assert_eq!(ctx.provider, "anthropic");
        assert_eq!(
            ctx.response_buf.unwrap().accumulated(),
            "the model said this"
        );
        assert_eq!(ctx.usage.unwrap().output_tokens, 9);
        // Request-side collections are empty on a response context.
        assert!(ctx.messages.is_empty());
        assert!(ctx.tool_defs.is_empty());
    }

    /// P0.2: the ClickHouse key is the resolved hyphenated UUID, never an
    /// org_id; the workspace scope collapses to the tenant in V1.
    #[test]
    fn ch_tenant_key_is_resolved_uuid() {
        let uuid = Uuid::from_u128(0x1234_5678);
        let tenant = TenantId::from_jwt_claim(uuid);
        let req = representative_request();
        let reg = CapabilityRegistry::new();
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            fixed_ulid(),
            &req,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        assert_eq!(ctx.ch_tenant_key(), uuid.to_string());
        assert_eq!(
            ctx.ch_tenant_key().len(),
            36,
            "hyphenated UUID, not an org_id"
        );
        assert_eq!(ctx.workspace_id(), &tenant);
    }

    #[test]
    fn system_prompt_prefers_top_level_then_system_message() {
        // Top-level wins.
        let mut req = representative_request();
        assert_eq!(
            extract_system_prompt(&req),
            Some("You are a careful assistant.")
        );
        // Falls back to a System-role message when no top-level system.
        req.system = None;
        req.messages.insert(
            0,
            Message {
                role: Role::System,
                content: MessageContent::Text("fallback system".to_string()),
                tool_call_id: None,
                tool_calls: None,
            },
        );
        assert_eq!(extract_system_prompt(&req), Some("fallback system"));
    }

    #[test]
    fn tool_calls_collected_from_both_shapes() {
        let messages = vec![
            Message {
                role: Role::Assistant,
                content: MessageContent::Text("thinking".to_string()),
                tool_call_id: None,
                tool_calls: Some(vec![ToolCall {
                    id: "openai_1".to_string(),
                    name: "search".to_string(),
                    input: json!({ "q": "x" }),
                }]),
            },
            Message {
                role: Role::Assistant,
                content: MessageContent::Parts(vec![ContentPart::ToolUse {
                    id: "anthropic_1".to_string(),
                    name: "fetch".to_string(),
                    input: json!({ "url": "y" }),
                }]),
                tool_call_id: None,
                tool_calls: None,
            },
        ];
        let calls = collect_tool_calls(&messages);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "search");
        assert_eq!(calls[1].name, "fetch");
    }

    #[test]
    fn tool_results_collected_from_both_shapes() {
        let messages = vec![
            Message {
                role: Role::Tool,
                content: MessageContent::Text("role-tool result".to_string()),
                tool_call_id: Some("t1".to_string()),
                tool_calls: None,
            },
            Message {
                role: Role::User,
                content: MessageContent::Parts(vec![ContentPart::ToolResult {
                    tool_use_id: "t2".to_string(),
                    content: "block result".to_string(),
                    cache_control: None,
                }]),
                tool_call_id: None,
                tool_calls: None,
            },
        ];
        let results = collect_tool_results(&messages);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].content, "role-tool result");
        assert_eq!(results[0].tool_call_id, Some("t1"));
        assert_eq!(results[1].content, "block result");
        assert_eq!(results[1].tool_call_id, Some("t2"));
    }

    #[test]
    fn rag_context_defaults_unspecified_provenance_to_untrusted() {
        let body = json!({
            "tracelane_rag_context": [
                { "content": "a", "provenance": "trusted" },
                { "content": "b" },                       // unspecified → untrusted
                { "content": "c", "provenance": "garbage" }, // invalid → untrusted
                { "not_content": "skip" }                  // no content → dropped
            ]
        });
        let chunks = extract_rag_context(&body);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].provenance, Provenance::Trusted);
        assert_eq!(chunks[1].provenance, Provenance::Untrusted);
        assert_eq!(chunks[2].provenance, Provenance::Untrusted);
    }

    #[test]
    fn rag_context_absent_is_empty_not_error() {
        assert!(extract_rag_context(&json!({ "messages": [] })).is_empty());
    }

    #[test]
    fn estimate_input_tokens_is_nonzero_and_grows() {
        let small = ChatRequest {
            model: "m".to_string(),
            system: None,
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hi".to_string()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
        };
        let big = representative_request();
        assert!(estimate_input_tokens(&big) > estimate_input_tokens(&small));
    }

    #[test]
    fn response_buffer_lookback_catches_straddle() {
        let mut buf = ResponseBuffer::with_lookback(8); // clamps up to MIN_LOOKBACK_CHARS
        buf.push_chunk(&"x".repeat(200));
        buf.push_chunk("SECRET");
        // The lookback window must include the trailing "SECRET" even though it
        // arrived in a later chunk than the long run.
        assert!(buf.lookback_window().ends_with("SECRET"));
        assert!(buf.lookback_window().len() >= MIN_LOOKBACK_CHARS);
        assert_eq!(buf.accumulated().len(), 206);
    }

    #[test]
    fn response_buffer_lookback_respects_char_boundary() {
        let mut buf = ResponseBuffer::with_lookback(MIN_LOOKBACK_CHARS);
        // Multi-byte chars; slicing must not panic on a UTF-8 boundary.
        buf.push_chunk(&"é".repeat(100));
        let w = buf.lookback_window();
        assert!(w.chars().all(|c| c == 'é'));
    }
}
