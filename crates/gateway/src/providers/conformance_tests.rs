//! `OG-90` — the adapter no-silent-drop conformance matrix (RCA control C1).
//! Spec: `specs/OG-90-adapter-no-silent-drop-conformance.md`. RCA:
//! `runbooks/RCA-one-gateway-bug-cluster-2026-10-01.md` root causes 1-3.
//!
//! **The property.** For every native adapter × every `ChatRequest` field × every `ContentPart`
//! variant, the caller's value EITHER appears in the body (or URL) the REAL adapter sends to the
//! provider, OR the request is refused with a 400 that names it, BEFORE any dispatch. A request
//! that is neither sent nor refused — a 200 answering a different question — is the defect class
//! D1 / D2 / OG-03 / D8, and it fails here.
//!
//! **How it is checked.** Each cell builds a request carrying a distinctive value for ONE field,
//! then
//!   * `Sent(pointer)` — the gate (`validate_shape` then `check_supported`, the two checks the
//!     chat handler runs) passes, the request is dispatched through the real adapter to a
//!     `wiremock` server, and the captured body has the value at the JSON pointer;
//!   * `Url(fragment)` — the same, for a value that rides in the request path or query
//!     (the model on Gemini and Bedrock);
//!   * `Omits(pointer)` — the value is honoured BY OMISSION (Anthropic and Converse have no
//!     `tool_choice: none`; the documented way to say it is to send no tools): the pointer is
//!     absent from the captured body;
//!   * `Refused(code, param)` — the gate returns that code with `param` naming the field or part,
//!     and nothing is dispatched (the harness never dispatches a refused cell);
//!   * `Consumed(reason)` — the gateway consumes it itself and no adapter reads it; backed by a
//!     source scan, so the day an adapter starts reading it the cell has to be re-decided.
//!
//! **Why the matrix cannot go stale.** `expected` matches every `Cell` and, inside it, every
//! `Adapter` WITHOUT a wildcard arm, so a new cell or adapter is a compile error until each
//! combination is decided. `part_cell` matches `ContentPart` exhaustively, so a new variant does
//! not compile. `every_chat_request_key_is_in_the_matrix` serialises a FULLY-populated
//! `ChatRequest` (struct literal, no `..Default`, so a new field does not compile until it is
//! populated here) and compares its keys with the matrix.
//!
//! **Out of scope** (spec §6): real providers (the live matrix is `OG-05` §3.5), and the
//! `/v1/responses` and Gemini-native wires, whose own suites cover them.

#![cfg(test)]

use std::collections::BTreeSet;

use futures::StreamExt as _;
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::providers::vertex::HostOverrideGuard;
use crate::providers::{
    AnthropicProvider, AzureOpenAiProvider, BedrockProvider, CohereProvider, GoogleProvider,
    OpenAiProvider, ProviderEvent, VertexProvider,
};
use crate::request_support::{self, Unsupported};
use tracelane_shared::{
    ChatRequest, ContentPart, FilePart, ImageUrl, InputAudio, Message, MessageContent,
    RequestMetadata, Role, Stop, TenantId, Tool, ToolCall, ToolChoice,
};

// ── the matrix vocabulary ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Adapter {
    /// An OpenAI-wire catalog provider (`openai` here; every catalog row shares the adapter).
    Compat,
    Azure,
    Anthropic,
    Google,
    Vertex,
    Bedrock,
    Cohere,
}

const ADAPTERS: [Adapter; 7] = [
    Adapter::Compat,
    Adapter::Azure,
    Adapter::Anthropic,
    Adapter::Google,
    Adapter::Vertex,
    Adapter::Bedrock,
    Adapter::Cohere,
];

impl Adapter {
    /// The provider id the chat handler passes to `check_supported`.
    fn provider_id(self) -> &'static str {
        match self {
            Self::Compat => "openai",
            Self::Azure => "azure",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
            Self::Vertex => "vertex",
            Self::Bedrock => "bedrock",
            Self::Cohere => "cohere",
        }
    }

    /// A model the adapter accepts and the reference tables know (`reasoning_effort`).
    fn model(self) -> &'static str {
        match self {
            Self::Compat => "gpt-4o",
            Self::Azure => "azure/gpt-4o",
            Self::Anthropic => "claude-sonnet-4-5",
            Self::Google => "gemini-2.5-flash",
            Self::Vertex => "vertex/gemini-2.5-flash",
            Self::Bedrock => "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0",
            Self::Cohere => "command-r-plus",
        }
    }

    fn bare_model(self) -> &'static str {
        let m = self.model();
        m.split_once('/').map_or(m, |(_, rest)| rest)
    }
}

/// What the matrix expects of one (adapter, cell).
#[derive(Clone, Copy, Debug)]
enum Out {
    Sent(&'static str),
    Url(&'static str),
    Omits(&'static str),
    Refused(&'static str, &'static str),
    Consumed(&'static str),
}

use Out::{Consumed, Omits, Refused, Sent, Url};

const PARAM: &str = "unsupported_parameter";
const CONTENT: &str = "unsupported_content";

/// One ChatRequest field, or one content-part / structure shape. Declared through a macro so the
/// enum and `CELLS` (the list the matrix runs) cannot drift apart: a variant added here runs.
macro_rules! cells {
    ($($(#[$m:meta])* $v:ident),* $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        enum Cell { $($(#[$m])* $v),* }
        const CELLS: &[Cell] = &[$(Cell::$v),*];
    };
}

cells! {
    // ── fields: one per `ChatRequest` key ──
    Model, Messages, System, Tools, ToolChoice, MaxTokens, Temperature, TopP, Seed, Logprobs,
    TopLogprobs, Stream, Metadata, Stop, ResponseFormat, ReasoningEffort, MaxCompletionTokens,
    PresencePenalty, FrequencyPenalty, ParallelToolCalls, User, ServiceTier, N, Extra,
    // ── fields, other values / shapes of the same keys ──
    ToolChoiceNone, ToolChoiceFunction, SystemMessage, TwoSystems,
    // ── one per `ContentPart` variant (+ shapes) ──
    PartText, PartImage, PartImageHttps, PartAudio, PartFile, PartToolUse, PartToolResult,
    ToolHistory,
}

impl Cell {
    /// The top-level `ChatRequest` JSON key this cell is the primary cell for, if any.
    fn json_key(self) -> Option<&'static str> {
        Some(match self {
            Self::Model => "model",
            Self::Messages => "messages",
            Self::System => "system",
            Self::Tools => "tools",
            Self::ToolChoice => "tool_choice",
            Self::MaxTokens => "max_tokens",
            Self::Temperature => "temperature",
            Self::TopP => "top_p",
            Self::Seed => "seed",
            Self::Logprobs => "logprobs",
            Self::TopLogprobs => "top_logprobs",
            Self::Stream => "stream",
            Self::Metadata => "metadata",
            Self::Stop => "stop",
            Self::ResponseFormat => "response_format",
            Self::ReasoningEffort => "reasoning_effort",
            Self::MaxCompletionTokens => "max_completion_tokens",
            Self::PresencePenalty => "presence_penalty",
            Self::FrequencyPenalty => "frequency_penalty",
            Self::ParallelToolCalls => "parallel_tool_calls",
            Self::User => "user",
            Self::ServiceTier => "service_tier",
            Self::N => "n",
            // The flattened map's keys are the caller's own; the probe's key stands in for it.
            Self::Extra => "x_unmodelled",
            Self::ToolChoiceNone
            | Self::ToolChoiceFunction
            | Self::SystemMessage
            | Self::TwoSystems
            | Self::PartText
            | Self::PartImage
            | Self::PartImageHttps
            | Self::PartAudio
            | Self::PartFile
            | Self::PartToolUse
            | Self::PartToolResult
            | Self::ToolHistory => return None,
        })
    }

    /// Every string the captured value must contain. Numbers are matched as their JSON text at a
    /// LEAF pointer, so `7` cannot be satisfied by a stray `7` elsewhere in the body.
    fn needles(self, a: Adapter) -> Vec<String> {
        let s = |x: &str| vec![x.to_owned()];
        match self {
            Self::Model => s(a.bare_model()),
            Self::Messages => s("OG90-USER-TEXT"),
            Self::System => s("OG90-SYSTEM"),
            Self::Tools | Self::ToolChoiceFunction => s("get_weather"),
            Self::ToolChoice => match a {
                Adapter::Anthropic => s("any"),
                Adapter::Google | Adapter::Vertex => s("ANY"),
                Adapter::Bedrock => s("any"),
                Adapter::Compat | Adapter::Azure | Adapter::Cohere => s("required"),
            },
            Self::ToolChoiceNone => match a {
                Adapter::Google | Adapter::Vertex => s("NONE"),
                _ => s("none"),
            },
            Self::MaxTokens => s("777"),
            Self::MaxCompletionTokens => s("555"),
            Self::Temperature => s("0.5"),
            Self::TopP => s("0.25"),
            Self::Seed => s("424242"),
            Self::Logprobs => s("true"),
            Self::TopLogprobs => s("7"),
            Self::Stream => match a {
                Adapter::Google | Adapter::Vertex => s(":streamGenerateContent"),
                Adapter::Bedrock => s("/converse"),
                _ => s("true"),
            },
            Self::Metadata => s("OG90-META"),
            Self::Stop => vec!["OG90-STOP-A".into(), "OG90-STOP-B".into()],
            Self::ResponseFormat => s("og90_field"),
            Self::ReasoningEffort => match a {
                // The table budget for `high` (16384) clamped below `max_tokens` (8192).
                Adapter::Anthropic => s("8191"),
                Adapter::Google | Adapter::Vertex => s("thinkingBudget"),
                _ => s("high"),
            },
            Self::PresencePenalty => s("0.375"),
            Self::FrequencyPenalty => s("0.625"),
            Self::ParallelToolCalls => match a {
                Adapter::Anthropic => s("true"), // disable_parallel_tool_use: true
                _ => s("false"),
            },
            Self::User => s("OG90-USER-ID"),
            Self::ServiceTier => s("flex"),
            Self::N => s("2"),
            Self::Extra => s("OG90-EXTRA"),
            Self::SystemMessage => s("OG90-SYSMSG"),
            Self::TwoSystems => vec!["OG90-SYSTEM".into(), "OG90-SYSMSG".into()],
            Self::PartText => s("OG90-PART-TEXT"),
            Self::PartImage => s(PNG_B64_PREFIX),
            Self::PartImageHttps => s("og90.invalid/cat.png"),
            Self::PartAudio => s(AUDIO_B64),
            Self::PartFile => s(PDF_B64_PREFIX),
            Self::PartToolUse => s("get_weather"),
            Self::PartToolResult => s("OG90-RESULT"),
            Self::ToolHistory => {
                let mut v = vec!["get_weather".into(), "Paris".into(), "OG90-RESULT".into()];
                // Gemini keys a function response by NAME; every other wire carries the call id.
                if !matches!(a, Adapter::Google | Adapter::Vertex) {
                    v.push("call_1".into());
                }
                v
            }
        }
    }
}

/// THE MATRIX. No wildcard arms, on either axis: a new cell or a new adapter does not compile
/// until every combination is decided. (`Refused` rows name the code and the `param` the 400
/// carries; `Sent` rows the JSON pointer into the body the adapter put on the wire.)
#[allow(clippy::too_many_lines)] // a table, not logic
fn expected(a: Adapter, c: Cell) -> Out {
    use Adapter::{Anthropic, Azure, Bedrock, Cohere, Compat, Google, Vertex};
    let img = "messages[0].content[0]";
    match c {
        Cell::Model => match a {
            // Azure keeps the model in the URL (`/deployments/{name}`); its body carries none.
            Compat | Anthropic | Cohere => Sent("/model"),
            Google | Vertex | Bedrock | Azure => Url(a.bare_model()),
        },
        Cell::Messages => match a {
            Compat | Azure | Anthropic => Sent("/messages/0/content"),
            Google | Vertex => Sent("/contents/0/parts/0/text"),
            Bedrock => Sent("/messages/0/content/0/text"),
            // D9: Cohere v2 `messages[]` (the v1 `message` + `chat_history` split is gone).
            Cohere => Sent("/messages/0/content"),
        },
        Cell::System => match a {
            // The adapter must put `ChatRequest.system` on the wire as a system turn.
            Compat | Azure => Sent("/messages/0/content"),
            Anthropic => Sent("/system"),
            Google | Vertex => Sent("/system_instruction/parts/0/text"),
            Bedrock => Sent("/system/0/text"),
            Cohere => Sent("/messages/0/content"),
        },
        Cell::SystemMessage => match a {
            Compat | Azure => Sent("/messages/0/content"),
            Anthropic => Sent("/system"),
            Google | Vertex => Sent("/system_instruction/parts/0/text"),
            Bedrock => Sent("/system/0/text"),
            Cohere => Sent("/messages/0/content"),
        },
        // `system` AND a `system` message: BOTH must survive (Anthropic merges them, so must the rest).
        Cell::TwoSystems => match a {
            Compat | Azure => Sent("/messages"),
            Anthropic => Sent("/system"),
            Google | Vertex => Sent("/system_instruction"),
            Bedrock => Sent("/system"),
            // v2: `system` leads at 0, the system MESSAGE follows at 1 — both survive in `messages`.
            Cohere => Sent("/messages"),
        },
        Cell::Tools => match a {
            Compat | Azure | Cohere => Sent("/tools/0/function/name"),
            Anthropic => Sent("/tools/0/name"),
            Google | Vertex => Sent("/tools/0/function_declarations/0/name"),
            Bedrock => Sent("/toolConfig/tools/0/toolSpec/name"),
        },
        Cell::ToolChoice => match a {
            Compat | Azure => Sent("/tool_choice"),
            Anthropic => Sent("/tool_choice/type"),
            Google | Vertex => Sent("/toolConfig/functionCallingConfig/mode"),
            Bedrock => Sent("/toolConfig/toolChoice"),
            Cohere => Refused(PARAM, "tool_choice"),
        },
        Cell::ToolChoiceNone => match a {
            Compat | Azure => Sent("/tool_choice"),
            Anthropic => Omits("/tools"),
            Google | Vertex => Sent("/toolConfig/functionCallingConfig/mode"),
            Bedrock => Omits("/toolConfig"),
            Cohere => Refused(PARAM, "tool_choice"),
        },
        Cell::ToolChoiceFunction => match a {
            Compat | Azure => Sent("/tool_choice/function/name"),
            Anthropic => Sent("/tool_choice/name"),
            Google | Vertex => Sent("/toolConfig/functionCallingConfig/allowedFunctionNames"),
            Bedrock => Sent("/toolConfig/toolChoice/tool/name"),
            Cohere => Refused(PARAM, "tool_choice"),
        },
        // `openai` sends the cap as `max_completion_tokens` whatever name the caller used.
        Cell::MaxTokens => match a {
            Compat => Sent("/max_completion_tokens"),
            Azure | Anthropic | Cohere => Sent("/max_tokens"),
            Google | Vertex => Sent("/generationConfig/maxOutputTokens"),
            Bedrock => Sent("/inferenceConfig/maxTokens"),
        },
        Cell::MaxCompletionTokens => match a {
            Compat | Azure => Sent("/max_completion_tokens"),
            Anthropic | Cohere => Sent("/max_tokens"),
            Google | Vertex => Sent("/generationConfig/maxOutputTokens"),
            Bedrock => Sent("/inferenceConfig/maxTokens"),
        },
        Cell::Temperature => match a {
            Compat | Azure | Anthropic | Cohere => Sent("/temperature"),
            Google | Vertex => Sent("/generationConfig/temperature"),
            Bedrock => Sent("/inferenceConfig/temperature"),
        },
        Cell::TopP => match a {
            Compat | Azure | Anthropic => Sent("/top_p"),
            Cohere => Sent("/p"),
            Google | Vertex => Sent("/generationConfig/topP"),
            Bedrock => Sent("/inferenceConfig/topP"),
        },
        Cell::Seed => match a {
            Compat | Azure => Sent("/seed"),
            Google | Vertex => Sent("/generationConfig/seed"),
            Anthropic | Bedrock | Cohere => Refused(PARAM, "seed"),
        },
        Cell::Logprobs => match a {
            Compat | Azure => Sent("/logprobs"),
            Anthropic | Google | Vertex | Bedrock | Cohere => Refused(PARAM, "logprobs"),
        },
        Cell::TopLogprobs => match a {
            Compat | Azure => Sent("/top_logprobs"),
            Anthropic | Google | Vertex | Bedrock | Cohere => Refused(PARAM, "top_logprobs"),
        },
        // Transport: Anthropic always streams upstream; Gemini's method IS the stream; Converse is
        // non-streaming and the adapter buffers it into the stream the caller asked for.
        Cell::Stream => match a {
            Compat | Azure | Anthropic | Cohere => Sent("/stream"),
            Google | Vertex => Url(":streamGenerateContent"),
            Bedrock => Url("/converse"),
        },
        Cell::Metadata => match a {
            Compat | Azure | Anthropic | Google | Vertex | Bedrock | Cohere => Consumed(
                "ChatRequest.metadata is gateway-internal trace context; no adapter reads it \
                 (an OpenAI `metadata` object decodes into it lossy — see the OG-90 hand-off)",
            ),
        },
        Cell::Stop => match a {
            Compat | Azure => Sent("/stop"),
            Anthropic => Sent("/stop_sequences"),
            Google | Vertex => Sent("/generationConfig/stopSequences"),
            Bedrock => Sent("/inferenceConfig/stopSequences"),
            Cohere => Sent("/stop_sequences"),
        },
        Cell::ResponseFormat => match a {
            Compat | Azure => Sent("/response_format"),
            Anthropic => Sent("/output_config/format"),
            Google | Vertex => Sent("/generationConfig/responseJsonSchema"),
            Bedrock => Sent("/outputConfig/textFormat"),
            // D9: Cohere v2 takes `response_format` (json_object / json_schema).
            Cohere => Sent("/response_format"),
        },
        Cell::ReasoningEffort => match a {
            Compat | Azure => Sent("/reasoning_effort"),
            Anthropic => Sent("/thinking/budget_tokens"),
            Google | Vertex => Sent("/generationConfig/thinkingConfig"),
            Bedrock | Cohere => Refused(PARAM, "reasoning_effort"),
        },
        Cell::PresencePenalty => match a {
            Compat | Azure | Cohere => Sent("/presence_penalty"),
            Google | Vertex => Sent("/generationConfig/presencePenalty"),
            Anthropic | Bedrock => Refused(PARAM, "presence_penalty"),
        },
        Cell::FrequencyPenalty => match a {
            Compat | Azure | Cohere => Sent("/frequency_penalty"),
            Google | Vertex => Sent("/generationConfig/frequencyPenalty"),
            Anthropic | Bedrock => Refused(PARAM, "frequency_penalty"),
        },
        Cell::ParallelToolCalls => match a {
            Compat | Azure => Sent("/parallel_tool_calls"),
            Anthropic => Sent("/tool_choice/disable_parallel_tool_use"),
            Google | Vertex | Bedrock | Cohere => Refused(PARAM, "parallel_tool_calls"),
        },
        Cell::User => match a {
            Compat | Azure => Sent("/user"),
            Anthropic => Sent("/metadata/user_id"),
            Google | Vertex | Bedrock | Cohere => Refused(PARAM, "user"),
        },
        Cell::ServiceTier => match a {
            Compat | Azure => Sent("/service_tier"),
            Anthropic | Google | Vertex | Bedrock | Cohere => Refused(PARAM, "service_tier"),
        },
        // Shape-level, provider-independent: `validate_shape` refuses `n != 1` for everyone.
        Cell::N => match a {
            Compat | Azure | Anthropic | Google | Vertex | Bedrock | Cohere => Refused(PARAM, "n"),
        },
        // OG-94 C1: an UNMODELLED field is refused everywhere — the guardrails cannot scan
        // what they do not model. (Allowlisted extras are covered in request_support's c1_*
        // tests; this cell pins the default: unknown → 400, never forwarded.)
        Cell::Extra => Refused(PARAM, "x_unmodelled"),
        Cell::PartText => match a {
            Compat | Azure | Anthropic => Sent("/messages/0/content/0/text"),
            Google | Vertex => Sent("/contents/0/parts/0/text"),
            Bedrock => Sent("/messages/0/content/0/text"),
            Cohere => Sent("/messages/0/content/0/text"),
        },
        Cell::PartImage => match a {
            Compat | Azure => Sent("/messages/0/content/0/image_url/url"),
            Anthropic => Sent("/messages/0/content/0/source/data"),
            Google | Vertex => Sent("/contents/0/parts/0/inlineData/data"),
            Bedrock => Sent("/messages/0/content/0/image/source/bytes"),
            Cohere => Refused(CONTENT, img),
        },
        // The gateway never fetches a URL on a caller's behalf: pass it through or refuse it.
        Cell::PartImageHttps => match a {
            Compat | Azure => Sent("/messages/0/content/0/image_url/url"),
            Anthropic => Sent("/messages/0/content/0/source/url"),
            Google | Vertex | Bedrock | Cohere => Refused(CONTENT, img),
        },
        Cell::PartAudio => match a {
            Compat | Azure => Sent("/messages/0/content/0/input_audio/data"),
            Google | Vertex => Sent("/contents/0/parts/0/inlineData/data"),
            Anthropic | Bedrock | Cohere => Refused(CONTENT, img),
        },
        Cell::PartFile => match a {
            Compat | Azure => Sent("/messages/0/content/0/file/file_data"),
            Anthropic => Sent("/messages/0/content/0/source/data"),
            Google | Vertex => Sent("/contents/0/parts/0/inlineData/data"),
            Bedrock => Sent("/messages/0/content/0/document/source/bytes"),
            Cohere => Refused(CONTENT, img),
        },
        // Assistant message 1 carries the `tool_use` part (message 0 is the user turn).
        Cell::PartToolUse => match a {
            Compat | Azure | Anthropic => Sent("/messages/1/content/0/name"),
            Google | Vertex => Sent("/contents/1/parts/0/functionCall/name"),
            Bedrock | Cohere => Refused(CONTENT, "messages[1].content[0]"),
        },
        Cell::PartToolResult => match a {
            Compat | Azure | Anthropic => Sent("/messages/0/content/0/content"),
            Google | Vertex | Bedrock | Cohere => Refused(CONTENT, img),
        },
        Cell::ToolHistory => match a {
            Compat | Azure | Anthropic | Bedrock => Sent("/messages"),
            Google | Vertex => Sent("/contents"),
            Cohere => Refused(CONTENT, "messages[1]"),
        },
    }
}

// ── the pins ────────────────────────────────────────────────────────────────

/// Exhaustive over `ContentPart`: a new variant does not COMPILE until it is mapped here, and
/// `every_content_part_variant_has_a_cell` then requires that cell to be in `CELLS`.
fn part_cell(p: &ContentPart) -> Cell {
    match p {
        ContentPart::Text { .. } => Cell::PartText,
        ContentPart::ImageUrl { .. } => Cell::PartImage,
        ContentPart::ToolUse { .. } => Cell::PartToolUse,
        ContentPart::ToolResult { .. } => Cell::PartToolResult,
        ContentPart::InputAudio { .. } => Cell::PartAudio,
        ContentPart::File { .. } => Cell::PartFile,
    }
}

/// One sample of every `ContentPart` variant.
fn every_content_part() -> Vec<ContentPart> {
    vec![
        text_part("x"),
        image_part(&png_uri()),
        tool_use_part(),
        tool_result_part(),
        audio_part(),
        file_part(),
    ]
}

/// A `ChatRequest` with EVERY field populated. A struct literal with no `..Default::default()`
/// on purpose: adding a field to `ChatRequest` is a compile error HERE until it is populated,
/// which is what lets the key-set test below see it.
fn fully_populated() -> ChatRequest {
    let mut extra = serde_json::Map::new();
    extra.insert("x_unmodelled".into(), json!("OG90-EXTRA"));
    ChatRequest {
        model: "m".into(),
        messages: vec![],
        tools: Some(vec![]),
        tool_choice: Some(ToolChoice::Auto),
        max_tokens: Some(1),
        temperature: Some(0.5),
        top_p: Some(0.5),
        seed: Some(1),
        logprobs: Some(true),
        top_logprobs: Some(1),
        stream: Some(true),
        system: Some("s".into()),
        metadata: Some(RequestMetadata {
            trace_parent: None,
            user_id: None,
            session_id: None,
        }),
        stop: Some(Stop::One("s".into())),
        response_format: Some(json!({"type": "text"})),
        reasoning_effort: Some("low".into()),
        max_completion_tokens: Some(1),
        presence_penalty: Some(0.5),
        frequency_penalty: Some(0.5),
        parallel_tool_calls: Some(true),
        user: Some("u".into()),
        service_tier: Some("auto".into()),
        n: Some(1),
        extra,
    }
}

#[test]
fn every_chat_request_key_is_in_the_matrix() {
    let wire = serde_json::to_value(fully_populated()).expect("serialise");
    let have: BTreeSet<String> = wire
        .as_object()
        .expect("a ChatRequest serialises to an object")
        .keys()
        .cloned()
        .collect();
    let want: BTreeSet<String> = CELLS
        .iter()
        .filter_map(|c| c.json_key())
        .map(str::to_owned)
        .collect();
    assert_eq!(
        have,
        want,
        "OG-90: ChatRequest serialises keys the conformance matrix has no cell for (or the \
         matrix names a key ChatRequest no longer has). Add a `Cell`, decide it for all seven \
         adapters in `expected`, and a probe in `apply`. Missing from the matrix: {:?}; stale in \
         the matrix: {:?}",
        have.difference(&want).collect::<Vec<_>>(),
        want.difference(&have).collect::<Vec<_>>(),
    );
}

#[test]
fn every_content_part_variant_has_a_cell() {
    let covered: BTreeSet<Cell> = every_content_part().iter().map(part_cell).collect();
    let in_matrix: BTreeSet<Cell> = CELLS.iter().copied().collect();
    for c in &covered {
        assert!(in_matrix.contains(c), "{c:?} is not in CELLS");
    }
    // Every part variant maps to a distinct cell (a copy-paste in `part_cell` would hide one).
    assert_eq!(covered.len(), 6, "{covered:?}");
    // And every cell the matrix lists is decided for every adapter (compiles; spot-run it).
    for &c in CELLS {
        for a in ADAPTERS {
            let _ = expected(a, c);
        }
    }
}

// ── building probes ─────────────────────────────────────────────────────────

const PNG_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";
const PNG_B64_PREFIX: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEA";
const PDF_B64: &str = "JVBERi0xLjQKJSBvZzkwCg==";
const PDF_B64_PREFIX: &str = "JVBERi0xLjQK";
const AUDIO_B64: &str = "QUJDREVGR0g=";

fn png_uri() -> String {
    format!("data:image/png;base64,{PNG_B64}")
}

fn text_part(t: &str) -> ContentPart {
    ContentPart::Text {
        text: t.into(),
        cache_control: None,
    }
}

fn image_part(url: &str) -> ContentPart {
    ContentPart::ImageUrl {
        image_url: ImageUrl {
            url: url.into(),
            detail: None,
        },
    }
}

fn audio_part() -> ContentPart {
    ContentPart::InputAudio {
        input_audio: InputAudio {
            data: AUDIO_B64.into(),
            format: "wav".into(),
        },
    }
}

fn file_part() -> ContentPart {
    ContentPart::File {
        file: FilePart {
            file_data: Some(format!("data:application/pdf;base64,{PDF_B64}")),
            file_id: None,
            filename: Some("og90.pdf".into()),
        },
    }
}

fn tool_use_part() -> ContentPart {
    ContentPart::ToolUse {
        id: "call_1".into(),
        name: "get_weather".into(),
        input: json!({"city": "Paris"}),
    }
}

fn tool_result_part() -> ContentPart {
    ContentPart::ToolResult {
        tool_use_id: "call_1".into(),
        content: "OG90-RESULT".into(),
        cache_control: None,
    }
}

fn msg(role: Role, content: MessageContent) -> Message {
    Message {
        role,
        content,
        tool_call_id: None,
        tool_calls: None,
    }
}

fn user_text(t: &str) -> Message {
    msg(Role::User, MessageContent::Text(t.into()))
}

fn weather_tool() -> Tool {
    Tool {
        name: "get_weather".into(),
        description: Some("weather".into()),
        input_schema: json!({"type": "object", "properties": {"city": {"type": "string"}}}),
    }
}

/// The request every cell starts from: one plain user turn, streamed.
fn base(a: Adapter) -> ChatRequest {
    ChatRequest {
        model: a.model().into(),
        messages: vec![user_text("OG90-USER-TEXT")],
        stream: Some(true),
        ..Default::default()
    }
}

/// The request for one cell: `base` plus the cell's distinctive value.
fn apply(a: Adapter, c: Cell) -> ChatRequest {
    let mut r = base(a);
    match c {
        Cell::Model | Cell::Messages | Cell::Stream => {}
        Cell::System => r.system = Some("OG90-SYSTEM".into()),
        Cell::SystemMessage => r.messages.insert(
            0,
            msg(Role::System, MessageContent::Text("OG90-SYSMSG".into())),
        ),
        Cell::TwoSystems => {
            r.system = Some("OG90-SYSTEM".into());
            r.messages.insert(
                0,
                msg(Role::System, MessageContent::Text("OG90-SYSMSG".into())),
            );
        }
        Cell::Tools => r.tools = Some(vec![weather_tool()]),
        Cell::ToolChoice => {
            r.tools = Some(vec![weather_tool()]);
            r.tool_choice = Some(ToolChoice::Required);
        }
        Cell::ToolChoiceNone => {
            r.tools = Some(vec![weather_tool()]);
            r.tool_choice = Some(ToolChoice::None);
        }
        Cell::ToolChoiceFunction => {
            r.tools = Some(vec![weather_tool()]);
            r.tool_choice = Some(ToolChoice::Function {
                name: "get_weather".into(),
            });
        }
        Cell::MaxTokens => r.max_tokens = Some(777),
        Cell::MaxCompletionTokens => r.max_completion_tokens = Some(555),
        Cell::Temperature => r.temperature = Some(0.5),
        Cell::TopP => r.top_p = Some(0.25),
        Cell::Seed => r.seed = Some(424_242),
        Cell::Logprobs => r.logprobs = Some(true),
        Cell::TopLogprobs => r.top_logprobs = Some(7),
        Cell::Metadata => {
            r.metadata = Some(RequestMetadata {
                trace_parent: Some(
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".into(),
                ),
                user_id: Some("OG90-META".into()),
                session_id: Some("OG90-META-SESSION".into()),
            });
        }
        Cell::Stop => {
            r.stop = Some(Stop::Many(vec!["OG90-STOP-A".into(), "OG90-STOP-B".into()]));
        }
        Cell::ResponseFormat => {
            r.response_format = Some(json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "og90",
                    "schema": {"type": "object", "properties": {"og90_field": {"type": "string"}}}
                }
            }));
        }
        Cell::ReasoningEffort => {
            r.reasoning_effort = Some("high".into());
            // Room for the smallest legal thinking budget (it must stay below max_tokens).
            r.max_tokens = Some(8192);
        }
        Cell::PresencePenalty => r.presence_penalty = Some(0.375),
        Cell::FrequencyPenalty => r.frequency_penalty = Some(0.625),
        Cell::ParallelToolCalls => {
            r.tools = Some(vec![weather_tool()]);
            r.parallel_tool_calls = Some(false);
        }
        Cell::User => r.user = Some("OG90-USER-ID".into()),
        Cell::ServiceTier => r.service_tier = Some("flex".into()),
        Cell::N => r.n = Some(2),
        Cell::Extra => {
            r.extra.insert("x_unmodelled".into(), json!("OG90-EXTRA"));
        }
        Cell::PartText => {
            r.messages = vec![msg(
                Role::User,
                MessageContent::Parts(vec![text_part("OG90-PART-TEXT")]),
            )]
        }
        Cell::PartImage => {
            r.messages = vec![msg(
                Role::User,
                MessageContent::Parts(vec![image_part(&png_uri())]),
            )];
        }
        Cell::PartImageHttps => {
            r.messages = vec![msg(
                Role::User,
                MessageContent::Parts(vec![image_part("https://og90.invalid/cat.png")]),
            )];
        }
        Cell::PartAudio => {
            r.messages = vec![msg(Role::User, MessageContent::Parts(vec![audio_part()]))];
        }
        Cell::PartFile => {
            r.messages = vec![msg(Role::User, MessageContent::Parts(vec![file_part()]))];
        }
        Cell::PartToolUse => {
            r.messages = vec![
                user_text("q"),
                msg(
                    Role::Assistant,
                    MessageContent::Parts(vec![tool_use_part()]),
                ),
            ];
        }
        Cell::PartToolResult => {
            r.messages = vec![msg(
                Role::User,
                MessageContent::Parts(vec![tool_result_part()]),
            )];
        }
        Cell::ToolHistory => {
            r.tools = Some(vec![weather_tool()]);
            let mut assistant = msg(Role::Assistant, MessageContent::Text(String::new()));
            assistant.tool_calls = Some(vec![ToolCall {
                id: "call_1".into(),
                name: "get_weather".into(),
                input: json!({"city": "Paris"}),
            }]);
            let mut tool = msg(Role::Tool, MessageContent::Text("OG90-RESULT".into()));
            tool.tool_call_id = Some("call_1".into());
            r.messages = vec![user_text("q"), assistant, tool];
        }
    }
    r
}

// ── dispatching through the REAL adapter ────────────────────────────────────

struct LoopbackBypassGuard;

impl LoopbackBypassGuard {
    fn new() -> Self {
        crate::ssrf_guard::set_loopback_bypass_for_tests(true);
        Self
    }
}

impl Drop for LoopbackBypassGuard {
    fn drop(&mut self) {
        crate::ssrf_guard::set_loopback_bypass_for_tests(false);
    }
}

fn tenant() -> TenantId {
    TenantId::from_jwt_claim(Uuid::from_u128(0x0690_0090))
}

/// A structurally valid PKCS#8 RSA key, generated in-process (never committed — `crates/` ships
/// publicly; same approach as `vertex.rs`'s own probe test).
fn throwaway_pem() -> String {
    use aws_lc_rs::encoding::AsDer as _;
    use base64::Engine as _;
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PEM.get_or_init(|| {
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("generate a test RSA key");
        let der = key.as_der().expect("PKCS#8 DER");
        let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let body: String = b64
            .as_bytes()
            .chunks(64)
            .map(|l| format!("{}\n", std::str::from_utf8(l).expect("ascii")))
            .collect();
        format!("-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n")
    })
    .clone()
}

/// What the mock saw: the request the adapter actually sent.
struct Captured {
    path_and_query: String,
    body: Value,
}

/// A canned 200 in the adapter's own response format.
fn canned(a: Adapter, tool_call: bool) -> ResponseTemplate {
    match a {
        Adapter::Compat | Adapter::Azure => {
            let delta = if tool_call {
                r#"{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]}"#
            } else {
                r#"{"role":"assistant","content":"hi"}"#
            };
            sse(&format!(
                "data: {{\"id\":\"x\",\"choices\":[{{\"index\":0,\"delta\":{delta},\"finish_reason\":null}}]}}\n\ndata: [DONE]\n\n"
            ))
        }
        Adapter::Anthropic => {
            let blocks = if tool_call {
                concat!(
                    "event: content_block_start\n",
                    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\",\"input\":{}}}\n\n",
                    "event: content_block_delta\n",
                    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\\\"Paris\\\"}\"}}\n\n",
                )
            } else {
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n"
            };
            sse(&format!(
                "data: {{\"type\":\"message_start\",\"message\":{{\"id\":\"m\",\"model\":\"x\",\"usage\":{{\"input_tokens\":1,\"output_tokens\":1}}}}}}\n\n{blocks}data: {{\"type\":\"message_stop\"}}\n\n"
            ))
        }
        Adapter::Google | Adapter::Vertex => {
            let part = if tool_call {
                r#"{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}"#
            } else {
                r#"{"text":"hi"}"#
            };
            sse(&format!(
                "data: {{\"candidates\":[{{\"content\":{{\"role\":\"model\",\"parts\":[{part}]}},\"finishReason\":\"STOP\"}}],\"usageMetadata\":{{\"promptTokenCount\":1,\"candidatesTokenCount\":1}}}}\n\n"
            ))
        }
        Adapter::Bedrock => {
            let content = if tool_call {
                json!([{"toolUse": {"toolUseId": "tu_1", "name": "get_weather", "input": {"city": "Paris"}}}])
            } else {
                json!([{"text": "hi"}])
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "output": {"message": {"role": "assistant", "content": content}},
                "stopReason": if tool_call { "tool_use" } else { "end_turn" },
                "usage": {"inputTokens": 1, "outputTokens": 1}
            }))
        }
        // D9: Cohere v2 SSE (`event:` + `data:` frames; tool calls stream as
        // tool-call-start / -delta / -end, usage rides on message-end).
        Adapter::Cohere => {
            let mid = if tool_call {
                concat!(
                    "event: tool-call-start\n",
                    r#"data: {"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}}}}"#,
                    "\n\n",
                    "event: tool-call-delta\n",
                    r#"data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"city\":\"Paris\"}"}}}}}"#,
                    "\n\n",
                    "event: tool-call-end\n",
                    r#"data: {"type":"tool-call-end","index":0}"#,
                    "\n\n",
                )
            } else {
                concat!(
                    "event: content-delta\n",
                    r#"data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"hi"}}}}"#,
                    "\n\n",
                )
            };
            sse(&format!(
                "{mid}event: message-end\ndata: {{\"type\":\"message-end\",\"delta\":{{\"finish_reason\":\"COMPLETE\",\"usage\":{{\"tokens\":{{\"input_tokens\":1,\"output_tokens\":1}}}}}}}}\n\n"
            ))
        }
    }
}

fn sse(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/event-stream")
        .set_body_string(body.to_owned())
}

/// Send `req` through the REAL adapter to a fresh mock and return what the adapter put on the
/// wire, plus every event it produced.
async fn dispatch(
    a: Adapter,
    req: ChatRequest,
    response: ResponseTemplate,
) -> (anyhow::Result<Vec<ProviderEvent>>, Option<Captured>) {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    // Vertex exchanges a service-account assertion first; the token endpoint is the mock too.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"access_token": "og90-token"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(response)
        .mount(&server)
        .await;
    let tenant = tenant();
    let uri = server.uri();
    let started = match a {
        Adapter::Compat => match OpenAiProvider::compatible(uri.clone(), "openai") {
            Ok(p) => p.chat(req, "og90-key", &tenant).await,
            Err(e) => Err(e),
        },
        Adapter::Azure => {
            match AzureOpenAiProvider::for_endpoint(uri.clone(), "2025-01-01-preview") {
                Ok(p) => p.chat(req, "og90-key", &tenant).await,
                Err(e) => Err(e),
            }
        }
        Adapter::Anthropic => match AnthropicProvider::for_base_url(uri.clone()) {
            Ok(p) => p.chat(req, "og90-key", &tenant).await,
            Err(e) => Err(e),
        },
        Adapter::Google => match GoogleProvider::for_base_url(uri.clone()) {
            Ok(p) => p.chat(req, "og90-key", &tenant).await,
            Err(e) => Err(e),
        },
        Adapter::Vertex => {
            let _host = HostOverrideGuard::new(uri.clone());
            let sa = json!({
                "client_email": "og90@example.test",
                "project_id": "og90-project",
                "private_key": throwaway_pem(),
                "token_uri": format!("{uri}/token"),
            })
            .to_string();
            match VertexProvider::new() {
                Ok(p) => p.chat(req, &sa, &tenant).await,
                Err(e) => Err(e),
            }
        }
        Adapter::Bedrock => {
            match BedrockProvider::for_test_endpoint(uri.clone(), "AKIAOG90TEST", "og90-secret") {
                Ok(p) => p.chat(req, "ignored", &tenant).await,
                Err(e) => Err(e),
            }
        }
        Adapter::Cohere => match CohereProvider::for_base_url(uri.clone()) {
            Ok(p) => p.chat(req, "og90-key", &tenant).await,
            Err(e) => Err(e),
        },
    };
    let events = match started {
        Err(e) => Err(e),
        Ok(mut stream) => {
            let mut out = Vec::new();
            let mut err = None;
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => out.push(ev),
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            match err {
                Some(e) if out.is_empty() => Err(e),
                _ => Ok(out),
            }
        }
    };
    let captured = server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .rfind(|r| r.method.as_str() == "POST" && r.url.path() != "/token")
        .map(|r| Captured {
            path_and_query: match r.url.query() {
                Some(q) => format!("{}?{q}", r.url.path()),
                None => r.url.path().to_owned(),
            },
            body: serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        });
    (events, captured)
}

/// The two checks the chat handler runs, in its order: shape at admission, support after the
/// provider is final.
fn gate(a: Adapter, req: &ChatRequest) -> Result<(), Unsupported> {
    request_support::validate_shape(req)?;
    request_support::check_supported(a.provider_id(), req)
}

/// Sources of every adapter, for the `Consumed` check.
const ADAPTER_SOURCES: [(&str, &str); 7] = [
    ("openai.rs", include_str!("openai.rs")),
    ("azure.rs", include_str!("azure.rs")),
    ("anthropic.rs", include_str!("anthropic.rs")),
    ("google.rs", include_str!("google.rs")),
    ("vertex.rs", include_str!("vertex.rs")),
    ("bedrock.rs", include_str!("bedrock.rs")),
    ("cohere.rs", include_str!("cohere.rs")),
];

/// Run one cell. `Err` is a human-readable failure naming the cell.
async fn run_cell(a: Adapter, c: Cell) -> Result<(), String> {
    let id = format!("{a:?} × {c:?}");
    let want = expected(a, c);
    let req = apply(a, c);
    match want {
        Refused(code, param) => match gate(a, &req) {
            Ok(()) => Err(format!(
                "{id}: expected a 400 {code} naming `{param}`, but the gate PASSED — the request would be dispatched and the value dropped or mangled"
            )),
            Err(u) if u.code == code && u.param == param => Ok(()),
            Err(u) => Err(format!(
                "{id}: refused with the wrong code/param: got {} naming `{}` ({}), wanted {code} naming `{param}`",
                u.code, u.param, u.message
            )),
        },
        Sent(_) | Url(_) | Omits(_) | Consumed(_) => {
            if let Err(u) = gate(a, &req) {
                return Err(format!(
                    "{id}: the matrix says it is sent, but the gate refuses it ({} naming `{}`: {})",
                    u.code, u.param, u.message
                ));
            }
            let (events, captured) = dispatch(a, req, canned(a, false)).await;
            if let Err(e) = &events {
                return Err(format!("{id}: dispatch failed: {e:#}"));
            }
            let Some(cap) = captured else {
                return Err(format!("{id}: the adapter sent nothing to the provider"));
            };
            let needles = c.needles(a);
            match want {
                Sent(ptr) => match cap.body.pointer(ptr) {
                    None => Err(format!(
                        "{id}: SILENT DROP — `{ptr}` is absent from the body the adapter sent. Body: {}",
                        cap.body
                    )),
                    Some(v) => {
                        let text = v.to_string();
                        needles
                            .iter()
                            .find(|n| !text.contains(n.as_str()))
                            .map_or(Ok(()), |n| {
                                Err(format!(
                                    "{id}: `{ptr}` is present but does not carry {n:?}: {text}"
                                ))
                            })
                    }
                },
                Url(frag) => {
                    if cap.path_and_query.contains(frag) {
                        Ok(())
                    } else {
                        Err(format!(
                            "{id}: the request URL `{}` does not carry {frag:?}",
                            cap.path_and_query
                        ))
                    }
                }
                Omits(ptr) => {
                    if cap.body.pointer(ptr).is_none() {
                        Ok(())
                    } else {
                        Err(format!(
                            "{id}: `{ptr}` must be absent (the value is honoured by omission) but is present: {}",
                            cap.body
                        ))
                    }
                }
                Consumed(why) => {
                    // The value must not be read by any adapter. If one starts to, decide the cell.
                    for (file, src) in ADAPTER_SOURCES {
                        for pat in ["req.metadata", "request.metadata", "r.metadata"] {
                            if src.contains(pat) {
                                return Err(format!(
                                    "{id}: {file} reads `{pat}` — the cell says no adapter does ({why}). Decide it: Sent(pointer)"
                                ));
                            }
                        }
                    }
                    Ok(())
                }
                Refused(..) => Ok(()),
            }
        }
    }
}

async fn run_adapter(a: Adapter) {
    let mut failures = Vec::new();
    for &c in CELLS {
        if let Err(e) = run_cell(a, c).await {
            failures.push(e);
        }
    }
    assert!(
        failures.is_empty(),
        "OG-90: {} of {} cells for {a:?} are red:\n  - {}",
        failures.len(),
        CELLS.len(),
        failures.join("\n  - ")
    );
}

#[tokio::test]
async fn og90_matrix_openai_compatible() {
    run_adapter(Adapter::Compat).await;
}

#[tokio::test]
async fn og90_matrix_azure() {
    run_adapter(Adapter::Azure).await;
}

#[tokio::test]
async fn og90_matrix_anthropic() {
    run_adapter(Adapter::Anthropic).await;
}

#[tokio::test]
async fn og90_matrix_google() {
    run_adapter(Adapter::Google).await;
}

#[tokio::test]
async fn og90_matrix_vertex() {
    run_adapter(Adapter::Vertex).await;
}

#[tokio::test]
async fn og90_matrix_bedrock() {
    run_adapter(Adapter::Bedrock).await;
}

#[tokio::test]
async fn og90_matrix_cohere() {
    run_adapter(Adapter::Cohere).await;
}

// ── response direction (minimal): a provider's tool call reaches the caller ──

/// The tool calls an adapter's event stream carries, as `(name, args)` — folding the argument
/// deltas by index the way the chat handler's accumulator does. Bedrock answers whole, in `Done`.
fn tool_calls_of(events: &[ProviderEvent]) -> Vec<(String, String)> {
    let mut calls: Vec<(usize, String, String)> = Vec::new();
    for ev in events {
        match ev {
            ProviderEvent::ToolCallDelta {
                index,
                name,
                input_delta,
                ..
            } => {
                if let Some(slot) = calls.iter_mut().find(|(i, ..)| i == index) {
                    if let Some(n) = name {
                        slot.1.clone_from(n);
                    }
                    slot.2.push_str(input_delta);
                } else {
                    calls.push((
                        *index,
                        name.clone().unwrap_or_default(),
                        input_delta.clone(),
                    ));
                }
            }
            ProviderEvent::Done { response } => {
                for ch in &response.choices {
                    for tc in ch.message.tool_calls.iter().flatten() {
                        calls.push((calls.len(), tc.name.clone(), tc.input.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    calls.into_iter().map(|(_, n, a)| (n, a)).collect()
}

async fn assert_response_tool_call(a: Adapter) {
    let (events, _) = dispatch(a, base(a), canned(a, true)).await;
    let events = events.unwrap_or_else(|e| panic!("{a:?}: dispatch failed: {e:#}"));
    let calls = tool_calls_of(&events);
    assert!(
        calls
            .iter()
            .any(|(n, args)| n == "get_weather" && args.contains("Paris")),
        "OG-90 response direction: {a:?} dropped the provider's tool call; got {calls:?} from {events:?}"
    );
}

#[tokio::test]
async fn og90_response_tool_call_reaches_the_caller_on_every_adapter() {
    for a in ADAPTERS {
        assert_response_tool_call(a).await;
    }
}

/// Parallel tool calls in ONE OpenAI-wire chunk (several compat providers batch them): each is
/// its own event. The adapter used to read `tool_calls.first()` and drop the rest.
#[tokio::test]
async fn og90_response_parallel_tool_calls_in_one_openai_chunk_all_arrive() {
    let body = concat!(
        "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
        "{\"index\":0,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\"}},",
        "{\"index\":1,\"id\":\"call_b\",\"type\":\"function\",\"function\":{\"name\":\"get_time\",\"arguments\":\"{\\\"tz\\\":\\\"UTC\\\"}\"}}",
        "]},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n"
    );
    let (events, _) = dispatch(Adapter::Compat, base(Adapter::Compat), sse(body)).await;
    let calls = tool_calls_of(&events.expect("dispatch"));
    assert!(
        calls
            .iter()
            .any(|(n, a)| n == "get_weather" && a.contains("Paris"))
            && calls
                .iter()
                .any(|(n, a)| n == "get_time" && a.contains("UTC")),
        "OG-90 response direction: a second parallel tool call in one chunk was dropped; got {calls:?}"
    );
}
