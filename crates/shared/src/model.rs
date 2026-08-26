//! Universal chat API types.
//!
//! `ChatRequest` is the gateway's internal representation of any provider's
//! chat request. Provider adapters translate from this format to their own
//! wire format. This is the only schema that crosses the provider boundary.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: MessageContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text {
        text: String,
        /// Anthropic prompt-caching marker (e.g. `{"type":"ephemeral"}`),
        /// preserved verbatim for the Anthropic adapter and stripped for
        /// providers that don't understand it (/ PP-G8). `None` for the
        /// overwhelming majority of blocks, so it never reaches the wire unless
        /// the caller set it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<Value>,
    },
    ImageUrl {
        image_url: ImageUrl,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrl {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A tool the model may call.
///
/// **The internal shape is Anthropic-native** (`name` / `input_schema`) and both
/// provider adapters translate outward from it correctly — `openai.rs` builds the
/// nested `{"type":"function","function":{…}}` form, `anthropic.rs` keeps
/// `input_schema`. Only the INBOUND direction was wrong, which is why this fix is
/// a `Deserialize` impl and touches nothing else.
///
/// # B-258 — what was broken
///
/// `/v1/chat/completions` is the OPENAI-COMPATIBLE endpoint, and every client of
/// it — the OpenAI SDK, LiteLLM, LangChain, the Vercel AI SDK — sends tools as
/// `{"type":"function","function":{"name":…,"parameters":{…}}}`. Deriving
/// `Deserialize` on the native shape rejected all of them with
/// **HTTP 400 `missing field \`name\``**. Verified on prod 2026-08-18: the flat
/// shape returned 200 and the nested shape 400, same model, same key, same
/// minute. So tool calling — the traffic ADR-055 puts at the centre of this
/// product — could not be accepted from a standard client at all.
///
/// It now accepts BOTH and normalises to one internal representation, because the
/// internal shape feeds the tool-schema and definition-drift rails and they must
/// see one thing regardless of how the caller spelled it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
}

/// OpenAI's `function` object. `parameters` is OPTIONAL in their schema — a tool
/// that takes no arguments may omit it — so this does too, and supplies the
/// empty-object JSON Schema rather than failing. Rejecting a legal request
/// because it omitted an optional field is the same defect class as B-258 itself.
#[derive(Deserialize)]
struct OpenAiFunctionWire {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Option<Value>,
}

/// The two wire shapes a tool can arrive in.
///
/// `untagged` tries variants in order, and the discriminator is structural: the
/// OpenAI form is the only one with a `function` object, the native form is the
/// only one with `input_schema`. `type` is accepted but not required — OpenAI
/// mandates `"type":"function"`, and refusing a request that omitted it would be
/// pedantry that costs a customer a 400.
#[derive(Deserialize)]
#[serde(untagged)]
enum ToolWire {
    OpenAi {
        #[serde(rename = "type", default)]
        _type: Option<String>,
        function: OpenAiFunctionWire,
    },
    Native {
        name: String,
        #[serde(default)]
        description: Option<String>,
        input_schema: Value,
    },
}

impl<'de> Deserialize<'de> for Tool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match ToolWire::deserialize(deserializer)? {
            ToolWire::OpenAi { function, .. } => Self {
                name: function.name,
                description: function.description,
                // A no-argument tool: the empty object schema, which is what every
                // provider expects for "callable, takes nothing".
                input_schema: function
                    .parameters
                    .unwrap_or_else(|| serde_json::json!({ "type": "object", "properties": {} })),
            },
            ToolWire::Native {
                name,
                description,
                input_schema,
            } => Self {
                name,
                description,
                input_schema,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input: Value,
}

/// Universal chat request shape used throughout the gateway.
/// Provider adapters translate from this to provider-native format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RequestMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Tracelane trace context for W3C propagation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_parent: Option<String>,
    /// Used for OTLP span correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Human-readable session identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub id: String,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Option<Usage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    pub index: u32,
    pub message: Message,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_read_input_tokens: Option<u32>,
    pub cache_creation_input_tokens: Option<u32>,
}

#[cfg(test)]
mod b258_tool_wire_tests {
    use super::*;

    /// **THE TEST THAT WOULD HAVE CAUGHT B-258.** A request built the way an
    /// OpenAI SDK builds one — the nested `{"type":"function","function":{…}}`
    /// shape that the OpenAI SDK, LiteLLM, LangChain and the Vercel AI SDK all
    /// emit. Before this fix the whole request failed to deserialize and the
    /// gateway answered HTTP 400 `missing field \`name\``.
    ///
    /// It asserts against the WIRE, not against the internal struct. Every tool
    /// test that existed before constructed `Tool { … }` directly, so it
    /// exercised the adapters and could not see the wire contract at all — the
    /// same blindness as B-257 (a read verified with a different client than the
    /// one that performs it) and the mock-provider eval tier.
    #[test]
    fn a_request_shaped_like_an_openai_sdk_sends_it_deserializes() {
        let body = r#"{
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "weather in Paris?"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get the weather for a city",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"]
                    }
                }
            }]
        }"#;
        let req: ChatRequest =
            serde_json::from_str(body).expect("an OpenAI-shaped request must parse");
        let tools = req.tools.expect("tools must survive deserialization");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "get_weather");
        assert_eq!(
            tools[0].description.as_deref(),
            Some("Get the weather for a city")
        );
        // `parameters` must land in `input_schema` — the field the rails and both
        // adapters read. Dropping it would parse and then send a schema-less tool.
        assert_eq!(
            tools[0].input_schema["properties"]["city"]["type"],
            "string"
        );
    }

    /// The Anthropic-native shape must KEEP working. Without this the fix would
    /// be a swap rather than a widening, and the 200 that shape returns on prod
    /// today would silently become a 400 — trading one broken client for another.
    #[test]
    fn the_anthropic_native_shape_still_deserializes() {
        let body = r#"{
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{
                "name": "get_weather",
                "description": "Get the weather",
                "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}
            }]
        }"#;
        let req: ChatRequest =
            serde_json::from_str(body).expect("the native shape must still parse");
        let tools = req.tools.expect("tools must survive");
        assert_eq!(tools[0].name, "get_weather");
        assert_eq!(
            tools[0].input_schema["properties"]["city"]["type"],
            "string"
        );
    }

    /// BOTH SHAPES MUST NORMALISE TO THE SAME THING. This is the property the
    /// guardrail rails depend on: tool-schema validation and definition-drift
    /// hash a tool's identity, so the same tool spelled two ways must not read as
    /// two different tools — that would make drift detection fire on a client
    /// library upgrade.
    #[test]
    fn the_two_shapes_normalise_to_an_identical_tool() {
        let openai: Tool = serde_json::from_str(
            r#"{"type":"function","function":{"name":"f","description":"d","parameters":{"type":"object"}}}"#,
        )
        .expect("openai shape");
        let native: Tool = serde_json::from_str(
            r#"{"name":"f","description":"d","input_schema":{"type":"object"}}"#,
        )
        .expect("native shape");
        assert_eq!(
            openai, native,
            "the same tool spelled two ways must normalise identically"
        );
    }

    /// OpenAI's `parameters` is OPTIONAL — a tool that takes no arguments may
    /// omit it. Rejecting that would be B-258 again in miniature: a legal request
    /// refused because an optional field was absent. It must become the empty
    /// object schema, not `null` and not an error.
    #[test]
    fn an_openai_tool_with_no_parameters_gets_the_empty_object_schema() {
        let t: Tool = serde_json::from_str(r#"{"type":"function","function":{"name":"ping"}}"#)
            .expect("a no-argument tool must parse");
        assert_eq!(t.name, "ping");
        assert_eq!(t.input_schema["type"], "object");
        assert!(t.input_schema["properties"].is_object());
    }

    /// `type` is accepted but not required. Some clients omit it; refusing them
    /// would be pedantry that costs a 400.
    #[test]
    fn the_type_field_is_optional() {
        let t: Tool =
            serde_json::from_str(r#"{"function":{"name":"f","parameters":{"type":"object"}}}"#)
                .expect("a tool without an explicit type must parse");
        assert_eq!(t.name, "f");
    }

    /// And the falsifying half: genuinely malformed input must still FAIL. Without
    /// this the tests above would pass for a deserializer that accepted anything,
    /// which is the failure mode a permissive `untagged` enum invites.
    #[test]
    fn a_tool_with_neither_shape_is_still_rejected() {
        for bad in [
            r#"{"description":"no name anywhere"}"#,
            r#"{"function":{"description":"a function with no name"}}"#,
            r#"{"name":"has a name but no schema at all"}"#,
            r#"[]"#,
            r#""just a string""#,
        ] {
            assert!(
                serde_json::from_str::<Tool>(bad).is_err(),
                "malformed tool was accepted: {bad}"
            );
        }
    }
}
