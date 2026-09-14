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
    /// B-360 (2026-09-07): OpenAI SDKs send `"content": null` — or omit it — on an
    /// assistant turn that carries `tool_calls`. Both decode to empty text; a string
    /// or a parts array decodes exactly as before. Found by replaying the model's own
    /// tool call through prod: the request 400'd on this field before the B-356 shim
    /// was ever reached.
    #[serde(default, deserialize_with = "deserialize_nullable_content")]
    pub content: MessageContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

impl Default for MessageContent {
    fn default() -> Self {
        MessageContent::Text(String::new())
    }
}

/// `null` → empty text; anything else → the untagged enum as usual.
fn deserialize_nullable_content<'de, D>(d: D) -> Result<MessageContent, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<MessageContent> = serde::Deserialize::deserialize(d)?;
    Ok(opt.unwrap_or_default())
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

/// A tool call the model asked for, carried in assistant message HISTORY.
///
/// **The internal shape is Anthropic-native** (`name` / `input`) and
/// `openai.rs` translates outward to the nested
/// `{"id","type":"function","function":{"name","arguments"}}` form. Only the
/// INBOUND direction was wrong — the same asymmetry, and the same fix, as
/// [`Tool`] (B-258).
///
/// # B-356 — what was broken
///
/// The standard multi-turn tool-use loop is: read the assistant message the
/// gateway returned, append it verbatim to `messages`, append the tool result,
/// send the whole history back. Every OpenAI-shaped client does that, and the
/// assistant message it replays carries OpenAI-shaped `tool_calls`. Deriving
/// `Deserialize` on the native shape rejected all of them, so the gateway
/// answered **HTTP 400** to a request built out of its own prior output.
///
/// It now accepts BOTH and normalises to one internal representation.
/// `arguments` is a JSON **string** on the OpenAI wire and a JSON **value**
/// internally, so it is parsed here — once, at the boundary — rather than left
/// for each adapter to guess at.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input: Value,
}

/// OpenAI's `function` object inside a `tool_calls[]` entry.
///
/// `arguments` is OPTIONAL here even though OpenAI always emits it: a model
/// that called a no-argument tool may be replayed by a client that dropped the
/// empty string, and refusing that is the same pedantry B-258 was about. Absent
/// or blank normalises to the empty object.
#[derive(Deserialize)]
struct OpenAiToolCallFunctionWire {
    name: String,
    #[serde(default)]
    arguments: Option<String>,
}

/// The two wire shapes a tool CALL can arrive in.
///
/// The discriminator is structural, exactly as [`ToolWire`]'s is: the OpenAI
/// form is the only one with a `function` object, the native form the only one
/// with `input`. `type` is accepted but not required.
#[derive(Deserialize)]
#[serde(untagged)]
enum ToolCallWire {
    OpenAi {
        id: String,
        #[serde(rename = "type", default)]
        _type: Option<String>,
        function: OpenAiToolCallFunctionWire,
    },
    Native {
        id: String,
        name: String,
        input: Value,
    },
}

impl<'de> Deserialize<'de> for ToolCall {
    /// # Errors
    ///
    /// **Fail-CLOSED**, deliberately. A `function.arguments` string that is not
    /// valid JSON is a request we cannot interpret — the adapters would have to
    /// invent a value to proceed — so it is refused with a message that NAMES
    /// the field, and the handler turns that into a 400. It never panics and it
    /// never silently substitutes an empty object: guessing at an
    /// uninterpretable input is the failure mode `CLAUDE.md` §21 forbids.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        Ok(match ToolCallWire::deserialize(deserializer)? {
            ToolCallWire::OpenAi { id, function, .. } => {
                let raw = function.arguments.unwrap_or_default();
                let input = if raw.trim().is_empty() {
                    Value::Object(serde_json::Map::new())
                } else {
                    serde_json::from_str(&raw).map_err(|e| {
                        D::Error::custom(format!(
                            "tool_calls[].function.arguments must be a JSON string \
                             containing a JSON object (got {raw:?}): {e}"
                        ))
                    })?
                };
                Self {
                    id,
                    name: function.name,
                    input,
                }
            }
            ToolCallWire::Native { id, name, input } => Self { id, name, input },
        })
    }
}

/// How the caller wants the model to use the tools it was given.
///
/// # B-355 — what was broken
///
/// `ChatRequest` had no `tool_choice` field at all, and serde ignores unknown
/// fields by default, so `"tool_choice": "required"` was accepted with a 200
/// and **silently discarded**. A caller forcing a tool call got a chat answer
/// and no signal that their instruction had been dropped.
///
/// The internal shape is OpenAI's vocabulary because `/v1/chat/completions` is
/// the OpenAI-compatible endpoint; the Anthropic adapter translates outward
/// (`auto` / `any` / `tool`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolChoice {
    /// `"auto"` — the model decides. Provider default.
    Auto,
    /// `"none"` — the model must not call a tool. Anthropic has no `none`, so
    /// that adapter expresses it by omitting `tools` entirely.
    None,
    /// `"required"` — the model must call SOME tool.
    Required,
    /// `{"type":"function","function":{"name":"…"}}` — this exact tool.
    Function { name: String },
}

#[derive(Deserialize)]
struct ToolChoiceFunctionWire {
    name: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ToolChoiceWire {
    /// `"auto" | "none" | "required"`.
    Mode(String),
    Function {
        #[serde(rename = "type", default)]
        _type: Option<String>,
        function: ToolChoiceFunctionWire,
    },
}

impl<'de> Deserialize<'de> for ToolChoice {
    /// # Errors
    ///
    /// **Fail-CLOSED.** An unrecognised mode string is refused rather than
    /// coerced to `auto` — silently downgrading `"required"` to `"auto"` is the
    /// very defect B-355 is, and doing it deliberately would be worse than the
    /// accident.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        Ok(match ToolChoiceWire::deserialize(deserializer)? {
            ToolChoiceWire::Mode(m) => match m.as_str() {
                "auto" => Self::Auto,
                "none" => Self::None,
                "required" => Self::Required,
                other => {
                    return Err(D::Error::custom(format!(
                        "tool_choice must be \"auto\", \"none\", \"required\", or \
                         {{\"type\":\"function\",\"function\":{{\"name\":…}}}} (got {other:?})"
                    )));
                }
            },
            ToolChoiceWire::Function { function, .. } => Self::Function {
                name: function.name,
            },
        })
    }
}

impl Serialize for ToolChoice {
    /// Serialises back to the OpenAI wire form, so the OpenAI-family adapters
    /// can forward it VERBATIM and a round-trip through the gateway is a no-op.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::None => serializer.serialize_str("none"),
            Self::Required => serializer.serialize_str("required"),
            Self::Function { name } => {
                use serde::ser::SerializeStruct as _;
                let mut s = serializer.serialize_struct("ToolChoice", 2)?;
                s.serialize_field("type", "function")?;
                s.serialize_field("function", &serde_json::json!({ "name": name }))?;
                s.end()
            }
        }
    }
}

/// Universal chat request shape used throughout the gateway.
/// Provider adapters translate from this to provider-native format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// B-355. `default` because it is optional on the wire, and
    /// `skip_serializing_if` so a request that did not carry one serialises
    /// byte-identically to before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// `GWY-48`. Nucleus-sampling cutoff. `default` + `skip_serializing_if` is
    /// the B-355 pattern on `tool_choice` above: a request that did not carry
    /// one serialises byte-identically to before this field existed.
    ///
    /// **Adding this field OBLIGES `semantic_cache::request_key` to hash it.**
    /// Two requests differing only in `top_p` are not interchangeable, and a
    /// shared cache entry would serve the second caller the first caller's
    /// answer — the exact defect B-355 already fixed once for `tool_choice`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// `GWY-48`. Deterministic-sampling seed. Only the OpenAI-compatible wire
    /// has the concept, so only that adapter forwards it (`providers/openai.rs`).
    /// The SPAN records what the CLIENT sent regardless of what the provider can
    /// do with it — that is not a lie, it is the first honest surfacing of a real
    /// client misconfiguration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// `OBS-53`. Opt-in, per request. **The gateway NEVER injects this.** Two
    /// reasons, and the second is the real one: it changes the response body the
    /// client receives, and this gateway is byte-compatible by contract; and it
    /// inflates the payload for a customer who did not ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<bool>,
    /// `OBS-53`. Forwarded verbatim beside `logprobs`; meaningless without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_logprobs: Option<u8>,
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
    #[test]
    fn b360_assistant_content_null_or_absent_decodes_to_empty_text() {
        let with_null: Message = serde_json::from_str(
            r#"{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}]}"#,
        )
        .expect("null content must decode");
        assert!(matches!(with_null.content, MessageContent::Text(ref t) if t.is_empty()));
        assert_eq!(with_null.tool_calls.as_ref().map(Vec::len), Some(1));

        let absent: Message = serde_json::from_str(
            r#"{"role":"assistant","tool_calls":[{"id":"c1","name":"f","input":{}}]}"#,
        )
        .expect("absent content must decode");
        assert!(matches!(absent.content, MessageContent::Text(ref t) if t.is_empty()));

        let text: Message = serde_json::from_str(r#"{"role":"user","content":"hi"}"#).unwrap();
        assert!(matches!(text.content, MessageContent::Text(ref t) if t == "hi"));

        let parts: Message =
            serde_json::from_str(r#"{"role":"user","content":[{"type":"text","text":"hi"}]}"#)
                .unwrap();
        assert!(matches!(parts.content, MessageContent::Parts(ref p) if p.len() == 1));
    }

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

#[cfg(test)]
mod b356_tool_call_wire_tests {
    use super::*;

    /// **THE TEST THAT WOULD HAVE CAUGHT B-356.** The standard multi-turn
    /// tool-use loop: the client appends the assistant message the gateway
    /// returned — OpenAI-shaped `tool_calls`, `arguments` as a JSON STRING —
    /// and sends the history back. Before this fix the whole request failed to
    /// deserialize and the gateway answered HTTP 400 to a body built out of its
    /// own prior output.
    #[test]
    fn an_openai_shaped_tool_call_replayed_into_history_deserializes() {
        let body = r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "weather in Paris?"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "call_abc123",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\",\"unit\":\"c\"}"
                        }
                    }]
                },
                {"role": "tool", "tool_call_id": "call_abc123", "content": "18C"}
            ]
        }"#;
        let req: ChatRequest =
            serde_json::from_str(body).expect("an OpenAI-shaped history must deserialize");
        let calls = req.messages[1]
            .tool_calls
            .as_ref()
            .expect("the assistant message carries tool_calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_abc123");
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[0].input["city"], "Paris");
        // The tool-result message keeps its OpenAI shape too — the field the
        // Anthropic adapter turns into a `tool_result` block.
        assert_eq!(req.messages[2].role, Role::Tool);
        assert_eq!(req.messages[2].tool_call_id.as_deref(), Some("call_abc123"));
    }

    /// Both wire shapes must land on the SAME struct — otherwise the rails and
    /// the adapters see two different things depending on how the caller spelled
    /// it, which is the drift the `Tool` shim (B-258) exists to prevent.
    #[test]
    fn both_shapes_deserialize_to_the_same_struct() {
        let openai: ToolCall = serde_json::from_str(
            r#"{"id":"c1","type":"function",
                "function":{"name":"f","arguments":"{\"a\":1}"}}"#,
        )
        .expect("openai shape");
        let native: ToolCall = serde_json::from_str(r#"{"id":"c1","name":"f","input":{"a":1}}"#)
            .expect("native shape");
        assert_eq!(openai, native);
    }

    /// A tool that takes no arguments: OpenAI emits `"{}"`, a client that
    /// dropped the field emits nothing, and a client that emitted `""` is also
    /// in the wild. All three mean the same thing and none may 400.
    #[test]
    fn an_empty_argument_list_normalises_to_the_empty_object() {
        for raw in [
            r#"{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}"#,
            r#"{"id":"c","type":"function","function":{"name":"f"}}"#,
            r#"{"id":"c","type":"function","function":{"name":"f","arguments":""}}"#,
        ] {
            let tc: ToolCall = serde_json::from_str(raw).expect("no-argument tool call");
            assert_eq!(tc.input, serde_json::json!({}), "input: {raw}");
        }
    }

    /// **The falsifying half.** `arguments` that is not JSON is a request we
    /// cannot interpret. It must ERROR — naming the field so the 400 the
    /// handler builds is actionable — and it must never panic.
    #[test]
    fn a_non_json_arguments_string_errors_naming_the_field_and_never_panics() {
        let err = serde_json::from_str::<ToolCall>(
            r#"{"id":"c","type":"function","function":{"name":"f","arguments":"not json at all"}}"#,
        )
        .expect_err("a non-JSON arguments string must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("tool_calls[].function.arguments"),
            "the error must name the offending field, got: {msg}"
        );
    }

    /// The whole-request path: a malformed `arguments` reaches the handler as a
    /// `serde_json` error on `ChatRequest`, which is what becomes the 400.
    #[test]
    fn a_malformed_tool_call_fails_the_whole_request_rather_than_being_dropped() {
        let body = r#"{
            "model": "gpt-4o",
            "messages": [{
                "role": "assistant", "content": "",
                "tool_calls": [{"id":"c","type":"function",
                    "function":{"name":"f","arguments":"<<<not json>>>"}}]
            }]
        }"#;
        let err = serde_json::from_str::<ChatRequest>(body)
            .expect_err("a malformed tool call must fail the request");
        assert!(err.to_string().contains("arguments"), "{err}");
    }

    /// Genuinely malformed shapes still fail — the guard against an `untagged`
    /// enum that has quietly become "accepts anything".
    #[test]
    fn a_tool_call_with_neither_shape_is_rejected() {
        for bad in [
            r#"{"name":"f","input":{}}"#,  // no id
            r#"{"id":"c"}"#,               // neither function nor name+input
            r#"{"id":"c","name":"f"}"#,    // name without input
            r#"{"id":"c","function":{}}"#, // function without a name
            r#""just a string""#,
        ] {
            assert!(
                serde_json::from_str::<ToolCall>(bad).is_err(),
                "malformed tool call was accepted: {bad}"
            );
        }
    }

    /// Serialization stays NATIVE — `openai.rs` reads `.id/.name/.input` and
    /// builds the nested form itself, and the Anthropic adapter needs the
    /// value, not a string. Changing this silently breaks both adapters.
    #[test]
    fn serialization_stays_in_the_native_shape() {
        let tc = ToolCall {
            id: "c".into(),
            name: "f".into(),
            input: serde_json::json!({"a": 1}),
        };
        assert_eq!(
            serde_json::to_value(&tc).expect("serialize"),
            serde_json::json!({"id":"c","name":"f","input":{"a":1}})
        );
    }
}

#[cfg(test)]
mod b355_tool_choice_tests {
    use super::*;

    /// **THE TEST THAT WOULD HAVE CAUGHT B-355.** `tool_choice` was not a field
    /// at all, so serde ignored it and the caller's instruction was discarded
    /// with a 200 and no signal.
    #[test]
    fn tool_choice_survives_deserialization_instead_of_being_dropped() {
        let body = r#"{
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": "required"
        }"#;
        let req: ChatRequest = serde_json::from_str(body).expect("must deserialize");
        assert_eq!(req.tool_choice, Some(ToolChoice::Required));
    }

    #[test]
    fn every_openai_tool_choice_form_round_trips() {
        for (wire, want) in [
            (r#""auto""#, ToolChoice::Auto),
            (r#""none""#, ToolChoice::None),
            (r#""required""#, ToolChoice::Required),
            (
                r#"{"type":"function","function":{"name":"get_weather"}}"#,
                ToolChoice::Function {
                    name: "get_weather".into(),
                },
            ),
        ] {
            let got: ToolChoice =
                serde_json::from_str(wire).unwrap_or_else(|e| panic!("{wire} must parse: {e}"));
            assert_eq!(got, want, "{wire}");
            // Round-trip: the OpenAI-family adapters forward this VERBATIM, so
            // what comes out must be what a caller could have sent in.
            let back = serde_json::to_value(&got).expect("serialize");
            let orig: serde_json::Value = serde_json::from_str(wire).expect("wire is json");
            assert_eq!(back, orig, "round trip changed the wire form of {wire}");
        }
    }

    /// **The falsifying half.** An unrecognised mode must be REFUSED, not
    /// coerced to `auto` — silently downgrading `"required"` is B-355 itself.
    #[test]
    fn an_unrecognised_tool_choice_is_refused_not_downgraded() {
        for bad in [
            r#""whatever""#,
            r#""ANY""#,
            r#"{"type":"function"}"#,
            r#"42"#,
        ] {
            assert!(
                serde_json::from_str::<ToolChoice>(bad).is_err(),
                "invalid tool_choice was accepted: {bad}"
            );
        }
    }

    /// A request that never mentions `tool_choice` must serialise EXACTLY as it
    /// did before the field existed. This is the no-behaviour-change assertion
    /// for the 94% of traffic that uses no tools at all.
    #[test]
    fn a_request_without_tool_choice_serialises_unchanged() {
        let req = ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            model: "claude-sonnet-4-6".into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hello".into()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            tool_choice: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            system: None,
            metadata: None,
        };
        let v = serde_json::to_value(&req).expect("serialize");
        assert!(
            v.get("tool_choice").is_none(),
            "an absent tool_choice must not reach the wire: {v}"
        );
    }
}
