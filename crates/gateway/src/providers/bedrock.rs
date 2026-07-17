//! AWS Bedrock Converse API adapter.
//!
//! Authenticates with AWS SigV4 (no static API key). Credentials come
//! from `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ optional
//! `AWS_SESSION_TOKEN`). The `api_key` parameter on `chat()` is ignored.
//!
//! Uses the Converse API (`/model/{modelId}/converse`) for V1 — the
//! non-streaming form. Streaming Converse (`converse-stream`) is a
//! follow-up; for failover purposes the buffered response is fine.
//!
//! Supported model id format on the gateway side: `bedrock/{modelId}`,
//! where `modelId` is whatever Bedrock expects (e.g.
//! `anthropic.claude-3-5-sonnet-20241022-v2:0`).
//!
//! Provider keys are never logged — `tracing::instrument` skips both the
//! AWS secret key and the request body.

use anyhow::{Context as _, Result, anyhow, bail};
use async_stream::try_stream;
use chrono::Utc;
use reqwest::Client;
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tracing::instrument;

use tracelane_shared::{
    ChatRequest, ChatResponse, Choice, Message, MessageContent, Role, TenantId, ToolCall, Usage,
};

use crate::providers::{ProviderEvent, ProviderStream};

const SERVICE: &str = "bedrock";
const SIGNING_ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// AWS Bedrock Converse API adapter.
pub struct BedrockProvider {
    client: Client,
    region: String,
}

impl BedrockProvider {
    pub fn new() -> anyhow::Result<Self> {
        let region = std::env::var("AWS_DEFAULT_REGION")
            .or_else(|_| std::env::var("AWS_REGION"))
            .unwrap_or_else(|_| "us-east-1".into());

        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(Duration::from_secs(300))
                .build()
                .context("build Bedrock reqwest client")?,
            region,
        })
    }

    /// Send a chat request through Bedrock Converse.
    ///
    /// Resolves credentials from the AWS environment, signs with SigV4,
    /// posts to `https://bedrock-runtime.{region}.amazonaws.com/model/{modelId}/converse`,
    /// and yields a single `Done` event with the buffered response.
    #[instrument(skip(self, request, _api_key), fields(
        tenant_id = %tenant_id,
        model = %request.model,
        provider = "bedrock",
        region = %self.region,
    ))]
    pub async fn chat(
        &self,
        request: ChatRequest,
        _api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let _ = tenant_id; // logged via instrument fields

        let creds = AwsCredentials::from_env()
            .context("Bedrock requires AWS credentials in the environment")?;

        let model_id = request
            .model
            .strip_prefix("bedrock/")
            .unwrap_or(&request.model)
            .to_owned();

        let converse = ConverseRequest::from_universal(&request)?;
        let body_json =
            serde_json::to_vec(&converse).context("failed to serialise Converse body")?;

        let host = format!("bedrock-runtime.{}.amazonaws.com", self.region);
        let path = format!("/model/{model_id}/converse");
        let url = format!("https://{host}{path}");

        // always AWS public, but config injection (AWS_BEDROCK_BASE_URL or
        // region override) could redirect this — validate every hop.
        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected Bedrock URL")?;

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let payload_hash = sha256_hex(&body_json);
        let signed = SignableRequest {
            method: "POST",
            host: &host,
            path: &path,
            query: "",
            payload_hash: &payload_hash,
            amz_date: &amz_date,
            date_stamp: &date_stamp,
            region: &self.region,
            session_token: creds.session_token.as_deref(),
        };
        let auth_header = signed.sign(&creds);

        let mut req = self
            .client
            .post(&url)
            .header("host", &host)
            .header("content-type", "application/json")
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("authorization", auth_header)
            .body(body_json.clone());

        if let Some(token) = signed.session_token {
            req = req.header("x-amz-security-token", token);
        }

        let response = req
            .send()
            .await
            .context("failed to send request to Bedrock Converse")?;

        let status = response.status();
        if !status.is_success() {
            // the X-Amz-Security-Token or the request's authorization
            // signature in error responses.
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(status = %status, "Bedrock Converse error");
            bail!("Bedrock Converse error: status {status}");
        }

        let bytes = response
            .bytes()
            .await
            .context("failed to read Bedrock response body")?;
        let parsed: ConverseResponse =
            serde_json::from_slice(&bytes).context("failed to parse Bedrock Converse response")?;
        let chat_response = parsed.into_universal(&request.model);
        let text = match chat_response.choices.first() {
            Some(choice) => match &choice.message.content {
                MessageContent::Text(t) => t.clone(),
                MessageContent::Parts(_) => String::new(),
            },
            None => String::new(),
        };

        let stream = try_stream! {
            if !text.is_empty() {
                yield ProviderEvent::StreamChunk { delta: text };
            }
            yield ProviderEvent::Done { response: chat_response };
        };
        Ok(Box::pin(stream))
    }
}

// A14: `Default` removed — `new()` is now fallible (see ProviderRegistry).

// ── AWS credentials ─────────────────────────────────────────────────────────

struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl AwsCredentials {
    fn from_env() -> Result<Self> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| anyhow!("AWS_ACCESS_KEY_ID missing from environment"))?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| anyhow!("AWS_SECRET_ACCESS_KEY missing from environment"))?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }
}

// ── SigV4 ──────────────────────────────────────────────────────────────────

struct SignableRequest<'a> {
    method: &'a str,
    host: &'a str,
    path: &'a str,
    query: &'a str,
    payload_hash: &'a str,
    amz_date: &'a str,
    date_stamp: &'a str,
    region: &'a str,
    session_token: Option<&'a str>,
}

impl<'a> SignableRequest<'a> {
    /// Produce the value of the `Authorization` header for this request.
    /// The header set sent on the wire MUST exactly match the headers
    /// listed here; any drift will produce a `SignatureDoesNotMatch`.
    fn sign(&self, creds: &AwsCredentials) -> String {
        // 1. Canonical request
        let mut signed_headers_pairs: Vec<(String, String)> = vec![
            ("content-type".into(), "application/json".into()),
            ("host".into(), self.host.into()),
            ("x-amz-content-sha256".into(), self.payload_hash.into()),
            ("x-amz-date".into(), self.amz_date.into()),
        ];
        if let Some(token) = self.session_token {
            signed_headers_pairs.push(("x-amz-security-token".into(), token.into()));
        }
        signed_headers_pairs.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers = signed_headers_pairs
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
            .collect::<String>();
        let signed_headers = signed_headers_pairs
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "{method}\n{path}\n{query}\n{headers}\n{signed}\n{payload}",
            method = self.method,
            path = self.path,
            query = self.query,
            headers = canonical_headers,
            signed = signed_headers,
            payload = self.payload_hash,
        );

        // 2. String to sign
        let credential_scope = format!(
            "{date}/{region}/{service}/aws4_request",
            date = self.date_stamp,
            region = self.region,
            service = SERVICE
        );
        let string_to_sign = format!(
            "{alg}\n{date}\n{scope}\n{hash}",
            alg = SIGNING_ALGORITHM,
            date = self.amz_date,
            scope = credential_scope,
            hash = sha256_hex(canonical_request.as_bytes()),
        );

        // 3. Signing key (HMAC chain)
        let k_secret = format!("AWS4{}", creds.secret_access_key);
        let k_date = hmac_sha256(k_secret.as_bytes(), self.date_stamp.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");

        // 4. Signature
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        format!(
            "{alg} Credential={ak}/{scope}, SignedHeaders={signed}, Signature={sig}",
            alg = SIGNING_ALGORITHM,
            ak = creds.access_key_id,
            scope = credential_scope,
            signed = signed_headers,
            sig = signature,
        )
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use ring::digest::{SHA256, digest};
    hex::encode(digest(&SHA256, bytes))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

// ── Converse request / response ─────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ConverseRequest {
    #[serde(rename = "toolConfig", skip_serializing_if = "Option::is_none")]
    tool_config: Option<Value>,
    messages: Vec<ConverseMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    system: Vec<ConverseSystemBlock>,
    #[serde(rename = "inferenceConfig", skip_serializing_if = "Option::is_none")]
    inference_config: Option<InferenceConfig>,
}

#[derive(Debug, Serialize)]
struct ConverseMessage {
    role: &'static str,
    content: Vec<ConverseContentBlock>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ConverseContentBlock {
    Text { text: String },
}

#[derive(Debug, Serialize)]
struct ConverseSystemBlock {
    text: String,
}

#[derive(Debug, Serialize)]
struct InferenceConfig {
    #[serde(rename = "maxTokens", skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

impl ConverseRequest {
    fn from_universal(req: &ChatRequest) -> Result<Self> {
        let mut system: Vec<ConverseSystemBlock> = Vec::new();
        let mut messages: Vec<ConverseMessage> = Vec::new();

        // The universal ChatRequest has a top-level `system: Option<String>`
        // AND can encode system messages via `Role::System`. Honour both.
        if let Some(sys) = req.system.clone() {
            if !sys.is_empty() {
                system.push(ConverseSystemBlock { text: sys });
            }
        }

        for m in &req.messages {
            let text = match &m.content {
                MessageContent::Text(t) => t.clone(),
                MessageContent::Parts(parts) => parts
                    .iter()
                    .filter_map(|p| match p {
                        tracelane_shared::ContentPart::Text { text, .. } => Some(text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(""),
            };
            match m.role {
                Role::System => system.push(ConverseSystemBlock { text }),
                Role::User => messages.push(ConverseMessage {
                    role: "user",
                    content: vec![ConverseContentBlock::Text { text }],
                }),
                Role::Assistant => messages.push(ConverseMessage {
                    role: "assistant",
                    content: vec![ConverseContentBlock::Text { text }],
                }),
                Role::Tool => {
                    // Bedrock tool-result blocks need a typed shape; for V1
                    // we coerce to user text so the failover path doesn't
                    // drop the message entirely.
                    messages.push(ConverseMessage {
                        role: "user",
                        content: vec![ConverseContentBlock::Text {
                            text: format!("[tool result] {text}"),
                        }],
                    });
                }
            }
        }

        if messages.is_empty() {
            bail!("Converse request requires at least one user/assistant message");
        }

        let inference_config = if req.max_tokens.is_some() || req.temperature.is_some() {
            Some(InferenceConfig {
                max_tokens: req.max_tokens,
                temperature: req.temperature,
            })
        } else {
            None
        };

        // Previously dropped — a tool-bearing request silently degraded to
        // plain chat on Bedrock.
        let tool_config = req.tools.as_ref().filter(|t| !t.is_empty()).map(|tools| {
            let specs: Vec<Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "toolSpec": {
                            "name": t.name,
                            "description": t.description.as_deref().unwrap_or(""),
                            "inputSchema": { "json": t.input_schema },
                        }
                    })
                })
                .collect();
            serde_json::json!({ "tools": specs })
        });

        Ok(Self {
            messages,
            system,
            inference_config,
            tool_config,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ConverseResponse {
    output: ConverseOutput,
    #[serde(default)]
    usage: Option<ConverseUsage>,
    #[serde(rename = "stopReason", default)]
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConverseOutput {
    message: ConverseRespMessage,
}

#[derive(Debug, Deserialize)]
struct ConverseRespMessage {
    role: String,
    content: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct ConverseUsage {
    #[serde(rename = "inputTokens")]
    input_tokens: u32,
    #[serde(rename = "outputTokens")]
    output_tokens: u32,
}

impl ConverseResponse {
    fn into_universal(self, model: &str) -> ChatResponse {
        let text = self
            .output
            .message
            .content
            .iter()
            .filter_map(|block| block.get("text").and_then(|t| t.as_str()).map(String::from))
            .collect::<Vec<_>>()
            .join("");

        let role = match self.output.message.role.as_str() {
            "assistant" => Role::Assistant,
            "user" => Role::User,
            _ => Role::Assistant,
        };

        let usage = self.usage.map(|u| Usage {
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        });

        // asking for a tool call surfaced as empty text with no tool_calls.
        let tool_calls: Vec<ToolCall> = self
            .output
            .message
            .content
            .iter()
            .filter_map(|block| block.get("toolUse"))
            .map(|tu| ToolCall {
                id: tu
                    .get("toolUseId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: tu
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                input: tu.get("input").cloned().unwrap_or(Value::Null),
            })
            .collect();

        ChatResponse {
            id: format!("bedrock-{}", uuid::Uuid::new_v4()),
            model: model.to_string(),
            choices: vec![Choice {
                index: 0,
                message: Message {
                    role,
                    content: MessageContent::Text(text),
                    tool_calls: (!tool_calls.is_empty()).then_some(tool_calls),
                    tool_call_id: None,
                },
                finish_reason: self.stop_reason,
            }],
            usage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4_signing_key_known_vector() {
        // From AWS docs:
        // Date 20150830, region us-east-1, service iam, secret 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        // produces signing key c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9.
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let date = "20150830";
        let region = "us-east-1";
        let service = "iam";

        let k_secret = format!("AWS4{secret}");
        let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");

        assert_eq!(
            hex::encode(&k_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    fn user_msg(text: &str) -> Message {
        Message {
            role: Role::User,
            content: MessageContent::Text(text.into()),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    fn make_request(
        messages: Vec<Message>,
        max_tokens: Option<u32>,
        temp: Option<f32>,
    ) -> ChatRequest {
        ChatRequest {
            model: "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0".into(),
            messages,
            tools: None,
            max_tokens,
            temperature: temp,
            stream: Some(false),
            system: None,
            metadata: None,
        }
    }

    #[test]
    fn converse_request_translates_text_message() {
        let req = make_request(vec![user_msg("hello")], Some(256), Some(0.7));
        let converse = ConverseRequest::from_universal(&req).unwrap();
        assert_eq!(converse.messages.len(), 1);
        assert_eq!(converse.messages[0].role, "user");
        assert!(converse.system.is_empty());
        assert!(converse.inference_config.is_some());
    }

    #[test]
    fn converse_request_extracts_top_level_system() {
        let mut req = make_request(vec![user_msg("hi")], None, None);
        req.system = Some("You are helpful.".into());
        let converse = ConverseRequest::from_universal(&req).unwrap();
        assert_eq!(converse.system.len(), 1);
        assert_eq!(converse.system[0].text, "You are helpful.");
        assert_eq!(converse.messages.len(), 1);
    }

    #[test]
    fn converse_request_extracts_role_system_message() {
        let req = make_request(
            vec![
                Message {
                    role: Role::System,
                    content: MessageContent::Text("Be concise.".into()),
                    tool_calls: None,
                    tool_call_id: None,
                },
                user_msg("hi"),
            ],
            None,
            None,
        );
        let converse = ConverseRequest::from_universal(&req).unwrap();
        assert_eq!(converse.system.len(), 1);
        assert_eq!(converse.system[0].text, "Be concise.");
        assert_eq!(converse.messages.len(), 1);
    }

    #[test]
    fn converse_request_rejects_empty_messages() {
        let req = make_request(vec![], None, None);
        assert!(ConverseRequest::from_universal(&req).is_err());
    }

    #[test]
    fn converse_response_round_trips_text_choice() {
        let raw = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "hi there"}]
                }
            },
            "stopReason": "end_turn",
            "usage": { "inputTokens": 10, "outputTokens": 5 }
        });
        let parsed: ConverseResponse = serde_json::from_value(raw).unwrap();
        let resp = parsed.into_universal("bedrock/test-model");
        assert_eq!(resp.choices.len(), 1);
        let choice = &resp.choices[0];
        if let MessageContent::Text(t) = &choice.message.content {
            assert_eq!(t, "hi there");
        } else {
            panic!("expected text content");
        }
        assert_eq!(resp.usage.as_ref().unwrap().input_tokens, 10);
        assert_eq!(resp.usage.as_ref().unwrap().output_tokens, 5);
    }

    /// `toolConfig` (previously silently dropped — Bedrock degraded to
    /// plain chat).
    #[test]
    fn converse_request_carries_tool_config() {
        let mut req = make_request(vec![user_msg("weather in Bangalore?")], None, None);
        req.tools = Some(vec![tracelane_shared::Tool {
            name: "get_weather".into(),
            description: Some("Look up current weather".into()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "city": { "type": "string" } },
                "required": ["city"]
            }),
        }]);
        let converse = ConverseRequest::from_universal(&req).unwrap();
        // Wire body FIRST (serialization borrows), then consume tool_config.
        let wire = serde_json::to_value(&converse).unwrap();
        assert!(wire.get("toolConfig").is_some(), "wire body: {wire}");
        let tc = converse.tool_config.expect("toolConfig must be present");
        assert_eq!(tc["tools"][0]["toolSpec"]["name"], "get_weather");
        assert_eq!(
            tc["tools"][0]["toolSpec"]["inputSchema"]["json"]["required"][0],
            "city"
        );
    }

    /// tool_calls with intact usage (previously dropped: empty text, no
    /// tool_calls, usage-only).
    #[test]
    fn converse_response_extracts_tool_use_and_usage() {
        let raw = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "Checking the weather."},
                        {"toolUse": {
                            "toolUseId": "tooluse_b067",
                            "name": "get_weather",
                            "input": {"city": "Bangalore"}
                        }}
                    ]
                }
            },
            "stopReason": "tool_use",
            "usage": { "inputTokens": 42, "outputTokens": 17 }
        });
        let parsed: ConverseResponse = serde_json::from_value(raw).unwrap();
        let resp = parsed.into_universal("bedrock/test-model");
        let choice = &resp.choices[0];
        let calls = choice
            .message
            .tool_calls
            .as_ref()
            .expect("toolUse must surface as tool_calls (previously dropped)");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "tooluse_b067");
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[0].input, serde_json::json!({"city": "Bangalore"}));
        if let MessageContent::Text(t) = &choice.message.content {
            assert_eq!(t, "Checking the weather.");
        } else {
            panic!("expected text content alongside tool_calls");
        }
        assert_eq!(resp.usage.as_ref().unwrap().input_tokens, 42);
        assert_eq!(resp.usage.as_ref().unwrap().output_tokens, 17);
    }

    #[test]
    fn signable_request_builds_authorization_header() {
        let creds = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let payload_hash = sha256_hex(b"{}");
        let req = SignableRequest {
            method: "POST",
            host: "bedrock-runtime.us-east-1.amazonaws.com",
            path: "/model/test/converse",
            query: "",
            payload_hash: &payload_hash,
            amz_date: "20260101T000000Z",
            date_stamp: "20260101",
            region: "us-east-1",
            session_token: None,
        };
        let header = req.sign(&creds);
        assert!(header.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/bedrock/aws4_request"
        ));
        assert!(header.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"));
        assert!(header.contains("Signature="));
    }
}
