//! Azure OpenAI adapter.
//!
//! Azure OpenAI uses deployment-scoped URLs:
//!   https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<ver>
//!
//! The `api-key` header replaces `Authorization: Bearer`.
//! Streaming and request shape are otherwise identical to OpenAI.
//!
//! Configuration env vars:
//!   AZURE_OPENAI_ENDPOINT   — https://<resource>.openai.azure.com
//!   AZURE_OPENAI_API_KEY    — Azure API key (or use Entra managed identity)
//!   AZURE_OPENAI_API_VERSION — defaults to 2025-01-01-preview

use anyhow::{Context as _, Result};
use async_stream::try_stream;
use bytes::Bytes;
use futures::Stream;
use reqwest::Client;
use serde_json::Value;
use tracing::instrument;

use crate::providers::{ProviderEvent, ProviderStream};
use tracelane_shared::{ChatRequest, TenantId};

/// Azure OpenAI Chat Completions adapter.
///
/// The deployment is inferred from the `model` field in the request:
///   model = "azure/gpt-4o" → deployment = "gpt-4o"
///   model = "gpt-4o"       → deployment = "gpt-4o"
pub struct AzureOpenAiProvider {
    client: Client,
    endpoint: String,
    api_version: String,
}

impl AzureOpenAiProvider {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build Azure reqwest client")?,
            endpoint: std::env::var("AZURE_OPENAI_ENDPOINT")
                .unwrap_or_else(|_| "https://tracelane.openai.azure.com".into()),
            api_version: std::env::var("AZURE_OPENAI_API_VERSION")
                .unwrap_or_else(|_| "2025-01-01-preview".into()),
        })
    }

    /// Construct against an explicit endpoint + API version, reading no process
    /// env. Used by `providers::smoke_tests` so the parallel suite never
    /// mutates env.
    #[cfg(test)]
    pub(crate) fn for_endpoint(
        endpoint: impl Into<String>,
        api_version: impl Into<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build Azure reqwest client")?,
            endpoint: endpoint.into(),
            api_version: api_version.into(),
        })
    }

    /// Deployment name from model field (`azure/gpt-4o` → `gpt-4o`, `gpt-4o` → `gpt-4o`).
    fn deployment(model: &str) -> &str {
        model.strip_prefix("azure/").unwrap_or(model)
    }

    #[instrument(skip(self, request, api_key), fields(tenant_id = %tenant_id, provider = "azure"))]
    pub async fn chat(
        &self,
        request: ChatRequest,
        api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let deployment = Self::deployment(&request.model).to_owned();
        let url = format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            self.endpoint, deployment, self.api_version
        );

        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected Azure endpoint")?;

        // Translate to OpenAI wire format
        let mut body = serde_json::to_value(&request).context("serialise request")?;
        // Remove model from body — Azure uses deployment URL instead
        if let Value::Object(ref mut m) = body {
            m.remove("model");
            m.insert("stream".into(), Value::Bool(true));
            m.insert(
                "stream_options".into(),
                serde_json::json!({ "include_usage": true }),
            );
        }

        let response = self
            .client
            .post(&url)
            .header("api-key", api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("azure openai request")?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            // api-key header value in 401 responses.
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(status, "Azure OpenAI API error");
            anyhow::bail!("azure openai error: status {status}");
        }

        // Reuse OpenAI SSE parsing by delegating to the openai module's stream parser
        let mut byte_stream = response.bytes_stream();
        let stream = try_stream! {
            use futures::StreamExt as _;
            let mut buf = String::new();
            while let Some(chunk) = byte_stream.next().await {
                let chunk: Bytes = chunk.context("stream chunk")?;
                buf.push_str(&String::from_utf8_lossy(&chunk));
                let lines: Vec<String> = buf.split('\n').map(str::to_owned).collect();
                let last = lines.len().saturating_sub(1);
                buf = lines[last].clone();
                for line in &lines[..last] {
                    let line = line.trim();
                    if let Some(data) = line.strip_prefix("data: ") {
                        if data == "[DONE]" { return; }
                        if let Ok(v) = serde_json::from_str::<Value>(data) {
                            if let Some(delta) = v["choices"][0]["delta"]["content"].as_str() {
                                yield ProviderEvent::StreamChunk { delta: delta.to_owned() };
                            }
                            // OpenAI shape; these were previously DROPPED.
                            if let Some(tool_calls) = v["choices"][0]["delta"]["tool_calls"].as_array() {
                                for tc in tool_calls {
                                    yield ProviderEvent::ToolCallDelta {
                                        index: tc["index"].as_u64().unwrap_or(0) as usize,
                                        id: tc["id"].as_str().map(str::to_owned),
                                        name: tc["function"]["name"].as_str().map(str::to_owned),
                                        input_delta: tc["function"]["arguments"]
                                            .as_str()
                                            .unwrap_or("")
                                            .to_owned(),
                                    };
                                }
                            }
                            if let Some(usage) = v.get("usage").filter(|u| !u.is_null()) {
                                yield ProviderEvent::UsageUpdate {
                                    input_tokens: usage["prompt_tokens"].as_u64().unwrap_or(0) as u32,
                                    output_tokens: usage["completion_tokens"].as_u64().unwrap_or(0) as u32,
                                    cache_read: None,
                                    cache_creation: None,
                                    cost_usd: None,
                                };
                            }
                        }
                    }
                }
            }
        };
        Ok(Box::pin(stream))
    }
}
