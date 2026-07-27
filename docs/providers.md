# Providers

Tracelane gateway speaks to **30+ LLM providers** through a single API surface
(OpenAI-compatible `/v1/chat/completions` and Anthropic-compatible
`/v1/messages`). You point at `https://gateway.tracelane.dev`, set the model
string, and we route + failover for you.

## Supported providers

### Dedicated adapters (6)

These have purpose-built request/response translators because their API
shape differs enough from OpenAI's that a generic adapter would lose
fidelity (think Bedrock SigV4, Anthropic's `messages` API, Google's
multi-modal parts).

| Provider | Model prefix | Auth env var | API style |
|---|---|---|---|
| Anthropic | `claude-*`, `anthropic/*` | `ANTHROPIC_API_KEY` | Native `/v1/messages` |
| OpenAI | `gpt-*`, `o1*`, `o3*`, `openai/*` | `OPENAI_API_KEY` | Native `/v1/chat/completions` |
| Google Gemini | `gemini-*`, `google/*` | `GOOGLE_API_KEY` | Native generateContent |
| AWS Bedrock | `bedrock/*` | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_REGION`) | SigV4-signed Converse API |
| Azure OpenAI | `azure/*` | `AZURE_OPENAI_API_KEY` (+ `AZURE_OPENAI_ENDPOINT`) | OpenAI shape, deployment-routed |
| Cohere | `command-*`, `cohere/*` | `COHERE_API_KEY` | Native `/v2/chat` |

### OpenAI-compatible adapters (29)

These all speak the OpenAI Chat Completions wire format. We auto-route by
model prefix; per-tenant overrides go in `tracelane.yaml`.

| Provider | Default base URL | Auth env var |
|---|---|---|
| Together AI | `api.together.xyz` | `TOGETHER_API_KEY` |
| Fireworks | `api.fireworks.ai/inference` | `FIREWORKS_API_KEY` |
| Groq | `api.groq.com/openai` | `GROQ_API_KEY` |
| OpenRouter | `openrouter.ai/api` | `OPENROUTER_API_KEY` |
| Mistral | `api.mistral.ai` | `MISTRAL_API_KEY` |
| Perplexity | `api.perplexity.ai` | `PERPLEXITY_API_KEY` |
| DeepSeek | `api.deepseek.com` | `DEEPSEEK_API_KEY` |
| xAI | `api.x.ai` | `XAI_API_KEY` |
| NVIDIA NIM | `integrate.api.nvidia.com` | `NVIDIA_API_KEY` |
| Cerebras | `api.cerebras.ai` | `CEREBRAS_API_KEY` |
| SambaNova | `api.sambanova.ai` | `SAMBANOVA_API_KEY` |
| Lepton | `*.lepton.run` | `LEPTON_API_KEY` |
| Lambda | `api.lambdalabs.com` | `LAMBDA_API_KEY` |
| Novita | `api.novita.ai` | `NOVITA_API_KEY` |
| AI21 | `api.ai21.com` | `AI21_API_KEY` |
| Hyperbolic | `api.hyperbolic.xyz` | `HYPERBOLIC_API_KEY` |
| DeepInfra | `api.deepinfra.com` | `DEEPINFRA_API_KEY` |
| Cloudflare Workers AI | `gateway.ai.cloudflare.com/.../openai` | `CLOUDFLARE_API_KEY` |
| Ollama | `localhost:11434` | (none — local) |
| Baseten | `bridge.baseten.co/v1/direct` | `BASETEN_API_KEY` |
| Hugging Face | `api-inference.huggingface.co` | `HUGGINGFACE_API_KEY` |
| Anyscale | `api.endpoints.anyscale.com` | `ANYSCALE_API_KEY` |
| Modal | `api.modal.com/v1/openai` | `MODAL_API_KEY` |
| Predibase | `serving.app.predibase.com` | `PREDIBASE_API_KEY` |
| Moonshot | `api.moonshot.cn` | `MOONSHOT_API_KEY` |
| Upstage | `api.upstage.ai` | `UPSTAGE_API_KEY` |
| 01.AI / Yi | `api.01.ai` | `YI_API_KEY` |
| Aleph Alpha | `api.aleph-alpha.com` | `ALEPH_ALPHA_API_KEY` |

Each base URL is overridable via `<PROVIDER>_BASE_URL` for self-hosted or
private-link deployments.

## Routing

Tracelane routes by model-string prefix. Examples:

```
claude-sonnet-4.5                → Anthropic
gpt-5-codex                      → OpenAI
gemini-3-pro                     → Google
bedrock/anthropic.claude-3-5...  → AWS Bedrock
azure/gpt-4o-mini                → Azure OpenAI
together/Qwen2.5-72B-Instruct    → Together AI
groq/llama-3.3-70b-versatile     → Groq
ollama/llama3.2:3b               → local Ollama
```

If your model name doesn't match a built-in prefix, set the routing
explicitly in `tracelane.yaml`:

```yaml
models:
  my-internal-fast:
    provider: groq
    upstream_model: llama-3.3-70b-versatile
  my-internal-smart:
    provider: anthropic
    upstream_model: claude-sonnet-4.5
```

## Failover

Configure a fallback chain per logical model. If the primary returns 5xx,
429, or times out past the configured budget, we try the next provider in
the chain — same request, translated to the target provider's wire format.

```yaml
models:
  sonnet-fallback-chain:
    primary:
      provider: anthropic
      upstream_model: claude-sonnet-4.5
    fallbacks:
      - { provider: openai,   upstream_model: gpt-5 }
      - { provider: google,   upstream_model: gemini-3-pro }
    timeout_ms: 30000
    retry_on: [503, 504, 429, network]
```

The recommended production fallback chain is **Anthropic Sonnet → OpenAI
gpt-5 → Gemini 3 Pro**. The gateway adds the `x-tracelane-failover` header
to the response when a fallback served the request, with the original
provider's status code in `x-tracelane-failover-from`.

See [`crates/gateway/src/providers/failover.rs`](./../crates/gateway/src/providers/failover.rs) for the implementation.

## BYOK only (V1)

V1 ships **bring-your-own-key (BYOK) only**. Provider API keys are
envelope-encrypted at rest with libsodium and decrypted in-memory just-in-time
on dispatch — they never appear in logs, spans, or error messages. The
`tracing` redaction filter strips them from any structured field that lands
in OTLP exports.

**No managed billing for upstream providers in V1.** You bring your own
provider keys; Tracelane bills only for its gateway/observability/audit
SKUs. The same envelope-encryption flow accepts AWS/Azure credentials for
Bedrock and Azure OpenAI respectively.

## Provider-specific behavior

### Anthropic
- Native `/v1/messages` is the canonical endpoint. We translate from OpenAI
  shape on `/v1/chat/completions` if the model is `claude-*`.
- `prompt_caching` is preserved (`cache_control` blocks pass through).
- `tool_use` blocks pass through unchanged.

### OpenAI
- Both `/v1/chat/completions` and `/v1/responses` are accepted.
- Function calling preserved across the failover chain.

### Google Gemini
- Multi-modal parts (image, audio, video) supported.
- `safetySettings` and `generationConfig` pass through.
- Counts as multi-modal billing if any non-text part is present.

### AWS Bedrock
- SigV4 signing inline, no `aws-sdk-rust` dependency (keeps gateway size down).
- Per-region routing via `AWS_REGION`.
- Converse API is the unified entry; legacy InvokeModel falls back per model.

### Azure OpenAI
- Deployment names route through `AZURE_OPENAI_ENDPOINT/openai/deployments/<name>`.
- Map deployment name → logical model in `tracelane.yaml`.

### Cohere
- Native `/v2/chat` for chat completions, `/v2/rerank` for reranking.
- Reranking emits its own span type (`cohere.rerank`) and is observable.

### Ollama (local)
- Defaults to `localhost:11434` — meant for local dev, never production.
- Skips BYOK envelope (no key to encrypt).

## Smoke tests

Each adapter has a wiremock-backed smoke test in
[`crates/gateway/src/providers/smoke_tests.rs`](./../crates/gateway/src/providers/smoke_tests.rs):
single-shot completion, streaming, tool-use, error mapping. Run with:

```bash
cargo test -p gateway providers::smoke_tests
```

These run with `MOCK_PROVIDERS=1` and never hit the real network — they
catch wire-format drift before it reaches a customer.

## Adding a new provider

1. If OpenAI-compatible: add an entry under "OpenAI-compatible adapters" in
   `crates/gateway/src/providers/mod.rs` (env var + base URL).
2. If a custom shape: add a dedicated adapter file (`my_provider.rs`)
   alongside `anthropic.rs` / `google.rs`.
3. Add prefix → provider mapping in `ProviderRegistry::api_key_env_var`.
4. Add a smoke test in `smoke_tests.rs`.
5. Add to this file's table.
6. ADR if the provider's wire format introduces a new edge case (e.g.,
   non-JSON streaming, non-standard tool format).

## Related

- [API reference](./api-reference.md) — `/v1/messages`, `/v1/chat/completions` surfaces
- [Architecture](./architecture.md) — gateway data flow
- [`crates/gateway/src/providers/`](./../crates/gateway/src/providers/) — adapters source
- [`decisions/ADR-006-byok-envelope-encryption.md`](./../decisions/) — key handling
