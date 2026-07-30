//! Provider adapter layer for the Tracelane gateway.
//!
//! Each sub-module translates the universal `ChatRequest` format into the
//! provider-specific wire format, handles SSE streaming, and emits `ProviderEvent`
//! items that the gateway aggregates into a response stream.
//!
//! Providers registered here (35 routable — 7 native adapters + 28 OpenAI-compatible):
//!   Dedicated adapters: Anthropic, OpenAI, Google Gemini (AI Studio),
//!                       Google Vertex AI, AWS Bedrock, Azure OpenAI, Cohere
//!   OpenAI-compatible:  Together, Fireworks, Groq, OpenRouter, Mistral,
//!                       Perplexity, DeepSeek, xAI, Nvidia NIM, Cerebras,
//!                       Sambanova, Lepton, Lambda, Novita, AI21, Hyperbolic,
//!                       DeepInfra, Cloudflare Workers AI, Ollama, Baseten,
//!                       Hugging Face TGI, Anyscale, Modal, Predibase,
//!                       Moonshot, Upstage, 01.AI, Aleph Alpha

use anyhow::Result;
use async_stream::try_stream;
use futures::Stream;
use std::pin::Pin;
use tracing::instrument;

/// An upstream provider returned a non-success HTTP status.
///
/// Carries the status code so the gateway can distinguish an **auth rejection**
/// (401/403 → the tenant's BYOK provider key was rejected; surface
/// `provider_key_rejected`) from an **availability** failure (5xx / timeout →
/// 502). The upstream response BODY is deliberately NOT carried — provider
/// so only the structured status survives.
///
/// Adapters return this (via `anyhow`) on a non-2xx upstream response; the chat
/// handler recovers it with `downcast_ref::<ProviderHttpError>()`.
#[derive(Debug, thiserror::Error)]
#[error("{provider} upstream error: status {status}")]
pub struct ProviderHttpError {
    pub provider: &'static str,
    pub status: u16,
    /// Machine-readable upstream reason token (e.g. `API_KEY_INVALID`), when the
    /// provider supplies one AND it passes [`safe_reason`].
    ///
    /// API key with **400 `INVALID_ARGUMENT` / `API_KEY_INVALID`** — verified live
    /// 2026-07-17 — not 401. A bare 400 is ambiguous (malformed request vs dead
    /// key), so without the reason we cannot tell a customer their key died, and
    /// it surfaces as an opaque 502 that reads as OUR outage.
    ///
    /// Never the upstream `message`: that is free text, and `security.md` R2 C-3
    /// holds that provider error bodies can echo the credential. Only a validated
    /// enum-shaped token gets in here — see [`safe_reason`].
    pub reason: Option<String>,
}

/// Accept an upstream reason token only if it is structurally incapable of
/// carrying a credential: SHOUTY_SNAKE_CASE, `[A-Z0-9_]`, ≤64 chars.
///
/// This is the security boundary that lets us read anything at all out of a
/// provider error body. An API key (`AIzaSy…`, `AQ.Ab…`, `sk-…`) is mixed-case
/// and/or punctuated, so it cannot satisfy this shape — the guard fails closed on
/// anything surprising rather than trusting the provider's field naming.
#[must_use]
pub fn safe_reason(raw: &str) -> Option<String> {
    let ok = !raw.is_empty()
        && raw.len() <= 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    ok.then(|| raw.to_owned())
}

/// Extract a safe reason token from a provider's JSON error body.
///
/// Reads ONLY structured tokens — Google/GCP shape:
/// `error.details[].reason`, falling back to `error.status`. The free-text
/// `error.message` is never touched. Returns `None` for any body we don't
/// recognise, so a provider that changes its shape degrades to today's behaviour
/// (status-only) rather than leaking or misreporting.
#[must_use]
pub fn reason_from_body(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let err = v.get("error")?;
    if let Some(details) = err.get("details").and_then(|d| d.as_array()) {
        for d in details {
            if let Some(r) = d.get("reason").and_then(|r| r.as_str()) {
                if let Some(safe) = safe_reason(r) {
                    return Some(safe);
                }
            }
        }
    }
    err.get("status")
        .and_then(|s| s.as_str())
        .and_then(safe_reason)
}

impl ProviderHttpError {
    /// True when the upstream rejected the credential itself — the tenant's key is
    /// wrong/expired/retired, not a transient outage. Drives the
    ///
    /// Two shapes:
    ///   - **401 / 403** — the classic status-level rejection.
    ///     NOT a rejection (it is usually a malformed request); only a 400 whose
    ///     reason names the key qualifies.
    #[must_use]
    pub fn is_auth_rejection(&self) -> bool {
        if matches!(self.status, 401 | 403) {
            return true;
        }
        self.status == 400
            && self
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("API_KEY") || r.contains("CREDENTIAL"))
    }

    /// True when the upstream rate-limited or exhausted quota (429). The caller
    /// should surface 429 — telling a caller "provider unavailable" when they are
    #[must_use]
    pub fn is_rate_limited(&self) -> bool {
        self.status == 429
    }

    /// True when the upstream says the model does not exist (404). Distinct from
    /// Observed live 2026-07-17 — AI Studio 404s models "no longer available to
    /// new users", which as a 502 read as a Tracelane outage.
    #[must_use]
    pub fn is_model_not_found(&self) -> bool {
        self.status == 404
    }

    /// True for any upstream **4xx we could not classify** with the three
    ///
    /// This is deliberately **NOT** a reclassification of 400 as an auth
    /// rejection. xAI answers an invalid key with `400 {"code":
    /// "invalid-argument", "error":"Incorrect API key provided."}` — verified
    /// live 2026-07-28 — but a malformed payload is *also* a 400, and calling
    /// that a key problem sends the caller to rotate a perfectly good key. We
    /// cannot tell the two apart without reading the free-text body, which
    /// `security.md` R2 C-3 forbids propagating (it can echo the credential).
    ///
    /// So we assert only what the status alone proves: the upstream rejected
    /// the **request**, which is a client-class problem, not a Tracelane
    /// outage. The caller gets a 4xx naming the upstream status and both
    /// candidate causes — strictly more honest than the `502 provider
    /// unavailable` this used to fall through to, which blamed us.
    ///
    /// `400 API_KEY_INVALID` still resolve to `provider_key_rejected` above and
    /// never reach here.
    #[must_use]
    pub fn is_unclassified_client_error(&self) -> bool {
        (400..500).contains(&self.status)
            && !self.is_auth_rejection()
            && !self.is_rate_limited()
            && !self.is_model_not_found()
    }
}

#[cfg(test)]
mod provider_http_error_tests {
    use super::ProviderHttpError;

    use super::{reason_from_body, safe_reason};

    fn err(status: u16, reason: Option<&str>) -> ProviderHttpError {
        ProviderHttpError {
            provider: "openai",
            status,
            reason: reason.map(str::to_owned),
        }
    }

    #[test]
    fn auth_rejection_covers_401_403() {
        for s in [401u16, 403] {
            assert!(err(s, None).is_auth_rejection());
        }
        // Availability / rate-limit failures are NOT auth rejections — they must
        // never be reported to the user as "provider key rejected".
        for s in [404u16, 408, 429, 500, 502, 503] {
            assert!(!err(s, None).is_auth_rejection());
        }
    }

    /// NOT 401 — verified live 2026-07-17. Google retires ALL classic `AIza` keys
    /// in Sept 2026, so without this every affected customer would get an opaque
    /// 502 reading as a Tracelane outage.
    #[test]
    fn bare_400_is_not_a_rejection_but_400_with_key_reason_is() {
        // A bare 400 is a malformed request — telling the user their key is bad
        // would send them to rotate a perfectly good credential.
        assert!(!err(400, None).is_auth_rejection());
        assert!(!err(400, Some("INVALID_ARGUMENT")).is_auth_rejection());
        // ...but a 400 that names the key IS a rejection.
        assert!(err(400, Some("API_KEY_INVALID")).is_auth_rejection());
        assert!(err(400, Some("API_KEY_EXPIRED")).is_auth_rejection());
        assert!(err(400, Some("CREDENTIAL_MISSING")).is_auth_rejection());
    }

    /// outage — but must NOT be reclassified as an auth rejection either, or a
    /// malformed payload would send the caller to rotate a good key.
    #[test]
    fn unclassified_4xx_is_client_class_but_never_an_auth_rejection() {
        // xAI's dead-key shape (400, unparseable reason) and a genuinely
        // malformed request are INDISTINGUISHABLE here — both land in this
        // bucket, and neither claims to know which it is.
        for s in [400u16, 402, 409, 413, 415, 422, 451] {
            let e = err(s, None);
            assert!(
                e.is_unclassified_client_error(),
                "{s} should be client-class"
            );
            assert!(!e.is_auth_rejection(), "{s} must NOT claim the key is bad");
        }
    }

    /// The three parsed paths keep their own handling — this bucket is strictly
    #[test]
    fn classified_statuses_never_fall_into_the_unclassified_bucket() {
        for e in [
            err(401, None),
            err(403, None),
            err(429, None),
            err(404, None),
            err(400, Some("API_KEY_INVALID")), // parsed path
        ] {
            assert!(!e.is_unclassified_client_error());
        }
    }

    /// 5xx is a real outage and must stay a 502 — the fallback below this bucket.
    #[test]
    fn server_errors_are_not_client_class() {
        for s in [500u16, 502, 503, 504] {
            assert!(!err(s, None).is_unclassified_client_error());
        }
    }

    #[test]
    fn rate_limit_and_model_not_found_are_distinct_from_outage() {
        assert!(err(429, None).is_rate_limited());
        assert!(err(404, None).is_model_not_found());
        // A real outage is neither — it must stay a 502.
        for s in [500u16, 502, 503] {
            assert!(!err(s, None).is_rate_limited());
            assert!(!err(s, None).is_model_not_found());
            assert!(!err(s, None).is_auth_rejection());
        }
    }

    /// THE SECURITY BOUNDARY: `safe_reason` is what lets us read anything at all
    /// out of a provider error body (which `security.md` R2 C-3 says can echo the
    /// credential). Every real key shape must be structurally incapable of passing.
    #[test]
    fn safe_reason_cannot_admit_a_credential() {
        for key in [
            "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456789", // classic Google (mixed case)
            "AQ.AbFAKEauthkeyshapedvaluefortesting00000", // modern Google (dot)
            "sk-proj-abcdefghijklmnopqrstuvwxyz",         // OpenAI (dashes, lowercase)
            "sk-ant-api03-abcdefghijklmnop",              // Anthropic
            "tlane_abcdefghijklmnopqrstuvwxyz012345",     // our own
            "-----BEGIN PRIVATE KEY-----",                // PEM
        ] {
            assert!(
                safe_reason(key).is_none(),
                "credential-shaped value must never pass safe_reason: {key}"
            );
        }
        // Real reason tokens do pass.
        for r in ["API_KEY_INVALID", "RESOURCE_EXHAUSTED", "INVALID_ARGUMENT"] {
            assert_eq!(safe_reason(r).as_deref(), Some(r));
        }
        // Bounded: no unbounded blob gets in.
        assert!(safe_reason(&"A".repeat(65)).is_none());
        assert!(safe_reason("").is_none());
    }

    /// Pinned to the REAL body Google returned for an invalid key (captured live
    /// 2026-07-17) — not a body I imagined.
    #[test]
    fn extracts_reason_from_the_real_google_error_body() {
        let body = r#"{"error":{"code":400,
            "message":"API key not valid. Please pass a valid API key.",
            "status":"INVALID_ARGUMENT",
            "details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo",
                        "reason":"API_KEY_INVALID","domain":"googleapis.com",
                        "metadata":{"service":"generativelanguage.googleapis.com"}}]}}"#;
        assert_eq!(reason_from_body(body).as_deref(), Some("API_KEY_INVALID"));
    }

    #[test]
    fn reason_falls_back_to_status_then_to_none() {
        // No details[] → fall back to error.status.
        let s = r#"{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED"}}"#;
        assert_eq!(reason_from_body(s).as_deref(), Some("RESOURCE_EXHAUSTED"));
        // Unrecognised shapes degrade to None (status-only mapping), never panic.
        assert!(reason_from_body(r#"{"error":"invalid_grant"}"#).is_none()); // OAuth shape
        assert!(reason_from_body(r#"{"error":{"message":"boom"}}"#).is_none());
        assert!(reason_from_body("not json").is_none());
        assert!(reason_from_body("").is_none());
    }

    /// The free-text `message` must never become a reason — it is the field most
    /// likely to echo a credential.
    #[test]
    fn message_is_never_used_as_a_reason() {
        let body = r#"{"error":{"code":400,"message":"key AIzaSyLEAKED0000000000000000000000000000 is bad"}}"#;
        let r = reason_from_body(body);
        assert!(r.is_none(), "message must not leak into reason: {r:?}");
    }
}

pub mod anthropic;
pub mod azure;
pub mod bedrock;
pub mod cohere;
pub mod failover;
pub mod google;
pub mod openai;
pub mod vertex;
pub mod wasm_plugin;

// `all(test, debug_assertions)`, NOT just `test`: smoke_tests calls the
// loopback bypass (`ssrf_guard::set_loopback_bypass_for_tests`), which is
// `#[cfg(debug_assertions)]` (bypass is debug-only; release hard-denies). Under
// `cargo bench`/`cargo test --release` the profile is release (debug_assertions
// off) while cfg(test) is on — so a plain `#[cfg(test)]` gate compiles the
// caller without the callee → E0425. Keeping the security invariant means
#[cfg(all(test, debug_assertions))]
mod smoke_tests;

// assertions (content assembly, tool-call deltas, usage, wire cost). Same
#[cfg(all(test, debug_assertions))]
mod behavioral_tests;

pub use anthropic::AnthropicProvider;
pub use azure::AzureOpenAiProvider;
pub use bedrock::BedrockProvider;
pub use cohere::CohereProvider;
pub use google::GoogleProvider;
pub use openai::OpenAiProvider;
pub use vertex::VertexProvider;

use tracelane_shared::{ChatRequest, ChatResponse, TenantId};

/// A streaming response event from a provider adapter.
#[derive(Debug)]
pub enum ProviderEvent {
    /// Incremental text token (also referred to as StreamChunk in eval specs)
    StreamChunk { delta: String },
    /// Incremental tool call argument chunk
    ToolCallDelta {
        index: usize,
        id: Option<String>,
        name: Option<String>,
        input_delta: String,
    },
    /// Incremental thinking/reasoning token (Anthropic extended thinking, etc.)
    ThinkingDelta { delta: String },
    /// Token usage update
    UsageUpdate {
        input_tokens: u32,
        output_tokens: u32,
        cache_read: Option<u32>,
        cache_creation: Option<u32>,
        /// provider puts a cost on the wire (e.g. OpenRouter's `usage.cost`);
        /// `None` otherwise — we never fabricate a price from a hardcoded
        /// model→price table. Threaded to the span as `gen_ai.usage.cost`.
        cost_usd: Option<f64>,
    },
    /// Final non-streaming response (used for non-streaming calls)
    Done { response: ChatResponse },
    /// Provider-level error
    Error {
        message: String,
        code: Option<String>,
    },
}

pub type ProviderStream = Pin<Box<dyn Stream<Item = Result<ProviderEvent>> + Send>>;

/// All provider adapters implement this trait.
/// RPITIT is used instead of `async_trait` in the hot path.
pub trait ProviderAdapter: Send + Sync {
    /// Provider identifier (e.g. "anthropic", "openai")
    fn provider_id(&self) -> &'static str;

    /// Send a chat request and return a stream of events.
    /// `tenant_id` is threaded through for `tracing::instrument` fields.
    fn chat(
        &self,
        request: ChatRequest,
        api_key: &str,
        tenant_id: &TenantId,
    ) -> impl Future<Output = Result<ProviderStream>> + Send;
}

/// Future alias so the trait object can be stored.
use std::future::Future;

/// Registry of provider adapters (7 native + 28 OpenAI-compatible instances).
///
/// The counts in this file's header and here are CI-enforced against the actual
/// doc-comment miscount that leaked into public marketing as "35+ providers", and
/// it drifted again within a day of being closed (the Vertex adapter). A comment
/// nobody checks is a claim waiting to rot.
///
/// Route logic in `server.rs` dispatches by `model` prefix:
///   "claude-*" | "anthropic/*" → anthropic
///   "gpt-*"    | "openai/*"    → openai
///   "gemini-*" | "google/*"    → google
///   "bedrock/*"                → bedrock
///   "azure/*"                  → azure
///   "cohere/*" | "command-*"   → cohere
///   "mistral/*"                → mistral
///   "sonar-*"  | "perplexity/*"→ perplexity
///   "deepseek/*"               → deepseek
///   "grok-*"   | "xai/*"       → xai
///   ... (full routing table in server.rs)
pub struct ProviderRegistry {
    // ── Dedicated adapters ────────────────────────────────────────────────────
    pub anthropic: AnthropicProvider,
    pub openai: OpenAiProvider,
    pub google: GoogleProvider,
    /// Vertex first-party Gemini. Separate from `google` because Vertex
    /// rejects API keys (service-account OAuth only) and is the ONLY Gemini
    /// path that Google Cloud credits can pay for.
    pub vertex: VertexProvider,
    pub bedrock: BedrockProvider,
    pub azure: AzureOpenAiProvider,
    pub cohere: CohereProvider,

    // ── OpenAI-compatible providers ───────────────────────────────────────────
    pub together: OpenAiProvider,
    pub fireworks: OpenAiProvider,
    pub groq: OpenAiProvider,
    pub openrouter: OpenAiProvider,
    pub mistral: OpenAiProvider,
    pub perplexity: OpenAiProvider,
    pub deepseek: OpenAiProvider,
    pub xai: OpenAiProvider,
    pub nvidia_nim: OpenAiProvider,
    pub cerebras: OpenAiProvider,
    pub sambanova: OpenAiProvider,
    pub lepton: OpenAiProvider,
    pub lambda: OpenAiProvider,
    pub novita: OpenAiProvider,
    pub ai21: OpenAiProvider,
    pub hyperbolic: OpenAiProvider,
    pub deepinfra: OpenAiProvider,
    pub cloudflare: OpenAiProvider,
    pub ollama: OpenAiProvider,
    pub baseten: OpenAiProvider,
    pub huggingface: OpenAiProvider,
    pub anyscale: OpenAiProvider,
    pub modal: OpenAiProvider,
    pub predibase: OpenAiProvider,
    pub moonshot: OpenAiProvider,
    pub upstage: OpenAiProvider,
    pub yi: OpenAiProvider, // 01.AI
    pub aleph_alpha: OpenAiProvider,
}

impl ProviderRegistry {
    /// A14: constructor is now fallible — every provider's reqwest client
    /// build is `?`-propagated rather than `expect()`-panicked, satisfying
    /// `.claude/rules/rust.md` "no unwrap/expect outside tests". Call this
    /// once at server startup and `?` the result into `Arc::new(...)`.
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            // ── Dedicated adapters ────────────────────────────────────────────
            anthropic: AnthropicProvider::new()?,
            openai: OpenAiProvider::openai()?,
            google: GoogleProvider::new()?,
            vertex: VertexProvider::new()?,
            bedrock: BedrockProvider::new()?,
            azure: AzureOpenAiProvider::new()?,
            cohere: CohereProvider::new()?,

            // ── OpenAI-compatible providers ───────────────────────────────────
            together: OpenAiProvider::compatible(
                std::env::var("TOGETHER_BASE_URL")
                    .unwrap_or_else(|_| "https://api.together.xyz".into()),
                "together",
            )?,
            fireworks: OpenAiProvider::compatible(
                std::env::var("FIREWORKS_BASE_URL")
                    .unwrap_or_else(|_| "https://api.fireworks.ai/inference".into()),
                "fireworks",
            )?,
            groq: OpenAiProvider::compatible(
                std::env::var("GROQ_BASE_URL")
                    .unwrap_or_else(|_| "https://api.groq.com/openai".into()),
                "groq",
            )?,
            openrouter: OpenAiProvider::compatible(
                std::env::var("OPENROUTER_BASE_URL")
                    .unwrap_or_else(|_| "https://openrouter.ai/api".into()),
                "openrouter",
            )?,
            mistral: OpenAiProvider::compatible(
                std::env::var("MISTRAL_BASE_URL")
                    .unwrap_or_else(|_| "https://api.mistral.ai".into()),
                "mistral",
            )?,
            perplexity: OpenAiProvider::compatible(
                std::env::var("PERPLEXITY_BASE_URL")
                    .unwrap_or_else(|_| "https://api.perplexity.ai".into()),
                "perplexity",
            )?,
            deepseek: OpenAiProvider::compatible(
                std::env::var("DEEPSEEK_BASE_URL")
                    .unwrap_or_else(|_| "https://api.deepseek.com".into()),
                "deepseek",
            )?,
            xai: OpenAiProvider::compatible(
                std::env::var("XAI_BASE_URL").unwrap_or_else(|_| "https://api.x.ai".into()),
                "xai",
            )?,
            nvidia_nim: OpenAiProvider::compatible(
                std::env::var("NVIDIA_BASE_URL")
                    .unwrap_or_else(|_| "https://integrate.api.nvidia.com".into()),
                "nvidia",
            )?,
            cerebras: OpenAiProvider::compatible(
                std::env::var("CEREBRAS_BASE_URL")
                    .unwrap_or_else(|_| "https://api.cerebras.ai".into()),
                "cerebras",
            )?,
            sambanova: OpenAiProvider::compatible(
                std::env::var("SAMBANOVA_BASE_URL")
                    .unwrap_or_else(|_| "https://api.sambanova.ai".into()),
                "sambanova",
            )?,
            lepton: OpenAiProvider::compatible(
                std::env::var("LEPTON_BASE_URL")
                    .unwrap_or_else(|_| "https://llama3-1-405b.lepton.run".into()),
                "lepton",
            )?,
            lambda: OpenAiProvider::compatible(
                std::env::var("LAMBDA_BASE_URL")
                    .unwrap_or_else(|_| "https://api.lambdalabs.com".into()),
                "lambda",
            )?,
            novita: OpenAiProvider::compatible(
                std::env::var("NOVITA_BASE_URL").unwrap_or_else(|_| "https://api.novita.ai".into()),
                "novita",
            )?,
            ai21: OpenAiProvider::compatible(
                std::env::var("AI21_BASE_URL").unwrap_or_else(|_| "https://api.ai21.com".into()),
                "ai21",
            )?,
            hyperbolic: OpenAiProvider::compatible(
                std::env::var("HYPERBOLIC_BASE_URL")
                    .unwrap_or_else(|_| "https://api.hyperbolic.xyz".into()),
                "hyperbolic",
            )?,
            deepinfra: OpenAiProvider::compatible(
                std::env::var("DEEPINFRA_BASE_URL")
                    .unwrap_or_else(|_| "https://api.deepinfra.com".into()),
                "deepinfra",
            )?,
            cloudflare: OpenAiProvider::compatible(
                std::env::var("CLOUDFLARE_AI_GATEWAY_URL").unwrap_or_else(|_| {
                    "https://gateway.ai.cloudflare.com/v1/tracelane/workers-ai/openai".into()
                }),
                "cloudflare",
            )?,
            ollama: OpenAiProvider::compatible(
                std::env::var("OLLAMA_BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:11434".into()),
                "ollama",
            )?,
            baseten: OpenAiProvider::compatible(
                std::env::var("BASETEN_BASE_URL")
                    .unwrap_or_else(|_| "https://bridge.baseten.co/v1/direct".into()),
                "baseten",
            )?,
            huggingface: OpenAiProvider::compatible(
                std::env::var("HUGGINGFACE_BASE_URL")
                    .unwrap_or_else(|_| "https://api-inference.huggingface.co".into()),
                "huggingface",
            )?,
            anyscale: OpenAiProvider::compatible(
                std::env::var("ANYSCALE_BASE_URL")
                    .unwrap_or_else(|_| "https://api.endpoints.anyscale.com".into()),
                "anyscale",
            )?,
            modal: OpenAiProvider::compatible(
                std::env::var("MODAL_BASE_URL")
                    .unwrap_or_else(|_| "https://api.modal.com/v1/openai".into()),
                "modal",
            )?,
            predibase: OpenAiProvider::compatible(
                std::env::var("PREDIBASE_BASE_URL")
                    .unwrap_or_else(|_| "https://serving.app.predibase.com".into()),
                "predibase",
            )?,
            moonshot: OpenAiProvider::compatible(
                std::env::var("MOONSHOT_BASE_URL")
                    .unwrap_or_else(|_| "https://api.moonshot.cn".into()),
                "moonshot",
            )?,
            upstage: OpenAiProvider::compatible(
                std::env::var("UPSTAGE_BASE_URL")
                    .unwrap_or_else(|_| "https://api.upstage.ai".into()),
                "upstage",
            )?,
            yi: OpenAiProvider::compatible(
                std::env::var("YI_BASE_URL").unwrap_or_else(|_| "https://api.01.ai".into()),
                "yi",
            )?,
            aleph_alpha: OpenAiProvider::compatible(
                std::env::var("ALEPH_ALPHA_BASE_URL")
                    .unwrap_or_else(|_| "https://api.aleph-alpha.com".into()),
                "aleph-alpha",
            )?,
        })
    }

    /// Resolve the provider family ID from a model string prefix (A4).
    ///
    /// Used as the `provider_id` column in `provider_keys` so BYOK
    /// ciphertext is bound to a stable family token regardless of the
    /// specific model variant. Mirrors the match arms in
    /// `api_key_env_var` — keep both in sync.
    /// The SINGLE canonical model→provider map. Returns `None` for an unmatched
    /// that provider's key for a model the caller never meant (credential
    /// misrouting). Every consumer fail-closes on `None` with a typed
    /// `unroutable_model` error. Enforced by
    /// `scripts/ci/check-provider-mapping-single-source.py`.
    pub fn provider_id_for_model(model: &str) -> Option<&'static str> {
        let pid = match model {
            m if m.starts_with("claude") || m.starts_with("anthropic/") => "anthropic",
            m if m.starts_with("gpt")
                || m.starts_with("openai/")
                || m.starts_with("o1")
                || m.starts_with("o3") =>
            {
                "openai"
            }
            m if m.starts_with("vertex/") => "vertex",
            m if m.starts_with("gemini") || m.starts_with("google/") => "google",
            m if m.starts_with("bedrock/") => "bedrock",
            m if m.starts_with("azure/") => "azure",
            m if m.starts_with("command") || m.starts_with("cohere/") => "cohere",
            m if m.starts_with("mistral") || m.starts_with("mixtral") => "mistral",
            m if m.starts_with("sonar")
                || m.starts_with("perplexity/")
                || m.starts_with("llama-3.1-sonar") =>
            {
                "perplexity"
            }
            m if m.starts_with("deepseek") => "deepseek",
            m if m.starts_with("grok") || m.starts_with("xai/") => "xai",
            m if m.starts_with("nvidia/") => "nvidia",
            m if m.starts_with("cerebras/") => "cerebras",
            m if m.starts_with("sambanova/") => "sambanova",
            m if m.starts_with("lepton/") => "lepton",
            m if m.starts_with("lambda/") => "lambda",
            m if m.starts_with("novita/") => "novita",
            m if m.starts_with("ai21/") || m.starts_with("j2-") || m.starts_with("jamba") => "ai21",
            m if m.starts_with("hyperbolic/") => "hyperbolic",
            m if m.starts_with("deepinfra/") => "deepinfra",
            m if m.starts_with("@cf/") || m.starts_with("cloudflare/") => "cloudflare",
            m if m.starts_with("ollama/") => "ollama",
            m if m.starts_with("baseten/") => "baseten",
            m if m.starts_with("hf/") || m.starts_with("huggingface/") => "huggingface",
            m if m.starts_with("anyscale/") => "anyscale",
            m if m.starts_with("modal/") => "modal",
            m if m.starts_with("predibase/") => "predibase",
            m if m.starts_with("moonshot/") => "moonshot",
            m if m.starts_with("solar-") || m.starts_with("upstage/") => "upstage",
            m if m.starts_with("yi-") || m.starts_with("yi/") => "yi",
            m if m.starts_with("luminous") || m.starts_with("aleph-alpha/") => "aleph-alpha",
            // Aggregator / multi-model inference hosts — reachable ONLY via an
            // explicit `provider/` prefix (their catalogs overlap open models like
            // llama/qwen, so a bare name can't disambiguate). These adapters were
            // registered but had NO routing prefix (unreachable — coverage audit
            // 2026-07-18); a `together/…` etc. model now routes correctly.
            m if m.starts_with("together/") => "together",
            m if m.starts_with("fireworks/") => "fireworks",
            m if m.starts_with("openrouter/") => "openrouter",
            // Groq's common OpenAI-compatible names (llama-3.x / qwen / gemma).
            // MUST mirror the dispatch arm in server.rs (`registry.groq.chat`) —
            // sonar/llama-3.1-sonar already matched perplexity above. Without this
            // arm these models dispatched to Groq but their BYOK key was looked up
            // under provider "anthropic" (default), so a stored Groq key never
            // resolved (401) and a stored Anthropic key would be sent to Groq.
            m if m.starts_with("llama") || m.starts_with("qwen") || m.starts_with("gemma") => {
                "groq"
            }
            // unroutable, not "probably Anthropic". Returning a default here would
            // send the Anthropic key (or whichever provider) to a model the caller
            // never asked for. Callers reject with 400 unroutable_model.
            _ => return None,
        };
        Some(pid)
    }

    /// Resolve the env-var name to read a provider API key from (legacy
    /// single-tenant env fallback).
    ///
    /// then maps provider_id → env var. NO model-prefix matching lives here — that
    /// was the drift surface (the Groq family dispatched to Groq but resolved
    /// `ANTHROPIC_API_KEY` here). Enforced by
    /// `scripts/ci/check-provider-mapping-single-source.py`.
    pub fn api_key_env_var(model: &str) -> Option<&'static str> {
        Self::provider_id_for_model(model).map(Self::env_var_for_provider_id)
    }

    /// Provider-id → API-key env-var name. A fixed enumeration keyed on the
    /// canonical provider_id (NOT model prefixes), so it cannot drift on model
    /// names. Vertex's credential is a service-account JSON; Ollama is local
    /// (no key). Keep every arm of `provider_id_for_model` represented here.
    pub fn env_var_for_provider_id(provider_id: &str) -> &'static str {
        match provider_id {
            "anthropic" => "ANTHROPIC_API_KEY",
            "openai" => "OPENAI_API_KEY",
            "vertex" => "GOOGLE_VERTEX_SERVICE_ACCOUNT_JSON",
            "google" => "GOOGLE_API_KEY",
            "bedrock" => "AWS_ACCESS_KEY_ID",
            "azure" => "AZURE_OPENAI_API_KEY",
            "cohere" => "COHERE_API_KEY",
            "mistral" => "MISTRAL_API_KEY",
            "perplexity" => "PERPLEXITY_API_KEY",
            "deepseek" => "DEEPSEEK_API_KEY",
            "xai" => "XAI_API_KEY",
            "nvidia" => "NVIDIA_API_KEY",
            "cerebras" => "CEREBRAS_API_KEY",
            "sambanova" => "SAMBANOVA_API_KEY",
            "lepton" => "LEPTON_API_KEY",
            "lambda" => "LAMBDA_API_KEY",
            "novita" => "NOVITA_API_KEY",
            "ai21" => "AI21_API_KEY",
            "hyperbolic" => "HYPERBOLIC_API_KEY",
            "deepinfra" => "DEEPINFRA_API_KEY",
            "cloudflare" => "CLOUDFLARE_API_KEY",
            "ollama" => "", // local, no key needed
            "baseten" => "BASETEN_API_KEY",
            "huggingface" => "HUGGINGFACE_API_KEY",
            "anyscale" => "ANYSCALE_API_KEY",
            "modal" => "MODAL_API_KEY",
            "predibase" => "PREDIBASE_API_KEY",
            "moonshot" => "MOONSHOT_API_KEY",
            "upstage" => "UPSTAGE_API_KEY",
            "yi" => "YI_API_KEY",
            "aleph-alpha" => "ALEPH_ALPHA_API_KEY",
            "groq" => "GROQ_API_KEY",
            "together" => "TOGETHER_API_KEY",
            "fireworks" => "FIREWORKS_API_KEY",
            "openrouter" => "OPENROUTER_API_KEY",
            // with a provider_id that provider_id_for_model already matched, so `_`
            // is unreachable; an empty env is the fail-safe (no key), NOT a
            // different provider's key.
            _ => "",
        }
    }
}

/// A mock provider for use in eval runs and tests.
/// Never makes real network calls.
pub struct MockProvider {
    pub response_text: String,
}

impl MockProvider {
    pub fn new(response_text: impl Into<String>) -> Self {
        Self {
            response_text: response_text.into(),
        }
    }

    #[instrument(skip(self, _request, _api_key), fields(tenant_id = %tenant_id))]
    pub async fn chat_mock(
        &self,
        _request: ChatRequest,
        _api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let text = self.response_text.clone();
        let stream = try_stream! {
            yield ProviderEvent::StreamChunk { delta: text };
            yield ProviderEvent::UsageUpdate {
                input_tokens: 10,
                output_tokens: 5,
                cache_read: None,
                cache_creation: None,
                cost_usd: None,
            };
        };
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod model_routing_consistency_tests {
    use super::ProviderRegistry;

    /// `llama*` / `qwen* `/ `gemma*` to `registry.groq`, but the BYOK
    /// key-lookup functions used to default them to `anthropic` /
    /// `ANTHROPIC_API_KEY`. A stored Groq key then never resolved (401), and
    /// a stored Anthropic key would have been sent to `api.groq.com`. The
    /// key-lookup pair MUST agree with the dispatch provider for these models.
    #[test]
    fn groq_family_models_resolve_to_groq_not_anthropic() {
        for m in [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "qwen-2.5-32b",
            "gemma2-9b-it",
        ] {
            assert_eq!(
                ProviderRegistry::provider_id_for_model(m),
                Some("groq"),
                "provider_id_for_model({m}) must be groq (dispatch routes it to registry.groq)"
            );
            assert_eq!(
                ProviderRegistry::api_key_env_var(m),
                Some("GROQ_API_KEY"),
                "api_key_env_var({m}) must be GROQ_API_KEY (was defaulting to ANTHROPIC_API_KEY)"
            );
        }
    }

    /// The Groq arm must NOT steal `llama-3.1-sonar*` — those are Perplexity
    /// and matched earlier in every match (dispatch + both key-lookups).
    #[test]
    fn llama_sonar_still_routes_to_perplexity() {
        let m = "llama-3.1-sonar-large-128k-online";
        assert_eq!(
            ProviderRegistry::provider_id_for_model(m),
            Some("perplexity")
        );
        assert_eq!(
            ProviderRegistry::api_key_env_var(m),
            Some("PERPLEXITY_API_KEY")
        );
    }

    /// Spot-check that the two key-lookup functions stay in lockstep on the
    /// families most likely to drift (the bug was exactly a divergence).
    #[test]
    fn provider_id_and_env_var_agree_on_key_families() {
        let cases = [
            ("claude-sonnet-4-6", "anthropic", "ANTHROPIC_API_KEY"),
            ("gpt-4o", "openai", "OPENAI_API_KEY"),
            ("gemini-2.5-flash", "google", "GOOGLE_API_KEY"),
            ("grok-2", "xai", "XAI_API_KEY"),
            ("llama-3.3-70b-versatile", "groq", "GROQ_API_KEY"),
        ];
        for (model, pid, env) in cases {
            assert_eq!(ProviderRegistry::provider_id_for_model(model), Some(pid));
            assert_eq!(ProviderRegistry::api_key_env_var(model), Some(env));
        }
    }

    /// Coverage audit 2026-07-18: the together/fireworks/openrouter adapters were
    /// registered but UNREACHABLE (no routing prefix → defaulted to anthropic).
    /// They now route via an explicit `provider/` prefix.
    #[test]
    fn aggregator_hosts_are_reachable_via_prefix() {
        for (model, pid, env) in [
            (
                "together/meta-llama/Llama-3.3-70B",
                "together",
                "TOGETHER_API_KEY",
            ),
            ("fireworks/llama-v3p3-70b", "fireworks", "FIREWORKS_API_KEY"),
            (
                "openrouter/anthropic/claude-3.5",
                "openrouter",
                "OPENROUTER_API_KEY",
            ),
        ] {
            assert_eq!(
                ProviderRegistry::provider_id_for_model(model),
                Some(pid),
                "{model} must route to {pid}, not the anthropic default"
            );
            assert_eq!(ProviderRegistry::api_key_env_var(model), Some(env));
        }
    }

    /// anthropic. Sending an unknown model to Anthropic with the Anthropic key is
    /// credential misrouting; rejecting is strictly safer. (These are top models
    /// with no bare-name arm — reachable via a provider prefix instead.)
    #[test]
    fn unmatched_models_fail_closed_not_default_anthropic() {
        for model in [
            "kimi-k2",
            "nova-pro",
            "glm-4-plus",
            "phi-4",
            "totally-unknown-model-xyz",
            "",
        ] {
            assert_eq!(
                ProviderRegistry::provider_id_for_model(model),
                None,
                "{model:?} must be unroutable (None), never a default provider"
            );
            assert_eq!(
                ProviderRegistry::api_key_env_var(model),
                None,
                "{model:?} must resolve NO key env (never ANTHROPIC_API_KEY)"
            );
        }
        // The prefixed forms route correctly where an adapter exists.
        assert_eq!(
            ProviderRegistry::provider_id_for_model("moonshot/kimi-k2"),
            Some("moonshot")
        );
        assert_eq!(
            ProviderRegistry::provider_id_for_model("bedrock/nova-pro"),
            Some("bedrock")
        );
    }

    /// One representative model per registered provider. Assertion 1 below proves
    /// each routes to its OWN provider, so this list is self-validating.
    const PROVIDER_MODELS: &[(&str, &str)] = &[
        ("anthropic", "claude-sonnet-4-6"),
        ("openai", "gpt-4o"),
        ("google", "gemini-2.5-flash"),
        ("vertex", "vertex/gemini-2.5-pro"),
        ("bedrock", "bedrock/nova-pro"),
        ("azure", "azure/gpt-4o"),
        ("cohere", "command-r-plus"),
        ("mistral", "mistral-large-latest"),
        ("perplexity", "sonar-pro"),
        ("deepseek", "deepseek-chat"),
        ("xai", "grok-2"),
        ("nvidia", "nvidia/llama-3.1-70b"),
        ("cerebras", "cerebras/llama-3.3-70b"),
        ("sambanova", "sambanova/Meta-Llama-3.3-70B"),
        ("lepton", "lepton/llama3-70b"),
        ("lambda", "lambda/llama-3.3-70b"),
        ("novita", "novita/llama-3.3-70b"),
        ("ai21", "jamba-1.5-large"),
        ("hyperbolic", "hyperbolic/llama-3.3-70b"),
        ("deepinfra", "deepinfra/llama-3.3-70b"),
        ("cloudflare", "@cf/meta/llama-3.1-8b"),
        ("ollama", "ollama/llama3.3"),
        ("baseten", "baseten/llama-3.3-70b"),
        ("huggingface", "hf/meta-llama/Llama-3.3-70B"),
        ("anyscale", "anyscale/llama-3.3-70b"),
        ("modal", "modal/llama-3.3-70b"),
        ("predibase", "predibase/llama-3-3-70b"),
        ("moonshot", "moonshot/kimi-k2"),
        ("upstage", "solar-pro"),
        ("yi", "yi-large"),
        ("aleph-alpha", "luminous-supreme"),
        ("groq", "llama-3.3-70b-versatile"),
        ("together", "together/meta-llama/Llama-3.3-70B"),
        ("fireworks", "fireworks/llama-v3p3-70b"),
        ("openrouter", "openrouter/meta-llama/llama-3.3-70b"),
    ];

    /// the FULL provider matrix (N×N, N=35 → 1225 ordered pairs). For every pair
    /// (A, B) with A≠B, calling B's model MUST resolve B's own key env, never A's.
    /// Since the key env is derived from the single canonical
    /// `provider_id_for_model`, this proves at the resolution layer that no
    /// credential-misrouting class cannot silently return. Providers with real
    /// keys are additionally exercised on the wire (see the multi-provider proof);
    /// the rest are asserted-by-construction here.
    #[test]
    fn cross_provider_key_isolation_full_matrix() {
        // 1. Every representative model routes to its OWN provider (self-validating
        //    the list) and yields that provider's key env.
        for (pid, model) in PROVIDER_MODELS {
            assert_eq!(
                ProviderRegistry::provider_id_for_model(model),
                Some(*pid),
                "{model} must route to provider {pid}"
            );
            let env = ProviderRegistry::api_key_env_var(model);
            assert!(env.is_some(), "{model} ({pid}) resolved NO key env");
        }

        // 2. N×N cross-leak: for every ordered pair A≠B, B's model never resolves
        //    A's key env. Distinct non-empty envs ⇒ storing only A's key leaves B's
        //    model with an empty key (upstream 401), never A's key. (ollama's env
        //    is the empty "no key" sentinel — a local, keyless provider.)
        let mut pairs = 0usize;
        for (a_pid, _a_model) in PROVIDER_MODELS {
            let a_env = ProviderRegistry::env_var_for_provider_id(a_pid);
            for (b_pid, b_model) in PROVIDER_MODELS {
                if a_pid == b_pid {
                    continue;
                }
                let b_env = ProviderRegistry::api_key_env_var(b_model).unwrap();
                pairs += 1;
                if a_env.is_empty() || b_env.is_empty() {
                    continue; // ollama carries no key — nothing to leak
                }
                assert_ne!(
                    b_env, a_env,
                    "CROSS-LEAK: model {b_model} (provider {b_pid}) resolves key env \
                     {a_env} which belongs to provider {a_pid}"
                );
            }
        }
        assert_eq!(pairs, PROVIDER_MODELS.len() * (PROVIDER_MODELS.len() - 1));

        // 3. Fail-closed: an unmatched model resolves NO provider and NO key env —
        //    it can never carry ANY provider's credential. (Names chosen to match
        //    NO prefix — note kimi/nova/glm are top models with no bare-name arm.)
        for m in [
            "zzz-nonexistent-model",
            "unknown-xyz",
            "",
            "kimi-k2",
            "nova-pro",
        ] {
            assert_eq!(
                ProviderRegistry::provider_id_for_model(m),
                None,
                "{m:?} must be unroutable (fail closed)"
            );
            assert_eq!(ProviderRegistry::api_key_env_var(m), None);
        }
    }
}
