//! `OG-91` layer 1 — client conformance by replay (RCA control C4).
//! Spec: `specs/OG-91-client-conformance-harness.md`. RCA:
//! `runbooks/RCA-one-gateway-bug-cluster-2026-10-01.md` root cause 4.
//!
//! Every provider-side test in this crate was written from OUR reading of a protocol. D7
//! (`/v1/messages` replacing every upstream error body, mapping 529 to 502) survived because
//! nothing replayed what a REAL CLIENT sends and then asked what that client's own docs say it
//! needs back. This module does, for the three coding agents the product is sold to:
//!
//!   * Claude Code → `POST /v1/messages?beta=true` (the byte-faithful Anthropic relay),
//!   * Codex → `POST /v1/responses`, responses-lite (mode N relay, and mode T translation),
//!   * Gemini CLI → `POST /v1beta/models/{m}:streamGenerateContent?alt=sse` (Gemini-native relay).
//!
//! Each fixture (`crates/gateway/tests/fixtures/client_conformance/*.fixture`) carries its
//! provenance in a header comment: they are HAND-BUILT from each client's published source until
//! `scripts/ops/client-conformance.sh --refresh-fixtures` captures the real bytes to
//! `~/.cache/tracelane/client-conformance/` (not the repo: a capture holds the client's whole
//! system prompt and the machine's paths) for a human to trim and promote. Codex's and Claude
//! Code's header NAMES and `anthropic-beta` value here were corrected against such a capture on
//! 2026-10-02.
//! They are replayed through the REAL handler against a SCRIPTED fake upstream (`wiremock`; no
//! provider, no spend), and the contract is asserted on what the CLIENT receives and on what the
//! UPSTREAM received.
//!
//! The scenario table (spec §3), and where each row lives here:
//!
//! | Scenario | Test |
//! |---|---|
//! | upstream 400 "prompt is too long…" → same status, exact body (D7) | `og91_a_400_...` |
//! | upstream 529 → 529 relayed, `retry-after` forwarded | `og91_a_529_...` |
//! | upstream 429 `Retry-After: 20` → ONE upstream call, header to the client | `og91_a_429_...` |
//! | tool round trip, each wire's tool-call shape preserved (Codex mode T: `custom_tool_call`) | `og91_tool_round_trip_*` |
//! | image part reaches the upstream body, or a 400 names it | `og91_an_image_part_*` |
//! | SSE ping relayed, not dropped | `og91_claude_code_sse_ping_*` |
//! | `anthropic-beta`/`anthropic-version` verbatim; our `tlane_` key never forwarded | `og91_*_headers_*` |
//!
//! Not applicable, said rather than skipped silently: OpenAI Responses and Gemini streams carry
//! no `ping` event (Anthropic-only), so the keepalive row is asserted for Claude Code alone.

#![cfg(test)]

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::handler_harness::LoopbackBypassGuard;
use crate::server::AppState;
use tracelane_shared::TenantId;

// ── fixtures ────────────────────────────────────────────────────────────────

const CLAUDE_CODE_FIXTURE: &str =
    include_str!("../tests/fixtures/client_conformance/claude-code-messages-beta.fixture");
const CODEX_FIXTURE: &str =
    include_str!("../tests/fixtures/client_conformance/codex-responses-lite.fixture");
const GEMINI_FIXTURE: &str =
    include_str!("../tests/fixtures/client_conformance/gemini-cli-stream.fixture");

/// A parsed `.fixture`: `# KEY: value` header lines (METHOD, PATH, HEADER, plus provenance
/// prose), then ONE line of JSON — the request body, replayed byte-for-byte.
struct Fixture {
    path_and_query: String,
    method: String,
    headers: Vec<(String, String)>,
    provenance: String,
    raw_body: String,
}

impl Fixture {
    fn parse(raw: &str) -> Self {
        let mut f = Self {
            path_and_query: String::new(),
            method: String::new(),
            headers: Vec::new(),
            provenance: String::new(),
            raw_body: String::new(),
        };
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix('#') {
                let rest = rest.trim_start();
                if let Some(v) = rest.strip_prefix("METHOD:") {
                    f.method = v.trim().to_owned();
                } else if let Some(v) = rest.strip_prefix("PATH:") {
                    f.path_and_query = v.trim().to_owned();
                } else if let Some(v) = rest.strip_prefix("HEADER:") {
                    let (k, val) = v.trim().split_once(':').expect("HEADER: name: value");
                    f.headers.push((k.trim().to_owned(), val.trim().to_owned()));
                } else if rest.starts_with("PROVENANCE:") {
                    f.provenance = rest.to_owned();
                }
            } else if !line.trim().is_empty() {
                assert!(
                    f.raw_body.is_empty(),
                    "a fixture holds exactly one JSON body"
                );
                f.raw_body = line.to_owned();
            }
        }
        f
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.raw_body).expect("fixture body is JSON")
    }

    /// The headers the client sent, as a `HeaderMap`.
    fn header_map(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in &self.headers {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).expect("header name"),
                HeaderValue::from_str(v).expect("header value"),
            );
        }
        h
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("fixture has no {name} header"))
    }

    fn body(&self) -> Bytes {
        Bytes::from(self.raw_body.clone())
    }
}

#[test]
fn every_fixture_states_its_provenance_and_carries_our_key_the_way_its_client_does() {
    for (name, raw, key_header) in [
        ("claude-code", CLAUDE_CODE_FIXTURE, "x-api-key"),
        ("codex", CODEX_FIXTURE, "authorization"),
        ("gemini-cli", GEMINI_FIXTURE, "x-goog-api-key"),
    ] {
        let f = Fixture::parse(raw);
        assert!(
            f.provenance.contains("HAND-BUILT") || f.provenance.contains("CAPTURED"),
            "{name}: a fixture must say whether it is hand-built or a capture"
        );
        assert_eq!(f.method, "POST", "{name}");
        assert!(f.header(key_header).contains("tlane_"), "{name}");
        let _ = f.json();
    }
}

// ── the scripted world ──────────────────────────────────────────────────────

const BYOK_ANTHROPIC: &str = "og91-byok-anthropic-key-do-not-use";
const BYOK_OPENAI: &str = "og91-byok-openai-key-do-not-use";
const BYOK_GOOGLE: &str = "og91-byok-google-key-do-not-use";
const PNG_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

fn claims_for(t: &TenantId) -> crate::auth::Claims {
    crate::auth::Claims {
        tenant_id: t.clone(),
        sub: format!("apikey:{}", Uuid::new_v4()),
        auth_method: crate::auth::AuthMethod::ApiKey,
        role: None,
        key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
        budget_usd_monthly: None,
        rate_limit_rpm: None,
        budget_reset: crate::spend::BudgetReset::Monthly,
        governance: None,
    }
}

fn install_byok(t: &TenantId, provider: &'static str, key: &str) {
    crate::db::provider_keys::cache_decrypted(
        t,
        provider,
        Arc::new(secrecy::SecretString::from(key.to_owned())),
    );
}

/// Every adapter this module drives, pointed at ONE scripted upstream.
fn state_for(base: &str) -> AppState {
    let mut reg = crate::providers::ProviderRegistry::new().expect("registry");
    reg.set_compat_base_url_for_test("openai", base.to_owned())
        .expect("openai");
    reg.anthropic = crate::providers::AnthropicProvider::for_base_url(base).expect("anthropic");
    reg.google = crate::providers::GoogleProvider::for_base_url(base).expect("google");
    crate::handler_harness::test_state_with_chain(reg, crate::handler_harness::in_memory_chain())
}

#[derive(Clone, Copy, Debug)]
enum Wire {
    ClaudeCode,
    CodexNative,
    CodexTranslate,
    GeminiCli,
}

impl Wire {
    /// The route on the scripted upstream the gateway is expected to call.
    fn upstream_path(self) -> &'static str {
        match self {
            Self::ClaudeCode | Self::CodexTranslate => "/v1/messages",
            Self::CodexNative => "/v1/responses",
            Self::GeminiCli => "/v1beta/models/gemini-2.5-pro:streamGenerateContent",
        }
    }

    fn fixture(self) -> Fixture {
        Fixture::parse(match self {
            Self::ClaudeCode => CLAUDE_CODE_FIXTURE,
            Self::CodexNative | Self::CodexTranslate => CODEX_FIXTURE,
            Self::GeminiCli => GEMINI_FIXTURE,
        })
    }
}

/// What came back to the client, and what the scripted upstream saw.
struct Replay {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    upstream: Vec<wiremock::Request>,
}

impl Replay {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn upstream_json(&self) -> Value {
        serde_json::from_slice(&self.upstream.last().expect("an upstream call").body)
            .expect("upstream body is JSON")
    }
}

/// Replay `wire`'s fixture (optionally with a different body) through the REAL handler against a
/// scripted upstream that answers `upstream` on the route the wire calls.
async fn replay(wire: Wire, body: Option<Bytes>, upstream: ResponseTemplate) -> Replay {
    let _bypass = LoopbackBypassGuard::new();
    let fx = wire.fixture();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(wire.upstream_path()))
        .respond_with(upstream)
        .mount(&server)
        .await;
    let t = TenantId::from_jwt_claim(Uuid::new_v4());
    install_byok(&t, "anthropic", BYOK_ANTHROPIC);
    install_byok(&t, "openai", BYOK_OPENAI);
    install_byok(&t, "google", BYOK_GOOGLE);
    let state = state_for(&server.uri());
    let body = body.unwrap_or_else(|| fx.body());
    let resp: Response = match wire {
        Wire::ClaudeCode => {
            crate::anthropic_messages::messages_with_claims(
                state,
                fx.header_map(),
                body,
                claims_for(&t),
            )
            .await
        }
        Wire::CodexNative | Wire::CodexTranslate => {
            let body = if matches!(wire, Wire::CodexTranslate) {
                // Same request, a model the gateway must TRANSLATE to (mode T).
                let mut v: Value = serde_json::from_slice(&body).expect("json");
                v["model"] = json!("claude-sonnet-4-6");
                Bytes::from(v.to_string())
            } else {
                body
            };
            crate::openai_responses::responses_with_claims(
                state,
                fx.header_map(),
                body,
                claims_for(&t),
            )
            .await
        }
        Wire::GeminiCli => {
            crate::gemini_native::gemini_with_claims(
                state,
                fx.header_map(),
                crate::gemini_native::GeminiBody {
                    model: "gemini-2.5-pro".to_owned(),
                    stream: true,
                    alt_sse: true,
                    raw: body,
                },
                claims_for(&t),
            )
            .await
        }
    };
    let (parts, resp_body) = resp.into_parts();
    let body = axum::body::to_bytes(resp_body, usize::MAX)
        .await
        .expect("response body");
    Replay {
        status: parts.status,
        headers: parts.headers,
        body,
        upstream: server.received_requests().await.unwrap_or_default(),
    }
}

fn sse(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.to_owned(), "text/event-stream")
}

fn error(status: u16, body: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_owned(), "application/json")
}

// ── what each provider answers ──────────────────────────────────────────────

/// Anthropic's own wording for a context overflow. Claude Code's compaction recovery matches on it.
const A_PROMPT_TOO_LONG: &str = r#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 213462 tokens > 200000 maximum"}}"#;
const A_OVERLOADED: &str =
    r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#;
const A_RATE_LIMITED: &str = r#"{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed your organization's rate limit"}}"#;

const O_PROMPT_TOO_LONG: &str = r#"{"error":{"message":"This model's maximum context length is 400000 tokens. However, your messages resulted in 513462 tokens.","type":"invalid_request_error","param":"messages","code":"context_length_exceeded"}}"#;
const O_OVERLOADED: &str =
    r#"{"error":{"message":"The server is overloaded","type":"server_error","code":null}}"#;
const O_RATE_LIMITED: &str = r#"{"error":{"message":"Rate limit reached for gpt-5.5 in organization org-fixture on tokens per min","type":"tokens","param":null,"code":"rate_limit_exceeded"}}"#;

const G_PROMPT_TOO_LONG: &str = r#"{"error":{"code":400,"message":"The input token count (1500000) exceeds the maximum number of tokens allowed (1048576).","status":"INVALID_ARGUMENT"}}"#;
const G_OVERLOADED: &str = r#"{"error":{"code":503,"message":"The model is overloaded. Please try again later.","status":"UNAVAILABLE"}}"#;
const G_RATE_LIMITED: &str = r#"{"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}"#;

/// How a wire's client must see the provider's error. The relays (`/v1/messages`, mode N,
/// Gemini-native) put the provider's own bytes in front of a client that speaks the provider's
/// dialect. Mode T answers an OpenAI-wire client (Codex) with a provider that is NOT OpenAI, so
/// the contract is the translated one: right status class, the provider's own wording preserved
/// in the message, the provider's wait forwarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Contract {
    /// Same status, same body, provider headers forwarded.
    Verbatim,
    /// OpenAI-shaped error of ours; 4xx status kept, wording preserved, 5xx stays 5xx.
    Translated,
}

struct Provider {
    wire: Wire,
    contract: Contract,
    prompt_too_long: &'static str,
    /// A phrase from `prompt_too_long` the client's recovery matches on.
    wording: &'static str,
    overloaded: &'static str,
    rate_limited: &'static str,
}

const PROVIDERS: [Provider; 4] = [
    Provider {
        wire: Wire::ClaudeCode,
        contract: Contract::Verbatim,
        prompt_too_long: A_PROMPT_TOO_LONG,
        wording: "prompt is too long",
        overloaded: A_OVERLOADED,
        rate_limited: A_RATE_LIMITED,
    },
    Provider {
        wire: Wire::CodexNative,
        contract: Contract::Verbatim,
        prompt_too_long: O_PROMPT_TOO_LONG,
        wording: "context_length_exceeded",
        overloaded: O_OVERLOADED,
        rate_limited: O_RATE_LIMITED,
    },
    // Mode T: a Codex request to a model the gateway translates for Anthropic. The CLIENT is
    // still Codex, but what answers is Anthropic — so the upstream bodies are Anthropic's.
    Provider {
        wire: Wire::CodexTranslate,
        contract: Contract::Translated,
        prompt_too_long: A_PROMPT_TOO_LONG,
        wording: "prompt is too long",
        overloaded: A_OVERLOADED,
        rate_limited: A_RATE_LIMITED,
    },
    Provider {
        wire: Wire::GeminiCli,
        contract: Contract::Verbatim,
        prompt_too_long: G_PROMPT_TOO_LONG,
        wording: "exceeds the maximum number of tokens",
        overloaded: G_OVERLOADED,
        rate_limited: G_RATE_LIMITED,
    },
];

/// Assert the JSON the client got is the provider's JSON — same value, scrubbing aside.
fn same_json(got: &str, want: &str) -> bool {
    serde_json::from_str::<Value>(got).ok() == serde_json::from_str::<Value>(want).ok()
}

// ── scenario: upstream errors ───────────────────────────────────────────────

/// **D7.** Claude Code's context-overflow recovery matches on Anthropic's wording; Codex's on
/// `context_length_exceeded`; Gemini CLI's on `INVALID_ARGUMENT` + the token-count message. The
/// gateway must put the provider's own status — and, where the client speaks the provider's
/// dialect, the provider's exact body — in front of the client.
///
/// Wire-by-wire, not a single combined assertion: the failure message names the wire that broke.
#[tokio::test]
async fn og91_a_400_prompt_too_long_is_relayed_with_its_status_and_wording_on_every_wire() {
    for p in &PROVIDERS {
        let r = replay(p.wire, None, error(400, p.prompt_too_long)).await;
        match p.contract {
            Contract::Verbatim => assert_eq!(
                r.status,
                StatusCode::BAD_REQUEST,
                "{:?}: the status is the provider's. Body: {}",
                p.wire,
                r.body_text()
            ),
            // OG-94 (Codex source, codex-rs): Codex treats an overflow as RECOVERABLE only as
            // a stream `response.failed` with `error.code = context_length_exceeded` — an
            // HTTP 400 is opaque to it. So a streaming mode-T replay answers 200 + that event.
            Contract::Translated => assert!(
                r.body_text()
                    .contains("\"code\":\"context_length_exceeded\""),
                "{:?}: an overflow must reach Codex as `context_length_exceeded`. Got {} {}",
                p.wire,
                r.status,
                r.body_text()
            ),
        }
        match p.contract {
            Contract::Verbatim => assert!(
                same_json(&r.body_text(), p.prompt_too_long),
                "{:?}: the client must receive the provider's error body, not ours — recovery \
                 that matches on the wording would silently stop working. Got: {}",
                p.wire,
                r.body_text()
            ),
            Contract::Translated => assert!(
                r.body_text().contains(p.wording),
                "{:?}: the provider's wording must survive translation, or the client is told \
                 only 'rejected with HTTP 400' and cannot act. Got: {}",
                p.wire,
                r.body_text()
            ),
        }
        assert_eq!(
            r.upstream.len(),
            1,
            "{:?}: exactly one upstream call",
            p.wire
        );
    }
}

/// **D7 / OG-10.** 529 stays 529 (never our 502) on the relays, and the retry hint reaches the
/// client. Mode T has no 529 to hand an OpenAI-wire client: it must stay a 5xx.
#[tokio::test]
async fn og91_a_529_is_relayed_as_a_529_with_retry_after_on_every_wire() {
    for p in &PROVIDERS {
        let r = replay(
            p.wire,
            None,
            error(529, p.overloaded).insert_header("retry-after", "7"),
        )
        .await;
        match p.contract {
            Contract::Verbatim => {
                assert_eq!(
                    r.status.as_u16(),
                    529,
                    "{:?}: a 529 must not become a 502 — the client's overload retry keys on \
                     it. Body: {}",
                    p.wire,
                    r.body_text()
                );
                assert_eq!(
                    r.header("retry-after"),
                    Some("7"),
                    "{:?}: the provider's retry-after reaches the client",
                    p.wire
                );
                assert!(
                    same_json(&r.body_text(), p.overloaded),
                    "{:?}: {}",
                    p.wire,
                    r.body_text()
                );
            }
            Contract::Translated => assert!(
                r.status.is_server_error(),
                "{:?}: an overloaded provider is a 5xx the client retries, got {}",
                p.wire,
                r.status
            ),
        }
    }
}

/// **OG-10 / C7.** A provider 429 with `Retry-After: 20`: the gateway makes exactly ONE upstream
/// call (it never retries the client's call behind its back at the provider's expense) and the
/// client is told to wait 20 s — on every wire, mode T included.
#[tokio::test]
async fn og91_a_429_with_retry_after_20_is_one_upstream_call_and_the_header_reaches_the_client() {
    for p in &PROVIDERS {
        let r = replay(
            p.wire,
            None,
            error(429, p.rate_limited).insert_header("retry-after", "20"),
        )
        .await;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{:?}", p.wire);
        assert_eq!(
            r.upstream.len(),
            1,
            "{:?}: a 429 with Retry-After must not be retried (amplification, D5)",
            p.wire
        );
        assert_eq!(
            r.header("retry-after"),
            Some("20"),
            "{:?}: the client learns the PROVIDER's wait, not a guess",
            p.wire
        );
    }
}

// ── scenario: the tool round trip ───────────────────────────────────────────

/// A real-shaped Anthropic stream carrying `ping` keepalives (one before the first block, one
/// between blocks — Anthropic sends them through long thinking), a text block and a `tool_use`.
const A_TOOL_SSE: &str = concat!(
    "event: message_start\n",
    r#"data: {"type":"message_start","message":{"id":"msg_01OG91","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"stop_reason":null,"usage":{"input_tokens":812,"output_tokens":1}}}"#,
    "\n\n",
    "event: ping\n",
    r#"data: {"type": "ping"}"#,
    "\n\n",
    "event: content_block_start\n",
    r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
    "\n\n",
    "event: content_block_delta\n",
    r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"It is 18C."}}"#,
    "\n\n",
    "event: ping\n",
    r#"data: {"type": "ping"}"#,
    "\n\n",
    "event: content_block_stop\n",
    r#"data: {"type":"content_block_stop","index":0}"#,
    "\n\n",
    "event: content_block_start\n",
    r#"data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01OG91NEXT","name":"get_weather","input":{}}}"#,
    "\n\n",
    "event: content_block_delta\n",
    r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"Lyon\"}"}}"#,
    "\n\n",
    "event: content_block_stop\n",
    r#"data: {"type":"content_block_stop","index":1}"#,
    "\n\n",
    "event: message_delta\n",
    r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":31}}"#,
    "\n\n",
    "event: message_stop\n",
    r#"data: {"type":"message_stop"}"#,
    "\n\n",
);

/// Anthropic's reply to Codex's mode-T request: text, a call to the FREEFORM tool, a call to the
/// function tool.
const A_CODEX_SSE: &str = concat!(
    "event: message_start\n",
    r#"data: {"type":"message_start","message":{"id":"msg_01OG91T","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"stop_reason":null,"usage":{"input_tokens":900,"output_tokens":1}}}"#,
    "\n\n",
    "event: content_block_start\n",
    r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_P","name":"apply_patch","input":{}}}"#,
    "\n\n",
    "event: content_block_delta\n",
    r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"input\":\"*** Begin Patch\\n*** End Patch\"}"}}"#,
    "\n\n",
    "event: content_block_stop\n",
    r#"data: {"type":"content_block_stop","index":0}"#,
    "\n\n",
    "event: content_block_start\n",
    r#"data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_S","name":"shell","input":{}}}"#,
    "\n\n",
    "event: content_block_delta\n",
    r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":[\"cargo\",\"test\"]}"}}"#,
    "\n\n",
    "event: content_block_stop\n",
    r#"data: {"type":"content_block_stop","index":1}"#,
    "\n\n",
    "event: message_delta\n",
    r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":42}}"#,
    "\n\n",
    "event: message_stop\n",
    r#"data: {"type":"message_stop"}"#,
    "\n\n",
);

/// OpenAI's reply (mode N): a `function_call` item and `response.completed`.
const O_TOOL_SSE: &str = concat!(
    "event: response.created\n",
    r#"data: {"type":"response.created","sequence_number":0,"response":{"id":"resp_og91","object":"response","status":"in_progress","model":"gpt-5.5","output":[]}}"#,
    "\n\n",
    "event: response.output_item.done\n",
    r#"data: {"type":"response.output_item.done","sequence_number":1,"output_index":0,"item":{"id":"fc_og91","type":"function_call","status":"completed","call_id":"call_og91_2","name":"shell","arguments":"{\"command\":[\"cargo\",\"test\",\"--lib\"]}"}}"#,
    "\n\n",
    "event: response.completed\n",
    r#"data: {"type":"response.completed","sequence_number":2,"response":{"id":"resp_og91","object":"response","status":"completed","model":"gpt-5.5","output":[],"usage":{"input_tokens":700,"input_tokens_details":{"cached_tokens":0},"output_tokens":20,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":720}}}"#,
    "\n\n",
);

/// Gemini's reply: a `functionCall` part.
const G_TOOL_SSE: &str = concat!(
    r#"data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Lyon"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":400,"candidatesTokenCount":12,"totalTokenCount":412},"modelVersion":"gemini-2.5-pro"}"#,
    "\n\n",
);

fn text_after<'a>(haystack: &'a str, needle: &str) -> &'a str {
    haystack.split_once(needle).map_or("", |(_, rest)| rest)
}

/// **Claude Code.** The two-turn tool history (tool_use → tool_result) goes upstream
/// BYTE-IDENTICAL, and the new `tool_use` block comes back byte-identical — `ping` events and all.
#[tokio::test]
async fn og91_tool_round_trip_claude_code_is_byte_faithful_both_ways() {
    let fx = Wire::ClaudeCode.fixture();
    let r = replay(Wire::ClaudeCode, None, sse(A_TOOL_SSE)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body_text());
    assert_eq!(
        r.body_text(),
        A_TOOL_SSE,
        "the client must receive the provider's SSE bytes unchanged"
    );
    assert_eq!(
        r.upstream.last().expect("call").body,
        fx.raw_body.as_bytes(),
        "the history — tool_use, tool_result, cache_control, thinking — reaches Anthropic as sent"
    );
}

/// **Codex, mode N.** `additional_tools` + `namespace` + the freeform `apply_patch` +
/// `store:false` + `include` reach OpenAI untouched; the `function_call` item comes back as is.
#[tokio::test]
async fn og91_tool_round_trip_codex_mode_n_is_byte_faithful_both_ways() {
    let fx = Wire::CodexNative.fixture();
    let r = replay(Wire::CodexNative, None, sse(O_TOOL_SSE)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body_text());
    assert_eq!(r.body_text(), O_TOOL_SSE);
    assert_eq!(
        r.upstream.last().expect("call").body,
        fx.raw_body.as_bytes(),
        "responses-lite request fields reach the provider exactly as Codex sent them"
    );
}

/// **Codex, mode T.** A Codex request to a model the gateway translates: the freeform tool's call
/// returns as a `custom_tool_call` carrying the RAW string (Codex applies it as a patch), the
/// function tool's as a `function_call`; and the namespaced tools and the history reached the
/// provider in ITS dialect.
#[tokio::test]
async fn og91_tool_round_trip_codex_mode_t_returns_a_custom_tool_call_as_a_custom_tool_call() {
    let r = replay(Wire::CodexTranslate, None, sse(A_CODEX_SSE)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body_text());
    let text = r.body_text();
    assert!(
        text.contains(r#""type":"custom_tool_call""#)
            || text.contains(r#""type": "custom_tool_call""#),
        "the freeform tool's call must come back as a custom_tool_call, not a function_call: {text}"
    );
    assert!(
        text.contains("*** Begin Patch\\n*** End Patch"),
        "the raw freeform input string survives: {text}"
    );
    assert!(
        text.contains(r#""name":"shell""#) || text.contains(r#""name": "shell""#),
        "the function tool's call survives: {text}"
    );
    let sent = r.upstream_json();
    let names: Vec<&str> = sent["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["shell", "apply_patch"],
        "the namespace is flattened: both tools reached the provider"
    );
    let rendered = sent["messages"].to_string();
    assert!(
        rendered.contains("tool_use") && rendered.contains("call_og91_1"),
        "the function_call history is translated: {rendered}"
    );
    assert!(
        rendered.contains("tool_result") && rendered.contains("1 passed; 1 failed"),
        "the function_call_output history is translated: {rendered}"
    );
}

/// **Gemini CLI.** The `functionCall` / `functionResponse` history reaches Google as sent and the
/// new `functionCall` comes back unchanged. M-2 (2026-10-02) had the request egress as the
/// re-serialised parse; M-A (security re-review 2026-10-03) refuses a duplicated key at parse
/// instead, so the CLI's own bytes are their only reading and egress byte-identical again.
#[tokio::test]
async fn og91_tool_round_trip_gemini_cli_is_byte_faithful_both_ways() {
    let fx = Wire::GeminiCli.fixture();
    let r = replay(Wire::GeminiCli, None, sse(G_TOOL_SSE)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body_text());
    assert_eq!(r.body_text(), G_TOOL_SSE);
    assert_eq!(
        r.upstream.last().expect("call").body,
        fx.raw_body.as_bytes(),
        "the CLI's bytes reach Google unchanged"
    );
}

// ── scenario: an image part ─────────────────────────────────────────────────

/// The fixture with an image appended to its last user turn, in the client's own dialect.
fn with_image(wire: Wire) -> Bytes {
    let mut v = wire.fixture().json();
    match wire {
        Wire::ClaudeCode => {
            let last = v["messages"]
                .as_array_mut()
                .expect("messages")
                .last_mut()
                .expect("m");
            last["content"]
                .as_array_mut()
                .expect("content")
                .push(json!({
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/png", "data": PNG_B64}
                }));
        }
        Wire::CodexNative | Wire::CodexTranslate => {
            let input = v["input"].as_array_mut().expect("input");
            let user = input
                .iter_mut()
                .find(|i| i["role"] == "user")
                .expect("user message");
            user["content"]
                .as_array_mut()
                .expect("content")
                .push(json!({
                    "type": "input_image",
                    "image_url": format!("data:image/png;base64,{PNG_B64}")
                }));
        }
        Wire::GeminiCli => {
            let last = v["contents"]
                .as_array_mut()
                .expect("contents")
                .last_mut()
                .expect("c");
            last["parts"].as_array_mut().expect("parts").push(json!({
                "inlineData": {"mimeType": "image/png", "data": PNG_B64}
            }));
        }
    }
    Bytes::from(v.to_string())
}

/// **An image part is never silently dropped.** It reaches the upstream body, or the client gets
/// a 400 that NAMES it — the D1 contract, on the client-facing wires.
#[tokio::test]
async fn og91_an_image_part_reaches_the_upstream_body_or_is_refused_by_name_on_every_wire() {
    for (wire, ok) in [
        (Wire::ClaudeCode, sse(A_TOOL_SSE)),
        (Wire::CodexNative, sse(O_TOOL_SSE)),
        (Wire::CodexTranslate, sse(A_CODEX_SSE)),
        (Wire::GeminiCli, sse(G_TOOL_SSE)),
    ] {
        let r = replay(wire, Some(with_image(wire)), ok).await;
        if let Some(call) = r.upstream.last() {
            assert!(
                String::from_utf8_lossy(&call.body).contains(PNG_B64),
                "{wire:?}: the request was dispatched ({}) but the image is not in the body the \
                 provider received — a silent drop",
                r.status
            );
        } else {
            assert_eq!(
                r.status,
                StatusCode::BAD_REQUEST,
                "{wire:?}: {}",
                r.body_text()
            );
            let t = r.body_text();
            assert!(
                t.contains("image") || t.contains("content"),
                "{wire:?}: the 400 must name the part it refused: {t}"
            );
        }
    }
}

// ── scenario: SSE keepalive ─────────────────────────────────────────────────

/// Claude Code aborts a stream after minutes of silence; Anthropic keeps it alive with `ping`
/// events. The relay must forward them, not swallow them as "not content".
#[tokio::test]
async fn og91_claude_code_sse_ping_is_relayed_not_dropped() {
    let r = replay(Wire::ClaudeCode, None, sse(A_TOOL_SSE)).await;
    assert_eq!(
        r.body_text().matches("event: ping").count(),
        2,
        "both keepalive frames must reach the client: {}",
        text_after(&r.body_text(), "message_start")
    );
}

// ── scenario: request headers ───────────────────────────────────────────────

fn assert_no_tlane_key_upstream(r: &Replay, wire: Wire) {
    for call in &r.upstream {
        for (name, value) in &call.headers {
            assert!(
                !value.as_bytes().windows(6).any(|w| w == b"tlane_"),
                "{wire:?}: our credential leaked upstream in header `{name}`"
            );
        }
        assert!(
            !call.url.as_str().contains("tlane_"),
            "{wire:?}: our credential leaked upstream in the URL"
        );
    }
}

/// `anthropic-beta` and `anthropic-version` reach Anthropic VERBATIM (a stripped beta header turns
/// Claude Code's features off); the credential is the tenant's own key, never ours.
#[tokio::test]
async fn og91_claude_code_headers_beta_and_version_verbatim_and_our_key_never_forwarded() {
    let fx = Wire::ClaudeCode.fixture();
    let r = replay(Wire::ClaudeCode, None, sse(A_TOOL_SSE)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body_text());
    let call = r.upstream.last().expect("call");
    let got = |n: &str| call.headers.get(n).and_then(|v| v.to_str().ok());
    assert_eq!(got("anthropic-beta"), Some(fx.header("anthropic-beta")));
    assert_eq!(
        got("anthropic-version"),
        Some(fx.header("anthropic-version"))
    );
    assert_eq!(
        got("x-api-key"),
        Some(BYOK_ANTHROPIC),
        "the tenant's own key"
    );
    assert!(
        got("authorization").is_none(),
        "no bearer reaches Anthropic"
    );
    assert_no_tlane_key_upstream(&r, Wire::ClaudeCode);
}

/// Codex's own headers reach OpenAI; the credential is the tenant's own OpenAI key.
#[tokio::test]
async fn og91_codex_headers_session_and_turn_metadata_forwarded_and_our_key_never() {
    let fx = Wire::CodexNative.fixture();
    let r = replay(Wire::CodexNative, None, sse(O_TOOL_SSE)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body_text());
    let call = r.upstream.last().expect("call");
    let got = |n: &str| call.headers.get(n).and_then(|v| v.to_str().ok());
    assert_eq!(got("session-id"), Some(fx.header("session-id")));
    assert_eq!(
        got("x-codex-turn-metadata"),
        Some(fx.header("x-codex-turn-metadata"))
    );
    assert_eq!(
        got("authorization"),
        Some(format!("Bearer {BYOK_OPENAI}").as_str()),
        "the tenant's own key"
    );
    assert_no_tlane_key_upstream(&r, Wire::CodexNative);
}

/// The Gemini key rides in `x-goog-api-key` (never the URL), and it is the tenant's own.
#[tokio::test]
async fn og91_gemini_cli_headers_key_is_the_tenants_in_a_header_and_ours_never_forwarded() {
    let r = replay(Wire::GeminiCli, None, sse(G_TOOL_SSE)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body_text());
    let call = r.upstream.last().expect("call");
    assert_eq!(
        call.headers
            .get("x-goog-api-key")
            .and_then(|v| v.to_str().ok()),
        Some(BYOK_GOOGLE)
    );
    assert!(
        call.url.query().is_none_or(|q| !q.contains("key=")),
        "a credential in a URL is refused on this repo: {}",
        call.url
    );
    assert_no_tlane_key_upstream(&r, Wire::GeminiCli);
}
