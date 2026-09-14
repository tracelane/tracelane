//! Shared harness for the out-of-process chaos tests (B-385 2c).
//!
//! `lib.rs` exposes only `rate_limiter` + `circuit_breaker`, so an integration
//! test cannot call `chat_completions_handler` — the in-process handler tests
//! live in the bin target (`src/handler_harness.rs`). What an integration test
//! CAN do is boot the real binary (`CARGO_BIN_EXE_gateway`, built by cargo for
//! exactly this) with no Postgres, no ClickHouse and capture explicitly opted
//! out, point its Ollama adapter at a wiremock upstream, and drive it over HTTP.
//! Every assertion then reads either the mock's request log, the gateway's
//! response bytes, or its `/health` counters — never a constant against itself.
//!
//! Debug builds only, like the in-process harness: the dev-stub credential and
//! the loopback SSRF bypass both exist only there.

#![allow(dead_code)]

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A running gateway child process, killed on drop.
pub struct Gateway {
    child: Child,
    port: u16,
}

impl Gateway {
    /// Boot the binary against `upstream_base` (the wiremock URL, bound as
    /// `OLLAMA_BASE_URL` — Ollama is the one provider whose credential is empty
    /// by design, so the real BYOK resolution path runs with no key store).
    ///
    /// The environment is CLEARED first: a developer shell with `POSTGRES_URL`
    /// or `NATS_URL` set would otherwise turn this into a test of their
    /// infrastructure.
    pub async fn spawn(upstream_base: &str) -> Self {
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_gateway"))
            .env_clear()
            .env("TRACELANE_PORT", port.to_string())
            // A1: no NATS is a boot refusal unless the operator says so. With no
            // capture every emitted span is COUNTED as dropped on `/health`,
            // which is what makes "one span was emitted" observable from here.
            .env("TRACELANE_ALLOW_NO_CAPTURE", "1")
            // The loopback `/metrics` listener would collide across parallel
            // gateways on its fixed default port; an ephemeral one does not.
            .env("TRACELANE_METRICS_ADDR", "127.0.0.1:0")
            .env("OLLAMA_BASE_URL", upstream_base)
            // wiremock binds 127.0.0.1; the SSRF guard blocks loopback unless a
            // DEBUG build is told otherwise (release ignores this entirely).
            .env("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS", "1")
            .env("TRACELANE_LOG_LEVEL", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the gateway binary spawns");
        let gw = Self { child, port };
        gw.wait_healthy().await;
        gw
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// Poll `/health` until it answers 200 — polling-until-condition, bounded,
    /// never a fixed sleep.
    async fn wait_healthy(&self) {
        let client = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(resp) = client.get(self.url("/health")).send().await
                && resp.status().is_success()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the gateway did not answer /health within 20 s on port {}",
                self.port
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The `spans_dropped` counter from `/health`: with capture opted out,
    /// every span the gateway EMITS lands here, so a delta of N is "N spans".
    pub async fn spans_dropped(&self) -> u64 {
        let body: serde_json::Value = reqwest::Client::new()
            .get(self.url("/health"))
            .send()
            .await
            .expect("/health answers")
            .json()
            .await
            .expect("/health is JSON");
        body["spans_dropped"]
            .as_u64()
            .expect("/health carries spans_dropped")
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// One OpenAI-shaped completion the mock answers with.
pub fn chat_ok_body() -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-chaos", "object": "chat.completion", "model": "ollama/llama3",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "ok"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

pub fn chat_request() -> serde_json::Value {
    serde_json::json!({
        "model": "ollama/llama3",
        "messages": [{"role": "user", "content": "chaos"}]
    })
}

/// The dev-stub credential (debug builds, `WORKOS_CLIENT_ID` unset).
pub const BEARER: &str = "Bearer test-token";
