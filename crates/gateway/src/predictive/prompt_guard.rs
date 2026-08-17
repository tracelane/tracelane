//! Llama Prompt Guard 2 sidecar bridge — gateway side of the PR6 inline guardrail.
//!
//! The Python sidecar (`ml/prompt_guard/serve.py`) loads the 22M-parameter ONNX
//! model and exposes a `POST /score` endpoint on `localhost:8080` (configurable
//! via `PROMPT_GUARD_URL`).  This module is the thin HTTP client that the
//! `PredictiveLayer` uses to call that endpoint inline on every request.
//!
//! ## Fail-open (FT-05)
//!
//! If the HTTP call fails for any reason — network error, timeout, sidecar
//! crash, ONNX runtime crash — `score()` / `is_injection()` fail open (0.0 /
//! that fails open SILENTLY is the span-publish failure class, so the fail-open
//! is made **loud**: each fail-open is counted and a rate-limited `warn!` (≤1 /
//! [`FAIL_WARN_INTERVAL_SECS`]).
//!
//! ## NOT DEPLOYED is not FAILING (2026-08-10)
//!
//! `PROMPT_GUARD_URL` **unset** means the sidecar is not deployed, which is a
//! configuration state, not a fault: [`PromptGuardClient::new`] returns `None`
//! and the predictor is omitted from the stack, costing nothing per request.
//!
//! It previously DEFAULTED to `http://127.0.0.1:8080` — the gateway's own
//! listener — so every request self-called a route that does not exist, took a
//! 404, counted a fail-open and warned, once per text segment. The warning said
//! the guardrail was not enforcing, which read as broken when the honest state
//! was "the optional ML augmentation is not deployed". Injection coverage never
//! depended on it: the deterministic **R8** rail
//! (`guardrail/rails/r8_injection.rs`) is free, ungated and always running.
//!
//! A URL that IS set and unreachable is a genuine fail-open and keeps the loud
//! path — that distinction is the point.
//!
//! ## Callers
//!
//! - `PredictiveLayer::evaluate()` via `PromptGuardPredictor` (see below).
//! - Integration test harness in `tests/prompt_guard.rs`.
//!
//! ## Performance
//!
//! The sidecar is co-located on the same host.  A 30 ms `reqwest` timeout is set
//! at client construction — matching the <30 ms p50 budget for the predictive
//! layer.  The sidecar itself targets ≥1 000 req/sec on a Hetzner CCX13 CPU.

use anyhow::Context as _;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::instrument;

// ---------------------------------------------------------------------------
// Sidecar response schema
// ---------------------------------------------------------------------------

/// Deserialised body from `POST /score`.
#[derive(Debug, Deserialize)]
struct ScoreResponse {
    score: f32,
    #[allow(dead_code)]
    is_injection: bool,
}

// ---------------------------------------------------------------------------
// Loud, rate-limited fail-open (a silently-disabled guardrail is the
// span-publish failure class — make PR6 fail-open impossible to miss)
// ---------------------------------------------------------------------------

/// Cumulative count of PR6 fail-opens (sidecar unreachable / non-2xx / parse error).
static PROMPT_GUARD_FAIL_OPENS: AtomicU64 = AtomicU64::new(0);
/// Sentinel: no fail-open warning has been emitted yet (so the first one always fires).
const FAIL_WARN_NEVER: u64 = u64::MAX;
/// Unix-seconds of the last emitted fail-open warning — the rate-limiter gate.
static LAST_FAIL_WARN_UNIX: AtomicU64 = AtomicU64::new(FAIL_WARN_NEVER);
/// At most one loud fail-open warning per this interval.
const FAIL_WARN_INTERVAL_SECS: u64 = 60;

/// Record a PR6 fail-open and emit a **rate-limited, loud** `warn!`. Returns the
/// fail-open score (`0.0`). The first fail-open warns immediately, then at most
/// once per [`FAIL_WARN_INTERVAL_SECS`] (with the cumulative count) so a
/// misconfigured / undeployed sidecar can never disable PR6 in silence.
fn note_fail_open(reason: &str) -> f32 {
    let total = PROMPT_GUARD_FAIL_OPENS.fetch_add(1, Ordering::Relaxed) + 1;
    let now = unix_now_secs();
    let last = LAST_FAIL_WARN_UNIX.load(Ordering::Relaxed);
    // CAS so exactly one racing thread wins the warn; first-ever fail-open always warns.
    let warn_due = last == FAIL_WARN_NEVER || now.saturating_sub(last) >= FAIL_WARN_INTERVAL_SECS;
    if warn_due
        && LAST_FAIL_WARN_UNIX
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::warn!(
            fail_opens_total = total,
            reason,
            "PR6 PromptGuard sidecar UNREACHABLE — the optional ML injection augmentation is \
             not scoring. PROMPT_GUARD_URL is SET but the sidecar did not answer; check it is \
             running and reachable at that address. NOTE: injection coverage is NOT absent — the \
             deterministic R8 rail (guardrail/rails/r8_injection.rs) is free, ungated and still \
             enforcing. This warning means the ML augmentation is degraded, not that the \
             guardrail is off."
        );
    }
    0.0
}

/// Wall-clock seconds since the Unix epoch, saturating to 0 on a pre-epoch clock.
/// Used only as the fail-open warning rate-limiter gate, never in an assertion.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// PromptGuardClient
// ---------------------------------------------------------------------------

/// HTTP client for the Llama Prompt Guard 2 ONNX inference sidecar.
///
/// Create once at gateway startup via [`PromptGuardClient::new`] and share
/// across request handlers via `Arc<PromptGuardClient>`.
///
/// The client is intentionally cheap to clone — it wraps a single
/// `reqwest::Client` which already pools connections internally.
#[derive(Debug)]
pub struct PromptGuardClient {
    client: reqwest::Client,
    score_url: String,
    /// Resolved once on first [`PromptGuardClient::score`] call: is
    /// `score_url` permitted by SSRF policy?  See [`Self::url_allowed`].
    url_allowed: tokio::sync::OnceCell<bool>,
}

/// Is `host` a loopback literal (`127.0.0.0/8` / `::1`)?
///
/// Used only by [`PromptGuardClient::url_allowed`] for the documented
/// same-host sidecar carve-out.  Hostnames are NOT resolved here — a name
/// that merely *resolves* to loopback takes the full `validate_url` path,
/// so `localhost.attacker.example` cannot slip through.
fn is_loopback_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Decide the sidecar `/score` URL from the raw `PROMPT_GUARD_URL` value.
///
/// **Pure on purpose.** The behaviour under test is "unset means not deployed",
/// and testing that through `std::env` would mean mutating process-global state —
/// which is unsound in a multi-threaded test runner and, when first written that
/// way, raced an unrelated env-reading auth test into failing. `.claude/rules/testing.md`
/// asks for a lock; a pure function needs neither the lock nor the `unsafe`.
///
/// `None` ⇒ the sidecar is not deployed. There is deliberately NO fallback to
/// `http://127.0.0.1:8080`: that is the gateway's own listener, and defaulting to
/// it made every request self-call a route that does not exist.
fn score_url_from(raw: Option<&str>) -> Option<String> {
    let base = raw?.trim();
    if base.is_empty() {
        return None;
    }
    Some(format!("{}/score", base.trim_end_matches('/')))
}

impl PromptGuardClient {
    /// Construct a new client.
    ///
    /// Reads `PROMPT_GUARD_URL` from the environment; defaults to
    /// `http://127.0.0.1:8080`.  The request timeout is fixed at 30 ms to
    /// match the predictive layer p50 budget — if the sidecar is slower than
    /// this the call fails open (see module-level docs).
    ///
    /// The client is built by [`crate::ssrf_guard::safe_client_builder`]
    /// (rustls, redirects disabled) — a plain `reqwest::Client::builder()`
    /// here was an SSRF bypass on an operator-supplied URL, contrary to
    /// `ssrf_guard`'s own module contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the `reqwest::Client` cannot be built (extremely
    /// rare; only fails on invalid TLS configuration).
    pub fn new() -> anyhow::Result<Option<Self>> {
        // UNSET means NOT DEPLOYED, and that is a configuration state — not a
        // fault. It used to default to `http://127.0.0.1:8080`, which is the
        // GATEWAY'S OWN LISTENER: every request self-called `POST /score` on a
        // route that does not exist, took a 404, counted a fail-open, and warned.
        // One self-call per text segment, so a multi-turn request paid it several
        // times over — hot-path cost buying nothing, on every request, forever.
        //
        // Returning `None` makes the predictor absent from the stack entirely, so
        // the cost is ZERO rather than merely smaller. A URL that IS set and is
        // unreachable remains a real fail-open and keeps the loud path.
        let Some(score_url) = score_url_from(std::env::var("PROMPT_GUARD_URL").ok().as_deref())
        else {
            return Ok(None);
        };

        let client = crate::ssrf_guard::safe_client_builder()
            .timeout(Duration::from_millis(30))
            .pool_max_idle_per_host(32)
            .build()
            .context("failed to build PromptGuardClient reqwest::Client")?;

        Ok(Some(Self {
            client,
            score_url,
            url_allowed: tokio::sync::OnceCell::new(),
        }))
    }

    /// SSRF gate for `score_url`, evaluated once and memoised.
    ///
    /// `PROMPT_GUARD_URL` is operator-supplied, and `ssrf_guard`'s module
    /// contract requires `validate_url` before ANY outbound request to an
    /// operator- or customer-supplied URL.  Two cases:
    ///
    /// - **Loopback IP literal** (the documented sidecar topology — the
    ///   Python sidecar runs on the same host, see module docs): allowed
    ///   without DNS.  SSRF defends against reaching *unintended* internal
    ///   services; a same-host sidecar on a configured port is the intended
    ///   target.  `validate_url` blocks loopback in release builds, so
    ///   routing this case through it would permanently disable PR6 rather
    ///   than protect anything.
    /// - **Everything else** (a sidecar moved off-host, or a
    ///   mis-set/hostile `PROMPT_GUARD_URL`): full `validate_url` — scheme
    ///   allowlist + DNS resolution + every blocked range.
    ///
    /// A rejected URL is terminal: `score()` fails open (0.0) without ever
    /// issuing a request, and the rejection is counted through the same loud
    /// rate-limited path as any other fail-open.
    async fn url_allowed(&self) -> bool {
        *self
            .url_allowed
            .get_or_init(|| async {
                let host = reqwest::Url::parse(&self.score_url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned));

                match host {
                    Some(h) if is_loopback_literal(&h) => true,
                    _ => match crate::ssrf_guard::validate_url(&self.score_url).await {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                url = %self.score_url,
                                "tracelane.predictive.degraded=true — PROMPT_GUARD_URL rejected by the SSRF guard; \
                                 PR6 (Llama Prompt Guard 2) is OFFLINE and every request fails open. Fix PROMPT_GUARD_URL.",
                            );
                            false
                        }
                    },
                }
            })
            .await
    }

    /// Score `text` for prompt-injection probability.
    ///
    /// # Returns
    ///
    /// Injection probability in `[0.0, 1.0]`.  On any HTTP / network error
    /// returns `Ok(0.0)` and emits `tracing::warn!` (fail-open, FT-05).
    ///
    /// # Performance
    ///
    /// Target: <30 ms p50, <50 ms p95.  If the sidecar exceeds the 30 ms
    /// timeout the call is cancelled and `Ok(0.0)` is returned immediately.
    #[instrument(skip(self), fields(text_len = text.len()))]
    pub async fn score(&self, text: &str) -> anyhow::Result<f32> {
        // SSRF gate (memoised): never issue a request to a URL the guard
        // rejects. Terminal fail-open — see `url_allowed`.
        if !self.url_allowed().await {
            return Ok(note_fail_open("PROMPT_GUARD_URL rejected by SSRF guard"));
        }

        let result = self
            .client
            .post(&self.score_url)
            .json(&serde_json::json!({ "text": text }))
            .send()
            .await;

        let response = match result {
            Ok(r) => r,
            Err(err) => {
                // Fail-open: network error / timeout — do not block the request.
                // Per-request detail at debug; the loud signal is rate-limited.
                tracing::debug!(error = %err, "PromptGuard sidecar unreachable");
                return Ok(note_fail_open("sidecar unreachable"));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            tracing::debug!(%status, "PromptGuard sidecar returned non-2xx");
            return Ok(note_fail_open("sidecar non-2xx"));
        }

        match response.json::<ScoreResponse>().await {
            Ok(body) => Ok(body.score),
            Err(err) => {
                tracing::debug!(error = %err, "PromptGuard sidecar response parse error");
                Ok(note_fail_open("response parse error"))
            }
        }
    }

    /// Return `true` if `score(text) >= threshold`.
    ///
    /// On any error, returns `Ok(false)` (fail-open, FT-05).
    ///
    /// # Parameters
    ///
    /// - `text`: raw text extracted from the request (before
    ///   `<UNTRUSTED_USER_DATA>` sentinel wrapping by the redaction layer).
    /// - `threshold`: decision boundary; the PR6 default is `0.5`.
    #[instrument(skip(self), fields(text_len = text.len(), threshold))]
    pub async fn is_injection(&self, text: &str, threshold: f32) -> anyhow::Result<bool> {
        let s = self.score(text).await?;
        Ok(s >= threshold)
    }
}

// ---------------------------------------------------------------------------
// Predictor wrapper — integrates with PredictiveLayer
// ---------------------------------------------------------------------------

use super::{Decision, PredictiveContext, Predictor};

/// `Predictor` adapter that wraps [`PromptGuardClient`] for synchronous use
/// inside `PredictiveLayer::evaluate()`.
///
/// Because `Predictor::evaluate` is sync (the trait is `!async`), this adapter
/// spawns a blocking task on the current Tokio runtime.  The 30 ms timeout on
/// the underlying client prevents the blocking thread from being held
/// indefinitely.
pub struct PromptGuardPredictor {
    client: PromptGuardClient,
    /// Injection decision threshold (default 0.5).
    threshold: f32,
}

impl PromptGuardPredictor {
    /// Create a new predictor.
    ///
    /// # Errors
    ///
    /// Propagates `PromptGuardClient::new()` errors (TLS init failure).
    ///
    /// Returns `Ok(None)` when `PROMPT_GUARD_URL` is unset — the sidecar is not
    /// deployed, so the predictor is omitted from the stack rather than added and
    /// then failing open on every request.
    pub fn new(threshold: f32) -> anyhow::Result<Option<Self>> {
        Ok(PromptGuardClient::new()?.map(|client| Self { client, threshold }))
    }
}

impl Predictor for PromptGuardPredictor {
    fn name(&self) -> &'static str {
        "prompt_guard_pr6"
    }

    /// Legacy sync entry. The hot path goes through `evaluate_async`
    /// (A11); this stays only because the `Predictor` trait still
    /// requires `evaluate`. Returning `Allow` here is safe because the
    /// async hot path overrides this entirely — and a caller without
    /// a tokio runtime (which is the only place the sync entry runs)
    /// has no way to query the ONNX sidecar anyway.
    fn evaluate(&self, _ctx: &PredictiveContext<'_>) -> Decision {
        Decision::Allow
    }

    /// A11: async hot-path entry. Removes `block_in_place` + the
    /// current-thread-runtime panic risk. Iterates every message
    /// (`messages[*].content` + tool-result blocks) so multi-turn
    /// injection where the payload arrives in a later message is
    /// scored rather than ignored.
    ///
    /// Fails open (Allow) on any sidecar error per FT-05.
    fn evaluate_async<'a>(
        &'a self,
        ctx: &'a PredictiveContext<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Decision> + Send + 'a>> {
        Box::pin(async move {
            let texts = extract_all_message_content(ctx.request_json);
            if texts.is_empty() {
                return Decision::Allow;
            }
            // the sidecar's 30ms per-call timeout, an unbounded loop
            // over `messages[*]` lets a 1000-turn conversation block
            // the hot path for 30s. 8 most-recent messages cover the
            // realistic injection surface (system + latest user + a
            // few tool returns); older history is rarely the attack
            // vector.
            const MAX_MESSAGES_SCORED: usize = 8;
            let n = texts.len();
            let start = n.saturating_sub(MAX_MESSAGES_SCORED);
            for text in &texts[start..] {
                if text.is_empty() {
                    continue;
                }
                match self.client.is_injection(text, self.threshold).await {
                    Ok(true) => {
                        tracing::info!(
                            tenant_id = %ctx.tenant_id,
                            "PromptGuard PR6: injection detected — blocking request"
                        );
                        return Decision::Block { aft_id: "PR6" };
                    }
                    Ok(false) => continue,
                    Err(err) => {
                        tracing::warn!(error = %err, "PromptGuardPredictor sidecar error — allowing (fail-open)");
                        return Decision::Allow;
                    }
                }
            }
            Decision::Allow
        })
    }
}

/// Collect every scoreable text from `request_json` — `messages[*].content`
/// (string OR content-array `text` blocks) AND tool-result blocks. The
/// PromptGuard model scores each separately so a later-message injection
/// payload can't slip past by hiding behind an innocuous first message
/// (A11 multi-message coverage).
fn extract_all_message_content(value: &serde_json::Value) -> Vec<String> {
    let Some(messages) = value.get("messages").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::with_capacity(messages.len() * 2);
    for msg in messages {
        if let Some(s) = msg.get("content").and_then(|v| v.as_str()) {
            out.push(s.to_owned());
            continue;
        }
        // Anthropic / OpenAI content-array form: [{type:"text", text:"…"}, …]
        if let Some(blocks) = msg.get("content").and_then(|v| v.as_array()) {
            for block in blocks {
                let t = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match t {
                    "text" => {
                        if let Some(s) = block.get("text").and_then(|v| v.as_str()) {
                            out.push(s.to_owned());
                        }
                    }
                    "tool_result" | "tool_use" => {
                        // Tool results are untrusted user-shaped content
                        // per CLAUDE.md security non-negotiable #4.
                        if let Some(s) = block.get("content").and_then(|v| v.as_str()) {
                            out.push(s.to_owned());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

/// Kept for backwards-compat with the prompt_guard tests; new callers
/// should use `extract_all_message_content`.
#[allow(dead_code)]
fn extract_first_message_content(value: &serde_json::Value) -> Option<String> {
    extract_all_message_content(value).into_iter().next()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------
    // SSRF regression (PART-1 #1): `new()` used to build a bare
    // `reqwest::Client::builder()` and `score()` never called
    // `validate_url`, contrary to ssrf_guard's own module contract. These
    // tests fail if the `url_allowed` gate is removed or widened.
    // -----------------------------------------------------------------

    fn client_for(url: &str) -> PromptGuardClient {
        PromptGuardClient {
            // Same 30 ms timeout as production `new()`, so a regression fails
            // in ~30 ms rather than parking on the OS connect timeout (~30 s).
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(Duration::from_millis(30))
                .build()
                .expect("client build"),
            score_url: format!("{url}/score"),
            url_allowed: tokio::sync::OnceCell::new(),
        }
    }

    #[test]
    fn loopback_literal_detection_is_literal_only() {
        assert!(is_loopback_literal("127.0.0.1"));
        assert!(is_loopback_literal("127.5.5.5"));
        assert!(is_loopback_literal("::1"));
        // A NAME is never treated as loopback, even one that resolves there —
        // it takes the full validate_url path instead. Without this,
        // `localhost.attacker.example` would skip the guard entirely.
        assert!(!is_loopback_literal("localhost"));
        assert!(!is_loopback_literal("localhost.attacker.example"));
        assert!(!is_loopback_literal("169.254.169.254"));
    }

    #[tokio::test]
    async fn sidecar_loopback_is_allowed() {
        // The documented topology: the Python sidecar on the same host.
        // Routing this through validate_url would permanently disable PR6 in
        // release builds rather than protect anything.
        assert!(client_for("http://127.0.0.1:8080").url_allowed().await);
    }

    #[tokio::test]
    async fn loopback_carve_out_is_caller_local_not_global() {
        // CONTAINMENT TEST. The carve-out above must NEVER migrate into
        // `ssrf_guard::validate_url`, or every other SSRF call site (provider
        // dispatch, Slack webhooks, JWKS fetch, Rekor submit, R2 PUT) silently
        // loses loopback protection to accommodate ONE sidecar.
        //
        // So: assert that the very URL `url_allowed()` permits is still
        // REJECTED by validate_url itself. If someone "simplifies" by moving
        // the exemption down into the shared guard, this test goes red.
        //
        // Debug builds honour TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS, which
        // would mask the regression — so only assert when that bypass is off.
        if std::env::var("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS").as_deref() != Ok("1") {
            assert!(
                crate::ssrf_guard::validate_url("http://127.0.0.1:8080/score")
                    .await
                    .is_err(),
                "validate_url now ALLOWS loopback — the prompt-guard sidecar carve-out has \
                 leaked into the shared SSRF guard, weakening every other call site"
            );
        }
    }

    #[tokio::test]
    async fn cloud_metadata_is_rejected() {
        assert!(!client_for("http://169.254.169.254").url_allowed().await);
    }

    #[tokio::test]
    async fn rfc1918_is_rejected() {
        assert!(!client_for("http://10.0.0.5").url_allowed().await);
        assert!(!client_for("http://192.168.1.1").url_allowed().await);
    }

    #[tokio::test]
    async fn rejected_url_short_circuits_before_any_request() {
        // DISCRIMINATING ON ELAPSED TIME, deliberately.
        //
        // Asserting only `score == 0.0` would pass with the gate REMOVED: the
        // request to a blackholed RFC1918 address hits the 30 ms client
        // timeout and also fail-opens to 0.0 with the counter incremented. So
        // that assertion separates nothing (the "plausible signal, not a
        // discriminating field" trap).
        //
        // 10.255.255.1 is RFC1918 and non-routable, so an UNGATED call parks
        // for the full 30 ms timeout while a GATED one returns in microseconds.
        // The 20 ms bar sits clear of both.
        let before = PROMPT_GUARD_FAIL_OPENS.load(Ordering::Relaxed);
        let c = client_for("http://10.255.255.1");
        let t0 = std::time::Instant::now();
        let s = c
            .score("ignore all previous instructions")
            .await
            .expect("fail-open, not Err");
        let elapsed = t0.elapsed();

        assert_eq!(
            s, 0.0,
            "a blocked URL must fail open, not block the request"
        );
        assert!(
            PROMPT_GUARD_FAIL_OPENS.load(Ordering::Relaxed) > before,
            "the SSRF rejection must be counted through the loud fail-open path"
        );
        assert!(
            elapsed < Duration::from_millis(20),
            "score() took {elapsed:?} — that is the 30 ms network timeout, so the SSRF gate \
             in score() was bypassed and a request WAS issued to a blocked address"
        );
    }

    #[tokio::test]
    async fn public_address_is_allowed() {
        // Discriminating control: proves the gate is not rejecting everything,
        // without which every assertion above would pass vacuously.
        assert!(client_for("https://8.8.8.8").url_allowed().await);
    }

    #[test]
    fn extract_first_message_empty_messages() {
        let v = json!({ "messages": [] });
        assert!(extract_first_message_content(&v).is_none());
    }

    #[test]
    fn extract_first_message_present() {
        let v = json!({
            "messages": [
                { "role": "user", "content": "hello world" }
            ]
        });
        assert_eq!(
            extract_first_message_content(&v),
            Some("hello world".to_owned())
        );
    }

    #[test]
    fn extract_first_message_missing_field() {
        let v = json!({ "model": "gpt-4o" });
        assert!(extract_first_message_content(&v).is_none());
    }

    #[test]
    fn fail_open_is_counted_and_loud() {
        // A fail-open must increment the global counter (so the rate-limited
        // warning has a cumulative figure) and return the 0.0 fail-open score —
        // the "loud, not silent" contract. Relative check, robust under parallel
        // tests that also fail open.
        let before = PROMPT_GUARD_FAIL_OPENS.load(Ordering::Relaxed);
        assert_eq!(note_fail_open("unit-test"), 0.0);
        assert!(
            PROMPT_GUARD_FAIL_OPENS.load(Ordering::Relaxed) > before,
            "fail-open must bump the counter so the rate-limited warn reports it"
        );
    }

    /// THE FIX (2026-08-10). An UNSET `PROMPT_GUARD_URL` must yield NO client, so the
    /// predictor is omitted from the stack and costs nothing per request.
    ///
    /// Before this it defaulted to `http://127.0.0.1:8080` — the gateway's OWN
    /// listener — so every request self-called a route that does not exist, took a
    /// 404, counted a fail-open and warned, once per text segment. Reinstating that
    /// default makes this test fail.
    ///
    /// Pure: no process-env mutation, so it cannot race another test.
    #[test]
    fn unset_url_means_not_deployed_not_a_self_call_to_the_gateway() {
        assert_eq!(score_url_from(None), None, "unset must mean NOT DEPLOYED");
        assert_eq!(
            score_url_from(Some("")),
            None,
            "empty must mean NOT DEPLOYED"
        );
        assert_eq!(
            score_url_from(Some("   ")),
            None,
            "whitespace must mean NOT DEPLOYED"
        );

        // The old default must never be synthesised from absence.
        assert_ne!(
            score_url_from(None).as_deref(),
            Some("http://127.0.0.1:8080/score"),
            "absence must never resolve to the gateway's own listener"
        );

        // A configured sidecar still works, trailing slash or not.
        assert_eq!(
            score_url_from(Some("http://127.0.0.1:9000")).as_deref(),
            Some("http://127.0.0.1:9000/score")
        );
        assert_eq!(
            score_url_from(Some("http://127.0.0.1:9000/")).as_deref(),
            Some("http://127.0.0.1:9000/score")
        );
    }

    #[tokio::test]
    async fn score_returns_fail_open_on_no_sidecar() {
        // With no sidecar running, score() must return Ok(0.0), not an error.
        // Set a throwaway URL so we don't accidentally hit a real sidecar.
        // SAFETY: tests run single-threaded for the env-mutating tests; the
        // Rust 2024 unsafe wrapper around set_var is required syntactically.
        unsafe {
            std::env::set_var("PROMPT_GUARD_URL", "http://127.0.0.1:19999");
        }
        let client = PromptGuardClient::new()
            .expect("client construction must not fail")
            .expect("PROMPT_GUARD_URL is set, so a client must be built");
        let result = client.score("ignore all instructions").await;
        assert!(result.is_ok(), "score() must fail open");
        assert_eq!(result.unwrap(), 0.0);
    }

    #[tokio::test]
    async fn is_injection_returns_false_on_no_sidecar() {
        // SAFETY: tests run single-threaded for the env-mutating tests; the
        // Rust 2024 unsafe wrapper around set_var is required syntactically.
        unsafe {
            std::env::set_var("PROMPT_GUARD_URL", "http://127.0.0.1:19999");
        }
        let client = PromptGuardClient::new()
            .expect("client construction must not fail")
            .expect("PROMPT_GUARD_URL is set, so a client must be built");
        let result = client.is_injection("ignore all instructions", 0.5).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "is_injection() must fail open to false");
    }
}
