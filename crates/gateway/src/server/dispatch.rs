//! Provider dispatch — the round-trip half of the hot path (B-385 §2d split of `server.rs`).
//!
//! BYOK key resolution (`resolve_provider_key`), the model→adapter dispatch
//! (`dispatch_to_provider`, which DELEGATES routing to the one canonical map),
//! the A7 retry loop, the bench-mock double gate, the breaker's trip input, the
//! post-ledger error-span funnel (`emit_post_ledger_error_span`) and the
//! `DispatchGuard` that records a client hanging up mid-await (B-375 b).

use std::sync::Arc;

use tracelane_shared::{TenantId, TracelaneSpan};
use uuid::Uuid;

use super::AppState;
use super::errors::{DispatchFailure, classify_dispatch_error};
use super::spans::{CallerIdentity, SpanUsageMeta, build_gateway_span};

/// Breaker outcome for a dispatch result, or `None` to feed the breaker NOTHING.
///
/// SRE audit finding 38. An upstream 4xx that is not a 429 is not an observation about
/// the upstream's health, and the breaker has no tenant dimension — so recording it
/// lets one tenant's dead key open the circuit for everyone on that provider.
///
/// It returns `None` rather than `Some(true)` deliberately: recording a 401 as a
/// SUCCESS would reset `consecutive_failures` and could hold a breaker closed over a
/// genuinely dead upstream. Same posture as the cache-hit skip above — feeding the
/// breaker an observation that did not happen is worse than feeding it nothing.
pub(super) fn breaker_outcome<T>(result: &anyhow::Result<T>) -> Option<bool> {
    match result {
        Ok(_) => Some(true),
        Err(err) => match err.downcast_ref::<crate::providers::ProviderHttpError>() {
            Some(http) if !http.is_upstream_fault() => None,
            _ => Some(false),
        },
    }
}

/// R13 — emit the error-status span for a request that ALREADY HAS A LEDGER ROW.
///
/// # Why this exists as one function
///
/// Past `state.audit_chain.publish(...)` on the chat path, the tamper-evident ledger
/// asserts the request happened. **A return from there without a span is a request the
/// ledger attests to and the product cannot show** — a customer reconciling their audit
/// export against `/traces` finds a gap, and nothing anywhere reports one. Measured
/// 2026-08-14 (B-245 §5.2): **~500 such rows fleet-wide**, on every tenant with traffic,
/// at 5–8% of requests, present from the first day of the current ledger.
///
/// Three call sites already did this correctly and three did not, and the three that did
/// were **the same ten lines copy-pasted** — which is exactly how the other three came to
/// be missed. One definition means a new post-ledger exit is one line away from correct,
/// and it is what makes `scripts/ci/check-post-ledger-span-emit.py` able to check the
/// property mechanically: the guard looks for a call to THIS function, so it matches a
/// construction rather than a word (`TRAPS.md` §19).
///
/// # Errors
/// None — infallible by construction. This is a **fault-tolerance** path: failing to
/// record a span must never change the response the customer already earned. The publish
/// is detached and its failure is counted by `note_span_publish_failed()`.
// 8 params since ADR-075 threaded `parent_span_id` alongside `trace_id`; the two travel
// together everywhere a span is built, and a struct for them would be one more shape.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_post_ledger_error_span(
    state: &AppState,
    tenant_id: &TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    model: &str,
    // B-367. This funnel used to take no caller identity at all, so an errored or
    // guardrail-blocked request answered "who initiated this" with nothing — on
    // exactly the request a customer opens Tracelane to investigate.
    identity: &CallerIdentity,
    request_start: chrono::DateTime<chrono::Utc>,
    reason: &str,
    aft_id: Option<&str>,
) {
    let span = build_error_span(
        tenant_id,
        trace_id,
        parent_span_id,
        model,
        identity,
        request_start,
        reason,
        aft_id,
    );
    // Test seam (B-385 2c): observable to a test whether or not NATS is wired.
    #[cfg(test)]
    crate::otlp_emit::test_sink::record(&span);
    // No NATS ⇒ capture is not wired at all (opted out with TRACELANE_ALLOW_NO_CAPTURE).
    // COUNT the drop like the other three emit sites do: `spans_dropped` is the live
    // signal, and an error span lost here is a span lost. (B-385's harness found this
    // site returning without counting — /health undercounted error spans in
    // no-capture mode.)
    let Some(ref nats_client) = state.nats else {
        crate::otlp_emit::note_span_dropped_no_nats();
        return;
    };
    crate::otlp_emit::spawn_publish(Arc::clone(nats_client), span, "post-ledger error");
}

/// Minimal Error-status span for a request that FAILED before or during the
/// provider round-trip (dispatch exhaustion, upstream 401/429/404/5xx, timeout).
/// Zero tokens, no cost, no optional attribution — its whole job is to make the
/// failure COUNTABLE (status_code = 2) so the error-rate metric reflects reality
/// instead of a structural 0%. Reuses `build_gateway_span` so the shape stays one
/// definition.
// EIGHT arguments, and the allow is the same call the other seven span-building
// functions in this file already make: every one is a distinct, named fact about the
// request, so bundling them further would only hide which is which. `CallerIdentity`
// already collapsed the five that WERE alike, which is the part that mattered.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_error_span(
    tenant_id: &TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    model: &str,
    identity: &CallerIdentity,
    start_time: chrono::DateTime<chrono::Utc>,
    reason: &str,
    // `Some` when a guardrail block maps to a canonical AFT-1 signature, so the
    // blocked hit still lands in `spans.aft_ids` and the tenant sees it on
    // /signatures — a blocked injection is "your hit", not a silent 403 (#5).
    //
    // This ABSORBED `build_blocked_aft_span`, which was a byte-for-byte copy of this
    // function differing only in passing `Some(aft_id)` here. Its sole caller already
    // branched on `Option<&str>` and then chose between two identical bodies.
    aft_id: Option<&str>,
) -> TracelaneSpan {
    build_gateway_span(
        tenant_id,
        trace_id,
        parent_span_id,
        model,
        // B-367: the caller's own identity now reaches the error path. An errored
        // or blocked span carries the same agent / authorizer / business ref /
        // end user / conversation as the successful one would have.
        identity,
        start_time,
        0,
        0,
        aft_id,
        SpanUsageMeta {
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
            stream: false,
            cost_usd: None,
        },
        None,
        None, // timing: no measured provider round-trip on a failure/block span
        Some(reason),
        // GWY-43: no key attribution on an error span. It carries zero tokens and
        // zero cost, so it cannot move a per-key spend total; attributing FAILURES
        // by key is a separate feature, and inventing a value here would put a
        // dimension on a row whose cost is structurally absent.
        None,
    )
}

/// Map a model name to a canonical provider name (OTel `gen_ai.system` /
/// `gen_ai.provider.name` value) for span attribution.
///
/// This DELEGATES to the canonical `ProviderRegistry::provider_id_for_model`
/// rather than carrying its own prefix table. A private copy had drifted — it only
/// knew 8 prefixes and stamped every other model (groq, mistral, perplexity, xai,
/// and the rest of the catalog) as `"unknown"` on the span, so the dashboard's provider
/// column + per-provider latency tiles were blank/"unknown" for most real traffic.
/// Only the two names that differ from the provider_id (AWS/GCP house style) are
/// remapped; the rest of the provider_id set already equals the gen_ai.system value.
pub(crate) fn provider_name_from_model(model: &str) -> &'static str {
    // An unmatched model has no provider — attribute it "unknown" (this is
    // a span label, never a key lookup, so "unknown" is safe; the key path already
    // fail-closed on None before reaching here).
    match crate::providers::ProviderRegistry::provider_id_for_model(model) {
        Some("vertex") => "gcp_vertex_ai",
        Some("bedrock") => "aws_bedrock",
        Some(other) => other,
        None => "unknown",
    }
}

/// Outcome of resolving a provider key. Distinguishes "the tenant never added
/// one" from "one exists but we cannot use it" — the two need OPPOSITE user
/// actions (add a key vs rotate an existing one), and collapsing them into a
/// single `None` is what made an unconfigured provider report
/// `provider_key_rejected` ("verify the key for this provider") to a user who
/// had no key to verify.
pub(crate) enum ProviderKey {
    /// A usable key. An EMPTY string is a legitimate value for the no-key
    /// providers (Ollama) — it means "this provider needs no credential".
    /// `Arc<SecretString>` because that is the shape the decrypted-key cache
    /// already holds, so the plaintext is never copied out of it; the ONLY
    /// `expose_secret()` is at the hop that builds the upstream header.
    Found(std::sync::Arc<secrecy::SecretString>),
    /// No BYOK row and no env fallback: the tenant has not configured this
    /// provider. Actionable in Settings → LLM Providers.
    NotConfigured,
    /// A BYOK row exists but could not be decrypted (AAD / master-key
    /// mismatch). A key IS configured — telling the user to add one would send
    /// them the wrong way.
    Unusable,
    /// B-380: the control plane could not be READ (a Postgres / Neon error), so
    /// whether this tenant has a key is unknown. Transient — the customer gets a
    /// 503 and retries. It is its own variant because the alternative that shipped
    /// was falling through to the process environment: during a Neon outage every
    /// tenant would have spent whatever `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` the
    /// operator's container carried. Fail-CLOSED on a credential path (§10).
    LookupFailed,
}

/// B-380: may a tenant's provider key come from the process ENVIRONMENT?
///
/// Only when there is no control plane at all — single-tenant self-host, where
/// the env IS the tenant's configuration — or in debug-build dev mode, which
/// has a Postgres pool but no BYOK master key (release builds refuse to boot in
/// that state, `A4`). With a control plane AND a master key, a missing BYOK row
/// means NOT CONFIGURED: the operator's own credential is never spent for a
/// tenant, and never on a lookup error either. Same shape and same reason as the
/// bench grant in `.claude/rules/tenancy.md` — one auditable site, closed by
/// default.
pub(crate) fn env_fallback_allowed(has_control_plane: bool, has_master_key: bool) -> bool {
    !(has_control_plane && has_master_key)
}

/// A4: resolve the provider-API plaintext key. Order:
///   1. Hot-path cache (`db::provider_keys::lookup_cached`).
///   2. Per-tenant BYOK row from `provider_keys` (decrypted with AAD).
///   3. Process env var (legacy single-tenant fallback).
///   4. Empty string (Ollama / no-key providers).
///
/// Returns [`ProviderKey::Found`] when we have a key to use, and a typed
/// failure otherwise so the caller can tell the customer what to actually DO
/// (add a key vs rotate one) instead of dispatching an empty credential and
/// relaying the upstream 401.
///
/// The `SecretString` stays wrapped; each dispatch site exposes it exactly
/// once, at the hop that builds the upstream header value.
/// `pub(crate)` for `prompt_eval`, for the same reason as `dispatch_to_provider`:
/// eval traffic resolves credentials exactly the way real traffic does.
pub(crate) async fn resolve_provider_key(
    tenant_id: &TenantId,
    provider_id: &str,
    env_var: &str,
) -> ProviderKey {
    use std::sync::Arc;

    if let Some(secret) = crate::db::provider_keys::lookup_cached(tenant_id, provider_id) {
        return ProviderKey::Found(secret);
    }

    let pool = crate::db::global_pool();
    let master = crate::byok::master_key();
    if let (Some(pool), Some(master)) = (pool, master) {
        match crate::db::provider_keys::get(pool, tenant_id, provider_id).await {
            Ok(Some(row)) => {
                let aad = crate::byok::provider_key_aad(tenant_id, provider_id);
                match master.decrypt_with_context(&row.ciphertext_b64, &aad) {
                    Ok(plaintext) => {
                        let secret = Arc::new(plaintext);
                        crate::db::provider_keys::cache_decrypted(
                            tenant_id,
                            provider_id,
                            Arc::clone(&secret),
                        );
                        return ProviderKey::Found(secret);
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            tenant_id = %tenant_id,
                            provider_id,
                            "BYOK decrypt failed — refusing env fallback (auth-fail safer)"
                        );
                        return ProviderKey::Unusable;
                    }
                }
            }
            // B-380: with a control plane present, "no row" is the tenant's answer,
            // not an invitation to spend the operator's key.
            Ok(None) => {
                if env_var.is_empty() {
                    return ProviderKey::Found(Arc::new(
                        secrecy::SecretString::from(String::new()),
                    )); // Ollama / no-key providers
                }
                return ProviderKey::NotConfigured;
            }
            // B-380: a lookup ERROR is not "no key" and is not "use the env". It is
            // "we cannot tell", and the only safe answer to that is to refuse.
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tenant_id = %tenant_id,
                    provider_id,
                    "provider_keys lookup failed — REFUSING (503), no env fallback"
                );
                return ProviderKey::LookupFailed;
            }
        }
    }
    debug_assert!(
        env_fallback_allowed(pool.is_some(), master.is_some()),
        "env fallback reached with a control plane and a master key present"
    );

    if env_var.is_empty() {
        return ProviderKey::Found(Arc::new(secrecy::SecretString::from(String::new()))); // Ollama
    }
    match std::env::var(env_var) {
        Ok(k) => ProviderKey::Found(Arc::new(secrecy::SecretString::from(k))),
        Err(_) => ProviderKey::NotConfigured,
    }
}

/// True for the reserved benchmark-only model names that, when
/// `TRACELANE_BENCH_MOCK_UPSTREAM` is enabled, route to an instant in-gateway
/// mock instead of a real provider — used to isolate gateway overhead
/// (`bench/gateway/`). The `__bench_` prefix is namespaced so it cannot collide
/// with any real model id, and it only matters when the flag is on; in normal
/// operation a request for one of these models dispatches like any other.
fn is_bench_mock_model(model: &str) -> bool {
    model.starts_with("__bench_mock")
}

/// Synthetic `provider_id` for the bench-mock path.
///
/// Deliberately NOT a real provider id. It is used only for span/log
/// attribution on a request whose dispatch is replaced by the in-gateway mock,
/// so it must never collide with a routable provider — if it did, a mocked
/// request could attribute cost or a BYOK lookup to a real provider.
/// `bench_mock_provider_id_is_not_routable` asserts the non-collision.
pub(super) const BENCH_MOCK_PROVIDER_ID: &str = "__bench_mock";

/// The double gate, as a pure function so all four quadrants are testable
/// without standing up the handler.
///
/// BOTH conditions must hold. Either alone fails closed:
/// - flag ON + real model  -> `false`, normal routing/BYOK path untouched
/// - flag OFF + mock model -> `false`, falls through to 400 `unroutable_model`
pub(crate) fn bench_mock_active(flag: bool, model: &str) -> bool {
    flag && is_bench_mock_model(model)
}

/// A7: retry the same-provider dispatch on TRANSIENT failure, inside the
/// FT-01 backoff budget. The original error is preserved if the retry also
/// fails.
///
/// Today this is intentionally same-provider only — true cross-provider
/// failover (Claude → GPT-5) needs request-shape translation that is
/// V1.5 work (BLOCKERS).
///
/// B-391 (2026-09-12) changed two things about the loop, both from the
/// independent review:
///
/// 1. **It classifies before it retries.** A 401 (rejected key), 404 (unknown
///    model) or any other 4xx is the same answer the second time; repeating the
///    request spent a provider call to learn nothing. Only [`retry_worthwhile`]
///    outcomes go round again.
/// 2. **The 200 ms budget bounds the BACKOFF, not the attempt.** It used to be
///    measured from the first attempt's start, so any upstream failure that
///    surfaced later than ~100 ms — which is every real 5xx, TLS handshake
///    included — exhausted the budget before the retry could fire. The
///    `failover.rs` policy already defines the budget as
///    `planned_backoff_ms() < FAILOVER_BUDGET_MS`, i.e. the sum of pauses; the
///    loop now measures exactly that.
pub(super) async fn dispatch_with_retry(
    registry: &crate::providers::ProviderRegistry,
    chat_request: &tracelane_shared::ChatRequest,
    provider_key: &str,
    model: &str,
    tenant_id: &tracelane_shared::TenantId,
    // GWY-44: the retry count and backoff come from the operator's
    // `tracelane.yaml` `failover:` block when one is installed, and from
    // `RetryPolicy::BUILTIN` (1 retry, 100 ms) otherwise — so every deployment
    // without a config file behaves exactly as it did. B-386 (b): resolved by
    // the caller from `AppState::failover` (read once at boot), not from a
    // process global here.
    policy: crate::providers::failover::RetryPolicy,
) -> anyhow::Result<crate::providers::ProviderStream> {
    let budget = std::time::Duration::from_millis(crate::providers::failover::FAILOVER_BUDGET_MS);
    retry_loop(policy, budget, model, || {
        dispatch_to_provider(
            registry,
            chat_request.clone(),
            provider_key,
            model,
            tenant_id,
        )
    })
    .await
}

/// A transport failure (no HTTP status at all — refused, reset, DNS, timeout)
/// is retried only when the attempt failed FAST. A refused or reset connection
/// fails in milliseconds and a second try is cheap; a failure that took longer
/// than this is a slow upstream or a client timeout (the adapters' clients are
/// built with a 300 s timeout), and repeating that wait is not a retry, it is a
/// doubled outage. HTTP-status failures are not subject to this cut-off: a 503
/// is a 503 however long the provider took to say so.
const TRANSPORT_RETRY_CUTOFF: std::time::Duration = std::time::Duration::from_secs(2);

/// B-391 (a): whether a failed attempt is worth an identical second request.
///
/// Pure, so the four quadrants are testable without a provider:
/// - upstream 5xx / 429 → yes (transient by the provider's own account)
/// - upstream 401 / 403 / 404 / other 4xx → no (the same request gets the same
///   answer; retrying spends a call and delays the honest error)
/// - no upstream status (transport) → yes iff the attempt failed within
///   [`TRANSPORT_RETRY_CUTOFF`]
fn retry_worthwhile(err: &anyhow::Error, attempt_took: std::time::Duration) -> bool {
    match err.downcast_ref::<crate::providers::ProviderHttpError>() {
        Some(_) => matches!(
            classify_dispatch_error(err),
            DispatchFailure::Unavailable | DispatchFailure::RateLimited
        ),
        None => attempt_took < TRANSPORT_RETRY_CUTOFF,
    }
}

/// The retry loop, generic over the attempt so it can be driven by a closure
/// in tests. `budget` bounds the SUM of backoff pauses (see
/// [`dispatch_with_retry`]); each attempt's own duration is bounded by the
/// adapter's client timeout, not by this loop.
async fn retry_loop<T, F, Fut>(
    policy: crate::providers::failover::RetryPolicy,
    budget: std::time::Duration,
    model: &str,
    mut attempt_fn: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let backoff = std::time::Duration::from_millis(policy.backoff_ms);
    let loop_started = std::time::Instant::now();
    let mut backoff_spent = std::time::Duration::ZERO;

    let mut attempt: u32 = 0;
    let mut first_err: Option<anyhow::Error> = None;
    loop {
        let attempt_started = std::time::Instant::now();
        match attempt_fn().await {
            Ok(s) => {
                if attempt > 0 {
                    tracing::info!(
                        model = %model,
                        attempt,
                        elapsed_ms = loop_started.elapsed().as_millis(),
                        "tracelane.failover.activated=true (same-provider retry succeeded)"
                    );
                }
                return Ok(s);
            }
            Err(err) => {
                let attempt_took = attempt_started.elapsed();
                let give_up = |err: anyhow::Error, first_err: Option<anyhow::Error>| match first_err
                {
                    Some(first) => err.context(first.to_string()),
                    None => err,
                };
                // Out of attempts.
                if attempt >= policy.retries {
                    return Err(give_up(err, first_err));
                }
                // Not a transient failure: the same request gets the same
                // answer, so return the honest error now.
                if !retry_worthwhile(&err, attempt_took) {
                    tracing::debug!(
                        error = %err,
                        attempt,
                        attempt_took_ms = attempt_took.as_millis(),
                        "provider failed with a non-transient error; not retrying"
                    );
                    return Err(give_up(err, first_err));
                }
                // Out of backoff budget. Checked BEFORE sleeping, so the sleep
                // itself can never be what breaches the ceiling.
                if backoff_spent + backoff > budget {
                    tracing::warn!(
                        error = %err,
                        attempt,
                        "provider failed; retry budget exhausted, no further attempt"
                    );
                    return Err(give_up(err, first_err));
                }
                tracing::warn!(
                    error = %err,
                    model = %model,
                    attempt,
                    backoff_ms = policy.backoff_ms,
                    "provider attempt failed — retrying"
                );
                if first_err.is_none() {
                    first_err = Some(err);
                }
                attempt += 1;
                backoff_spent += backoff;
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Routes a chat request to the correct provider adapter.
///
/// The provider is resolved by the SINGLE canonical model→provider table
/// `ProviderRegistry::provider_id_for_model`, then this match selects the typed
/// adapter by that provider_id. It deliberately does NOT re-match model prefixes
/// — a second model-prefix table is exactly what drifted (Groq family dispatched
/// here but the BYOK key was looked up under "anthropic"). Adapter selection by
/// provider_id is a fixed enumeration that cannot drift on model names. Keep this
/// arm set a superset of `provider_id_for_model`'s outputs; `_` mirrors that
/// table's `anthropic` default. Enforced by `scripts/ci/check-provider-mapping-single-source.py`.
/// `pub(crate)` for `prompt_eval`: an eval case must go through the SAME
/// dispatch the chat path uses, with the tenant's own BYOK credential. A second
/// dispatch path would be a second place for provider routing to drift, which is
/// the class this function's own comments exist to prevent.
pub(crate) async fn dispatch_to_provider(
    registry: &crate::providers::ProviderRegistry,
    request: tracelane_shared::ChatRequest,
    api_key: &str,
    model: &str,
    tenant_id: &tracelane_shared::TenantId,
) -> anyhow::Result<crate::providers::ProviderStream> {
    use crate::providers::ProviderRegistry;

    // Fail closed. No default provider — an unmatched model bails here too
    // (defense in depth; the handler already rejected it before resolving a key).
    let Some(provider_id) = ProviderRegistry::provider_id_for_model(model) else {
        anyhow::bail!("unroutable model '{model}': no provider configured");
    };
    match provider_id {
        // The six native adapters — genuinely different wire formats.
        "anthropic" => registry.anthropic.chat(request, api_key, tenant_id).await,
        "vertex" => registry.vertex.chat(request, api_key, tenant_id).await,
        "google" => registry.google.chat(request, api_key, tenant_id).await,
        "bedrock" => registry.bedrock.chat(request, api_key, tenant_id).await,
        "azure" => registry.azure.chat(request, api_key, tenant_id).await,
        "cohere" => registry.cohere.chat(request, api_key, tenant_id).await,
        // GWY-42: every OpenAI-compatible provider, from the one catalog. This
        // was 29 hand-written arms that had to mirror 29 struct fields, and a
        // provider present in `provider_id_for_model` but missing an arm here
        // bailed as "unroutable" AFTER its BYOK key had already been fetched.
        other => match registry.compat(other) {
            Some(p) => p.chat(request, api_key, tenant_id).await,
            // NO default-to-anthropic. A provider_id the dispatch doesn't
            // know is a bug in the catalog, not "probably Anthropic" — bail
            // rather than ship a request to the wrong provider with the wrong key.
            None => anyhow::bail!("unroutable provider_id '{provider_id}' for model '{model}'"),
        },
    }
}

/// Requests whose client hung up while the provider was still being awaited —
/// before any stream existed (streaming), or before the buffered response was
/// assembled (non-streaming). Recorded by [`DispatchGuard`], counted here.
pub(crate) static REQUESTS_CANCELLED_IN_DISPATCH: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// B-375 (b): the record for a request abandoned by its client while the
/// provider was still being awaited.
///
/// `StreamFinalizer` covers a stream that has STARTED. It cannot cover the
/// window before it exists — dispatch (connect, TLS, the provider's own
/// time-to-first-byte), the cross-provider failover's second dispatch, and the
/// whole of a NON-streaming request, whose body is assembled inside one
/// `.await`. hyper drops the handler future when the connection closes, so
/// nothing after the drop point runs; a value with `impl Drop` is the only
/// thing that does. Armed at the dispatch boundary, disarmed by every path that
/// records its own span. What it records: an ERROR span with
/// `status.message = "client_cancelled"`, zero usage (the provider's usage
/// never arrived) and no cost — the flight recorder's job is that the request
/// happened and was abandoned, which is exactly what was missing.
pub(crate) struct DispatchGuard {
    armed: bool,
    state: AppState,
    tenant_id: TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    model: String,
    identity: CallerIdentity,
    request_start: chrono::DateTime<chrono::Utc>,
}

impl DispatchGuard {
    pub(crate) fn arm(
        state: &AppState,
        tenant_id: &TenantId,
        trace_id: Uuid,
        parent_span_id: Option<Uuid>,
        model: &str,
        identity: &CallerIdentity,
        request_start: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            armed: true,
            state: state.clone(),
            tenant_id: tenant_id.clone(),
            trace_id,
            parent_span_id,
            model: model.to_owned(),
            identity: identity.clone(),
            request_start,
        }
    }

    /// The normal paths call this once they own the record.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// A post-ledger REFUSAL: record the error span for `reason` (R13 — the
    /// ledger row exists, so a silent exit would be a request the product
    /// cannot show) and disarm, so `Drop` does not record a second,
    /// `client_cancelled`, span for a request the handler answered. One call
    /// replaces the nine-argument emit + `disarm()` pair at every refusal site
    /// after admission (B-385).
    pub(crate) fn abort(&mut self, reason: &str, aft_id: Option<&str>) {
        emit_post_ledger_error_span(
            &self.state,
            &self.tenant_id,
            self.trace_id,
            self.parent_span_id,
            &self.model,
            &self.identity,
            self.request_start,
            reason,
            aft_id,
        );
        self.armed = false;
    }
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        REQUESTS_CANCELLED_IN_DISPATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Same funnel as a dispatch failure, so the cancellation is countable by
        // the error-rate metric and visible on /traces like any other outcome.
        emit_post_ledger_error_span(
            &self.state,
            &self.tenant_id,
            self.trace_id,
            self.parent_span_id,
            &self.model,
            &self.identity,
            self.request_start,
            "client_cancelled",
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;
    use tracelane_shared::SpanStatusCode;

    /// R13 — a guardrail block whose reason has NO AFT mapping must still be visible.
    ///
    /// This is a DECISION, not a measurement (`TRAPS.md` §27). The old code read
    /// `if let Some(aft_id) = reason_to_aft(reason) { …emit… }` with the 403 returning
    /// unconditionally below it, so the span was gated on the AFT lookup. Injection is
    /// the only live mapping, which meant **every other blocking rail produced a ledger
    /// row, a `guardrail_verdicts` row, a 403 — and nothing in `/traces`.** The customer
    /// was told their request was blocked and could not see the block.
    ///
    /// Both halves are asserted on purpose. The first alone would pass if someone made
    /// `reason_to_aft` return `Some` for everything; the second alone would pass if the
    /// mapping were deleted entirely.
    #[test]
    fn guardrail_block_without_an_aft_mapping_still_produces_a_span() {
        use crate::guardrail::rails::r3_tool_safety::reason_to_aft;

        // (a) The gate that used to suppress the span really does return None for a
        //     blocking reason — i.e. the defect was reachable, not theoretical.
        assert!(
            reason_to_aft(crate::guardrail::outcome::reason_codes::BUDGET_CAP).is_none(),
            "BUDGET_CAP has no AFT mapping — under the old nesting this block emitted NO \
             span at all, which is the defect this test pins"
        );

        // (b) …and the span we now build for it is a real, renderable error span rather
        //     than an empty shell. `aft_id: None` selects build_error_span.
        let span = build_error_span(
            &TenantId::from_jwt_claim("a4037bef-e786-44e3-bfb6-88c93ba9d381".parse().unwrap()),
            Uuid::new_v4(),
            None,
            "claude-haiku-4-5",
            // B-367: an error span carries the caller's identity like any other.
            &CallerIdentity {
                end_user_id: Some("u_blocked".into()),
                conversation_id: Some("sess_blocked".into()),
                ..Default::default()
            },
            chrono::Utc::now(),
            "guardrail_block",
            None,
        );
        assert_eq!(
            span.attributes.user_id.as_deref(),
            Some("u_blocked"),
            "B-367: a BLOCKED request is exactly the one a customer investigates — it must \
             answer 'who initiated this'. This asserted nothing before 2026-09-10 because \
             build_error_span took no caller identity at all."
        );
        assert_eq!(
            span.attributes.gen_ai_conversation_id.as_deref(),
            Some("sess_blocked"),
            "B-367: and which session it belonged to"
        );
        assert_eq!(
            span.status.code,
            tracelane_shared::SpanStatusCode::Error,
            "a blocked request must land as an ERROR span, not a success or Unset one — \
             otherwise it renders as a normal call in /traces"
        );
        assert!(
            span.attributes.tracelane_aft_id.is_none(),
            "no AFT mapping means no signature id — the span must not invent one"
        );

        // (c) And the mapped case still carries its signature, so (a) cannot be
        //     satisfied by deleting the AFT feature.
        let poisoned = build_error_span(
            &TenantId::from_jwt_claim("a4037bef-e786-44e3-bfb6-88c93ba9d381".parse().unwrap()),
            Uuid::new_v4(),
            None,
            "claude-haiku-4-5",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            "guardrail_block",
            Some("AFT-TOOL-POISON-001"),
        );
        assert_eq!(
            poisoned.attributes.tracelane_aft_id.as_deref(),
            Some("AFT-TOOL-POISON-001"),
            "a mapped block must still reach /signatures"
        );
    }

    /// Regression: the span provider-attribution mapping had drifted
    /// from the dispatch/key-lookup mapping and stamped most of the providers
    /// as "unknown" on the span. It now delegates to provider_id_for_model.
    #[test]
    fn provider_name_from_model_matches_dispatch_not_unknown() {
        // Groq-family (the trigger) + other previously-"unknown" providers.
        assert_eq!(provider_name_from_model("llama-3.3-70b-versatile"), "groq");
        assert_eq!(provider_name_from_model("qwen-2.5-32b"), "groq");
        assert_eq!(provider_name_from_model("mistral-large-latest"), "mistral");
        assert_eq!(provider_name_from_model("grok-2"), "xai");
        assert_eq!(
            provider_name_from_model("sonar-pro"),
            "perplexity",
            "sonar must stay perplexity"
        );
        // The two OTel house-style remaps are preserved.
        assert_eq!(
            provider_name_from_model("vertex/gemini-2.5-pro"),
            "gcp_vertex_ai"
        );
        assert_eq!(provider_name_from_model("bedrock/claude"), "aws_bedrock");
        // Known-good baselines still resolve.
        assert_eq!(provider_name_from_model("claude-sonnet-4-6"), "anthropic");
        assert_eq!(provider_name_from_model("gpt-4o"), "openai");
        // The delegation agrees with the canonical mapping by construction.
        assert_eq!(
            provider_name_from_model("llama-3.3-70b-versatile"),
            crate::providers::ProviderRegistry::provider_id_for_model("llama-3.3-70b-versatile")
                .unwrap()
        );
        // An unmatched model attributes "unknown" (never a default provider).
        assert_eq!(provider_name_from_model("totally-unknown-xyz"), "unknown");
    }

    /// Regression: an UNCONFIGURED provider must resolve to `NotConfigured`, not
    /// to an empty key that gets dispatched upstream and comes back as
    /// `provider_key_rejected` ("verify the key for this provider") — advice
    /// aimed at a key the caller never had. Found on the first-value path:
    /// PRODDEMO2 has vertex + anthropic keys and NO openai key, and an openai
    /// call reported the tenant's key as rejected.
    ///
    /// Uses an env var that cannot exist rather than mutating the environment,
    /// so the test leaks no process state (rules/testing.md).
    #[tokio::test]
    async fn unconfigured_provider_resolves_to_not_configured_not_empty_key() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xC0FFEE));

        // No BYOK row (no pool in unit tests) + an env var that is never set.
        let outcome = resolve_provider_key(
            &tenant,
            "openai",
            "TRACELANE_UNIT_TEST_PROVIDER_KEY_VAR_THAT_IS_NEVER_SET",
        )
        .await;
        assert!(
            matches!(outcome, ProviderKey::NotConfigured),
            "an unconfigured provider must be NotConfigured — collapsing it into an empty key is what produced the misleading provider_key_rejected"
        );

        // A no-key provider (Ollama: empty env var name) is still a real
        // resolution — an empty string here is correct, not "not configured".
        assert!(
            matches!(
                resolve_provider_key(&tenant, "ollama", "").await,
                ProviderKey::Found(ref k) if k.expose_secret().is_empty()
            ),
            "a no-credential provider must resolve to Found(\"\"), not NotConfigured"
        );
    }

    /// B-380: the env fallback is a SELF-HOST grant. With a control plane and a
    /// master key present, a missing BYOK row is "not configured" and a lookup
    /// error is "refuse" — the operator's own credential is never spent for a
    /// tenant. Same shape as the bench grant (`.claude/rules/tenancy.md`).
    #[test]
    fn env_fallback_is_only_for_deployments_without_a_control_plane() {
        // single-tenant self-host: no Postgres at all → the env IS the config
        assert!(env_fallback_allowed(false, false));
        assert!(env_fallback_allowed(false, true));
        // debug-build dev mode: pool but no master key (release refuses to boot here)
        assert!(env_fallback_allowed(true, false));
        // hosted: control plane + master key → NEVER the operator's key
        assert!(!env_fallback_allowed(true, true));
    }

    ///  #1 + #5: the span builder maps failure reasons to Error status
    /// (`countIf(status_code = 2)`) and a clean finish to Ok — the exact mapping a
    /// mid-stream sever rides on (the `Some(Err)` arm sets
    /// `stream_error = Some("provider_stream_error")`). Also asserts the
    /// injection-block span carries the AFT id AND Error status (#5).
    #[test]
    fn span_status_reflects_stream_error() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xF1E));
        let t = uuid::Uuid::from_u128(1);
        // Clean finish → Ok.
        let ok = build_gateway_span(
            &tenant,
            t,
            None,
            "claude-sonnet-4-6",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            5,
            5,
            None,
            SpanUsageMeta {
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                stream: true,
                cost_usd: None,
            },
            None,
            None, // timing (not under test here)
            None, // error_reason
            None, // api_key_id
        );
        assert_eq!(ok.status.code, SpanStatusCode::Ok);
        // Mid-stream sever reason (what the `Some(Err)` arm sets) → Error, countable.
        let severed = build_error_span(
            &tenant,
            t,
            None,
            "claude-sonnet-4-6",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            "provider_stream_error",
            None,
        );
        assert_eq!(severed.status.code, SpanStatusCode::Error);
        assert_eq!(
            severed.status.message.as_deref(),
            Some("provider_stream_error")
        );
        // #5: an injection block writes an Error span carrying the canonical AFT id
        // so the blocked hit surfaces on /signatures.
        let poison = build_error_span(
            &tenant,
            t,
            None,
            "claude-sonnet-4-6",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            "guardrail_block",
            Some("AFT-TOOL-POISON-001"),
        );
        assert_eq!(poison.status.code, SpanStatusCode::Error);
        assert_eq!(
            poison.attributes.tracelane_aft_id.as_deref(),
            Some("AFT-TOOL-POISON-001")
        );
    }

    #[test]
    fn bench_mock_model_is_reserved_and_namespaced() {
        // Gating half #2 (the model name): only the reserved `__bench_` prefix
        // matches, so a normal tenant model id can never trip the mock branch —
        // even on a node where TRACELANE_BENCH_MOCK_UPSTREAM is (mis)enabled.
        assert!(is_bench_mock_model("__bench_mock_instant"));
        assert!(is_bench_mock_model("__bench_mock_fast"));
        assert!(!is_bench_mock_model("claude-sonnet-4-6"));
        assert!(!is_bench_mock_model("gpt-5"));
        assert!(!is_bench_mock_model("mock-instant")); // un-prefixed ≠ reserved
    }

    // the bench-mock bypass -----------------------------------

    #[test]
    fn bench_mock_gate_all_four_quadrants() {
        // Gate half #1 (env flag) x half #2 (reserved prefix). Only ON+reserved
        // opens the bypass; the other three MUST fail closed, because the
        // bypass skips BOTH routing and BYOK resolution.
        assert!(
            bench_mock_active(true, "__bench_mock_instant"),
            "ON + reserved must bypass"
        );
        assert!(
            !bench_mock_active(true, "claude-sonnet-4-6"),
            "ON + real model must take the normal path"
        );
        assert!(
            !bench_mock_active(false, "__bench_mock_instant"),
            "OFF + reserved must fall through to unroutable_model"
        );
        assert!(
            !bench_mock_active(false, "claude-sonnet-4-6"),
            "OFF + real model must take the normal path"
        );
    }

    /// INCLUDE_STR GUARD (B-385 2c) — a SINGLE-SITE count, not an order: the bench
    /// gate has exactly one definition and the bench grant exactly one
    /// construction site, across every file that could hold them. The ORDER
    /// (gate after auth, grant denied with a control plane) is proven
    /// behaviourally in `admission::tests`, not here.
    #[test]
    fn bench_gate_and_grant_each_have_exactly_one_site() {
        // Verifier finding (a): the dispatch site used to re-derive
        // `state.bench_mock_upstream && is_bench_mock_model(&model)` inline
        // instead of consuming the unified `bench_mock`. Both agreed at the
        // time, so nothing was broken — but extending `bench_mock_active`
        // (an allowlisted tenant, a renamed env var) would have moved the
        // routing/BYOK bypass without moving the dispatch decision, splitting
        // one gate into two that disagree.
        //
        // Scan only the NON-TEST portion of each file: `include_str!` pulls in
        // this test's own source, so the literals below would count themselves.
        // The boundary is the first test MODULE, not the first `#[cfg(test)]`
        // attribute — `admission.rs` carries a `#[cfg(test)]` FIELD well above
        // its pipeline, and truncating there read the grant site as absent.
        //
        // B-385 §2d split `server.rs` into `server/*.rs`: the set scanned is now
        // EVERY file of the hot path plus the pipeline, so a re-derived gate in
        // any of them is counted rather than escaping into a file this test did
        // not read. Adding a file under `server/` means adding it here.
        let sources: [&'static str; 10] = [
            include_str!("../server.rs"),
            include_str!("chat.rs"),
            include_str!("embeddings.rs"),
            include_str!("dispatch.rs"),
            include_str!("stream.rs"),
            include_str!("buffered.rs"),
            include_str!("spans.rs"),
            include_str!("errors.rs"),
            include_str!("quota.rs"),
            include_str!("../admission.rs"),
        ];
        let non_test = |src: &'static str| &src[..src.find("\nmod tests {").unwrap_or(src.len())];
        let count_non_test = |needle: &str| -> usize {
            sources
                .iter()
                .map(|s| non_test(s).matches(needle).count())
                .sum()
        };
        let needle = concat!("state.", "bench_mock_upstream &&");
        let inline = count_non_test(needle);
        assert_eq!(
            inline, 0,
            "the bench gate is re-derived inline {inline}x — consume the unified \
             `bench_mock` binding instead, or the two decisions can drift apart"
        );
        // `bench_mock_active` is the single definition of the gate. Split
        // literal, same self-match reason — do not write the un-split form
        // anywhere in these files, comments included.
        let def = concat!("fn ", "bench", "_mock_active(");
        assert_eq!(
            sources
                .iter()
                .map(|s| s.matches(def).count())
                .sum::<usize>(),
            1,
            "bench_mock_active must have exactly one definition"
        );
        // The hot path constructs the grant in exactly ONE place — the whole
        // point of B-187d is that bench logic is not scattered across limiters.
        // Since B-385 that place is the admission pipeline.
        let grant = concat!("ResolvedEntitlements::", "bench_unlimited()");
        assert_eq!(
            count_non_test(grant),
            1,
            "the bench grant is constructed more than once in the hot path"
        );
    }

    #[test]
    fn bench_grant_drives_every_limiter() {
        use crate::entitlement_cache::ResolvedEntitlements as RE;
        let g = RE::bench_unlimited();

        // MECHANISM, not outcome. Assert each enforcement point SHORT-CIRCUITS
        // off this one grant — not that N requests happen to pass. Outcome tests
        // were vacuous twice here: 100k requests pass a 4.29e9-token bucket.
        //
        // BILL-01 / ADR-076 deleted `RateLimitTier` and the monthly trace-count
        // quota entirely: the bench grant now confers unlimited RPM by setting
        // `rate_limit_rpm: None` directly (`RateLimiter::check` short-circuits
        // on `None` before touching the bucket map — see `rate_limiter.rs`'s
        // own `unlimited_rpm_is_never_throttled_and_never_touches_the_bucket_map`
        // test for the mechanism proof), and there is no more monthly cap to
        // carry an "unlimited" sentinel for.
        assert_eq!(
            g.rate_limit_rpm, None,
            "grant does not confer unlimited RPM — the rate limiter will throttle"
        );
        assert!(g.is_bench());

        // A REAL grant must do none of this.
        let real = RE::deny_all();
        assert!(!real.is_bench());
        assert_eq!(
            real.rate_limit_rpm,
            Some(60),
            "deny_all is fail-restricted to the conservative 60 rpm, never unlimited"
        );
    }

    // `bench_tier_for` (a MODEL of the production condition) and the two tests
    // over it — `bench_tier_is_unreachable_for_a_postgres_backed_tenant` and
    // `bench_grant_branch_matches_production_shape`, which pinned the real `if`
    // as a string — were RETIRED 2026-09-12 (B-385 2c). The condition itself is
    // now driven, with and without a control plane, in
    // `admission::tests::the_bench_grant_needs_the_flag_the_model_and_no_control_plane`.

    // ── B-391 (a): the retry loop classifies before it retries, and its budget
    // bounds the backoff, not the attempt. Driven by closures, no provider. ──

    fn http_err(status: u16) -> anyhow::Error {
        crate::providers::ProviderHttpError {
            provider: "test",
            status,
            reason: None,
        }
        .into()
    }

    #[test]
    fn retry_worthwhile_is_transient_only() {
        use std::time::Duration;
        // Transient by the provider's own account: yes.
        assert!(retry_worthwhile(&http_err(503), Duration::from_secs(30)));
        assert!(retry_worthwhile(&http_err(500), Duration::from_millis(1)));
        assert!(retry_worthwhile(&http_err(429), Duration::from_millis(1)));
        // The same request gets the same answer: no.
        assert!(!retry_worthwhile(&http_err(401), Duration::from_millis(1)));
        assert!(!retry_worthwhile(&http_err(403), Duration::from_millis(1)));
        assert!(!retry_worthwhile(&http_err(404), Duration::from_millis(1)));
        assert!(!retry_worthwhile(&http_err(400), Duration::from_millis(1)));
        // Transport failure: only when it failed FAST.
        let refused = anyhow::anyhow!("connection refused");
        assert!(retry_worthwhile(&refused, Duration::from_millis(5)));
        assert!(!retry_worthwhile(
            &refused,
            TRANSPORT_RETRY_CUTOFF + Duration::from_millis(1)
        ));
    }

    #[tokio::test]
    async fn retry_loop_retries_a_5xx_that_surfaced_after_the_old_budget_had_expired() {
        // The pre-B-391 loop measured its 200 ms budget from the FIRST attempt's
        // start, so a 503 that took 150 ms to arrive (every real one does) never
        // retried. Now the budget bounds the backoff only.
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let policy = crate::providers::failover::RetryPolicy::BUILTIN; // 1 retry, 100 ms
        let budget =
            std::time::Duration::from_millis(crate::providers::failover::FAILOVER_BUDGET_MS);
        let out: anyhow::Result<&'static str> = retry_loop(policy, budget, "m", || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    Err(http_err(503))
                } else {
                    Ok("second attempt")
                }
            }
        })
        .await;
        assert_eq!(
            out.expect("the retry must fire and succeed"),
            "second attempt"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retry_loop_does_not_retry_a_rejected_key() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let policy = crate::providers::failover::RetryPolicy {
            retries: 5,
            backoff_ms: 1,
        };
        let out: anyhow::Result<()> =
            retry_loop(policy, std::time::Duration::from_millis(200), "m", || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(http_err(401)) }
            })
            .await;
        let err = out.expect_err("a 401 is an error");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a 401 must not be retried");
        assert!(
            err.downcast_ref::<crate::providers::ProviderHttpError>()
                .is_some_and(|h| h.status == 401),
            "the typed 401 must survive the loop so the handler classifies it"
        );
    }

    #[tokio::test]
    async fn retry_loop_stops_when_the_backoff_budget_is_spent() {
        // retries=5 but each backoff is 150 ms against a 200 ms budget: the
        // first pause fits (150 ≤ 200), the second would not (300 > 200).
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let policy = crate::providers::failover::RetryPolicy {
            retries: 5,
            backoff_ms: 150,
        };
        let out: anyhow::Result<()> =
            retry_loop(policy, std::time::Duration::from_millis(200), "m", || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(http_err(503)) }
            })
            .await;
        assert!(out.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn bench_mock_provider_id_is_not_routable() {
        // The synthetic id must never collide with a real provider, or a mocked
        // request could attribute cost or a BYOK lookup to one.
        assert!(
            crate::providers::ProviderRegistry::provider_id_for_model(BENCH_MOCK_PROVIDER_ID)
                .is_none(),
            "BENCH_MOCK_PROVIDER_ID collides with a routable provider"
        );
        assert!(BENCH_MOCK_PROVIDER_ID.starts_with("__bench_mock"));
    }

    // `bench_mock_bypass_sits_after_auth_and_tenant_resolution` was RETIRED
    // 2026-09-12 (B-385 2c). It compared the string offsets of three needles in
    // the compile-time-included text of `server.rs` — and after the pipeline
    // extraction all three
    // matched only ITS OWN source text, in the order it wrote them, so it kept
    // passing with the code gone. The property is now a run:
    // `admission::tests::the_bench_grant_is_unreachable_without_a_credential`.
}

#[cfg(test)]
mod breaker_trip_inputs {
    // SRE audit finding 38, 2026-09-04. Both directions: a caller-blaming 4xx must
    // feed the breaker NOTHING, and a genuine upstream fault must still trip it.
    // Before the fix the breaker was fed `result.is_ok()`, which is false for a 401
    // too — so five requests with one tenant's dead BYOK key opened the shared
    // (provider, region) circuit for every other tenant on that provider.
    fn http_err(status: u16) -> anyhow::Result<()> {
        Err(crate::providers::ProviderHttpError {
            provider: "openai",
            status,
            reason: None,
        }
        .into())
    }

    #[test]
    fn breaker_ignores_a_caller_blaming_upstream_4xx() {
        for status in [400u16, 401, 403, 404] {
            assert_eq!(
                super::breaker_outcome(&http_err(status)),
                None,
                "a {status} blames the caller's key/model/body, not the provider — and \
             the breaker has no tenant dimension, so recording it opens the circuit \
             for every tenant on that provider"
            );
        }
    }

    #[test]
    fn breaker_still_trips_on_a_real_upstream_fault() {
        for status in [429u16, 500, 502, 503] {
            assert_eq!(
                super::breaker_outcome(&http_err(status)),
                Some(false),
                "{status} is an upstream fault — ADR-036 names exactly these as trip inputs"
            );
        }
        assert_eq!(
            super::breaker_outcome(&Ok::<(), anyhow::Error>(())),
            Some(true)
        );
    }
}
