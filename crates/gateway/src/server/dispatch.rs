//! Provider dispatch — the round-trip half of the hot path (B-385 §2d split of `server.rs`).
//!
//! BYOK key resolution (`resolve_provider_key`), the model→adapter dispatch
//! (`dispatch_to_provider`, which DELEGATES routing to the one canonical map),
//! the A7 retry loop, the bench-mock double gate, the breaker's trip input, the
//! post-ledger error-span funnel (`emit_post_ledger_error_span`) and the
//! `DispatchGuard` that records a client hanging up mid-await (B-375 b).

use std::sync::Arc;

use tracelane_shared::{DispatchAttempt, TenantId, TracelaneSpan};
use uuid::Uuid;

use super::AppState;
use super::errors::{DispatchFailure, classify_dispatch_error};
use super::spans::{CallerIdentity, CapturedInput, SpanUsageMeta, build_gateway_span};

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
///
/// SB (security re-review round 2, 2026-10-05): every error that was not a
/// `ProviderHttpError` used to count as a provider failure — so a tenant's poisoned
/// Vertex service account or a key with a control byte opened the SHARED tier. Only
/// proven upstream evidence is [`Outcome::UpstreamFault`]; everything else is
/// [`Outcome::CredentialFault`] (that credential only). See [`transport_outcome`].
pub(super) fn breaker_outcome<T>(
    result: &anyhow::Result<T>,
) -> Option<crate::circuit_breaker::Outcome> {
    use crate::circuit_breaker::Outcome;
    match result {
        Ok(_) => Some(Outcome::Success),
        Err(err) if err.is::<crate::routing::attempt::Denied>() => None,
        Err(err) => transport_outcome(err),
    }
}

/// The breaker outcome of a failed dispatch (SB). In order:
/// - credential-derived ([`crate::providers::CredentialDerived`] anywhere in the chain:
///   a credential parse or token exchange) → `CredentialFault`;
/// - a provider HTTP status → `UpstreamFault` for 5xx, nothing for any 4xx (F4);
/// - a workspace deadline → `CredentialFault` (the workspace's bound, S1);
/// - a reqwest error that is a CONNECT or TIMEOUT error and not a builder error →
///   `UpstreamFault` (the adapter ceiling timeout is a reqwest timeout);
/// - anything else → `CredentialFault`. Unknown is never provider evidence.
pub(crate) fn transport_outcome(err: &anyhow::Error) -> Option<crate::circuit_breaker::Outcome> {
    use crate::circuit_breaker::Outcome;
    if err
        .downcast_ref::<crate::providers::CredentialDerived>()
        .is_some()
    {
        return Some(Outcome::CredentialFault);
    }
    if let Some(http) = err.downcast_ref::<crate::providers::ProviderHttpError>() {
        return http.is_upstream_fault().then_some(Outcome::UpstreamFault);
    }
    if crate::routing::deadlines::Timeout::find(err.as_ref()).is_some() {
        return Some(Outcome::CredentialFault);
    }
    let upstream = err
        .chain()
        .filter_map(|e| e.downcast_ref::<reqwest::Error>())
        .any(|e| !e.is_builder() && (e.is_connect() || e.is_timeout()));
    Some(if upstream {
        Outcome::UpstreamFault
    } else {
        Outcome::CredentialFault
    })
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
    // RI-05 M1: the attempts that led here. The terminal FAILURE span is exactly the
    // one an operator opens, so the ledger lands on it too — not only on a success.
    dispatch_attempts: Vec<DispatchAttempt>,
    // GWY-49: `Some(eligible)` when the request carried `x-tracelane-zdr: required` —
    // the providers the constraint left standing (EMPTY on a `zdr_unsatisfiable`
    // refusal). On the error span too, so an auditor filtering
    // `tracelane_zdr_required = true` sees the refusals, not only the served requests.
    zdr_eligible: Option<Vec<String>>, // The error span also carries policy-safe input.
    captured_input: Option<CapturedInput>,
) {
    let mut span = build_error_span(
        tenant_id,
        trace_id,
        parent_span_id,
        model,
        identity,
        request_start,
        reason,
        aft_id,
        dispatch_attempts,
    );
    if let Some(eligible) = zdr_eligible {
        span.attributes.tracelane_zdr_required = Some(true);
        span.attributes
            .tracelane_zdr_eligible_providers
            .replace(eligible);
    }
    if let Some(captured) = captured_input {
        captured.apply(&mut span.attributes);
    }
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
    dispatch_attempts: Vec<DispatchAttempt>,
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
            served: crate::server::ServedMeta::default(),
            finish_reason: None,
            // RI-05 M1: the ledger the caller collected before giving up — a
            // pre-dispatch refusal or a guardrail block passes an empty one; the
            // dispatch-exhausted path passes every attempt and skip. The write
            // rule (`dispatch_attempts_worth_recording`) still applies, so an
            // empty ledger stays absent.
            dispatch_attempts,
            reasoning_output_tokens: None,
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

/// The inverse of [`provider_name_from_model`]'s renames: the provider ID a breaker /
/// span name stands for. LOW round 2 (2026-10-05): the deadline budget resolves rules by
/// provider ID while chat/embeddings key the breaker by this name, so the legacy record
/// must translate back — or a `vertex` rule double-records and a timeout is counted twice.
pub(crate) fn provider_id_from_name(name: &str) -> &str {
    match name {
        "gcp_vertex_ai" => "vertex",
        "aws_bedrock" => "bedrock",
        other => other,
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
    KmsUnavailable,
    KmsDenied,
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

/// `OG-13`: the circuit-breaker credential of a dispatch made with `tenant_id`'s key
/// `label` for `provider_id`. The operator's environment credential exactly when the key
/// came (or would come) from the process environment ([`env_fallback_allowed`]) or the
/// provider takes no key at all (Ollama — every caller shares that upstream); otherwise
/// the tenant's own BYOK credential, so its failures open ITS breaker and nobody else's.
/// One decision for every wire — a call site never builds a credential itself.
pub(crate) fn breaker_cred(
    tenant_id: &TenantId,
    provider_id: &str,
    label: &str,
    routing: Option<&crate::routing::RoutingState>,
) -> crate::circuit_breaker::Cred {
    let mut cred = breaker_cred_with(
        env_fallback_allowed(
            crate::db::global_pool().is_some(),
            crate::byok::master_key().is_some(),
        ),
        tenant_id,
        provider_id,
        label,
    );
    if let Some(routing) = routing {
        crate::routing::deadlines::tune(&mut cred, routing);
    }
    cred
}

/// [`breaker_cred`] with the environment decision passed in — pure, so both answers are
/// asserted without a control plane.
pub(crate) fn breaker_cred_with(
    env_key: bool,
    tenant_id: &TenantId,
    provider_id: &str,
    label: &str,
) -> crate::circuit_breaker::Cred {
    let keyless =
        crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id).is_empty();
    if env_key || keyless {
        crate::circuit_breaker::Cred::env()
    } else {
        crate::circuit_breaker::Cred::byok(tenant_id.as_uuid(), provider_id, label)
    }
}

/// One read of a `(tenant, provider)` BYOK row, decrypted under its AAD. Shared
/// by the inline path and the B-568 F2 background refresh, so the two can never
/// disagree about what "usable" means.
enum ByokFetch {
    Key(crate::kms::vault::Opened),
    Kms(crate::kms::KmsError),
    NoRow,
    Undecryptable(anyhow::Error),
    LookupError(anyhow::Error),
}

async fn fetch_byok(
    pool: &deadpool_postgres::Pool,
    master: &crate::byok::ByokMasterKey,
    tenant_id: &TenantId,
    provider_id: &str,
    label: &str,
) -> ByokFetch {
    match crate::db::provider_keys::get(pool, tenant_id, provider_id, label).await {
        Ok(Some(row)) => {
            // OG-11 + OG-37: the AAD binds the label (byte-identical to the old AAD for
            // `default`), so a blob copied between labels fails here. The vault takes the
            // row's AAD subject — `provider` for `default`, `provider:label` otherwise —
            // so a customer-sealed pool key opens under the same label-bound AAD.
            let subject = crate::db::provider_keys::target_id(provider_id, label);
            let vault = match crate::kms::KeyVault::global() {
                Ok(v) => v,
                Err(e) => return ByokFetch::LookupError(e.into()),
            };
            // H1 round 2: the pooled connection is RELEASED before the customer-KMS await
            // in `open` — a hanging Vault must never pin the shared Postgres pool.
            let loaded = match pool.get().await {
                Ok(client) => crate::kms::vault::load(&**client, tenant_id, master).await,
                Err(e) => return ByokFetch::LookupError(e.into()),
            };
            let opened = match loaded {
                Ok(config) => {
                    vault
                        .open(
                            config.as_ref(),
                            tenant_id,
                            &subject,
                            &row.ciphertext_b64,
                            master,
                        )
                        .await
                }
                Err(e) => Err(e),
            };
            match opened {
                // SB: a key stored before upload validation existed is refused at use too —
                // it would only fail at the header build (fail CLOSED, no dispatch).
                Ok(key)
                    if !crate::db::provider_keys::credential_bytes_ok(
                        secrecy::ExposeSecret::expose_secret(&*key.secret),
                    ) =>
                {
                    ByokFetch::Undecryptable(anyhow::anyhow!(
                        "stored provider key contains whitespace or control characters"
                    ))
                }
                Ok(key) => ByokFetch::Key(key),
                Err(crate::kms::VaultError::Kms(e)) => ByokFetch::Kms(e),
                Err(crate::kms::VaultError::Invalid) => {
                    ByokFetch::Undecryptable(anyhow::anyhow!("invalid provider envelope"))
                }
                Err(e) => ByokFetch::LookupError(e.into()),
            }
        }
        Ok(None) => ByokFetch::NoRow,
        Err(e) => ByokFetch::LookupError(e),
    }
}

/// What a background refresh does with what it read. Pure, so the fail-CLOSED
/// mapping is asserted directly: a missing or undecryptable row EVICTS; only a
/// failure to READ keeps the stale key (inside the bound).
fn refresh_outcome(fetch: ByokFetch) -> crate::db::provider_keys::RefreshOutcome {
    use crate::db::provider_keys::RefreshOutcome;
    match fetch {
        ByokFetch::Key(k) => match k.expires_at {
            Some(until) => RefreshOutcome::RenewedUntil(k.secret, Some(until)),
            None => RefreshOutcome::Renewed(k.secret),
        },
        ByokFetch::Kms(_) => RefreshOutcome::Gone,
        ByokFetch::NoRow | ByokFetch::Undecryptable(_) => RefreshOutcome::Gone,
        ByokFetch::LookupError(_) => RefreshOutcome::Failed,
    }
}

/// B-568 F2: re-read a stale BYOK entry OFF the request path. Exactly one of
/// these runs per stale entry at a time (the `lookup_swr` claim). A failure is
/// DEBUG, not WARN: the entry keeps serving inside its bound and the next request
/// retries, and `/health`'s `byok_cache` counters carry the rate
/// (`.claude/rules/logging.md` — a repeating condition is a counter).
fn spawn_byok_refresh(
    tenant_id: &TenantId,
    provider_id: &str,
    label: &str,
    served: std::sync::Arc<secrecy::SecretString>,
) {
    let tenant = tenant_id.clone();
    let provider = provider_id.to_owned();
    let label = label.to_owned();
    tokio::spawn(async move {
        let outcome = match (crate::db::global_pool(), crate::byok::master_key()) {
            (Some(pool), Some(master)) => {
                let Some(_fill) = cold_fill_flight(&tenant, &provider, &label).await else {
                    // This key's other fill is still running: keep the bound, retry later.
                    crate::db::provider_keys::complete_refresh_labeled(
                        &tenant,
                        &provider,
                        &label,
                        &served,
                        crate::db::provider_keys::RefreshOutcome::Failed,
                    );
                    return;
                };
                let fetch = fetch_byok(pool, master, &tenant, &provider, &label).await;
                if let ByokFetch::LookupError(ref e) | ByokFetch::Undecryptable(ref e) = fetch {
                    tracing::debug!(error = %e, provider_id = %provider, "BYOK off-path re-check did not renew the key");
                }
                refresh_outcome(fetch)
            }
            // Unreachable in practice (only the BYOK path fills the cache), and
            // "cannot tell" either way — keep the bound, release the claim.
            _ => crate::db::provider_keys::RefreshOutcome::Failed,
        };
        crate::db::provider_keys::complete_refresh_labeled(
            &tenant, &provider, &label, &served, outcome,
        );
    });
}

/// H1 (security review, 2026-10-05): ONE cold fill per `(tenant, provider, label)` at a
/// time, so concurrent first requests share one read (a second `begin_cold_fill` would
/// fence the first). It replaced the KMS tenant lock on this path: a tenant without
/// customer KMS takes no KMS lock at all, and nobody waits on another tenant. The wait
/// is bounded by `kms.lock_wait_ms`; `None` = fail CLOSED for this key only.
async fn cold_fill_flight(
    tenant_id: &TenantId,
    provider_id: &str,
    label: &str,
) -> Option<crate::kms::vault::KeyedPermit> {
    static FILLS: std::sync::OnceLock<crate::kms::vault::KeyedLocks<(uuid::Uuid, String, String)>> =
        std::sync::OnceLock::new();
    let wait = std::time::Duration::from_millis(crate::kms::limits()?.lock_wait_ms);
    FILLS
        .get_or_init(Default::default)
        .acquire(
            (
                *tenant_id.as_uuid(),
                provider_id.to_owned(),
                label.to_owned(),
            ),
            wait,
        )
        .await
}

/// A4: resolve the provider-API plaintext key. Order:
///   1. Hot-path cache (`db::provider_keys::lookup_swr`) — fresh, or (B-568 F2)
///      stale-while-revalidate: a key past its TTL is served while ONE background
///      refresh re-reads it; a key the refresh finds gone is evicted (fail-CLOSED).
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
    resolve_provider_key_traced(tenant_id, provider_id, env_var)
        .await
        .0
}

/// [`resolve_provider_key`], also reporting whether THIS request waited on a
/// control-plane read (B-568 I5: a BYOK cache miss makes the request cold). A
/// stale-served key is NOT cold — its re-read runs off the request path.
pub(crate) async fn resolve_provider_key_traced(
    tenant_id: &TenantId,
    provider_id: &str,
    env_var: &str,
) -> (ProviderKey, bool) {
    resolve_provider_key_labeled(
        tenant_id,
        provider_id,
        crate::db::provider_keys::DEFAULT_LABEL,
        env_var,
    )
    .await
}

/// `OG-11`: [`resolve_provider_key_traced`] for one key-pool `label`. The SAME tenant's
/// key only — `(tenant, provider, label)` is the cache key, the row key and the AAD.
/// The process environment is a fallback for the `default` label ONLY: a named pool key
/// that is absent is `NotConfigured`, never the operator's key (B-380's rule, kept).
pub(crate) async fn resolve_provider_key_labeled(
    tenant_id: &TenantId,
    provider_id: &str,
    label: &str,
    env_var: &str,
) -> (ProviderKey, bool) {
    use crate::db::provider_keys::CachedLookup;
    use std::sync::Arc;
    #[cfg(test)]
    if let Ok(error) = crate::kms::wire_tests::FAILURE.try_with(|e| *e) {
        return (kms_failure(error), true);
    }

    match crate::db::provider_keys::lookup_swr_labeled(tenant_id, provider_id, label) {
        CachedLookup::Fresh(secret) => return (ProviderKey::Found(secret), false),
        CachedLookup::Stale { secret, refresh } => {
            if refresh {
                spawn_byok_refresh(tenant_id, provider_id, label, Arc::clone(&secret));
            }
            return (ProviderKey::Found(secret), false);
        }
        CachedLookup::Miss => {}
    }

    let pool = crate::db::global_pool();
    let master = crate::byok::master_key();
    if let (Some(pool), Some(master)) = (pool, master) {
        if crate::kms::KeyVault::global().is_err() {
            return (ProviderKey::KmsUnavailable, true);
        }
        let Some(_fill) = cold_fill_flight(tenant_id, provider_id, label).await else {
            return (ProviderKey::LookupFailed, true);
        };
        if let CachedLookup::Fresh(secret) =
            crate::db::provider_keys::lookup_swr_labeled(tenant_id, provider_id, label)
        {
            return (ProviderKey::Found(secret), false);
        };
        let Some(fill) = crate::db::provider_keys::begin_cold_fill(tenant_id, provider_id, label)
        else {
            return (ProviderKey::LookupFailed, false);
        };
        let key = match fetch_byok(pool, master, tenant_id, provider_id, label).await {
            ByokFetch::Key(opened) => {
                let secret = opened.secret;
                if fill.publish(Arc::clone(&secret), opened.expires_at) {
                    ProviderKey::Found(secret)
                } else {
                    ProviderKey::LookupFailed
                }
            }
            ByokFetch::Kms(error) => kms_failure(error),
            ByokFetch::Undecryptable(e) => {
                tracing::error!(
                    error = %e,
                    tenant_id = %tenant_id,
                    provider_id,
                    "BYOK decrypt failed — refusing env fallback (auth-fail safer)"
                );
                ProviderKey::Unusable
            }
            // B-380: with a control plane present, "no row" is the tenant's answer,
            // not an invitation to spend the operator's key.
            ByokFetch::NoRow => {
                if env_var.is_empty() {
                    // Ollama / no-key providers
                    ProviderKey::Found(Arc::new(secrecy::SecretString::from(String::new())))
                } else {
                    ProviderKey::NotConfigured
                }
            }
            // B-380: a lookup ERROR is not "no key" and is not "use the env". It is
            // "we cannot tell", and the only safe answer to that is to refuse.
            ByokFetch::LookupError(e) => {
                tracing::error!(
                    error = %e,
                    tenant_id = %tenant_id,
                    provider_id,
                    "provider_keys lookup failed — REFUSING (503), no env fallback"
                );
                ProviderKey::LookupFailed
            }
        };
        // A control-plane read happened on the request path, whatever it found.
        return (key, true);
    }
    debug_assert!(
        env_fallback_allowed(pool.is_some(), master.is_some()),
        "env fallback reached with a control plane and a master key present"
    );
    // OG-11: a named pool key never resolves to the environment.
    if label != crate::db::provider_keys::DEFAULT_LABEL {
        return (ProviderKey::NotConfigured, false);
    }

    if env_var.is_empty() {
        return (
            ProviderKey::Found(Arc::new(secrecy::SecretString::from(String::new()))),
            false,
        ); // Ollama
    }
    let key = match std::env::var(env_var) {
        Ok(k) => ProviderKey::Found(Arc::new(secrecy::SecretString::from(k))),
        Err(_) => ProviderKey::NotConfigured,
    };
    (key, false)
}

/// `OG-11`: walks one provider's key POOL in order, resolving each label's key only
/// when it is reached — the first usable key costs one lookup, exactly as the single
/// `default` key did. The tenant's own keys only (`(tenant, provider, label)`).
pub(crate) struct KeyCursor {
    labels: Vec<String>,
    next: usize,
    /// Why labels did not resolve — the refusal when none does. `LookupFailed` wins
    /// (the store could not be read: 503, never "add a key").
    failure: Option<ProviderKey>,
    /// A control-plane read happened on the request path (B-568 I5).
    pub(crate) cold: bool,
}

impl KeyCursor {
    pub(crate) fn new(labels: Vec<String>) -> Self {
        Self {
            labels,
            next: 0,
            failure: None,
            cold: false,
        }
    }

    /// The next label whose key resolves, or `None` when the pool is spent.
    pub(crate) async fn next_key(
        &mut self,
        tenant_id: &TenantId,
        provider_id: &str,
        env_var: &str,
    ) -> Option<(String, Arc<secrecy::SecretString>)> {
        while self.next < self.labels.len() {
            let label = self.labels[self.next].clone();
            self.next += 1;
            let (key, cold) =
                resolve_provider_key_labeled(tenant_id, provider_id, &label, env_var).await;
            self.cold |= cold;
            match key {
                ProviderKey::Found(k) => return Some((label, k)),
                ProviderKey::LookupFailed => self.failure = Some(ProviderKey::LookupFailed),
                // OG-37: a customer-key-service refusal is the answer to give (503/403, never
                // "add a key"), so it outranks the pool's plain misses — but not `LookupFailed`.
                other @ (ProviderKey::KmsUnavailable | ProviderKey::KmsDenied) => {
                    if !matches!(self.failure, Some(ProviderKey::LookupFailed)) {
                        self.failure = Some(other);
                    }
                }
                other => {
                    if self.failure.is_none() {
                        self.failure = Some(other);
                    }
                }
            }
        }
        None
    }

    /// Labels not yet tried remain.
    pub(crate) fn has_more(&self) -> bool {
        self.next < self.labels.len()
    }

    /// The refusal for a pool none of whose keys resolved.
    pub(crate) fn into_failure(self) -> ProviderKey {
        self.failure.unwrap_or(ProviderKey::NotConfigured)
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
///
/// RI-05 M1: returns the per-attempt LEDGER alongside the result — one
/// element per attempt this call made, numbered locally (0, 1, … within this
/// one call). The caller (`server/chat.rs`) merges it into the request's full
/// dispatch sequence via `tracelane_shared::span::extend_dispatch_attempts`,
/// which renumbers on merge.
#[allow(clippy::too_many_arguments)] // dispatch identity plus the request's retry and deadline policies
pub(super) async fn dispatch_with_retry(
    registry: &crate::providers::ProviderRegistry,
    chat_request: &tracelane_shared::ChatRequest,
    provider_key: &str,
    // RI-05 M1: the provider this dispatch call is against — the caller
    // (`server/chat.rs`) already computed this (`upstream` for the primary
    // call, `fo_provider` for a failover hop) to resolve the BYOK key, so it
    // costs nothing new to pass it through for the ledger.
    provider: &str,
    model: &str,
    tenant_id: &tracelane_shared::TenantId,
    // GWY-44: the retry count and backoff come from the operator's
    // `tracelane.yaml` `failover:` block when one is installed, and from
    // `RetryPolicy::BUILTIN` (1 retry, 100 ms) otherwise — so every deployment
    // without a config file behaves exactly as it did. B-386 (b): resolved by
    // the caller from `AppState::failover` (read once at boot), not from a
    // process global here.
    policy: crate::providers::failover::RetryPolicy,
    deadlines: crate::routing::deadlines::Budget,
) -> (
    anyhow::Result<crate::providers::ProviderStream>,
    Vec<DispatchAttempt>,
) {
    let budget = std::time::Duration::from_millis(crate::providers::failover::FAILOVER_BUDGET_MS);
    retry_loop(policy, budget, provider, model, || {
        deadlines.clone().scope(dispatch_to_provider(
            registry,
            chat_request.clone(),
            provider_key,
            model,
            tenant_id,
        ))
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
    if err.is::<crate::routing::attempt::Denied>() {
        return false;
    }
    if crate::routing::deadlines::Timeout::find(err.as_ref()).is_some() {
        return false;
    }
    match err.downcast_ref::<crate::providers::ProviderHttpError>() {
        Some(_) => matches!(
            classify_dispatch_error(err),
            DispatchFailure::Unavailable | DispatchFailure::RateLimited
        ),
        None => attempt_took < TRANSPORT_RETRY_CUTOFF,
    }
}

/// Wall-clock milliseconds for one dispatch attempt, saturating rather than
/// panicking on an implausible (> u32::MAX ms, ~49 days) duration — this only
/// ever measures a single HTTP round trip.
fn attempt_took_ms(d: std::time::Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

/// RI-05 M1 + M4 — the ledger-recording decision for a FAILED attempt,
/// factored out as a PURE function so it is unit-testable without a live
/// provider or even a mock HTTP server: given the typed error `retry_loop`
/// already holds, decide `status` and `reason` exactly per spec §2.1.
///
/// `status`/`reason` never touch an upstream error BODY — `ProviderHttpError`
/// does not even carry one (`.claude/rules/security.md`; `providers/mod.rs`'s
/// own doc comment on the struct). The upstream's own safe token (already
/// validated where `ProviderHttpError` was constructed — see
/// `providers::safe_reason` / `providers::reason_from_body`) wins when
/// present; otherwise the gateway's five-class dispatch-failure label
/// (`server/errors.rs::DispatchFailure::reason`) — `provider_key_rejected` |
/// `provider_rate_limited` | `model_not_found` | `provider_request_rejected`
/// | `provider_unavailable`.
fn dispatch_attempt_for_error(
    attempt: u32,
    provider: &str,
    model: &str,
    err: &anyhow::Error,
    took_ms: u32,
) -> DispatchAttempt {
    if let Some(denied) = err.downcast_ref::<crate::routing::attempt::Denied>() {
        return DispatchAttempt {
            key_label: None,
            attempt,
            provider: provider.to_owned(),
            model: model.to_owned(),
            outcome: "skipped".to_owned(),
            status: None,
            reason: Some(denied.code().to_owned()),
            took_ms,
        };
    }
    let http = err.downcast_ref::<crate::providers::ProviderHttpError>();
    let mut attempt = DispatchAttempt {
        key_label: None,
        attempt,
        provider: provider.to_string(),
        model: model.to_string(),
        outcome: "error".to_string(),
        status: http.map(|e| e.status),
        reason: http
            .and_then(|e| e.reason.clone())
            .or_else(|| Some(classify_dispatch_error(err).reason().to_string())),
        took_ms,
    };
    if let Some(timeout) = crate::routing::deadlines::Timeout::find(err.as_ref()) {
        timeout.record_attempt(std::slice::from_mut(&mut attempt));
    }
    attempt
}

/// OG-10: one pause drawn by FULL JITTER — `uniform(0, min(remaining, backoff × 2^attempt))`.
///
/// Pure, so the bound is property-tested: the result is always `<= remaining` and
/// `<= backoff × 2^attempt`. `sample` is a uniform `u64`; the pause is
/// `cap × sample / 2^64`, so `sample = 0` gives 0 and `u64::MAX` approaches the cap
/// (never reaches it). The exponent is capped at 2^16 — far past any budget — so the
/// shift cannot overflow however many attempts a future policy allows.
fn jitter_pause(
    backoff: std::time::Duration,
    attempt: u32,
    remaining: std::time::Duration,
    sample: u64,
) -> std::time::Duration {
    let cap = backoff
        .saturating_mul(1u32 << attempt.min(16))
        .min(remaining);
    let picked = cap.as_nanos() * u128::from(sample) / (u128::from(u64::MAX) + 1);
    std::time::Duration::from_nanos(u64::try_from(picked).unwrap_or(u64::MAX))
}

/// A uniform `u64` for the jitter. Not security-sensitive (it spreads retries, it
/// guards nothing), but `ring` is already a dependency of this crate, so no new crate
/// is needed. **Fail-OPEN** (fault-tolerance path): if the OS source errors, fall back
/// to the clock's sub-second nanos mixed with a golden-ratio constant — still enough
/// spread to de-synchronise retries, and a retry is never refused over it.
fn random_u64() -> u64 {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 8];
    if ring::rand::SystemRandom::new().fill(&mut b).is_ok() {
        return u64::from_le_bytes(b);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// The retry loop, generic over the attempt so it can be driven by a closure
/// in tests. `budget` bounds the SUM of backoff pauses (see
/// [`dispatch_with_retry`]); each attempt's own duration is bounded by the
/// adapter's client timeout, not by this loop.
///
/// **OG-10 — how long to wait.** For a [`retry_worthwhile`] failure:
/// - the upstream said `Retry-After` and it fits in the remaining budget → sleep
///   EXACTLY that long, then retry;
/// - it said `Retry-After` and it does NOT fit → **do not retry this provider** (a
///   retry would be refused again and spend a call); the typed error, carrying the
///   hint, goes back so the handler can relay it and the CLIENT's backoff can work.
///   A cross-provider failover, if the caller opted in, proceeds as before;
/// - it said nothing → full-jitter exponential ([`jitter_pause`]).
///
/// RI-05 M1: also returns the per-attempt ledger — one element per attempt
/// THIS call made, numbered locally (0, 1, … within this call only; see
/// [`dispatch_with_retry`]'s doc for how the caller renumbers on merge).
async fn retry_loop<T, F, Fut>(
    policy: crate::providers::failover::RetryPolicy,
    budget: std::time::Duration,
    provider: &str,
    model: &str,
    attempt_fn: F,
) -> (anyhow::Result<T>, Vec<DispatchAttempt>)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    retry_loop_with(policy, budget, provider, model, random_u64, attempt_fn).await
}

/// [`retry_loop`] with the jitter source injected, so a test can pin it.
async fn retry_loop_with<T, F, Fut>(
    policy: crate::providers::failover::RetryPolicy,
    budget: std::time::Duration,
    provider: &str,
    model: &str,
    mut sampler: impl FnMut() -> u64,
    mut attempt_fn: F,
) -> (anyhow::Result<T>, Vec<DispatchAttempt>)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let backoff = std::time::Duration::from_millis(policy.backoff_ms);
    let loop_started = std::time::Instant::now();
    let mut backoff_spent = std::time::Duration::ZERO;
    let mut ledger: Vec<DispatchAttempt> = Vec::new();

    let mut attempt: u32 = 0;
    let mut first_err: Option<anyhow::Error> = None;
    loop {
        let attempt_started = std::time::Instant::now();
        match attempt_fn().await {
            Ok(s) => {
                ledger.push(DispatchAttempt {
                    key_label: None,
                    attempt,
                    provider: provider.to_string(),
                    model: model.to_string(),
                    outcome: "ok".to_string(),
                    status: None,
                    reason: None,
                    took_ms: attempt_took_ms(attempt_started.elapsed()),
                });
                if attempt > 0 {
                    tracing::info!(
                        model = %model,
                        attempt,
                        elapsed_ms = loop_started.elapsed().as_millis(),
                        "tracelane.failover.activated=true (same-provider retry succeeded)"
                    );
                }
                return (Ok(s), ledger);
            }
            Err(err) => {
                let attempt_took = attempt_started.elapsed();
                ledger.push(dispatch_attempt_for_error(
                    attempt,
                    provider,
                    model,
                    &err,
                    attempt_took_ms(attempt_took),
                ));
                let give_up = |err: anyhow::Error, first_err: Option<anyhow::Error>| match first_err
                {
                    Some(first) => err.context(first.to_string()),
                    None => err,
                };
                // Out of attempts.
                if attempt >= policy.retries {
                    return (Err(give_up(err, first_err)), ledger);
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
                    return (Err(give_up(err, first_err)), ledger);
                }
                // How long to wait. Decided BEFORE sleeping, so the sleep itself can
                // never be what breaches the budget.
                let remaining = budget.saturating_sub(backoff_spent);
                let upstream_hint = err
                    .downcast_ref::<crate::providers::ProviderHttpError>()
                    .and_then(|e| e.retry_after);
                let pause = match upstream_hint {
                    Some(asked) if asked <= remaining => asked,
                    Some(asked) => {
                        tracing::warn!(
                            error = %err,
                            attempt,
                            retry_after_ms = asked.as_millis(),
                            "provider asked for a longer wait than the retry budget — not retrying it"
                        );
                        return (Err(give_up(err, first_err)), ledger);
                    }
                    None if remaining.is_zero() => {
                        tracing::warn!(
                            error = %err,
                            attempt,
                            "provider failed; retry budget exhausted, no further attempt"
                        );
                        return (Err(give_up(err, first_err)), ledger);
                    }
                    None => jitter_pause(backoff, attempt, remaining, sampler()),
                };
                tracing::warn!(
                    error = %err,
                    model = %model,
                    attempt,
                    pause_ms = pause.as_millis(),
                    honouring_retry_after = upstream_hint.is_some(),
                    "provider attempt failed — retrying"
                );
                if first_err.is_none() {
                    first_err = Some(err);
                }
                attempt += 1;
                backoff_spent += pause;
                tokio::time::sleep(pause).await;
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
    /// RI-05 M1: the attempts made before the request ended in a refusal or a
    /// cancellation, handed to the error span by `abort` / `Drop`. Set by the
    /// handler once dispatch has failed (`record_attempts`); empty until then.
    dispatch_attempts: Vec<DispatchAttempt>,
    /// GWY-49: the ZDR constraint's outcome so far, for the terminal error span —
    /// `None` until the handler judged the constraint (or when there was none).
    zdr_eligible: Option<Vec<String>>, // Capture is cleared on unsafe redaction.
    captured_input: Option<CapturedInput>,
}

impl DispatchGuard {
    pub(crate) fn record_labels(&mut self, labels: super::request_labels::BoundedLabels) {
        self.identity.labels = labels;
    }

    /// GWY-49: the request is constrained; `eligible` is what the constraint left
    /// standing (empty when nothing did). Lands on the error span if the request
    /// ends in a refusal, a dispatch failure or a client cancellation.
    pub(crate) fn record_zdr(&mut self, eligible: Vec<String>) {
        self.zdr_eligible = Some(eligible);
    }

    /// `OG-11`/`OG-12`: how the request was routed, for the terminal error span.
    pub(crate) fn record_route(&mut self, route: super::spans::RouteMeta) {
        self.identity.route = route;
    }

    pub(crate) fn record_timeout(
        &mut self,
        timeout: crate::routing::deadlines::Timeout,
        provider: &str,
    ) {
        let mut attempt = timeout.attempt(provider, &self.model);
        attempt.took_ms = u32::try_from(
            (chrono::Utc::now() - self.request_start)
                .num_milliseconds()
                .max(0),
        )
        .unwrap_or(u32::MAX);
        self.dispatch_attempts = vec![attempt];
    }

    /// RI-05 M1: attach the attempt ledger so the terminal error span carries it.
    pub(crate) fn record_attempts(&mut self, ledger: Vec<DispatchAttempt>) {
        self.dispatch_attempts = ledger;
    }

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
            dispatch_attempts: Vec::new(),
            zdr_eligible: None, // The request's capture decision arrives later.
            captured_input: None,
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
            std::mem::take(&mut self.dispatch_attempts),
            self.zdr_eligible.take(), // Give the error span the final safe input.
            self.captured_input.take(),
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
            std::mem::take(&mut self.dispatch_attempts),
            self.zdr_eligible.take(), // Give the cancellation span the safe input.
            self.captured_input.take(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;
    use tracelane_shared::SpanStatusCode;

    /// B-568 F2, fail-CLOSED: a refresh that finds the row GONE or no longer
    /// decryptable evicts (the next request is refused inline); only a failure to
    /// READ the store keeps the stale key — "cannot tell" is not "revoked".
    #[test]
    fn a_byok_refresh_evicts_on_gone_or_undecryptable_and_keeps_only_on_a_read_error() {
        use crate::db::provider_keys::RefreshOutcome;
        assert!(matches!(
            refresh_outcome(ByokFetch::NoRow),
            RefreshOutcome::Gone
        ));
        assert!(matches!(
            refresh_outcome(ByokFetch::Undecryptable(anyhow::anyhow!("aad mismatch"))),
            RefreshOutcome::Gone
        ));
        assert!(matches!(
            refresh_outcome(ByokFetch::LookupError(anyhow::anyhow!("neon resuming"))),
            RefreshOutcome::Failed
        ));
        let k = std::sync::Arc::new(secrecy::SecretString::from("sk-x".to_string()));
        assert!(matches!(
            refresh_outcome(ByokFetch::Key(crate::kms::vault::Opened { secret:k, expires_at:None })),
            RefreshOutcome::Renewed(ref s) if s.expose_secret() == "sk-x"
        ));
    }

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
            &TenantId::from_jwt_claim("0e57f1c7-0000-4000-8000-00000000c0de".parse().unwrap()),
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
            Vec::new(),
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
            &TenantId::from_jwt_claim("0e57f1c7-0000-4000-8000-00000000c0de".parse().unwrap()),
            Uuid::new_v4(),
            None,
            "claude-haiku-4-5",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            "guardrail_block",
            Some("AFT-TOOL-POISON-001"),
            Vec::new(),
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
        assert_eq!(provider_name_from_model("qwen/qwen3-32b"), "groq");
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
                served: crate::server::ServedMeta::default(),
                finish_reason: None,
                dispatch_attempts: Vec::new(),
                reasoning_output_tokens: None,
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
            Vec::new(),
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
            Vec::new(),
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
            message: None,
            retry_after: None,
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

    // ── RI-05 M1: the ledger-recording decision, as a pure function ──

    /// The upstream's OWN safe token wins over the gateway's five-class
    /// label — spec §2.1's stated rule, in the direction that matters: a
    /// provider that DOES tell us something specific must not be flattened
    /// into the generic bucket.
    #[test]
    fn dispatch_attempt_for_error_prefers_the_upstream_safe_token() {
        let err: anyhow::Error = crate::providers::ProviderHttpError {
            provider: "google",
            status: 429,
            reason: Some("RESOURCE_EXHAUSTED".to_string()),
            message: None,
            retry_after: None,
        }
        .into();
        let a = dispatch_attempt_for_error(0, "google", "gemini-1.5-pro", &err, 12);
        assert_eq!(a.status, Some(429));
        assert_eq!(a.reason.as_deref(), Some("RESOURCE_EXHAUSTED"));
        assert_eq!(a.outcome, "error");
        assert_eq!(a.took_ms, 12);
    }

    /// No safe token on the wire → the five-class label
    /// (`server/errors.rs::DispatchFailure::reason`), never the raw error's
    /// own `Display`/`Debug` text. Falsified against a version of
    /// `dispatch_attempt_for_error` that read `err.to_string()` as a
    /// fallback — see the RED/GREEN note in this test's body for how it was
    /// proven, not merely asserted.
    #[test]
    fn dispatch_attempt_for_error_falls_back_to_the_five_class_label_never_the_body() {
        // A transport failure whose message is deliberately shaped like a
        // credential — nothing here has an HTTP status at all, which is
        // exactly the case `.reason` cannot help with.
        let planted = "sk-live-PLANTED-CREDENTIAL-4471";
        let err = anyhow::anyhow!("connection reset while talking to {planted}");
        let a = dispatch_attempt_for_error(0, "openai", "gpt-4o", &err, 3);
        assert_eq!(a.status, None, "no ProviderHttpError, so no typed status");
        assert_eq!(
            a.reason.as_deref(),
            Some("provider_unavailable"),
            "a transport failure with no typed status classifies as Unavailable"
        );
        // THE PROOF: serialize the whole element and confirm the planted
        // text is not merely absent from `.reason` but absent from the
        // JSON this actually ships in a span attribute.
        let json = serde_json::to_string(&a).expect("DispatchAttempt serializes");
        assert!(
            !json.contains(planted),
            "the planted credential-shaped string leaked into the ledger element: {json}"
        );

        // A 4xx WITH a status but no safe token: same rule, different label.
        let http_err: anyhow::Error = crate::providers::ProviderHttpError {
            provider: "openai",
            status: 429,
            reason: None, // OpenAI-shape bodies never pass `safe_reason`
            message: None,
            retry_after: None,
        }
        .into();
        let b = dispatch_attempt_for_error(1, "openai", "gpt-4o", &http_err, 5);
        assert_eq!(b.status, Some(429));
        assert_eq!(b.reason.as_deref(), Some("provider_rate_limited"));
    }

    /// RI-05 §2.1's write rule (`tracelane_shared::span::dispatch_attempts_worth_recording`):
    /// a clean single attempt writes nothing; anything else does.
    #[test]
    fn dispatch_attempts_worth_recording_matches_the_write_rule() {
        use tracelane_shared::span::dispatch_attempts_worth_recording as worth;
        let ok = |attempt: u32| DispatchAttempt {
            key_label: None,
            attempt,
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            outcome: "ok".to_string(),
            status: None,
            reason: None,
            took_ms: 1,
        };
        assert!(
            !worth(&[ok(0)]),
            "one clean attempt must write NOTHING (a pre-RI-05 span has no field at all)"
        );
        assert!(!worth(&[]), "an empty ledger is never worth recording");
        let err = DispatchAttempt {
            key_label: None,
            outcome: "error".to_string(),
            status: Some(429),
            reason: Some("provider_rate_limited".to_string()),
            ..ok(0)
        };
        assert!(worth(&[err.clone(), ok(1)]), "len > 1 → write");
        assert!(
            worth(&[err]),
            "a single ERRORED attempt is still worth recording"
        );
        // Verifier finding (2026-09-20): a lone `skipped` is unreachable today but
        // must never be dropped silently if a future path produces one.
        let skipped = DispatchAttempt {
            key_label: None,
            outcome: "skipped".to_string(),
            reason: Some("breaker_open".to_string()),
            ..ok(0)
        };
        assert!(
            worth(&[skipped]),
            "any non-ok single element is worth recording"
        );
    }

    /// RI-05 M1 on the FAILURE span (verifier finding, 2026-09-20): when every
    /// attempt fails, the error span the guard emits carries the ledger — that is
    /// the span an operator opens. Empty ledger → field absent (the write rule).
    #[test]
    fn the_terminal_error_span_carries_the_attempt_ledger() {
        let tenant =
            TenantId::from_jwt_claim("0e57f1c7-0000-4000-8000-00000000c0de".parse().unwrap());
        let ledger = vec![
            DispatchAttempt {
                key_label: None,
                attempt: 0,
                provider: "anthropic".to_string(),
                model: "claude-haiku-4-5".to_string(),
                outcome: "error".to_string(),
                status: Some(503),
                reason: Some("provider_unavailable".to_string()),
                took_ms: 12,
            },
            DispatchAttempt {
                key_label: None,
                attempt: 1,
                provider: "anthropic".to_string(),
                model: "claude-haiku-4-5".to_string(),
                outcome: "error".to_string(),
                status: Some(503),
                reason: Some("provider_unavailable".to_string()),
                took_ms: 9,
            },
        ];
        let span = build_error_span(
            &tenant,
            Uuid::new_v4(),
            None,
            "claude-haiku-4-5",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            "provider_unavailable",
            None,
            ledger.clone(),
        );
        assert_eq!(span.status.code, SpanStatusCode::Error);
        assert_eq!(
            span.attributes.tracelane_dispatch_attempts.as_deref(),
            Some(ledger.as_slice()),
            "both failed attempts land on the terminal error span"
        );
        let bare = build_error_span(
            &tenant,
            Uuid::new_v4(),
            None,
            "claude-haiku-4-5",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            "guardrail_block",
            None,
            Vec::new(),
        );
        assert!(
            bare.attributes.tracelane_dispatch_attempts.is_none(),
            "a pre-dispatch refusal has no attempts and writes nothing"
        );
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
        let (out, ledger): (anyhow::Result<&'static str>, Vec<DispatchAttempt>) =
            retry_loop(policy, budget, "test-provider", "m", || {
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
        assert_eq!(ledger.len(), 2, "one element per attempt made");
        assert_eq!(ledger[0].outcome, "error");
        assert_eq!(ledger[0].status, Some(503));
        assert_eq!(ledger[1].outcome, "ok");
    }

    #[tokio::test]
    async fn retry_loop_does_not_retry_a_rejected_key() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let policy = crate::providers::failover::RetryPolicy {
            retries: 5,
            backoff_ms: 1,
        };
        let (out, ledger): (anyhow::Result<()>, Vec<DispatchAttempt>) = retry_loop(
            policy,
            std::time::Duration::from_millis(200),
            "test-provider",
            "m",
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(http_err(401)) }
            },
        )
        .await;
        let err = out.expect_err("a 401 is an error");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a 401 must not be retried");
        assert!(
            err.downcast_ref::<crate::providers::ProviderHttpError>()
                .is_some_and(|h| h.status == 401),
            "the typed 401 must survive the loop so the handler classifies it"
        );
        assert_eq!(ledger.len(), 1, "a non-retried failure is a single attempt");
        assert_eq!(ledger[0].status, Some(401));
        assert_eq!(
            ledger[0].reason.as_deref(),
            Some("provider_key_rejected"),
            "no safe token on this synthetic error, so the five-class label applies"
        );
    }

    #[tokio::test]
    async fn the_sum_of_pauses_never_exceeds_the_budget() {
        // OG-10: retries=5, backoff 150 ms, budget 200 ms, sampler pinned to the top of the
        // range (the worst case for time). The first pause draws up to 150, the next is
        // capped by what is left of the budget — so the TOTAL sleep stays inside 200 ms
        // however many of the 5 retries fire. (The pre-OG-10 loop stopped after one retry
        // because its fixed 150 ms pause could not be repeated; jitter spends the remainder.)
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let policy = crate::providers::failover::RetryPolicy {
            retries: 5,
            backoff_ms: 150,
        };
        let started = std::time::Instant::now();
        let (out, ledger): (anyhow::Result<()>, Vec<DispatchAttempt>) = retry_loop_with(
            policy,
            std::time::Duration::from_millis(200),
            "test-provider",
            "m",
            || u64::MAX,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(http_err(503)) }
            },
        )
        .await;
        assert!(out.is_err());
        let n = calls.load(Ordering::SeqCst);
        assert!((2..=6).contains(&n), "attempts bounded by retries: {n}");
        assert_eq!(ledger.len() as u32, n);
        assert!(ledger.iter().all(|a| a.outcome == "error"));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(400),
            "pauses are bounded by the 200 ms budget (plus scheduler slack): {:?}",
            started.elapsed()
        );
    }

    // ── OG-10: honour the upstream `Retry-After`; full-jitter backoff otherwise ──

    fn http_err_after(status: u16, retry_after: std::time::Duration) -> anyhow::Error {
        crate::providers::ProviderHttpError {
            provider: "test",
            status,
            reason: None,
            message: None,
            retry_after: Some(retry_after),
        }
        .into()
    }

    /// **OG-10 proof 2, at the loop.** A provider that says "wait 20 s" must not be
    /// re-hit after our 200 ms budget: ONE call, no sleep, and the typed error — with
    /// its `retry_after` — survives for the handler to relay.
    #[tokio::test]
    async fn retry_after_beyond_the_budget_means_no_same_provider_retry() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let started = std::time::Instant::now();
        let (out, ledger): (anyhow::Result<()>, Vec<DispatchAttempt>) = retry_loop(
            crate::providers::failover::RetryPolicy::BUILTIN,
            std::time::Duration::from_millis(crate::providers::failover::FAILOVER_BUDGET_MS),
            "test-provider",
            "m",
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(http_err_after(429, std::time::Duration::from_secs(20))) }
            },
        )
        .await;
        let err = out.expect_err("a 429 that outlasts the budget stays an error");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "retrying a provider that said 'wait 20 s' spends a call to be refused again"
        );
        assert_eq!(ledger.len(), 1);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "no pause may precede giving up"
        );
        assert_eq!(
            err.downcast_ref::<crate::providers::ProviderHttpError>()
                .and_then(|h| h.retry_after),
            Some(std::time::Duration::from_secs(20)),
            "the hint must reach the handler so the client learns how long to wait"
        );
    }

    /// In-budget honour: the pause is EXACTLY the provider's value, not our backoff.
    /// The built-in 100 ms backoff would fail the upper bound; a `0` would fail the lower.
    #[tokio::test]
    async fn retry_after_inside_the_budget_is_slept_exactly() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let started = std::time::Instant::now();
        let (out, ledger): (anyhow::Result<&'static str>, Vec<DispatchAttempt>) = retry_loop(
            crate::providers::failover::RetryPolicy {
                retries: 1,
                backoff_ms: 150,
            },
            std::time::Duration::from_millis(crate::providers::failover::FAILOVER_BUDGET_MS),
            "test-provider",
            "m",
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err(http_err_after(429, std::time::Duration::from_millis(30)))
                    } else {
                        Ok("served")
                    }
                }
            },
        )
        .await;
        assert_eq!(out.expect("the retry fires and succeeds"), "served");
        let took = started.elapsed();
        assert!(
            took >= std::time::Duration::from_millis(30),
            "must wait what the provider asked: {took:?}"
        );
        assert!(
            took < std::time::Duration::from_millis(120),
            "must NOT wait our own backoff instead: {took:?}"
        );
        assert_eq!(ledger.len(), 2);
    }

    /// `Retry-After: 0` is "retry now" — honoured as zero, not replaced by a jittered guess.
    #[tokio::test]
    async fn retry_after_zero_retries_immediately() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let started = std::time::Instant::now();
        let (out, _ledger): (anyhow::Result<&'static str>, Vec<DispatchAttempt>) = retry_loop(
            crate::providers::failover::RetryPolicy {
                retries: 1,
                backoff_ms: 150,
            },
            std::time::Duration::from_millis(crate::providers::failover::FAILOVER_BUDGET_MS),
            "test-provider",
            "m",
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err(http_err_after(429, std::time::Duration::ZERO))
                    } else {
                        Ok("served")
                    }
                }
            },
        )
        .await;
        assert_eq!(out.expect("served"), "served");
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A 4xx that is not transient ignores a `Retry-After` it carries: the same request
    /// gets the same answer (the classifier still runs first).
    #[tokio::test]
    async fn retry_after_on_a_non_transient_error_does_not_create_a_retry() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let (out, _): (anyhow::Result<()>, Vec<DispatchAttempt>) = retry_loop(
            crate::providers::failover::RetryPolicy::BUILTIN,
            std::time::Duration::from_millis(200),
            "test-provider",
            "m",
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(http_err_after(400, std::time::Duration::ZERO)) }
            },
        )
        .await;
        assert!(out.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// **OG-10 proof 4.** Every computed pause is ≤ the remaining budget AND ≤
    /// `backoff × 2^n`, across the whole sample range and a spread of parameters — and the
    /// two bounds are each the binding one somewhere, so neither is vacuous.
    #[test]
    fn jitter_never_exceeds_the_remaining_budget_or_the_exponential_cap() {
        use std::time::Duration;
        let mut cap_binds = false;
        let mut budget_binds = false;
        for backoff_ms in [0u64, 1, 10, 100, 199] {
            for attempt in [0u32, 1, 2, 3, 5, 10, 40, 200] {
                for remaining_ms in [0u64, 1, 7, 100, 200] {
                    for sample in [0u64, 1, u64::MAX / 3, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
                        let backoff = Duration::from_millis(backoff_ms);
                        let remaining = Duration::from_millis(remaining_ms);
                        let pause = jitter_pause(backoff, attempt, remaining, sample);
                        let cap = backoff.saturating_mul(2u32.saturating_pow(attempt.min(30)));
                        assert!(pause <= remaining, "{pause:?} > remaining {remaining:?}");
                        assert!(pause <= cap, "{pause:?} > cap {cap:?}");
                        cap_binds |= remaining > cap && pause > Duration::ZERO;
                        budget_binds |= cap > remaining && pause > Duration::ZERO;
                    }
                }
            }
        }
        assert!(cap_binds && budget_binds, "both bounds must be exercised");
        // Full jitter spans the interval: the lowest sample is 0 and the highest approaches the cap.
        let b = Duration::from_millis(100);
        let big = Duration::from_secs(10);
        assert_eq!(jitter_pause(b, 0, big, 0), Duration::ZERO);
        assert!(jitter_pause(b, 0, big, u64::MAX) >= Duration::from_millis(99));
        assert!(jitter_pause(b, 2, big, u64::MAX) >= Duration::from_millis(399));
    }

    /// With no `Retry-After`, the loop retries on a jittered pause bounded by the budget:
    /// a sampler pinned to the top of the range makes the bound observable in total time.
    #[tokio::test]
    async fn a_503_without_retry_after_retries_on_a_jittered_pause_within_the_budget() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let started = std::time::Instant::now();
        let (out, _): (anyhow::Result<&'static str>, Vec<DispatchAttempt>) = retry_loop_with(
            crate::providers::failover::RetryPolicy {
                retries: 3,
                backoff_ms: 40,
            },
            std::time::Duration::from_millis(200),
            "test-provider",
            "m",
            || u64::MAX,
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 3 {
                        Err(http_err(503))
                    } else {
                        Ok("served")
                    }
                }
            },
        )
        .await;
        assert_eq!(out.expect("served on the last retry"), "served");
        // Pauses at the top of the range: ~40 + ~80 + (200-120)=80 capped → total ≤ 200 ms.
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_millis(400),
            "the sum of pauses is bounded by the 200 ms budget: {took:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 4);
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
            message: None,
            retry_after: None,
        }
        .into())
    }

    #[test]
    fn breaker_ignores_a_caller_blaming_upstream_4xx() {
        // F4 (2026-10-03): 429 joins this list. Under BYOK a 429 is ONE tenant's account
        // quota — observed live: a free-tier Mistral key's 429s opened `mistral` for the
        // whole process (`503 upstream_circuit_open`).
        for status in [400u16, 401, 403, 404, 429] {
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
        for status in [500u16, 502, 503] {
            assert_eq!(
                super::breaker_outcome(&http_err(status)),
                Some(crate::circuit_breaker::Outcome::UpstreamFault),
                "{status} is an upstream fault — ADR-036 (as amended 2026-10-03) trips on 5xx"
            );
        }
        assert_eq!(
            super::breaker_outcome(&Ok::<(), anyhow::Error>(())),
            Some(crate::circuit_breaker::Outcome::Success)
        );
    }

    /// `OG-13` proof 4: 429 / 401 / 403 / 404 feed NEITHER tier on any wire. Chat and
    /// embeddings feed through `breaker_outcome`; every relay wire (messages, responses,
    /// gemini, media, files, batches, realtime, passthrough) through
    /// `openai_responses::breaker_observation`. Both predicates are driven into a real
    /// breaker exactly as the call sites do, a hundred times, and both tiers stay Closed.
    #[test]
    fn og13_proof4_caller_blaming_4xx_feed_neither_tier_on_any_wire() {
        use crate::circuit_breaker::{CircuitBreaker, Cred, State};
        let cb = CircuitBreaker::default();
        let tenant = uuid::Uuid::from_u128(4);
        let cred = Cred::byok(&tenant, "openai", "default");
        for status in [401u16, 403, 404, 429] {
            for _ in 0..100 {
                if let Some(ok) = super::breaker_outcome(&http_err(status)) {
                    cb.record("openai", "default", &cred, ok);
                }
                if let Some(ok) = crate::openai_responses::breaker_observation(Some(status)) {
                    cb.record("openai", "default", &cred, ok);
                }
            }
        }
        assert_eq!(cb.state("openai", "default", &cred.id), State::Closed);
        assert!(
            cb.outcomes("openai", "default", &cred.id).is_empty(),
            "fed nothing"
        );
        let other = Cred::byok(&uuid::Uuid::from_u128(5), "openai", "default");
        assert!(
            cb.allow("openai", "default", &other),
            "provider-wide tier Closed"
        );
    }

    /// `OG-13`: the credential decision. With a control plane and a master key a tenant's
    /// dispatch is ITS credential (two tenants never share one); otherwise — and for a
    /// provider that takes no key — it is the operator's environment credential.
    #[test]
    fn og13_breaker_cred_is_per_tenant_under_byok_and_env_otherwise() {
        use crate::circuit_breaker::Credential;
        let a = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(1));
        let b = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(2));
        let ca = super::breaker_cred_with(false, &a, "openai", "default");
        let cb = super::breaker_cred_with(false, &b, "openai", "default");
        assert!(matches!(ca.id, Credential::Byok(_)));
        assert_ne!(ca.id, cb.id, "two tenants never share a credential breaker");
        assert_ne!(
            ca.id,
            super::breaker_cred_with(false, &a, "openai", "team-b").id,
            "two labels of one tenant are two credentials"
        );
        assert_eq!(
            super::breaker_cred_with(true, &a, "openai", "default").id,
            Credential::Env,
            "no control plane: the operator's environment key, shared"
        );
        assert_eq!(
            super::breaker_cred_with(false, &a, "ollama", "default").id,
            Credential::Env,
            "a keyless provider has no tenant credential"
        );
    }
    fn pem() -> String {
        use aws_lc_rs::encoding::AsDer as _;
        use base64::Engine as _;
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("generate a test RSA key");
        let der = key.as_der().expect("PKCS#8 DER");
        let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let body: String = b64
            .as_bytes()
            .chunks(64)
            .map(|l| format!("{}\n", std::str::from_utf8(l).expect("ascii")))
            .collect();
        format!("-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n")
    }

    /// The three tenant-controlled failure shapes the round-2 review named, produced by
    /// the REAL code paths: a Vertex service account whose `token_uri` is the tenant's
    /// own host answering 500, a malformed service-account JSON, and a key with an
    /// interior control byte (a reqwest builder error at header build).
    async fn tenant_made_failures() -> Vec<anyhow::Error> {
        let _bypass = crate::handler_harness::LoopbackBypassGuard::new();
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let req = || -> tracelane_shared::ChatRequest {
            serde_json::from_value(serde_json::json!({
                "model": "vertex/gemini-2.5-pro",
                "messages": [{"role": "user", "content": "hi"}]
            }))
            .unwrap()
        };
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let vertex = crate::providers::VertexProvider::new().unwrap();
        let poisoned_sa = serde_json::json!({
            "client_email": "sb@example.test",
            "project_id": "sb-project",
            "private_key": pem(),
            "token_uri": format!("{}/token", server.uri()),
        })
        .to_string();
        let mut out = Vec::new();
        out.push(
            vertex
                .chat(req(), &poisoned_sa, &tenant)
                .await
                .err()
                .unwrap(),
        );
        out.push(
            vertex
                .chat(req(), "{\"client_email\":", &tenant)
                .await
                .err()
                .unwrap(),
        );
        let client = crate::ssrf_guard::safe_client_builder().build().unwrap();
        out.push(
            client
                .post(format!("{}/v1/chat/completions", server.uri()))
                .header("authorization", "Bearer sk-ab\u{1}cd")
                .send()
                .await
                .map_err(reqwest::Error::without_url)
                .map(|_| ())
                .err()
                .map(anyhow::Error::from)
                .expect("an interior control byte is a builder error"),
        );
        out
    }

    /// SB (security re-review round 2, 2026-10-05): `breaker_outcome` counted EVERY
    /// non-`ProviderHttpError` error as a provider failure under default tuning, so three
    /// free workspaces with poisoned credentials opened the SHARED provider tier for
    /// everyone. A credential-derived failure may only affect its own credential.
    #[tokio::test]
    async fn sb_credential_derived_failures_never_open_the_provider_tier() {
        use crate::circuit_breaker::{CircuitBreaker, Cred};
        let cb = CircuitBreaker::default();
        let creds: Vec<Cred> = (0..3u128)
            .map(|n| Cred::byok(&uuid::Uuid::from_u128(0x5b00 + n), "openai", "default"))
            .collect();
        for _round in 0..6 {
            for (cred, err) in creds.iter().zip(tenant_made_failures().await) {
                if let Some(ok) = super::breaker_outcome(&Err::<(), _>(err)) {
                    cb.record("openai", "default", cred, ok);
                }
            }
        }
        let healthy = Cred::byok(&uuid::Uuid::from_u128(0x5b99), "openai", "default");
        assert!(
            cb.allow("openai", "default", &healthy),
            "three tenants' credential-derived failures must not shed a healthy fourth tenant"
        );
        // The protection kept: real upstream 5xx from three tenants under defaults.
        for n in 0..3u128 {
            let cred = Cred::byok(&uuid::Uuid::from_u128(0x5c00 + n), "openai", "default");
            for _ in 0..10 {
                if let Some(ok) = super::breaker_outcome(&http_err(503)) {
                    cb.record("openai", "default", &cred, ok);
                }
            }
        }
        assert!(
            !cb.allow("openai", "default", &healthy),
            "a real outage still opens it"
        );
    }
}

/// `OG-10` end to end: the REAL chat handler, a wiremock upstream, and what the CLIENT sees.
/// The hammer proofs count requests at the upstream — a 429 that is retried after our
/// 100 ms instead of the provider's 20 s is invisible in a status code.
#[cfg(all(test, debug_assertions))]
mod og10_handler_tests {
    use crate::handler_harness::{
        LoopbackBypassGuard, authed, body_json, chat_ok_body, registry_pointing_ollama_at,
        test_state,
    };
    use crate::server::chat_completions_handler;
    use axum::extract::{Json, State};
    use axum::http::StatusCode;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn call(server: &MockServer) -> axum::response::Response {
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        chat_completions_handler(
            State(state),
            authed(),
            Json(json!({
                "model": "ollama/llama3",
                "messages": [{"role": "user", "content": "hi"}],
            })),
        )
        .await
    }

    fn retry_after(resp: &axum::response::Response) -> Option<&str> {
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
    }

    /// **OG-10 proof 2.** A 429 that says "wait 20 s": exactly ONE upstream request, and the
    /// client gets 429 with the provider's `Retry-After: 20` (header AND body).
    #[tokio::test]
    async fn a_429_with_retry_after_20_is_not_hammered_and_the_client_is_told_20() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "20")
                    .set_body_string(r#"{"error":{"message":"slow down"}}"#),
            )
            .expect(1)
            .mount(&server)
            .await;
        let resp = call(&server).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            retry_after(&resp),
            Some("20"),
            "the provider's value, not the gateway's 60 s guess"
        );
        let body = body_json(resp).await;
        assert_eq!(body["retry_after_secs"], 20);
        assert_eq!(
            server.received_requests().await.map(|r| r.len()),
            Some(1),
            "exactly one upstream request — the hammer is stopped"
        );
    }

    /// Without an upstream hint the pre-OG-10 behaviour stands: the gateway's 60 s guess in
    /// the header only, no `retry_after_secs` in the body (a guess is not the provider's word).
    #[tokio::test]
    async fn a_429_without_retry_after_keeps_the_header_guess_and_no_body_field() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let resp = call(&server).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after(&resp), Some("60"));
        assert!(body_json(resp).await.get("retry_after_secs").is_none());
    }

    /// **OG-10 proof 3.** `Retry-After: 0` then 200: two requests, success.
    #[tokio::test]
    async fn a_429_with_retry_after_0_is_retried_once_and_succeeds() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(chat_ok_body()))
            .with_priority(2)
            .mount(&server)
            .await;
        let resp = call(&server).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(server.received_requests().await.map(|r| r.len()), Some(2));
    }

    /// A 503 with no header: jittered retry, then success.
    #[tokio::test]
    async fn a_503_without_retry_after_is_retried_on_a_jittered_pause() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(chat_ok_body()))
            .with_priority(2)
            .mount(&server)
            .await;
        let resp = call(&server).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(server.received_requests().await.map(|r| r.len()), Some(2));
    }

    /// A 503 that says "wait 20 s": no retry, the status keeps its existing mapping (502),
    /// and the provider's `Retry-After` reaches the client.
    #[tokio::test]
    async fn a_503_with_retry_after_surfaces_it_on_the_existing_502() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503).insert_header("retry-after", "20"))
            .expect(1)
            .mount(&server)
            .await;
        let resp = call(&server).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(retry_after(&resp), Some("20"));
        assert_eq!(body_json(resp).await["retry_after_secs"], 20);
        assert_eq!(server.received_requests().await.map(|r| r.len()), Some(1));
    }

    /// The upstream's `Retry-After` is clamped by the reference table before anyone sees it.
    #[tokio::test]
    async fn a_huge_retry_after_is_clamped_to_the_table_ceiling() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "9999999"))
            .mount(&server)
            .await;
        let resp = call(&server).await;
        assert_eq!(retry_after(&resp), Some("3600"));
    }
}

#[cfg(test)]
mod capture_error_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_guardrail_error_span_replaces_raw_input_with_the_redacted_form() {
        let state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        let tenant = crate::handler_harness::dev_tenant();
        let trace = Uuid::new_v4();
        let mut guard = DispatchGuard::arm(
            &state,
            &tenant,
            trace,
            None,
            "ollama/llama3",
            &CallerIdentity::default(),
            chrono::Utc::now(),
        );
        let capture = crate::server::config::ContentCapture {
            input: true,
            output: false,
            max_field_bytes: 64 * 1024,
        };
        let raw: tracelane_shared::ChatRequest = serde_json::from_value(json!({
            "model":"ollama/llama3", "messages":[{"role":"user","content":"RAW_BEFORE_GUARDRAIL"}]
        }))
        .unwrap();
        let safe: tracelane_shared::ChatRequest = serde_json::from_value(json!({
            "model":"ollama/llama3", "messages":[{"role":"user","content":"R2_SAFE_ONLY"}]
        }))
        .unwrap();
        guard.record_input(CapturedInput::build(capture, &raw));
        guard.record_input(CapturedInput::build(capture, &safe));
        guard.abort("guardrail_block", None);
        let spans = crate::otlp_emit::test_sink::for_trace(trace);
        assert_eq!(spans.len(), 1);
        let input = spans[0]
            .attributes
            .gen_ai_input_messages
            .as_ref()
            .unwrap()
            .to_string();
        assert!(input.contains("R2_SAFE_ONLY"));
        assert!(!input.contains("RAW_BEFORE_GUARDRAIL"));
    }
}

impl DispatchGuard {
    /// Replace request content after redaction; `None` clears unsafe raw input.
    pub(crate) fn record_input(&mut self, captured: Option<CapturedInput>) {
        self.captured_input = captured;
    }
}

fn kms_failure(error: crate::kms::KmsError) -> ProviderKey {
    match error {
        crate::kms::KmsError::Unavailable => ProviderKey::KmsUnavailable,
        crate::kms::KmsError::Denied => ProviderKey::KmsDenied,
    }
}
