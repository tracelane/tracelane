//! Provider failover (FT-01 /).
//!
//! ## Two mechanisms share this name; only one is on the request path
//!
//! - **On the request path.** [`cross_provider_candidates`] supplies the
//!   ordered `(provider id, model)` hops the chat handler walks when a request
//!   opted in with `X-Tracelane-Failover: cross-provider` *and* the primary
//!   provider errored. That opt-in is OFF by default, so a request that does
//!   not send the header never reaches a second provider.
//! - **Not on the request path.** [`execute_with_failover`] is a generic
//!   try-each-in-turn combinator. Its only callers are this module's tests and
//!   `providers/smoke_tests.rs`; the chat handler does not call it. Recorded
//!   here because a reader who assumes otherwise will change it and watch
//!   production behave identically.
//!
//! The retry that runs on **every** request is same-provider, and it lives in
//! `server.rs::dispatch_with_retry` — not in this module.
//!
//! ## Operator configuration (`tracelane.yaml`)
//!
//! ```yaml
//! failover:
//!   chain: anthropic, openai, google
//!   retries: 1
//!   backoff_ms: 100
//! ```
//!
//! Parsed and validated by [`crate::server::config`]: every provider id is
//! checked against the catalog and every hop's model must resolve back to its
//! own provider, both at parse time. A hop the gateway could not dispatch is a
//! failover that silently does not happen, so an unroutable entry refuses the
//! boot instead of being dropped. A hop may name its own model
//! (`chain: groq:llama-3.3-70b-versatile`), which is the only way to use one of
//! the 160-odd providers that has no built-in entry below.
//!
//! With **no** `failover:` block the built-ins below apply, so a deployment
//! that ships no config file is unchanged.

use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::instrument;

use tracelane_shared::TenantId;

/// Error codes that trigger failover (not caller errors like 400, 401).
pub const FAILOVER_CODES: &[u16] = &[500, 502, 503, 504];

/// Maximum time budget for the entire failover chain.
///
/// Read by `server.rs::dispatch_with_retry` to decide whether a retry still
/// fits, and by [`crate::server::config`] to bound a configured `backoff_ms`.
pub const FAILOVER_BUDGET_MS: u64 = 200;

/// The built-in cross-provider chain: `(provider id, the model to ask that
/// provider for)`.
///
/// Cross-provider failover works because the gateway carries a *universal*
/// `ChatRequest` that each adapter translates into its provider's wire format
/// — so failing over is re-dispatching the same canonical request to a
/// different provider with a model that routes there. Every model here must
/// therefore resolve back to its own provider through
/// `ProviderRegistry::provider_id_for_model`, which
/// `builtin_chain_models_route_back_to_their_own_provider` proves rather than
/// asserts by prefix.
///
/// These are deliberately long-lived model names, **not** each family's current
/// flagship: changing one changes what every deployment without a `failover:`
/// block dispatches to. An operator who wants a newer model names it in
/// `tracelane.yaml` instead of waiting for a gateway release.
pub const DEFAULT_CHAIN: &[(&str, &str)] = &[
    ("anthropic", "claude-3-5-sonnet-latest"),
    ("openai", "gpt-4o"),
    ("google", "gemini-1.5-pro"),
];

/// Same-provider retry attempts made when no `failover:` block is present.
/// This is the count `server.rs::dispatch_with_retry` hardcodes today.
pub const DEFAULT_RETRIES: u32 = 1;

/// Pause before the same-provider retry when no `failover:` block is present,
/// in milliseconds. The value `server.rs::dispatch_with_retry` hardcodes today.
pub const DEFAULT_BACKOFF_MS: u64 = 100;

/// Largest `retries:` a `failover:` block may ask for.
///
/// An operator cap, not a derived limit: every attempt is a real upstream round
/// trip inside the same [`FAILOVER_BUDGET_MS`] budget, so a sixth attempt
/// cannot fit even at zero backoff.
pub const MAX_RETRIES: u32 = 5;

/// How many extra same-provider attempts to make, and how long to wait between
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts *after* the first. `0` disables the retry.
    pub retries: u32,
    /// Pause between attempts, in milliseconds.
    pub backoff_ms: u64,
}

impl RetryPolicy {
    /// The built-in policy: one retry, 100 ms apart.
    pub const BUILTIN: Self = Self {
        retries: DEFAULT_RETRIES,
        backoff_ms: DEFAULT_BACKOFF_MS,
    };

    /// Total time this policy can spend sleeping between attempts.
    ///
    /// [`crate::server::config`] refuses a `failover:` block whose plan does
    /// not fit inside [`FAILOVER_BUDGET_MS`] — a backoff longer than the budget
    /// is a retry that can never fire, which reads as "retries configured" and
    /// behaves as "no retries".
    #[must_use]
    pub const fn planned_backoff_ms(&self) -> u64 {
        self.retries as u64 * self.backoff_ms
    }
}

// The built-in policy must satisfy the very bounds `config` enforces on a
// CONFIGURED one — otherwise the default would be a value an operator is
// forbidden to write down, and `build_failover` could not skip the plan check
// when neither `retries:` nor `backoff_ms:` is present. Asserted at COMPILE
// time rather than in a test: every term is a `const`, so a unit test asserting
// them would pass by construction and prove nothing a reader could not already
// see. Change a default past a bound and the crate does not build.
const _: () = assert!(RetryPolicy::BUILTIN.planned_backoff_ms() < FAILOVER_BUDGET_MS);
const _: () = assert!(RetryPolicy::BUILTIN.retries <= MAX_RETRIES);
const _: () = assert!(RetryPolicy::BUILTIN.backoff_ms < FAILOVER_BUDGET_MS);

/// The retry policy in force: the `failover:` block's, or [`RetryPolicy::BUILTIN`].
///
/// **APPLIED. `server.rs::dispatch_with_retry` calls this** (`server.rs`, the
/// `retry_policy()` call at the head of the loop), so an operator's `retries:`
/// and `backoff_ms:` change the real number of attempts and the real pause
/// between them.
///
/// This doc previously said the opposite — "the retry loop does not read this
/// yet" — and pointed at a startup WARN that announced the gap. GWY-44 wired the
/// loop; the doc and the WARN were not updated with it. **A stale doc that
/// UNDERSTATES what the code does is still a defect**, and this one had teeth: it
/// told an operator their configured retry policy was inert, so the reasonable
/// response was to stop trusting the knob. Corrected 2026-08-18, found by
/// checking whether the chain was really in force rather than assuming it.
///
/// `retries:` and `backoff_ms:` are ALSO validated at parse time — an
/// out-of-budget value refuses the boot rather than being silently clamped.
#[must_use]
pub fn retry_policy() -> RetryPolicy {
    crate::server::config::failover().map_or(RetryPolicy::BUILTIN, |f| RetryPolicy {
        retries: f.retries(),
        backoff_ms: f.backoff_ms(),
    })
}

/// Records the outcome of a failover chain execution.
#[derive(Debug, Clone)]
pub struct FailoverRecord {
    /// Index of the provider that succeeded (0 = primary, 1 = secondary, …)
    pub winning_provider_index: usize,
    /// Provider name of the winner
    pub winning_provider_name: String,
    /// Number of providers tried (1 = primary succeeded)
    pub attempt_count: usize,
    /// Whether failover activated (attempt_count > 1)
    pub failover_activated: bool,
    /// Total wall-clock elapsed across all attempts
    pub total_elapsed_ms: u64,
}

impl FailoverRecord {
    /// Render this record as `(key, value)` pairs.
    ///
    /// Nothing emits these today: the span fields a served request actually
    /// carries are `tracelane_failover_activated` / `tracelane_failover_from`
    /// (`crates/shared/src/span.rs`), set by the chat handler on the
    /// cross-provider path. This method belongs to [`execute_with_failover`],
    /// which is not on that path.
    pub fn span_attrs(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "tracelane.failover.activated",
                self.failover_activated.to_string(),
            ),
            (
                "tracelane.failover.attempt_count",
                self.attempt_count.to_string(),
            ),
            (
                "tracelane.failover.winning_provider",
                self.winning_provider_name.clone(),
            ),
            (
                "tracelane.failover.elapsed_ms",
                self.total_elapsed_ms.to_string(),
            ),
        ]
    }
}

/// Determine whether an HTTP status code should trigger provider failover.
#[inline]
pub fn is_failover_eligible(status_code: u16) -> bool {
    FAILOVER_CODES.contains(&status_code)
}

/// The built-in model for a provider in [`DEFAULT_CHAIN`], or `None`.
///
/// `None` is a real answer, and the common one: only three of the 169 routable
/// providers have a built-in entry. A `failover:` chain that names any other
/// provider must spell the model out (`chain: groq:llama-3.3-70b-versatile`),
/// and [`crate::server::config`] refuses the block if it does not — rather than
/// dropping the hop and leaving a chain that looks configured and does nothing.
#[must_use]
pub fn failover_model_for(provider: &str) -> Option<&'static str> {
    DEFAULT_CHAIN
        .iter()
        .find(|(p, _)| *p == provider)
        .map(|(_, m)| *m)
}

/// Ordered `(provider, model)` candidates to try when failing over AWAY
/// from `primary_family`. Skips the primary; empty when it is the only hop.
///
/// Reads the `failover:` chain from `tracelane.yaml` when one was installed,
/// otherwise [`DEFAULT_CHAIN`]. Both are already validated — every id is a
/// provider some adapter serves, every model resolves back to its own provider
/// — so this cannot silently drop a hop the operator *wrote*.
///
/// The chat handler still skips a hop at *dispatch* time, for two runtime
/// reasons that are not this function's to know: an open circuit breaker or a
/// kill switch (skipped with no log line at all), and no BYOK key stored for
/// that provider (one `DEBUG`). Both are properties of the moment, not of the
/// config, so neither is knowable at parse time.
#[must_use]
pub fn cross_provider_candidates(primary_family: &str) -> Vec<(&'static str, &'static str)> {
    match crate::server::config::failover() {
        Some(cfg) => cfg
            .chain()
            .iter()
            .filter(|hop| hop.provider_id != primary_family)
            .map(|hop| (hop.provider_id.as_str(), hop.model.as_str()))
            .collect(),
        None => DEFAULT_CHAIN
            .iter()
            .filter(|(p, _)| *p != primary_family)
            .copied()
            .collect(),
    }
}

/// Trait implemented by provider executor closures.
/// Returns `Ok(output)` on success, `Err(status_code)` on retryable failure.
pub trait ProviderAttempt: Send + Sync {
    type Output: Send;
    fn execute(
        &self,
        provider_name: &str,
    ) -> impl std::future::Future<Output = std::result::Result<Self::Output, u16>> + Send;
}

/// Execute a closure against each provider in `chain` until one succeeds.
///
/// **Not on the request path.** The chat handler does its own cross-provider
/// walk inline (it has to resolve a BYOK key and consult a circuit breaker per
/// hop, neither of which this signature can express). The callers here are this
/// module's tests and `providers/smoke_tests.rs`.
///
/// Returns `Ok((output, record))` when a provider succeeds.
/// Returns `Err(last_error)` if all providers fail.
///
/// # Arguments
/// - `chain` — ordered provider names to try
/// - `attempt_fn` — async closure `(provider_name: &str) -> Result<T, status_code>`
///
/// # Errors
///
/// Fails when every provider in the chain returned a failover-eligible status,
/// and short-circuits with an error on the first NON-retryable status (a 401 is
/// the same 401 from every provider, so trying the next one only costs money).
#[instrument(skip(chain, attempt_fn), fields(tenant_id = %tenant_id))]
pub async fn execute_with_failover<F, Fut, T>(
    tenant_id: &TenantId,
    chain: &[&str],
    attempt_fn: F,
) -> Result<(T, FailoverRecord)>
where
    F: Fn(&str) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, u16>> + Send,
    T: Send,
{
    let started = Instant::now();
    let deadline = started + Duration::from_millis(FAILOVER_BUDGET_MS);
    let mut last_code: u16 = 0;

    for (idx, &provider_name) in chain.iter().enumerate() {
        if Instant::now() >= deadline && idx > 0 {
            tracing::warn!(
                provider = provider_name,
                elapsed_ms = started.elapsed().as_millis(),
                "failover budget exhausted — skipping remaining providers"
            );
            break;
        }

        match attempt_fn(provider_name).await {
            Ok(output) => {
                let record = FailoverRecord {
                    winning_provider_index: idx,
                    winning_provider_name: provider_name.to_string(),
                    attempt_count: idx + 1,
                    failover_activated: idx > 0,
                    total_elapsed_ms: started.elapsed().as_millis() as u64,
                };

                if record.failover_activated {
                    tracing::warn!(
                        winning_provider = provider_name,
                        attempt_count = record.attempt_count,
                        elapsed_ms = record.total_elapsed_ms,
                        "failover activated — primary provider failed"
                    );
                }

                return Ok((output, record));
            }
            Err(status_code) if is_failover_eligible(status_code) => {
                last_code = status_code;
                tracing::warn!(
                    provider = provider_name,
                    status_code,
                    attempt = idx + 1,
                    "provider failed — trying next in chain"
                );
            }
            Err(status_code) => {
                // Non-retryable error (e.g. 401 Unauthorized) — don't failover
                anyhow::bail!("provider '{provider_name}' returned non-retryable {status_code}");
            }
        }
    }

    anyhow::bail!(
        "all {} providers in failover chain failed (last status: {})",
        chain.len(),
        last_code,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ProviderRegistry;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }

    #[test]
    fn is_failover_eligible_codes() {
        assert!(is_failover_eligible(500));
        assert!(is_failover_eligible(502));
        assert!(is_failover_eligible(503));
        assert!(is_failover_eligible(504));
        assert!(!is_failover_eligible(200));
        assert!(!is_failover_eligible(400));
        assert!(!is_failover_eligible(401));
        assert!(!is_failover_eligible(429));
    }

    #[tokio::test]
    async fn primary_succeeds_no_failover() {
        let t = tenant();
        let chain = ["anthropic", "openai", "google"];
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls2 = calls.clone();

        let (output, record) = execute_with_failover(&t, &chain, |provider| {
            let calls = calls2.clone();
            let provider = provider.to_owned();
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if provider == "anthropic" {
                    Ok::<&'static str, u16>("success")
                } else {
                    Err(500)
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(output, "success");
        assert_eq!(record.attempt_count, 1);
        assert!(!record.failover_activated);
        assert_eq!(record.winning_provider_name, "anthropic");
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn primary_500_triggers_failover_to_secondary() {
        let t = tenant();
        let chain = ["anthropic", "openai", "google"];

        let (output, record) = execute_with_failover(&t, &chain, |provider| {
            let provider = provider.to_owned();
            async move {
                if provider == "anthropic" {
                    Err::<&'static str, u16>(500)
                } else {
                    Ok("secondary-success")
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(output, "secondary-success");
        assert!(record.failover_activated);
        assert_eq!(record.attempt_count, 2);
        assert_eq!(record.winning_provider_name, "openai");
    }

    #[tokio::test]
    async fn all_providers_fail_returns_error() {
        let t = tenant();
        let chain = ["anthropic", "openai"];

        let result =
            execute_with_failover(&t, &chain, |_provider| async move { Err::<&str, u16>(503) })
                .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("providers in failover chain failed")
        );
    }

    #[tokio::test]
    async fn non_retryable_error_short_circuits() {
        let t = tenant();
        let chain = ["anthropic", "openai"];

        let result = execute_with_failover(&t, &chain, |_provider| async move {
            Err::<&str, u16>(401) // non-retryable
        })
        .await;

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("non-retryable"));
    }

    #[test]
    fn failover_record_span_attrs_set_activated() {
        let record = FailoverRecord {
            winning_provider_index: 1,
            winning_provider_name: "openai".into(),
            attempt_count: 2,
            failover_activated: true,
            total_elapsed_ms: 45,
        };
        let attrs = record.span_attrs();
        let activated = attrs
            .iter()
            .find(|(k, _)| *k == "tracelane.failover.activated");
        assert_eq!(activated.map(|(_, v)| v.as_str()), Some("true"));
    }

    /// The property the chain actually depends on: re-dispatching a hop's model
    /// must land on that hop's provider. Asserted through the SAME resolver the
    /// chat handler calls, not through a prefix the test writes down itself —
    /// a prefix assertion passes even when the routing table has moved.
    #[test]
    fn builtin_chain_models_route_back_to_their_own_provider() {
        for (provider, model) in DEFAULT_CHAIN {
            assert_eq!(
                ProviderRegistry::provider_id_for_model(model),
                Some(*provider),
                "failover model `{model}` must still resolve to `{provider}`"
            );
        }
        assert_eq!(
            failover_model_for("anthropic"),
            Some("claude-3-5-sonnet-latest")
        );
        // A provider with no built-in model is `None`, not a guess — that is
        // what makes `config` refuse `chain: groq` instead of dropping the hop.
        assert_eq!(failover_model_for("groq"), None);
        assert_eq!(failover_model_for("cohere"), None);
    }

    #[test]
    fn cross_provider_candidates_skips_the_primary() {
        // No `failover:` block is installed in this test binary, so these
        // exercise the DEFAULT_CHAIN branch.
        assert_eq!(
            cross_provider_candidates("anthropic"),
            vec![("openai", "gpt-4o"), ("google", "gemini-1.5-pro")],
        );
        // From OpenAI → anthropic then google (primary excluded, order kept).
        assert_eq!(
            cross_provider_candidates("openai"),
            vec![
                ("anthropic", "claude-3-5-sonnet-latest"),
                ("google", "gemini-1.5-pro"),
            ],
        );
        // A primary outside the chain still yields the full chain.
        assert_eq!(
            cross_provider_candidates("cohere").len(),
            DEFAULT_CHAIN.len()
        );
    }

    #[test]
    fn retry_policy_is_the_builtin_when_no_failover_block_is_installed() {
        assert_eq!(retry_policy(), RetryPolicy::BUILTIN);
    }
}
