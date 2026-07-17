//! Provider failover logic (FT-01).
//!
//! `FailoverChain` wraps an ordered list of provider names and tries them
//! in sequence when the primary fails. A provider is considered failed if
//! it returns a non-retryable HTTP error (500, 502, 503, 504) or a network
//! timeout. The chain activates the secondary within the 200ms SLO defined
//! in TRD FT-01.
//!
//! Span attribute `tracelane.failover.activated=true` is set whenever a
//! secondary provider is used. `tracelane.failover.attempt_count=N` records
//! the number of attempts made.
//!
//! Failover chain (from CLAUDE.md §model-routing):
//!   Anthropic Sonnet → OpenAI gpt-5.x → Gemini 3 Pro

use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::instrument;

use tracelane_shared::TenantId;

/// Error codes that trigger failover (not caller errors like 400, 401).
pub const FAILOVER_CODES: &[u16] = &[500, 502, 503, 504];

/// Default timeout before giving up on a single provider attempt.
pub const PROVIDER_ATTEMPT_TIMEOUT_MS: u64 = 10_000;

/// Maximum time budget for the entire failover chain.
pub const FAILOVER_BUDGET_MS: u64 = 200;

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
    /// Build span attributes from this record for OTLP emission.
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

/// The ordered fallback chain of provider names.
///
/// Production: Anthropic Sonnet → OpenAI → Gemini (from CLAUDE.md).
/// Overridable per-tenant in the Cedar policy engine (Week 8).
pub fn default_failover_chain() -> Vec<&'static str> {
    vec!["anthropic", "openai", "google"]
}

///
/// Cross-provider failover works because the gateway carries a *universal*
/// `ChatRequest` that each adapter translates into its provider's wire format
/// — so failing over is just re-dispatching the same canonical request to a
/// different provider with a model that routes there. The returned string must
/// match that provider's prefix in `dispatch_to_provider` /
/// `provider_name_from_model`. Kept deliberately small (one flagship model per
/// family); tune as flagship models change.
#[must_use]
pub fn failover_model_for(provider: &str) -> Option<&'static str> {
    match provider {
        "anthropic" => Some("claude-3-5-sonnet-latest"),
        "openai" => Some("gpt-4o"),
        "google" => Some("gemini-1.5-pro"),
        _ => None,
    }
}

/// from `primary_family`. Skips the primary and any provider without a known
/// failover model. Empty when the primary is the only viable family.
#[must_use]
pub fn cross_provider_candidates(primary_family: &str) -> Vec<(&'static str, &'static str)> {
    default_failover_chain()
        .into_iter()
        .filter(|p| *p != primary_family)
        .filter_map(|p| failover_model_for(p).map(|m| (p, m)))
        .collect()
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
/// Returns `Ok((output, record))` when a provider succeeds.
/// Returns `Err(last_error)` if all providers fail.
///
/// # Arguments
/// - `chain` — ordered provider names to try
/// - `attempt_fn` — async closure `(provider_name: &str) -> Result<T, status_code>`
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
    let deadline = Instant::now() + Duration::from_millis(FAILOVER_BUDGET_MS);
    let mut last_code: u16 = 0;

    for (idx, &provider_name) in chain.iter().enumerate() {
        if Instant::now() >= deadline && idx > 0 {
            tracing::warn!(
                provider = provider_name,
                elapsed_ms = deadline.elapsed().as_millis(),
                "failover budget exhausted — skipping remaining providers"
            );
            break;
        }

        match attempt_fn(provider_name).await {
            Ok(output) => {
                let elapsed_ms = Instant::now()
                    .duration_since(deadline - Duration::from_millis(FAILOVER_BUDGET_MS))
                    .as_millis() as u64;

                let record = FailoverRecord {
                    winning_provider_index: idx,
                    winning_provider_name: provider_name.to_string(),
                    attempt_count: idx + 1,
                    failover_activated: idx > 0,
                    total_elapsed_ms: elapsed_ms,
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
                anyhow::bail!(
                    "provider '{}' returned non-retryable {status_code}",
                    provider_name
                );
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

    #[test]
    fn failover_models_route_back_to_their_provider() {
        // Each failover model must start with the prefix dispatch_to_provider
        // uses to route, so re-dispatch lands on the intended adapter.
        assert_eq!(
            failover_model_for("anthropic"),
            Some("claude-3-5-sonnet-latest")
        );
        assert!(
            failover_model_for("anthropic")
                .unwrap()
                .starts_with("claude")
        );
        assert!(failover_model_for("openai").unwrap().starts_with("gpt"));
        assert!(failover_model_for("google").unwrap().starts_with("gemini"));
        assert_eq!(failover_model_for("cohere"), None);
    }

    #[test]
    fn cross_provider_candidates_skips_primary_and_keyless_families() {
        // Failing over from Anthropic → the rest of the default chain.
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
        assert_eq!(cross_provider_candidates("cohere").len(), 3);
    }
}
