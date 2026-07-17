//!
//! Distinct from entitlements: entitlements answer "is this tenant *allowed*
//! this feature?" (commercial); kill-switches answer "is this code path *safe
//! to run* right now?" (operational). Conflating them means you can't disable a
//! misbehaving predictor without changing someone's plan.
//!
//! Backed by PostHog feature flags, read through a **30s-TTL cached snapshot**
//! (same no-per-request-network discipline as the entitlement cache, ADR-035) —
//! a background task refreshes the snapshot; the hot path only reads an
//! `ArcSwap`. Three flag families:
//!   - `kill.predictive.{trajectory_guard,slm_judge,argdrift}` — disable a
//!     predictor fleet-wide in seconds, no redeploy.
//!   - `kill.upstream.<provider>` — force a provider's breaker open.
//!   - `flag.canary.<feature>` — canary cohort selection (§23.5).
//!
//! **Fail-safe** (ADR-038): if PostHog is unreachable or unconfigured, every
//! flag resolves to its safe default. The V1 flags all default to `false`
//! (feature stays **on**, no upstream forced open, no canary) — the fail-open
//! posture for predictors that are themselves fail-open. Any future flag
//! guarding a failure-*amplifying* path must instead default `true` (disabled);
//! such flags pass a `true` default to [`KillSwitch::flag`] and are documented
//! at their call site.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

/// Refresh cadence for the PostHog flag snapshot.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// Stable server identity for PostHog flag evaluation (`/decide`).
const DISTINCT_ID: &str = "tracelane-gateway";

/// Operational kill-switch reader. Cheap to clone (`Arc`-backed snapshot).
#[derive(Clone)]
pub struct KillSwitch {
    flags: Arc<ArcSwap<HashMap<String, bool>>>,
}

impl KillSwitch {
    /// A kill-switch with no flags set — every flag resolves to its safe
    /// default. Used when PostHog is unconfigured (dev) and as the test seed.
    pub fn disabled() -> Self {
        Self {
            flags: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    /// Build from the environment. If `POSTHOG_PROJECT_API_KEY` is set, spawns
    /// the 30s refresh task against `POSTHOG_HOST` (default `https://app.posthog.com`).
    /// Otherwise returns a [`KillSwitch::disabled`] that always serves defaults.
    pub fn from_env() -> Self {
        let ks = Self::disabled();
        match std::env::var("POSTHOG_PROJECT_API_KEY") {
            Ok(key) if !key.is_empty() => {
                let host = std::env::var("POSTHOG_HOST")
                    .unwrap_or_else(|_| "https://app.posthog.com".to_string());
                tracing::info!(%host, "kill-switch: PostHog flag refresh enabled (30s)");
                ks.spawn_refresh(key, host);
            }
            _ => {
                tracing::info!(
                    "kill-switch: POSTHOG_PROJECT_API_KEY unset — all flags serve safe defaults"
                );
            }
        }
        ks
    }

    /// Seed a snapshot directly (tests / explicit configuration).
    #[cfg(test)]
    pub fn with_flags(flags: HashMap<String, bool>) -> Self {
        Self {
            flags: Arc::new(ArcSwap::from_pointee(flags)),
        }
    }

    /// Resolve a flag, returning `default` when absent (fail-safe). The default
    /// encodes the safe posture for that flag's code path (see module docs).
    pub fn flag(&self, key: &str, default: bool) -> bool {
        self.flags.load().get(key).copied().unwrap_or(default)
    }

    /// Is predictor `name` killed? Default `false` — predictors are fail-open,
    /// so an unreachable flag service leaves them running.
    pub fn predictive_killed(&self, name: &str) -> bool {
        self.flag(&format!("kill.predictive.{name}"), false)
    }

    /// Is `provider` force-disabled (breaker forced open)? Default `false`.
    pub fn upstream_killed(&self, provider: &str) -> bool {
        self.flag(&format!("kill.upstream.{provider}"), false)
    }

    /// Is canary cohorting enabled for `feature`? Default `false` (no canary).
    /// Consumed by `canary::should_route_to_canary`; no V1 call site until a
    /// gateway-config canary is staged (ADR-038 §23.5), hence `dead_code`.
    #[allow(dead_code)]
    pub fn canary_enabled(&self, feature: &str) -> bool {
        self.flag(&format!("flag.canary.{feature}"), false)
    }

    /// Spawn the background refresh task. On any error it keeps the last good
    /// snapshot (or the empty default snapshot) — never clears to an unsafe state.
    fn spawn_refresh(&self, api_key: String, host: String) {
        let flags = self.flags.clone();
        tokio::spawn(async move {
            // Operator-configured host (not customer-supplied) → a plain client
            // with a tight timeout is appropriate; SSRF guard is for
            // customer-supplied URLs (security.md).
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "kill-switch: client build failed; defaults only");
                    return;
                }
            };
            let url = format!("{}/decide/?v=3", host.trim_end_matches('/'));
            loop {
                match fetch_flags(&client, &url, &api_key).await {
                    Ok(snapshot) => flags.store(Arc::new(snapshot)),
                    Err(e) => {
                        tracing::warn!(error = %e, "kill-switch: PostHog refresh failed; keeping last snapshot")
                    }
                }
                tokio::time::sleep(REFRESH_INTERVAL).await;
            }
        });
    }
}

/// POST PostHog `/decide` and parse `featureFlags` into a bool map. A flag whose
/// value is `true` (or a non-`false` variant string) is considered set.
async fn fetch_flags(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
) -> anyhow::Result<HashMap<String, bool>> {
    let body = serde_json::json!({ "api_key": api_key, "distinct_id": DISTINCT_ID });
    let resp = client.post(url).json(&body).send().await?;
    if !resp.status().is_success() {
        // Drop the body — provider/3p responses may echo tokens (security.md).
        anyhow::bail!("PostHog /decide returned {}", resp.status());
    }
    let json: serde_json::Value = resp.json().await?;
    let mut out = HashMap::new();
    if let Some(map) = json.get("featureFlags").and_then(|v| v.as_object()) {
        for (k, v) in map {
            let on = match v {
                serde_json::Value::Bool(b) => *b,
                // A variant string means the flag is enabled (some variant).
                serde_json::Value::String(s) => s != "false",
                _ => false,
            };
            out.insert(k.clone(), on);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_serves_safe_defaults() {
        let ks = KillSwitch::disabled();
        // Predictors stay on (not killed); upstreams available; no canary.
        assert!(!ks.predictive_killed("slm_judge"));
        assert!(!ks.upstream_killed("openai"));
        assert!(!ks.canary_enabled("new-router"));
        // Explicit amplify-path default is honoured.
        assert!(ks.flag("kill.some.amplifier", true));
    }

    #[test]
    fn set_flags_are_read() {
        let mut m = HashMap::new();
        m.insert("kill.predictive.slm_judge".to_string(), true);
        m.insert("kill.upstream.anthropic".to_string(), true);
        m.insert("flag.canary.new-router".to_string(), true);
        let ks = KillSwitch::with_flags(m);
        assert!(ks.predictive_killed("slm_judge"));
        assert!(!ks.predictive_killed("trajectory_guard")); // unset → default off
        assert!(ks.upstream_killed("anthropic"));
        assert!(!ks.upstream_killed("openai"));
        assert!(ks.canary_enabled("new-router"));
    }
}
