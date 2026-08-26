//! Operational kill-switch / feature-flag layer (ADR-038, TRD §23.6).
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
        // GWY-40. Until now the ONLY flag source was PostHog, so a deployment
        // without a PostHog account — which is every deployment today, and prod
        // — logged "all flags serve safe defaults" and every switch was
        // permanently OFF. The switches were documented as an operational
        // control and could not be operated: the STUB class, confirmed on the
        // running container's own log before this was written.
        //
        // ONE env var carrying EXACT flag keys, not a var per flag. A per-flag
        // name (`TRACELANE_KILLSWITCH_KILL_UPSTREAM_ANTHROPIC`) needs a mangling
        // rule between `_` and `.` that is ambiguous in both directions — and a
        // kill switch that fires on the wrong key, or silently fails to fire
        // because the name round-tripped wrong, is worse than no switch. The
        // keys here are the same strings `flag()` looks up, so there is nothing
        // to translate and nothing to drift.
        let ks = Self::from_flag_list(
            std::env::var("TRACELANE_KILLSWITCH_FLAGS")
                .unwrap_or_default()
                .as_str(),
        );
        match std::env::var("POSTHOG_PROJECT_API_KEY") {
            Ok(key) if !key.is_empty() => {
                let host = std::env::var("POSTHOG_HOST")
                    .unwrap_or_else(|_| "https://app.posthog.com".to_string());
                tracing::info!(%host, "kill-switch: PostHog flag refresh enabled (30s)");
                // Detached by design: the gateway does not join this task.
                let _refresh = ks.spawn_refresh(key, host);
            }
            _ => {
                tracing::info!(
                    "kill-switch: POSTHOG_PROJECT_API_KEY unset — all flags serve safe defaults"
                );
            }
        }
        ks
    }

    /// Build a snapshot from `TRACELANE_KILLSWITCH_FLAGS` — a comma-separated
    /// list of flag keys to force ON.
    ///
    /// Every listed key is set to `true`; anything absent keeps its call-site
    /// default. **Listing is the only thing this can do**: it cannot force a
    /// flag OFF, because `false` is already every flag's fail-safe default and a
    /// syntax for "off" would only create a way to spell the safe state wrongly.
    ///
    /// Unknown keys are kept, not rejected: `flag()` is a plain map lookup, so a
    /// typo simply never matches a call site. Rejecting would mean this function
    /// owning a list of every valid key — a second registry to drift.
    pub fn from_flag_list(raw: &str) -> Self {
        let flags: HashMap<String, bool> = raw
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(|k| (k.to_string(), true))
            .collect();
        if !flags.is_empty() {
            // A state TRANSITION at startup, not a per-request line: this is
            // exactly what INFO is for (.claude/rules/logging.md). Operators
            // must be able to see which switches a process booted with — a kill
            // switch nobody can confirm is armed is not a control.
            let mut keys: Vec<&str> = flags.keys().map(String::as_str).collect();
            keys.sort_unstable();
            tracing::info!(flags = %keys.join(","), "kill-switch: flags forced ON via TRACELANE_KILLSWITCH_FLAGS");
        }
        Self {
            flags: Arc::new(ArcSwap::from_pointee(flags)),
        }
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
    /// No V1 call site until a gateway-config canary is staged
    /// (ADR-038 §23.5), hence `dead_code`; exercised by this module's tests.
    #[allow(dead_code)]
    pub fn canary_enabled(&self, feature: &str) -> bool {
        self.flag(&format!("flag.canary.{feature}"), false)
    }

    /// Spawn the background refresh task. On any error it keeps the last good
    /// snapshot (or the empty default snapshot) — never clears to an unsafe state.
    ///
    /// **Returns the `JoinHandle`**. It used to return ``, and that was the
    /// defect: deleting the `refresh_target` call below — the SSRF gate's only
    /// invocation — compiled clean and turned NO test red, because a detached
    /// `tokio::spawn` with no observable result cannot be asserted on. The gate's
    /// LOGIC was falsification-proven; its INVOCATION was covered by review only, and
    /// review is not a guard. With the handle returned, a test can observe the one
    /// externally visible consequence of the gate firing: on a refused host the task
    /// ENDS instead of entering the refresh loop.
    fn spawn_refresh(&self, api_key: String, host: String) -> tokio::task::JoinHandle<()> {
        let flags = self.flags.clone();
        tokio::spawn(async move {
            // `POSTHOG_HOST` is operator-supplied, and `ssrf_guard`'s module
            // contract requires `validate_url` before ANY outbound request to
            // an operator- OR customer-supplied URL. The previous "operator
            // hosts are exempt" reasoning was the bypass: an env var is not a
            // trust boundary, and this task loops forever, so one bad host is
            // an indefinite SSRF beacon against the node's own network.
            //
            // ONE call builds the client AND clears the gate, so the gate
            // cannot be dropped from this call site without a test noticing
            // (a guard whose INVOCATION is untested is not a guard).
            let Some((client, url)) = refresh_target(&host).await else {
                return;
            };
            loop {
                match fetch_flags(&client, &url, &api_key).await {
                    Ok(snapshot) => flags.store(Arc::new(snapshot)),
                    Err(e) => {
                        tracing::warn!(error = %e, "kill-switch: PostHog refresh failed; keeping last snapshot")
                    }
                }
                tokio::time::sleep(REFRESH_INTERVAL).await;
            }
        })
    }
}

/// Build the PostHog `/decide` URL from an operator-supplied host.
fn decide_url(host: &str) -> String {
    format!("{}/decide/?v=3", host.trim_end_matches('/'))
}

/// Build the refresh client and clear the SSRF gate, or refuse.
///
/// Factored out of [`KillSwitch::spawn_refresh`] so it is unit-testable
/// without spawning a task or hitting the network — the same pattern as
/// `validate_slack_webhook` in `server.rs`. Client construction and the SSRF
/// gate are deliberately in ONE function so that a test of this function
/// covers the gate's INVOCATION, not merely its logic.
///
/// Returns `None` (and logs at `error`) when the URL is rejected. The caller
/// MUST NOT start the refresh loop on `None`: every `kill.*` flag then serves
/// its documented safe default, which is exactly the no-PostHog behaviour of
/// [`KillSwitch::disabled`]. Fail-safe, not fail-open.
async fn refresh_target(host: &str) -> Option<(reqwest::Client, String)> {
    let client = match crate::ssrf_guard::safe_client_builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "kill-switch: client build failed; defaults only");
            return None;
        }
    };

    let url = decide_url(host);
    if let Err(e) = crate::ssrf_guard::validate_url(&url).await {
        tracing::error!(
            error = %e,
            "kill-switch: POSTHOG_HOST rejected by the SSRF guard — refresh task NOT started; \
             all kill.* flags serve safe defaults. Fix POSTHOG_HOST."
        );
        return None;
    }
    Some((client, url))
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
    // ── GWY-40: the env flag source ──────────────────────────────────────────

    /// The point of the whole change: a listed key must reach the CALL-SITE
    /// predicates, not merely land in a map. Before GWY-40 these could not be
    /// turned on at all without a PostHog account.
    #[test]
    fn a_listed_flag_reaches_the_call_site_predicates() {
        let ks = KillSwitch::from_flag_list("kill.upstream.anthropic,kill.predictive.foo");
        assert!(
            ks.upstream_killed("anthropic"),
            "the switch must actually fire"
        );
        assert!(ks.predictive_killed("foo"));
        // And a neighbour must NOT be caught by it.
        assert!(
            !ks.upstream_killed("openai"),
            "only the listed provider is killed"
        );
        assert!(!ks.predictive_killed("bar"));
    }

    /// Empty / absent env keeps every flag at its fail-safe default. This is the
    /// state every deployment is in today, and it must stay harmless.
    #[test]
    fn empty_flag_list_leaves_every_switch_off() {
        for raw in ["", "   ", ",", " , , "] {
            let ks = KillSwitch::from_flag_list(raw);
            assert!(!ks.upstream_killed("anthropic"), "{raw:?} must arm nothing");
            assert!(!ks.predictive_killed("x"));
            assert!(!ks.flag("kill.audit.async", false));
        }
    }

    /// Whitespace around keys is tolerated — an operator editing a compose file
    /// will write `a, b`, and a switch that silently fails on a space is the
    /// same defect as no switch.
    #[test]
    fn whitespace_between_keys_is_tolerated() {
        let ks = KillSwitch::from_flag_list("  kill.upstream.anthropic ,  kill.audit.async  ");
        assert!(ks.upstream_killed("anthropic"));
        assert!(ks.flag("kill.audit.async", false));
    }

    /// An unknown key is kept rather than rejected: `flag()` is a map lookup, so
    /// a typo simply never matches a call site. Rejecting would mean this
    /// function owning a list of every valid key — a second registry to drift.
    #[test]
    fn an_unknown_key_is_inert_not_an_error() {
        let ks = KillSwitch::from_flag_list("kill.upstream.anthropic,kil.typo.here");
        assert!(ks.upstream_killed("anthropic"), "the valid key still works");
        assert!(!ks.upstream_killed("typo"));
    }

    /// The list can only force ON. There is deliberately no syntax for OFF,
    /// because OFF is already every flag's default and a spelling for it would
    /// only create a way to get the safe state wrong.
    #[test]
    fn the_list_cannot_force_a_flag_off() {
        let ks = KillSwitch::from_flag_list("kill.upstream.anthropic");
        // `default` still governs anything unlisted, in both directions.
        assert!(
            ks.flag("something.unlisted", true),
            "unlisted keeps its default"
        );
        assert!(!ks.flag("other.unlisted", false));
    }

    use super::*;

    // -----------------------------------------------------------------
    // SSRF regression (PART-1 #1): `spawn_refresh` used to build a bare
    // `reqwest::Client::builder()` and never call `validate_url`, on the
    // reasoning that POSTHOG_HOST is "operator-supplied". An env var is not
    // a trust boundary, and this task loops forever — one bad host is an
    // indefinite SSRF beacon. These tests fail if the gate is removed.
    // -----------------------------------------------------------------

    #[test]
    fn decide_url_trims_trailing_slash() {
        assert_eq!(
            decide_url("https://eu.i.posthog.com"),
            "https://eu.i.posthog.com/decide/?v=3"
        );
        assert_eq!(
            decide_url("https://eu.i.posthog.com/"),
            "https://eu.i.posthog.com/decide/?v=3"
        );
    }

    /// . The gate's LOGIC is covered by the `refresh_target_rejects_*` tests
    /// below. Its INVOCATION was not: `spawn_refresh` fired a detached task with
    /// no observable result, so deleting the `refresh_target` call — the only
    /// thing standing between an operator-supplied `POSTHOG_HOST` and an
    /// indefinite SSRF beacon — compiled clean and turned nothing red.
    ///
    /// The externally visible consequence of the gate firing is that the task
    /// ENDS rather than entering the forever-loop. Now that the handle is
    /// returned, that is assertable.
    #[tokio::test]
    async fn a_refused_host_ends_the_refresh_task_instead_of_looping() {
        let ks = KillSwitch::disabled();
        // Cloud metadata — refused by the SSRF gate before any request is made,
        // so this test performs no network I/O.
        let handle = ks.spawn_refresh("k".into(), "http://169.254.169.254".into());

        let ended = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(
            ended.is_ok(),
            "the refresh task must END when the host is refused. If it is still \
             running, the SSRF gate is not being CALLED — which compiles clean \
             and every logic test still passes"
        );
        assert!(
            ended.is_ok_and(|r| r.is_ok()),
            "the task must end cleanly, not panic"
        );
    }

    /// The other direction, so the test above cannot pass by the task always
    /// ending. A permitted host must produce a target — i.e. the gate admits as
    /// well as refuses. IP literal, so no DNS and no network request.
    #[tokio::test]
    async fn a_permitted_host_yields_a_refresh_target() {
        assert!(
            refresh_target("https://1.1.1.1").await.is_some(),
            "a public address must be ADMITTED — a gate that refuses everything \
             would make the assertion above pass while PostHog never works"
        );
    }

    #[tokio::test]
    async fn refresh_target_rejects_cloud_metadata() {
        // 169.254.169.254 — AWS/GCP IMDS. The canonical SSRF target.
        assert!(refresh_target("http://169.254.169.254").await.is_none());
    }

    #[tokio::test]
    async fn refresh_target_rejects_rfc1918() {
        assert!(refresh_target("http://10.0.0.5").await.is_none());
        assert!(refresh_target("http://192.168.1.1").await.is_none());
    }

    #[tokio::test]
    async fn refresh_target_rejects_non_http_scheme() {
        assert!(refresh_target("file:///etc/passwd").await.is_none());
        assert!(refresh_target("gopher://169.254.169.254").await.is_none());
    }

    #[tokio::test]
    async fn refresh_target_allows_public_address() {
        // Public IP literal — no DNS needed, so this is hermetic. Proves the
        // gate is discriminating rather than refusing everything (without
        // which every assertion above would pass vacuously).
        let t = refresh_target("https://8.8.8.8").await;
        assert!(t.is_some());
        assert_eq!(t.unwrap().1, "https://8.8.8.8/decide/?v=3");
    }

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
