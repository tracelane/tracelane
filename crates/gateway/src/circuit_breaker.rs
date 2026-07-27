//!
//! 35+ providers are 35+ independent failure domains. Without a breaker, one
//! hung or erroring upstream (regional outage, 429 storm) ties up gateway
//! worker slots and degrades *all* tenants — a common-mode failure across
//! unrelated traffic. This breaker bulkheads each `(provider, region)` so one
//! upstream's failure cannot exhaust the gateway.
//!
//! ## Why in-dispatch, not a Tower layer
//!
//! ADR-036 describes "a Tower layer wrapping every provider adapter". The
//! adapters are not `tower::Service`s — they are dispatched by a `match` in
//! `server::dispatch_to_provider`. Rather than refactor all 35 adapters into
//! Services purely to satisfy the wording, the breaker is an in-process state
//! map checked/recorded around the existing dispatch. The semantics (Closed →
//! Open → Half-Open) are identical; the integration is smaller and lower-risk.
//!
//! ## States (per `(provider, region)`)
//!
//! - **Closed** — pass traffic. Trip to **Open** on ≥50% failure over a
//!   20-request rolling window, or 5 consecutive 5xx/timeout.
//! - **Open** — reject immediately (the gateway returns 503 + `Retry-After` +
//!   `tracelane.upstream.circuit=open`, or fails over if the request asked for
//!   it). After a 10s cool-down, transition to **Half-Open**.
//! - **Half-Open** — allow up to 3 probes. A probe failure re-opens; 3 probe
//!   successes close.
//!
//! Trip input is the failure classification surfaced as the
//! `gen_ai.client.operation.exception` event (ADR-032): timeouts, 429s, 5xx.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

/// Tuning for a breaker. Conservative defaults; per-provider overridable later.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Rolling-window size for the failure-rate check.
    pub window_size: usize,
    /// Failure rate (0.0–1.0) over a full window that trips Closed → Open.
    pub failure_rate_threshold: f64,
    /// Consecutive 5xx/timeout that trips Closed → Open regardless of rate.
    pub consecutive_failure_threshold: u32,
    /// How long to stay Open before allowing Half-Open probes.
    pub cooldown: Duration,
    /// Probes allowed in Half-Open; this many consecutive successes closes.
    pub half_open_max_probes: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            window_size: 20,
            failure_rate_threshold: 0.5,
            consecutive_failure_threshold: 5,
            cooldown: Duration::from_secs(10),
            half_open_max_probes: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

impl State {
    /// Stable wire/UI string for the breaker state (the /gateway "Circuit"
    /// column + the `tracelane.upstream.circuit` span attribute).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Closed => "closed",
            State::Open => "open",
            State::HalfOpen => "half_open",
        }
    }

    /// Severity rank for collapsing several regions of one provider to a single
    /// dashboard state: the WORST wins (Open > HalfOpen > Closed) so a partially
    /// tripped provider never shows as healthy.
    pub fn severity(&self) -> u8 {
        match self {
            State::Closed => 0,
            State::HalfOpen => 1,
            State::Open => 2,
        }
    }
}

#[derive(Debug)]
struct BreakerState {
    state: State,
    /// Last `window_size` outcomes; `true` = success.
    window: VecDeque<bool>,
    consecutive_failures: u32,
    opened_at: Option<Instant>,
    /// Probes dispatched in the current Half-Open period.
    half_open_probes: u32,
    /// Probe successes in the current Half-Open period.
    half_open_successes: u32,
}

impl BreakerState {
    fn new() -> Self {
        Self {
            state: State::Closed,
            window: VecDeque::new(),
            consecutive_failures: 0,
            opened_at: None,
            half_open_probes: 0,
            half_open_successes: 0,
        }
    }

    fn failure_rate(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let failures = self.window.iter().filter(|ok| !**ok).count();
        failures as f64 / self.window.len() as f64
    }
}

// ── Metrics (atomic-counter house style) ────────────────────────────────────
static TRIP_TOTAL: AtomicU64 = AtomicU64::new(0);
static REJECT_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Snapshot for the `tracelane_circuit_breaker_*` metrics scrape.
pub fn metrics_snapshot() -> (u64, u64) {
    (
        TRIP_TOTAL.load(Ordering::Relaxed),
        REJECT_TOTAL.load(Ordering::Relaxed),
    )
}

/// Process-wide read handle to the live breaker, registered once at server start
/// (mirrors `rejection_metrics::registry()`). Lets the /gateway stats handler read
/// a breaker snapshot without threading `Arc<CircuitBreaker>` through every read
/// state. Unregistered (e.g. unit tests) → an empty snapshot.
static BREAKER_REGISTRY: OnceLock<Arc<CircuitBreaker>> = OnceLock::new();

/// Register the process breaker for the read surfaces. Idempotent (first wins).
pub fn register_global(cb: Arc<CircuitBreaker>) {
    let _ = BREAKER_REGISTRY.set(cb);
}

/// Snapshot every live breaker `(provider, region, state)` via the global handle;
/// empty when none is registered.
#[must_use]
pub fn global_snapshot() -> Vec<(String, String, State)> {
    BREAKER_REGISTRY
        .get()
        .map(|cb| cb.snapshot())
        .unwrap_or_default()
}

/// Per-`(provider, region)` circuit breakers. Cheap to share via `Arc`.
pub struct CircuitBreaker {
    breakers: DashMap<(String, String), Mutex<BreakerState>>,
    config: BreakerConfig,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(BreakerConfig::default())
    }
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            breakers: DashMap::new(),
            config,
        }
    }

    fn entry(
        &self,
        provider: &str,
        region: &str,
    ) -> dashmap::mapref::one::Ref<'_, (String, String), Mutex<BreakerState>> {
        let key = (provider.to_string(), region.to_string());
        // Get-or-create, then downgrade RefMut→Ref in one atomic step — no
        // separate `get()` that the type system forces an `.expect()` on
        // (banned on the hot path per CLAUDE.md).
        self.breakers
            .entry(key)
            .or_insert_with(|| Mutex::new(BreakerState::new()))
            .downgrade()
    }

    /// May a request to `(provider, region)` proceed right now? Also drives the
    /// Open → Half-Open transition once the cool-down elapses.
    pub fn allow(&self, provider: &str, region: &str) -> bool {
        let cell = self.entry(provider, region);
        let mut s = cell.lock();
        match s.state {
            State::Closed => true,
            State::HalfOpen => {
                if s.half_open_probes < self.config.half_open_max_probes {
                    s.half_open_probes += 1;
                    true
                } else {
                    // Probe budget spent; wait for results before more traffic.
                    false
                }
            }
            State::Open => {
                let elapsed = s
                    .opened_at
                    .map(|t| t.elapsed())
                    .unwrap_or(self.config.cooldown);
                if elapsed >= self.config.cooldown {
                    // Cool-down elapsed → enter Half-Open and allow the first probe.
                    s.state = State::HalfOpen;
                    s.half_open_probes = 1;
                    s.half_open_successes = 0;
                    true
                } else {
                    REJECT_TOTAL.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        }
    }

    /// Record the outcome of a dispatched request. `success = false` for any
    /// timeout / 429 / 5xx (the `gen_ai.client.operation.exception` classes).
    pub fn record(&self, provider: &str, region: &str, success: bool) {
        let cell = self.entry(provider, region);
        let mut s = cell.lock();

        // Maintain the rolling window.
        s.window.push_back(success);
        while s.window.len() > self.config.window_size {
            s.window.pop_front();
        }
        if success {
            s.consecutive_failures = 0;
        } else {
            s.consecutive_failures += 1;
        }

        match s.state {
            State::HalfOpen => {
                if success {
                    s.half_open_successes += 1;
                    if s.half_open_successes >= self.config.half_open_max_probes {
                        // Recovered.
                        s.state = State::Closed;
                        s.window.clear();
                        s.consecutive_failures = 0;
                        s.half_open_probes = 0;
                        s.half_open_successes = 0;
                    }
                } else {
                    // A probe failed — back to Open for another cool-down.
                    s.state = State::Open;
                    s.opened_at = Some(Instant::now());
                    s.half_open_probes = 0;
                    s.half_open_successes = 0;
                    TRIP_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
            }
            State::Closed => {
                let window_full = s.window.len() >= self.config.window_size;
                let trip = s.consecutive_failures >= self.config.consecutive_failure_threshold
                    || (window_full && s.failure_rate() >= self.config.failure_rate_threshold);
                if trip {
                    s.state = State::Open;
                    s.opened_at = Some(Instant::now());
                    TRIP_TOTAL.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        provider,
                        region,
                        consecutive = s.consecutive_failures,
                        "circuit breaker tripped Open"
                    );
                }
            }
            State::Open => {
                // Outcome recorded while Open (a race with allow()); ignore for
                // state purposes — the cool-down timer governs the transition.
            }
        }
    }

    /// Current state — for tests and the `tracelane.upstream.circuit` attribute.
    pub fn state(&self, provider: &str, region: &str) -> State {
        self.entry(provider, region).lock().state
    }

    /// Current state of every LIVE breaker as `(provider, region, state)`, for the
    /// /gateway router-health surface. Read-only — never creates an entry (a
    /// provider with no breaker recorded is healthy/Closed by definition).
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, String, State)> {
        self.breakers
            .iter()
            .map(|e| {
                let (provider, region) = e.key();
                (provider.clone(), region.clone(), e.value().lock().state)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_cooldown() -> CircuitBreaker {
        CircuitBreaker::new(BreakerConfig {
            cooldown: Duration::from_millis(20),
            ..Default::default()
        })
    }

    #[test]
    fn trips_open_after_consecutive_failures() {
        let cb = CircuitBreaker::default();
        assert!(cb.allow("openai", "default"));
        for _ in 0..5 {
            cb.record("openai", "default", false);
        }
        assert_eq!(cb.state("openai", "default"), State::Open);
        assert!(!cb.allow("openai", "default"), "Open breaker must reject");
    }

    #[test]
    fn snapshot_reports_live_states_and_omits_untouched_providers() {
        let cb = CircuitBreaker::default();
        cb.allow("openai", "default"); // touches → Closed entry
        for _ in 0..5 {
            cb.record("anthropic", "default", false); // trips Open
        }
        let snap = cb.snapshot();
        let get = |p: &str| snap.iter().find(|(pr, _, _)| pr == p).map(|(_, _, s)| *s);
        assert_eq!(get("openai"), Some(State::Closed));
        assert_eq!(get("anthropic"), Some(State::Open));
        assert_eq!(
            get("cohere"),
            None,
            "untouched provider has no breaker entry"
        );
    }

    #[test]
    fn state_as_str_maps_every_variant() {
        assert_eq!(State::Closed.as_str(), "closed");
        assert_eq!(State::Open.as_str(), "open");
        assert_eq!(State::HalfOpen.as_str(), "half_open");
    }

    #[test]
    fn severity_orders_worst_wins() {
        // The per-provider region collapse keeps the highest severity.
        assert!(State::Open.severity() > State::HalfOpen.severity());
        assert!(State::HalfOpen.severity() > State::Closed.severity());
    }

    #[test]
    fn trips_open_on_failure_rate_over_full_window() {
        let cb = CircuitBreaker::default();
        // 20-request window, alternate so consecutive never hits 5 but rate = 50%.
        for i in 0..20 {
            cb.record("google", "default", i % 2 == 0);
        }
        assert_eq!(cb.state("google", "default"), State::Open);
    }

    #[test]
    fn other_providers_unaffected_bulkhead() {
        let cb = CircuitBreaker::default();
        for _ in 0..5 {
            cb.record("openai", "default", false);
        }
        assert_eq!(cb.state("openai", "default"), State::Open);
        // Anthropic is a separate failure domain — still closed and serving.
        assert_eq!(cb.state("anthropic", "default"), State::Closed);
        assert!(cb.allow("anthropic", "default"));
    }

    #[test]
    fn recovers_through_half_open_after_cooldown() {
        let cb = fast_cooldown();
        for _ in 0..5 {
            cb.record("cohere", "default", false);
        }
        assert_eq!(cb.state("cohere", "default"), State::Open);
        // During cool-down: rejected.
        assert!(!cb.allow("cohere", "default"));
        std::thread::sleep(Duration::from_millis(25));
        // Cool-down elapsed → first probe allowed, state Half-Open.
        assert!(cb.allow("cohere", "default"));
        assert_eq!(cb.state("cohere", "default"), State::HalfOpen);
        // Three probe successes close the breaker.
        cb.record("cohere", "default", true);
        cb.record("cohere", "default", true);
        cb.record("cohere", "default", true);
        assert_eq!(cb.state("cohere", "default"), State::Closed);
    }

    #[test]
    fn half_open_probe_failure_reopens() {
        let cb = fast_cooldown();
        for _ in 0..5 {
            cb.record("xai", "default", false);
        }
        std::thread::sleep(Duration::from_millis(25));
        assert!(cb.allow("xai", "default")); // half-open probe
        cb.record("xai", "default", false); // probe fails
        assert_eq!(cb.state("xai", "default"), State::Open);
    }
}
