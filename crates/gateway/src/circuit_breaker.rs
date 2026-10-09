//! Per-upstream, PER-CREDENTIAL circuit breakers (ADR-036, TRD §23.2; `OG-13` slice a).
//!
//! The gateway routes 205 providers, and each one is an independent failure
//! domain. Without a breaker, one hung or erroring upstream (regional outage,
//! 5xx storm) ties up gateway worker slots and degrades *all* tenants — a
//! common-mode failure across unrelated traffic.
//!
//! ## Two tiers (`OG-13` §2 slice a)
//!
//! Until `OG-13` there was ONE breaker per `(provider, region)` and every wire passed the
//! literal `"default"` region, so the breaker was shared by every tenant: one tenant's
//! dead key or poison request opened the circuit for everybody on that provider (the
//! 2026-10-03 incident, ADR-036 F4 — 429 was removed as a trip input then; this closes
//! the same class for 5xx and timeouts).
//!
//! - **Credential tier** — the state machine below, keyed by
//!   `(provider, region, credential)`. It sees every outcome for its credential and is
//!   the only thing `record` feeds. A credential is [`Credential::Env`] (the operator's
//!   environment key: self-host, no control plane) or [`Credential::Byok`] (a
//!   fingerprint of `(tenant, provider, key label)` — never the raw tenant id).
//! - **Provider-wide tier** — DERIVED, never fed: a `(provider, region)` is Open iff at
//!   least `provider_min_open_credentials` distinct OWNERS (tenants) have a credential
//!   that tripped on SHARED evidence (inside its cool-down). Multiple labels of one owner
//!   supply only one vote. It sheds every tenant. With no control plane the lone
//!   credential is `Env`, whose own breaker sheds exactly as the old shared breaker did.
//!
//! ## Only shared evidence opens the provider tier (S1, security review 2026-10-05)
//!
//! A workspace controls two inputs to its OWN credential breaker: the breaker tuning
//! (`PUT /v1/routing` `breaker`, threshold down to 1, cool-down up to 300 s) and the
//! per-route deadlines (`timeouts`), whose timeouts count as failures. Either lets a
//! workspace force its credential Open at will — and before S1, three free workspaces
//! doing so opened the provider-wide tier and answered 503 to every tenant. So an outcome
//! observed under a workspace override ([`Cred::isolated`]) affects ONLY that
//! credential: a credential trips onto the provider tier only when every failure that
//! tripped it was observed under DEFAULT tuning and DEFAULT deadlines (a real upstream
//! 5xx / transport error / adapter-ceiling timeout). The environment credential, which
//! every caller shares, is never fed an isolated failure at all.
//!
//! `allow` = provider-wide allows AND the credential allows. So one tenant, however many
//! bad requests or dead keys it has, cannot shed another tenant.
//!
//! ## Why in-dispatch, not a Tower layer
//!
//! ADR-036 describes "a Tower layer wrapping every provider adapter". The
//! adapters are not `tower::Service`s — they are dispatched by a `match` in
//! `server::dispatch_to_provider`. The breaker is an in-process state map
//! checked/recorded around the existing dispatch. The semantics (Closed →
//! Open → Half-Open) are identical; the integration is smaller and lower-risk.
//!
//! ## States (per credential)
//!
//! - **Closed** — pass traffic. Trip to **Open** on ≥ `failure_rate_threshold` over a
//!   `window_size` rolling window, or `consecutive_failure_threshold` consecutive
//!   5xx/timeouts.
//! - **Open** — reject immediately (503 + `Retry-After`). After `cooldown`,
//!   transition to **Half-Open**.
//! - **Half-Open** — allow up to `half_open_max_probes` probes. A probe failure
//!   re-opens; that many probe successes close. A probe whose outcome never arrives (a
//!   cache hit after `allow`, a client hang-up) is treated as LOST after `probe_lost`
//!   (the 300 s adapter ceiling), so the breaker can never wedge in Half-Open with its
//!   probe budget spent — the old breaker could, forever.
//!
//! Trip input is timeouts and 5xx only (`ProviderHttpError::is_upstream_fault`). 429 was
//! a trip input until 2026-10-03 (F4, ADR-036 amendment).
//!
//! ## Bounded (`breaker.max_entries`)
//!
//! Idle Closed entries are evicted after `idle_evict_secs`; an Open entry only once its
//! cool-down has passed AND it has been idle that long; a Half-Open entry once its probes
//! have been idle that long (they are lost). At capacity a NEW credential is admitted and
//! counted (`capacity_admitted`) — a breaker is a fault-tolerance path and fails OPEN
//! (CLAUDE.md §10).
//!
//! All tunables come from the `breaker` block of `translation_policy.v1.json`
//! (CLAUDE.md §23) — [`BreakerConfig::from_policy`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

/// Tuning for the breakers. Read from the `breaker` reference table.
#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// Distinct owners (tenants) with a credential Open on SHARED evidence (S1) for one
    /// `(provider, region)` that open the provider-wide tier. The reference key retains
    /// its original name. Always ≥ 1.
    pub provider_min_open_credentials: usize,
    /// Most credential breakers held at once.
    pub max_entries: usize,
    /// An idle Closed entry is evicted after this long.
    pub idle_evict: Duration,
    /// A Half-Open probe outstanding this long is LOST (its outcome will never arrive)
    /// and a fresh probe is granted.
    pub probe_lost: Duration,
}

/// The documented values of the `breaker` block, used only when the embedded table does
/// not parse (a unit test makes that a red build, not a runtime surprise). They equal
/// the table, so a broken edit degrades to the shipped behaviour, never to "no breaker".
const FALLBACK: BreakerConfig = BreakerConfig {
    window_size: 20,
    failure_rate_threshold: 0.5,
    consecutive_failure_threshold: 5,
    cooldown: Duration::from_secs(10),
    half_open_max_probes: 3,
    provider_min_open_credentials: 3,
    max_entries: 100_000,
    idle_evict: Duration::from_secs(3_600),
    probe_lost: Duration::from_secs(300),
};

fn parse_table(raw: &str) -> Option<BreakerConfig> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let b = v.get("breaker")?;
    let n = |k: &str| {
        b.get(k)
            .and_then(serde_json::Value::as_u64)
            .filter(|n| *n >= 1)
    };
    let rate = b
        .get("failure_rate_threshold")
        .and_then(serde_json::Value::as_f64)
        .filter(|r| *r > 0.0 && *r <= 1.0)?;
    Some(BreakerConfig {
        window_size: usize::try_from(n("window_size")?).ok()?,
        failure_rate_threshold: rate,
        consecutive_failure_threshold: u32::try_from(n("consecutive_failure_threshold")?).ok()?,
        cooldown: Duration::from_secs(n("cooldown_secs")?),
        half_open_max_probes: u32::try_from(n("half_open_max_probes")?).ok()?,
        provider_min_open_credentials: usize::try_from(n("provider_min_open_credentials")?).ok()?,
        max_entries: usize::try_from(n("max_entries")?).ok()?,
        idle_evict: Duration::from_secs(n("idle_evict_secs")?),
        probe_lost: Duration::from_secs(n("probe_lost_secs")?),
    })
}

impl BreakerConfig {
    /// The `breaker` block of the embedded `translation_policy.v1.json`, parsed once.
    #[must_use]
    pub fn from_policy() -> Self {
        static C: OnceLock<BreakerConfig> = OnceLock::new();
        *C.get_or_init(|| {
            parse_table(include_str!("../translation_policy.v1.json")).unwrap_or_else(|| {
                tracing::warn!(
                    "translation_policy.v1.json breaker block did not parse — using the documented defaults"
                );
                FALLBACK
            })
        })
    }
}

impl Default for BreakerConfig {
    /// The reference table — never a second copy of its numbers.
    fn default() -> Self {
        Self::from_policy()
    }
}

/// The credential a dispatch is made with — the breaker's third key dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Credential {
    /// The operator's environment key (self-host with no control plane, or a debug
    /// build with no BYOK master key): one credential shared by every caller.
    Env,
    /// A tenant's BYOK key: the first 8 bytes (16 hex) of
    /// `blake3("breaker-credential:" | tenant | "|" | provider | "|" | label)`. Stable
    /// per `(tenant, provider, key label)`, not reversible, and never the tenant id.
    Byok([u8; 8]),
}

impl Credential {
    /// The fingerprint of one tenant's key `label` for `provider_id`.
    #[must_use]
    pub fn byok(tenant: &uuid::Uuid, provider_id: &str, label: &str) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"breaker-credential:");
        h.update(tenant.to_string().as_bytes());
        h.update(b"|");
        h.update(provider_id.as_bytes());
        h.update(b"|");
        h.update(label.as_bytes());
        let digest = h.finalize();
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&digest.as_bytes()[..8]);
        Self::Byok(fp)
    }

    /// The 16-hex fingerprint, `None` for the environment credential. Test-only today:
    /// the read surface shows the key LABEL, never a fingerprint.
    #[cfg(test)]
    #[must_use]
    pub fn fingerprint(&self) -> Option<String> {
        match self {
            Self::Env => None,
            Self::Byok(fp) => Some(hex::encode(fp)),
        }
    }
}

/// Which tenant a credential breaker belongs to, for the per-tenant read surface
/// (`GET /v1/gateway/breakers`): `blake3("breaker-owner:" | tenant)`, 16 bytes. Held in
/// memory only; never logged, never in a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnerTag([u8; 16]);

impl OwnerTag {
    #[must_use]
    pub fn of(tenant: &uuid::Uuid) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"breaker-owner:");
        h.update(tenant.to_string().as_bytes());
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&h.finalize().as_bytes()[..16]);
        Self(tag)
    }
}

/// `OG-13` slice b: a workspace's own override of ITS credential breakers (never the
/// provider-wide tier). Already clamped to the table's bounds by the routing document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    pub consecutive_failure_threshold: u32,
    pub cooldown: Duration,
}

type ObservedEntry = Option<(Key, std::sync::Weak<Mutex<Entry>>)>;

/// What a call site hands the breaker: the credential, who owns it, and any override.
#[derive(Debug, Clone)]
pub struct Cred {
    pub id: Credential,
    /// `(owner, key label)` for a BYOK credential; `None` for the environment key.
    pub owner: Option<(OwnerTag, Arc<str>)>,
    pub tuning: Option<Tuning>,
    /// The outcome is observed under a workspace-set DEADLINE (`timeouts`), so a timeout
    /// may be the workspace's own bound rather than the provider's health (S1).
    pub deadline_scoped: bool,
    observed: Arc<Mutex<ObservedEntry>>,
}

impl Cred {
    /// The operator's environment key.
    #[must_use]
    pub fn env() -> Self {
        Self {
            id: Credential::Env,
            owner: None,
            tuning: None,
            deadline_scoped: false,
            observed: Arc::default(),
        }
    }

    /// One tenant's BYOK key `label` for `provider_id`.
    #[must_use]
    pub fn byok(tenant: &uuid::Uuid, provider_id: &str, label: &str) -> Self {
        Self {
            id: Credential::byok(tenant, provider_id, label),
            owner: Some((OwnerTag::of(tenant), Arc::from(label))),
            tuning: None,
            deadline_scoped: false,
            observed: Arc::default(),
        }
    }

    /// S1: is this outcome observed under a WORKSPACE override (its own breaker tuning
    /// or its own deadline)? Then it is evidence about the workspace's configuration, not
    /// the provider, and it may affect only this credential — never the provider tier.
    #[must_use]
    pub fn isolated(&self) -> bool {
        self.tuning.is_some() || self.deadline_scoped
    }

    /// Attach a workspace override (`OG-13` slice b).
    #[cfg(test)]
    #[must_use]
    pub fn with_tuning(mut self, tuning: Option<Tuning>) -> Self {
        self.tuning = tuning;
        self
    }
}

/// What one dispatch tells the breaker. SB (security re-review round 2, 2026-10-05):
/// a FAILURE must say what kind it is, so a call site cannot feed a tenant-made error
/// to the shared tier by default — the old `bool` counted every non-HTTP error (a
/// poisoned Vertex service account, a key with a control byte) as provider evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    /// PROVEN upstream evidence: a provider 5xx, the adapter-ceiling timeout, or a
    /// transport connect/timeout error (never a builder error). Eligible for the
    /// provider-wide tier when observed under default tuning and deadlines.
    UpstreamFault,
    /// Anything else — derived from the credential or the request the tenant controls
    /// (token exchange, key header build, credential parse, an unclassified error).
    /// Affects ONLY this credential; the shared environment credential ignores it.
    CredentialFault,
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

    /// Severity rank for collapsing several breakers of one provider to a single
    /// dashboard state: the WORST wins (Open > HalfOpen > Closed) so a partially
    /// tripped provider never shows as healthy.
    #[must_use]
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
    /// Parallel to `window`: was that outcome observed under a workspace override (S1)?
    window_isolated: VecDeque<bool>,
    consecutive_failures: u32,
    /// Some failure of the current consecutive streak was observed under a workspace
    /// override (S1) — the streak then is not provider evidence.
    streak_isolated: bool,
    /// The current Open period counts toward the provider-wide tier (S1).
    open_shared: bool,
    opened_at: Option<Instant>,
    /// Probes dispatched in the current Half-Open period.
    half_open_probes: u32,
    /// Probe successes in the current Half-Open period.
    half_open_successes: u32,
    /// When the last probe was granted — a probe outstanding for `probe_lost` is treated
    /// as lost.
    probe_granted_at: Option<Instant>,
}

impl BreakerState {
    fn new() -> Self {
        Self {
            state: State::Closed,
            window: VecDeque::new(),
            window_isolated: VecDeque::new(),
            consecutive_failures: 0,
            streak_isolated: false,
            open_shared: false,
            opened_at: None,
            half_open_probes: 0,
            half_open_successes: 0,
            probe_granted_at: None,
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

#[derive(Debug)]
struct Entry {
    retired: bool,
    st: BreakerState,
    owner: Option<(OwnerTag, Arc<str>)>,
    tuning: Option<Tuning>,
    last_used: Instant,
}

type Key = (String, String, Credential);

// ── Metrics (atomic-counter house style) ────────────────────────────────────
static TRIP_TOTAL: AtomicU64 = AtomicU64::new(0);
static REJECT_TOTAL: AtomicU64 = AtomicU64::new(0);
/// A call admitted (or an outcome dropped) because the breaker map was at
/// `max_entries` — `/health`'s `breaker.capacity_admitted`.
static CAPACITY_ADMITTED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// `(trips, rejects, capacity_admitted)` since process start, for `/health`.
#[must_use]
pub fn counters() -> (u64, u64, u64) {
    (
        TRIP_TOTAL.load(Ordering::Relaxed),
        REJECT_TOTAL.load(Ordering::Relaxed),
        CAPACITY_ADMITTED_TOTAL.load(Ordering::Relaxed),
    )
}

/// Process-wide read handle to the live breaker, registered once at server start
/// (mirrors `rejection_metrics::registry()`). Lets the /gateway stats handler read
/// a breaker snapshot without threading `Arc<CircuitBreaker>` through every read
/// state. Unregistered (e.g. unit tests) → an empty snapshot.
// B-386: stays global — a READ HANDLE only. The breaker itself is owned by
// `AppState::circuit_breaker`; this is registered from it at boot so the
// `/v1/gateway` stats route (a different state type) can snapshot it.
static BREAKER_REGISTRY: OnceLock<Arc<CircuitBreaker>> = OnceLock::new();

/// Register the process breaker for the read surfaces. Idempotent (first wins).
pub fn register_global(cb: Arc<CircuitBreaker>) {
    let _ = BREAKER_REGISTRY.set(cb);
}

/// One tenant's view of the live breakers, collapsed per provider (worst wins): the
/// DERIVED provider-wide state of every provider, plus the tenant's OWN credential
/// breakers (and the environment credential's, which every caller of a no-control-plane
/// gateway shares). Never another tenant's credential. Empty when none is registered.
#[must_use]
pub fn global_view(owner: Option<OwnerTag>, include_env: bool) -> HashMap<String, State> {
    BREAKER_REGISTRY
        .get()
        .map(|cb| cb.tenant_view(owner, include_env))
        .unwrap_or_default()
}

/// One tenant's credential breakers and the provider-wide tier, via the global handle.
#[must_use]
pub fn global_owner_snapshot(owner: Option<OwnerTag>, include_env: bool) -> OwnerSnapshot {
    BREAKER_REGISTRY
        .get()
        .map(|cb| cb.owner_snapshot(owner, include_env))
        .unwrap_or_default()
}

/// Reset one credential's breakers through the global handle (a key upsert/delete).
pub fn global_reset(cred: &Credential) {
    if let Some(cb) = BREAKER_REGISTRY.get() {
        cb.reset_credential(cred);
    }
}

/// One credential breaker as the per-tenant surface shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialView {
    pub provider: String,
    pub region: String,
    /// The key label; `env` for the operator's environment credential.
    pub label: String,
    pub state: State,
}

/// The provider-wide tier of one `(provider, region)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderView {
    pub provider: String,
    pub region: String,
    pub state: State,
    /// Distinct credential breakers of this `(provider, region)` Open right now,
    /// process-wide (a count — never whose).
    pub open_credentials: usize,
    /// Distinct owners supplying those credentials; this drives the provider tier.
    pub open_owners: usize,
}

/// `GET /v1/gateway/breakers`' body, before rendering.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnerSnapshot {
    pub credentials: Vec<CredentialView>,
    pub providers: Vec<ProviderView>,
}

type OpenCredentials = HashMap<Credential, (Option<OwnerTag>, Instant)>;

/// Per-credential circuit breakers plus the derived provider-wide tier. Cheap to share
/// via `Arc`.
pub struct CircuitBreaker {
    breakers: DashMap<Key, Arc<Mutex<Entry>>>,
    /// `(provider, region)` → the credentials of it that are Open, each with the
    /// instant its cool-down ends. The provider-wide tier counts the unexpired ones.
    open: DashMap<(String, String), Mutex<OpenCredentials>>,
    insert_lock: Mutex<()>,
    config: BreakerConfig,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(BreakerConfig::from_policy())
    }
}

impl CircuitBreaker {
    #[must_use]
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            breakers: DashMap::new(),
            open: DashMap::new(),
            insert_lock: Mutex::new(()),
            config: BreakerConfig {
                provider_min_open_credentials: config.provider_min_open_credentials.max(1),
                ..config
            },
        }
    }

    fn consecutive_threshold(&self, tuning: Option<Tuning>) -> u32 {
        tuning.map_or(self.config.consecutive_failure_threshold, |t| {
            t.consecutive_failure_threshold
        })
    }

    fn cooldown(&self, tuning: Option<Tuning>) -> Duration {
        tuning.map_or(self.config.cooldown, |t| t.cooldown)
    }

    /// Distinct credentials of `(provider, region)` Open inside their cool-down. Prunes
    /// expired ones as it reads, so an Open credential nobody calls again stops counting
    /// once its cool-down ends — it can never hold the provider open forever.
    fn provider_open_count(&self, provider: &str, region: &str, now: Instant) -> usize {
        let key = (provider.to_owned(), region.to_owned());
        let Some(cell) = self.open.get(&key) else {
            return 0;
        };
        let mut set = cell.lock();
        set.retain(|_, (_, until)| *until > now);
        // A tenant can hold many labels; it supplies only ONE independent outage
        // observation. Otherwise three bad keys in one workspace shed all tenants.
        set.values()
            .map(|(owner, _)| *owner)
            .collect::<HashSet<_>>()
            .len()
    }

    fn mark_open(&self, provider: &str, region: &str, cred: &Cred, until: Instant) {
        self.open
            .entry((provider.to_owned(), region.to_owned()))
            .or_default()
            .lock()
            .insert(
                cred.id,
                (cred.owner.as_ref().map(|(owner, _)| *owner), until),
            );
    }

    fn unmark_open(&self, provider: &str, region: &str, cred: &Credential) {
        if let Some(cell) = self.open.get(&(provider.to_owned(), region.to_owned())) {
            cell.lock().remove(cred);
        }
    }

    fn evictable(&self, e: &Entry, now: Instant) -> bool {
        let idle = now.saturating_duration_since(e.last_used) >= self.config.idle_evict;
        match e.st.state {
            State::Closed => idle,
            State::Open => {
                idle && e
                    .st
                    .opened_at
                    .is_none_or(|t| now.saturating_duration_since(t) >= self.cooldown(e.tuning))
            }
            State::HalfOpen => idle,
        }
    }

    /// Evict every evictable entry. Called when the map is full and by the periodic
    /// sweep (`server.rs`). Returns how many went.
    pub fn sweep_idle(&self) -> usize {
        let _insert = self.insert_lock.lock();
        self.sweep_idle_locked()
    }

    fn sweep_idle_locked(&self) -> usize {
        let now = Instant::now();
        let before = self.breakers.len();
        let mut gone: Vec<Key> = Vec::new();
        self.breakers.retain(|k, cell| {
            let mut entry = cell.lock();
            let keep = !self.evictable(&entry, now);
            if !keep {
                entry.retired = true;
                gone.push(k.clone());
            }
            keep
        });
        for (p, r, c) in &gone {
            self.unmark_open(p, r, c);
        }
        self.open.retain(|_, cell| {
            let mut open = cell.lock();
            open.retain(|_, (_, until)| *until > now);
            !open.is_empty()
        });
        before.saturating_sub(self.breakers.len())
    }

    /// The entry for `key`, created when absent — unless the map is full of entries
    /// that cannot be evicted, in which case `None` (the caller admits and counts).
    fn entry(&self, key: Key, cred: &Cred) -> Option<Arc<Mutex<Entry>>> {
        if let Some(r) = self.breakers.get(&key) {
            return Some(r.value().clone());
        }
        // Serialize only insertion; warm lookups briefly read their existing shard.
        // A len check alone lets concurrent misses exceed max_entries.
        let _insert = self.insert_lock.lock();
        if let Some(r) = self.breakers.get(&key) {
            return Some(r.value().clone());
        }
        if self.breakers.len() >= self.config.max_entries {
            self.sweep_idle_locked();
            if self.breakers.len() >= self.config.max_entries {
                CAPACITY_ADMITTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        // Get-or-create and clone the owned entry before releasing the shard.
        // Observers can then identify retired entries without retaining a map lock.
        // No separate lookup or unwrap is needed.
        Some(
            self.breakers
                .entry(key)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(Entry {
                        retired: false,
                        st: BreakerState::new(),
                        owner: cred.owner.clone(),
                        tuning: cred.tuning,
                        last_used: Instant::now(),
                    }))
                })
                .value()
                .clone(),
        )
    }

    fn key(provider: &str, region: &str, cred: &Cred) -> Key {
        (provider.to_owned(), region.to_owned(), cred.id)
    }

    /// May a request to `(provider, region)` with `cred` proceed right now? The
    /// provider-wide tier first (a read), then the credential's own breaker, which also
    /// drives its Open → Half-Open transition once the cool-down elapses.
    ///
    /// # Errors
    /// None. Fail-OPEN on capacity (a fault-tolerance path, §10): a credential the full
    /// map cannot hold is admitted and counted.
    pub fn allow(&self, provider: &str, region: &str, cred: &Cred) -> bool {
        let now = Instant::now();
        if self.provider_open_count(provider, region, now)
            >= self.config.provider_min_open_credentials
        {
            REJECT_TOTAL.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let Some(cell) = self.entry(Self::key(provider, region, cred), cred) else {
            return true;
        };
        *cred.observed.lock() = Some((Self::key(provider, region, cred), Arc::downgrade(&cell)));
        let mut e = cell.lock();
        e.last_used = now;
        e.tuning = cred.tuning;
        if e.owner.is_none() {
            e.owner.clone_from(&cred.owner);
        }
        let cooldown = self.cooldown(e.tuning);
        let max_probes = self.config.half_open_max_probes;
        let probe_lost = self.config.probe_lost;
        let s = &mut e.st;
        match s.state {
            State::Closed => true,
            State::HalfOpen => {
                if s.half_open_probes < max_probes {
                    s.half_open_probes += 1;
                    s.probe_granted_at = Some(now);
                    true
                } else if s
                    .probe_granted_at
                    .is_none_or(|t| now.saturating_duration_since(t) >= probe_lost)
                {
                    // Every probe granted `probe_lost` ago and none reported back: they
                    // are LOST (a cache hit after `allow`, a client hang-up). Grant a
                    // fresh probe rather than wedge in Half-Open forever.
                    s.half_open_probes = 1;
                    s.probe_granted_at = Some(now);
                    true
                } else {
                    // Probe budget spent; wait for results before more traffic.
                    false
                }
            }
            State::Open => {
                let elapsed = s
                    .opened_at
                    .map_or(cooldown, |t| now.saturating_duration_since(t));
                if elapsed >= cooldown {
                    // Cool-down elapsed → enter Half-Open and allow the first probe.
                    s.state = State::HalfOpen;
                    s.half_open_probes = 1;
                    s.half_open_successes = 0;
                    s.probe_granted_at = Some(now);
                    drop(e);
                    self.unmark_open(provider, region, &cred.id);
                    true
                } else {
                    REJECT_TOTAL.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        }
    }

    /// Would [`Self::allow`] admit a call right now — WITHOUT consuming a Half-Open probe
    /// or moving any state? Used to choose among targets and pool keys before one is
    /// committed to; the real `allow` is still called at dispatch.
    #[must_use]
    pub fn would_allow(&self, provider: &str, region: &str, cred: &Cred) -> bool {
        let now = Instant::now();
        if self.provider_open_count(provider, region, now)
            >= self.config.provider_min_open_credentials
        {
            return false;
        }
        let Some(cell) = self.breakers.get(&Self::key(provider, region, cred)) else {
            return true;
        };
        let e = cell.lock();
        let cooldown = self.cooldown(cred.tuning);
        match e.st.state {
            State::Closed => true,
            State::HalfOpen => {
                e.st.half_open_probes < self.config.half_open_max_probes
                    || e.st
                        .probe_granted_at
                        .is_none_or(|t| now.saturating_duration_since(t) >= self.config.probe_lost)
            }
            State::Open => {
                e.st.opened_at
                    .is_none_or(|t| now.saturating_duration_since(t) >= cooldown)
            }
        }
    }

    /// Record the outcome of a dispatched request with `cred` — NOT a 429 or any other
    /// 4xx (F4, ADR-036 amendment: the call site records nothing for those). Feeds the
    /// credential tier ONLY; the provider-wide tier is derived from it, and only from
    /// [`Outcome::UpstreamFault`] observed under defaults (S1, SB).
    pub fn record(&self, provider: &str, region: &str, cred: &Cred, outcome: Outcome) {
        let success = outcome == Outcome::Success;
        let isolated = cred.isolated() || outcome == Outcome::CredentialFault;
        // S1/SB: the environment credential is shared by every caller; a failure the
        // workspace's own override or credential produced must not open it for others.
        if isolated && !success && cred.owner.is_none() {
            return;
        }
        let key = Self::key(provider, region, cred);
        let observed = cred.observed.lock().clone();
        let cell = if let Some((_, seen)) = observed.filter(|(seen_key, _)| seen_key == &key) {
            let Some(cell) = seen.upgrade() else { return };
            cell
        } else {
            let Some(cell) = self.entry(key, cred) else {
                return;
            };
            cell
        };
        let now = Instant::now();
        let mut e = cell.lock();
        if e.retired {
            return;
        }
        e.last_used = now;
        e.tuning = cred.tuning;
        let consecutive = self.consecutive_threshold(e.tuning);
        let cooldown = self.cooldown(e.tuning);
        let window_size = self.config.window_size;
        let rate_threshold = self.config.failure_rate_threshold;
        let max_probes = self.config.half_open_max_probes;
        let s = &mut e.st;

        // Maintain the rolling window.
        s.window.push_back(success);
        s.window_isolated.push_back(isolated);
        while s.window.len() > window_size {
            s.window.pop_front();
            s.window_isolated.pop_front();
        }
        if success {
            s.consecutive_failures = 0;
            s.streak_isolated = false;
        } else {
            s.consecutive_failures += 1;
            s.streak_isolated |= isolated;
        }

        let mut opened = false;
        match s.state {
            State::HalfOpen => {
                if success {
                    s.half_open_successes += 1;
                    if s.half_open_successes >= max_probes {
                        // Recovered.
                        s.state = State::Closed;
                        s.window.clear();
                        s.window_isolated.clear();
                        s.consecutive_failures = 0;
                        s.streak_isolated = false;
                        s.open_shared = false;
                        s.half_open_probes = 0;
                        s.half_open_successes = 0;
                        s.probe_granted_at = None;
                    }
                } else {
                    // A probe failed — back to Open for another cool-down. It stays
                    // provider evidence only if the Open period it ends was, and this
                    // probe was observed under defaults (S1).
                    s.open_shared = s.open_shared && !isolated;
                    s.state = State::Open;
                    s.opened_at = Some(now);
                    s.half_open_probes = 0;
                    s.half_open_successes = 0;
                    s.probe_granted_at = None;
                    TRIP_TOTAL.fetch_add(1, Ordering::Relaxed);
                    opened = true;
                }
            }
            State::Closed => {
                let window_full = s.window.len() >= window_size;
                let by_streak = s.consecutive_failures >= consecutive;
                let by_rate = window_full && s.failure_rate() >= rate_threshold;
                if by_streak || by_rate {
                    // S1: provider evidence only when the trip used no outcome observed
                    // under a workspace override, and the credential is on default
                    // tuning now.
                    let window_clean = !s
                        .window
                        .iter()
                        .zip(&s.window_isolated)
                        .any(|(ok, iso)| !*ok && *iso);
                    s.open_shared = !isolated
                        && ((by_streak && !s.streak_isolated) || (by_rate && window_clean));
                    s.state = State::Open;
                    s.opened_at = Some(now);
                    TRIP_TOTAL.fetch_add(1, Ordering::Relaxed);
                    opened = true;
                    // The provider and region only — never the credential or its owner.
                    tracing::warn!(
                        provider,
                        region,
                        consecutive = s.consecutive_failures,
                        "circuit breaker tripped Open for one credential"
                    );
                }
            }
            State::Open => {
                // Outcome recorded while Open (a race with allow()); ignore for
                // state purposes — the cool-down timer governs the transition.
            }
        }
        if opened && e.st.open_shared {
            self.mark_open(provider, region, cred, now + cooldown);
        }
        drop(e);
    }

    /// Reset every breaker of one credential (all regions) — a provider-key upsert or
    /// delete replaced or removed the key the old outcomes were about. Other labels and
    /// other tenants are untouched.
    pub fn reset_credential(&self, cred: &Credential) {
        let _insert = self.insert_lock.lock();
        let mut gone: Vec<Key> = Vec::new();
        self.breakers.retain(|k, cell| {
            let keep = &k.2 != cred;
            if !keep {
                cell.lock().retired = true;
                gone.push(k.clone());
            }
            keep
        });
        for (p, r, c) in &gone {
            self.unmark_open(p, r, c);
        }
    }

    /// The DERIVED provider-wide state of `(provider, region)`.
    fn provider_state(&self, provider: &str, region: &str, now: Instant) -> (State, usize) {
        let n = self.provider_open_count(provider, region, now);
        let state = if n >= self.config.provider_min_open_credentials {
            State::Open
        } else {
            State::Closed
        };
        (state, n)
    }

    fn visible(owner: Option<OwnerTag>, include_env: bool, key: &Key, e: &Entry) -> bool {
        match key.2 {
            Credential::Env => include_env,
            Credential::Byok(_) => owner.is_some() && e.owner.as_ref().map(|o| o.0) == owner,
        }
    }

    /// One tenant's view, collapsed per provider, worst wins (see [`global_view`]).
    #[must_use]
    pub fn tenant_view(
        &self,
        owner: Option<OwnerTag>,
        include_env: bool,
    ) -> HashMap<String, State> {
        let now = Instant::now();
        let mut out: HashMap<String, State> = HashMap::new();
        let mut bump = |provider: &str, state: State| {
            out.entry(provider.to_owned())
                .and_modify(|s| {
                    if state.severity() > s.severity() {
                        *s = state;
                    }
                })
                .or_insert(state);
        };
        let pairs: Vec<(String, String)> = self.open.iter().map(|e| e.key().clone()).collect();
        for (p, r) in pairs {
            let (state, _) = self.provider_state(&p, &r, now);
            if state != State::Closed {
                bump(&p, state);
            }
        }
        for e in &self.breakers {
            let entry = e.value().lock();
            if Self::visible(owner, include_env, e.key(), &entry) {
                bump(&e.key().0, entry.st.state);
            }
        }
        out
    }

    /// One tenant's credential breakers, plus the provider-wide tier of every
    /// `(provider, region)` those credentials touch.
    #[must_use]
    pub fn owner_snapshot(&self, owner: Option<OwnerTag>, include_env: bool) -> OwnerSnapshot {
        let now = Instant::now();
        let mut credentials = Vec::new();
        for e in &self.breakers {
            let entry = e.value().lock();
            if Self::visible(owner, include_env, e.key(), &entry) {
                credentials.push(CredentialView {
                    provider: e.key().0.clone(),
                    region: e.key().1.clone(),
                    label: entry
                        .owner
                        .as_ref()
                        .map_or_else(|| "env".to_owned(), |o| o.1.to_string()),
                    state: entry.st.state,
                });
            }
        }
        credentials.sort_by(|a, b| {
            (&a.provider, &a.region, &a.label).cmp(&(&b.provider, &b.region, &b.label))
        });
        let mut pairs: Vec<(String, String)> = credentials
            .iter()
            .map(|c| (c.provider.clone(), c.region.clone()))
            .collect();
        pairs.dedup();
        let providers = pairs
            .into_iter()
            .map(|(provider, region)| {
                let (state, open_owners) = self.provider_state(&provider, &region, now);
                let open_credentials = self
                    .open
                    .get(&(provider.clone(), region.clone()))
                    .map_or(0, |set| set.lock().len());
                ProviderView {
                    provider,
                    region,
                    state,
                    open_credentials,
                    open_owners,
                }
            })
            .collect();
        OwnerSnapshot {
            credentials,
            providers,
        }
    }

    /// How many credential breakers are held. Test-only.
    #[cfg(test)]
    #[must_use]
    pub fn entries(&self) -> usize {
        self.breakers.len()
    }

    /// Current state of one credential breaker. Test-only.
    #[cfg(test)]
    pub fn state(&self, provider: &str, region: &str, cred: &Credential) -> State {
        self.breakers
            .get(&(provider.to_owned(), region.to_owned(), *cred))
            .map_or(State::Closed, |e| e.lock().st.state)
    }

    /// The outcomes recorded for one credential breaker, oldest first — i.e. how many
    /// times, and with what, the breaker was FED. B-385 (2c): the chaos harness asserts a
    /// 503-then-200 dispatch feeds the breaker ONCE, with the final outcome, rather than
    /// once per attempt. Test-only.
    #[cfg(test)]
    pub fn outcomes(&self, provider: &str, region: &str, cred: &Credential) -> Vec<bool> {
        self.breakers
            .get(&(provider.to_owned(), region.to_owned(), *cred))
            .map(|e| e.lock().st.window.iter().copied().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = "default";

    fn cfg() -> BreakerConfig {
        BreakerConfig::from_policy()
    }

    fn fast_cooldown() -> CircuitBreaker {
        CircuitBreaker::new(BreakerConfig {
            cooldown: Duration::from_millis(20),
            ..cfg()
        })
    }

    fn env() -> Cred {
        Cred::env()
    }

    fn tenant(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    fn byok(n: u128) -> Cred {
        Cred::byok(&tenant(n), "mistral", "default")
    }

    fn outcome(ok: bool) -> Outcome {
        if ok {
            Outcome::Success
        } else {
            Outcome::UpstreamFault
        }
    }

    #[test]
    fn the_breaker_block_of_the_reference_table_parses_and_carries_the_adr_036_values() {
        let c = parse_table(include_str!("../translation_policy.v1.json"))
            .expect("the breaker block parses — a broken edit is a red build");
        assert_eq!(c, FALLBACK, "the fallback must equal the table");
        assert_eq!(c.window_size, 20);
        assert_eq!(c.consecutive_failure_threshold, 5);
        assert_eq!(c.cooldown, Duration::from_secs(10));
        assert_eq!(c.half_open_max_probes, 3);
        assert_eq!(c.provider_min_open_credentials, 3);
        assert!(parse_table(r#"{"breaker":{"window_size":0}}"#).is_none());
    }

    #[test]
    fn trips_open_after_consecutive_failures() {
        let cb = CircuitBreaker::default();
        assert!(cb.allow("openai", R, &env()));
        for _ in 0..5 {
            cb.record("openai", R, &env(), Outcome::UpstreamFault);
        }
        assert_eq!(cb.state("openai", R, &Credential::Env), State::Open);
        assert!(!cb.allow("openai", R, &env()), "Open breaker must reject");
    }

    #[test]
    fn state_as_str_maps_every_variant() {
        assert_eq!(State::Closed.as_str(), "closed");
        assert_eq!(State::Open.as_str(), "open");
        assert_eq!(State::HalfOpen.as_str(), "half_open");
    }

    #[test]
    fn severity_orders_worst_wins() {
        assert!(State::Open.severity() > State::HalfOpen.severity());
        assert!(State::HalfOpen.severity() > State::Closed.severity());
    }

    #[test]
    fn trips_open_on_failure_rate_over_full_window() {
        let cb = CircuitBreaker::default();
        // 20-request window, alternate so consecutive never hits 5 but rate = 50%.
        for i in 0..20 {
            cb.record("google", R, &env(), outcome(i % 2 == 0));
        }
        assert_eq!(cb.state("google", R, &Credential::Env), State::Open);
    }

    #[test]
    fn other_providers_unaffected_bulkhead() {
        let cb = CircuitBreaker::default();
        for _ in 0..5 {
            cb.record("openai", R, &env(), Outcome::UpstreamFault);
        }
        assert_eq!(cb.state("openai", R, &Credential::Env), State::Open);
        assert_eq!(cb.state("anthropic", R, &Credential::Env), State::Closed);
        assert!(cb.allow("anthropic", R, &env()));
    }

    #[test]
    fn recovers_through_half_open_after_cooldown() {
        let cb = fast_cooldown();
        for _ in 0..5 {
            cb.record("cohere", R, &env(), Outcome::UpstreamFault);
        }
        assert_eq!(cb.state("cohere", R, &Credential::Env), State::Open);
        assert!(!cb.allow("cohere", R, &env()));
        std::thread::sleep(Duration::from_millis(25));
        assert!(cb.allow("cohere", R, &env()));
        assert_eq!(cb.state("cohere", R, &Credential::Env), State::HalfOpen);
        for _ in 0..3 {
            cb.record("cohere", R, &env(), Outcome::Success);
        }
        assert_eq!(cb.state("cohere", R, &Credential::Env), State::Closed);
    }

    #[test]
    fn half_open_probe_failure_reopens() {
        let cb = fast_cooldown();
        for _ in 0..5 {
            cb.record("xai", R, &env(), Outcome::UpstreamFault);
        }
        std::thread::sleep(Duration::from_millis(25));
        assert!(cb.allow("xai", R, &env()));
        cb.record("xai", R, &env(), Outcome::UpstreamFault);
        assert_eq!(cb.state("xai", R, &Credential::Env), State::Open);
    }

    /// A probe whose outcome never arrives (a cache hit after `allow`, a client hang-up)
    /// must not wedge the breaker in Half-Open with its budget spent. The old breaker
    /// rejected forever in that state.
    #[test]
    fn lost_half_open_probes_are_re_granted_after_probe_lost() {
        let cb = CircuitBreaker::new(BreakerConfig {
            cooldown: Duration::from_millis(20),
            probe_lost: Duration::from_millis(20),
            ..cfg()
        });
        for _ in 0..5 {
            cb.record("groq", R, &env(), Outcome::UpstreamFault);
        }
        std::thread::sleep(Duration::from_millis(25));
        for _ in 0..3 {
            assert!(cb.allow("groq", R, &env()), "the probe budget");
        }
        assert!(
            !cb.allow("groq", R, &env()),
            "budget spent, results pending"
        );
        std::thread::sleep(Duration::from_millis(25));
        assert!(
            cb.allow("groq", R, &env()),
            "probes outstanding `probe_lost` are lost — a fresh one is granted"
        );
    }

    // ── OG-13 §7 proofs ─────────────────────────────────────────────────────

    /// The pre-OG-13 breaker, kept verbatim as the oracle for proof 1.
    mod oracle {
        use super::super::State;
        use std::collections::VecDeque;
        use std::time::{Duration, Instant};

        pub struct Old {
            pub state: State,
            window: VecDeque<bool>,
            consecutive: u32,
            opened_at: Option<Instant>,
            probes: u32,
            successes: u32,
        }

        impl Old {
            pub fn new() -> Self {
                Self {
                    state: State::Closed,
                    window: VecDeque::new(),
                    consecutive: 0,
                    opened_at: None,
                    probes: 0,
                    successes: 0,
                }
            }
            pub fn allow(&mut self, cooldown: Duration, max_probes: u32) -> bool {
                match self.state {
                    State::Closed => true,
                    State::HalfOpen => {
                        if self.probes < max_probes {
                            self.probes += 1;
                            true
                        } else {
                            false
                        }
                    }
                    State::Open => {
                        let el = self.opened_at.map_or(cooldown, |t| t.elapsed());
                        if el >= cooldown {
                            self.state = State::HalfOpen;
                            self.probes = 1;
                            self.successes = 0;
                            true
                        } else {
                            false
                        }
                    }
                }
            }
            pub fn record(&mut self, ok: bool, window: usize, rate: f64, consec: u32, probes: u32) {
                self.window.push_back(ok);
                while self.window.len() > window {
                    self.window.pop_front();
                }
                if ok {
                    self.consecutive = 0;
                } else {
                    self.consecutive += 1;
                }
                match self.state {
                    State::HalfOpen => {
                        if ok {
                            self.successes += 1;
                            if self.successes >= probes {
                                self.state = State::Closed;
                                self.window.clear();
                                self.consecutive = 0;
                                self.probes = 0;
                                self.successes = 0;
                            }
                        } else {
                            self.state = State::Open;
                            self.opened_at = Some(Instant::now());
                            self.probes = 0;
                            self.successes = 0;
                        }
                    }
                    State::Closed => {
                        let full = self.window.len() >= window;
                        let fr = self.window.iter().filter(|o| !**o).count() as f64
                            / self.window.len().max(1) as f64;
                        if self.consecutive >= consec || (full && fr >= rate) {
                            self.state = State::Open;
                            self.opened_at = Some(Instant::now());
                        }
                    }
                    State::Open => {}
                }
            }
        }
    }

    /// Proof 1 — with only an `Env` credential the new breaker's state sequence equals
    /// the old one over 200 random outcome sequences. A zero cool-down exercises every
    /// transition (Open → Half-Open on the next `allow`) without sleeping.
    #[test]
    fn og13_proof1_env_only_state_sequence_equals_the_old_breaker() {
        let c = BreakerConfig {
            cooldown: Duration::ZERO,
            ..cfg()
        };
        let mut seed: u64 = 0x5eed_0013;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let cb = CircuitBreaker::new(c);
            let mut old = oracle::Old::new();
            for _ in 0..60 {
                let r = next();
                if r % 3 == 0 {
                    let a = cb.allow("openai", R, &env());
                    let b = old.allow(c.cooldown, c.half_open_max_probes);
                    assert_eq!(a, b, "allow diverged");
                } else {
                    let ok = r % 5 < 2;
                    cb.record("openai", R, &env(), outcome(ok));
                    old.record(
                        ok,
                        c.window_size,
                        c.failure_rate_threshold,
                        c.consecutive_failure_threshold,
                        c.half_open_max_probes,
                    );
                }
                assert_eq!(cb.state("openai", R, &Credential::Env), old.state);
            }
        }
    }

    /// Proof 2 — RED before OG-13: tenant A's key 5xx-ing until A's credential breaker
    /// is Open does not shed tenant B on the same provider, and the provider-wide tier
    /// stays Closed.
    #[test]
    fn og13_proof2_one_tenants_failures_never_shed_another_tenant() {
        let cb = CircuitBreaker::default();
        let (a, b) = (byok(1), byok(2));
        for _ in 0..5 {
            assert!(cb.allow("mistral", R, &a));
            cb.record("mistral", R, &a, Outcome::UpstreamFault);
        }
        assert!(!cb.allow("mistral", R, &a), "A's own breaker is Open");
        assert!(
            cb.allow("mistral", R, &b),
            "B on the same provider is still admitted"
        );
        let snap = cb.owner_snapshot(Some(OwnerTag::of(&tenant(2))), false);
        assert_eq!(
            snap.providers[0].state,
            State::Closed,
            "provider-wide Closed"
        );
        assert_eq!(snap.providers[0].open_credentials, 1);
        assert_eq!(snap.providers[0].open_owners, 1);
    }

    #[test]
    fn og13_one_tenant_with_multiple_failing_labels_cannot_shed_other_tenants() {
        let cb = CircuitBreaker::default();
        for label in ["a", "b", "c", "d"] {
            let cred = Cred::byok(&tenant(1), "mistral", label);
            for _ in 0..cb.config.consecutive_failure_threshold {
                cb.record("mistral", R, &cred, Outcome::UpstreamFault);
            }
            assert_eq!(cb.state("mistral", R, &cred.id), State::Open);
        }
        assert!(
            cb.allow("mistral", R, &byok(2)),
            "one tenant's key pool must never open another tenant's circuit"
        );
        let snap = cb.owner_snapshot(Some(OwnerTag::of(&tenant(2))), false);
        assert_eq!(snap.providers[0].open_credentials, 4);
        assert_eq!(snap.providers[0].open_owners, 1);
    }

    /// Proof 3 — three DISTINCT Open credentials open the provider-wide tier and a
    /// healthy fourth tenant is shed; it recovers below three.
    #[test]
    fn og13_proof3_three_open_credentials_shed_the_provider_and_it_recovers() {
        let cb = CircuitBreaker::new(BreakerConfig {
            cooldown: Duration::from_millis(40),
            ..cfg()
        });
        for n in 1..=3 {
            for _ in 0..5 {
                cb.record("mistral", R, &byok(n), Outcome::UpstreamFault);
            }
        }
        assert!(
            !cb.allow("mistral", R, &byok(4)),
            "the healthy fourth tenant is shed by the provider-wide tier"
        );
        assert!(
            cb.allow("openai", R, &byok(4)),
            "other providers unaffected"
        );
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            cb.allow("mistral", R, &byok(4)),
            "below three Open credentials (cool-downs ended) the provider recovers"
        );
        // Many failures from ONE tenant never reach the threshold.
        let one = CircuitBreaker::default();
        for _ in 0..500 {
            one.record("mistral", R, &byok(9), Outcome::UpstreamFault);
        }
        assert!(one.allow("mistral", R, &byok(10)));
    }

    /// Proof 5 — capacity: past `max_entries` calls are admitted and counted; idle Closed
    /// entries evict; an Open one never does before its cool-down.
    #[test]
    fn og13_proof5_capacity_admits_and_counts_and_eviction_spares_open_entries() {
        let cb = CircuitBreaker::new(BreakerConfig {
            max_entries: 2,
            idle_evict: Duration::from_millis(30),
            cooldown: Duration::from_secs(60),
            ..cfg()
        });
        for _ in 0..5 {
            cb.record("mistral", R, &byok(1), Outcome::UpstreamFault); // Open, 60 s cool-down
        }
        assert!(cb.allow("mistral", R, &byok(2))); // Closed
        let before = counters().2;
        assert!(cb.allow("mistral", R, &byok(3)), "admitted at capacity");
        assert!(counters().2 > before, "and counted");
        assert_eq!(cb.entries(), 2);
        std::thread::sleep(Duration::from_millis(35));
        assert_eq!(cb.sweep_idle(), 1, "the idle Closed entry goes");
        assert_eq!(
            cb.state("mistral", R, &byok(1).id),
            State::Open,
            "the Open one stays inside its cool-down"
        );
    }

    /// Proof 6 — a key upsert/delete resets THAT label's breaker only.
    #[test]
    fn og13_proof6_reset_touches_one_label_only() {
        let cb = CircuitBreaker::default();
        let t = tenant(7);
        let a = Cred::byok(&t, "openai", "team-a");
        let b = Cred::byok(&t, "openai", "team-b");
        for _ in 0..5 {
            cb.record("openai", R, &a, Outcome::UpstreamFault);
            cb.record("openai", R, &b, Outcome::UpstreamFault);
        }
        cb.reset_credential(&a.id);
        assert_eq!(cb.state("openai", R, &a.id), State::Closed);
        assert_eq!(cb.state("openai", R, &b.id), State::Open);
        assert!(cb.allow("openai", R, &a));
    }

    #[test]
    fn og11_late_failure_after_rotation_cannot_recreate_the_old_breaker() {
        let cb = CircuitBreaker::default();
        let old = Cred::byok(&tenant(99), "openai", "rotating");
        assert!(cb.allow("openai", R, &old));
        cb.reset_credential(&old.id);
        let new = Cred::byok(&tenant(99), "openai", "rotating");
        assert!(cb.allow("openai", R, &new));
        for _ in 0..10 {
            cb.record("openai", R, &old, Outcome::UpstreamFault);
        }
        assert_eq!(cb.state("openai", R, &new.id), State::Closed);
        assert!(cb.allow("openai", R, &new));
        assert_eq!(cb.provider_open_count("openai", R, Instant::now()), 0);
    }

    /// Proof 8 — a workspace override changes only its own credential breakers.
    #[test]
    fn og13_proof8_a_tuning_override_binds_only_its_own_credential() {
        let cb = CircuitBreaker::default();
        let tuned = byok(1).with_tuning(Some(Tuning {
            consecutive_failure_threshold: 2,
            cooldown: Duration::from_secs(30),
        }));
        let other = byok(2);
        for _ in 0..2 {
            cb.record("mistral", R, &tuned, Outcome::UpstreamFault);
            cb.record("mistral", R, &other, Outcome::UpstreamFault);
        }
        assert_eq!(cb.state("mistral", R, &tuned.id), State::Open);
        assert_eq!(cb.state("mistral", R, &other.id), State::Closed);
    }

    /// Proof 9 (breaker half) — the per-tenant view shows only the caller's credentials,
    /// and no fingerprint contains the tenant id.
    #[test]
    fn og13_proof9_the_owner_view_is_tenant_scoped_and_fingerprints_hide_the_tenant() {
        let cb = CircuitBreaker::default();
        let (ta, tb) = (tenant(0xaaaa), tenant(0xbbbb));
        for _ in 0..5 {
            cb.record(
                "openai",
                R,
                &Cred::byok(&ta, "openai", "default"),
                Outcome::UpstreamFault,
            );
        }
        cb.record(
            "openai",
            R,
            &Cred::byok(&tb, "openai", "default"),
            Outcome::Success,
        );
        let a = cb.owner_snapshot(Some(OwnerTag::of(&ta)), false);
        assert_eq!(a.credentials.len(), 1);
        assert_eq!(a.credentials[0].state, State::Open);
        let b = cb.owner_snapshot(Some(OwnerTag::of(&tb)), false);
        assert_eq!(b.credentials.len(), 1);
        assert_eq!(b.credentials[0].state, State::Closed, "never A's state");
        let v = cb.tenant_view(Some(OwnerTag::of(&tb)), false);
        assert_eq!(
            v.get("openai"),
            Some(&State::Closed),
            "B's dashboard shows B's own Closed key — never A's Open key as a provider outage"
        );
        let fp = Credential::byok(&ta, "openai", "default")
            .fingerprint()
            .expect("byok");
        assert_eq!(fp.len(), 16);
        let simple = ta.simple().to_string();
        assert!(!simple.contains(&fp) && !ta.to_string().contains(&fp));
    }
    #[test]
    fn og13_concurrent_first_credentials_cannot_overfill_the_breaker_map() {
        let cb = std::sync::Arc::new(CircuitBreaker::new(BreakerConfig {
            max_entries: 2,
            ..Default::default()
        }));
        let ready = std::sync::Arc::new(std::sync::Barrier::new(16));
        std::thread::scope(|threads| {
            for n in 0..16 {
                let cb = cb.clone();
                let ready = ready.clone();
                threads.spawn(move || {
                    ready.wait();
                    assert!(cb.allow("openai", R, &byok(n)));
                });
            }
        });
        assert_eq!(cb.entries(), 2);
    }

    /// S1 (security review, 2026-10-05): a workspace that tunes ITS breaker (threshold 1,
    /// 300 s cool-down) can open its own credential at will. Three such workspaces must
    /// never open the provider-wide tier and shed a fourth, healthy tenant.
    #[test]
    fn s1_workspace_tuned_breakers_never_open_the_provider_tier() {
        let cb = CircuitBreaker::default();
        let tuned = Some(Tuning {
            consecutive_failure_threshold: 1,
            cooldown: Duration::from_secs(300),
        });
        for n in 1..=3 {
            let cred = byok(n).with_tuning(tuned);
            assert!(cb.allow("mistral", R, &cred));
            cb.record("mistral", R, &cred, Outcome::UpstreamFault);
            assert_eq!(
                cb.state("mistral", R, &cred.id),
                State::Open,
                "its OWN breaker opens"
            );
            assert!(!cb.allow("mistral", R, &cred), "and sheds its own traffic");
        }
        assert!(
            cb.allow("mistral", R, &byok(4)),
            "three workspace-tuned credentials must not shed a healthy fourth tenant"
        );
        let snap = cb.owner_snapshot(Some(OwnerTag::of(&tenant(4))), false);
        assert!(snap.providers.is_empty() || snap.providers[0].state == State::Closed);
    }

    /// S1: failures recorded while a workspace override was in force must not count
    /// toward a later provider-wide trip once the override is removed.
    #[test]
    fn s1_failures_seen_under_a_workspace_override_do_not_feed_the_provider_tier_later() {
        let cb = CircuitBreaker::default();
        let tuned = Some(Tuning {
            consecutive_failure_threshold: 100,
            cooldown: Duration::from_secs(1),
        });
        for n in 1..=3 {
            for _ in 0..4 {
                cb.record(
                    "mistral",
                    R,
                    &byok(n).with_tuning(tuned),
                    Outcome::UpstreamFault,
                );
            }
            // One failure under default tuning reaches the default threshold (5).
            cb.record("mistral", R, &byok(n), Outcome::UpstreamFault);
            assert_eq!(cb.state("mistral", R, &byok(n).id), State::Open);
        }
        assert!(
            cb.allow("mistral", R, &byok(4)),
            "a streak built under an override is the workspace's, not the provider's"
        );
    }

    /// S1, the protection kept: three tenants seeing real upstream 5xx under DEFAULT
    /// tuning still open the provider-wide tier, counted by distinct TENANT.
    #[test]
    fn s1_real_upstream_failures_under_defaults_still_open_the_provider_tier() {
        let cb = CircuitBreaker::default();
        for n in 1..=3 {
            for _ in 0..cb.config.consecutive_failure_threshold {
                cb.record("mistral", R, &byok(n), Outcome::UpstreamFault);
            }
        }
        assert!(
            !cb.allow("mistral", R, &byok(4)),
            "the provider is down for everyone"
        );
        let snap = cb.owner_snapshot(Some(OwnerTag::of(&tenant(1))), false);
        assert_eq!(snap.providers[0].open_owners, 3);
    }
}
