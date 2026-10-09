//! `api_keys` table — peppered-HMAC lookup + Argon2id verification.
//!
//! ## Scheme (ADR-042)
//!
//! API keys are `tlane_<base62>`; the part after the prefix is the *key body*.
//! Storage matches the canonical Drizzle/Neon shape (ADR-040): PK column `id`,
//! plus `key_prefix` (display), `lookup_hash`, `argon2id_phc`:
//!
//! 1. `lookup_hash = HMAC-SHA256(server_pepper, key_body)` — `bytea`.
//!    - Deterministic ⇒ UNIQUE index ⇒ ~1µs hot-path lookup.
//!    - Peppered ⇒ a DB dump alone cannot regenerate it. The pepper loads from
//!      `TRACELANE_APIKEY_PEPPER` (KMS-backed in prod); release binaries refuse
//!      to start without it.
//! 2. `argon2id_phc` — PHC string (per-row salt + m/t/p params).
//!    - Verified AFTER the lookup hits, so the slow KDF cost is paid once per
//!      legitimate request, never on a brute-force sweep. Defense in depth: even
//!      if the pepper leaks, Argon2id makes offline brute force expensive.
//!
//! The minter (`apps/web/app/api/settings/api-keys`) and this verifier MUST HMAC
//! with the **same** pepper. There is **no** legacy bare-SHA-256 fallback: prod
//! is minted onto this scheme (ADR-042), so every live row has `lookup_hash` +
//! `argon2id_phc`. A nullable `key_hash` column lingers for one row-drop window
//! and is removed in a follow-up migration; this module never reads or writes it.
//!
//! Argon2id alone can't be the lookup column because the per-row salt makes the
//! output non-deterministic — you'd have to load every row and KDF-verify each.
//! Peppered HMAC is the load-bearing ergonomic; Argon2id is the depth.
//!
//! Hot-path budget (CLAUDE.md): the lookup HMAC + index probe is well under the
//! gateway 5ms p50 overhead. Argon2id verify at the default params (~50ms) is
//! paid once per **authenticated** request; the auth result is cached upstream.

use anyhow::{Context as _, Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use moka::future::Cache;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use secrecy::{ExposeSecret, SecretBox};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

use tracelane_shared::TenantId;

// ---------------------------------------------------------------------
// Pepper
// ---------------------------------------------------------------------

/// Process-wide pepper key. Loaded once at startup from
/// `TRACELANE_APIKEY_PEPPER` and never logged. `SecretBox` zeroizes on
/// drop; the lock is `OnceLock` so the load is single-shot.
static PEPPER: OnceLock<SecretBox<[u8; 32]>> = OnceLock::new();

/// Initialize the process-wide pepper from `TRACELANE_APIKEY_PEPPER`.
///
/// Expects 64 hex chars (32 raw bytes) or 44 base64 chars. Anything
/// shorter is rejected — a 32-byte HMAC key is the minimum for the
/// strong-key bound in RFC 2104.
///
/// Idempotent: a second call with the same pepper is a no-op; a second
/// call with a different pepper returns an error so misconfiguration
/// surfaces loudly.
pub fn init_pepper(raw: &str) -> Result<()> {
    let bytes = decode_pepper(raw)?;
    let secret = SecretBox::new(Box::new(bytes));
    match PEPPER.set(secret) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Already initialized. Verify the value matches what's
            // installed; if it doesn't, refuse loudly.
            let current = PEPPER
                .get()
                .ok_or_else(|| anyhow!("pepper present-but-missing race"))?;
            if current.expose_secret() == &bytes {
                Ok(())
            } else {
                Err(anyhow!(
                    "init_pepper called twice with different values — refusing"
                ))
            }
        }
    }
}

fn decode_pepper(raw: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 {
        // Try hex first.
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex_nibble(trimmed.as_bytes()[2 * i])
                .ok_or_else(|| anyhow!("pepper hex: non-hex char"))?;
            let lo = hex_nibble(trimmed.as_bytes()[2 * i + 1])
                .ok_or_else(|| anyhow!("pepper hex: non-hex char"))?;
            *byte = (hi << 4) | lo;
        }
        Ok(out)
    } else {
        // Try base64.
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)
            .context("pepper is not 64-hex-chars or valid base64")?;
        if decoded.len() != 32 {
            return Err(anyhow!(
                "pepper must decode to exactly 32 bytes (got {})",
                decoded.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        Ok(out)
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn pepper() -> Result<&'static SecretBox<[u8; 32]>> {
    PEPPER
        .get()
        .ok_or_else(|| anyhow!("api-key pepper not initialized (call init_pepper at startup)"))
}

// ---------------------------------------------------------------------
// Auth-result cache (fix B)
// ---------------------------------------------------------------------
//
// The measured gateway overhead was 62ms of Argon2id + PG round-trips on EVERY
// request (the module doc's "the auth result is cached upstream" was aspirational
// — no cache existed). This is that cache.
//
// Keyed by the peppered-HMAC lookup digest (`peppered_lookup(key_body)` — never
// the raw key, never a truncation); value = the resolved `(tenant_uuid, key_id)`.
// A HIT skips the PG SELECT + the ~50ms Argon2id verify: the digest is already
// peppered, so recomputing it and matching a cached entry authenticates the
// presented token (an attacker cannot produce a matching digest without the
// server pepper). Argon2id remains the depth-in-case-of-DB-leak layer, paid on
// every cache MISS.
//
// POSITIVES ONLY — a not-found/revoked key is never cached, so a fresh key works
// on its first request and a revoked key can only linger if it was cached BEFORE
// revocation.
//
//  (2026-08-12): that lingering window is bounded by THIS TTL, and by nothing
// else. The previous comment here said the window was "closed immediately by the
// `key_revoked` NOTIFY", with the TTL as a mere backstop. That was false in
// production and the failure was systematic, not occasional: `pg_notify` reaches
// only listeners attached at that instant, the Neon compute autosuspends after 5
// min idle, and the revoking UPDATE is itself what wakes it — so on an idle system
// the NOTIFY fires on a fresh postmaster while the gateway's listener is still
// holding a socket it has not yet noticed is dead. Measured: 110 drop/reconnect
// cycles in 21.07 h. The NOTIFY path is now off by default
// (`entitlement_cache::control_plane_listen_enabled`).
//
// So the TTL is the revocation bound, it is stated as such, and it is 60s rather
// than the 900s that silently applied while we believed otherwise. Cost of the
// shorter TTL is one PG SELECT + one Argon2id verify per ACTIVE key per minute —
// paid only when a request actually arrives, because this cache is in-memory and
// positives-only. It therefore does not poll, and does not defeat Neon autosuspend
// (which was the whole point of dropping LISTEN).

/// What one authenticated API key resolves to, in ONE round trip.
///
/// A13 established the shape: resolve the capability at auth time rather than
/// re-deriving it per route, because the only available default is full-surface
/// and that is a privilege escalation on every cached request. GWY-43 extends
/// the same argument to money and to rate: `budget_usd_monthly` and
/// `rate_limit_rpm` are read HERE, in the SELECT that already authenticates the
/// key, so enforcing them costs zero extra round trips.
///
/// `budget_usd_monthly` in particular has existed as a column since A13 and was
/// **never selected again after the INSERT** — the hot-path query read five
/// columns and that was not one of them. That is why it enforced nothing.
#[derive(Debug, Clone)]
pub struct KeyAuth {
    pub tenant_id: TenantId,
    /// `api_keys.id` — the value that becomes the `apikey:` subject and the
    /// span's attribution dimension. Never secret-derived (ADR-042 / M-2).
    pub key_id: Uuid,
    pub scope: tracelane_shared::api_scope::KeyScope,
    /// Monthly USD ceiling for this key. `None` = uncapped.
    pub budget_usd_monthly: Option<f64>,
    /// Per-key requests-per-minute override. `None` = fall back to the tenant's
    /// plan tier, which is the behaviour every key had before GWY-43.
    pub rate_limit_rpm: Option<u32>,
    /// BILL-01 A3 — this key's budget reset cadence (`api_keys.budget_reset`).
    /// `Monthly` for every key minted before A3.
    pub budget_reset: tracelane_shared::spend::BudgetReset,
    /// OG-20 / OG-23 — the key's project, environment and policy layers. `None` for a
    /// key with none of them (the common case: no allocation, today's behaviour).
    pub governance: Option<std::sync::Arc<tracelane_shared::key_policy::Governance>>,
    /// B-568 I1: which branch answered. Carries no secret and changes nothing
    /// about the grant — it exists so the slow-request line can say `auth=cold`
    /// and the span can say `tracelane_gateway_cold_start`.
    pub path: LookupPath,
}

/// Which branch of [`lookup_tenant_by_key_body_at`] served a successful lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupPath {
    /// The positive cache — no I/O.
    Warm,
    /// The last-known answer past the TTL, re-checked OFF the request path.
    Stale,
    /// A control-plane round trip (pool checkout, SELECT, Argon2id verify).
    Cold,
}

impl LookupPath {
    /// The `auth=` label on the slow-request line.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Stale => "stale",
            Self::Cold => "cold",
        }
    }
}

/// `(hits, misses, stale_served, negative_hits)` since boot — `/health`'s
/// `auth_cache` object (B-568 I6). A miss counts every lookup the positive cache
/// did not answer, so it INCLUDES the stale-served and negative-cache answers;
/// the control-plane round trips are `misses − stale_served − negative_hits`.
#[must_use]
pub fn auth_cache_counters() -> (u64, u64, u64, u64) {
    (
        AUTH_CACHE_HIT_TOTAL.load(Ordering::Relaxed),
        AUTH_CACHE_MISS_TOTAL.load(Ordering::Relaxed),
        AUTH_STALE_SERVED_TOTAL.load(Ordering::Relaxed),
        AUTH_NEGATIVE_HIT_TOTAL.load(Ordering::Relaxed),
    )
}

/// What the auth cache stores. Mirrors [`KeyAuth`] minus the `TenantId` wrapper,
/// which is reconstructed with `from_jwt_claim` on the way out so the tenant seam
/// has exactly one construction site.
type CachedAuth = (
    Uuid,
    Uuid,
    tracelane_shared::api_scope::KeyScope,
    Option<f64>,
    Option<u32>,
    tracelane_shared::spend::BudgetReset,
    Option<DateTime<Utc>>, // earlier of expiry and scheduled revocation
    // OG-20 / OG-23: project, environment and the parsed policy layers, resolved in the
    // SAME SELECT. Cached WITH the grant: a warm hit that dropped it would serve the
    // key unrestricted, which is the privilege escalation A13 named for scope.
    Option<std::sync::Arc<tracelane_shared::key_policy::Governance>>,
);

// Only cold lookups and refreshes lock cache writes. Rotation holds the write
// lock across commit and invalidation, so a pre-rotation SELECT cannot restore
// a cached grant without its new deadline. Warm hits remain lock-free.
static AUTH_CACHE_WRITES: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

fn auth_deadline(
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    expires_at.into_iter().chain(revoked_at).min()
}

static AUTH_CACHE_HIT_TOTAL: AtomicU64 = AtomicU64::new(0);
static AUTH_CACHE_MISS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Default auth-cache TTL, and therefore the API-key revocation bound.
///
// hot-path-cache-ttl: exempt -- 60s is BELOW the floor deliberately, and it is
// safe here for a reason that does not generalise: `spawn_auth_cache_refresher`
// renews active entries every `refresh_interval_secs()` (20s by default) — BUT PROD SETS
// `TRACELANE_AUTH_REFRESH_SECS=0`, WHICH MAKES THAT TASK A NO-OP (see `start_warm_refresh`).
// Read this bound as the DEFAULT-CONFIG behaviour, never as the deployed one: on prod the
// only things bounding staleness are the 60 s TTL and `stale_max_secs()`. A comment that
// asserts a mechanism the deployment has switched off is worse than none — it retires the
// question for the next reader (SRE audit finding 41, 2026-09-04). So: a short TTL
// costs no cache misses and buys a revocation bound three times TIGHTER than the
// TTL itself. Remove the refresher and this exemption is void — the cache goes
// back to missing on every sparse request, which is exactly B-256.
const DEFAULT_AUTH_CACHE_TTL_SECS: u64 = 60;
/// Hard ceiling. A revocation window is a security property, so an env typo must
/// not be able to widen it past the value we previously (wrongly) shipped.
const MAX_AUTH_CACHE_TTL_SECS: u64 = 900;

/// Resolve the auth-cache TTL, clamped to `1..=900` seconds.
///
/// Fails CLOSED on garbage: an unparseable or out-of-range value falls back to the
/// 60s default rather than to the maximum, because this bounds how long a REVOKED
/// key keeps working.
///
/// Split from the env read so the policy is unit-testable without touching
/// process-global env — `docs/reference/TRAPS.md` §20: a test that mutates a
/// process-global races every other test that reads it, and the fix is not to
/// share it rather than to guard it.
fn parse_auth_cache_ttl(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| (1..=MAX_AUTH_CACHE_TTL_SECS).contains(s))
        .unwrap_or(DEFAULT_AUTH_CACHE_TTL_SECS)
}

fn auth_cache_ttl_secs() -> u64 {
    parse_auth_cache_ttl(
        std::env::var("TRACELANE_AUTH_CACHE_TTL_SECS")
            .ok()
            .as_deref(),
    )
}

/// Maximum cached auth results. At scale this, not the TTL, decides whether the
/// cache works at all.
fn auth_cache_capacity() -> u64 {
    std::env::var("TRACELANE_AUTH_CACHE_CAPACITY")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(500_000)
}

// B-386: stays global (for now) — this cache, the negative cache, `last_known`
// and `active_digests` below are read by `api_key::validate`, which has no state
// handle; converting them means threading an auth context through
// `validate_authorization`'s ~25 callers. Deferred and listed in the B-386
// report; the refresher (`spawn_auth_cache_refresher`) is spawned from `run()`
// against the same pool that is now `AppState::pg`.
fn auth_cache() -> &'static Cache<[u8; 32], CachedAuth> {
    static C: OnceLock<Cache<[u8; 32], CachedAuth>> = OnceLock::new();
    C.get_or_init(|| {
        Cache::builder()
            // Capacity, not TTL, is what binds at scale. 50,000 entries against
            // a million keys is a 5% hit rate — the SAME defect B-256 was,
            // reached through a different parameter, and it would present
            // identically: most requests paying the cold path forever. ~150
            // bytes/entry, so 500k is ~75MB. Tunable so it can move without a
            // release.
            .max_capacity(auth_cache_capacity())
            // 60s IS the revocation bound (see the block comment above),
            // not a backstop behind a NOTIFY that does not arrive. Override with
            // TRACELANE_AUTH_CACHE_TTL_SECS when traffic makes the Argon2id cost
            // matter; clamped so a typo cannot produce an unbounded window.
            .time_to_live(Duration::from_secs(auth_cache_ttl_secs()))
            .build()
    })
}

/// B-383 (f), 2026-09-12: the NEGATIVE cache. A lookup that found no row is
/// remembered for [`NEGATIVE_TTL`], so a scan of random `tlane_` strings is a
/// scan of this map, not of Neon — before this, every unknown key cost one
/// Postgres round trip and every retry of it cost another. Keyed on the same
/// peppered lookup hash as the positive cache; bounded so a scan cannot grow it.
///
/// The one cost, stated: a key MINTED inside the window is refused for up to
/// 30 s on its first use if that exact key was probed before it existed. The
/// mint route says so.
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const NEGATIVE_CAPACITY: u64 = 10_000;
pub(crate) static AUTH_NEGATIVE_HIT_TOTAL: AtomicU64 = AtomicU64::new(0);

fn negative_cache() -> &'static Cache<[u8; 32], ()> {
    static C: OnceLock<Cache<[u8; 32], ()>> = OnceLock::new();
    C.get_or_init(|| {
        Cache::builder()
            .max_capacity(NEGATIVE_CAPACITY)
            .time_to_live(NEGATIVE_TTL)
            .build()
    })
}

/// Test/ops hook: forget a key's negative entry (a mint route may call this so
/// a just-minted key authenticates immediately).
pub async fn forget_negative(lookup: &[u8; 32]) {
    negative_cache().invalidate(lookup).await;
}

/// A key was minted IN THIS PROCESS: it must authenticate on its first request.
/// Clears a negative entry left by a probe of the same key before it existed, and
/// adds its digest to the valid-key set at once (other instances and any writer
/// outside this process are caught by the set's miss-triggered refresh).
async fn note_minted(lookup: &[u8; 32]) {
    forget_negative(lookup).await;
    if let Some(k) = known_keys() {
        k.note_minted(*lookup);
    }
}

// ---------------------------------------------------------------------
// B-594 (2026-10-03): the COLD-LOOKUP GATE
// ---------------------------------------------------------------------
//
// The positive cache, the negative cache and the stale last-known answer cost
// no round trip. The one branch that does — the `SELECT … WHERE lookup_hash`
// below — is where a flood of never-seen keys lands, one Neon query each, and
// the negative cache cannot absorb a key it has never seen. Three bounds sit on
// that branch, in this order (security review rev4, 2026-10-03):
//
// 1. THE VALID-KEY SET ([`KnownKeys`], H1 d / M1) — every live `lookup_hash`,
//    loaded on the first cold lookup and read again (ONE query for everyone, at
//    most once per `known_keys_refresh_ms`) when a miss arrives after the last
//    read. A digest not in the set after that read is a 401 with NO per-key
//    Postgres lookup and NO token. A digest IN the set skips the per-source bucket,
//    so a valid cold key behind a shared egress is never throttled by a scanner on
//    that egress. Set unavailable (never loaded, load failed, past
//    `known_keys_max`) → the per-source gate below, i.e. today's behaviour
//    (fail-OPEN on a fault-tolerance path, never a refusal of a valid key).
// 2. THE PER-SOURCE BUCKET ([`ColdLookupGate`], only when the set could not
//    answer) — a token RESERVED before `pool.get()` (reserving first is the point:
//    counting after the fact lets N concurrent junk keys through before the first
//    is counted). REFUNDED only when no SQL ran: the pool checkout failed, or the
//    request was cancelled before the checkout completed (drop guard). Kept on
//    not-found, a failed Argon2id, and a store error AFTER the SQL ran — a refund
//    there made a slow or exhausted Neon free for an attacker (rev4 H1 b).
// 3. THE SLOTS ([`ColdSlots`], H1 a) — a fixed number of concurrent cold lookups
//    across ALL sources, a share of the Postgres pool. Over it, a lookup waits up
//    to `cold_lookup_wait_ms` and is then refused 429 `auth_throttled` — never
//    queued without bound. Per-source buckets cannot bound total load: 65,536 /64s
//    each with a full bucket all reach a 16-connection pool at once.
//
// The trait, the task-local and the set live HERE, not in `preauth_limiter`,
// because `tests/postgres_tenant_integration.rs` mounts `db/` by `#[path]` and
// cannot reach other crate modules. A lookup with no scope (that integration
// crate, a spawned task that lost the task-local) has no source to key on: it is
// counted ([`AUTH_UNGATED_COLD_LOOKUPS_TOTAL`], rev4 L4) and still takes a slot
// from the process-wide set the gateway installs at boot.

/// What one reservation charged, opaque to this module: the limiter encodes which
/// buckets (the source's, a wider IPv6 network's, the shared overflow) took a
/// token so `refund` returns exactly those.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reservation(pub u8);

/// A per-source token ledger for store-reaching key lookups. `source` is an
/// opaque key the limiter derived from the request (`preauth_limiter::SourceKey`).
pub trait ColdLookupGate: Send + Sync + 'static {
    /// Reserve one token. `Err(retry_after_secs)` when the source has none.
    fn try_acquire(&self, source: u128) -> std::result::Result<Reservation, u64>;
    /// Give the reserved token back — no SQL ran for it.
    fn refund(&self, source: u128, reservation: Reservation);
    /// The reserved token stays spent — the store found no valid key.
    fn charge(&self, source: u128);
    /// The process's concurrent cold-lookup slots (rev4 H1 a); `None` = unbounded.
    fn slots(&self) -> Option<&ColdSlots> {
        None
    }
}

/// A fixed number of concurrent store-reaching key lookups (rev4 H1 a). Cheap to
/// clone (one `Arc`).
#[derive(Clone, Debug)]
pub struct ColdSlots {
    sem: std::sync::Arc<tokio::sync::Semaphore>,
    size: usize,
    wait: Duration,
}

impl ColdSlots {
    /// `size` slots (at least one); a lookup over them waits up to `wait`.
    #[must_use]
    pub fn new(size: usize, wait: Duration) -> Self {
        let size = size.max(1);
        Self {
            sem: std::sync::Arc::new(tokio::sync::Semaphore::new(size)),
            size,
            wait,
        }
    }

    /// Slots in total.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// One slot, or `None` once `wait` has passed with none free.
    async fn take(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        if let Ok(p) = std::sync::Arc::clone(&self.sem).try_acquire_owned() {
            return Some(p);
        }
        if self.wait.is_zero() {
            return None;
        }
        tokio::time::timeout(self.wait, std::sync::Arc::clone(&self.sem).acquire_owned())
            .await
            .ok()?
            .ok()
    }
}

/// The slots a lookup with NO request scope takes — the same set the request
/// gate holds, installed once at boot (`preauth_limiter::PreAuthLimiter::from_policy`).
static UNSCOPED_SLOTS: OnceLock<ColdSlots> = OnceLock::new();

/// Install the process-wide slots for unscoped cold lookups. First call wins.
pub fn install_unscoped_cold_slots(slots: ColdSlots) {
    let _ = UNSCOPED_SLOTS.set(slots);
}

/// Cold lookups refused 429 because every slot stayed busy for the whole wait.
pub static AUTH_COLD_SATURATED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// rev4 L4: cold lookups that ran with NO request scope (no source to key a bucket
/// on) while the valid-key set could not answer — the bucket could not bound them.
pub static AUTH_UNGATED_COLD_LOOKUPS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Keys refused 401 by the valid-key set with no per-key Postgres lookup.
pub static AUTH_KNOWN_KEY_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// One request's gate: the ledger, who is asking, and whether this request was
/// refused (the retry-after seconds; 0 = not refused) so the middleware can
/// normalise whatever the route answered into one 429.
pub struct ColdGateScope {
    pub gate: std::sync::Arc<dyn ColdLookupGate>,
    pub source: u128,
    /// `OG-20`: the client's address, by B-594's ONE derivation
    /// (`preauth_limiter::client_ip`) — what a key's `source_ips` rule is judged on.
    /// `None` when neither a peer nor a believable header gave one.
    pub client_ip: Option<std::net::IpAddr>,
    pub throttled_retry_after: AtomicU64,
}

impl ColdGateScope {
    #[must_use]
    pub fn new(
        gate: std::sync::Arc<dyn ColdLookupGate>,
        source: u128,
        client_ip: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            gate,
            source,
            client_ip,
            throttled_retry_after: AtomicU64::new(0),
        }
    }
}

tokio::task_local! {
    static COLD_GATE: ColdGateScope;
}

/// `OG-20`: the address this request came from, as the pre-auth layer derived it.
/// `None` outside a request scope (a background caller, the integration crate) or when
/// no address could be derived — and a key with a `source_ips` rule is then DENIED
/// (`Governance::check_source`, fail-CLOSED).
#[must_use]
pub fn current_client_ip() -> Option<std::net::IpAddr> {
    COLD_GATE.try_with(|s| s.client_ip).ok().flatten()
}

/// Run `fut` with `scope` as its cold-lookup gate.
pub fn with_cold_gate<F: std::future::Future>(
    scope: ColdGateScope,
    fut: F,
) -> tokio::task::futures::TaskLocalFuture<ColdGateScope, F> {
    COLD_GATE.scope(scope, fut)
}

/// The cold lookup was refused before the store: this request's source spent its
/// failed-lookup budget, or every cold-lookup slot stayed busy. Typed so
/// `auth::failure` answers 429 — never the 503 a store error gets, never the 401 a
/// wrong key gets.
#[derive(Debug, thiserror::Error)]
#[error("authentication lookups are rate limited — retry after {retry_after_secs} s")]
pub struct AuthThrottled {
    pub retry_after_secs: u64,
}

/// Set by the lookup the moment its connection is checked out: from here on SQL
/// runs, so a failure or a cancellation keeps the source's token (rev4 H1 b).
#[derive(Clone, Debug, Default)]
pub struct SqlMark(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl SqlMark {
    /// The connection is held; the next await may run SQL.
    pub fn started(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn is_started(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Which bound a cold lookup is under (see the section comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gating {
    /// The valid-key set could not answer: per-source bucket, then a slot.
    Source,
    /// The digest is in the valid-key set: a slot only — a valid key is never
    /// charged to its source's bucket (rev4 M1).
    Known,
}

/// A reserved token that goes back unless the lookup settles it: dropped before
/// its SQL ran (a cancelled request, a refused slot, a failed checkout) it refunds;
/// dropped after, it stays spent (rev4 M2 + H1 b).
struct Held {
    gate: std::sync::Arc<dyn ColdLookupGate>,
    source: u128,
    reservation: Reservation,
    mark: SqlMark,
    settled: bool,
}

impl Held {
    fn refund(&mut self) {
        self.settled = true;
        self.gate.refund(self.source, self.reservation);
    }
    fn charge(&mut self) {
        self.settled = true;
        self.gate.charge(self.source);
    }
    fn keep(&mut self) {
        self.settled = true;
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if !self.settled && !self.mark.is_started() {
            self.gate.refund(self.source, self.reservation);
        }
    }
}

fn note_throttled(retry_after_secs: u64) {
    let _ = COLD_GATE.try_with(|s| {
        s.throttled_retry_after
            .store(retry_after_secs, Ordering::Relaxed);
    });
}

/// Run a store-reaching lookup under the request's bounds (B-594 + rev4). `f` gets
/// a [`SqlMark`] and must call [`SqlMark::started`] once its connection is checked
/// out.
///
/// # Errors
/// Fail-CLOSED: [`AuthThrottled`] when the source's bucket is empty (under
/// [`Gating::Source`]) or no slot frees within the wait — `f` is never called, so
/// no connection is taken and no SQL runs. Otherwise `f`'s own result. A lookup
/// with no request scope has no bucket to charge (counted, rev4 L4) but still
/// takes a slot when the process installed them.
pub(crate) async fn gated_cold_lookup<T, Fut>(
    gating: Gating,
    f: impl FnOnce(SqlMark) -> Fut,
) -> Result<Option<T>>
where
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let mark = SqlMark::default();
    let scoped = COLD_GATE
        .try_with(|s| (std::sync::Arc::clone(&s.gate), s.source))
        .ok();
    let mut held = None;
    if gating == Gating::Source {
        match &scoped {
            Some((gate, source)) => match gate.try_acquire(*source) {
                Ok(reservation) => {
                    held = Some(Held {
                        gate: std::sync::Arc::clone(gate),
                        source: *source,
                        reservation,
                        mark: mark.clone(),
                        settled: false,
                    });
                }
                Err(retry_after) => {
                    let retry_after_secs = retry_after.max(1);
                    note_throttled(retry_after_secs);
                    return Err(AuthThrottled { retry_after_secs }.into());
                }
            },
            None => {
                AUTH_UNGATED_COLD_LOOKUPS_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let slots = scoped
        .as_ref()
        .and_then(|(gate, _)| gate.slots().cloned())
        .or_else(|| UNSCOPED_SLOTS.get().cloned());
    let _slot = match slots {
        Some(s) => {
            if let Some(p) = s.take().await {
                Some(p)
            } else {
                AUTH_COLD_SATURATED_TOTAL.fetch_add(1, Ordering::Relaxed);
                note_throttled(1);
                // `held` drops here with no SQL run → its token goes back.
                return Err(AuthThrottled {
                    retry_after_secs: 1,
                }
                .into());
            }
        }
        None => None,
    };
    let result = f(mark.clone()).await;
    if let Some(h) = held.as_mut() {
        match &result {
            Ok(None) => h.charge(),
            Ok(Some(_)) => h.refund(),
            // The checkout failed — no SQL ran (an outage is not an auth failure).
            Err(_) if !mark.is_started() => h.refund(),
            // The SQL ran and failed: the token stays spent.
            Err(_) => h.keep(),
        }
    }
    result
}

// ---------------------------------------------------------------------
// rev4 H1 d / M1 (2026-10-03): the VALID-KEY SET
// ---------------------------------------------------------------------
//
// Why a set rather than a bloom filter: a few hundred to a few hundred thousand
// 32-byte digests is ~32 B each plus hash-set overhead — tens of MB at the
// `known_keys_max` ceiling — and an exact set has NO false positive to measure
// or tune. Kept current WITHOUT a timer and without NOTIFY: the control-plane
// LISTEN is off by default because it measured structurally unreliable on Neon
// (110 drop/reconnect cycles in 21 h — see the auth-cache block comment above), and
// a timer would keep an idle Neon compute awake. Instead a MISS asks: if no read
// of the set has STARTED since this request arrived, one read runs (single
// flight, at most once per `refresh`), and every miss queued behind it decides on
// its answer. So a key minted anywhere — another instance, any writer — is
// accepted on its first request within `refresh` + one query; a flood of junk
// costs at most one cheap read per `refresh` for everyone, and no per-key lookup.
// Mints in THIS process add the digest at once ([`note_minted`]).
//
// Deletions: revoked/expired digests leave the set only on a FULL read (the first
// read, and any read once the last full one is `full_reload` old). A revoked digest
// still in the set costs one ordinary cold lookup, which refuses it (the SELECT
// filters `revoked_at`/`expires_at`) and negative-caches it — membership admits a
// lookup, it never grants anything.

/// The valid-key set's tunables (`auth_throttle` table, `known_keys_*`).
#[derive(Debug, Clone, Copy)]
pub struct KnownKeysConfig {
    /// Least time between two reads a miss triggers.
    pub refresh: Duration,
    /// Longest a miss waits for its read before taking the gated lookup.
    pub wait: Duration,
    /// A set whose last FULL read is older than this is read whole again.
    pub full_reload: Duration,
    /// How far behind the last read a delta read starts.
    pub overlap: Duration,
    /// Past this many digests the set is dropped (the gated lookup applies).
    pub max: usize,
}

/// What the set says about one digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    /// A live key's digest (as of the last read): look it up, no bucket.
    Present,
    /// Not in a read that started after this request arrived: 401, no lookup.
    Absent,
    /// The set cannot answer (never loaded, the read failed or timed out, too
    /// large): the gated lookup decides, exactly as before the set existed.
    Unknown,
}

/// One read of `api_keys`: the database's `now()` at the read, and the digests.
#[derive(Debug, Clone)]
pub struct KeySnapshot {
    pub at: DateTime<Utc>,
    pub hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, Default)]
struct KnownState {
    last_ok_start: Option<Instant>,
    last_attempt: Option<Instant>,
    last_failed: Option<Instant>,
    last_full: Option<Instant>,
    watermark: Option<DateTime<Utc>>,
}

/// Reads of the valid-key set (full or delta) that succeeded / failed.
pub static KNOWN_KEYS_READS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static KNOWN_KEYS_READ_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// The set of live `lookup_hash` digests (see the section comment).
pub struct KnownKeys {
    cfg: KnownKeysConfig,
    set: parking_lot::RwLock<Option<std::collections::HashSet<[u8; 32]>>>,
    state: parking_lot::Mutex<KnownState>,
    reading: tokio::sync::Mutex<()>,
}

impl KnownKeys {
    #[must_use]
    pub fn new(cfg: KnownKeysConfig) -> Self {
        Self {
            cfg,
            set: parking_lot::RwLock::new(None),
            state: parking_lot::Mutex::new(KnownState::default()),
            reading: tokio::sync::Mutex::new(()),
        }
    }

    /// Whether a read has populated the set (and it was not dropped since).
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.set.read().is_some()
    }

    /// Digests held (0 when not loaded).
    #[must_use]
    pub fn digest_count(&self) -> usize {
        self.set
            .read()
            .as_ref()
            .map_or(0, std::collections::HashSet::len)
    }

    /// A key minted in this process: present at once (no-op before the first read,
    /// which will see it).
    pub fn note_minted(&self, digest: [u8; 32]) {
        if let Some(s) = self.set.write().as_mut() {
            s.insert(digest);
        }
    }

    fn contains(&self, digest: &[u8; 32]) -> bool {
        self.set.read().as_ref().is_some_and(|s| s.contains(digest))
    }

    /// Whether `digest` belongs to a live key. `fetch(None)` reads every live
    /// digest; `fetch(Some(t))` reads every digest created at or after `t`.
    ///
    /// # Errors
    /// None — every failure (the read failed, it timed out, the set is too large)
    /// is [`Membership::Unknown`]: fail-OPEN to the gated lookup, never a refusal
    /// of a valid key.
    pub async fn classify<F, Fut>(&self, digest: &[u8; 32], fetch: F) -> Membership
    where
        F: FnOnce(Option<DateTime<Utc>>) -> Fut,
        Fut: std::future::Future<Output = Result<KeySnapshot>>,
    {
        if self.contains(digest) {
            return Membership::Present;
        }
        let arrival = Instant::now();
        tokio::time::timeout(self.cfg.wait, self.confirm(digest, arrival, fetch))
            .await
            .unwrap_or(Membership::Unknown)
    }

    async fn confirm<F, Fut>(&self, digest: &[u8; 32], arrival: Instant, fetch: F) -> Membership
    where
        F: FnOnce(Option<DateTime<Utc>>) -> Fut,
        Fut: std::future::Future<Output = Result<KeySnapshot>>,
    {
        let _single_flight = self.reading.lock().await;
        if self.contains(digest) {
            return Membership::Present;
        }
        let st = *self.state.lock();
        let loaded = self.is_loaded();
        // A read that STARTED after this request arrived did not see the key.
        if loaded && st.last_ok_start.is_some_and(|s| s >= arrival) {
            return Membership::Absent;
        }
        // Never loaded and the last attempt failed recently: do not make every
        // request wait on a store that is down — the gated lookup answers.
        if !loaded
            && st
                .last_failed
                .is_some_and(|f| arrival.saturating_duration_since(f) < self.cfg.refresh)
        {
            return Membership::Unknown;
        }
        if let Some(last) = st.last_attempt {
            tokio::time::sleep_until((last + self.cfg.refresh).into()).await;
        }
        let started = Instant::now();
        let full = !loaded
            || st.watermark.is_none()
            || st
                .last_full
                .is_none_or(|f| started.saturating_duration_since(f) >= self.cfg.full_reload);
        let since = if full {
            None
        } else {
            st.watermark.map(|w| {
                w - chrono::Duration::from_std(self.cfg.overlap).unwrap_or(chrono::Duration::zero())
            })
        };
        self.state.lock().last_attempt = Some(started);
        let snap = match fetch(since).await {
            Ok(s) => s,
            Err(err) => {
                KNOWN_KEYS_READ_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
                self.state.lock().last_failed = Some(started);
                tracing::debug!(error = %err, "valid-key set read failed; the gated lookup answers");
                return Membership::Unknown;
            }
        };
        KNOWN_KEYS_READS_TOTAL.fetch_add(1, Ordering::Relaxed);
        {
            let mut set = self.set.write();
            if full {
                *set = Some(snap.hashes.into_iter().collect());
            } else if let Some(s) = set.as_mut() {
                s.extend(snap.hashes);
            }
            if set.as_ref().is_some_and(|s| s.len() > self.cfg.max) {
                // Too many keys to hold: drop the set — the gated lookup applies.
                *set = None;
                self.state.lock().last_failed = Some(started);
                return Membership::Unknown;
            }
        }
        {
            let mut s = self.state.lock();
            s.last_ok_start = Some(started);
            s.watermark = Some(snap.at);
            if full {
                s.last_full = Some(started);
            }
        }
        if self.contains(digest) {
            Membership::Present
        } else {
            Membership::Absent
        }
    }
}

static KNOWN_KEYS: OnceLock<KnownKeys> = OnceLock::new();

/// Turn the valid-key set on for this process (boot, with a Postgres pool). First
/// call wins. Unconfigured — tests, the integration crate, a no-Postgres gateway —
/// every lookup takes the gated path, as before the set existed.
pub fn configure_known_keys(cfg: KnownKeysConfig) {
    let _ = KNOWN_KEYS.set(KnownKeys::new(cfg));
}

/// The process's valid-key set, if configured.
#[must_use]
pub fn known_keys() -> Option<&'static KnownKeys> {
    KNOWN_KEYS.get()
}

/// One read of `api_keys` for the valid-key set: `since = None` reads every LIVE
/// digest (not revoked, not expired); `Some(t)` reads every digest created at or
/// after `t` (revoked or not — membership admits a lookup, it grants nothing).
/// At most `max + 1` digests, so an oversized table is detected without loading it.
///
/// # Errors
/// The checkout or the query failed.
async fn fetch_known_keys(
    pool: &Pool,
    since: Option<DateTime<Utc>>,
    max: usize,
) -> Result<KeySnapshot> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let limit = i64::try_from(max).unwrap_or(i64::MAX).saturating_add(1);
    let row = match since {
        None => {
            client
                .query_one(
                    "SELECT now(), ARRAY(SELECT lookup_hash FROM api_keys \
                     WHERE lookup_hash IS NOT NULL \
                       AND (revoked_at IS NULL OR revoked_at > now()) \
                       AND (expires_at IS NULL OR expires_at > now()) \
                     LIMIT $1)",
                    &[&limit],
                )
                .await
        }
        Some(t) => {
            client
                .query_one(
                    "SELECT now(), ARRAY(SELECT lookup_hash FROM api_keys \
                     WHERE lookup_hash IS NOT NULL AND created_at >= $2 LIMIT $1)",
                    &[&limit, &t],
                )
                .await
        }
    }
    .context("SELECT api_keys digests for the valid-key set failed")?;
    let raw: Vec<Vec<u8>> = row.get(1);
    Ok(KeySnapshot {
        at: row.get(0),
        hashes: raw
            .into_iter()
            .filter_map(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .collect(),
    })
}

// ---------------------------------------------------------------------
// Warm refresh (B-256)
// ---------------------------------------------------------------------
//
// THE PROBLEM THIS SOLVES, and it is not hypothetical — the entitlement cache
// hit it first and its doc records the incident verbatim: a TTL SHORTER than the
// gap between a tenant's requests means the cache never hits, so *every* request
// pays the cold path. `entitlement_cache.rs` puts the number on it: "a blocking
// Postgres re-resolve on EVERY request from a low-QPS tenant ... ~72ms p50
// gateway overhead ... while the warm/sustained path measured ~1.6ms".
//
// That module fixed it with a 900s TTL plus refresh-ahead, and its comment says
// the auth cache matched at 15 minutes. then cut THIS cache to 60s for a
// tighter revocation bound and did not carry the refresh across. Prod traffic
// arrives roughly every 400s, so the hit rate for a sparse tenant is ZERO and
// every request pays a Neon round trip plus a ~50ms Argon2id verify.
//
// WHY REFRESH-AHEAD ALONE DOES NOT WORK HERE. The entitlement cache refreshes on
// READ — an entry older than `REFRESH_AHEAD` triggers a background re-resolve
// while the request is served from cache. With 400s between requests the entry
// is already 340s past a 60s TTL when the next read arrives; there is no entry
// left to refresh ahead of. The refresh has to run on a TIMER, independent of
// traffic. That is what this is.
//
// WHAT IT DOES TO THE REVOCATION BOUND — it TIGHTENS it. Today the bound is the
// 60s TTL: a revoked key keeps working until its cached entry expires. The
// refresher re-runs the SAME future-revocation and expiry predicate (expires_at IS NULL
// OR expires_at > now())` predicate the miss path uses, every
// `refresh_interval_secs()` (default 20s — A NO-OP ON PROD, which sets
// TRACELANE_AUTH_REFRESH_SECS=0), and INVALIDATES on a row that no
// longer qualifies. So the bound becomes the refresh interval, three times
// tighter than what shipped.
//
// FAIL-SAFE, not fail-open: if the refresher dies, stalls, or the database is
// unreachable, entries stop being renewed and expire at the 60s TTL exactly as
// they do today. There is no state in which this makes a key live LONGER than
// the current behaviour.
//
// NO ARGON2ID ON REFRESH, and the reason is stated rather than assumed. Argon2id
// proves POSSESSION of the key body, which was proven when the entry was created
// and cannot be re-proven without the raw secret — which is never stored. The
// refresh asks a different question: is this row still valid? That is answered by
// the row predicate alone. The digest keying the entry is a peppered HMAC, so it
// cannot be produced without the server pepper, and the cache is positives-only:
// nothing enters it that did not pass a full Argon2id verify first.
//
// **The narrow case this does NOT cover, stated because it is real:** if an
// attacker with write access to the `api_keys` row swapped `argon2id_phc` AFTER
// a key had authenticated, the refresh would not notice, because it does not
// re-verify possession. The entry still dies once the key goes unused for
// `active_idle_secs()`. That is a database-compromise scenario in which the
// attacker can also mint their own key, so the marginal exposure is nil — but it
// is a difference from the pre-B-256 behaviour and belongs in writing.

/// **THE SCALE CEILING, stated so nobody assumes this holds at any size.**
///
/// This is a SPARSE-TRAFFIC optimisation and it degrades, by design, into
/// today's behaviour rather than into an outage. It can hold roughly
/// `MAX_REFRESH_PER_TICK * (ttl / 2 / interval)` keys warm — about **150 at the
/// defaults**. Past that, surplus keys miss and pay the cold path they pay
/// today. Nothing breaks; the optimisation stops applying to them.
///
/// **Beyond that the answer is NOT a bigger budget here.** In order:
///   1. **Raise the TTL.** At 900s any key used more often than every 15 minutes
///      keeps itself warm and needs no background work at all. This is the whole
///      fix for the 1,000-10,000 user range.
///   2. **Cache capacity** (`auth_cache_capacity`) — 50,000 entries against a
///      million keys is a 5% hit rate, the same bug via a different parameter.
///   3. **Event-driven invalidation.** The gateway already runs NATS for spans
///      and audit; a `key_revoked` event on it invalidates every instance in
///      milliseconds. That beats polling, beats a short TTL, and beats `LISTEN`
///      the mechanism measured as structurally unreliable (110
///      drop/reconnect cycles in 21h, the NOTIFY landing on a compute the
///      revoking write had itself just woken). With it, TTLs can be long at ANY
///      scale and this task becomes unnecessary.
///
/// How often to re-check every active key against Postgres. This IS the
/// revocation bound once the refresher is running.
const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 20;
/// A key not presented for this long stops being refreshed, so its entry expires
/// naturally. Bounds the background query rate to keys actually in use.
///
/// **3600s, raised from 900s — because 900s was THE SAME BUG this module exists
/// to fix, one level up.** A tracking window shorter than the gap between a
/// tenant's requests means the key is not tracked at the moment it matters, so
/// it goes cold anyway and the refresher buys nothing. Caught by the scenario
/// sweep on 2026-08-18: request #1 of a burst cost **178.36ms** while requests
/// #2-15 cost 1.23-2.02ms, because the preceding gap had exceeded 900s and the
/// key had been dropped from the active set. Our own canary runs HOURLY, so at
/// 900s every single canary request would have paid the cold path.
///
/// The cost of a wider window is bounded by `MAX_REFRESH_PER_TICK`, not by this
/// value — which is why widening it is safe and narrowing it was not.
///
/// **This does not reach forever, and no value here would.** A key idle longer
/// than this pays one cold request and is then warm again. Making that gap
/// disappear entirely needs event-driven invalidation with a long TTL, not a
/// bigger number here — see the note on `DEFAULT_REFRESH_INTERVAL_SECS`.
const DEFAULT_ACTIVE_IDLE_SECS: u64 = 3600;
/// Ceiling on tracked digests. 32 bytes of key + a timestamp each, so the cap is
/// about a megabyte at the limit — small, but unbounded growth on an auth path
/// is not a thing to leave to chance.
const MAX_ACTIVE_DIGESTS: usize = 10_000;

fn refresh_interval_secs() -> u64 {
    let raw = std::env::var("TRACELANE_AUTH_REFRESH_SECS").ok();
    parse_refresh_interval(raw.as_deref(), auth_cache_ttl_secs())
}

/// Clamped to at most HALF the TTL, and never below 5s.
///
/// The half-TTL ceiling is load-bearing: an interval longer than the TTL means
/// entries expire between refreshes and the cache stops hitting, which is the
/// exact defect this exists to remove. Half leaves room for one missed tick.
/// Pure, so the clamp is testable without touching process env
/// (`docs/reference/TRAPS.md` §20).
fn parse_refresh_interval(raw: Option<&str>, ttl_secs: u64) -> u64 {
    let want = raw
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECS);
    want.clamp(5, (ttl_secs / 2).max(5))
}

fn active_idle_secs() -> u64 {
    std::env::var("TRACELANE_AUTH_ACTIVE_IDLE_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_ACTIVE_IDLE_SECS)
}

/// Digests presented on the hot path, and when each was last seen. Separate from
/// the moka cache on purpose: moka entries expire, and the set of keys we want to
/// KEEP alive has to outlive the entries it is keeping alive.
/// STALE-WHILE-REVALIDATE (2026-09-04, the p95 investigation). The moka cache
/// EVICTS at its TTL, so a key presented less often than 60 s missed every time
/// and paid the control-plane round trip on the hot path — with the keepalive
/// off (NEON-COMPUTE-PIN) that is a fresh connect plus, when the compute had
/// suspended, its ~1.2 s resume. This map keeps the last successful answer per
/// digest for up to [`stale_max_secs`] beyond the TTL; a miss that finds one is
/// served from it and the row is re-checked OFF-PATH (`refresh_one`).
///
/// What that means for revocation, stated honestly (B-303, accepted 2026-09-03):
/// a key revoked while idle may be accepted ONCE more on its next use, and is
/// refused from the refresh that use triggers (seconds). A key in steady use is
/// still refused within the 60 s TTL. Nothing is served past `stale_max_secs`.
type LastKnownMap = std::sync::Mutex<HashMap<[u8; 32], (CachedAuth, Instant)>>;

fn last_known() -> &'static LastKnownMap {
    static M: OnceLock<LastKnownMap> = OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// How long past the TTL a last-known answer may still be served: 15× the TTL,
/// capped at 15 minutes — the entitlement cache's own staleness bound.
fn stale_max_secs() -> u64 {
    (auth_cache_ttl_secs() * 15).min(900)
}

/// Ceiling on remembered answers, mirroring `MAX_ACTIVE_DIGESTS` above.
///
/// SRE audit finding 49, 2026-09-04. This map grew without any bound while the sibling
/// map twenty lines up carries one, and nothing ever removed an entry except an explicit
/// invalidation — so an answer that can NEVER be served again (past `stale_max_secs`,
/// where `last_known_fresh_enough` refuses it) still held its slot forever. Unbounded
/// growth on the auth path is not a thing to leave to chance, which is the reasoning
/// already written at `MAX_ACTIVE_DIGESTS`; it simply was not applied here.
const MAX_LAST_KNOWN: usize = 10_000;

fn remember_last_known(digest: [u8; 32], entry: CachedAuth) {
    if let Ok(mut m) = last_known().lock() {
        evict_last_known_if_full(&mut m, MAX_LAST_KNOWN, stale_max_secs());
        m.insert(digest, (entry, Instant::now()));
    }
}

/// The bound itself, factored out so it is testable without the global map or a clock —
/// the same reason `parse_refresh_interval` is pure (`docs/reference/TRAPS.md` §20).
fn evict_last_known_if_full(
    m: &mut HashMap<[u8; 32], (CachedAuth, Instant)>,
    cap: usize,
    cutoff_secs: u64,
) {
    if m.len() < cap {
        return;
    }
    // Expired entries are pure dead weight: `last_known_fresh_enough` already refuses
    // anything past this bound, so dropping them costs nothing and is usually enough.
    m.retain(|_, (_, at)| at.elapsed().as_secs() < cutoff_secs);
    // Still full of LIVE entries — evict the stalest, which is the one closest to being
    // refused anyway.
    while m.len() >= cap {
        let Some(stalest) = m
            .iter()
            .max_by_key(|(_, (_, at))| at.elapsed())
            .map(|(k, _)| *k)
        else {
            break;
        };
        m.remove(&stalest);
    }
}

fn forget_last_known(digest: [u8; 32]) {
    if let Ok(mut m) = last_known().lock() {
        m.remove(&digest);
    }
}

fn last_known_fresh_enough(digest: [u8; 32]) -> Option<CachedAuth> {
    let m = last_known().lock().ok()?;
    let (entry, at) = m.get(&digest)?;
    (at.elapsed().as_secs() < stale_max_secs()).then(|| entry.clone())
}

/// Misses served from the last-known answer while a refresh ran off-path.
pub static AUTH_STALE_SERVED_TOTAL: AtomicU64 = AtomicU64::new(0);

fn active_digests() -> &'static std::sync::Mutex<HashMap<[u8; 32], Instant>> {
    static A: OnceLock<std::sync::Mutex<HashMap<[u8; 32], Instant>>> = OnceLock::new();
    A.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Record that this digest was just used. Called on every successful auth, hit or
/// miss. A poisoned lock is ignored rather than propagated: failing an
/// authenticated request because a bookkeeping mutex panicked elsewhere would
/// turn an optimisation into an outage.
fn note_active(digest: [u8; 32]) {
    let Ok(mut map) = active_digests().lock() else {
        return;
    };
    if map.len() >= MAX_ACTIVE_DIGESTS && !map.contains_key(&digest) {
        // AT THE CAP: skip the insert. Deliberately O(1).
        //
        // This used to evict the least-recently-seen via `min_by_key`, which is
        // A LINEAR SCAN OF 10,000 ENTRIES ON EVERY AUTHENTICATED REQUEST once
        // full — an O(n) hot-path cost added while fixing a latency bug. The
        // scan is gone; nothing here is worse than a hash insert.
        //
        // Skipping loses nothing, because of WHERE the cap binds. The tracked
        // set only matters for keys too SPARSE to keep themselves warm, and
        // `due_for_refresh` already skips any key that traffic is warming. The
        // set is pruned every tick, so space frees itself as keys go idle.
        return;
    }
    map.insert(digest, Instant::now());
}

/// Most keys refreshed in one tick. The ceiling on background database load,
/// and it does NOT move with user count — that is the whole point.
///
/// Without it this task is O(active keys) per tick: 3 queries/minute at one key,
/// **500 queries per second at ten thousand**, and a self-inflicted outage at a
/// million. A cap on the tracked SET bounds memory; only a cap on the WORK bounds
/// the database.
const MAX_REFRESH_PER_TICK: usize = 100;

/// Digests that actually need refreshing this tick: inside the idle window, and
/// NOT already kept warm by real traffic. Oldest first, budget-capped.
///
/// **The skip is what makes this scale-safe.** A key presented within half the
/// TTL is being refreshed by requests already; touching it again is pure waste.
/// So the refresh set shrinks toward EMPTY as traffic grows — which is correct,
/// because this task exists for keys too sparse to keep themselves warm. At one
/// request per 400s it refreshes; at one per second it does nothing.
///
/// Entries past the idle window are dropped here rather than refreshed, so a key
/// that goes quiet stops costing queries within one interval.
fn due_for_refresh() -> Vec<[u8; 32]> {
    let idle = Duration::from_secs(active_idle_secs());
    // Half the TTL: far enough from expiry that a request arriving next tick
    // still finds a live entry, close enough that traffic-warmed keys are skipped.
    let warm_enough = Duration::from_secs(auth_cache_ttl_secs() / 2);
    let Ok(mut map) = active_digests().lock() else {
        return Vec::new();
    };
    map.retain(|_, seen| seen.elapsed() < idle);
    let due: Vec<([u8; 32], Duration)> = map
        .iter()
        .filter(|(_, seen)| seen.elapsed() >= warm_enough)
        .map(|(d, seen)| (*d, seen.elapsed()))
        .collect();
    if due.len() > MAX_REFRESH_PER_TICK {
        tracing::debug!(
            due = due.len(),
            budget = MAX_REFRESH_PER_TICK,
            "auth warm-refresh budget reached — deferring the freshest entries to the next tick"
        );
    }
    select_due(due, MAX_REFRESH_PER_TICK)
}

/// Ordering + budget policy, split out so it is testable without aging an
/// `Instant` (which cannot be done, so a test against the real clock would
/// either sleep for minutes or assert nothing).
///
/// Oldest first, then truncated to `budget`.
fn select_due(mut due: Vec<([u8; 32], Duration)>, budget: usize) -> Vec<[u8; 32]> {
    // Descending by elapsed — stalest (closest to expiry) first.
    due.sort_unstable_by_key(|(_, elapsed)| std::cmp::Reverse(*elapsed));
    due.truncate(budget);
    due.into_iter().map(|(d, _)| d).collect()
}

/// Re-check one digest against Postgres and renew or invalidate its cache entry.
/// Returns `Ok(true)` if the key is still valid.
async fn refresh_one(pool: &Pool, digest: [u8; 32]) -> Result<bool> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let _cache_write = AUTH_CACHE_WRITES.read().await;
    // The SAME predicate the miss path uses. Deliberately not a second copy of
    // the validity rule with its own drift risk — if the miss path's notion of
    // "valid" changes, this must change with it, and keeping the text identical
    // is what makes that obvious in review.
    let row = client
        .query_opt(
            // OG-20/OG-23: the governance columns + the project JOIN are the SAME text as
            // the miss path's (`AUTH_GOVERNANCE_COLUMNS`, `AUTH_PROJECT_JOIN`), so a
            // refresh can never cache a key without the policy the miss path would read.
            &format!(
                "SELECT k.tenant_id, k.id, k.scope, k.budget_usd_monthly::text, k.rate_limit_rpm, \
                        k.budget_reset, k.expires_at, k.revoked_at, {AUTH_GOVERNANCE_COLUMNS}
                 FROM api_keys k {AUTH_PROJECT_JOIN}
                 WHERE k.lookup_hash = $1
                   AND (k.revoked_at IS NULL OR k.revoked_at > now())
                   AND (k.expires_at IS NULL OR k.expires_at > now())"
            ),
            &[&digest.as_slice()],
        )
        .await
        .context("auth refresh SELECT failed")?;

    let Some(row) = row else {
        // Revoked, expired, or deleted — drop it now rather than at TTL.
        auth_cache().invalidate(&digest).await;
        forget_last_known(digest);
        if let Ok(mut map) = active_digests().lock() {
            map.remove(&digest);
        }
        return Ok(false);
    };

    let tenant_uuid: Uuid = row.get(0);
    let id: Uuid = row.get(1);
    let scope_raw: Option<Vec<String>> = row.get(2);
    let key_scope = tracelane_shared::api_scope::KeyScope::from_column(scope_raw.as_deref());
    let budget_usd_monthly: Option<f64> = row
        .get::<_, Option<String>>(3)
        .and_then(|t| t.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0);
    let rate_limit_rpm: Option<u32> = row
        .get::<_, Option<i32>>(4)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0);
    let budget_reset = tracelane_shared::spend::BudgetReset::from_column(row.get::<_, &str>(5));

    // Re-inserting resets the TTL, which is what keeps a sparse tenant warm. It
    // also picks up a budget or rate-limit change within one interval instead of
    // one TTL — the live-proof found that both ceilings took up to 60s to bind.
    let entry = (
        tenant_uuid,
        id,
        key_scope,
        budget_usd_monthly,
        rate_limit_rpm,
        budget_reset,
        auth_deadline(row.get(6), row.get(7)),
        governance_from_row(&row, 8),
    );
    auth_cache().insert(digest, entry.clone()).await;
    remember_last_known(digest, entry);
    Ok(true)
}

/// `OG-20` / `OG-23`: the four governance columns every auth SELECT reads, in
/// [`governance_from_row`]'s order. `p.id`, not `k.project_id`: the JOIN repeats the
/// tenant predicate, so a hand-edited cross-tenant `project_id` resolves to NO project
/// (and no project policy) rather than to another tenant's.
pub(crate) const AUTH_GOVERNANCE_COLUMNS: &str = "p.id, k.environment, k.policy, p.policy";

/// The project JOIN of every auth SELECT (`k` = `api_keys`).
pub(crate) const AUTH_PROJECT_JOIN: &str =
    "LEFT JOIN projects p ON p.id = k.project_id AND p.tenant_id = k.tenant_id";

/// The `(table, column)` pairs the auth SELECT reads beyond the original key columns —
/// named so the boot check (`entitlement_cache::verify_schema`) refuses to start a
/// gateway whose control plane lacks migrations 0056/0057 (S2), instead of every API
/// key failing its lookup with a 503.
pub const AUTH_SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("api_keys", "project_id"),
    ("api_keys", "environment"),
    ("api_keys", "policy"),
    ("projects", "id"),
    ("projects", "tenant_id"),
    ("projects", "policy"),
];

/// Parse the governance columns at `base` (`AUTH_GOVERNANCE_COLUMNS`' order). Parsed
/// ONCE per cold lookup / refresh, never per request. A stored policy that does not
/// parse becomes an INVALID layer (fail-CLOSED: every request on the key is refused),
/// never "no policy".
fn governance_from_row(
    row: &tokio_postgres::Row,
    base: usize,
) -> Option<std::sync::Arc<tracelane_shared::key_policy::Governance>> {
    let project_id: Option<Uuid> = row.get(base);
    let environment: Option<String> = row.get(base + 1);
    let key_policy: Option<serde_json::Value> = row.get(base + 2);
    let project_policy: Option<serde_json::Value> = row.get(base + 3);
    tracelane_shared::key_policy::Governance::from_columns(
        project_id,
        environment,
        project_policy.as_ref(),
        key_policy.as_ref(),
    )
    .map(std::sync::Arc::new)
}

/// Start the warm-refresh task. No-op when `TRACELANE_AUTH_REFRESH_SECS=0`.
pub fn spawn_auth_cache_refresher(pool: Pool) {
    if std::env::var("TRACELANE_AUTH_REFRESH_SECS").is_ok_and(|v| v.trim() == "0") {
        tracing::info!(
            "api-key auth warm-refresh DISABLED — a key presented less often than the cache TTL              will pay a database round trip and a key-derivation verify on every request"
        );
        return;
    }
    let interval = refresh_interval_secs();
    tracing::info!(
        interval_secs = interval,
        idle_secs = active_idle_secs(),
        ttl_secs = auth_cache_ttl_secs(),
        "api-key auth warm-refresh ACTIVE — active keys are re-checked against the control plane          on this interval, which is also the revocation bound (tighter than the cache TTL)"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut warned = false;
        loop {
            ticker.tick().await;
            let digests = due_for_refresh();
            if digests.is_empty() {
                continue;
            }
            let mut failed = 0u32;
            for digest in digests {
                if let Err(err) = refresh_one(&pool, digest).await {
                    failed += 1;
                    if !warned {
                        warned = true;
                        tracing::warn!(
                            error = %err,
                            "api-key auth warm-refresh FAILING — entries will fall back to                              expiring at the cache TTL, which is the behaviour without this                              task. Requests still authenticate; they pay the cold path."
                        );
                    }
                }
            }
            if failed == 0 && warned {
                warned = false;
                tracing::warn!("api-key auth warm-refresh RECOVERED");
            }
        }
    });
}

/// Evict one cached auth result by its peppered-HMAC lookup digest. Called by the
/// `key_revoked` LISTEN handler when that listener is enabled — an OPTIMISATION
/// that shortens the window, never the bound. The bound is the TTL above (60s).
/// This used to say "so revocation is immediate, not TTL-bound", which was
/// false in production for a structural reason, not an occasional one.
pub async fn invalidate(digest: [u8; 32]) {
    auth_cache().invalidate(&digest).await;
    // An explicit invalidation (our own revoke path) is immediate: the
    // last-known answer must not outlive it.
    forget_last_known(digest);
}

/// `OG-20` / `OG-23`: commit `tx` under the auth-cache WRITE lock, then evict every
/// digest in `digests` — [`update`]'s ordering, for a write that changes the governance
/// of MANY keys at once (a project's policy). A cold lookup that read the OLD rows before
/// the commit finishes populating first, so it cannot put the old policy back.
///
/// # Errors
/// The commit failed: nothing was written and nothing is evicted.
pub async fn commit_and_invalidate(
    tx: deadpool_postgres::Transaction<'_>,
    digests: Vec<[u8; 32]>,
) -> Result<()> {
    let _cache_write = AUTH_CACHE_WRITES.write().await;
    tx.commit().await.context("commit failed")?;
    for d in digests {
        invalidate(d).await;
    }
    Ok(())
}

// `auth_cache_stats` (a `(hits, misses)` reader for the health/metrics
// surface) was deleted 2026-09-12 (B-390) — zero callers anywhere, including
// tests. Superseded 2026-09-27 by `auth_cache_counters` (above), which B-568 I6
// wires into `/health` — it has a caller from the day it exists.

// ---------------------------------------------------------------------
// Key material primitives
// ---------------------------------------------------------------------

/// The two derived shapes stored for a key body: the peppered-HMAC lookup
/// (indexed) and the Argon2id PHC (KDF verify). Built off the hot path, at
/// key-creation time only.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub lookup_hash: [u8; 32],
    pub argon2id_phc: String,
}

impl KeyMaterial {
    /// Build the full `KeyMaterial` from a raw key body. Argon2id at
    /// default params (~50ms on a modest server) so call this off the
    /// hot path — at key creation time only.
    pub fn from_body(key_body: &str) -> Result<Self> {
        Ok(Self {
            lookup_hash: peppered_lookup(key_body)?,
            argon2id_phc: argon2id_hash(key_body)?,
        })
    }
}

/// Peppered HMAC-SHA256 of the key body. Deterministic, indexable, but
/// DB-dump-resistant because regenerating it requires the pepper.
pub fn peppered_lookup(key_body: &str) -> Result<[u8; 32]> {
    let p = pepper()?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, p.expose_secret());
    let tag = hmac::sign(&key, key_body.as_bytes());
    let mut buf = [0u8; 32];
    buf.copy_from_slice(tag.as_ref());
    Ok(buf)
}

/// Argon2id hash of the key body, returned as a PHC string
/// (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`). Default RustCrypto
/// params: m=19456 (19 MiB), t=2, p=1 — the OWASP recommendation as of
/// 2024 for "low latency, low memory" servers. Verification cost is
/// ~50ms on a modest server; this is acceptable because it's paid only
/// on successful peppered-HMAC hits.
pub fn argon2id_hash(key_body: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let phc = argon
        .hash_password(key_body.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2id hash: {e}"))?
        .to_string();
    Ok(phc)
}

/// Verify a key body against a stored PHC string. Constant-time inside
/// the `argon2` crate. Returns `Ok(true)` on match, `Ok(false)` on
/// mismatch, `Err` if the PHC string itself is malformed.
pub fn argon2id_verify(phc: &str, key_body: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc).map_err(|e| anyhow!("argon2id PHC parse: {e}"))?;
    Ok(Argon2::default()
        .verify_password(key_body.as_bytes(), &parsed)
        .is_ok())
}

/// `argon2id_verify` moved OFF the tokio worker threads.
///
/// SRE audit finding 9, 2026-09-04. The verify is ~35 ms of CPU at the default params
/// (m=19456, t=2, p=1 — measured on this box: min 28.9 / median 35.3 / max 45.4 ms),
/// and it ran inline on the async task. The gateway is a bare `#[tokio::main]`, so it
/// gets one worker per core — **FOUR on prod**, confirmed from `/proc/<pid>/task` on
/// the production node (4x `tokio-rt-worker`, and ZERO blocking-pool threads, which is its own
/// evidence that `spawn_blocking` was unused). An inline verify therefore parks a
/// QUARTER of the runtime for ~35 ms, including whatever else lives in this process —
/// the audit head-writer consumer among it.
///
/// Scope, stated so the fix is not over-read: this is a LATENCY defect, not a DoS
/// amplifier. The KDF only runs after a peppered-HMAC `lookup_hash` row match, which
/// an attacker cannot produce without `TRACELANE_APIKEY_PEPPER` — the `let Some(row)
/// = row else { return Ok(None) }` above returns first. It is reached on a COLD auth
/// only (cache miss AND no fresh last-known answer), which prod hits more often than
/// most deployments because it sets `TRACELANE_AUTH_REFRESH_SECS=0`, disabling the
/// warm refresher that would otherwise keep entries hot.
///
/// `block_in_place` is deliberately NOT used: it panics on a current-thread runtime,
/// and this crate's tests default to `#[tokio::test]`.
async fn argon2id_verify_blocking(phc: String, key_body: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || argon2id_verify(&phc, &key_body))
        .await
        .map_err(|e| anyhow::anyhow!("argon2id verify task join failed: {e}"))?
}

// ---------------------------------------------------------------------
// Key generation (gateway-side mint path)
// ---------------------------------------------------------------------

/// Base62 alphabet — digits, then upper, then lower. MUST match the web
/// minter (`apps/web/lib/api-key-hash.ts`) so a `tlane_` key looks identical
/// regardless of which surface minted it.
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// A key body is 32 random bytes rendered big-endian base62, left-padded to 43
/// chars (62^43 ≳ 2^256 ≥ any 32-byte value, so 43 is the fixed width).
const KEY_BODY_LEN: usize = 43;
/// Non-secret display prefix stored in `key_prefix` — the first chars of the
/// body (the UI shows `tlane_<prefix>…`). Matches the web `body.slice(0, 6)`.
const KEY_PREFIX_LEN: usize = 6;

/// Render 32 bytes as a big-endian base62 string, left-padded to
/// [`KEY_BODY_LEN`]. Byte-identical to the web minter's `toBase62`: interpret
/// the bytes as one 256-bit big-endian integer and repeatedly divmod 62.
fn to_base62(bytes: &[u8; 32]) -> String {
    let mut num = *bytes;
    let mut digits = Vec::with_capacity(KEY_BODY_LEN);
    while num.iter().any(|&b| b != 0) {
        let mut remainder = 0u16;
        for byte in num.iter_mut() {
            let acc = (remainder << 8) | u16::from(*byte);
            *byte = (acc / 62) as u8;
            remainder = acc % 62;
        }
        digits.push(BASE62[remainder as usize]);
    }
    // `digits` is least-significant-first; left-pad with '0' (base62 zero) then
    // reverse to most-significant-first — mirrors JS `padStart(43, "0")`.
    while digits.len() < KEY_BODY_LEN {
        digits.push(b'0');
    }
    digits.reverse();
    String::from_utf8(digits).expect("BASE62 is ASCII")
}

/// Generate a fresh key body (the part after the `tlane_` prefix): 32 CSPRNG
/// bytes as base62. Uses `ring`'s `SystemRandom` (the crypto RNG mandated by
/// CLAUDE.md — no `openssl`, no ad-hoc entropy).
///
/// # Errors
/// Fails only if the OS RNG is unavailable (`ring::error::Unspecified`).
fn generate_key_body() -> Result<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("system RNG unavailable while minting API key"))?;
    Ok(to_base62(&bytes))
}

/// A freshly minted key: the persisted row plus the one-time raw secret.
///
/// `raw_key` (`tlane_<body>`) is returned to the API caller exactly once and is
/// never stored or re-derivable — only its `lookup_hash`/`argon2id_phc` live in
/// the DB. It is a credential: never log it, never persist it.
#[derive(Debug)]
pub struct MintedKey {
    pub api_key: ApiKey,
    pub key_prefix: String,
    pub raw_key: String,
}

pub struct RotatedKey {
    pub minted: MintedKey,
    pub options: MintOptions,
    pub revoked_at: DateTime<Utc>,
}

/// Read the rotation default off the traffic hot path. Fail CLOSED if unseeded.
/// # Errors
/// Missing, malformed or unreadable policy refuses the default; no literal fallback.
#[tracing::instrument(skip(pool))]
pub async fn rotation_grace_hours(pool: &Pool) -> Result<i64> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT value::text FROM billing_policy WHERE key = 'key_rotation_grace_hours'",
            &[],
        )
        .await?
        .ok_or_else(|| anyhow!("rotation policy unavailable"))?;
    let hours: i64 = serde_json::from_str(row.get::<_, &str>(0))?;
    if !valid_rotation_grace(hours) {
        anyhow::bail!("invalid rotation policy");
    }
    Ok(hours)
}

pub fn valid_rotation_grace(hours: i64) -> bool {
    hours >= 0
        && chrono::Duration::try_hours(hours)
            .and_then(|duration| Utc::now().checked_add_signed(duration))
            .is_some()
}

/// Atomically create a successor, schedule the source's retirement and audit it.
/// Source settings (including legacy NULL scope and the original minter) are
/// copied in SQL. The source row lock makes concurrent rotations single-winner.
/// # Errors
/// Fail CLOSED: any failure rolls back all three writes; raw material is never logged.
#[tracing::instrument(skip(pool, tenant, actor), fields(tenant_id = %tenant))]
pub async fn rotate(
    pool: &Pool,
    tenant: &TenantId,
    id: Uuid,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
    grace_hours: i64,
) -> Result<Option<RotatedKey>> {
    if !valid_rotation_grace(grace_hours) {
        anyhow::bail!("invalid rotation grace");
    }
    let body = secrecy::SecretString::from(generate_key_body()?);
    let material = KeyMaterial::from_body(body.expose_secret())?;
    let prefix: String = body.expose_secret().chars().take(KEY_PREFIX_LEN).collect();
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let source = tx.query_opt(
        "SELECT lookup_hash FROM api_keys WHERE tenant_id = $1 AND id = $2
         AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > clock_timestamp()) FOR UPDATE",
        &[tenant.as_uuid(), &id],
    ).await?;
    let Some(source) = source else {
        return Ok(None);
    };
    let digest: Vec<u8> = source.get(0);
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| anyhow!("invalid lookup digest"))?;
    let row = tx.query_one(
        // OG-20 / OG-23: the successor inherits the project, the environment and the
        // POLICY — a rotation must never shed a restriction.
        "INSERT INTO api_keys (tenant_id, name, lookup_hash, argon2id_phc, key_prefix, minted_by,
             scope, expires_at, budget_usd_monthly, rate_limit_rpm, budget_reset, velocity_breaker,
             project_id, environment, policy)
         SELECT tenant_id, name, $3, $4, $5, minted_by, scope, expires_at, budget_usd_monthly,
             rate_limit_rpm, budget_reset, velocity_breaker, project_id, environment, policy
             FROM api_keys WHERE tenant_id = $1 AND id = $2
         RETURNING id, name, created_at, scope, expires_at, budget_usd_monthly::text,
             rate_limit_rpm, budget_reset, velocity_breaker, project_id, environment, policy",
        &[tenant.as_uuid(), &id, &material.lookup_hash.as_slice(), &material.argon2id_phc, &prefix],
    ).await?;
    let successor_id: Uuid = row.get(0);
    // clock_timestamp avoids consuming the grace window while waiting for a lock.
    let revoked_at: DateTime<Utc> = tx
        .query_one(
            "UPDATE api_keys SET revoked_at = clock_timestamp() + $3::bigint * interval '1 hour'
         WHERE tenant_id = $1 AND id = $2 RETURNING revoked_at",
            &[tenant.as_uuid(), &id, &grace_hours],
        )
        .await?
        .get(0);
    // OG-35: through the ONE writer (request id, role, method; redaction). Same
    // transaction as before — a refused audit row still rolls the rotation back.
    crate::db::control_audit::record(
        &tx,
        tenant,
        &actor.as_actor(),
        crate::db::control_audit::Change {
            action: "api_key.rotate",
            target_type: "api_key",
            target_id: id.to_string(),
            before: Some(serde_json::json!({ "revokedAt": null })),
            after: Some(serde_json::json!({
                "successorId": successor_id.to_string(),
                "revokedAt": revoked_at.to_rfc3339(),
            })),
        },
    )
    .await?;
    let options = MintOptions {
        scope: row.get(3),
        expires_at: row.get(4),
        budget_usd_monthly: row
            .get::<_, Option<String>>(5)
            .map(|v| v.parse())
            .transpose()?,
        rate_limit_rpm: row.get(6),
        budget_reset: Some(tracelane_shared::spend::BudgetReset::from_column(
            row.get(7),
        )),
        velocity_breaker: row.get(8),
        project_id: row.get(9),
        environment: row.get(10),
        policy: row.get(11),
    };
    // A cold lookup that started before this transaction must finish populating
    // before invalidation. No request can restore its pre-rotation cache entry.
    let _cache_write = AUTH_CACHE_WRITES.write().await;
    tx.commit().await?;
    invalidate(digest).await;
    note_minted(&material.lookup_hash).await;
    Ok(Some(RotatedKey {
        minted: MintedKey {
            api_key: ApiKey {
                id: successor_id,
                name: row.get(1),
                created_at: row.get(2),
                scope: options.scope.clone(),
                expires_at: options.expires_at,
            },
            key_prefix: prefix,
            // `MintedKey.raw_key` is the ONE-TIME reveal: `String` by design, because
            // it is serialized straight into the response body. The owned copy IS the
            // destination here, not an accident — the mint path does the same at the
            // sibling site below. See the marker on the line itself.
            raw_key: format!("tlane_{}", body.expose_secret()), // banned-pattern-allow: the one-time reveal is serialized to the response; String is the destination
        },
        options,
        revoked_at,
    }))
}

/// Mint a new API key end-to-end for `tenant_id`: generate the body, derive the
/// [`KeyMaterial`] (peppered HMAC + Argon2id), and insert the row. The Argon2id
/// KDF (~50ms) runs here, at creation time only — never on the request path.
///
/// This is the gateway-side mint path: the Cloudflare Workers runtime
/// cannot run the web minter's WASM Argon2 reliably, so the dashboard proxies
/// key creation here where RustCrypto Argon2 runs natively. The derived
/// material is byte-identical to the web minter (same pepper, same params), so
/// keys from either surface verify through `lookup_tenant_by_key_body`.
///
/// # Errors
/// RNG failure, pepper-not-initialized, Argon2id hashing, or the DB insert —
/// including its OG-35 `api_key.create` audit row (fail-CLOSED: no row, no key).
///
/// The actor is the minter as a SYSTEM actor (`minted_by`, else `system`); the
/// HTTP path calls [`mint_as`] with the full request actor instead. Both record.
pub async fn mint(
    pool: &Pool,
    tenant_id: &TenantId,
    name: &str,
    minted_by: Option<&str>,
    opts: MintOptions,
) -> Result<MintedKey> {
    let actor = crate::db::control_audit::Actor::system(minted_by.unwrap_or("system"));
    mint_as(pool, tenant_id, name, minted_by, opts, &actor).await
}

/// [`mint`], recording `actor` (role, method, request id, address) on the
/// `api_key.create` row — the `POST /v1/keys` path.
///
/// # Errors
/// As [`mint`].
pub async fn mint_as(
    pool: &Pool,
    tenant_id: &TenantId,
    name: &str,
    minted_by: Option<&str>,
    opts: MintOptions,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
) -> Result<MintedKey> {
    let body = generate_key_body()?;
    let material = KeyMaterial::from_body(&body)?;
    let key_prefix: String = body.chars().take(KEY_PREFIX_LEN).collect();
    let api_key = create_as(
        pool,
        tenant_id,
        &material,
        name,
        &key_prefix,
        minted_by,
        &opts,
        actor,
    )
    .await?;
    Ok(MintedKey {
        api_key,
        key_prefix,
        raw_key: format!("tlane_{body}"),
    })
}

// ---------------------------------------------------------------------
// Public data model
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ApiKey {
    /// The `id` PK column (uuid, DB-generated).
    pub id: Uuid,
    // `tenant_id`, `last_used_at`, `revoked_at` (deleted 2026-09-12, B-390) —
    // never read after construction; `create`'s sole caller
    // (`crates/gateway/tests/postgres_tenant_integration.rs`) only reads
    // `.id` off the returned value. The `RETURNING` clause and the SQL
    // column list in `create` are unchanged — only the struct fields and
    // their three positional `row.get(N)` assignments were removed.
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// A13. `None` = the legacy full-surface key; see `api_scope::KeyScope`.
    pub scope: Option<Vec<String>>,
    /// A13. `None` = never expires.
    pub expires_at: Option<DateTime<Utc>>,
}

/// A13 mint options. Every field is optional at the wire, but the mint path
/// turns an omitted `scope` into an EXPLICIT full set rather than SQL NULL —
/// see [`mint`] for why that distinction is the whole point.
#[derive(Debug, Clone, Default)]
pub struct MintOptions {
    pub scope: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    /// USD/month. Carried as `f64` and bound as TEXT with a `::numeric` cast —
    /// tokio-postgres has no native NUMERIC mapping without pulling in
    /// `rust_decimal`, and the same bind-as-text-then-cast shape is already the
    /// house workaround for PG enums. Postgres does the parse, and
    /// `api_keys_budget_nonneg_chk` does the range check, so a bad value is a
    /// constraint violation rather than a silently truncated number.
    ///
    /// A13 RECORDED and REPORTED the budget and enforced nothing. GWY-43 made it
    /// a cut-off: `chat_completions_handler` returns 402 `key_budget_exceeded`
    /// once the month's recorded spend reaches it (`server.rs`, Step 2c). The
    /// A13 note that said "does not enforce a cut-off" outlived the code that
    /// justified it — CLAUDE.md §17, the doc is the defect.
    pub budget_usd_monthly: Option<f64>,
    /// GWY-43. Requests-per-minute ceiling for this ONE key. `None` = inherit
    /// the tenant's plan tier, which is what every key did before GWY-43.
    ///
    /// Typed as the column's own `i32` (`rate_limit_rpm integer`), so unlike the
    /// budget this binds NATIVELY and needs no `::text::` detour — tokio-postgres
    /// maps `i32` to `int4` directly. The mint route rejects 0 and out-of-range
    /// values at the edge so the caller gets a 400 naming the field;
    /// `api_keys_rate_limit_rpm_positive_chk` (migration 0029) is the backstop
    /// for any other caller.
    pub rate_limit_rpm: Option<i32>,
    /// BILL-01 A3. `None` ⇒ the column's own `DEFAULT 'monthly'` — every key
    /// minted before A3 (and any caller that does not set this) keeps the
    /// pre-A3 monthly cadence.
    pub budget_reset: Option<tracelane_shared::spend::BudgetReset>,
    /// BILL-01 A3. Opt IN to the velocity breaker for this key. `false` by
    /// default (the column's own `DEFAULT false`) — a customer must ask for
    /// anomaly-triggered promotion freezes, not receive them unasked.
    pub velocity_breaker: bool,
    /// OG-23: the project to mint the key into (live, this tenant — checked by
    /// [`create`]) and its environment label.
    pub project_id: Option<Uuid>,
    pub environment: Option<String>,
    /// OG-20: the key's own policy, ALREADY validated and canonical.
    pub policy: Option<serde_json::Value>,
}

/// OG-23: why [`create`] refused an assignment. Typed so the mint route answers 404 / 409
/// instead of a 500.
#[derive(Debug, thiserror::Error)]
pub enum AssignmentError {
    #[error("project not found")]
    ProjectNotFound,
    #[error("environment `{0}` is not one of the project's environments")]
    EnvironmentNotInProject(String),
    #[error("an environment needs a project")]
    EnvironmentNeedsProject,
}

impl MintOptions {
    // A13 — the NULL-vs-explicit distinction used to be decided here, by
    // `with_default_scope()`: an omitted `scope` was filled in with
    // `Scope::default_mint_set()` = `{chat, read, ingest}`.
    //
    // **SUPERSEDED 2026-08-22 by founder ruling R73 — the mint route now REQUIRES
    // a scope and 400s on an omitted one** (`key_routes.rs`, the `None` arm of the
    // scope match). Migration 0024's hand-off note asked for exactly that from the
    // start; the deviation recorded here argued that requiring it "would 400 every
    // existing caller of `POST /v1/keys` the moment this deploys, the dashboard
    // proxy included."
    //
    // THAT ARGUMENT WAS NEVER MEASURED, AND MEASURING IT REFUTED IT: of 37 keys
    // ever minted on prod, all 14 carrying an explicit scope are revoked, so zero
    // live keys came through the default; the dashboard gates submit on at least
    // one scope; and self-host cannot mint at all (no Postgres control plane).
    // The prose defending the value was the evidence the value was unmeasured —
    // `docs/reference/TRAPS.md` §40, in a security default rather than a duration.
    //
    // NOTE THE SCOPE OF THIS CHANGE, because it is narrower than it looks: it
    // governs only what NEW keys are minted with. The 23 pre-existing rows holding
    // SQL NULL still resolve to `KeyScope::LegacyFullSurface`, which `allows()`
    // answers TRUE for every scope INCLUDING `admin`. That is the wider grant and
    // it is a separate, un-taken decision.
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

/// Bind shape for `budget_usd_monthly`. **The `::text::` half is load-bearing.**
///
/// `budget_text` is an `Option<String>`. Written as a bare `$9::numeric`,
/// Postgres infers the parameter type as `numeric` and tokio-postgres refuses to
/// serialize a Rust `String` into it — `error serializing parameter 8` — **on
/// every call, including when the value is `None`**, because the type check
/// precedes any NULL handling. That shipped in `5ab66bd0` (A13, 2026-08-12) and
/// took `POST /v1/keys` down completely: every mint returned 500, the dashboard
/// showed 502, and **no customer could create an API key for two days.**
///
/// The fix is to bind as `text` and let the DB coerce. This is the *identical*
/// rule `db/tenants.rs`'s `PLAN_ENUM_CAST` already wrote down — *"NEVER write a
/// bare `$N::plan` for a string parameter"* — and the comment that introduced
/// this bug cited that very workaround while dropping the `::text::` half that
/// does the work. A lesson with no consumer on the second site.
///
/// Pinned by `tests::budget_numeric_cast_routes_through_text` and falsified for
/// real against Postgres by `budget_param_serialization_contract`.
const BUDGET_NUMERIC_CAST: &str = "::text::numeric";

/// Insert a new API key. The caller has already generated the body and
/// derived the `KeyMaterial`; `key_prefix` is the non-secret display prefix
/// (e.g. the first chars of the body). The raw key is returned to the API
/// caller exactly once at creation time and is never re-derivable.
///
/// `id` is DB-generated (`gen_random_uuid()`); the row is returned.
///
/// NOTE: production minting happens in the web app
/// (`apps/web/app/api/settings/api-keys`); this gateway-side `create` is used by
/// integration tests and any future gateway-side mint path. Both must produce
/// identical `lookup_hash`/`argon2id_phc` from the key body.
///
/// # Errors
/// Fail-CLOSED (OG-35): the insert and its `api_key.create` audit row are ONE
/// transaction — a refused audit row means no key exists.
// The raw writer the real-Postgres crate (`tests/postgres_tenant_integration.rs`,
// which mounts this module by `#[path]`) drives directly; the gateway binary mints
// through `mint` / `mint_as` → `create_as`, so in THIS crate it has no caller.
#[allow(dead_code)]
pub async fn create(
    pool: &Pool,
    tenant_id: &TenantId,
    material: &KeyMaterial,
    name: &str,
    key_prefix: &str,
    minted_by: Option<&str>,
    opts: &MintOptions,
) -> Result<ApiKey> {
    let actor = crate::db::control_audit::Actor::system(minted_by.unwrap_or("system"));
    create_as(
        pool, tenant_id, material, name, key_prefix, minted_by, opts, &actor,
    )
    .await
}

/// [`create`], recording `actor` on the `api_key.create` row.
///
/// # Errors
/// As [`create`] — fail-CLOSED.
// Eight inputs, each a distinct column or the audit actor; a params struct would
// only rename the same list (OG-35 added the actor).
#[allow(clippy::too_many_arguments)]
pub async fn create_as(
    pool: &Pool,
    tenant_id: &TenantId,
    material: &KeyMaterial,
    name: &str,
    key_prefix: &str,
    minted_by: Option<&str>,
    opts: &MintOptions,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
) -> Result<ApiKey> {
    // OG-35: the key and its `api_key.create` row commit together, or neither does.
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    // OG-23: the project must be a LIVE project of THIS tenant, and the environment one
    // of its own. (An archive racing this INSERT is harmless: an archived project still
    // governs its keys.)
    match (opts.project_id, &opts.environment) {
        (None, None) => {}
        (None, Some(_)) => return Err(AssignmentError::EnvironmentNeedsProject.into()),
        (Some(project), env) => {
            let Some(envs) = live_project_environments(&tx, tenant_id, project).await? else {
                return Err(AssignmentError::ProjectNotFound.into());
            };
            if let Some(e) = env.as_ref().filter(|e| !envs.contains(e)) {
                return Err(AssignmentError::EnvironmentNotInProject(e.clone()).into());
            }
        }
    }
    let budget_text: Option<String> = opts.budget_usd_monthly.map(|b| format!("{b:.4}"));
    // `budget_reset` binds as TEXT into a `CHECK`-constrained column, same
    // shape as the `plan` enum cast (`db/tenants.rs::PLAN_ENUM_CAST`) — a bare
    // Rust `&str` serializes fine into `text`, so no `::text::` detour is
    // needed here (unlike the `numeric` budget above); `None` lets the
    // column's own `DEFAULT 'monthly'` apply.
    let budget_reset: Option<&'static str> = opts
        .budget_reset
        .map(tracelane_shared::spend::BudgetReset::as_str);
    let sql = format!(
        // `$10` is bare on purpose: `rate_limit_rpm` is `integer`, and an `i32`
        // binds to `int4` natively. Only the `numeric` column needs the
        // `::text::` detour above. `$11`/`$12` (budget_reset/velocity_breaker)
        // are likewise bare — `text` and `boolean` both bind natively.
        "INSERT INTO api_keys (tenant_id, name, lookup_hash, argon2id_phc, key_prefix, minted_by, \
                               scope, expires_at, budget_usd_monthly, rate_limit_rpm, \
                               budget_reset, velocity_breaker, project_id, environment, policy)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9{BUDGET_NUMERIC_CAST}, $10, \
                 COALESCE($11, 'monthly'), $12, $13, $14, $15)
         RETURNING id, tenant_id, name, created_at, last_used_at, revoked_at, scope, expires_at"
    );
    let row = tx
        .query_one(
            &sql,
            &[
                tenant_id.as_uuid(),
                &name,
                &material.lookup_hash.as_slice(),
                &material.argon2id_phc,
                &key_prefix,
                &minted_by,
                &opts.scope,
                &opts.expires_at,
                &budget_text,
                &opts.rate_limit_rpm,
                &budget_reset,
                &opts.velocity_breaker,
                &opts.project_id,
                &opts.environment,
                &opts.policy,
            ],
        )
        .await
        .context("INSERT INTO api_keys failed")?;
    let id: Uuid = row.get(0);
    // Never the body, the lookup digest or the PHC: the display prefix is the one
    // key-derived field, and it is already what the dashboard shows.
    crate::db::control_audit::record(
        &tx,
        tenant_id,
        &actor.as_actor(),
        crate::db::control_audit::Change {
            action: "api_key.create",
            target_type: "api_key",
            target_id: id.to_string(),
            before: None,
            after: Some(serde_json::json!({
                "name": name,
                "keyPrefix": key_prefix,
                "mintedBy": minted_by,
                "scope": opts.scope,
                "expiresAt": opts.expires_at.map(|t| t.to_rfc3339()),
                "budgetUsdMonthly": opts.budget_usd_monthly,
                "rateLimitRpm": opts.rate_limit_rpm,
                "budgetReset": budget_reset,
                "velocityBreaker": opts.velocity_breaker,
                "projectId": opts.project_id,
                "environment": opts.environment,
                "policy": opts.policy,
            })),
        },
    )
    .await
    .context("admin_audit_log api_key.create insert failed")?;
    tx.commit().await.context("api_keys create commit failed")?;
    // B-383 (f): a probe of this exact key before it existed would have left a
    // negative entry; a freshly minted key must authenticate at once.
    note_minted(&material.lookup_hash).await;
    Ok(ApiKey {
        id: row.get(0),
        name: row.get(2),
        created_at: row.get(3),
        scope: row.get(6),
        expires_at: row.get(7),
    })
}

/// Hot-path lookup. Returns `Ok(Some((tenant, api_key_id)))` on success — the
/// caller uses the row `id` (never a secret-derived value) for the `sub` claim
/// (ADR-042 / security review M-2). `Ok(None)` when no row matches (caller
/// surfaces 401), `Err` for real DB failures (caller surfaces 500).
///
/// Peppered lookup (`lookup_hash`) then Argon2id PHC verify. A row whose
/// `argon2id_phc` is NULL is rejected — the strong scheme always stores both,
/// so a NULL is a malformed/legacy row that must not authenticate without the
/// KDF check. `last_used_at` is updated best-effort on success.
pub async fn lookup_tenant_by_key_body(pool: &Pool, key_body: &str) -> Result<Option<KeyAuth>> {
    lookup_tenant_by_key_body_at(pool, key_body, Utc::now()).await
}

pub(crate) async fn lookup_tenant_by_key_body_at(
    pool: &Pool,
    key_body: &str,
    now: DateTime<Utc>,
) -> Result<Option<KeyAuth>> {
    lookup_with_known(pool, key_body, now, known_keys()).await
}

async fn lookup_with_known(
    pool: &Pool,
    key_body: &str,
    now: DateTime<Utc>,
    known: Option<&KnownKeys>,
) -> Result<Option<KeyAuth>> {
    let lookup = peppered_lookup(key_body)?;

    // fix B: warm-cache hit — the peppered-HMAC digest matched a previously
    // authenticated key. Skip the PG SELECT + the ~50ms Argon2id verify.
    if let Some((
        tenant,
        key_id,
        key_scope,
        budget_usd_monthly,
        rate_limit_rpm,
        budget_reset,
        valid_until,
        governance,
    )) = auth_cache().get(&lookup).await
    {
        // Fail CLOSED at the deadline even while the cache TTL is live.
        if valid_until.is_some_and(|deadline| now >= deadline) {
            return Ok(None);
        }
        let hits = AUTH_CACHE_HIT_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        let miss = AUTH_CACHE_MISS_TOTAL.load(Ordering::Relaxed);
        // Loud, bounded hit-rate signal (once per 1000 lookups).
        if (hits + miss).is_multiple_of(1000) {
            tracing::info!(
                hits,
                miss,
                hit_rate_pct = hits * 100 / (hits + miss).max(1),
                "api-key auth cache hit-rate"
            );
        }
        // Mark it live so the refresher keeps renewing it. Done on the HIT path
        // too, not just the miss: a key that only ever hits would otherwise age
        // out of the active set and fall back to the cold path it just avoided.
        note_active(lookup);
        return Ok(Some(KeyAuth {
            tenant_id: TenantId::from_jwt_claim(tenant),
            key_id,
            scope: key_scope,
            budget_usd_monthly,
            rate_limit_rpm,
            budget_reset,
            governance,
            path: LookupPath::Warm,
        }));
    }
    AUTH_CACHE_MISS_TOTAL.fetch_add(1, Ordering::Relaxed);
    // B-383 (f): a key that was NOT FOUND within the last 30 s is not found now
    // either — answer without a round trip.
    if negative_cache().get(&lookup).await.is_some() {
        AUTH_NEGATIVE_HIT_TOTAL.fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    }
    if let Some((
        tenant,
        key_id,
        key_scope,
        budget_usd_monthly,
        rate_limit_rpm,
        budget_reset,
        valid_until,
        governance,
    )) = last_known_fresh_enough(lookup)
    {
        // Stale grants never extend known expiry or scheduled revocation.
        if valid_until.is_some_and(|deadline| now >= deadline) {
            return Ok(None);
        }
        // Serve the last-known answer NOW; re-check the row off the request path.
        AUTH_STALE_SERVED_TOTAL.fetch_add(1, Ordering::Relaxed);
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(err) = refresh_one(&pool, lookup).await {
                tracing::debug!(error = %err, "off-path auth re-check failed; the entry ages out on its own");
            }
        });
        note_active(lookup);
        return Ok(Some(KeyAuth {
            tenant_id: TenantId::from_jwt_claim(tenant),
            key_id,
            scope: key_scope,
            budget_usd_monthly,
            rate_limit_rpm,
            budget_reset,
            governance,
            path: LookupPath::Stale,
        }));
    }

    lookup_cold_stage(pool, key_body, lookup, now, known).await
}

/// The miss path past every cache, against an explicit valid-key set — what
/// [`lookup_tenant_by_key_body`] runs with the process's set, and what the
/// real-Postgres integration test runs with its OWN set over its own database
/// (the process set would answer for a different database).
///
/// # Errors
/// As [`lookup_tenant_by_key_body`].
///
/// Called only from `crates/gateway/tests/postgres_tenant_integration.rs` (a
/// separate crate, invisible to this crate's `dead_code` analysis) — allowed the
/// same way as [`revoke`].
#[allow(dead_code)]
pub async fn lookup_tenant_by_key_body_with(
    pool: &Pool,
    key_body: &str,
    known: Option<&KnownKeys>,
) -> Result<Option<KeyAuth>> {
    lookup_with_known(pool, key_body, Utc::now(), known).await
}

/// The ONE store-reaching stage. The valid-key set answers first (rev4 H1 d): a
/// digest absent from a read that started after this request arrived is a 401 with
/// no per-key lookup; a present one is looked up under a slot only; when the set
/// cannot answer, the request's per-source bucket and a slot both apply (B-594).
async fn lookup_cold_stage(
    pool: &Pool,
    key_body: &str,
    lookup: [u8; 32],
    now: DateTime<Utc>,
    known: Option<&KnownKeys>,
) -> Result<Option<KeyAuth>> {
    let gating = match known {
        None => Gating::Source,
        Some(k) => {
            let max = k.cfg.max;
            match k
                .classify(&lookup, |since| fetch_known_keys(pool, since, max))
                .await
            {
                Membership::Present => Gating::Known,
                Membership::Absent => {
                    AUTH_KNOWN_KEY_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                    negative_cache().insert(lookup, ()).await;
                    return Ok(None);
                }
                Membership::Unknown => Gating::Source,
            }
        }
    };
    gated_cold_lookup(gating, |mark| {
        cold_lookup(pool, key_body, lookup, now, mark)
    })
    .await
}

/// The Postgres stage of [`lookup_tenant_by_key_body_at`]: SELECT by the
/// peppered digest, Argon2id verify, populate the caches. `Ok(None)` = no valid
/// key (and the miss is remembered); `Err` = the store failed.
async fn cold_lookup(
    pool: &Pool,
    key_body: &str,
    lookup: [u8; 32],
    now: DateTime<Utc>,
    mark: SqlMark,
) -> Result<Option<KeyAuth>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    // From here on SQL runs: a failure or a cancellation keeps the source's token.
    mark.started();

    let cache_write = AUTH_CACHE_WRITES.read().await;

    // A13: `scope` and `expires_at` are read HERE, in the same round-trip that
    // already authenticates the key — not re-derived per route. `expires_at` is
    // filtered in SQL alongside `revoked_at` so an expired key is indistinguishable
    // from a revoked one to everything downstream: same NULL row, same 401, no
    // second code path to keep in step.
    //
    // Enforced in the gateway rather than by the DB (no constraint can express
    // "reject at read time"), which means a clock skew between Neon and the
    // gateway is the failure mode — `now()` is Postgres's, so both sides of the
    // comparison come from the same clock. That is deliberate.
    let row = client
        .query_opt(
            // GWY-43 adds `budget_usd_monthly` and `rate_limit_rpm` to the SAME
            // round trip. `budget_usd_monthly` is `numeric`, which tokio-postgres
            // cannot deserialize into f64 directly, so it is cast to text here
            // and parsed — the mirror image of the `::text::numeric` cast the
            // INSERT side needs, and for the same reason.
            // OG-20/OG-23: the project JOIN and the governance columns ride the SAME
            // round trip (no second query on a cold key).
            &format!(
                "SELECT k.tenant_id, k.id, k.argon2id_phc, k.scope, k.expires_at,
                        k.budget_usd_monthly::text, k.rate_limit_rpm, k.budget_reset, k.revoked_at,
                        {AUTH_GOVERNANCE_COLUMNS}
                 FROM api_keys k {AUTH_PROJECT_JOIN}
                 WHERE k.lookup_hash = $1
                   AND (k.revoked_at IS NULL OR k.revoked_at > now())
                   AND (k.expires_at IS NULL OR k.expires_at > now())"
            ),
            &[&lookup.as_slice()],
        )
        .await
        .context("SELECT api_keys by lookup_hash failed")?;

    let Some(row) = row else {
        // B-383 (f): remember the miss. Revoked and expired keys land here too
        // (the SELECT filters them), which is right: a revoked key stays revoked.
        negative_cache().insert(lookup, ()).await;
        return Ok(None);
    };

    let tenant_uuid: Uuid = row.get(0);
    let id: Uuid = row.get(1);
    let phc: Option<String> = row.get(2);
    let scope_raw: Option<Vec<String>> = row.get(3);
    let key_scope = tracelane_shared::api_scope::KeyScope::from_column(scope_raw.as_deref());
    // A NULL budget is uncapped. A budget that will not parse is ALSO treated as
    // uncapped rather than as zero: a mis-read that silently refuses every
    // request on a working key is worse than a budget that fails to bite, and
    // `api_keys_budget_nonneg_chk` already rejects a negative at write time.
    let budget_usd_monthly: Option<f64> = row
        .get::<_, Option<String>>(5)
        .and_then(|t| t.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0);
    let rate_limit_rpm: Option<u32> = row
        .get::<_, Option<i32>>(6)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0);
    let budget_reset = tracelane_shared::spend::BudgetReset::from_column(row.get::<_, &str>(7));

    // KDF verify — defense in depth. The peppered HMAC already authenticated,
    // but the strong scheme REQUIRES the Argon2id PHC: a row with a NULL or
    // failing PHC is rejected (a tampered row, or a row that should
    // have been re-minted).
    let phc_ok = match phc {
        Some(p) => match argon2id_verify_blocking(p, key_body.to_string()).await {
            Ok(ok) => ok,
            Err(e) => {
                // Malformed PHC on a lookup_hash hit = a corrupted/tampered row,
                // not a normal auth miss — surface it for operators. No key
                // material logged; only the row id (L-3).
                tracing::error!(
                    api_key_id = %id,
                    error = %e,
                    "argon2id PHC parse failed — possible DB-row corruption"
                );
                false
            }
        },
        None => false,
    };
    if !phc_ok {
        tracing::error!(
            api_key_id = %id,
            "lookup_hash matched but argon2id_phc missing/failed — rejecting"
        );
        return Ok(None);
    }

    let valid_until = auth_deadline(row.get(4), row.get(8));
    let governance = governance_from_row(&row, 9);
    if valid_until.is_some_and(|deadline| now.max(Utc::now()) >= deadline) {
        return Ok(None);
    }
    // Populate the warm cache for subsequent requests with this key (fix B).
    // A13: the SCOPE is cached with the identity. Caching only (tenant, key_id)
    // would force the caller to re-derive a capability it cannot see on a warm
    // hit — and the only available default is full-surface, which would be a
    // privilege escalation on every cached request.
    let entry = (
        tenant_uuid,
        id,
        key_scope.clone(),
        budget_usd_monthly,
        rate_limit_rpm,
        budget_reset,
        valid_until,
        governance.clone(),
    );
    auth_cache().insert(lookup, entry.clone()).await;
    remember_last_known(lookup, entry);
    note_active(lookup);
    // ponytail: last_used_at is refreshed only on the (cold) miss path — a
    // warm-cached key updates it at most every 15m (TTL refill). Fine for a
    // display field; a spawned touch per warm hit would put a PG write back on
    // every request, defeating the cache.
    drop(cache_write); // Never wait on the source row while blocking rotation commit.
    touch_last_used(&client, id).await;
    Ok(Some(KeyAuth {
        tenant_id: TenantId::from_jwt_claim(tenant_uuid),
        key_id: id,
        scope: key_scope,
        budget_usd_monthly,
        rate_limit_rpm,
        budget_reset,
        governance,
        path: LookupPath::Cold,
    }))
}

async fn touch_last_used(client: &deadpool_postgres::Client, id: Uuid) {
    let _ = client
        .execute(
            "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
            &[&id],
        )
        .await;
}

/// Revoke a key by id. Idempotent — repeated revoke is a no-op.
///
/// Called only from `crates/gateway/tests/postgres_tenant_integration.rs`
/// (a separate crate, invisible to this crate's own `dead_code` analysis).
/// Allow justified the same way as `db::apply_migrations` (B-390, 2026-09-12).
#[allow(dead_code)]
pub async fn revoke(pool: &Pool, id: Uuid) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    client
        .execute(
            "UPDATE api_keys SET revoked_at = NOW()
             WHERE id = $1 AND (revoked_at IS NULL OR revoked_at > NOW())",
            &[&id],
        )
        .await
        .context("UPDATE api_keys revoke failed")?;
    Ok(())
}

// ---------------------------------------------------------------------
// SET-38 — edit a key's limits in place, read one key, revoke through the gateway
// ---------------------------------------------------------------------

/// Who may edit a key. The ROUTE decides this from the validated claims; THIS
/// module enforces it against the row's `minted_by`, under the row lock, so the
/// check and the write see the same row.
#[derive(Debug, Clone, Copy)]
pub enum KeyEditor<'a> {
    /// A verified owner, or the self-host operator.
    Any,
    /// A member: only a key whose `minted_by` equals this subject.
    MintedBy(&'a str),
}

/// A validated JSON Merge Patch (RFC 7396) of a key's editable columns.
///
/// Outer `None` = absent (unchanged). For the nullable columns the inner
/// `Option` is the new value, `None` meaning "clear". `name`, `scope`,
/// `budget_reset` and `velocity_breaker` cannot be cleared — the route refuses a
/// `null` for them before this is built (a key may LEAVE the legacy NULL scope and
/// never re-enter it).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KeyPatch {
    pub name: Option<String>,
    pub scope: Option<Vec<String>>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub budget_usd_monthly: Option<Option<f64>>,
    pub rate_limit_rpm: Option<Option<i32>>,
    pub budget_reset: Option<tracelane_shared::spend::BudgetReset>,
    pub velocity_breaker: Option<bool>,
    /// OG-23: move the key into a project (`Some(Some(id))`) or out of one (`Some(None)`).
    /// The project must be live and in THIS tenant — checked under the row lock.
    pub project_id: Option<Option<Uuid>>,
    /// OG-23: the key's environment label (one of its project's environments).
    pub environment: Option<Option<String>>,
    /// OG-20: the key's own policy, ALREADY validated and canonical (`KeyPolicy::to_value`);
    /// `Some(None)` clears it.
    pub policy: Option<Option<serde_json::Value>>,
    /// OG-51: the key's own cache narrowing, ALREADY validated and canonical
    /// (`KeyCache::to_json`); `Some(None)` clears it (which WIDENS — an owner decision).
    pub cache: Option<Option<serde_json::Value>>,
}

/// One key as the settings surface reads it. No secret-derived column.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyRecord {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub minted_by: Option<String>,
    pub scope: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub budget_usd_monthly: Option<f64>,
    pub rate_limit_rpm: Option<i32>,
    pub budget_reset: tracelane_shared::spend::BudgetReset,
    pub velocity_breaker: bool,
    /// A FUTURE value means the key is retiring (rotated, in its grace window).
    pub revoked_at: Option<DateTime<Utc>>,
    /// OG-23: the key's project, and its environment label.
    pub project_id: Option<Uuid>,
    pub environment: Option<String>,
    /// OG-20: the key's own policy document as stored.
    pub policy: Option<serde_json::Value>,
    /// OG-51: the key's own cache narrowing as stored (`{"mode":"off"?,"namespace_by"?}`).
    pub cache: Option<serde_json::Value>,
}

/// The result of [`update`]. Every refusal is decided under the row lock.
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateOutcome {
    /// Not in this tenant, already revoked, or expired — one answer for all
    /// three, so the route cannot become an existence oracle across tenants.
    NotFound,
    /// A member editing a key someone else minted.
    Forbidden,
    /// Rotated and in its grace window: the successor is the key to edit.
    Retiring { revoked_at: DateTime<Utc> },
    /// Committed (or a no-op: `changed` is empty and nothing was written).
    Updated {
        record: Box<KeyRecord>,
        changed: Vec<&'static str>,
    },
    /// OG-23: the named project is not a LIVE project of this tenant (one answer for
    /// absent, archived and another tenant's — no existence oracle).
    ProjectNotFound,
    /// OG-23: the environment the key would carry is not one of its project's.
    EnvironmentNotInProject { environment: String },
    /// OG-23: an environment label needs a project (the key would have none).
    EnvironmentNeedsProject,
}

/// The record columns, in [`record_from_row`]'s order. ONE list for the
/// `SELECT … FOR UPDATE`, the `UPDATE … RETURNING` and [`get`], so they cannot
/// disagree about positions.
const RECORD_COLUMNS: &str = "id, name, key_prefix, created_at, last_used_at, minted_by, scope, \
     expires_at, budget_usd_monthly::text, rate_limit_rpm, budget_reset, velocity_breaker, revoked_at, \
     project_id, environment, policy, cache";

/// How many columns [`RECORD_COLUMNS`] names — the index of the first column a query
/// appends after it.
const RECORD_LEN: usize = 17;

fn record_from_row(row: &tokio_postgres::Row) -> KeyRecord {
    KeyRecord {
        id: row.get(0),
        name: row.get(1),
        key_prefix: row.get(2),
        created_at: row.get(3),
        last_used_at: row.get(4),
        minted_by: row.get(5),
        scope: row.get(6),
        expires_at: row.get(7),
        budget_usd_monthly: row
            .get::<_, Option<String>>(8)
            .and_then(|t| t.parse::<f64>().ok()),
        rate_limit_rpm: row.get(9),
        budget_reset: tracelane_shared::spend::BudgetReset::from_column(row.get::<_, &str>(10)),
        velocity_breaker: row.get(11),
        revoked_at: row.get(12),
        project_id: row.get(13),
        environment: row.get(14),
        policy: row.get(15),
        cache: row.get(16),
    }
}

/// The canonical stored text of a budget: what `create`'s `{b:.4}` and the
/// `numeric(12,4)` column agree on. Comparing THIS, not the f64, is what makes
/// "set it to the value it already has" a no-op instead of an audit row.
fn budget_text(v: Option<f64>) -> Option<String> {
    v.map(|b| format!("{b:.4}"))
}

/// Postgres stores microseconds; compare and store at that precision so an
/// unchanged `expires_at` never reads as a change.
fn to_micros(t: DateTime<Utc>) -> DateTime<Utc> {
    use chrono::SubsecRound as _;
    t.trunc_subsecs(6)
}

fn same_scope(a: &[String], b: &[String]) -> bool {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

fn json_time(t: Option<DateTime<Utc>>) -> serde_json::Value {
    t.map_or(serde_json::Value::Null, |t| {
        serde_json::Value::String(t.to_rfc3339())
    })
}

/// The effective diff of `patch` against `current`: which fields REALLY change,
/// with their before/after values for the audit row. Pure, so the no-op and the
/// only-the-changed-fields rules are unit-testable without a database.
#[allow(clippy::type_complexity)]
fn diff_patch(
    current: &KeyRecord,
    patch: &KeyPatch,
) -> (
    KeyPatch,
    Vec<&'static str>,
    serde_json::Map<String, serde_json::Value>,
    serde_json::Map<String, serde_json::Value>,
) {
    use serde_json::{Value, json};
    let mut eff = KeyPatch::default();
    let mut changed = Vec::new();
    let mut before = serde_json::Map::new();
    let mut after = serde_json::Map::new();
    let mut note = |field: &'static str, b: Value, a: Value| {
        changed.push(field);
        before.insert(field.to_string(), b);
        after.insert(field.to_string(), a);
    };
    if let Some(name) = &patch.name
        && *name != current.name
    {
        note("name", json!(current.name), json!(name));
        eff.name = Some(name.clone());
    }
    if let Some(scope) = &patch.scope {
        let unchanged = current
            .scope
            .as_deref()
            .is_some_and(|cur| same_scope(cur, scope));
        if !unchanged {
            note("scope", json!(current.scope), json!(scope));
            eff.scope = Some(scope.clone());
        }
    }
    if let Some(exp) = patch.expires_at {
        let exp = exp.map(to_micros);
        if exp != current.expires_at.map(to_micros) {
            note("expires_at", json_time(current.expires_at), json_time(exp));
            eff.expires_at = Some(exp);
        }
    }
    if let Some(budget) = patch.budget_usd_monthly
        && budget_text(budget) != budget_text(current.budget_usd_monthly)
    {
        note(
            "budget_usd_monthly",
            json!(current.budget_usd_monthly),
            json!(budget),
        );
        eff.budget_usd_monthly = Some(budget);
    }
    if let Some(rpm) = patch.rate_limit_rpm
        && rpm != current.rate_limit_rpm
    {
        note("rate_limit_rpm", json!(current.rate_limit_rpm), json!(rpm));
        eff.rate_limit_rpm = Some(rpm);
    }
    if let Some(reset) = patch.budget_reset
        && reset != current.budget_reset
    {
        note(
            "budget_reset",
            json!(current.budget_reset.as_str()),
            json!(reset.as_str()),
        );
        eff.budget_reset = Some(reset);
    }
    if let Some(vb) = patch.velocity_breaker
        && vb != current.velocity_breaker
    {
        note(
            "velocity_breaker",
            json!(current.velocity_breaker),
            json!(vb),
        );
        eff.velocity_breaker = Some(vb);
    }
    if let Some(pid) = patch.project_id
        && pid != current.project_id
    {
        note(
            "project_id",
            json!(current.project_id.map(|p| p.to_string())),
            json!(pid.map(|p| p.to_string())),
        );
        eff.project_id = Some(pid);
    }
    if let Some(env) = &patch.environment
        && *env != current.environment
    {
        note("environment", json!(current.environment), json!(env));
        eff.environment = Some(env.clone());
    }
    if let Some(policy) = &patch.policy
        && *policy != current.policy
    {
        // Before AND after, whole: the audit row is the record of who changed a
        // security control and from what (OG-35 reads it).
        note("policy", json!(current.policy), json!(policy));
        eff.policy = Some(policy.clone());
    }
    if let Some(cache) = &patch.cache
        && *cache != current.cache
    {
        // OG-51: before AND after, whole — removing a narrowing widens the cache, and the
        // audit row is the record of who did it.
        note("cache", json!(current.cache), json!(cache));
        eff.cache = Some(cache.clone());
    }
    (eff, changed, before, after)
}

/// OG-23: the environments of a LIVE project of `tenant`, or `None` (absent, archived,
/// or another tenant's — one answer).
async fn live_project_environments(
    client: &impl deadpool_postgres::GenericClient,
    tenant: &TenantId,
    project: Uuid,
) -> Result<Option<Vec<String>>> {
    Ok(client
        .query_opt(
            "SELECT environments FROM projects \
             WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL",
            &[tenant.as_uuid(), &project],
        )
        .await
        .context("SELECT projects (assignment) failed")?
        .map(|r| r.get(0)))
}

/// OG-23: the assignment a key would END with after `eff` (project, environment) is
/// valid — the project live and in this tenant, the environment one of its own. Checked
/// under the key's row lock; `None` = valid.
async fn assignment_refusal(
    client: &impl deadpool_postgres::GenericClient,
    tenant: &TenantId,
    current: &KeyRecord,
    eff: &KeyPatch,
) -> Result<Option<UpdateOutcome>> {
    if eff.project_id.is_none() && eff.environment.is_none() {
        return Ok(None);
    }
    let project = eff.project_id.unwrap_or(current.project_id);
    let environment = eff
        .environment
        .clone()
        .unwrap_or_else(|| current.environment.clone());
    let Some(project) = project else {
        return Ok(environment.map(|_| UpdateOutcome::EnvironmentNeedsProject));
    };
    let Some(envs) = live_project_environments(client, tenant, project).await? else {
        return Ok(Some(UpdateOutcome::ProjectNotFound));
    };
    Ok(environment
        .filter(|e| !envs.contains(e))
        .map(|environment| UpdateOutcome::EnvironmentNotInProject { environment }))
}

/// Read one key of `tenant` for the settings surface. `None` when the key is not
/// in this tenant or is already revoked (a retiring key IS returned — the list
/// shows it too).
///
/// # Errors
/// A database failure. Fail CLOSED: the route answers 5xx, never a guessed row.
#[tracing::instrument(skip(pool, tenant), fields(tenant_id = %tenant))]
pub async fn get(pool: &Pool, tenant: &TenantId, id: Uuid) -> Result<Option<KeyRecord>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let sql = format!(
        "SELECT {RECORD_COLUMNS} FROM api_keys \
         WHERE tenant_id = $1 AND id = $2 AND (revoked_at IS NULL OR revoked_at > clock_timestamp())"
    );
    let row = client
        .query_opt(sql.as_str(), &[tenant.as_uuid(), &id])
        .await
        .context("SELECT api_keys by id failed")?;
    Ok(row.as_ref().map(record_from_row))
}

/// SET-38 — edit a key's limits in place. `rotate`'s ordering exactly:
/// `SELECT … FOR UPDATE` → authorize → `UPDATE` (only the changed columns) →
/// `admin_audit_log` `api_key.update` (only the changed fields) → take the
/// cache WRITE lock → `COMMIT` → [`invalidate`]. So a cold lookup that began
/// before the commit cannot restore the old limits into the cache, and the key's
/// NEXT authenticated request reads the new row.
///
/// # Errors
/// Fail CLOSED: any failure — the UPDATE, the audit insert, the commit — rolls
/// back every write, and the caller answers "not saved".
#[tracing::instrument(skip(pool, tenant, editor, patch, actor), fields(tenant_id = %tenant))]
pub async fn update(
    pool: &Pool,
    tenant: &TenantId,
    id: Uuid,
    editor: KeyEditor<'_>,
    patch: &KeyPatch,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
) -> Result<UpdateOutcome> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let select = format!(
        "SELECT {RECORD_COLUMNS}, lookup_hash, \
                COALESCE(revoked_at <= clock_timestamp(), false), \
                COALESCE(expires_at <= clock_timestamp(), false) \
         FROM api_keys WHERE tenant_id = $1 AND id = $2 FOR UPDATE"
    );
    let Some(row) = tx
        .query_opt(select.as_str(), &[tenant.as_uuid(), &id])
        .await
        .context("SELECT api_keys FOR UPDATE failed")?
    else {
        return Ok(UpdateOutcome::NotFound);
    };
    let current = record_from_row(&row);
    let digest: Option<Vec<u8>> = row.get(RECORD_LEN);
    let revoked_now: bool = row.get(RECORD_LEN + 1);
    let expired_now: bool = row.get(RECORD_LEN + 2);
    if revoked_now || expired_now {
        return Ok(UpdateOutcome::NotFound);
    }
    if let KeyEditor::MintedBy(sub) = editor
        && current.minted_by.as_deref() != Some(sub)
    {
        return Ok(UpdateOutcome::Forbidden);
    }
    if let Some(revoked_at) = current.revoked_at {
        return Ok(UpdateOutcome::Retiring { revoked_at });
    }
    let (eff, changed, before, after) = diff_patch(&current, patch);
    // OG-23: a key may only join a LIVE project of its own tenant, with one of that
    // project's environments. Under the row lock, before anything is written.
    if let Some(refusal) = assignment_refusal(&tx, tenant, &current, &eff).await? {
        return Ok(refusal);
    }
    if changed.is_empty() {
        // A no-op writes nothing: no UPDATE, no audit row, no invalidation.
        return Ok(UpdateOutcome::Updated {
            record: Box::new(current),
            changed,
        });
    }
    // A row with no (or a malformed) lookup digest can never authenticate — the
    // cache and the lookup are both keyed on it — so there is nothing to clear.
    let digest: Option<[u8; 32]> = digest.and_then(|d| <[u8; 32]>::try_from(d).ok());
    let budget_reset = eff
        .budget_reset
        .map(tracelane_shared::spend::BudgetReset::as_str);
    let expires_at: Option<DateTime<Utc>> = eff.expires_at.flatten();
    let budget: Option<String> = eff.budget_usd_monthly.and_then(budget_text);
    let rpm: Option<i32> = eff.rate_limit_rpm.flatten();
    // ONE static statement: every column is `CASE WHEN <changed> THEN <new> ELSE
    // <itself>`, so the unchanged columns are not touched in meaning and no SQL is
    // ever assembled from values. The numeric bind routes through `text` for the
    // reason `BUDGET_NUMERIC_CAST` records.
    let sql = format!(
        "UPDATE api_keys SET \
           name = CASE WHEN $3 THEN $4::text ELSE name END, \
           scope = CASE WHEN $5 THEN $6::text[] ELSE scope END, \
           expires_at = CASE WHEN $7 THEN $8::timestamptz ELSE expires_at END, \
           budget_usd_monthly = CASE WHEN $9 THEN $10{BUDGET_NUMERIC_CAST} ELSE budget_usd_monthly END, \
           rate_limit_rpm = CASE WHEN $11 THEN $12::int4 ELSE rate_limit_rpm END, \
           budget_reset = CASE WHEN $13 THEN $14::text ELSE budget_reset END, \
           velocity_breaker = CASE WHEN $15 THEN $16::bool ELSE velocity_breaker END, \
           project_id = CASE WHEN $17 THEN $18::uuid ELSE project_id END, \
           environment = CASE WHEN $19 THEN $20::text ELSE environment END, \
           policy = CASE WHEN $21 THEN $22::jsonb ELSE policy END, \
           cache = CASE WHEN $23 THEN $24::jsonb ELSE cache END \
         WHERE tenant_id = $1 AND id = $2 \
         RETURNING {RECORD_COLUMNS}"
    );
    let project_id: Option<Uuid> = eff.project_id.flatten();
    let environment: Option<String> = eff.environment.clone().flatten();
    let policy: Option<serde_json::Value> = eff.policy.clone().flatten();
    let cache: Option<serde_json::Value> = eff.cache.clone().flatten();
    let updated = tx
        .query_one(
            sql.as_str(),
            &[
                tenant.as_uuid(),
                &id,
                &eff.name.is_some(),
                &eff.name,
                &eff.scope.is_some(),
                &eff.scope,
                &eff.expires_at.is_some(),
                &expires_at,
                &eff.budget_usd_monthly.is_some(),
                &budget,
                &eff.rate_limit_rpm.is_some(),
                &rpm,
                &eff.budget_reset.is_some(),
                &budget_reset,
                &eff.velocity_breaker.is_some(),
                &eff.velocity_breaker,
                &eff.project_id.is_some(),
                &project_id,
                &eff.environment.is_some(),
                &environment,
                &eff.policy.is_some(),
                &policy,
                &eff.cache.is_some(),
                &cache,
            ],
        )
        .await
        .context("UPDATE api_keys failed")?;
    let record = record_from_row(&updated);
    let before = serde_json::Value::Object(before);
    let after = serde_json::Value::Object(after);
    crate::db::control_audit::record(
        &tx,
        tenant,
        &actor.as_actor(),
        crate::db::control_audit::Change {
            action: "api_key.update",
            target_type: "api_key",
            target_id: id.to_string(),
            before: Some(before),
            after: Some(after),
        },
    )
    .await
    .context("admin_audit_log api_key.update insert failed")?;
    // Same reason as `rotate`: a cold lookup that read the OLD row before this
    // commit must finish populating before the invalidation, or it would put the
    // old limits back into the cache after we cleared it.
    let _cache_write = AUTH_CACHE_WRITES.write().await;
    tx.commit().await.context("api_keys update commit failed")?;
    if let Some(d) = digest {
        invalidate(d).await;
    }
    Ok(UpdateOutcome::Updated {
        record: Box::new(record),
        changed,
    })
}

/// B-586 — revoke through the gateway so the revocation reaches the in-process
/// auth cache: `SELECT … FOR UPDATE` → `UPDATE revoked_at = clock_timestamp()` →
/// `admin_audit_log` `api_key.revoke` → cache WRITE lock → `COMMIT` →
/// [`invalidate`]. The key's next request takes the cold path and finds no row.
///
/// A retiring key (rotated, future `revoked_at`) is revoked NOW — ending its
/// grace early, as the web revoke always did. Returns the new `revoked_at`;
/// `Ok(None)` when the key is not in
/// this tenant or is already revoked.
///
/// # Errors
/// Fail CLOSED: an audit-insert or commit failure rolls the revocation back.
#[tracing::instrument(skip(pool, tenant, actor), fields(tenant_id = %tenant))]
pub async fn revoke_key(
    pool: &Pool,
    tenant: &TenantId,
    id: Uuid,
    actor: &(impl crate::db::control_audit::AsActor + ?Sized),
) -> Result<Option<DateTime<Utc>>> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "SELECT lookup_hash, name, key_prefix, revoked_at FROM api_keys
             WHERE tenant_id = $1 AND id = $2
               AND (revoked_at IS NULL OR revoked_at > clock_timestamp())
             FOR UPDATE",
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("SELECT api_keys FOR UPDATE (revoke) failed")?
    else {
        return Ok(None);
    };
    let digest: Option<Vec<u8>> = row.get(0);
    let name: String = row.get(1);
    let key_prefix: String = row.get(2);
    let scheduled: Option<DateTime<Utc>> = row.get(3);
    let revoked_at: DateTime<Utc> = tx
        .query_one(
            "UPDATE api_keys SET revoked_at = clock_timestamp()
             WHERE tenant_id = $1 AND id = $2 RETURNING revoked_at",
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("UPDATE api_keys revoke failed")?
        .get(0);
    let before = serde_json::json!({
        "name": name,
        "keyPrefix": key_prefix,
        "scheduledRevokedAt": json_time(scheduled),
    });
    let after = serde_json::json!({ "revokedAt": revoked_at.to_rfc3339() });
    crate::db::control_audit::record(
        &tx,
        tenant,
        &actor.as_actor(),
        crate::db::control_audit::Change {
            action: "api_key.revoke",
            target_type: "api_key",
            target_id: id.to_string(),
            before: Some(before),
            after: Some(after),
        },
    )
    .await
    .context("admin_audit_log api_key.revoke insert failed")?;
    let _cache_write = AUTH_CACHE_WRITES.write().await;
    tx.commit().await.context("api_keys revoke commit failed")?;
    // A row minted before ADR-042 may carry no lookup digest; it cannot be in the
    // cache (the cache is keyed on it), so there is nothing to clear.
    if let Some(d) = digest.and_then(|d| <[u8; 32]>::try_from(d).ok()) {
        invalidate(d).await;
    }
    Ok(Some(revoked_at))
}

/// `OG-25` — revoke EVERY live and retiring key of a tenant in one transaction:
/// `UPDATE … SET revoked_at = clock_timestamp()` over the tenant's not-yet-revoked rows →
/// ONE control-change record (`api_key.revoke_all`, the ids and the count) → cache WRITE
/// lock → `COMMIT` → every revoked key's cache entry invalidated, exactly as
/// [`revoke_key`] does for one. Irreversible: there is no un-revoke; mint new keys.
///
/// Returns the revoked key ids.
///
/// # Errors
/// Fail CLOSED: an audit-insert or commit failure rolls every revocation back.
#[tracing::instrument(skip(pool, tenant, actor), fields(tenant_id = %tenant))]
pub async fn revoke_all_keys(pool: &Pool, tenant: &TenantId, actor: &str) -> Result<Vec<Uuid>> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let rows = tx
        .query(
            "UPDATE api_keys SET revoked_at = clock_timestamp()
             WHERE tenant_id = $1
               AND (revoked_at IS NULL OR revoked_at > clock_timestamp())
             RETURNING id, lookup_hash",
            &[tenant.as_uuid()],
        )
        .await
        .context("UPDATE api_keys revoke-all failed")?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.get(0)).collect();
    let digests: Vec<[u8; 32]> = rows
        .iter()
        .filter_map(|r| r.get::<_, Option<Vec<u8>>>(1))
        .filter_map(|d| <[u8; 32]>::try_from(d).ok())
        .collect();
    crate::db::controls::record_control_change(
        &tx,
        &crate::db::controls::ControlChange {
            tenant: *tenant.as_uuid(),
            actor,
            action: "api_key.revoke_all",
            target_type: "workspace",
            target_id: tenant.to_string(),
            before: None,
            after: Some(serde_json::json!({
                "revoked": ids.len(),
                "keyIds": ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
            })),
        },
    )
    .await?;
    let _cache_write = AUTH_CACHE_WRITES.write().await;
    tx.commit()
        .await
        .context("api_keys revoke-all commit failed")?;
    for d in digests {
        invalidate(d).await;
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    /// The budget is the ONLY thing standing between this task and a
    /// self-inflicted database outage: without it the work is O(active keys) per
    /// tick, which is 3 queries/minute at one key and 500 PER SECOND at ten
    /// thousand. Asserted at a million so the property is stated at the scale it
    /// matters, not just the scale we run at.
    #[test]
    fn refresh_work_per_tick_is_capped_regardless_of_user_count() {
        for population in [1usize, 100, 10_000, 1_000_000] {
            let due: Vec<([u8; 32], Duration)> = (0..population)
                .map(|i| {
                    let mut d = [0u8; 32];
                    d[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    (d, Duration::from_secs(i as u64 % 1000))
                })
                .collect();
            let picked = super::select_due(due, super::MAX_REFRESH_PER_TICK);
            assert!(
                picked.len() <= super::MAX_REFRESH_PER_TICK,
                "{population} active keys produced {} refreshes, past the {} budget",
                picked.len(),
                super::MAX_REFRESH_PER_TICK
            );
        }
    }

    /// A binding budget must defer the keys with the MOST slack, never the ones
    /// about to expire — otherwise the budget silently converts into the exact
    /// cache-miss it exists to prevent, for the keys that needed it most.
    /// Falsified by the ordering assertion: a `truncate` without the sort would
    /// still satisfy the length cap and fail here.
    #[test]
    fn a_binding_budget_defers_the_freshest_not_the_stalest() {
        let mut due = Vec::new();
        for i in 0..(super::MAX_REFRESH_PER_TICK * 3) {
            let mut d = [0u8; 32];
            d[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            // i = 0 is the STALEST (largest elapsed), descending from there.
            due.push((d, Duration::from_secs((1_000 - i) as u64)));
        }
        let picked = super::select_due(due, super::MAX_REFRESH_PER_TICK);
        let mut stalest = [0u8; 32];
        stalest[0..8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            picked.first().copied(),
            Some(stalest),
            "the stalest key was not refreshed first"
        );
        let mut freshest = [0u8; 32];
        freshest[0..8]
            .copy_from_slice(&((super::MAX_REFRESH_PER_TICK * 3 - 1) as u64).to_le_bytes());
        assert!(
            !picked.contains(&freshest),
            "the freshest key consumed budget that a near-expiry key needed"
        );
    }

    // ── B-256 warm refresh ────────────────────────────────────────────────

    /// The half-TTL ceiling is the whole point of the clamp: an interval LONGER
    /// than the TTL lets entries expire between refreshes, which is exactly the
    /// cache-never-hits defect the refresher exists to remove. Asserted against
    /// the real TTL range rather than one example, because a clamp that holds for
    /// 60 and not for 10 is a clamp that fails on the day someone tunes it.
    #[test]
    fn refresh_interval_can_never_exceed_half_the_ttl() {
        for ttl in [1u64, 10, 30, 60, 120, 900] {
            for want in ["1", "5", "20", "300", "100000"] {
                let got = super::parse_refresh_interval(Some(want), ttl);
                assert!(
                    got <= (ttl / 2).max(5),
                    "ttl={ttl} want={want} -> {got} exceeds half the TTL"
                );
                assert!(
                    got >= 5,
                    "ttl={ttl} want={want} -> {got} is below the 5s floor"
                );
            }
        }
    }

    /// A malformed value must fall back to the DEFAULT, not to zero and not to
    /// the maximum. Zero would disable the refresh silently and hand back the
    /// B-256 latency; the maximum would let entries expire between ticks.
    #[test]
    fn a_malformed_refresh_interval_falls_back_to_the_default() {
        let ttl = 60;
        for bad in ["", "  ", "off", "-1", "abc", "1.5"] {
            assert_eq!(
                super::parse_refresh_interval(Some(bad), ttl),
                super::DEFAULT_REFRESH_INTERVAL_SECS,
                "{bad:?} did not fall back to the default"
            );
        }
        assert_eq!(
            super::parse_refresh_interval(None, ttl),
            super::DEFAULT_REFRESH_INTERVAL_SECS
        );
    }

    /// The refresh interval IS the revocation bound, so it must be strictly
    /// tighter than the TTL it replaces. If this ever fails, the change stopped
    /// being a security improvement and became a regression.
    #[test]
    fn the_refresh_interval_is_tighter_than_the_revocation_ttl() {
        let ttl = super::DEFAULT_AUTH_CACHE_TTL_SECS;
        let interval = super::parse_refresh_interval(None, ttl);
        assert!(
            interval < ttl,
            "refresh interval {interval}s is not tighter than the {ttl}s TTL it bounds"
        );
    }

    /// The active set must stay bounded on an auth path, and an ALREADY-TRACKED
    /// key must keep being updated even when the set is full — otherwise a key in
    /// steady use would stop being refreshed the moment some unrelated burst
    /// filled the map, silently handing it back the cold path.
    ///
    /// Renamed from `..._evicts_the_oldest`, which described the previous
    /// implementation. That one evicted via `min_by_key` — a linear scan of
    /// 10,000 entries ON EVERY AUTHENTICATED REQUEST once full. The scan is gone;
    /// at the cap the insert is skipped instead, which is O(1). A test whose name
    /// outlives the behaviour it describes is worse than no test, because it
    /// reads as coverage of something nothing checks any more.
    #[test]
    fn the_active_digest_set_is_bounded_and_keeps_tracking_a_key_in_steady_use() {
        let hot = [7u8; 32];
        super::note_active(hot);
        for i in 0..(super::MAX_ACTIVE_DIGESTS + 50) {
            let mut d = [0u8; 32];
            d[0] = u8::try_from(i % 251).unwrap_or(0);
            d[1] = u8::try_from((i / 251) % 251).unwrap_or(0);
            d[2] = u8::try_from((i / 63001) % 251).unwrap_or(0);
            if d != hot {
                super::note_active(d);
            }
            // Keep the hot key genuinely hot, so eviction has to prefer others.
            super::note_active(hot);
        }
        let map = super::active_digests().lock().expect("active set lock");
        assert!(
            map.len() <= super::MAX_ACTIVE_DIGESTS,
            "active set grew to {} past the {} cap",
            map.len(),
            super::MAX_ACTIVE_DIGESTS
        );
        assert!(
            map.contains_key(&hot),
            "a key in continuous use stopped being tracked once the set filled"
        );
    }

    use super::*;

    /// This TTL is the API-key REVOCATION bound, so every way it can be
    /// set wrong must land on the tighter value, never the looser one.
    #[test]
    fn auth_cache_ttl_defaults_to_sixty_seconds() {
        assert_eq!(parse_auth_cache_ttl(None), 60);
        assert_eq!(DEFAULT_AUTH_CACHE_TTL_SECS, 60);
    }

    #[test]
    fn auth_cache_ttl_honours_a_valid_override() {
        assert_eq!(parse_auth_cache_ttl(Some("120")), 120);
        assert_eq!(parse_auth_cache_ttl(Some(" 30 ")), 30);
        assert_eq!(parse_auth_cache_ttl(Some("900")), 900);
    }

    /// Fails CLOSED, and this is the discriminating half: every bad input must
    /// resolve to the 60s DEFAULT, not to `MAX`. An implementation that clamped
    /// (`min(v, MAX)`) would pass "too large" by returning 900 — a 15-minute
    /// window for a revoked credential, which is exactly the state found us
    /// in. These assertions fail against that implementation.
    #[test]
    fn auth_cache_ttl_rejects_garbage_toward_the_tighter_bound() {
        for bad in ["0", "901", "86400", "-1", "abc", "", "60s", "1e3"] {
            assert_eq!(
                parse_auth_cache_ttl(Some(bad)),
                DEFAULT_AUTH_CACHE_TTL_SECS,
                "{bad:?} must fall back to the 60s default, never to MAX"
            );
        }
        assert!(parse_auth_cache_ttl(Some("901")) < MAX_AUTH_CACHE_TTL_SECS);
    }

    fn init_test_pepper() {
        // 32 zero bytes for tests. Real prod pepper comes from KMS.
        let _ = init_pepper(&"00".repeat(32));
    }

    #[test]
    fn peppered_lookup_is_deterministic_with_same_pepper() {
        init_test_pepper();
        let a = peppered_lookup("tlane-body-1").unwrap();
        let b = peppered_lookup("tlane-body-1").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, peppered_lookup("tlane-body-2").unwrap());
    }

    #[test]
    fn hmac_sha256_known_answer_matches_web_minter() {
        // Cross-impl KAT (ADR-042): ring HMAC-SHA256(32 zero bytes, "abc123")
        // must equal node `crypto.createHmac('sha256', zeros).update('abc123')`
        // used by the web minter (apps/web/lib/api-key-hash.ts) — so lookup_hash
        // agrees across the gateway verifier and the minter. Computed directly
        // (not via the global pepper) so it's order-independent in the test bin.
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        let tag = hmac::sign(&key, b"abc123");
        assert_eq!(
            hex::encode(tag.as_ref()),
            "a88e2d710bee460c0fd3561f2057706a7780cc5fc8d1005fd7cd7e34f453e499"
        );
    }

    // SRE audit finding 9, 2026-09-04. STRUCTURAL, and deliberately so.
    //
    // I tried three times to write a behavioural test — a 1-worker multi-thread runtime
    // with a 1 ms ticker, asserting the ticker keeps ticking across the verify — and
    // ALL THREE PASSED WITH THE PRE-FIX INLINE CALL STILL IN PLACE. First it counted
    // ticks from t=0 (they accumulated before the verify ran); then it called the verify
    // from the test body, which `#[tokio::test(flavor = "multi_thread")]` drives with
    // `block_on` on the MAIN thread, never touching the worker; then it moved the verify
    // into a spawned task and STILL did not discriminate.
    //
    // A test that passes whether or not the fix is present proves nothing, and shipping
    // one as a regression guard is the exact defect this audit spent its time removing.
    // So this asserts the SHAPE instead, which does catch the regression that matters
    // (someone putting the KDF back on the async task), and says plainly what it cannot
    // prove: that the runtime is actually unblocked. That half is the reasoning at
    // `argon2id_verify_blocking`, backed by the measurement in its doc comment.
    #[test]
    fn cold_auth_runs_the_kdf_off_the_tokio_workers() {
        let src = include_str!("api_keys.rs");
        assert!(
            src.contains("async fn argon2id_verify_blocking"),
            "the off-runtime wrapper is gone"
        );
        assert!(
            src.contains("tokio::task::spawn_blocking(move || argon2id_verify("),
            "argon2id_verify_blocking no longer uses spawn_blocking"
        );
        assert!(
            src.contains("argon2id_verify_blocking(p, key_body.to_string()).await"),
            "the COLD AUTH path no longer calls the off-runtime wrapper — a ~35 ms KDF \
             is back on a tokio worker, and prod has only four"
        );
    }

    #[test]
    fn argon2id_roundtrip_succeeds() {
        let phc = argon2id_hash("a-secret-key-body").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(argon2id_verify(&phc, "a-secret-key-body").unwrap());
    }

    #[test]
    fn argon2id_rejects_wrong_body() {
        let phc = argon2id_hash("right-body").unwrap();
        assert!(!argon2id_verify(&phc, "wrong-body").unwrap());
    }

    /// Cross-impl round-trip (ADR-042, Vercel→CF `hash-wasm` swap): a PHC minted
    /// by the dashboard's pure-WASM Argon2id (`apps/web/lib/api-key-hash.ts`)
    /// MUST verify byte-for-byte in this RustCrypto verifier — that is the exact
    /// production path (web mints, gateway verifies). A PHC-encoding drift here =
    /// silent key-verify failure for every new key (#81 class), so the hash-wasm
    /// output is frozen as a known-answer vector: params m=19456,t=2,p=1, tag 32B,
    /// salt = bytes 0..15. Regenerate via `apps/web` mint-vector if params change.
    #[test]
    fn rustcrypto_verifies_hashwasm_minted_phc() {
        const HASHWASM_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAECAwQFBgcICQoLDA0ODw$qbMc+TooxRwdHvoqtALQowxdbkKLXf4ucwdZsgIIxg4";
        const KEY_BODY: &str = "rt-vector-key-body-do-not-use-in-prod";
        assert!(
            argon2id_verify(HASHWASM_PHC, KEY_BODY).unwrap(),
            "RustCrypto gateway verifier must accept a hash-wasm-minted PHC"
        );
        assert!(
            !argon2id_verify(HASHWASM_PHC, "wrong-body").unwrap(),
            "must still reject the wrong body against the hash-wasm-minted PHC"
        );
    }

    #[test]
    fn argon2id_includes_per_row_salt() {
        // Same body → two distinct PHC strings because the salt differs.
        let a = argon2id_hash("same-body").unwrap();
        let b = argon2id_hash("same-body").unwrap();
        assert_ne!(a, b, "salt should make outputs differ");
        // But both verify against the original body.
        assert!(argon2id_verify(&a, "same-body").unwrap());
        assert!(argon2id_verify(&b, "same-body").unwrap());
    }

    #[test]
    fn argon2id_verify_rejects_malformed_phc() {
        assert!(argon2id_verify("not-a-phc-string", "x").is_err());
    }

    #[test]
    fn key_material_carries_lookup_and_phc() {
        init_test_pepper();
        let m = KeyMaterial::from_body("body-1").unwrap();
        assert_eq!(m.lookup_hash.len(), 32);
        assert!(m.argon2id_phc.starts_with("$argon2id$"));
        // lookup_hash is deterministic for the same body…
        assert_eq!(m.lookup_hash, peppered_lookup("body-1").unwrap());
        // …and the PHC verifies the right body only.
        assert!(argon2id_verify(&m.argon2id_phc, "body-1").unwrap());
        assert!(!argon2id_verify(&m.argon2id_phc, "body-2").unwrap());
    }

    #[test]
    fn pepper_decode_accepts_hex_64() {
        let raw = "0".repeat(64);
        let out = decode_pepper(&raw).unwrap();
        assert_eq!(out, [0u8; 32]);
    }

    #[test]
    fn pepper_decode_accepts_base64() {
        // 32 zero bytes base64-encoded = 44 chars.
        let raw = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        let out = decode_pepper(&raw).unwrap();
        assert_eq!(out, [0u8; 32]);
    }

    #[test]
    fn pepper_decode_rejects_short_input() {
        assert!(decode_pepper("too-short").is_err());
        // Hex of 16 bytes (32 chars) — rejected: neither 64-hex nor base64-32-bytes.
        assert!(decode_pepper(&"a".repeat(32)).is_err());
    }

    #[test]
    fn to_base62_is_fixed_width_and_in_alphabet() {
        // All-zero and all-one bounds both render to exactly 43 base62 chars.
        for bytes in [[0u8; 32], [0xFFu8; 32]] {
            let s = to_base62(&bytes);
            assert_eq!(s.len(), KEY_BODY_LEN, "body must be {KEY_BODY_LEN} chars");
            assert!(
                s.bytes().all(|b| BASE62.contains(&b)),
                "every char must be in the base62 alphabet"
            );
        }
        assert_eq!(to_base62(&[0u8; 32]), "0".repeat(KEY_BODY_LEN));
    }

    #[test]
    fn to_base62_known_answer_matches_web_minter() {
        // Cross-impl KAT vs apps/web toBase62 (big-endian divmod 62, padStart 43):
        //   value 1  -> "0…01", value 61 -> "0…0z", value 62 -> "0…010".
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(to_base62(&one).ends_with("01"));
        assert_eq!(to_base62(&one).trim_start_matches('0'), "1");

        let mut sixty_one = [0u8; 32];
        sixty_one[31] = 61;
        assert_eq!(to_base62(&sixty_one).trim_start_matches('0'), "z");

        let mut sixty_two = [0u8; 32];
        sixty_two[31] = 62;
        assert_eq!(to_base62(&sixty_two).trim_start_matches('0'), "10");
    }

    #[test]
    fn generate_key_body_is_well_formed_and_unique() {
        let a = generate_key_body().unwrap();
        let b = generate_key_body().unwrap();
        assert_eq!(a.len(), KEY_BODY_LEN);
        assert!(a.bytes().all(|c| BASE62.contains(&c)));
        assert_ne!(a, b, "each mint must draw fresh entropy");
        // The stored prefix is the first KEY_PREFIX_LEN chars of the body.
        assert_eq!(
            &a.chars().take(KEY_PREFIX_LEN).collect::<String>(),
            &a[..KEY_PREFIX_LEN]
        );
    }

    /// The `budget_usd_monthly` bind MUST route through `text`. A bare
    /// `$9::numeric` makes Postgres infer the param as `numeric`, which
    /// tokio-postgres cannot serialize a `String` into — every mint 500s.
    /// Exact twin of `db::tenants::tests::plan_enum_cast_routes_through_text`;
    /// that rule existed and this site did not consume it.
    #[test]
    fn budget_numeric_cast_routes_through_text() {
        assert_eq!(BUDGET_NUMERIC_CAST, "::text::numeric");
        assert!(
            BUDGET_NUMERIC_CAST.contains("::text::"),
            "numeric binds carrying a String must serialize as text, not the bare numeric type"
        );
        // Mirrors the real statement in `create`, `$10` (rate_limit_rpm) included
        // — a pin that stops mirroring the SQL stops pinning anything.
        let values =
            format!("VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9{BUDGET_NUMERIC_CAST}, $10)");
        assert!(values.contains("$9::text::numeric"), "must be text-routed");
        assert!(
            !values
                .replace("$9::text::numeric", "")
                .contains("::numeric"),
            "no bare `$N::numeric` may remain"
        );
    }

    /// Live contract against a real Postgres, the regression the unit suite
    /// cannot express. A bare `$1::numeric` MUST fail `Option<String>` ->
    /// numeric serialization (the shipped bug, and it fails for `None` too),
    /// and the text-routed form MUST round-trip. Read-only; no table writes.
    ///   POSTGRES_TEST_URL=postgres://... cargo test -p gateway --bins \
    ///     db::api_keys::tests::budget_param_serialization_contract -- --ignored
    #[tokio::test]
    #[ignore = "needs a real Postgres; set POSTGRES_TEST_URL"]
    async fn budget_param_serialization_contract() {
        let url = std::env::var("POSTGRES_TEST_URL").expect("POSTGRES_TEST_URL");
        let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let none: Option<String> = None;
        let some: Option<String> = Some("12.3400".to_string());
        // The shipped bug — and note it fails even for NULL, because the type
        // check precedes any NULL handling. That is why no input avoided it.
        assert!(
            client
                .query_one("SELECT $1::numeric", &[&none])
                .await
                .is_err(),
            "bare $1::numeric must fail Option<String> serialization, even for None"
        );
        assert!(
            client
                .query_one("SELECT $1::numeric", &[&some])
                .await
                .is_err(),
            "bare $1::numeric must fail Option<String> serialization for Some too"
        );
        // The fix.
        for v in [&none, &some] {
            client
                .query_one("SELECT $1::text::numeric", &[v])
                .await
                .expect("text-routed numeric must serialize and round-trip");
        }
    }
}

#[cfg(test)]
mod stale_while_revalidate {

    // SRE audit finding 49. Falsifies the bound in BOTH directions: under the cap
    // nothing is evicted, at the cap the map does not grow past it. Without
    // `evict_last_known_if_full` the second assert fails (the map was unbounded).
    #[test]
    fn last_known_is_bounded_and_evicts_the_stalest() {
        use std::collections::HashMap;
        let mk = |n: u8| {
            let mut d = [0u8; 32];
            d[0] = n;
            d
        };
        let mut m: HashMap<[u8; 32], (CachedAuth, Instant)> = HashMap::new();
        let sample: CachedAuth = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            tracelane_shared::api_scope::KeyScope::from_column(None),
            None,
            None,
            tracelane_shared::spend::BudgetReset::Monthly,
            None,
            None,
        );
        for n in 0..5u8 {
            m.insert(mk(n), (sample.clone(), Instant::now()));
        }
        // Under the cap: untouched.
        evict_last_known_if_full(&mut m, 10, 900);
        assert_eq!(m.len(), 5, "nothing should be evicted below the cap");

        // At the cap with every entry live: it must still come down below it.
        evict_last_known_if_full(&mut m, 5, 900);
        assert!(
            m.len() < 5,
            "at the cap the map must shed an entry; it was unbounded before finding 49"
        );
    }

    use super::*;

    #[test]
    fn stale_bound_is_fifteen_ttls_capped_at_fifteen_minutes() {
        assert_eq!(stale_max_secs(), (auth_cache_ttl_secs() * 15).min(900));
        assert!(stale_max_secs() <= 900);
    }

    #[test]
    fn a_remembered_answer_is_served_until_forgotten() {
        let digest = [7u8; 32];
        let entry: CachedAuth = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            tracelane_shared::api_scope::KeyScope::from_column(None),
            None,
            None,
            tracelane_shared::spend::BudgetReset::Monthly,
            None,
            None,
        );
        remember_last_known(digest, entry);
        assert!(
            last_known_fresh_enough(digest).is_some(),
            "served while fresh enough"
        );
        forget_last_known(digest);
        assert!(
            last_known_fresh_enough(digest).is_none(),
            "a revoked key is never served stale"
        );
    }
}

#[cfg(test)]
mod rotation_cache_tests {
    use super::*;

    #[tokio::test]
    async fn cached_rotation_deadline_denies_at_boundary_without_database() {
        let _ = init_pepper(&"11".repeat(32));
        let body = "unit-test-rotation-cached-deadline";
        let digest = peppered_lookup(body).unwrap();
        let deadline = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry: CachedAuth = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            tracelane_shared::api_scope::KeyScope::from_column(None),
            None,
            None,
            tracelane_shared::spend::BudgetReset::Monthly,
            Some(deadline),
            None,
        );
        let mut config = deadpool_postgres::Config::new();
        config.host = Some("unused.invalid".into());
        config.dbname = Some("unused".into());
        let pool = config
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .unwrap();
        auth_cache().insert(digest, entry).await;
        assert!(
            lookup_tenant_by_key_body_at(&pool, body, deadline - chrono::Duration::seconds(1))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            lookup_tenant_by_key_body_at(&pool, body, deadline)
                .await
                .unwrap()
                .is_none(),
            "a warm credential must fail at its scheduled revocation deadline"
        );
        let entry = auth_cache().get(&digest).await.unwrap();
        remember_last_known(digest, entry);
        auth_cache().invalidate(&digest).await;
        assert!(
            lookup_tenant_by_key_body_at(&pool, body, deadline)
                .await
                .unwrap()
                .is_none(),
            "a stale credential must fail at its scheduled revocation deadline"
        );
        invalidate(digest).await;
    }

    #[test]
    fn rotation_deadline_uses_earlier_expiry_and_preserves_unbounded_keys() {
        let early = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let late = early + chrono::Duration::hours(1);
        assert_eq!(auth_deadline(Some(early), Some(late)), Some(early));
        assert_eq!(auth_deadline(Some(late), Some(early)), Some(early));
        assert_eq!(auth_deadline(None, Some(late)), Some(late));
        assert_eq!(auth_deadline(Some(early), None), Some(early));
        assert_eq!(auth_deadline(None, None), None);
        assert!(valid_rotation_grace(0));
        assert!(!valid_rotation_grace(-1));
        assert!(!valid_rotation_grace(i64::MAX));
    }
}

/// rev4 H1 d / M1: the valid-key set, against a counting fake `api_keys` read
/// (the real read runs in `tests/postgres_tenant_integration.rs`).
#[cfg(test)]
mod known_keys_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    fn cfg(refresh_ms: u64) -> KnownKeysConfig {
        KnownKeysConfig {
            refresh: Duration::from_millis(refresh_ms),
            wait: Duration::from_secs(5),
            full_reload: Duration::from_secs(3600),
            overlap: Duration::from_secs(300),
            max: 1_000,
        }
    }

    fn digest(n: u32) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[..4].copy_from_slice(&n.to_be_bytes());
        d
    }

    /// A fake `api_keys`: the live digests, and every read it served
    /// (`None` = full, `Some(_)` = delta).
    #[derive(Clone, Default)]
    struct Table {
        keys: Arc<parking_lot::Mutex<Vec<[u8; 32]>>>,
        reads: Arc<parking_lot::Mutex<Vec<Option<DateTime<Utc>>>>>,
        fail: Arc<std::sync::atomic::AtomicBool>,
    }

    type Read = std::pin::Pin<Box<dyn std::future::Future<Output = Result<KeySnapshot>> + Send>>;

    impl Table {
        fn with(keys: &[[u8; 32]]) -> Self {
            let t = Self::default();
            t.keys.lock().extend_from_slice(keys);
            t
        }
        fn fetch(&self) -> impl FnOnce(Option<DateTime<Utc>>) -> Read + use<> {
            let t = self.clone();
            move |since| {
                Box::pin(async move {
                    t.reads.lock().push(since);
                    if t.fail.load(Ordering::SeqCst) {
                        anyhow::bail!("pool: connection refused");
                    }
                    Ok(KeySnapshot {
                        at: Utc::now(),
                        hashes: t.keys.lock().clone(),
                    })
                })
            }
        }
        fn reads(&self) -> usize {
            self.reads.lock().len()
        }
    }

    #[tokio::test]
    async fn a_flood_of_junk_is_refused_with_one_read_for_everyone() {
        let table = Table::with(&[digest(1)]);
        let k = Arc::new(KnownKeys::new(cfg(200)));
        // 500 different never-seen digests, all at once.
        let flood = (100..600u32).map(|n| {
            let (k, t) = (Arc::clone(&k), table.clone());
            async move { k.classify(&digest(n), t.fetch()).await }
        });
        let answers = futures::future::join_all(flood).await;
        assert!(
            answers.iter().all(|m| *m == Membership::Absent),
            "{answers:?}"
        );
        assert!(
            table.reads() <= 2,
            "500 junk digests cost {} reads; one load (+ one refresh for late arrivals)",
            table.reads()
        );
        // The valid key is present, with no further read.
        let before = table.reads();
        assert_eq!(
            k.classify(&digest(1), table.fetch()).await,
            Membership::Present
        );
        assert_eq!(table.reads(), before);
    }

    #[tokio::test]
    async fn a_key_minted_elsewhere_is_present_after_one_refresh_and_a_local_mint_at_once() {
        let table = Table::with(&[digest(1)]);
        let k = KnownKeys::new(cfg(50));
        assert_eq!(
            k.classify(&digest(9), table.fetch()).await,
            Membership::Absent
        );
        // Another instance mints digest 2.
        table.keys.lock().push(digest(2));
        let t0 = Instant::now();
        assert_eq!(
            k.classify(&digest(2), table.fetch()).await,
            Membership::Present
        );
        assert!(t0.elapsed() < Duration::from_secs(1));
        assert!(
            table.reads.lock().last().is_some_and(Option::is_some),
            "the refresh is a DELTA read, not a reload"
        );
        // A mint in THIS process needs no read at all.
        let before = table.reads();
        k.note_minted(digest(3));
        assert_eq!(
            k.classify(&digest(3), table.fetch()).await,
            Membership::Present
        );
        assert_eq!(table.reads(), before);
    }

    #[tokio::test]
    async fn a_full_reload_drops_a_revoked_key() {
        let table = Table::with(&[digest(1), digest(2)]);
        let mut c = cfg(10);
        c.full_reload = Duration::from_millis(30);
        let k = KnownKeys::new(c);
        assert_eq!(
            k.classify(&digest(2), table.fetch()).await,
            Membership::Present
        );
        // Digest 2 is revoked; the next FULL read no longer returns it.
        table.keys.lock().retain(|d| *d != digest(2));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            k.classify(&digest(7), table.fetch()).await,
            Membership::Absent
        );
        assert!(
            table.reads.lock().last().is_some_and(Option::is_none),
            "past full_reload the read is FULL"
        );
        assert_eq!(
            k.classify(&digest(2), table.fetch()).await,
            Membership::Absent
        );
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_read_falls_back_to_the_gated_lookup_without_waiting() {
        let table = Table::with(&[digest(1)]);
        table.fail.store(true, Ordering::SeqCst);
        let k = KnownKeys::new(cfg(60_000));
        assert_eq!(
            k.classify(&digest(1), table.fetch()).await,
            Membership::Unknown
        );
        // A second miss inside the refresh interval does not wait on a dead store.
        let t0 = Instant::now();
        assert_eq!(
            k.classify(&digest(5), table.fetch()).await,
            Membership::Unknown
        );
        assert!(t0.elapsed() < Duration::from_millis(500));
        assert_eq!(table.reads(), 1, "no second read inside the interval");
        assert!(!k.is_loaded());
    }

    #[tokio::test]
    async fn more_keys_than_the_ceiling_disables_the_set() {
        let keys: Vec<[u8; 32]> = (0..20).map(digest).collect();
        let table = Table::with(&keys);
        let mut c = cfg(10);
        c.max = 10;
        let k = KnownKeys::new(c);
        assert_eq!(
            k.classify(&digest(3), table.fetch()).await,
            Membership::Unknown
        );
        assert!(
            !k.is_loaded(),
            "an oversized set is dropped, never half-held"
        );
    }

    #[tokio::test]
    async fn a_miss_that_outwaits_its_read_takes_the_gated_lookup() {
        let k = KnownKeys::new(KnownKeysConfig {
            wait: Duration::from_millis(20),
            ..cfg(10)
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let m = k
            .classify(&digest(1), move |_since| {
                c.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<KeySnapshot>>()
            })
            .await;
        assert_eq!(m, Membership::Unknown);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
