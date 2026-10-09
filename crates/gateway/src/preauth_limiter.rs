//! Pre-auth bounds on the ONE store-reaching authentication stage (B-594,
//! 2026-10-03 — supersedes the B-383 f failed-401 window of 2026-09-12; hardened
//! the same day after security review rev4).
//!
//! # Why
//!
//! Every `tlane_` string a caller sends costs a peppered HMAC and three cache
//! probes (positive, negative, stale last-known — `db::api_keys`). Only a key
//! none of them has seen reaches Postgres, and a NEW random key per request
//! defeats the 30 s negative cache by construction. Cloudflare Free cannot rate
//! limit by response status, and a per-IP limit on ALL traffic would throttle
//! real customers behind one egress IP. So the bounds sit on exactly that stage
//! ([`crate::db::api_keys::gated_cold_lookup`]), in this order:
//!
//! 1. **The valid-key set** (`db::api_keys::KnownKeys`, configured here at boot):
//!    a digest no live key has is a 401 with no per-key Postgres lookup and no
//!    token; a live key's digest skips the per-source bucket entirely.
//! 2. **The per-source bucket** (this module), only when the set cannot answer:
//!    a token RESERVED before `pool.get()`, refunded only when no SQL ran.
//! 3. **The slots** (this module sizes them): a fixed share of the Postgres pool
//!    across ALL sources; over it a lookup waits `cold_lookup_wait_ms`, then 429.
//!
//! # What it is not
//!
//! - Not a request rate limit (per-tenant, after auth, `rate_limiter.rs`).
//! - Never a refusal of a WARM key: the positive cache, the stale last-known
//!   answer and the negative cache answer before any bound. A COLD valid key is
//!   in the valid-key set, so a scanner on the same egress cannot empty a bucket
//!   it is charged to (rev4 M1 — the "≤ 1 s" this doc once promised was wrong: one
//!   junk key per second ate every refill). It CAN be refused 429 by the slots
//!   when every slot stays busy for `cold_lookup_wait_ms` — a saturation of the
//!   whole store path, not of its source — and, only while the set is
//!   unavailable, by its source's bucket as before.
//!
//! # The source — a forwarding header is believed only from a trusted proxy
//!
//! The TCP peer comes from `ConnectInfo` (`server.rs` serves with it). If the
//! peer is inside `trusted_proxy_cidrs` (default: loopback and private —
//! `127/8`, `10/8`, `172.16/12`, `192.168/16`, `::1`, `fc00::/7`) it is a proxy
//! hop, and the source is the `client_ip_header` (default `cf-connecting-ip`),
//! else the RIGHTMOST `x-forwarded-for` entry (the one that hop appended — the
//! leftmost is whatever the client wrote), else the peer. On prod the hop is
//! Caddy on the docker network, Caddy is reachable on :443 only from
//! Cloudflare's ranges (`infra/prod/docker-compose.yml`, the `tl-fw` firewall)
//! and Cloudflare overwrites `cf-connecting-ip` — that chain is what makes the
//! header true. Any OTHER peer is the source itself and every header is ignored,
//! so rotating a forged header per request buys nothing. A value that does not
//! parse as an IP is ignored, so a garbage string cannot mint a fresh bucket.
//! IPv6 is aggregated to its `/ipv6_prefix_len` network (64 by default) AND must
//! also find a token in its `/ipv6_wide_prefix_len` network (48): one subscriber
//! is a /64, and one site is a /48 — not 65,536 sources.
//!
//! **Residual, stated:** an operator whose proxy sits in a trusted range and
//! forwards a client-supplied header unmodified is spoofable; that proxy must
//! overwrite or strip it, or the operator narrows `trusted_proxy_cidrs` (L2: both
//! are table values now, defaults = the behaviour before).
//!
//! # Memory
//!
//! At most `max_sources` buckets. When full, a sweep (at most once per
//! `sweep_interval_ms`, so a flood cannot make every request O(n)) drops
//! buckets that have refilled — a full bucket is the same as no bucket. If the
//! map is still full the source is charged against ONE shared overflow bucket,
//! and the `auth_throttle_overflow` degradation says it is happening.
//!
//! Tunables: `crates/gateway/translation_policy.v1.json` → `auth_throttle`
//! (CLAUDE.md §23). Spec: `specs/B-594-auth-failure-ip-limiter.md`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State, connect_info::MockConnectInfo},
    http::{Extensions, HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use tracelane_shared::degradation::{self, Degradation};

use crate::db::api_keys::{ColdGateScope, ColdLookupGate, ColdSlots, KnownKeysConfig, Reservation};
use crate::providers::translation_policy::{AuthThrottlePolicy, auth_throttle_policy};

/// Cold lookups refused 429 because the source's bucket was empty (the
/// `/metrics` series `tracelane_gateway_auth_throttled_total`, and `/health`).
pub static AUTH_THROTTLED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Store-reaching lookups that found no valid key — the token stayed spent.
pub static AUTH_FAILURES_CHARGED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Cold lookups charged to the shared overflow bucket (the map was full).
pub static AUTH_THROTTLE_OVERFLOW_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Buckets in the map at the last insert or sweep (approximate: DashMap `len`).
/// `/metrics` only — not `/health` (rev4 L3).
pub static SOURCES_TRACKED: AtomicU64 = AtomicU64::new(0);

/// Millitokens per token: the bucket counts in thousandths so refill needs no
/// floating point.
const MILLI: u64 = 1_000;
/// `last_sweep_ms` before the first sweep.
const NEVER: u64 = u64::MAX;
/// The gateway's own Postgres pool size (`db/mod.rs` `max_size: 16`), used to size
/// the slots only when there is no pool to ask (tests; a gateway without Postgres
/// takes no cold lookup at all).
const POOL_SIZE_WITHOUT_A_POOL: usize = 16;

/// [`Reservation`] bits: the source's own token went to the overflow bucket; a
/// wide-network token was taken; that token went to the overflow bucket.
const RES_PRIMARY_OVERFLOW: u8 = 1;
const RES_WIDE_TAKEN: u8 = 2;
const RES_WIDE_OVERFLOW: u8 = 4;

/// Who is asking, as the bucket map keys it — an opaque, `Copy` `u128`, so
/// deriving it allocates nothing. IPv4 is tagged `4 << 64 | addr`; an IPv6
/// network `6 << 64 | prefix`; a WIDE IPv6 network `7 << 64 | prefix`; none of
/// them can collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceKey(u128);

impl SourceKey {
    /// No peer and no header: in-process callers only (tests).
    pub const UNKNOWN: Self = Self(0);

    /// The key for one address. IPv4-mapped IPv6 is IPv4; other IPv6 is cut to
    /// its `/v6_prefix_len` network (clamped to 1..=64).
    #[must_use]
    pub fn of_ip(ip: IpAddr, v6_prefix_len: u8) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(a) => Self::v4(a),
            IpAddr::V6(a) => Self::v6_net(a, v6_prefix_len),
        }
    }

    /// The opaque value (what the cold-lookup gate is handed).
    #[must_use]
    pub fn raw(self) -> u128 {
        self.0
    }

    fn v4(a: Ipv4Addr) -> Self {
        Self((4u128 << 64) | u128::from(u32::from(a)))
    }

    fn v6_net(a: Ipv6Addr, prefix_len: u8) -> Self {
        let len = u32::from(prefix_len.clamp(1, 64));
        let mask = u128::MAX << (128 - len);
        Self((6u128 << 64) | ((u128::from(a) & mask) >> 64))
    }

    /// For an IPv6 source, its `/wide_len` network — the second bucket that must
    /// also have a token (rev4 H1 c). `None` for IPv4, `UNKNOWN`, or a wide prefix
    /// no shorter than the source's own.
    #[must_use]
    pub fn wide(self, wide_len: u8, prefix_len: u8) -> Option<Self> {
        if self.0 >> 64 != 6 || wide_len >= prefix_len.clamp(1, 64) {
            return None;
        }
        let upper = self.0 & u128::from(u64::MAX);
        let mask = u128::from(u64::MAX) << (64 - u32::from(wide_len.clamp(1, 63)));
        Some(Self((7u128 << 64) | (upper & mask & u128::from(u64::MAX))))
    }
}

fn header_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)?
        .to_str()
        .ok()?
        .trim()
        .parse::<IpAddr>()
        .ok()
}

/// The RIGHTMOST `x-forwarded-for` entry across every header line — the one the
/// proxy hop appended. The leftmost is the client's to write.
fn rightmost_forwarded(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()?
        .to_str()
        .ok()?
        .rsplit(',')
        .next()?
        .trim()
        .parse::<IpAddr>()
        .ok()
}

/// The TCP peer of a request: the listener's `ConnectInfo`, else axum's own test
/// stand-in `MockConnectInfo` (which its `ConnectInfo` extractor also honours), else
/// `None` (an in-process router with neither).
#[must_use]
pub fn peer_of(ext: &Extensions) -> Option<IpAddr> {
    ext.get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .or_else(|| ext.get::<MockConnectInfo<SocketAddr>>().map(|m| m.0.ip()))
}

/// The source for a request (module doc, "The source"). `peer` is `None` only
/// for an in-process router with no `ConnectInfo` (tests), which is treated as
/// a proxy hop.
#[must_use]
pub fn source_of(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    policy: &AuthThrottlePolicy,
) -> SourceKey {
    client_ip(headers, peer, policy).map_or(SourceKey::UNKNOWN, |ip| {
        SourceKey::of_ip(ip, policy.ipv6_prefix_len)
    })
}

/// The client's address, as the module doc's "The source" derives it — the ONE
/// derivation: the throttle keys on it ([`source_of`]) and `OG-20`'s `source_ips` rule
/// reads it (carried on the request's `ColdGateScope`, read back by
/// `db::api_keys::current_client_ip`). A forwarding header is believed only from a
/// peer inside `policy.trusted_proxy_cidrs` (rev4 L2: a table value); any other peer is
/// the client and every header is ignored. `None` only when there is no peer AND no
/// parseable header (in-process tests).
#[must_use]
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    policy: &AuthThrottlePolicy,
) -> Option<IpAddr> {
    let peer = peer.map(|p| p.to_canonical());
    let trusted = peer.is_none_or(|p| policy.trusted_proxy_cidrs.iter().any(|c| c.contains(p)));
    if trusted {
        (!policy.client_ip_header.is_empty())
            .then(|| header_ip(headers, &policy.client_ip_header))
            .flatten()
            .or_else(|| rightmost_forwarded(headers))
            .or(peer)
    } else {
        peer
    }
}

#[derive(Debug)]
struct Bucket {
    milli: u64,
    at: Instant,
}

/// The per-source token ledger. `Clone` is cheap (one `Arc`).
#[derive(Clone)]
pub struct PreAuthLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    policy: AuthThrottlePolicy,
    buckets: DashMap<SourceKey, Bucket>,
    overflow: parking_lot::Mutex<Bucket>,
    epoch: Instant,
    last_sweep_ms: AtomicU64,
    slots: ColdSlots,
}

/// The slot count for a pool of `pool_size` connections at `pct` percent (≥ 1).
fn slot_count(pool_size: usize, pct: u8) -> usize {
    (pool_size * usize::from(pct) / 100).max(1)
}

impl PreAuthLimiter {
    /// The limiter the gateway runs: the `auth_throttle` reference table, its slots
    /// sized from the live Postgres pool. Also installs those slots for cold
    /// lookups that run outside a request scope, and — when a pool exists — turns
    /// the valid-key set on (`db::api_keys::configure_known_keys`). Called once, at
    /// boot (`server.rs`).
    #[must_use]
    pub fn from_policy() -> Self {
        let policy = auth_throttle_policy().clone();
        let pool_size = crate::db::global_pool().map(|p| p.status().max_size);
        let limiter = Self::with_policy_and_pool(policy, pool_size);
        crate::db::api_keys::install_unscoped_cold_slots(limiter.inner.slots.clone());
        if pool_size.is_some() {
            let p = &limiter.inner.policy;
            crate::db::api_keys::configure_known_keys(KnownKeysConfig {
                refresh: Duration::from_millis(p.known_keys_refresh_ms),
                wait: Duration::from_millis(p.known_keys_wait_ms),
                full_reload: Duration::from_secs(p.known_keys_full_reload_secs),
                overlap: Duration::from_secs(p.known_keys_overlap_secs),
                max: p.known_keys_max,
            });
        }
        // Boot-time configuration — a lifecycle line, once (logging.md: INFO).
        tracing::info!(
            cold_lookup_slots = limiter.inner.slots.size(),
            valid_key_set = pool_size.is_some(),
            "auth-failure bounds configured"
        );
        limiter
    }

    /// A limiter whose burst and per-minute refill are both `burst`, the rest
    /// from the table — the shape tests want.
    #[cfg(test)]
    #[must_use]
    pub fn new(burst: u32) -> Self {
        Self::with_policy(AuthThrottlePolicy {
            burst: burst.max(1),
            refill_per_minute: burst.max(1),
            ..auth_throttle_policy().clone()
        })
    }

    /// A limiter over `policy`, its slots sized as if for the gateway's default pool.
    #[cfg(test)]
    #[must_use]
    pub fn with_policy(policy: AuthThrottlePolicy) -> Self {
        Self::with_policy_and_pool(policy, None)
    }

    fn with_policy_and_pool(policy: AuthThrottlePolicy, pool_size: Option<usize>) -> Self {
        let now = Instant::now();
        let slots = ColdSlots::new(
            slot_count(
                pool_size.unwrap_or(POOL_SIZE_WITHOUT_A_POOL),
                policy.cold_lookup_pool_pct,
            ),
            Duration::from_millis(policy.cold_lookup_wait_ms),
        );
        let inner = Inner {
            overflow: parking_lot::Mutex::new(Bucket {
                milli: policy.burst_milli(),
                at: now,
            }),
            policy,
            buckets: DashMap::new(),
            epoch: now,
            last_sweep_ms: AtomicU64::new(NEVER),
            slots,
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// The limiter as a request's cold-lookup gate (test scopes only; the layer builds its
    /// own).
    #[cfg(test)]
    pub(crate) fn gate_for_tests(&self) -> Arc<dyn ColdLookupGate> {
        self.inner.clone()
    }

    /// Buckets currently held (tests; `/metrics` reads the gauge).
    #[cfg(test)]
    #[must_use]
    pub fn sources(&self) -> usize {
        self.inner.buckets.len()
    }

    /// Reserve one token for `source` at an explicit `now` (tests drive time).
    ///
    /// # Errors
    /// Fail-CLOSED: `Err(retry_after_secs)` from an empty bucket.
    #[cfg(test)]
    pub fn acquire_at(&self, source: SourceKey, now: Instant) -> Result<Reservation, u64> {
        self.inner.acquire(source, now)
    }
}

impl AuthThrottlePolicy {
    fn burst_milli(&self) -> u64 {
        u64::from(self.burst) * MILLI
    }
}

impl Inner {
    fn refill(&self, b: &mut Bucket, now: Instant) {
        let us = u64::try_from(now.saturating_duration_since(b.at).as_micros()).unwrap_or(u64::MAX);
        // millitokens = µs × (tokens/min) × 1000 / 60e6 = µs × rate / 60_000.
        let add = us.saturating_mul(u64::from(self.policy.refill_per_minute)) / 60_000;
        if add > 0 {
            b.milli = b.milli.saturating_add(add).min(self.policy.burst_milli());
            b.at = now;
        }
    }

    fn take(&self, b: &mut Bucket, now: Instant) -> Result<(), u64> {
        self.refill(b, now);
        if b.milli >= MILLI {
            b.milli -= MILLI;
            return Ok(());
        }
        // Seconds until one whole token, rounded up, at least 1.
        let need_us = (MILLI - b.milli) * 60_000 / u64::from(self.policy.refill_per_minute.max(1));
        Err(need_us.div_ceil(1_000_000).max(1))
    }

    /// Reserve one token for `source` — and, for IPv6, one for its wide network
    /// too (both must allow; rev4 H1 c). `Err(retry_after_secs)` when either is
    /// empty (counted on `AUTH_THROTTLED_TOTAL`); a token taken from the first is
    /// returned when the second refuses. Fail-CLOSED: an empty bucket, or the
    /// shared overflow bucket when the map is full, refuses.
    fn acquire(&self, source: SourceKey, now: Instant) -> Result<Reservation, u64> {
        let r = self.acquire_uncounted(source, now);
        if r.is_err() {
            AUTH_THROTTLED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    fn acquire_uncounted(&self, source: SourceKey, now: Instant) -> Result<Reservation, u64> {
        let primary_overflow = self.acquire_one(source, now)?;
        let mut bits = if primary_overflow {
            RES_PRIMARY_OVERFLOW
        } else {
            0
        };
        if let Some(wide) = source.wide(
            self.policy.ipv6_wide_prefix_len,
            self.policy.ipv6_prefix_len,
        ) {
            match self.acquire_one(wide, now) {
                Ok(wide_overflow) => {
                    bits |= RES_WIDE_TAKEN;
                    if wide_overflow {
                        bits |= RES_WIDE_OVERFLOW;
                    }
                }
                Err(retry_after) => {
                    self.refund_one(source, primary_overflow);
                    return Err(retry_after);
                }
            }
        }
        Ok(Reservation(bits))
    }

    /// Take one token from `key`'s bucket — `Ok(true)` when it came from the
    /// shared overflow bucket because the map was full.
    fn acquire_one(&self, key: SourceKey, now: Instant) -> Result<bool, u64> {
        if let Some(mut b) = self.buckets.get_mut(&key) {
            return self.take(&mut b, now).map(|()| false);
        }
        if self.buckets.len() >= self.policy.max_sources {
            self.maybe_sweep(now);
        }
        if self.buckets.len() >= self.policy.max_sources {
            AUTH_THROTTLE_OVERFLOW_TOTAL.fetch_add(1, Ordering::Relaxed);
            degradation::note(Degradation::AuthThrottleOverflow);
            let mut b = self.overflow.lock();
            return self.take(&mut b, now).map(|()| true);
        }
        let r = {
            let mut b = self.buckets.entry(key).or_insert_with(|| Bucket {
                milli: self.policy.burst_milli(),
                at: now,
            });
            self.take(&mut b, now)
        };
        SOURCES_TRACKED.store(self.buckets.len() as u64, Ordering::Relaxed);
        r.map(|()| false)
    }

    /// Give one token back to where it was charged. A bucket swept away since is
    /// a full bucket already — nothing to return to.
    fn refund_one(&self, key: SourceKey, overflow: bool) {
        let cap = self.policy.burst_milli();
        if overflow {
            let mut b = self.overflow.lock();
            b.milli = (b.milli + MILLI).min(cap);
        } else if let Some(mut b) = self.buckets.get_mut(&key) {
            b.milli = (b.milli + MILLI).min(cap);
        }
    }

    /// Give a reservation back: every token it took, to where each was charged.
    fn refund(&self, source: SourceKey, r: Reservation) {
        self.refund_one(source, r.0 & RES_PRIMARY_OVERFLOW != 0);
        if r.0 & RES_WIDE_TAKEN != 0
            && let Some(wide) = source.wide(
                self.policy.ipv6_wide_prefix_len,
                self.policy.ipv6_prefix_len,
            )
        {
            self.refund_one(wide, r.0 & RES_WIDE_OVERFLOW != 0);
        }
    }

    /// Drop every bucket that has refilled — at most once per sweep interval,
    /// so a flood of new sources cannot make each request walk the map.
    fn maybe_sweep(&self, now: Instant) {
        let now_ms = u64::try_from(now.saturating_duration_since(self.epoch).as_millis())
            .unwrap_or(NEVER - 1);
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if last != NEVER && now_ms.saturating_sub(last) < self.policy.sweep_interval_ms {
            return;
        }
        if self
            .last_sweep_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // another request is sweeping
        }
        let cap = self.policy.burst_milli();
        self.buckets.retain(|_, b| {
            self.refill(b, now);
            b.milli < cap
        });
        let len = self.buckets.len();
        SOURCES_TRACKED.store(len as u64, Ordering::Relaxed);
        if len < self.policy.max_sources {
            degradation::resolve(Degradation::AuthThrottleOverflow);
        }
    }
}

impl ColdLookupGate for Inner {
    fn try_acquire(&self, source: u128) -> Result<Reservation, u64> {
        self.acquire(SourceKey(source), Instant::now())
    }

    fn refund(&self, source: u128, reservation: Reservation) {
        Inner::refund(self, SourceKey(source), reservation);
    }

    fn charge(&self, _source: u128) {
        AUTH_FAILURES_CHARGED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    fn slots(&self) -> Option<&ColdSlots> {
        Some(&self.slots)
    }
}

/// The `/health` `auth_throttle` object. `/health` is PUBLIC (rev4 L3): it says the
/// bounds are working — 429s answered, whether the valid-key set is loaded — and
/// nothing a scanner could tune against (the live bucket-map size, the overflow
/// count, the failed-lookup count, the slot size). Those are on the loopback-only
/// `/metrics` listener (`metrics.rs`), which is never routed through Caddy.
#[must_use]
pub fn health_json() -> serde_json::Value {
    serde_json::json!({
        "throttled": AUTH_THROTTLED_TOTAL.load(Ordering::Relaxed)
            + crate::db::api_keys::AUTH_COLD_SATURATED_TOTAL.load(Ordering::Relaxed),
        "known_keys_loaded": crate::db::api_keys::known_keys()
            .is_some_and(crate::db::api_keys::KnownKeys::is_loaded),
    })
}

fn throttled_response(retry_after_secs: u64) -> Response {
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "error": "auth_throttled",
            "message": "authentication lookups are rate limited; retry after the Retry-After interval"
        })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    resp
}

/// The middleware: give the request a cold-lookup gate keyed on its source,
/// and if that gate refused the lookup, answer one 429 + `Retry-After` whatever
/// the route made of the refusal. Nothing here touches a request whose lookup
/// was not refused.
pub async fn layer(State(limiter): State<PreAuthLimiter>, req: Request, next: Next) -> Response {
    // ONE derivation (OG-20): the address the throttle keys on is the address the
    // `source_ips` policy rule judges, carried on the same per-request scope.
    let peer = peer_of(req.extensions());
    let ip = client_ip(req.headers(), peer, &limiter.inner.policy);
    let source = source_of(req.headers(), peer, &limiter.inner.policy);
    let gate: Arc<dyn ColdLookupGate> = limiter.inner.clone();
    let fut =
        crate::db::api_keys::with_cold_gate(ColdGateScope::new(gate, source.0, ip), next.run(req));
    tokio::pin!(fut);
    let resp = (&mut fut).await;
    let retry_after = fut
        .as_mut()
        .take_value()
        .map_or(0, |s| s.throttled_retry_after.load(Ordering::Relaxed));
    if retry_after > 0 && !resp.status().is_success() {
        return throttled_response(retry_after);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn policy(burst: u32, max_sources: usize) -> AuthThrottlePolicy {
        AuthThrottlePolicy {
            burst,
            refill_per_minute: 60,
            max_sources,
            ipv6_prefix_len: 64,
            sweep_interval_ms: 1_000,
            ..auth_throttle_policy().clone()
        }
    }

    fn v4(s: &str) -> SourceKey {
        SourceKey::of_ip(s.parse().unwrap(), 64)
    }

    #[test]
    fn the_bucket_empties_at_burst_says_when_to_retry_and_refills_with_time() {
        let l = PreAuthLimiter::with_policy(policy(3, 100));
        let t0 = Instant::now();
        let s = v4("192.0.2.1");
        for _ in 0..3 {
            assert!(l.acquire_at(s, t0).is_ok());
        }
        assert_eq!(
            l.acquire_at(s, t0),
            Err(1),
            "60/min: the next token is ≤ 1 s away"
        );
        assert!(
            l.acquire_at(v4("192.0.2.2"), t0).is_ok(),
            "another source is untouched"
        );
        // One second at 60/min is exactly one token; not two.
        let t1 = t0 + Duration::from_secs(1);
        assert!(l.acquire_at(s, t1).is_ok());
        assert!(l.acquire_at(s, t1).is_err());
        // A long idle refills to the burst and no further.
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(l.acquire_at(s, t2).is_ok());
        }
        assert!(l.acquire_at(s, t2).is_err());
    }

    #[test]
    fn a_refund_returns_the_token_and_never_exceeds_the_burst() {
        let l = PreAuthLimiter::with_policy(policy(2, 100));
        let t0 = Instant::now();
        let s = v4("192.0.2.3");
        for _ in 0..100 {
            let r = l.acquire_at(s, t0).expect("a token");
            l.inner.refund(s, r);
        }
        // Many refunds of an untaken token cannot bank more than the burst.
        for _ in 0..10 {
            l.inner.refund(s, Reservation::default());
        }
        assert!(l.acquire_at(s, t0).is_ok());
        assert!(l.acquire_at(s, t0).is_ok());
        assert!(l.acquire_at(s, t0).is_err());
    }

    #[test]
    fn memory_is_bounded_and_untracked_sources_share_one_overflow_budget() {
        // 50,000 distinct sources against a map of 1,000: the map never grows past
        // the cap, and every source past it draws on ONE bucket — so the number of
        // lookups admitted is bounded by (cap + 1) x burst, not by the attacker's
        // address count.
        let (burst, cap) = (5u32, 1_000usize);
        let l = PreAuthLimiter::with_policy(policy(burst, cap));
        let t0 = Instant::now();
        let overflow_before = AUTH_THROTTLE_OVERFLOW_TOTAL.load(Ordering::Relaxed);
        let mut admitted = 0usize;
        for i in 0..50_000u32 {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i);
            if l.acquire_at(SourceKey::of_ip(IpAddr::V4(ip), 64), t0)
                .is_ok()
            {
                admitted += 1;
            }
            assert!(l.sources() <= cap, "map grew to {}", l.sources());
        }
        assert!(
            admitted <= (cap + 1) * burst as usize,
            "{admitted} lookups admitted from 50,000 sources"
        );
        assert!(AUTH_THROTTLE_OVERFLOW_TOTAL.load(Ordering::Relaxed) > overflow_before);
        assert!(
            degradation::count(Degradation::AuthThrottleOverflow) > 0,
            "the overflow is a noted degradation"
        );
        // Once the tracked buckets have refilled, a sweep frees the map again.
        let later = t0 + Duration::from_secs(60);
        assert!(l.acquire_at(v4("198.51.100.200"), later).is_ok());
        assert!(l.sources() < cap, "a sweep dropped the refilled buckets");
    }

    #[test]
    fn source_derivation_trusts_headers_only_from_a_proxy_hop() {
        let p = policy(60, 100);
        let caddy: Option<IpAddr> = Some("172.18.0.5".parse().unwrap());
        let public: Option<IpAddr> = Some("203.0.113.9".parse().unwrap());
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "198.51.100.7".parse().unwrap());
        h.insert("x-forwarded-for", "10.0.0.1, 198.51.100.8".parse().unwrap());
        assert_eq!(
            source_of(&h, caddy, &p),
            v4("198.51.100.7"),
            "CF header first"
        );
        assert_eq!(
            source_of(&h, public, &p),
            v4("203.0.113.9"),
            "a public peer is the source"
        );
        h.remove("cf-connecting-ip");
        assert_eq!(
            source_of(&h, caddy, &p),
            v4("198.51.100.8"),
            "rightmost XFF hop"
        );
        // Garbage never mints a bucket: it falls through to the next rule.
        h.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
        h.insert("x-forwarded-for", "also garbage".parse().unwrap());
        assert_eq!(source_of(&h, caddy, &p), v4("172.18.0.5"));
        assert_eq!(source_of(&HeaderMap::new(), None, &p), SourceKey::UNKNOWN);
        // An IPv4-mapped IPv6 peer is the IPv4 address.
        let mapped: Option<IpAddr> = Some("::ffff:203.0.113.9".parse().unwrap());
        assert_eq!(source_of(&HeaderMap::new(), mapped, &p), v4("203.0.113.9"));
        // Loopback and ULA peers are proxy hops; a public v6 peer is not.
        let ula: Option<IpAddr> = Some("fd00::5".parse().unwrap());
        let mut cf = HeaderMap::new();
        cf.insert("cf-connecting-ip", "198.51.100.9".parse().unwrap());
        assert_eq!(source_of(&cf, ula, &p), v4("198.51.100.9"));
        let v6pub: Option<IpAddr> = Some("2001:db8::9".parse().unwrap());
        assert_eq!(
            source_of(&cf, v6pub, &p),
            SourceKey::of_ip("2001:db8::1".parse().unwrap(), 64)
        );
    }

    /// rev4 L2: which peers are proxies, and which header names the client, are
    /// table values — a self-host behind its own load balancer sets them instead of
    /// being spoofable. The shipped defaults are the behaviour before (the test
    /// above runs on them).
    #[test]
    fn rev4_l2_trusted_proxies_and_the_client_header_come_from_the_table() {
        let mut p = auth_throttle_policy().clone();
        p.trusted_proxy_cidrs =
            vec![crate::providers::translation_policy::Cidr::parse("203.0.113.0/24").unwrap()];
        p.client_ip_header = "x-real-ip".into();
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "198.51.100.21".parse().unwrap());
        h.insert("cf-connecting-ip", "198.51.100.22".parse().unwrap());
        let lb: Option<IpAddr> = Some("203.0.113.9".parse().unwrap());
        let caddy: Option<IpAddr> = Some("172.18.0.5".parse().unwrap());
        assert_eq!(
            source_of(&h, lb, &p),
            v4("198.51.100.21"),
            "the configured proxy, the configured header"
        );
        assert_eq!(
            source_of(&h, caddy, &p),
            v4("172.18.0.5"),
            "a private peer is NOT a proxy unless the table says so"
        );
        // No client header configured: the rightmost XFF entry, then the peer.
        p.client_ip_header = String::new();
        h.insert(
            "x-forwarded-for",
            "10.1.1.1, 198.51.100.23".parse().unwrap(),
        );
        assert_eq!(source_of(&h, lb, &p), v4("198.51.100.23"));
        h.remove("x-forwarded-for");
        assert_eq!(source_of(&h, lb, &p), v4("203.0.113.9"));
    }

    #[test]
    fn rev4_h1c_an_ipv6_source_also_names_its_wide_network() {
        let a = SourceKey::of_ip("2001:db8:1:2::1".parse().unwrap(), 64);
        let b = SourceKey::of_ip("2001:db8:1:3::1".parse().unwrap(), 64);
        let c = SourceKey::of_ip("2001:db8:2:2::1".parse().unwrap(), 64);
        assert_ne!(a, b);
        assert_eq!(a.wide(48, 64), b.wide(48, 64), "one /48");
        assert_ne!(a.wide(48, 64), c.wide(48, 64));
        assert!(
            a.wide(48, 64).is_some_and(|w| w != a),
            "a distinct key space"
        );
        assert_eq!(
            v4("192.0.2.1").wide(48, 64),
            None,
            "IPv4 has no wide bucket"
        );
        assert_eq!(a.wide(64, 64), None, "equal prefixes = no second bucket");
        assert_eq!(SourceKey::UNKNOWN.wide(48, 64), None);
    }

    #[test]
    fn ipv6_keys_are_the_configured_network_and_never_collide_with_ipv4() {
        let a = SourceKey::of_ip("2001:db8:1:2::1".parse().unwrap(), 64);
        let b = SourceKey::of_ip("2001:db8:1:2:ffff::1".parse().unwrap(), 64);
        let c = SourceKey::of_ip("2001:db8:1:3::1".parse().unwrap(), 64);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // A /48 policy folds the neighbouring /64 in.
        assert_eq!(
            SourceKey::of_ip("2001:db8:1:2::1".parse().unwrap(), 48),
            SourceKey::of_ip("2001:db8:1:3::1".parse().unwrap(), 48)
        );
        // 0.0.0.1 and ::1-in-a-zero-network do not share a key.
        assert_ne!(
            SourceKey::of_ip("0.0.0.1".parse().unwrap(), 64),
            SourceKey::of_ip("::2:0:0:1".parse().unwrap(), 64)
        );
    }
}

/// B-594 (2026-10-03): the flood is bounded at the STORE, a valid key is not
/// collateral, and the source cannot be forged. These drive the real middleware
/// and the real `db::api_keys::gated_cold_lookup` around a counting fake store
/// (the same wrapper `lookup_tenant_by_key_body_at` puts around its Postgres stage).
#[cfg(test)]
mod b594 {
    use super::*;
    use crate::db::api_keys::Gating;
    use axum::{Router, routing::get};
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;
    use tower::ServiceExt as _;

    /// A key validator shaped like the real one: a warm hit never reaches the
    /// store; anything else goes through the gated cold stage, which counts.
    #[derive(Clone)]
    struct Fake {
        warm: Arc<HashSet<String>>,
        valid_cold: Arc<HashSet<String>>,
        /// The query fails AFTER the connection was checked out (SQL ran).
        store_fails: bool,
        /// `pool.get()` fails — no SQL ran.
        checkout_fails: bool,
        store_calls: Arc<AtomicU32>,
        in_flight: Arc<AtomicU32>,
        max_in_flight: Arc<AtomicU32>,
    }

    impl Fake {
        fn new(warm: &[&str], valid_cold: &[&str]) -> Self {
            Self {
                warm: Arc::new(warm.iter().map(|s| (*s).to_owned()).collect()),
                valid_cold: Arc::new(valid_cold.iter().map(|s| (*s).to_owned()).collect()),
                store_fails: false,
                checkout_fails: false,
                store_calls: Arc::new(AtomicU32::new(0)),
                in_flight: Arc::new(AtomicU32::new(0)),
                max_in_flight: Arc::new(AtomicU32::new(0)),
            }
        }
        fn calls(&self) -> u32 {
            self.store_calls.load(Ordering::SeqCst)
        }
        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(Ordering::SeqCst) as usize
        }
    }

    async fn fake_auth(State(f): State<Fake>, headers: HeaderMap) -> Response {
        let key = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        if f.warm.contains(&key) {
            return StatusCode::OK.into_response();
        }
        let calls = Arc::clone(&f.store_calls);
        let (in_flight, max_in_flight) = (Arc::clone(&f.in_flight), Arc::clone(&f.max_in_flight));
        let valid = f.valid_cold.contains(&key);
        let (fails, checkout_fails) = (f.store_fails, f.checkout_fails);
        let r = crate::db::api_keys::gated_cold_lookup(Gating::Source, |mark| async move {
            calls.fetch_add(1, Ordering::SeqCst);
            if checkout_fails {
                // `pool.get()` refused: no SQL ran.
                return Err(crate::auth::AuthStoreUnavailable {
                    detail: "pool: connection refused".into(),
                }
                .into());
            }
            mark.started();
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max_in_flight.fetch_max(now, Ordering::SeqCst);
            // Hold the "query" open so concurrent requests overlap in the store.
            tokio::time::sleep(Duration::from_millis(5)).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            if fails {
                return Err(crate::auth::AuthStoreUnavailable {
                    detail: "query: statement timeout".into(),
                }
                .into());
            }
            Ok(valid.then_some(()))
        })
        .await;
        match r {
            Ok(Some(())) => StatusCode::OK.into_response(),
            Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
            Err(e) => crate::auth::failure(&e).0.into_response(),
        }
    }

    fn app(limiter: PreAuthLimiter, fake: Fake, peer: &str) -> Router {
        let peer: SocketAddr = peer.parse().unwrap();
        Router::new()
            .route("/v1/x", get(fake_auth))
            .with_state(fake)
            .layer(axum::middleware::from_fn_with_state(limiter, layer))
            .layer(MockConnectInfo(peer))
    }

    /// Caddy on the prod docker network — a private, trusted proxy hop.
    const CADDY: &str = "172.18.0.5:41000";

    fn req(key: &str, headers: &[(&str, &str)]) -> axum::http::Request<axum::body::Body> {
        let mut b = axum::http::Request::builder()
            .uri("/v1/x")
            .header(header::AUTHORIZATION, key);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    async fn status(app: &Router, r: axum::http::Request<axum::body::Body>) -> StatusCode {
        app.clone().oneshot(r).await.unwrap().status()
    }

    #[tokio::test]
    async fn a_flood_of_never_seen_keys_reaches_the_store_at_most_burst_times() {
        let fake = Fake::new(&[], &[]);
        let app = app(PreAuthLimiter::new(60), fake.clone(), CADDY);
        let mut refused = 0;
        for i in 0..500 {
            let r = app
                .clone()
                .oneshot(req(
                    &format!("tlane_junk_seq_{i}"),
                    &[("cf-connecting-ip", "198.51.100.10")],
                ))
                .await
                .unwrap();
            if r.status() == StatusCode::TOO_MANY_REQUESTS {
                refused += 1;
                assert!(
                    r.headers().get(header::RETRY_AFTER).is_some(),
                    "a 429 must say when to retry"
                );
            }
        }
        // The loop's own wall clock refills at most a few tokens at 60/min.
        assert!(fake.calls() <= 65, "store reached {} times", fake.calls());
        assert!(refused >= 435, "only {refused} of 500 refused");
    }

    #[tokio::test]
    async fn a_concurrent_flood_cannot_outrun_the_bucket() {
        // Counting 401s AFTER the handler (B-383 f) lets every in-flight request
        // through before the first failure lands. A reserved token does not.
        let fake = Fake::new(&[], &[]);
        let app = app(PreAuthLimiter::new(10), fake.clone(), CADDY);
        let reqs = (0..200).map(|i| {
            app.clone().oneshot(req(
                &format!("tlane_junk_par_{i}"),
                &[("cf-connecting-ip", "198.51.100.11")],
            ))
        });
        let statuses: Vec<StatusCode> = futures::future::join_all(reqs)
            .await
            .into_iter()
            .map(|r| r.unwrap().status())
            .collect();
        assert!(
            fake.calls() <= 11,
            "200 concurrent junk keys reached the store {} times against a burst of 10",
            fake.calls()
        );
        assert!(
            statuses
                .iter()
                .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
                .count()
                >= 189
        );
    }

    #[tokio::test]
    async fn a_valid_warm_key_from_the_flooding_source_is_still_served() {
        let fake = Fake::new(&["tlane_good_warm"], &[]);
        let app = app(PreAuthLimiter::new(5), fake.clone(), CADDY);
        let src = [("cf-connecting-ip", "198.51.100.12")];
        for i in 0..50 {
            let _ = status(&app, req(&format!("tlane_junk_w_{i}"), &src)).await;
        }
        assert_eq!(
            status(&app, req("tlane_junk_w_after", &src)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "the source is throttled for cold lookups"
        );
        assert_eq!(
            status(&app, req("tlane_good_warm", &src)).await,
            StatusCode::OK,
            "a valid warm key from the same source must not pay for the scanner"
        );
    }

    #[tokio::test]
    async fn another_source_is_unaffected_by_a_throttled_one() {
        let fake = Fake::new(&[], &["tlane_good_cold"]);
        let app = app(PreAuthLimiter::new(3), fake.clone(), CADDY);
        for i in 0..20 {
            let _ = status(
                &app,
                req(
                    &format!("tlane_junk_o_{i}"),
                    &[("cf-connecting-ip", "198.51.100.13")],
                ),
            )
            .await;
        }
        let before = fake.calls();
        let other = [("cf-connecting-ip", "198.51.100.14")];
        assert_eq!(
            status(&app, req("tlane_junk_o_x", &other)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&app, req("tlane_good_cold", &other)).await,
            StatusCode::OK
        );
        assert_eq!(
            fake.calls(),
            before + 2,
            "the other source reached the store"
        );
    }

    #[tokio::test]
    async fn a_successful_lookup_never_spends_a_token_and_a_failed_checkout_is_refunded() {
        let fake = Fake::new(&[], &["tlane_good_cold"]);
        let app = app(PreAuthLimiter::new(2), fake.clone(), CADDY);
        let src = [("cf-connecting-ip", "198.51.100.15")];
        for _ in 0..50 {
            assert_eq!(
                status(&app, req("tlane_good_cold", &src)).await,
                StatusCode::OK
            );
        }
        let mut down = Fake::new(&[], &[]);
        down.checkout_fails = true; // no SQL ran: the outage is refunded
        let app = self::app(PreAuthLimiter::new(2), down.clone(), CADDY);
        for _ in 0..20 {
            assert_eq!(
                status(&app, req("tlane_any", &src)).await,
                StatusCode::SERVICE_UNAVAILABLE,
                "a checkout that never ran SQL is not an auth failure and must not throttle"
            );
        }
        assert_eq!(down.calls(), 20);
    }

    #[tokio::test]
    async fn ipv6_sources_aggregate_to_their_slash_64() {
        let fake = Fake::new(&[], &[]);
        let app = app(PreAuthLimiter::new(2), fake.clone(), CADDY);
        for host in ["2001:db8:1:2::1", "2001:db8:1:2::ffff:1"] {
            let _ = status(&app, req("tlane_junk_v6_a", &[("cf-connecting-ip", host)])).await;
        }
        let before = fake.calls();
        assert_eq!(
            status(
                &app,
                req(
                    "tlane_junk_v6_b",
                    &[("cf-connecting-ip", "2001:db8:1:2:dead:beef:0:1")]
                )
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "a third address in the same /64 is the same subscriber"
        );
        assert_eq!(fake.calls(), before, "refused before the store");
        assert_eq!(
            status(
                &app,
                req(
                    "tlane_junk_v6_c",
                    &[("cf-connecting-ip", "2001:db8:1:3::1")]
                )
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "the neighbouring /64 has its own bucket, but it shares the spent /48 (rev4 H1 c)"
        );
        assert_eq!(
            status(
                &app,
                req(
                    "tlane_junk_v6_d",
                    &[("cf-connecting-ip", "2001:db8:2:3::1")]
                )
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "a /64 in another /48 is a different source"
        );
    }

    #[tokio::test]
    async fn a_public_peer_cannot_escape_by_rotating_the_forwarding_header() {
        // The gateway exposed directly (the self-host compose publishes :8080):
        // the header is the client's to write, so it is ignored.
        let fake = Fake::new(&[], &[]);
        let app = app(PreAuthLimiter::new(3), fake.clone(), "203.0.113.9:5555");
        for i in 0..40 {
            let ip = format!("10.9.0.{}", i + 1);
            let _ = status(
                &app,
                req(
                    &format!("tlane_junk_s_{i}"),
                    &[
                        ("cf-connecting-ip", ip.as_str()),
                        ("x-forwarded-for", ip.as_str()),
                    ],
                ),
            )
            .await;
        }
        assert!(
            fake.calls() <= 4,
            "a forged header per request reached the store {} times",
            fake.calls()
        );
    }

    #[tokio::test]
    async fn behind_a_trusted_hop_the_rightmost_forwarded_entry_is_the_source() {
        // The leftmost X-Forwarded-For entry is whatever the client wrote; the
        // rightmost is what the trusted proxy appended.
        let fake = Fake::new(&[], &[]);
        let app = app(PreAuthLimiter::new(3), fake.clone(), CADDY);
        for i in 0..40 {
            let xff = format!("10.8.0.{}, 198.51.100.16", i + 1);
            let _ = status(
                &app,
                req(
                    &format!("tlane_junk_x_{i}"),
                    &[("x-forwarded-for", xff.as_str())],
                ),
            )
            .await;
        }
        assert!(fake.calls() <= 4, "store reached {} times", fake.calls());
    }

    /// rev4 H1(c): a /48 holds 65,536 /64s. Keyed on the /64 alone, one site buys
    /// 65,536 buckets; the /48 must ALSO have a token.
    #[tokio::test]
    async fn rev4_h1c_a_slash_48_shares_one_bucket_across_its_slash_64s() {
        let fake = Fake::new(&[], &[]);
        let app = app(PreAuthLimiter::new(2), fake.clone(), CADDY);
        for host in ["2001:db8:77:a::1", "2001:db8:77:b::1"] {
            assert_eq!(
                status(&app, req("tlane_junk_48", &[("cf-connecting-ip", host)])).await,
                StatusCode::UNAUTHORIZED
            );
        }
        let before = fake.calls();
        assert_eq!(
            status(
                &app,
                req(
                    "tlane_junk_48c",
                    &[("cf-connecting-ip", "2001:db8:77:c::1")]
                )
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "a third /64 in the same /48 is the same site"
        );
        assert_eq!(fake.calls(), before, "refused before the store");
        assert_eq!(
            status(
                &app,
                req(
                    "tlane_junk_48d",
                    &[("cf-connecting-ip", "2001:db8:78:a::1")]
                )
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "the neighbouring /48 is a different site"
        );
    }

    /// rev4 H1(b): a store error AFTER the SQL ran keeps the token — otherwise an
    /// attacker who can make the lookup fail (pool exhaustion, a slow Neon) gets
    /// every lookup for free.
    #[tokio::test]
    async fn rev4_h1b_a_store_error_after_the_sql_ran_keeps_the_token() {
        let mut down = Fake::new(&[], &[]);
        down.store_fails = true;
        let app = app(PreAuthLimiter::new(2), down.clone(), CADDY);
        let src = [("cf-connecting-ip", "198.51.100.40")];
        for _ in 0..2 {
            assert_eq!(
                status(&app, req("tlane_any_err", &src)).await,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        assert_eq!(
            status(&app, req("tlane_any_err", &src)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "two failed queries spent the burst of two"
        );
        assert_eq!(down.calls(), 2);
    }

    /// rev4 M2: a request cancelled while its lookup is pending (client gone) must
    /// not burn the source's token forever.
    #[tokio::test]
    async fn rev4_m2_a_lookup_cancelled_before_its_sql_gives_the_token_back() {
        let limiter = PreAuthLimiter::new(1);
        let src = SourceKey::of_ip("198.51.100.41".parse().unwrap(), 64);
        let scope = ColdGateScope::new(limiter.inner.clone(), src.0, None);
        let pending = crate::db::api_keys::with_cold_gate(
            scope,
            crate::db::api_keys::gated_cold_lookup(Gating::Source, |_mark| {
                // Still waiting for a connection: no SQL has run.
                std::future::pending::<anyhow::Result<Option<()>>>()
            }),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pending)
                .await
                .is_err(),
            "the lookup is still waiting when the request goes away"
        );
        assert!(
            limiter.acquire_at(src, Instant::now()).is_ok(),
            "the cancelled lookup's token came back"
        );
    }

    /// …but a request cancelled AFTER its SQL started keeps the token spent — a
    /// client that hangs up mid-query must not get free lookups (rev4 H1 b).
    #[tokio::test]
    async fn rev4_m2_a_lookup_cancelled_after_its_sql_started_keeps_the_token() {
        let limiter = PreAuthLimiter::new(1);
        let src = SourceKey::of_ip("198.51.100.42".parse().unwrap(), 64);
        let pending = crate::db::api_keys::with_cold_gate(
            ColdGateScope::new(limiter.inner.clone(), src.0, None),
            crate::db::api_keys::gated_cold_lookup(Gating::Source, |mark| async move {
                mark.started();
                std::future::pending::<anyhow::Result<Option<()>>>().await
            }),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pending)
                .await
                .is_err()
        );
        assert!(
            limiter.acquire_at(src, Instant::now()).is_err(),
            "the token stayed spent"
        );
    }

    /// rev4 H1(a): over the slots a lookup waits at most `cold_lookup_wait_ms`
    /// and is then refused 429 + Retry-After — never queued without bound — and
    /// its source's token goes back (no SQL ran for it).
    #[tokio::test]
    async fn rev4_h1a_over_the_slots_a_lookup_is_refused_not_queued() {
        let mut p = auth_throttle_policy().clone();
        p.cold_lookup_pool_pct = 1; // one slot
        p.cold_lookup_wait_ms = 0;
        p.burst = 1;
        let limiter = PreAuthLimiter::with_policy(p);
        let busy_src = SourceKey::of_ip("198.51.100.43".parse().unwrap(), 64);
        let src = SourceKey::of_ip("198.51.100.44".parse().unwrap(), 64);
        assert_eq!(limiter.inner.slots.size(), 1);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (holding_tx, holding_rx) = tokio::sync::oneshot::channel::<()>();
        let holder = tokio::spawn(crate::db::api_keys::with_cold_gate(
            ColdGateScope::new(limiter.inner.clone(), busy_src.0, None),
            crate::db::api_keys::gated_cold_lookup(Gating::Source, |mark| async move {
                mark.started();
                let _ = holding_tx.send(()); // the closure runs only with the slot held
                let _ = release_rx.await;
                anyhow::Ok(None::<()>)
            }),
        ));
        holding_rx.await.expect("the holder took the only slot");
        let saturated_before =
            crate::db::api_keys::AUTH_COLD_SATURATED_TOTAL.load(Ordering::Relaxed);
        let scope = ColdGateScope::new(limiter.inner.clone(), src.0, None);
        let err = crate::db::api_keys::with_cold_gate(
            scope,
            // Were it reached, this "store" answers an error that is NOT
            // `AuthThrottled` — so the assertion below tells the two apart.
            crate::db::api_keys::gated_cold_lookup(Gating::Source, |_mark| async {
                Err::<Option<()>, _>(anyhow::anyhow!("reached the store"))
            }),
        )
        .await
        .unwrap_err();
        assert!(err.is::<crate::db::api_keys::AuthThrottled>(), "{err:#}");
        assert!(
            crate::db::api_keys::AUTH_COLD_SATURATED_TOTAL.load(Ordering::Relaxed)
                > saturated_before
        );
        assert!(
            limiter.acquire_at(src, Instant::now()).is_ok(),
            "the refused lookup's token went back"
        );
        let _ = release_tx.send(());
        let _ = holder.await;
    }

    /// rev4 L4: a cold lookup with no request scope (a task that lost the
    /// task-local) has no source to charge — it is counted, not silent.
    #[tokio::test]
    async fn rev4_l4_an_unscoped_cold_lookup_is_counted() {
        let before = crate::db::api_keys::AUTH_UNGATED_COLD_LOOKUPS_TOTAL.load(Ordering::Relaxed);
        let r = crate::db::api_keys::gated_cold_lookup(Gating::Source, |mark| async move {
            mark.started();
            anyhow::Ok(None::<()>)
        })
        .await;
        assert!(matches!(r, Ok(None)));
        assert!(
            crate::db::api_keys::AUTH_UNGATED_COLD_LOOKUPS_TOTAL.load(Ordering::Relaxed) > before
        );
        // A key the valid-key set vouches for is NOT "ungated": it needs no bucket.
        let mid = crate::db::api_keys::AUTH_UNGATED_COLD_LOOKUPS_TOTAL.load(Ordering::Relaxed);
        let _ = crate::db::api_keys::gated_cold_lookup(Gating::Known, |mark| async move {
            mark.started();
            anyhow::Ok(Some(()))
        })
        .await;
        assert_eq!(
            crate::db::api_keys::AUTH_UNGATED_COLD_LOOKUPS_TOTAL.load(Ordering::Relaxed),
            mid
        );
    }

    /// rev4 M1: a key the valid-key set vouches for is never charged to its
    /// source's bucket — a scanner sharing the egress cannot lock it out.
    #[tokio::test]
    async fn rev4_m1_a_known_key_skips_an_empty_source_bucket() {
        let limiter = PreAuthLimiter::new(1);
        let src = SourceKey::of_ip("198.51.100.45".parse().unwrap(), 64);
        assert!(
            limiter.acquire_at(src, Instant::now()).is_ok(),
            "the scanner spent it"
        );
        let r = crate::db::api_keys::with_cold_gate(
            ColdGateScope::new(limiter.inner.clone(), src.0, None),
            crate::db::api_keys::gated_cold_lookup(Gating::Known, |mark| async move {
                mark.started();
                anyhow::Ok(Some(()))
            }),
        )
        .await;
        assert!(matches!(r, Ok(Some(()))), "{r:?}");
    }

    /// rev4 H1(a): the per-source buckets do not bound TOTAL Postgres load — N
    /// sources each with a full bucket all reach the 16-connection pool at once.
    /// A fixed number of cold-lookup slots does.
    #[tokio::test]
    async fn rev4_h1a_cold_lookups_are_bounded_globally_not_per_source() {
        let fake = Fake::new(&[], &[]);
        let app = app(PreAuthLimiter::new(60), fake.clone(), CADDY);
        let reqs = (0..40).map(|i| {
            let ip = format!("198.51.100.{}", 100 + i);
            let app = app.clone();
            async move {
                app.oneshot(req(
                    &format!("tlane_junk_glob_{i}"),
                    &[("cf-connecting-ip", ip.as_str())],
                ))
                .await
                .unwrap()
                .status()
            }
        });
        let statuses = futures::future::join_all(reqs).await;
        let slots = expected_default_slots();
        assert!(
            fake.max_in_flight() <= slots,
            "{} lookups ran at once across 40 sources; the bound is {slots}",
            fake.max_in_flight()
        );
        assert!(
            statuses
                .iter()
                .all(|s| *s == StatusCode::UNAUTHORIZED || *s == StatusCode::TOO_MANY_REQUESTS),
            "{statuses:?}"
        );
    }

    /// The slot count the shipped table gives with no pool to size against: the
    /// percentage of the gateway's default pool (`db::mod.rs` `max_size: 16`).
    fn expected_default_slots() -> usize {
        (16 * usize::from(auth_throttle_policy().cold_lookup_pool_pct) / 100).max(1)
    }

    /// rev4 L3: `/health` is public. It may say the limiter is working; it must not
    /// hand a scanner the live map size or overflow count to tune against.
    #[test]
    fn rev4_l3_health_shows_no_live_tuning_detail() {
        let t = health_json();
        for field in [
            "sources_tracked",
            "overflowed",
            "max_sources",
            "failures_charged",
        ] {
            assert!(t.get(field).is_none(), "/health still exposes {field}: {t}");
        }
        assert!(t["throttled"].is_u64());
    }

    #[test]
    fn health_exposes_the_auth_throttle() {
        let body = crate::server::health_body(true, 0, 0);
        let t = &body["auth_throttle"];
        assert!(
            t["throttled"].is_u64(),
            "/health auth_throttle.throttled: {t}"
        );
        assert!(
            t["known_keys_loaded"].is_boolean(),
            "/health auth_throttle.known_keys_loaded: {t}"
        );
    }

    #[tokio::test]
    async fn the_real_lookup_is_refused_before_it_takes_a_connection() {
        // `lookup_tenant_by_key_body` itself, against a pool whose every connect is
        // refused: with the gate empty the answer is AuthThrottled, not the pool's
        // connect error — the refusal happens before `pool.get()`.
        let _ = crate::db::api_keys::init_pepper(&"00".repeat(32));
        let mut config = deadpool_postgres::Config::new();
        config.host = Some("127.0.0.1".into());
        config.port = Some(1);
        config.dbname = Some("unused".into());
        let pool = config
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .unwrap();
        let limiter = PreAuthLimiter::new(1);
        let src = SourceKey::of_ip("198.51.100.30".parse().unwrap(), 64);
        assert!(
            limiter.acquire_at(src, Instant::now()).is_ok(),
            "spend the only token"
        );
        let scope = ColdGateScope::new(limiter.inner.clone(), src.0, None);
        let err = crate::db::api_keys::with_cold_gate(
            scope,
            crate::db::api_keys::lookup_tenant_by_key_body(&pool, "b594_never_seen_key_body_xxxx"),
        )
        .await
        .unwrap_err();
        assert!(err.is::<crate::db::api_keys::AuthThrottled>(), "{err:#}");
        assert_eq!(
            crate::auth::failure_status(&err),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(crate::auth::failure_code(&err), "auth_throttled");
        // Ungated, the same call does reach the pool — so the refusal above is real.
        let open =
            crate::db::api_keys::lookup_tenant_by_key_body(&pool, "b594_never_seen_key_body_yyyy")
                .await
                .unwrap_err();
        assert!(!open.is::<crate::db::api_keys::AuthThrottled>(), "{open:#}");
        assert!(format!("{open:#}").contains("pool"), "{open:#}");
    }
}
