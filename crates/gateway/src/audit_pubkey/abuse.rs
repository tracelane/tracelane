//! Process-local bounds for public workspace-key discovery. Source identity is
//! resolved by the gateway's canonical trusted-proxy contract, not here.

use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Deserialize;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    auth::workos_webhook::WebhookRateLimiter, preauth_limiter::SourceKey,
    providers::translation_policy::auth_throttle_policy, rate_limiter::RateLimitDecision,
};

#[derive(Clone, Debug, Deserialize)]
pub(super) struct Policy {
    pub source_per_minute: u32,
    pub overflow_per_minute: u32,
    pub max_sources: usize,
    pub source_idle_secs: u64,
    pub store_per_minute: u32,
    pub store_concurrency: usize,
    pub lookup_timeout_ms: u64,
    pub negative_max_entries: usize,
    pub negative_ttl_secs: u64,
}

impl Policy {
    /// # Errors
    /// Fail-CLOSED: missing, malformed or zero bounds disable workspace lookup;
    /// no permissive fallback. The shipped reference block is covered by a test.
    pub fn parse(raw: &str) -> Option<Self> {
        let table: serde_json::Value = serde_json::from_str(raw).ok()?;
        let p: Self = serde_json::from_value(table.get("audit_pubkey")?.clone()).ok()?;
        (p.source_per_minute > 0
            && p.overflow_per_minute > 0
            && p.overflow_per_minute <= p.source_per_minute
            && p.max_sources > 0
            // Burst = minute refill; a bucket must be idle for a full refill
            // before removal can be equivalent to retaining it.
            && p.source_idle_secs >= 60
            && p.store_per_minute > 0
            && p.store_concurrency > 0
            && p.store_concurrency <= Semaphore::MAX_PERMITS
            && p.lookup_timeout_ms > 0
            && p.negative_max_entries > 0
            && p.negative_ttl_secs > 0)
            .then_some(p)
    }

    pub fn shipped() -> Option<Self> {
        static POLICY: OnceLock<Option<Policy>> = OnceLock::new();
        POLICY
            .get_or_init(|| Self::parse(include_str!("../../translation_policy.v1.json")))
            .clone()
    }
}

struct SourceBucket {
    rate: WebhookRateLimiter,
    admitted: Instant,
}

struct Sources {
    buckets: HashMap<SourceKey, SourceBucket>,
    next_sweep: Instant,
    overflow: WebhookRateLimiter,
    overflow_admitted: Option<Instant>,
}

#[derive(Default)]
struct Misses {
    entries: HashMap<Uuid, Instant>,
    // Exactly one expiry index entry per UUID; no append-only eviction queue.
    expiry: BTreeSet<(Instant, Uuid)>,
}

impl Misses {
    fn remove_first(&mut self) {
        if let Some((_, id)) = self.expiry.pop_first() {
            self.entries.remove(&id);
        }
    }

    fn expire(&mut self, now: Instant) {
        while self.expiry.first().is_some_and(|(until, _)| *until <= now) {
            self.remove_first();
        }
    }
}

pub(super) struct Abuse {
    pub policy: Policy,
    sources: Mutex<Sources>,
    misses: Mutex<Misses>,
    pub store_rate: WebhookRateLimiter,
    pub slots: Semaphore,
    #[cfg(test)]
    pub clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl Abuse {
    pub fn new(policy: Policy) -> Self {
        Self {
            sources: Mutex::new(Sources {
                buckets: HashMap::new(),
                next_sweep: Instant::now(),
                overflow: WebhookRateLimiter::new(
                    policy.overflow_per_minute.min(policy.source_per_minute),
                ),
                overflow_admitted: None,
            }),
            misses: Mutex::default(),
            store_rate: WebhookRateLimiter::new(policy.store_per_minute),
            slots: Semaphore::new(policy.store_concurrency),
            policy,
            #[cfg(test)]
            clock: Arc::new(Instant::now),
        }
    }

    pub fn now(&self) -> Instant {
        #[cfg(test)]
        {
            (self.clock)()
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    /// # Errors
    /// Fail-CLOSED on depleted source/prefix/overflow allowance. A full source
    /// map uses one shared overflow bucket without allocating more identities.
    /// Admission, recency and capacity changes share one mutex.
    pub fn source(&self, source: SourceKey, now: Instant) -> Result<(), u32> {
        let mut sources = self.sources.lock();
        let policy = auth_throttle_policy();
        let wide = source.wide(policy.ipv6_wide_prefix_len, policy.ipv6_prefix_len);
        let keys = [wide, Some(source)];
        let idle = Duration::from_secs(self.policy.source_idle_secs);
        // Never promote recent overflow users to fresh full buckets. Without
        // retaining their identities, an idle overflow interval is the bound
        // that guarantees every overflow user's allowance has fully refilled.
        let overflow_active = sources
            .overflow_admitted
            .is_some_and(|at| now.saturating_duration_since(at) < idle);
        let missing = keys
            .iter()
            .flatten()
            .filter(|key| !sources.buckets.contains_key(key))
            .count();
        if missing > self.policy.max_sources - sources.buckets.len()
            && now >= sources.next_sweep
            && !overflow_active
        {
            sources
                .buckets
                .retain(|_, b| now.saturating_duration_since(b.admitted) < idle);
            // At most one full sweep per idle interval, even under churn.
            sources.next_sweep = now + idle;
        }
        let missing = keys
            .iter()
            .flatten()
            .filter(|key| !sources.buckets.contains_key(key))
            .count();
        let overflow = missing > 0
            && (overflow_active || missing > self.policy.max_sources - sources.buckets.len());

        // Wide prefix first: a depleted resident prefix cannot mint new /64
        // buckets or bypass its allowance via overflow.
        for key in keys.into_iter().flatten() {
            if overflow && !sources.buckets.contains_key(&key) {
                continue;
            }
            let bucket = sources.buckets.entry(key).or_insert_with(|| SourceBucket {
                rate: WebhookRateLimiter::new(self.policy.source_per_minute),
                admitted: now,
            });
            if let RateLimitDecision::Throttle { retry_after_secs } = bucket.rate.check() {
                return Err(retry_after_secs);
            }
        }
        if overflow {
            if let RateLimitDecision::Throttle { retry_after_secs } = sources.overflow.check() {
                return Err(retry_after_secs);
            }
            sources.overflow_admitted = Some(now);
        }
        // A rejected request must not keep any resident bucket alive, including
        // a wide prefix charged before a narrower bucket/overflow refused it.
        for key in keys.into_iter().flatten() {
            if let Some(bucket) = sources.buckets.get_mut(&key) {
                bucket.admitted = now;
            }
        }
        Ok(())
    }

    pub fn missing(&self, id: Uuid, now: Instant) -> bool {
        let mut misses = self.misses.lock();
        misses.expire(now);
        misses.entries.contains_key(&id)
    }

    /// Cache ONLY a confirmed absence. Expiry begins before the read, so an
    /// enrollment racing a delayed no-row response is never hidden for an extra
    /// TTL. Hits and overlapping misses do not refresh existing entries.
    pub fn confirm_missing(&self, id: Uuid, started: Instant) {
        let until = started + Duration::from_secs(self.policy.negative_ttl_secs);
        let now = self.now();
        let mut misses = self.misses.lock();
        misses.expire(now);
        if until <= now || misses.entries.contains_key(&id) {
            return;
        }
        if misses.entries.len() >= self.policy.negative_max_entries {
            misses.remove_first();
        }
        misses.entries.insert(id, until);
        misses.expiry.insert((until, id));
    }

    #[cfg(test)]
    pub fn sizes(&self) -> (usize, usize, usize) {
        let misses = self.misses.lock();
        (
            self.sources.lock().buckets.len(),
            misses.entries.len(),
            misses.expiry.len(),
        )
    }
}
