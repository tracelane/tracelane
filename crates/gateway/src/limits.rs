//! `OG-21` — TPM and RPM limits per workspace, project, key, end user and model.
//! Spec: `specs/OG-21-tpm-rpm-limits.md`.
//!
//! **A token bucket per limit** (capacity = the per-minute limit, refill = limit / 60
//! per second), held per tenant behind ONE short `std::sync::Mutex` — the check and the
//! debit of every applicable bucket are one critical section, so a request either
//! charges every bucket or none (AND semantics without a partial debit to roll back).
//! No `.await` is ever held across the lock.
//!
//! **TPM is reserved, then reconciled.** Admission charges the request's estimate (input
//! estimate + declared output cap, or the reference table's default reserve); when the
//! request's span is recorded (`server::record_key_spend`, the one funnel every
//! recording route goes through) the bucket is corrected by `actual − reserved`. A
//! reservation is found again by `(tenant, trace_id)` and, within one trace, by its key,
//! model and end user (an agent loop reuses one trace id across calls). An unreconciled
//! reservation (a cancelled request, no span) simply stays charged — the conservative
//! direction — and is dropped after `reservation_ttl_secs`.
//!
//! **Per-process**, correct because a second gateway on the same control plane is
//! refused at boot (`db::singleton`, B-386). **Bounded:** per-end-user buckets are capped
//! per tenant (idle ones evicted first; past the cap a new end user is refused
//! `429 end_user_limit_capacity` — fail-CLOSED), pending reservations are capped
//! process-wide.

use std::collections::HashMap;
use std::hash::BuildHasher as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

/// Which counter a bucket belongs to: the layer's subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Scope {
    Workspace,
    Project(Uuid),
    Key(Uuid),
}

impl Scope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Project(_) => "project",
            Self::Key(_) => "key",
        }
    }
}

/// The dimension inside a scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Dim {
    /// Every request the scope governs.
    All,
    /// One end user (a keyed hash of the `OBS-20` id — never the id itself).
    EndUser(u64),
    /// One `per_model` pattern.
    Model(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Rpm,
    Tpm,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BucketKey {
    pub scope: Scope,
    pub dim: Dim,
    pub kind: Kind,
}

/// One bucket a request must fit in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Check {
    pub key: BucketKey,
    /// The per-minute limit.
    pub limit: u64,
    /// What this request takes from it: 1 (RPM) or the token reservation (TPM).
    pub cost: u64,
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LimitDenial {
    pub code: &'static str,
    pub scope: Scope,
    pub dim: Dim,
    pub kind: Kind,
    pub limit: u64,
    pub requested: u64,
    pub retry_after_secs: u32,
    /// The request alone needs more than the bucket's whole capacity.
    pub exceeds_capacity: bool,
}

impl LimitDenial {
    fn capacity(scope: Scope) -> Self {
        Self {
            code: "end_user_limit_capacity",
            scope,
            dim: Dim::EndUser(0),
            kind: Kind::Rpm,
            limit: 0,
            requested: 1,
            retry_after_secs: 60,
            exceeds_capacity: false,
        }
    }

    /// The human message every wire renders.
    pub(crate) fn message(&self) -> String {
        if self.code == "end_user_limit_capacity" {
            return "too many distinct end users are being rate-limited in this workspace right \
                    now; retry shortly"
                .to_owned();
        }
        let what = match self.kind {
            Kind::Rpm => "requests",
            Kind::Tpm => "tokens",
        };
        let whose = match (&self.dim, self.scope) {
            (Dim::All, Scope::Workspace) => "this workspace's".to_owned(),
            (Dim::All, s) => format!("this {}'s", s.as_str()),
            (Dim::EndUser(_), s) => format!("this end user's ({} policy)", s.as_str()),
            (Dim::Model(p), s) => format!("the `{p}` model ({} policy)", s.as_str()),
        };
        if self.exceeds_capacity {
            format!(
                "this request needs {} {what} but {whose} limit is {} {what} per minute — it can \
                 never fit; lower its max tokens",
                self.requested, self.limit
            )
        } else {
            format!(
                "{whose} limit of {} {what} per minute is exhausted; retry after {} s",
                self.limit, self.retry_after_secs
            )
        }
    }

    /// The JSON every OpenAI-shaped wire puts beside `error` / `message`.
    pub(crate) fn detail(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "limit": self.limit,
            "requested": self.requested,
            "scope": self.scope.as_str(),
            "retry_after_secs": self.retry_after_secs,
        });
        if let Dim::Model(p) = &self.dim {
            v["model_pattern"] = serde_json::json!(p);
        }
        v
    }
}

fn code_for(kind: Kind, scope: Scope, dim: &Dim) -> &'static str {
    match (kind, dim, scope) {
        (Kind::Rpm, Dim::EndUser(_), _) => "rpm_limit_end_user",
        (Kind::Tpm, Dim::EndUser(_), _) => "tpm_limit_end_user",
        (Kind::Rpm, Dim::Model(_), _) => "rpm_limit_model",
        (Kind::Tpm, Dim::Model(_), _) => "tpm_limit_model",
        (Kind::Rpm, Dim::All, Scope::Workspace) => "rpm_limit_workspace",
        (Kind::Rpm, Dim::All, Scope::Project(_)) => "rpm_limit_project",
        (Kind::Rpm, Dim::All, Scope::Key(_)) => "rpm_limit_key",
        (Kind::Tpm, Dim::All, Scope::Workspace) => "tpm_limit_workspace",
        (Kind::Tpm, Dim::All, Scope::Project(_)) => "tpm_limit_project",
        (Kind::Tpm, Dim::All, Scope::Key(_)) => "tpm_limit_key",
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    capacity: f64,
    last_refill: Instant,
    last_used: Instant,
}

impl Bucket {
    fn new(limit: u64, now: Instant) -> Self {
        Self {
            tokens: limit as f64,
            capacity: limit as f64,
            last_refill: now,
            last_used: now,
        }
    }

    /// Bring the bucket to `now` under (possibly edited) `limit`.
    fn refill(&mut self, limit: u64, now: Instant) {
        let cap = limit as f64;
        if (cap - self.capacity).abs() > f64::EPSILON {
            self.capacity = cap;
        }
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * cap / 60.0).min(cap);
        self.last_refill = now;
    }

    /// Seconds until `cost` fits (≥ 1).
    fn wait_secs(&self, cost: u64) -> u32 {
        let per_sec = self.capacity / 60.0;
        if per_sec <= 0.0 {
            return 60;
        }
        let secs = ((cost as f64 - self.tokens) / per_sec).ceil();
        if secs.is_finite() {
            (secs.max(1.0) as u64).min(3600) as u32
        } else {
            60
        }
    }
}

#[derive(Default)]
struct TenantBuckets {
    map: HashMap<BucketKey, Bucket>,
    end_users: usize,
}

impl TenantBuckets {
    fn evict_idle(&mut self, now: Instant, idle: Duration) {
        let before = self.map.len();
        let mut freed_end_users = 0usize;
        self.map.retain(|k, b| {
            let keep = now.saturating_duration_since(b.last_used) < idle;
            if !keep && matches!(k.dim, Dim::EndUser(_)) {
                freed_end_users += 1;
            }
            keep
        });
        if self.map.len() != before {
            self.end_users = self.end_users.saturating_sub(freed_end_users);
        }
    }
}

/// One admitted request's TPM reservation, waiting for its span.
#[derive(Debug, Clone)]
pub(crate) struct Reservation {
    pub tenant: Uuid,
    /// The TPM buckets charged, and how much each.
    pub debits: Vec<(BucketKey, u64)>,
    pub key_id: Option<String>,
    pub model: String,
    pub end_user: Option<String>,
    at: Instant,
}

/// The process-wide bucket table.
pub(crate) struct LimitTable {
    tenants: DashMap<Uuid, Arc<Mutex<TenantBuckets>>>,
    pending: DashMap<(Uuid, Uuid), Vec<Reservation>>,
    pending_count: AtomicUsize,
    max_end_users: usize,
    idle: Duration,
    reservation_ttl: Duration,
    max_pending: usize,
}

/// The process-wide table (a global for the same reason `spend::tracker` is: the span
/// recorder that reconciles reservations outlives the handler frame).
pub(crate) fn table() -> &'static LimitTable {
    static T: OnceLock<LimitTable> = OnceLock::new();
    T.get_or_init(|| {
        let c = crate::controls::config();
        LimitTable::new(
            c.limit_max_end_users_per_tenant,
            Duration::from_secs(c.limit_idle_evict_secs),
            Duration::from_secs(c.reservation_ttl_secs),
            c.max_pending_reservations,
        )
    })
}

/// The keyed hash an end user's bucket is stored under: random per process, so an
/// attacker cannot choose an id that collides with a victim's bucket.
/// rev5 `L6` — how many DISTINCT end-user ids one key (or the session principal, `None`)
/// introduced in the current window. The end-user id is caller-asserted, so without this a
/// key rotating ids fills the per-workspace end-user capacity (`limit_max_end_users_per_
/// tenant`, `budget_max_end_users_per_tenant`) and pushes every other end user into a
/// capacity refusal. An id already counted in the window is always admitted; a NEW one
/// past the cap is refused. Fixed windows; at most `MAX_TRACKED` (tenant, key) entries
/// (a full map drops expired windows, then everything — losing counts, never admitting
/// an id the cap refused).
pub(crate) struct EndUserCap {
    map: DashMap<(Uuid, Option<String>), (Instant, std::collections::HashSet<u64>)>,
    cap: usize,
    window: Duration,
}

impl EndUserCap {
    const MAX_TRACKED: usize = 100_000;

    pub(crate) fn new(cap: usize, window: Duration) -> Self {
        Self {
            map: DashMap::new(),
            cap,
            window,
        }
    }

    /// Admit `end_user` for `(tenant, key)` at `now`.
    ///
    /// # Errors
    /// The seconds until the window resets, when `end_user` is NEW and the key is at its
    /// cap. Fail-CLOSED for a new id only; a known one is never refused.
    pub(crate) fn admit(
        &self,
        tenant: Uuid,
        key: Option<&str>,
        end_user: u64,
        now: Instant,
    ) -> Result<(), u64> {
        if self.map.len() >= Self::MAX_TRACKED {
            let w = self.window;
            self.map
                .retain(|_, (start, _)| now.saturating_duration_since(*start) < w);
            if self.map.len() >= Self::MAX_TRACKED {
                self.map.clear();
            }
        }
        let mut e = self
            .map
            .entry((tenant, key.map(str::to_owned)))
            .or_insert_with(|| (now, std::collections::HashSet::new()));
        let (start, ids) = &mut *e;
        if now.saturating_duration_since(*start) >= self.window {
            *start = now;
            ids.clear();
        }
        if ids.contains(&end_user) {
            return Ok(());
        }
        if ids.len() >= self.cap {
            let left = self
                .window
                .saturating_sub(now.saturating_duration_since(*start));
            return Err(left.as_secs().max(1));
        }
        ids.insert(end_user);
        Ok(())
    }
}

/// The process-wide [`EndUserCap`], from the reference table.
pub(crate) fn end_user_cap() -> &'static EndUserCap {
    static C: OnceLock<EndUserCap> = OnceLock::new();
    C.get_or_init(|| {
        let c = crate::controls::config();
        EndUserCap::new(
            c.end_user_ids_per_key_per_window,
            Duration::from_secs(c.end_user_ids_window_secs),
        )
    })
}

pub(crate) fn end_user_hash(id: &str) -> u64 {
    static S: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
    S.get_or_init(std::collections::hash_map::RandomState::new)
        .hash_one(id)
}

fn lock(m: &Mutex<TenantBuckets>) -> std::sync::MutexGuard<'_, TenantBuckets> {
    // A panic while holding the lock left plain numbers behind; keep serving.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl LimitTable {
    pub(crate) fn new(
        max_end_users: usize,
        idle: Duration,
        reservation_ttl: Duration,
        max_pending: usize,
    ) -> Self {
        Self {
            tenants: DashMap::new(),
            pending: DashMap::new(),
            pending_count: AtomicUsize::new(0),
            max_end_users,
            idle,
            reservation_ttl,
            max_pending,
        }
    }

    /// Charge every check, or none.
    ///
    /// # Errors
    /// The binding bucket (the one a client must wait longest for), or
    /// `end_user_limit_capacity`. Fail-CLOSED.
    pub(crate) fn admit(
        &self,
        tenant: Uuid,
        checks: &[Check],
        now: Instant,
    ) -> Result<Vec<(BucketKey, u64)>, LimitDenial> {
        if checks.is_empty() {
            return Ok(Vec::new());
        }
        let entry = Arc::clone(
            &self
                .tenants
                .entry(tenant)
                .or_insert_with(|| Arc::new(Mutex::new(TenantBuckets::default()))),
        );
        let mut tb = lock(&entry);
        let new_end_users = checks
            .iter()
            .filter(|c| matches!(c.key.dim, Dim::EndUser(_)) && !tb.map.contains_key(&c.key))
            .count();
        if new_end_users > 0 && tb.end_users + new_end_users > self.max_end_users {
            tb.evict_idle(now, self.idle);
            if tb.end_users + new_end_users > self.max_end_users {
                let scope = checks
                    .iter()
                    .find(|c| matches!(c.key.dim, Dim::EndUser(_)))
                    .map_or(Scope::Workspace, |c| c.key.scope);
                return Err(LimitDenial::capacity(scope));
            }
        }
        let mut worst: Option<LimitDenial> = None;
        for c in checks {
            let is_new = !tb.map.contains_key(&c.key);
            let b = tb
                .map
                .entry(c.key.clone())
                .or_insert_with(|| Bucket::new(c.limit, now));
            b.refill(c.limit, now);
            if b.tokens + 1e-9 < c.cost as f64 {
                let exceeds = c.cost > c.limit;
                let wait = if exceeds { 60 } else { b.wait_secs(c.cost) };
                if worst.as_ref().is_none_or(|w| wait > w.retry_after_secs) {
                    worst = Some(LimitDenial {
                        code: code_for(c.key.kind, c.key.scope, &c.key.dim),
                        scope: c.key.scope,
                        dim: c.key.dim.clone(),
                        kind: c.key.kind,
                        limit: c.limit,
                        requested: c.cost,
                        retry_after_secs: wait,
                        exceeds_capacity: exceeds,
                    });
                }
            }
            if is_new && matches!(c.key.dim, Dim::EndUser(_)) {
                tb.end_users += 1;
            }
        }
        if let Some(w) = worst {
            return Err(w);
        }
        let mut debits = Vec::new();
        for c in checks {
            if let Some(b) = tb.map.get_mut(&c.key) {
                b.tokens -= c.cost as f64;
                b.last_used = now;
            }
            if c.key.kind == Kind::Tpm && c.cost > 0 {
                debits.push((c.key.clone(), c.cost));
            }
        }
        Ok(debits)
    }

    /// Correct each TPM bucket of `r` by `actual − reserved`. The bucket may go into debt
    /// (the next request waits), floored at one minute of capacity.
    pub(crate) fn reconcile(&self, r: &Reservation, actual_tokens: u64) {
        let Some(entry) = self.tenants.get(&r.tenant).map(|e| Arc::clone(&e)) else {
            return;
        };
        let mut tb = lock(&entry);
        for (key, n) in &r.debits {
            if let Some(b) = tb.map.get_mut(key) {
                let delta = *n as f64 - actual_tokens as f64;
                b.tokens = (b.tokens + delta).clamp(-b.capacity, b.capacity);
            }
        }
    }

    /// Park a reservation until its span is recorded. Over the bound, expired ones are
    /// swept first; if still full the reservation is not parked (it stays charged).
    pub(crate) fn park(&self, trace_id: Uuid, mut r: Reservation, now: Instant) {
        if r.debits.is_empty() {
            return;
        }
        if self.pending_count.load(Ordering::Relaxed) >= self.max_pending {
            self.sweep(now);
            if self.pending_count.load(Ordering::Relaxed) >= self.max_pending {
                return;
            }
        }
        r.at = now;
        self.pending
            .entry((r.tenant, trace_id))
            .or_default()
            .push(r);
        self.pending_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Drop parked reservations older than the TTL (they stay charged).
    pub(crate) fn sweep(&self, now: Instant) {
        let ttl = self.reservation_ttl;
        let mut dropped = 0usize;
        self.pending.retain(|_, v| {
            let before = v.len();
            v.retain(|r| now.saturating_duration_since(r.at) < ttl);
            dropped += before - v.len();
            !v.is_empty()
        });
        self.pending_count.fetch_sub(
            dropped.min(self.pending_count.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
    }

    /// Take the parked reservation a recorded span belongs to: same tenant, trace AND key;
    /// among that key's, the one with the same model and end user if any, else the oldest
    /// of that key's (a failover renames the model). rev5 L1: never another key's — the
    /// old fallback to the trace's oldest reservation let one key's span refund or drain
    /// another key's bucket.
    pub(crate) fn take(
        &self,
        tenant: Uuid,
        trace_id: Uuid,
        key_id: Option<&str>,
        model: Option<&str>,
        end_user: Option<&str>,
    ) -> Option<Reservation> {
        let mut out = None;
        let mut empty = false;
        if let Some(mut v) = self.pending.get_mut(&(tenant, trace_id)) {
            let same_key = |r: &Reservation| r.key_id.as_deref() == key_id;
            let idx = v
                .iter()
                .position(|r| {
                    same_key(r)
                        && model.is_none_or(|m| r.model == m)
                        && r.end_user.as_deref() == end_user
                })
                .or_else(|| v.iter().position(same_key));
            if let Some(idx) = idx {
                out = Some(v.remove(idx));
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
            }
            empty = v.is_empty();
        }
        if empty {
            self.pending
                .remove_if(&(tenant, trace_id), |_, v| v.is_empty());
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn tokens(&self, tenant: Uuid, key: &BucketKey) -> Option<f64> {
        let e = self.tenants.get(&tenant)?;
        let tb = lock(&e);
        tb.map.get(key).map(|b| b.tokens)
    }
}

impl Reservation {
    pub(crate) fn new(
        tenant: Uuid,
        debits: Vec<(BucketKey, u64)>,
        key_id: Option<String>,
        model: String,
        end_user: Option<String>,
    ) -> Self {
        Self {
            tenant,
            debits,
            key_id,
            model,
            end_user,
            at: Instant::now(),
        }
    }
}

/// `OG-21` reconciliation from a recorded span (called by `server::record_key_spend`).
/// Actual = input + output tokens as the span records them. A span with no usage at all
/// leaves the reservation charged, unless the request failed (nothing was generated).
pub(crate) fn reconcile_span(api_key_id: Option<&str>, span: &tracelane_shared::TracelaneSpan) {
    let a = &span.attributes;
    let tenant = *span.tenant_id.as_uuid();
    let Some(r) = table().take(
        tenant,
        span.trace_id,
        api_key_id,
        a.gen_ai_request_model.as_deref(),
        a.user_id.as_deref(),
    ) else {
        return;
    };
    let actual = match (a.gen_ai_usage_input_tokens, a.gen_ai_usage_output_tokens) {
        (None, None) => {
            if span.status.code == tracelane_shared::SpanStatusCode::Error {
                0
            } else {
                return;
            }
        }
        (i, o) => u64::from(i.unwrap_or(0)) + u64::from(o.unwrap_or(0)),
    };
    table().reconcile(&r, actual);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> LimitTable {
        LimitTable::new(2, Duration::from_secs(120), Duration::from_secs(600), 4)
    }

    fn key(scope: Scope, dim: Dim, kind: Kind) -> BucketKey {
        BucketKey { scope, dim, kind }
    }

    fn rpm(scope: Scope, limit: u64) -> Check {
        Check {
            key: key(scope, Dim::All, Kind::Rpm),
            limit,
            cost: 1,
        }
    }

    #[test]
    fn og21_rpm_bucket_refuses_past_the_limit_and_names_it_with_a_retry_after() {
        let t = t();
        let tenant = Uuid::new_v4();
        let k = Scope::Key(Uuid::new_v4());
        let now = Instant::now();
        assert!(t.admit(tenant, &[rpm(k, 2)], now).is_ok());
        assert!(t.admit(tenant, &[rpm(k, 2)], now).is_ok());
        let d = t
            .admit(tenant, &[rpm(k, 2)], now)
            .expect_err("third in the minute");
        assert_eq!(d.code, "rpm_limit_key");
        assert_eq!(d.limit, 2);
        assert_eq!(d.retry_after_secs, 30, "one token at 2/min refills in 30 s");
        // 30 s later one token is back.
        assert!(
            t.admit(tenant, &[rpm(k, 2)], now + Duration::from_secs(30))
                .is_ok()
        );
    }

    #[test]
    fn og21_every_bucket_must_have_room_and_a_refusal_charges_none() {
        let t = t();
        let tenant = Uuid::new_v4();
        let k = Scope::Key(Uuid::new_v4());
        let p = Scope::Project(Uuid::new_v4());
        let now = Instant::now();
        // Project allows 1, key allows 10.
        assert!(t.admit(tenant, &[rpm(p, 1), rpm(k, 10)], now).is_ok());
        let d = t
            .admit(tenant, &[rpm(p, 1), rpm(k, 10)], now)
            .expect_err("the project bucket is empty");
        assert_eq!(d.code, "rpm_limit_project");
        let kk = key(k, Dim::All, Kind::Rpm);
        assert_eq!(
            t.tokens(tenant, &kk).map(f64::round),
            Some(9.0),
            "the refused request charged the key bucket nothing"
        );
        // A second key in the same project shares the project bucket.
        let k2 = Scope::Key(Uuid::new_v4());
        assert_eq!(
            t.admit(tenant, &[rpm(p, 1), rpm(k2, 10)], now)
                .expect_err("shared")
                .code,
            "rpm_limit_project"
        );
        // Another tenant is untouched.
        assert!(t.admit(Uuid::new_v4(), &[rpm(p, 1)], now).is_ok());
    }

    #[test]
    fn og21_end_users_and_models_are_separate_buckets_and_end_users_are_bounded() {
        let t = t();
        let tenant = Uuid::new_v4();
        let w = Scope::Workspace;
        let now = Instant::now();
        let eu = |id: &str| Check {
            key: key(w, Dim::EndUser(end_user_hash(id)), Kind::Rpm),
            limit: 1,
            cost: 1,
        };
        assert!(t.admit(tenant, &[eu("a")], now).is_ok());
        assert_eq!(
            t.admit(tenant, &[eu("a")], now).expect_err("a again").code,
            "rpm_limit_end_user"
        );
        assert!(
            t.admit(tenant, &[eu("b")], now).is_ok(),
            "b has its own bucket"
        );
        // The table holds 2 end users; a third is refused until one idles out.
        assert_eq!(
            t.admit(tenant, &[eu("c")], now).expect_err("full").code,
            "end_user_limit_capacity"
        );
        assert!(
            t.admit(tenant, &[eu("c")], now + Duration::from_secs(121))
                .is_ok(),
            "idle buckets are evicted to make room"
        );
        let m = Check {
            key: key(w, Dim::Model("gpt-4o*".into()), Kind::Tpm),
            limit: 100,
            cost: 80,
        };
        assert!(t.admit(tenant, std::slice::from_ref(&m), now).is_ok());
        let d = t.admit(tenant, &[m], now).expect_err("80 + 80 > 100");
        assert_eq!(d.code, "tpm_limit_model");
        assert_eq!(d.detail()["model_pattern"], "gpt-4o*");
    }

    #[test]
    fn og21_a_request_bigger_than_the_whole_bucket_says_so() {
        let t = t();
        let d = t
            .admit(
                Uuid::new_v4(),
                &[Check {
                    key: key(Scope::Workspace, Dim::All, Kind::Tpm),
                    limit: 100,
                    cost: 500,
                }],
                Instant::now(),
            )
            .expect_err("never fits");
        assert!(d.exceeds_capacity);
        assert_eq!(d.code, "tpm_limit_workspace");
        assert!(d.message().contains("never fit"), "{}", d.message());
    }

    #[test]
    fn og21_tpm_reservation_is_reconciled_against_actual_usage() {
        let t = t();
        let tenant = Uuid::new_v4();
        let trace = Uuid::new_v4();
        let k = key(Scope::Key(Uuid::new_v4()), Dim::All, Kind::Tpm);
        let now = Instant::now();
        let check = Check {
            key: k.clone(),
            limit: 1000,
            cost: 600,
        };
        let debits = t.admit(tenant, &[check], now).expect("fits");
        assert_eq!(debits, vec![(k.clone(), 600)]);
        assert_eq!(t.tokens(tenant, &k).map(f64::round), Some(400.0));
        t.park(
            trace,
            Reservation::new(tenant, debits, Some("k1".into()), "gpt-4o".into(), None),
            now,
        );
        // The response used 100 tokens: 500 come back.
        let r = t
            .take(tenant, trace, Some("k1"), Some("gpt-4o"), None)
            .expect("parked");
        t.reconcile(&r, 100);
        let after = t.tokens(tenant, &k).expect("bucket");
        assert!((899.0..=901.0).contains(&after), "{after}");
        assert!(
            t.take(tenant, trace, Some("k1"), Some("gpt-4o"), None)
                .is_none(),
            "taken once"
        );
        // Over-use goes into debt, floored at one minute of capacity.
        let r = Reservation::new(tenant, vec![(k.clone(), 10)], None, "m".into(), None);
        t.reconcile(&r, 1_000_000);
        assert_eq!(t.tokens(tenant, &k).map(f64::round), Some(-1000.0));
    }

    /// rev5 L1: a span reconciles ONLY a reservation of its own key. The fallback to "the
    /// oldest under this trace" used to hand key B's span key A's reservation — refunding
    /// or draining a bucket of a key that never made the call (same workspace, a shared
    /// trace id). Within the key, a model / end-user mismatch still falls back.
    #[test]
    fn rev5_l1_reconcile_takes_only_a_reservation_of_the_same_key() {
        let t = t();
        let tenant = Uuid::new_v4();
        let trace = Uuid::new_v4();
        let k = key(Scope::Key(Uuid::new_v4()), Dim::All, Kind::Tpm);
        let now = Instant::now();
        t.park(
            trace,
            Reservation::new(
                tenant,
                vec![(k, 600)],
                Some("ka".into()),
                "gpt-4o".into(),
                None,
            ),
            now,
        );
        assert!(
            t.take(tenant, trace, Some("kb"), Some("gpt-4o"), None)
                .is_none(),
            "key B's span must not take key A's reservation"
        );
        assert!(
            t.take(tenant, trace, None, Some("gpt-4o"), None).is_none(),
            "a keyless span must not take a key's reservation"
        );
        assert!(
            t.take(tenant, trace, Some("ka"), Some("gpt-4o-mini"), None)
                .is_some(),
            "the same key, another model name (a failover): still its own"
        );
    }

    #[test]
    fn og21_parked_reservations_are_bounded_and_expire() {
        let t = t();
        let tenant = Uuid::new_v4();
        let k = key(Scope::Workspace, Dim::All, Kind::Tpm);
        let now = Instant::now();
        for _ in 0..6 {
            t.park(
                Uuid::new_v4(),
                Reservation::new(tenant, vec![(k.clone(), 1)], None, "m".into(), None),
                now,
            );
        }
        assert_eq!(
            t.pending_count.load(Ordering::Relaxed),
            4,
            "capped at max_pending"
        );
        t.sweep(now + Duration::from_secs(601));
        assert_eq!(t.pending_count.load(Ordering::Relaxed), 0);
        assert!(t.pending.is_empty());
    }
}
