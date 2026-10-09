//! `OG-22` — USD budgets at every level (workspace, project, key, end user), hard or
//! soft, over calendar or rolling windows; and the threshold crossings `OG-24` alerts on.
//! Spec: `specs/OG-22-budgets-every-level.md`.
//!
//! **The GWY-43 accounting, extended — not a second one.** Spend is the span's own cost
//! (`server::record_key_spend`, the one funnel), added after the response; the counter is
//! seeded from ClickHouse once per subject per window per process, tenant-first. What is
//! new: more subjects (project, end user), rolling windows (a ring of hourly buckets),
//! soft mode, and **fail-CLOSED on unknown spend**: a hard budget whose baseline read
//! FAILED refuses (`503 budget_spend_unknown`) rather than seeding zero; the next read is
//! attempted no sooner than `budget_seed_retry_backoff_ms` later. No ClickHouse configured
//! at all is not "unknown" — the in-process counter is then the whole accounting
//! (`spend.rs`).
//!
//! Per-process (one gateway per control plane, B-386). Per-end-user counters are bounded
//! per tenant (idle ones evicted first — eviction loses nothing durable: the next use
//! re-seeds from ClickHouse).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Datelike as _, TimeZone as _, Utc};
use dashmap::DashMap;
use serde_json::{Value, json};
use tracelane_shared::key_policy::{Budget, BudgetMode, BudgetWindow, Origin};
use uuid::Uuid;

use crate::limits::Scope;

/// Where a durable spend baseline is read from: the ClickHouse URL, and the entitlement
/// cache (for the tenant's ADR-031 read tier). Borrowed, so admission allocates nothing for
/// it; rev5 H2 — the eval / experiment / online-eval executors hold no `AppState`, so they
/// pass their own copies of the same two handles and read the SAME baselines.
#[derive(Clone, Copy)]
pub(crate) struct SpendSource<'a> {
    pub quota_ch_url: Option<&'a str>,
    pub entitlements: Option<&'a Arc<crate::entitlement_cache::EntitlementCache>>,
}

impl<'a> SpendSource<'a> {
    pub(crate) fn of(state: &'a crate::server::AppState) -> Self {
        Self {
            quota_ch_url: state.quota_ch_url.as_deref(),
            entitlements: state.entitlements.as_ref(),
        }
    }
}

/// One budget that applies to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Applicable {
    pub origin: Origin,
    pub scope: Scope,
    /// `Some` for an `end_user_budget`: the request's end-user id.
    pub end_user: Option<String>,
    pub budget: Budget,
}

impl Applicable {
    /// The `budget_exceeded_*` code's suffix.
    pub(crate) fn subject_label(&self) -> &'static str {
        if self.end_user.is_some() {
            "end_user"
        } else {
            self.scope.as_str()
        }
    }
}

/// What a budget check needs before it can decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prep {
    /// The counter is known: spent so far in the window, micro-USD.
    Ready { spent: u64 },
    /// Read the baseline for `period` first.
    NeedsSeed { period: u64 },
    /// The last baseline read failed less than the backoff ago: spend is unknown.
    Backoff,
    /// Too many end-user counters for this tenant.
    Capacity,
}

/// A durable baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seed {
    /// A calendar window's total, micro-USD.
    Total(u64),
    /// A rolling window's hourly totals: (hour index = unix secs / 3600, micro-USD).
    Hours(Vec<(u64, u64)>),
}

/// A threshold crossed, for `OG-24`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Crossing {
    pub tenant: Uuid,
    /// `budget:<layer>:<subject>:<window>:<threshold>:<period>` — fires once per window.
    pub dedup_key: String,
    pub payload: Value,
}

/// `seeded_for` of a rolling counter: it is seeded once per process; the hourly ring
/// keeps itself current after that.
const ROLLING: u64 = u64::MAX;

#[derive(Debug, Clone)]
struct Counter {
    origin: Origin,
    spec: Budget,
    end_user: Option<String>,
    seeded_for: Option<u64>,
    micro: u64,
    hours: VecDeque<(u64, u64)>,
    fired: HashSet<(String, u64)>,
    seed_failed_at: Option<Instant>,
    last_used: Instant,
}

impl Counter {
    fn new(a: &Applicable, now: Instant) -> Self {
        Self {
            origin: a.origin,
            spec: a.budget.clone(),
            end_user: a.end_user.clone(),
            seeded_for: None,
            micro: 0,
            hours: VecDeque::new(),
            fired: HashSet::new(),
            seed_failed_at: None,
            last_used: now,
        }
    }

    fn spent(&mut self, now: DateTime<Utc>) -> u64 {
        match self.spec.window.rolling_hours() {
            Some(n) => {
                let first = hour_index(now).saturating_sub(u64::from(n) - 1);
                while self.hours.front().is_some_and(|(h, _)| *h < first) {
                    self.hours.pop_front();
                }
                self.hours.iter().map(|(_, m)| *m).sum()
            }
            None => self.micro,
        }
    }

    fn add(&mut self, now: DateTime<Utc>, micro: u64) {
        match self.spec.window.rolling_hours() {
            Some(_) => {
                let h = hour_index(now);
                match self.hours.back_mut() {
                    Some((last, m)) if *last == h => *m = m.saturating_add(micro),
                    _ => self.hours.push_back((h, micro)),
                }
            }
            None => self.micro = self.micro.saturating_add(micro),
        }
    }

    /// Is this counter current for `now`'s period (or still awaiting its first seed)?
    fn current(&self, now: DateTime<Utc>) -> bool {
        match self.seeded_for {
            None => true,
            Some(ROLLING) => true,
            Some(p) => p == period_key(self.spec.window, now),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Slot {
    scope: Scope,
    end_user: Option<u64>,
}

/// One grouped end-user baseline read: (`scope`, `window`, period) → user → micro-USD.
#[derive(Debug, Clone, Default)]
pub(crate) struct EndUserSeed {
    pub by_user: HashMap<String, u64>,
    /// The read hit its row limit: a user absent from it is NOT known to be zero.
    pub truncated: bool,
}

#[derive(Default)]
struct TenantCounters {
    slots: HashMap<Slot, Vec<Counter>>,
    end_users: usize,
    eu_seeds: HashMap<(Scope, BudgetWindow, u64), EndUserSeed>,
}

/// The process-wide budget table.
pub(crate) struct BudgetTable {
    tenants: DashMap<Uuid, Arc<Mutex<TenantCounters>>>,
    max_end_users: usize,
    backoff: Duration,
}

/// The process-wide table.
pub(crate) fn table() -> &'static BudgetTable {
    static T: OnceLock<BudgetTable> = OnceLock::new();
    T.get_or_init(|| {
        let c = crate::controls::config();
        BudgetTable::new(
            c.budget_max_end_users_per_tenant,
            Duration::from_millis(c.budget_seed_retry_backoff_ms),
        )
    })
}

fn lock(m: &Mutex<TenantCounters>) -> std::sync::MutexGuard<'_, TenantCounters> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Hours since the epoch.
pub(crate) fn hour_index(now: DateTime<Utc>) -> u64 {
    u64::try_from(now.timestamp()).unwrap_or(0) / 3600
}

/// The calendar period key (`YYYYMMDD`, ISO `YYYYWW`, `YYYYMM`), or for a rolling window
/// the window-length bucket `hour / N` — the period an alert fires at most once in.
pub(crate) fn period_key(window: BudgetWindow, now: DateTime<Utc>) -> u64 {
    use tracelane_shared::spend::{BudgetReset, window_key};
    match window {
        BudgetWindow::Daily => u64::from(window_key(BudgetReset::Daily, now)),
        BudgetWindow::Weekly => u64::from(window_key(BudgetReset::Weekly, now)),
        BudgetWindow::Monthly => u64::from(window_key(BudgetReset::Monthly, now)),
        w => hour_index(now) / u64::from(w.rolling_hours().unwrap_or(1)),
    }
}

/// The first instant the window covers (UTC).
pub(crate) fn window_start(window: BudgetWindow, now: DateTime<Utc>) -> DateTime<Utc> {
    let midnight =
        |d: chrono::NaiveDate| Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).unwrap_or_default());
    let today = now.date_naive();
    match window {
        BudgetWindow::Daily => midnight(today),
        BudgetWindow::Weekly => midnight(
            today - chrono::Duration::days(i64::from(today.weekday().num_days_from_monday())),
        ),
        BudgetWindow::Monthly => midnight(today.with_day(1).unwrap_or(today)),
        w => {
            let n = u64::from(w.rolling_hours().unwrap_or(1));
            let first = hour_index(now).saturating_sub(n - 1) * 3600;
            Utc.timestamp_opt(i64::try_from(first).unwrap_or(0), 0)
                .single()
                .unwrap_or(now)
        }
    }
}

/// When a calendar window resets (`None` for a rolling one).
pub(crate) fn resets_at(window: BudgetWindow, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let start = window_start(window, now);
    match window {
        BudgetWindow::Daily => Some(start + chrono::Duration::days(1)),
        BudgetWindow::Weekly => Some(start + chrono::Duration::days(7)),
        BudgetWindow::Monthly => {
            let (y, m) = if start.month() == 12 {
                (start.year() + 1, 1)
            } else {
                (start.year(), start.month() + 1)
            };
            Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).single()
        }
        _ => None,
    }
}

fn slot_of(a: &Applicable) -> Slot {
    Slot {
        scope: a.scope,
        end_user: a.end_user.as_deref().map(crate::limits::end_user_hash),
    }
}

impl BudgetTable {
    pub(crate) fn new(max_end_users: usize, backoff: Duration) -> Self {
        Self {
            tenants: DashMap::new(),
            max_end_users,
            backoff,
        }
    }

    fn entry(&self, tenant: Uuid) -> Arc<Mutex<TenantCounters>> {
        Arc::clone(
            &self
                .tenants
                .entry(tenant)
                .or_insert_with(|| Arc::new(Mutex::new(TenantCounters::default()))),
        )
    }

    /// Find or create the counter for `a`, refresh its spec, and say whether it can
    /// decide now.
    pub(crate) fn prepare(
        &self,
        tenant: Uuid,
        a: &Applicable,
        now: DateTime<Utc>,
        at: Instant,
    ) -> Prep {
        let entry = self.entry(tenant);
        let mut tc = lock(&entry);
        let slot = slot_of(a);
        let exists = tc
            .slots
            .get(&slot)
            .is_some_and(|v| v.iter().any(|c| c.spec.window == a.budget.window));
        if !exists && slot.end_user.is_some() {
            if tc.end_users >= self.max_end_users {
                evict_idle_end_users(&mut tc, at, Duration::from_secs(3600));
            }
            if tc.end_users >= self.max_end_users {
                return Prep::Capacity;
            }
            tc.end_users += 1;
        }
        let v = tc.slots.entry(slot).or_default();
        let idx = match v.iter().position(|c| c.spec.window == a.budget.window) {
            Some(i) => i,
            None => {
                v.push(Counter::new(a, at));
                v.len() - 1
            }
        };
        let c = &mut v[idx];
        c.spec = a.budget.clone();
        c.origin = a.origin;
        c.last_used = at;
        if c.seed_failed_at
            .is_some_and(|t| at.saturating_duration_since(t) < self.backoff)
        {
            return Prep::Backoff;
        }
        match a.budget.window.rolling_hours() {
            Some(_) => {
                if c.seeded_for.is_none() {
                    Prep::NeedsSeed { period: ROLLING }
                } else {
                    Prep::Ready {
                        spent: c.spent(now),
                    }
                }
            }
            None => {
                let key = period_key(a.budget.window, now);
                if c.seeded_for == Some(key) {
                    Prep::Ready { spent: c.micro }
                } else {
                    Prep::NeedsSeed { period: key }
                }
            }
        }
    }

    /// Apply a durable baseline. Idempotent: a counter already seeded for `period` is not
    /// seeded twice. The first seed ADDS (spend recorded while the read was in flight is
    /// kept); a calendar rollover STORES (last period's total must not carry over).
    /// Returns the counter's spend after seeding.
    pub(crate) fn seed(
        &self,
        tenant: Uuid,
        a: &Applicable,
        period: u64,
        seed: &Seed,
        now: DateTime<Utc>,
    ) -> Option<u64> {
        let entry = self.entry(tenant);
        let mut tc = lock(&entry);
        let c = tc
            .slots
            .get_mut(&slot_of(a))?
            .iter_mut()
            .find(|c| c.spec.window == a.budget.window)?;
        c.seed_failed_at = None;
        if c.seeded_for != Some(period) {
            match seed {
                Seed::Total(m) => {
                    if c.seeded_for.is_some() {
                        c.micro = *m;
                        c.fired.clear();
                    } else {
                        c.micro = c.micro.saturating_add(*m);
                    }
                }
                Seed::Hours(hours) => {
                    let mut merged: std::collections::BTreeMap<u64, u64> =
                        c.hours.iter().copied().collect();
                    for (h, m) in hours {
                        let e = merged.entry(*h).or_insert(0);
                        *e = e.saturating_add(*m);
                    }
                    c.hours = merged.into_iter().collect();
                }
            }
            c.seeded_for = Some(period);
        }
        Some(c.spent(now))
    }

    /// Record that a baseline read FAILED: spend is unknown until a read succeeds, and the
    /// next read waits the backoff.
    pub(crate) fn seed_failed(&self, tenant: Uuid, a: &Applicable, at: Instant) {
        let entry = self.entry(tenant);
        let mut tc = lock(&entry);
        if let Some(c) = tc
            .slots
            .get_mut(&slot_of(a))
            .and_then(|v| v.iter_mut().find(|c| c.spec.window == a.budget.window))
        {
            c.seed_failed_at = Some(at);
        }
    }

    /// A cached grouped end-user baseline for (scope, window, period), if one was read.
    pub(crate) fn end_user_seed(
        &self,
        tenant: Uuid,
        scope: Scope,
        window: BudgetWindow,
        period: u64,
    ) -> Option<EndUserSeed> {
        let e = self.tenants.get(&tenant)?;
        let tc = lock(&e);
        tc.eu_seeds.get(&(scope, window, period)).cloned()
    }

    /// Keep a grouped end-user baseline (one per scope and window; an older period's is
    /// replaced).
    pub(crate) fn store_end_user_seed(
        &self,
        tenant: Uuid,
        scope: Scope,
        window: BudgetWindow,
        period: u64,
        seed: EndUserSeed,
    ) {
        let entry = self.entry(tenant);
        let mut tc = lock(&entry);
        tc.eu_seeds
            .retain(|(s, w, _), _| !(*s == scope && *w == window));
        tc.eu_seeds.insert((scope, window, period), seed);
    }

    /// Add a recorded request's cost to every counter it belongs to (workspace; its
    /// project; its key; each of those for its end user) and return the thresholds it
    /// crossed for the first time this period. `sink` queues a crossing; a crossing is
    /// marked fired ONLY when the sink accepted it, so a full queue retries on the next
    /// request instead of losing the alert.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record(
        &self,
        tenant: Uuid,
        project: Option<Uuid>,
        key: Option<Uuid>,
        end_user: Option<&str>,
        cost_micro: u64,
        now: DateTime<Utc>,
        sink: &dyn Fn(&Crossing) -> bool,
    ) {
        if cost_micro == 0 {
            return;
        }
        let Some(entry) = self.tenants.get(&tenant).map(|e| Arc::clone(&e)) else {
            return;
        };
        let mut tc = lock(&entry);
        let eu = end_user.map(crate::limits::end_user_hash);
        let mut scopes = vec![Scope::Workspace];
        scopes.extend(project.map(Scope::Project));
        scopes.extend(key.map(Scope::Key));
        for scope in scopes {
            let slots: &[Option<u64>] = if eu.is_some() { &[None, eu] } else { &[None] };
            for &end_user_slot in slots {
                let Some(v) = tc.slots.get_mut(&Slot {
                    scope,
                    end_user: end_user_slot,
                }) else {
                    continue;
                };
                for c in v.iter_mut() {
                    if !c.current(now) {
                        continue;
                    }
                    let before = c.spent(now);
                    c.add(now, cost_micro);
                    let after = before.saturating_add(cost_micro);
                    let period = period_key(c.spec.window, now);
                    for (at, label) in c.spec.thresholds() {
                        if after < at || c.fired.contains(&(label.clone(), period)) {
                            continue;
                        }
                        let crossing = crossing_for(tenant, scope, c, &label, period, after, now);
                        if sink(&crossing) {
                            c.fired.insert((label, period));
                        }
                    }
                }
            }
        }
    }

    /// Every live counter of `tenant`, for `GET /v1/controls/budgets`.
    pub(crate) fn snapshot(&self, tenant: Uuid, now: DateTime<Utc>) -> Vec<Value> {
        let Some(entry) = self.tenants.get(&tenant).map(|e| Arc::clone(&e)) else {
            return Vec::new();
        };
        let mut tc = lock(&entry);
        let mut out = Vec::new();
        for (slot, v) in &mut tc.slots {
            for c in v.iter_mut() {
                let known = c.seeded_for.is_some() && c.current(now);
                let spent = if known { c.spent(now) } else { 0 };
                out.push(json!({
                    "policy": c.origin.as_str(),
                    "scope": slot.scope.as_str(),
                    "subjectId": subject_id(slot.scope),
                    "endUser": c.end_user,
                    "window": c.spec.window.as_str(),
                    "mode": c.spec.mode.as_str(),
                    "budgetUsd": c.spec.usd(),
                    "spentUsd": known.then(|| spent as f64 / 1_000_000.0),
                    "known": known,
                    "resetsAt": resets_at(c.spec.window, now).map(|t| t.to_rfc3339()),
                }));
            }
        }
        out
    }
}

fn evict_idle_end_users(tc: &mut TenantCounters, at: Instant, idle: Duration) {
    let mut freed = 0usize;
    tc.slots.retain(|slot, v| {
        if slot.end_user.is_none() {
            return true;
        }
        let keep = v
            .iter()
            .any(|c| at.saturating_duration_since(c.last_used) < idle);
        if !keep {
            freed += 1;
        }
        keep
    });
    tc.end_users = tc.end_users.saturating_sub(freed);
}

fn subject_id(scope: Scope) -> Option<String> {
    match scope {
        Scope::Workspace => None,
        Scope::Project(id) | Scope::Key(id) => Some(id.to_string()),
    }
}

/// A short, stable, non-reversible token for an end-user id inside a dedup key.
fn end_user_token(id: &str) -> String {
    use sha2::Digest as _;
    hex::encode(&sha2::Sha256::digest(id.as_bytes())[..8])
}

fn crossing_for(
    tenant: Uuid,
    scope: Scope,
    c: &Counter,
    label: &str,
    period: u64,
    spent: u64,
    now: DateTime<Utc>,
) -> Crossing {
    let mut subject = subject_id(scope).unwrap_or_else(|| "workspace".to_owned());
    if let Some(u) = &c.end_user {
        subject = format!("{subject}:eu:{}", end_user_token(u));
    }
    let dedup_key = format!(
        "budget:{}:{subject}:{}:{label}:{period}",
        c.origin.as_str(),
        c.spec.window.as_str()
    );
    Crossing {
        tenant,
        dedup_key,
        payload: json!({
            "type": "budget.threshold_crossed",
            "tenant_id": tenant.to_string(),
            "policy": c.origin.as_str(),
            "scope": scope.as_str(),
            "subject_id": subject_id(scope),
            "end_user": c.end_user,
            "window": c.spec.window.as_str(),
            "mode": c.spec.mode.as_str(),
            "threshold": label,
            "budget_usd": c.spec.usd(),
            "spent_usd": spent as f64 / 1_000_000.0,
            "period": period,
            "resets_at": resets_at(c.spec.window, now).map(|t| t.to_rfc3339()),
            "crossed_at": now.to_rfc3339(),
        }),
    }
}

/// `server::record_key_spend`'s hook: add the span's cost to every OG-22 counter it
/// belongs to, and queue the thresholds it crossed (`OG-24`). Off the response path's
/// critical work: one map probe when the tenant has no budgets.
pub(crate) fn record_span(api_key_id: Option<&str>, span: &tracelane_shared::TracelaneSpan) {
    let a = &span.attributes;
    let Some(cost) = a.gen_ai_usage_cost.filter(|c| c.is_finite() && *c > 0.0) else {
        return;
    };
    let micro = (cost * 1_000_000.0).round() as u64;
    let project = a
        .tracelane_project_id
        .as_deref()
        .and_then(|p| Uuid::parse_str(p).ok());
    let key = api_key_id.and_then(|k| Uuid::parse_str(k).ok());
    table().record(
        *span.tenant_id.as_uuid(),
        project,
        key,
        a.user_id.as_deref(),
        micro,
        Utc::now(),
        &crate::spend_alerts::enqueue,
    );
}

// ── Durable baselines (ClickHouse, tenant-first, ADR-031 caps) ───────────────

/// The scope filter of a baseline read: the workspace has none; a key filters the
/// materialised `api_key_id`; a project and an end user read the span's attributes
/// JSON (`OG-23` / `OBS-20` — no materialised column, spec §6). Binds, in order:
/// tenant, the scope value(s), the window start (unix seconds), then a `LIMIT`.
macro_rules! budget_sql {
    ($select:literal, $filter:literal, $tail:literal) => {
        concat!(
            "SELECT ",
            $select,
            " FROM tracelane.spans WHERE tenant_id = ? ",
            $filter,
            " AND cost_usd_present = 1 AND start_time >= toDateTime(?, 'UTC')",
            $tail
        )
    };
}

pub(crate) const WS_TOTAL_SQL: &str = budget_sql!("toFloat64(sum(cost_usd)) AS usd", "", "");
pub(crate) const KEY_TOTAL_SQL: &str =
    budget_sql!("toFloat64(sum(cost_usd)) AS usd", "AND api_key_id = ?", "");
pub(crate) const PROJECT_TOTAL_SQL: &str = budget_sql!(
    "toFloat64(sum(cost_usd)) AS usd",
    "AND JSONExtractString(attributes, 'tracelane_project_id') = ?",
    ""
);
pub(crate) const WS_HOURLY_SQL: &str = budget_sql!(
    "intDiv(toUInt64(toUnixTimestamp(start_time)), 3600) AS h, toFloat64(sum(cost_usd)) AS usd",
    "",
    " GROUP BY h"
);
pub(crate) const KEY_HOURLY_SQL: &str = budget_sql!(
    "intDiv(toUInt64(toUnixTimestamp(start_time)), 3600) AS h, toFloat64(sum(cost_usd)) AS usd",
    "AND api_key_id = ?",
    " GROUP BY h"
);
pub(crate) const PROJECT_HOURLY_SQL: &str = budget_sql!(
    "intDiv(toUInt64(toUnixTimestamp(start_time)), 3600) AS h, toFloat64(sum(cost_usd)) AS usd",
    "AND JSONExtractString(attributes, 'tracelane_project_id') = ?",
    " GROUP BY h"
);
/// End users, grouped: the top `LIMIT` spenders of the window in one read.
pub(crate) const WS_END_USERS_SQL: &str = budget_sql!(
    "JSONExtractString(attributes, 'user_id') AS u, toFloat64(sum(cost_usd)) AS usd",
    "",
    " AND u != '' GROUP BY u ORDER BY usd DESC LIMIT ?"
);
pub(crate) const KEY_END_USERS_SQL: &str = budget_sql!(
    "JSONExtractString(attributes, 'user_id') AS u, toFloat64(sum(cost_usd)) AS usd",
    "AND api_key_id = ?",
    " AND u != '' GROUP BY u ORDER BY usd DESC LIMIT ?"
);
pub(crate) const PROJECT_END_USERS_SQL: &str = budget_sql!(
    "JSONExtractString(attributes, 'user_id') AS u, toFloat64(sum(cost_usd)) AS usd",
    "AND JSONExtractString(attributes, 'tracelane_project_id') = ?",
    " AND u != '' GROUP BY u ORDER BY usd DESC LIMIT ?"
);
/// One end user, when the grouped read was truncated and did not include them.
pub(crate) const WS_END_USER_SQL: &str = budget_sql!(
    "toFloat64(sum(cost_usd)) AS usd",
    "AND JSONExtractString(attributes, 'user_id') = ?",
    ""
);
pub(crate) const KEY_END_USER_SQL: &str = budget_sql!(
    "toFloat64(sum(cost_usd)) AS usd",
    "AND api_key_id = ? AND JSONExtractString(attributes, 'user_id') = ?",
    ""
);
pub(crate) const PROJECT_END_USER_SQL: &str = budget_sql!(
    "toFloat64(sum(cost_usd)) AS usd",
    "AND JSONExtractString(attributes, 'tracelane_project_id') = ? AND JSONExtractString(attributes, 'user_id') = ?",
    ""
);

#[derive(serde::Deserialize, clickhouse::Row)]
struct UsdRow {
    usd: f64,
}

#[derive(serde::Deserialize, clickhouse::Row)]
struct HourRow {
    h: u64,
    usd: f64,
}

#[derive(serde::Deserialize, clickhouse::Row)]
struct UserRow {
    u: String,
    usd: f64,
}

fn to_micro(usd: f64) -> u64 {
    if usd.is_finite() && usd > 0.0 {
        (usd * 1_000_000.0).round() as u64
    } else {
        0
    }
}

/// Read the durable baseline for `a`. `None` = the read FAILED: spend is UNKNOWN (the
/// caller refuses a hard budget — fail-CLOSED). No ClickHouse configured ⇒ zero: there is
/// no durable source and the in-process counter is the whole accounting.
///
/// Failures are counted (`budget_spend_unknown`), logged once per degraded episode.
pub(crate) async fn baseline(
    src: SpendSource<'_>,
    tenant: &tracelane_shared::TenantId,
    a: &Applicable,
    period: u64,
    now: DateTime<Utc>,
) -> Option<Seed> {
    let rolling = a.budget.window.rolling_hours().is_some();
    let Some(url) = src.quota_ch_url else {
        return Some(if rolling {
            Seed::Hours(Vec::new())
        } else {
            Seed::Total(0)
        });
    };
    let tier = crate::clickhouse_query::tier_for_tenant(src.entitlements, tenant).await;
    let ch = crate::clickhouse_query::ch_client(url);
    let start = u32::try_from(window_start(a.budget.window, now).timestamp()).unwrap_or(0);
    let result = read_baseline(&ch, tier, tenant, a, period, start, rolling).await;
    match result {
        Ok(s) => {
            tracelane_shared::degradation::resolve(
                tracelane_shared::degradation::Degradation::BudgetSpendUnknown,
            );
            Some(s)
        }
        Err(e) => {
            if tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::BudgetSpendUnknown,
            ) == 1
            {
                tracing::warn!(error = %e, tenant_id = %tenant, "budget baseline ClickHouse read failed — a HARD budget refuses until a read succeeds (fail-closed). Further occurrences are counted, not logged (kind=budget_spend_unknown)");
            }
            None
        }
    }
}

fn capped(
    ch: &clickhouse::Client,
    tier: crate::clickhouse_query::PlanTier,
    sql: &'static str,
    tenant: &tracelane_shared::TenantId,
    scope: Scope,
) -> clickhouse::query::Query {
    let mut q = ch
        .query(&crate::clickhouse_query::TenantQuery::new(sql, tier).sql_with_settings())
        .bind(tenant.to_string());
    if let Some(v) = subject_id(scope) {
        q = q.bind(v);
    }
    q
}

async fn read_baseline(
    ch: &clickhouse::Client,
    tier: crate::clickhouse_query::PlanTier,
    tenant: &tracelane_shared::TenantId,
    a: &Applicable,
    period: u64,
    start: u32,
    rolling: bool,
) -> Result<Seed, clickhouse::error::Error> {
    if let Some(user) = &a.end_user {
        return end_user_baseline(ch, tier, tenant, a, user, period, start).await;
    }
    if rolling {
        let sql = match a.scope {
            Scope::Workspace => WS_HOURLY_SQL,
            Scope::Key(_) => KEY_HOURLY_SQL,
            Scope::Project(_) => PROJECT_HOURLY_SQL,
        };
        let rows = capped(ch, tier, sql, tenant, a.scope)
            .bind(start)
            .fetch_all::<HourRow>()
            .await?;
        return Ok(Seed::Hours(
            rows.into_iter().map(|r| (r.h, to_micro(r.usd))).collect(),
        ));
    }
    let sql = match a.scope {
        Scope::Workspace => WS_TOTAL_SQL,
        Scope::Key(_) => KEY_TOTAL_SQL,
        Scope::Project(_) => PROJECT_TOTAL_SQL,
    };
    let r = capped(ch, tier, sql, tenant, a.scope)
        .bind(start)
        .fetch_one::<UsdRow>()
        .await?;
    Ok(Seed::Total(to_micro(r.usd)))
}

/// An end user's calendar baseline: the tenant's grouped read for (scope, window,
/// period), cached; a user missing from a TRUNCATED read is read on its own.
async fn end_user_baseline(
    ch: &clickhouse::Client,
    tier: crate::clickhouse_query::PlanTier,
    tenant: &tracelane_shared::TenantId,
    a: &Applicable,
    user: &str,
    period: u64,
    start: u32,
) -> Result<Seed, clickhouse::error::Error> {
    let t = *tenant.as_uuid();
    let seed = match table().end_user_seed(t, a.scope, a.budget.window, period) {
        Some(s) => s,
        None => {
            let limit = table().max_end_users as u64;
            let sql = match a.scope {
                Scope::Workspace => WS_END_USERS_SQL,
                Scope::Key(_) => KEY_END_USERS_SQL,
                Scope::Project(_) => PROJECT_END_USERS_SQL,
            };
            let rows = capped(ch, tier, sql, tenant, a.scope)
                .bind(start)
                .bind(limit)
                .fetch_all::<UserRow>()
                .await?;
            let truncated = rows.len() as u64 >= limit;
            let s = EndUserSeed {
                by_user: rows.into_iter().map(|r| (r.u, to_micro(r.usd))).collect(),
                truncated,
            };
            table().store_end_user_seed(t, a.scope, a.budget.window, period, s.clone());
            s
        }
    };
    if let Some(m) = seed.by_user.get(user) {
        return Ok(Seed::Total(*m));
    }
    if !seed.truncated {
        return Ok(Seed::Total(0));
    }
    let sql = match a.scope {
        Scope::Workspace => WS_END_USER_SQL,
        Scope::Key(_) => KEY_END_USER_SQL,
        Scope::Project(_) => PROJECT_END_USER_SQL,
    };
    let r = capped(ch, tier, sql, tenant, a.scope)
        .bind(user)
        .bind(start)
        .fetch_one::<UsdRow>()
        .await?;
    Ok(Seed::Total(to_micro(r.usd)))
}

/// Is a budget's mode hard?
pub(crate) fn is_hard(b: &Budget) -> bool {
    b.mode == BudgetMode::Hard
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn budget(usd: u64, window: BudgetWindow, mode: BudgetMode, pct: &[u32]) -> Budget {
        Budget {
            micro_usd: usd * 1_000_000,
            window,
            mode,
            alert_at_percent: pct.to_vec(),
            alert_at_micro_usd: vec![],
        }
    }

    fn app(scope: Scope, end_user: Option<&str>, b: Budget) -> Applicable {
        Applicable {
            origin: Origin::Project,
            scope,
            end_user: end_user.map(str::to_owned),
            budget: b,
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn og22_a_calendar_counter_needs_a_seed_then_counts_and_rolls_over() {
        let t = BudgetTable::new(10, Duration::from_secs(5));
        let tenant = Uuid::new_v4();
        let p = Scope::Project(Uuid::new_v4());
        let a = app(
            p,
            None,
            budget(10, BudgetWindow::Monthly, BudgetMode::Hard, &[]),
        );
        let oct = at("2026-10-04T12:00:00Z");
        let i = Instant::now();
        let Prep::NeedsSeed { period } = t.prepare(tenant, &a, oct, i) else {
            panic!("a fresh counter needs a seed");
        };
        assert_eq!(period, 202_610);
        assert_eq!(
            t.seed(tenant, &a, period, &Seed::Total(4_000_000), oct),
            Some(4_000_000)
        );
        assert_eq!(
            t.prepare(tenant, &a, oct, i),
            Prep::Ready { spent: 4_000_000 }
        );
        t.record(
            tenant,
            Some(match p {
                Scope::Project(u) => u,
                _ => unreachable!(),
            }),
            None,
            None,
            1_000_000,
            oct,
            &|_| true,
        );
        assert_eq!(
            t.prepare(tenant, &a, oct, i),
            Prep::Ready { spent: 5_000_000 }
        );
        // November: a new period needs a new seed, and the seed REPLACES October's total.
        let nov = at("2026-11-01T00:00:01Z");
        assert_eq!(
            t.prepare(tenant, &a, nov, i),
            Prep::NeedsSeed { period: 202_611 }
        );
        assert_eq!(t.seed(tenant, &a, 202_611, &Seed::Total(0), nov), Some(0));
    }

    #[test]
    fn og22_a_rolling_counter_expires_hour_by_hour() {
        let t = BudgetTable::new(10, Duration::from_secs(5));
        let tenant = Uuid::new_v4();
        let a = app(
            Scope::Workspace,
            None,
            budget(10, BudgetWindow::Rolling24h, BudgetMode::Hard, &[]),
        );
        let now = at("2026-10-04T12:30:00Z");
        let h = hour_index(now);
        let i = Instant::now();
        assert_eq!(
            t.prepare(tenant, &a, now, i),
            Prep::NeedsSeed { period: ROLLING }
        );
        // 3 USD 23 hours ago (still in), 2 USD 24 hours ago (out).
        let seeded = t.seed(
            tenant,
            &a,
            ROLLING,
            &Seed::Hours(vec![(h - 24, 2_000_000), (h - 23, 3_000_000)]),
            now,
        );
        assert_eq!(seeded, Some(3_000_000));
        let later = now + chrono::Duration::hours(1);
        assert_eq!(
            t.prepare(tenant, &a, later, i),
            Prep::Ready { spent: 0 },
            "the 3 USD hour aged out"
        );
    }

    #[test]
    fn og22_a_failed_seed_is_unknown_until_the_backoff_passes() {
        let t = BudgetTable::new(10, Duration::from_secs(5));
        let tenant = Uuid::new_v4();
        let a = app(
            Scope::Key(Uuid::new_v4()),
            None,
            budget(1, BudgetWindow::Daily, BudgetMode::Hard, &[]),
        );
        let now = at("2026-10-04T12:00:00Z");
        let i = Instant::now();
        assert!(matches!(
            t.prepare(tenant, &a, now, i),
            Prep::NeedsSeed { .. }
        ));
        t.seed_failed(tenant, &a, i);
        assert_eq!(
            t.prepare(tenant, &a, now, i + Duration::from_secs(1)),
            Prep::Backoff
        );
        assert!(matches!(
            t.prepare(tenant, &a, now, i + Duration::from_secs(6)),
            Prep::NeedsSeed { .. }
        ));
    }

    #[test]
    fn og22_end_user_counters_are_separate_and_bounded() {
        let t = BudgetTable::new(2, Duration::from_secs(5));
        let tenant = Uuid::new_v4();
        let b = budget(1, BudgetWindow::Daily, BudgetMode::Hard, &[]);
        let now = at("2026-10-04T12:00:00Z");
        let i = Instant::now();
        for u in ["a", "b"] {
            let a = app(Scope::Workspace, Some(u), b.clone());
            let Prep::NeedsSeed { period } = t.prepare(tenant, &a, now, i) else {
                panic!()
            };
            t.seed(tenant, &a, period, &Seed::Total(0), now);
        }
        t.record(tenant, None, None, Some("a"), 1_500_000, now, &|_| true);
        let a = app(Scope::Workspace, Some("a"), b.clone());
        let bb = app(Scope::Workspace, Some("b"), b.clone());
        assert_eq!(
            t.prepare(tenant, &a, now, i),
            Prep::Ready { spent: 1_500_000 }
        );
        assert_eq!(t.prepare(tenant, &bb, now, i), Prep::Ready { spent: 0 });
        assert_eq!(
            t.prepare(tenant, &app(Scope::Workspace, Some("c"), b), now, i),
            Prep::Capacity
        );
    }

    #[test]
    fn og24_a_threshold_fires_once_per_window_and_again_next_window() {
        let t = BudgetTable::new(10, Duration::from_secs(5));
        let tenant = Uuid::new_v4();
        let a = app(
            Scope::Workspace,
            None,
            budget(10, BudgetWindow::Daily, BudgetMode::Soft, &[50]),
        );
        let d1 = at("2026-10-04T12:00:00Z");
        let i = Instant::now();
        let Prep::NeedsSeed { period } = t.prepare(tenant, &a, d1, i) else {
            panic!()
        };
        t.seed(tenant, &a, period, &Seed::Total(0), d1);
        let seen: RefCell<Vec<Crossing>> = RefCell::new(Vec::new());
        let sink = |c: &Crossing| {
            seen.borrow_mut().push(c.clone());
            true
        };
        t.record(tenant, None, None, None, 6_000_000, d1, &sink); // 60 %: the 50 % fires
        t.record(tenant, None, None, None, 1_000_000, d1, &sink); // 70 %: nothing new
        t.record(tenant, None, None, None, 4_000_000, d1, &sink); // 110 %: soft 100 % fires
        let labels: Vec<String> = seen
            .borrow()
            .iter()
            .map(|c| c.payload["threshold"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(labels, vec!["50%", "100%"]);
        assert!(
            seen.borrow()[0].dedup_key.ends_with(":50%:20261004"),
            "{}",
            seen.borrow()[0].dedup_key
        );
        // The next day: a new period, re-seeded, fires again.
        let d2 = at("2026-10-05T01:00:00Z");
        let Prep::NeedsSeed { period } = t.prepare(tenant, &a, d2, i) else {
            panic!()
        };
        t.seed(tenant, &a, period, &Seed::Total(0), d2);
        t.record(tenant, None, None, None, 6_000_000, d2, &sink);
        assert_eq!(seen.borrow().len(), 3);
        assert!(seen.borrow()[2].dedup_key.ends_with(":50%:20261005"));
    }

    #[test]
    fn og24_a_crossing_the_queue_refused_is_retried_on_the_next_record() {
        let t = BudgetTable::new(10, Duration::from_secs(5));
        let tenant = Uuid::new_v4();
        let a = app(
            Scope::Workspace,
            None,
            budget(10, BudgetWindow::Monthly, BudgetMode::Hard, &[10]),
        );
        let now = at("2026-10-04T12:00:00Z");
        let i = Instant::now();
        let Prep::NeedsSeed { period } = t.prepare(tenant, &a, now, i) else {
            panic!()
        };
        t.seed(tenant, &a, period, &Seed::Total(0), now);
        let tries = RefCell::new(0);
        t.record(tenant, None, None, None, 2_000_000, now, &|_| {
            *tries.borrow_mut() += 1;
            false
        });
        t.record(tenant, None, None, None, 1, now, &|_| {
            *tries.borrow_mut() += 1;
            true
        });
        t.record(tenant, None, None, None, 1, now, &|_| {
            *tries.borrow_mut() += 1;
            true
        });
        assert_eq!(
            *tries.borrow(),
            2,
            "refused once, accepted once, then never again"
        );
    }

    #[test]
    fn og22_window_start_and_resets_at_are_utc_calendar_boundaries() {
        let now = at("2026-10-07T15:20:00Z"); // a Wednesday
        assert_eq!(
            window_start(BudgetWindow::Daily, now),
            at("2026-10-07T00:00:00Z")
        );
        assert_eq!(
            window_start(BudgetWindow::Weekly, now),
            at("2026-10-05T00:00:00Z")
        );
        assert_eq!(
            window_start(BudgetWindow::Monthly, now),
            at("2026-10-01T00:00:00Z")
        );
        assert_eq!(
            window_start(BudgetWindow::Rolling24h, now),
            at("2026-10-06T16:00:00Z")
        );
        assert_eq!(
            resets_at(BudgetWindow::Monthly, now),
            Some(at("2026-11-01T00:00:00Z"))
        );
        assert_eq!(resets_at(BudgetWindow::Rolling7d, now), None);
    }
}
