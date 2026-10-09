//! Per-tenant gateway rejection counters (rate-limit 429s + budget-exceeded 402s —
//! `admission.rs` `Refusal`; this header said "429s" for both until B-453, 2026-09-20) PLUS
//! (RI-05 / M2, 2026-09-20) the aggregated admission-refusal telemetry that turns
//! those counters into `tracelane.admission.rejected` spans.
//!
//! Callers: `admission.rs`'s three refusal sites (`Step::RateLimit`,
//! `Step::KeyBudget`, `Step::WorkspaceBudget` — shared by `/v1/chat/completions`,
//! `/v1/embeddings` and `/v1/messages`) call [`RejectionRegistry::record_admission_refusal`];
//! `anthropic_messages.rs`'s `/v1/messages/count_tokens` and `trace_ingest.rs`'s
//! `/v1/traces` OTLP-ingest rate limiter call the older
//! [`RejectionRegistry::record_rate_limited`] directly (out of RI-05's scope — no
//! per-request reason/key context to hand the aggregator there). The Gateway-ops
//! read (`/v1/gateway/stats` in [`crate::trace_reads`]) reads the authenticated
//! tenant's totals, unaffected by which entry point recorded them.
//!
//! Why a counter and not a span, historically: a rate-limit / budget 429 is
//! returned BEFORE any provider dispatch, so there is no request span to carry
//! the signal. Emitting one span PER rejected request would write telemetry for
//! exactly the load the limiter is shedding — a DoS amplifier under a flood.
//!
//! **RI-05 §2.2 answers this without giving up the DoS argument**: aggregate.
//! [`RejectionRegistry::record_admission_refusal`] buckets each refusal by
//! `(tenant, api_key_id, reason)` inside the CURRENT UTC minute (the limiter's own
//! window, `admission.rs` `Step::RateLimit`) — an `AtomicU32` bump, no I/O, no
//! allocation beyond the map's own (bounded) growth. Once a minute closes,
//! [`RejectionRegistry::roll_minute`] turns each closed bucket into exactly ONE
//! `tracelane.admission.rejected` span carrying the count — so a flood of 10⁶
//! refusals against one key still writes ONE row, never 10⁶. This keeps the
//! per-request cost O(1) (one more `DashMap` probe on the existing 429 path) and
//! keeps the aggregation's cost bounded by the number of DISTINCT triples, not by
//! request volume ([`MAX_LIVE_BUCKETS`]).
//!
//! **BILL-01 / ADR-076 (2026-09-13) retired what the OLD counter used to mean.**
//! It was the MONTHLY TRACE-COUNT hard cap (ADR-020); that concept is
//! deleted outright — ingest is never blocked by billing state, on any tier.
//! `record_budget_exceeded` is called from `admission::run`'s
//! `KeyBudget`/`WorkspaceBudget` steps, so it counts a customer's own opt-in
//! USD spend-budget 429s (GWY-43), never a quota. The field, method and JSON
//! wire name (`budget_exceeded_since_start`, `GatewayStatsResponse` in
//! `trace_reads.rs`; `apps/web/lib/gateway-ops.ts` reads that key) were
//! renamed together on 2026-09-14 — founder: "no old code logic should
//! exist" — so no surface names a quota this gateway does not have.
//!
//! Semantics of the OLD counters — **process-lifetime totals**, reset on
//! restart/redeploy, NOT a rolling window. The surface labels them "since gateway
//! start" so the number is never confused with the 24h span-derived metrics
//! beside it. Single gateway instance per node today; a multi-instance fleet
//! would sum per-instance counters (documented, not silently wrong).
//! [`record_admission_refusal`] keeps bumping these SAME counters (unchanged
//! behaviour, unchanged wire contract) in addition to the new per-minute
//! buckets — nothing `/v1/gateway/stats` reads was removed.

/// The aggregate refusal span's name (RI-05 §2.2). ONE constant, read by the
/// writer here and by every reader that must EXCLUDE it — `billing/metering_job.rs`'s
/// series meter (a refusal is not a billable series) — so the two cannot drift.
pub(crate) const REJECTED_SPAN_NAME: &str = "tracelane.admission.rejected";

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tracelane_shared::span::{SpanAttributes, SpanStatus, SpanStatusCode};
use tracelane_shared::{TenantId, TracelaneSpan};
use uuid::Uuid;

/// One tenant's rejection tallies. `Default` gives both counters at 0.
#[derive(Default)]
struct TenantRejections {
    rate_limited: AtomicU64,
    budget_exceeded: AtomicU64,
}

/// The three admission-refusal reasons `admission.rs` produces (RI-05 / M2 §2.2).
/// `as_str` is the wire value stored on `tracelane_rejection_reason` — a CLOSED
/// vocabulary, never a free-form string, so a read path can `IN (...)` it safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RejectionReason {
    /// `Step::RateLimit` — the per-minute token bucket (tenant, or the key's own
    /// override).
    RateLimited,
    /// `Step::KeyBudget` — the credential's own USD spend ceiling (GWY-43).
    KeyBudgetExceeded,
    /// `Step::WorkspaceBudget` — the tenant-wide USD spend ceiling (GWY-43).
    WorkspaceBudgetExceeded,
    /// `Step::Policy` — the key.s or its project.s policy (OG-20). A refusal at
    /// AUTHENTICATION (`source_ips`) is not counted here: it never reaches admission.
    PolicyDenied,
}

impl RejectionReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::KeyBudgetExceeded => "key_budget_exceeded",
            Self::WorkspaceBudgetExceeded => "workspace_budget_exceeded",
            Self::PolicyDenied => "policy_denied",
        }
    }
}

/// The most (tenant, api_key_id, reason) triples the per-minute bucket table may
/// hold live at once. RI-05 §2.2's DoS argument bounds the aggregate by DISTINCT
/// triples, not by request count — this is the cap on that distinct-triple count,
/// so an attacker minting a huge number of distinct (tenant, key) pairs in one
/// minute (credential stuffing, a key-enumeration sweep) cannot grow this table
/// without bound between rolls. The spec (§5) does not name a number, so this is
/// the task's own default.
///
/// **Eviction on the cap:** a NEW triple (not already bucketed this minute) that
/// arrives once the table is at the cap is NOT bucketed — no aggregate span will
/// carry it — but the request's REFUSAL still counts on the unchanged
/// process-lifetime counters (`snapshot`, `/v1/gateway/stats`). The miss is
/// recorded once per occurrence on
/// `Degradation::RejectionBucketCapReached` (`crates/shared/src/degradation.rs`),
/// which is the load-bearing signal here, not a dropped span nobody would notice.
/// An ALREADY-bucketed triple is never evicted early — only [`RejectionRegistry::roll_minute`]
/// removes entries, and only closed (previous-minute) ones — so the cap governs
/// distinct-triple GROWTH, never an in-progress count.
const MAX_LIVE_BUCKETS: usize = 10_000;

/// One (tenant, api_key_id, reason, UTC-minute) bucket identity. `minute` is the
/// Unix-minute floor (`timestamp / 60`) — the limiter's own window
/// (`admission.rs` `Step::RateLimit` is a per-minute token bucket), not a
/// tunable, so RI-05 §2.2 deliberately names no reference table for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    tenant: TenantId,
    api_key_id: Option<String>,
    reason: RejectionReason,
    minute: i64,
}

/// Per-tenant rejection registry. ONE instance per process, owned by
/// `AppState` (B-386 b) — not a global.
///
/// `String` key on `by_tenant` mirrors [`crate::spend::SpendTracker`]'s subject
/// keying (and the retired trace-quota tracker's before it, deleted under
/// ADR-076) — kept exactly as it was; `buckets` below uses `TenantId` directly
/// (it already derives `Hash + Eq`) since that map is new and pays no legacy
/// constraint.
pub struct RejectionRegistry {
    by_tenant: DashMap<String, TenantRejections>,
    /// RI-05 / M2 — live (not yet rolled) per-minute buckets. Removed from this
    /// map the moment [`Self::roll_minute`] closes them, so its steady-state size
    /// is bounded by the CURRENT minute's distinct-triple count, capped at
    /// [`MAX_LIVE_BUCKETS`] — never by the process lifetime.
    buckets: DashMap<BucketKey, AtomicU32>,
}

impl Default for RejectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RejectionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_tenant: DashMap::new(),
            buckets: DashMap::new(),
        }
    }

    /// Record one rate-limit (token-bucket) 429 for `tenant`.
    ///
    /// Kept as its own method (rather than folded away) because it is still the
    /// direct call from the two routes RI-05 does not cover — `/v1/messages/count_tokens`
    /// (`anthropic_messages.rs`) and `/v1/traces` OTLP ingest (`trace_ingest.rs`) —
    /// which have no per-request API-key/reason context to hand
    /// [`Self::record_admission_refusal`] and are out of this slice's scope.
    pub fn record_rate_limited(&self, tenant: &TenantId) {
        self.by_tenant
            .entry(tenant.to_string())
            .or_default()
            .rate_limited
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record one budget-exceeded 429 for `tenant` — a per-key or workspace
    /// USD spend budget (GWY-43; BILL-01 A3 daily/weekly ceilings).
    pub fn record_budget_exceeded(&self, tenant: &TenantId) {
        self.by_tenant
            .entry(tenant.to_string())
            .or_default()
            .budget_exceeded
            .fetch_add(1, Ordering::Relaxed);
    }

    /// `(rate_limited, budget_exceeded)` process-lifetime totals for `tenant`
    /// (`(0, 0)` if the tenant has never been rejected).
    #[must_use]
    pub fn snapshot(&self, tenant: &TenantId) -> (u64, u64) {
        self.by_tenant
            .get(&tenant.to_string())
            .map(|e| {
                (
                    e.rate_limited.load(Ordering::Relaxed),
                    e.budget_exceeded.load(Ordering::Relaxed),
                )
            })
            .unwrap_or((0, 0))
    }

    /// RI-05 / M2 — record ONE admission refusal, for both surfaces at once:
    ///
    /// 1. the EXISTING process-lifetime `(tenant, reason-class)` counters above
    ///    (unchanged behaviour — `/v1/gateway/stats` reads them exactly as before);
    /// 2. the per-minute `(tenant, api_key_id, reason)` bucket this module adds,
    ///    which [`Self::roll_minute`] turns into one aggregate span per closed
    ///    bucket.
    ///
    /// Call from the three `admission.rs` refusal sites (`Step::RateLimit`,
    /// `Step::KeyBudget`, `Step::WorkspaceBudget`) — see that file's `grep -n
    /// rejection_metrics`. `api_key_id` is `claims.api_key_id()` verbatim: `None`
    /// for a JWT session, which is a real fact (`tracelane_api_key_id` absent),
    /// never smoothed into a sentinel.
    ///
    /// O(1), no allocation beyond what the two existing counter methods already
    /// pay (the `tenant.to_string()` map key) plus, on a genuinely NEW triple this
    /// minute, one more `String`/`DashMap`-entry allocation — bounded by
    /// [`MAX_LIVE_BUCKETS`], never by request volume (`.claude/rules/rust.md`,
    /// `crates/gateway/CLAUDE.md` hot-path discipline).
    pub(crate) fn record_admission_refusal(
        &self,
        tenant: &TenantId,
        api_key_id: Option<&str>,
        reason: RejectionReason,
        now: DateTime<Utc>,
    ) {
        // 1. Unchanged process-lifetime counters — same effect as calling
        // `record_rate_limited`/`record_budget_exceeded` directly.
        match reason {
            RejectionReason::RateLimited => self.record_rate_limited(tenant),
            RejectionReason::KeyBudgetExceeded | RejectionReason::WorkspaceBudgetExceeded => {
                self.record_budget_exceeded(tenant)
            }
            // OG-20: no process-lifetime counter of its own (the two above feed the
            // Gateway-ops live counters, which name throttling and budgets only); the
            // per-minute aggregate span below is where a policy refusal is recorded.
            RejectionReason::PolicyDenied => {}
        }

        // 2. The new per-minute bucket.
        let minute = now.timestamp().div_euclid(60);
        let probe = BucketKey {
            tenant: tenant.clone(),
            api_key_id: api_key_id.map(str::to_owned),
            reason,
            minute,
        };
        if let Some(counter) = self.buckets.get(&probe) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Not bucketed yet this minute. `len()` on a `DashMap` is an approximate,
        // racy read across shards — acceptable here because the cap is a
        // DoS-safety BOUND, not an exact invariant (a benign race can land a
        // handful of triples over 10,000; it cannot land millions).
        if self.buckets.len() >= MAX_LIVE_BUCKETS {
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::RejectionBucketCapReached,
            );
            return;
        }
        self.buckets
            .entry(probe)
            .or_insert_with(|| AtomicU32::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// RI-05 / M2 — close every bucket whose minute is STRICTLY BEFORE `now`'s
    /// minute, remove it from the live table, and return one `TracelaneSpan` per
    /// closed bucket. The bucket CURRENTLY being written (this minute) is left
    /// alone — closing it would let a late-arriving refusal in the last second of
    /// the minute land in a bucket that already rolled.
    ///
    /// Pure with respect to publishing (RI-05 spec §7 test note: "make the roll
    /// return the `Vec<TracelaneSpan>` it would publish and test that") — this
    /// function does no I/O; [`crate::rejection_metrics::spawn`] is the thin
    /// async wrapper that calls this on a tick and hands the result to
    /// `otlp_emit::spawn_publish`.
    pub(crate) fn roll_minute(&self, now: DateTime<Utc>) -> Vec<TracelaneSpan> {
        let current_minute = now.timestamp().div_euclid(60);
        let to_close: Vec<BucketKey> = self
            .buckets
            .iter()
            .filter(|entry| entry.key().minute < current_minute)
            .map(|entry| entry.key().clone())
            .collect();
        let mut spans = Vec::with_capacity(to_close.len());
        for key in to_close {
            if let Some((key, counter)) = self.buckets.remove(&key) {
                spans.push(build_rejection_span(&key, counter.load(Ordering::Relaxed)));
            }
        }
        spans
    }
}

/// Deterministic `(trace_id, span_id)` for one aggregate span, hashed from the
/// identity it aggregates: `(tenant, api_key_id, reason, minute)`.
///
/// **Why deterministic, not random (RI-05 build note):** E2 / RI-07 (B-443) keys
/// the JetStream `Nats-Msg-Id` on `tenant:trace:span`
/// (`crate::otlp_emit::msg_id_for`) for publish-side dedup. If this span's ids
/// were randomly generated, a gateway restart that re-emits an already-closed
/// minute (the bucket was live in memory, not yet rolled, when the process died)
/// would mint a NEW id and publish a DUPLICATE row rather than a deduped no-op.
/// With deterministic ids the restart's re-publish is BYTE-IDENTICAL in its
/// dedup key on two layers: the stream's 2-minute `Nats-Msg-Id` window catches a
/// near-term repeat, and (outside that window) ClickHouse's
/// `ReplacingMergeTree(ingested_at)` keyed on `(tenant_id, trace_id, span_id)`
/// (`infra/dev/clickhouse/schema.sql`) still collapses it on the next merge — so
/// "dedups instead of duplicating" holds regardless of how long after the
/// original minute the restart happens.
///
/// Length-prefixed framing (`lp(x) = u64_be(len) ‖ x`), same shape as
/// `guardrail::capability::def_hash`, so no field-boundary collision can make two
/// different triples hash the same id (e.g. `tenant="ab"` + `key="c"` colliding
/// with `tenant="a"` + `key="bc"`).
fn deterministic_ids(
    tenant: &TenantId,
    api_key_id: Option<&str>,
    reason: RejectionReason,
    minute: i64,
) -> (Uuid, Uuid) {
    let mut base = blake3::Hasher::new();
    for field in [
        tenant.as_uuid().to_string().as_bytes(),
        api_key_id.unwrap_or("").as_bytes(),
        reason.as_str().as_bytes(),
        minute.to_string().as_bytes(),
    ] {
        base.update(&(field.len() as u64).to_be_bytes());
        base.update(field);
    }

    let mut trace_hasher = base.clone();
    trace_hasher.update(b"trace");
    let trace_id = uuid_from_hash(trace_hasher.finalize());

    let mut span_hasher = base;
    span_hasher.update(b"span");
    let span_id = uuid_from_hash(span_hasher.finalize());

    (trace_id, span_id)
}

/// Take the first 16 bytes of a blake3 hash as a `Uuid`. Not a UUID version/variant
/// construction — just a stable 128-bit id derived from content, which is all a
/// span/trace id needs to be (`crates/shared/src/otlp/decode.rs`'s
/// `otlp_span_id_to_uuid` does the analogous thing for OTLP's raw byte ids).
fn uuid_from_hash(hash: blake3::Hash) -> Uuid {
    let bytes = hash.as_bytes();
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[..16]);
    Uuid::from_bytes(arr)
}

/// Build the ONE `tracelane.admission.rejected` span for a closed bucket.
///
/// `status` is deliberately `Unset`, never `Error` (RI-05 ruling G', spec §2.2):
/// `/slo`'s `countIf(status_code = 2)` must not move because an aggregate refusal
/// span exists. `start_time`/`end_time` bracket the UTC minute the refusals
/// happened in, not "now" — the minute IS the observation window.
fn build_rejection_span(key: &BucketKey, count: u32) -> TracelaneSpan {
    let start_time = DateTime::<Utc>::from_timestamp(key.minute * 60, 0).unwrap_or_else(Utc::now);
    let end_time = start_time + chrono::Duration::minutes(1);
    let (trace_id, span_id) = deterministic_ids(
        &key.tenant,
        key.api_key_id.as_deref(),
        key.reason,
        key.minute,
    );

    TracelaneSpan {
        span_id,
        trace_id,
        // A root of its own trace, deliberately — an aggregate refusal is not a
        // child of any request span (there IS no request span; that is the whole
        // reason this exists). RI-05 §9 Q2: it appears in `/traces` unfiltered,
        // which the spec calls the point ("a 429 is an agent action").
        parent_span_id: None,
        tenant_id: key.tenant.clone(),
        name: REJECTED_SPAN_NAME.to_string(),
        start_time,
        end_time: Some(end_time),
        attributes: SpanAttributes {
            tracelane_rejection_reason: Some(key.reason.as_str().to_string()),
            tracelane_rejection_count: Some(count),
            tracelane_api_key_id: key.api_key_id.clone(),
            ..Default::default()
        },
        status: SpanStatus {
            code: SpanStatusCode::Unset,
            message: None,
        },
    }
}

/// How often the minute roll ticks. Matches the bucket granularity exactly —
/// ticking faster would just re-check with nothing new to close; slower would
/// delay when a closed minute's span reaches ClickHouse without changing
/// correctness.
const ROLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Spawn the background task that rolls closed minutes into spans and publishes
/// them through the EXISTING `otlp_emit` publish path (ingest stays the sole
/// ClickHouse writer — RI-05 §2.2). Call once, where the registry is constructed
/// (`server.rs`, alongside the other `AppState`-adjacent spawns).
///
/// Fail-open by construction, matching every other best-effort span publish in
/// this crate: with no NATS client the span is counted
/// (`otlp_emit::note_span_dropped_no_nats`) rather than silently discarded, and a
/// publish failure is counted by `otlp_emit::spawn_publish` itself. Losing an
/// aggregate span loses a COUNT, never a customer-facing signal — the
/// process-lifetime counters `/v1/gateway/stats` reads are unaffected either way.
pub fn spawn(registry: Arc<RejectionRegistry>, nats: Option<Arc<async_nats::Client>>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ROLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for span in registry.roll_minute(Utc::now()) {
                #[cfg(test)]
                crate::otlp_emit::test_sink::record(&span);
                match nats.as_ref() {
                    Some(client) => {
                        crate::otlp_emit::spawn_publish(
                            Arc::clone(client),
                            span,
                            "admission_rejected",
                        );
                    }
                    None => {
                        crate::otlp_emit::note_span_dropped_no_nats();
                    }
                }
            }
        }
    });
}

// `registry()` — the process-global `LazyLock` — was DELETED 2026-09-12 (B-386 b).
// The one instance now lives on `AppState::rejection_metrics` (constructed in
// `server::run`, built fresh by `handler_harness::test_state`) and is shared
// with `trace_reads::TraceReadState` by `Arc`, so the hot path records on the
// same counters the `/v1/gateway` stats surface reads.

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn tenant(n: u128) -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(n))
    }

    /// A fixed UTC instant so every test's minute arithmetic is exact and the
    /// suite never depends on when it happens to run.
    fn at(minute: i64, second: u32) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(minute * 60 + i64::from(second), 0)
            .expect("in-range test timestamp")
    }

    #[test]
    fn snapshot_is_zero_for_unseen_tenant() {
        let reg = RejectionRegistry::new();
        assert_eq!(reg.snapshot(&tenant(0xA1)), (0, 0));
    }

    #[test]
    fn counters_advance_independently_per_reason() {
        let reg = RejectionRegistry::new();
        let t = tenant(0xB2);
        reg.record_rate_limited(&t);
        reg.record_rate_limited(&t);
        reg.record_budget_exceeded(&t);
        assert_eq!(reg.snapshot(&t), (2, 1));
    }

    #[test]
    fn counters_are_isolated_per_tenant() {
        let reg = RejectionRegistry::new();
        let a = tenant(1);
        let b = tenant(2);
        reg.record_rate_limited(&a);
        reg.record_budget_exceeded(&b);
        // Tenant a sees only its own rate-limit; b only its own budget reject.
        assert_eq!(reg.snapshot(&a), (1, 0));
        assert_eq!(reg.snapshot(&b), (0, 1));
    }

    // ── RI-05 / M2 — the aggregated admission-refusal record ──────────────────

    /// (a) 200 refusals for one (tenant, key, reason) inside one minute → exactly
    /// ONE span with `tracelane_rejection_count == 200` on the roll, and ZERO
    /// spans before the roll.
    #[test]
    fn two_hundred_refusals_in_one_minute_roll_into_one_span_carrying_the_count() {
        let reg = RejectionRegistry::new();
        let t = tenant(0x200);
        let now = at(1_000_000, 5);
        for _ in 0..200 {
            reg.record_admission_refusal(
                &t,
                Some("11111111-1111-4111-8111-111111111111"),
                RejectionReason::RateLimited,
                now,
            );
        }

        // Still inside the same minute: nothing closed yet.
        assert!(
            reg.roll_minute(now).is_empty(),
            "a roll at the SAME minute the refusals happened in must not close it"
        );

        // The old process-lifetime counter moved too — RI-05 changes nothing there.
        assert_eq!(reg.snapshot(&t), (200, 0));

        // One minute later, the bucket closes.
        let spans = reg.roll_minute(at(1_000_001, 0));
        assert_eq!(
            spans.len(),
            1,
            "200 refusals for ONE triple in ONE minute must roll into exactly one span"
        );
        let span = &spans[0];
        assert_eq!(span.name, "tracelane.admission.rejected");
        assert_eq!(span.attributes.tracelane_rejection_count, Some(200));
        assert_eq!(
            span.attributes.tracelane_rejection_reason.as_deref(),
            Some("rate_limited")
        );
        assert_eq!(span.status.code, SpanStatusCode::Unset);

        // Rolling again produces nothing more — the bucket was REMOVED, not merely read.
        assert!(reg.roll_minute(at(1_000_002, 0)).is_empty());
    }

    /// (b) two reasons for the same (tenant, key) → two spans.
    #[test]
    fn two_reasons_for_the_same_tenant_and_key_roll_into_two_spans() {
        let reg = RejectionRegistry::new();
        let t = tenant(0x201);
        let now = at(2_000_000, 10);
        let key = Some("22222222-2222-4222-8222-222222222222");

        reg.record_admission_refusal(&t, key, RejectionReason::RateLimited, now);
        reg.record_admission_refusal(&t, key, RejectionReason::KeyBudgetExceeded, now);
        reg.record_admission_refusal(&t, key, RejectionReason::KeyBudgetExceeded, now);

        let mut spans = reg.roll_minute(at(2_000_001, 0));
        assert_eq!(spans.len(), 2, "one span per DISTINCT reason");
        spans.sort_by(|a, b| {
            a.attributes
                .tracelane_rejection_reason
                .cmp(&b.attributes.tracelane_rejection_reason)
        });
        assert_eq!(
            spans[0].attributes.tracelane_rejection_reason.as_deref(),
            Some("key_budget_exceeded")
        );
        assert_eq!(spans[0].attributes.tracelane_rejection_count, Some(2));
        assert_eq!(
            spans[1].attributes.tracelane_rejection_reason.as_deref(),
            Some("rate_limited")
        );
        assert_eq!(spans[1].attributes.tracelane_rejection_count, Some(1));
    }

    /// (c) a JWT session (no key) → `tracelane_api_key_id` absent, never a
    /// sentinel like `""` or `"none"`.
    #[test]
    fn a_jwt_session_with_no_api_key_leaves_the_attribute_absent() {
        let reg = RejectionRegistry::new();
        let t = tenant(0x202);
        let now = at(3_000_000, 0);
        reg.record_admission_refusal(&t, None, RejectionReason::WorkspaceBudgetExceeded, now);

        let spans = reg.roll_minute(at(3_000_001, 0));
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].attributes.tracelane_api_key_id, None);
        assert_eq!(
            spans[0].tenant_id, t,
            "the refused tenant's own id, not another's"
        );
    }

    /// (d) the deterministic ids: the SAME triple+minute yields the SAME
    /// span_id/trace_id twice — the property a gateway restart re-emitting an
    /// already-closed minute relies on for NATS + ClickHouse dedup.
    #[test]
    fn the_same_triple_and_minute_always_hashes_to_the_same_span_and_trace_id() {
        let t = tenant(0x203);
        let (trace_a, span_a) = deterministic_ids(
            &t,
            Some("33333333-3333-4333-8333-333333333333"),
            RejectionReason::RateLimited,
            4_000_000,
        );
        let (trace_b, span_b) = deterministic_ids(
            &t,
            Some("33333333-3333-4333-8333-333333333333"),
            RejectionReason::RateLimited,
            4_000_000,
        );
        assert_eq!(trace_a, trace_b, "same identity ⇒ same trace_id, always");
        assert_eq!(span_a, span_b, "same identity ⇒ same span_id, always");
        assert_ne!(
            trace_a, span_a,
            "the trace_id and span_id of the SAME span must still differ"
        );

        // A different minute (a different observation window) must hash differently —
        // otherwise two distinct rolled spans would collide.
        let (trace_c, span_c) = deterministic_ids(
            &t,
            Some("33333333-3333-4333-8333-333333333333"),
            RejectionReason::RateLimited,
            4_000_001,
        );
        assert_ne!(trace_a, trace_c);
        assert_ne!(span_a, span_c);

        // A different reason, same everything else, must also hash differently —
        // this is the field-boundary-collision guard the length-prefixed framing buys.
        let (trace_d, _) = deterministic_ids(
            &t,
            Some("33333333-3333-4333-8333-333333333333"),
            RejectionReason::KeyBudgetExceeded,
            4_000_000,
        );
        assert_ne!(trace_a, trace_d);
    }

    /// Full round trip through `roll_minute` (not just `deterministic_ids`
    /// directly): re-recording the identical triple+minute AFTER a roll and
    /// rolling again reproduces the exact same ids — the shape a restart hits.
    #[test]
    fn a_re_recorded_identical_minute_reproduces_the_same_span_after_a_second_roll() {
        let reg = RejectionRegistry::new();
        let t = tenant(0x204);
        let now = at(5_000_000, 0);
        let key = Some("44444444-4444-4444-8444-444444444444");

        reg.record_admission_refusal(&t, key, RejectionReason::RateLimited, now);
        let first = reg.roll_minute(at(5_000_001, 0));
        assert_eq!(first.len(), 1);

        // Simulate a restart re-emitting the SAME already-closed minute (e.g. the
        // registry was rebuilt fresh and the caller re-derives it from a durable
        // source outside this test's scope) — recording against the SAME `now`
        // again must reproduce identical ids on its own roll.
        reg.record_admission_refusal(&t, key, RejectionReason::RateLimited, now);
        let second = reg.roll_minute(at(5_000_001, 0));
        assert_eq!(second.len(), 1);

        assert_eq!(first[0].trace_id, second[0].trace_id);
        assert_eq!(first[0].span_id, second[0].span_id);
    }

    /// (e) the cap: the (cap+1)th DISTINCT triple in one minute is counted on the
    /// degradation kind and not stored — it never appears in the roll.
    #[test]
    fn the_cap_plus_one_distinct_triple_is_counted_on_the_degradation_kind_and_dropped() {
        let reg = RejectionRegistry::new();
        let now = at(6_000_000, 0);
        let before = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::RejectionBucketCapReached,
        );

        // Fill the table to the cap with MAX_LIVE_BUCKETS distinct tenants (each a
        // distinct triple, since tenant is part of the key).
        for i in 0..MAX_LIVE_BUCKETS {
            let t = tenant(0x600_0000 + i as u128);
            reg.record_admission_refusal(&t, None, RejectionReason::RateLimited, now);
        }
        assert_eq!(reg.buckets.len(), MAX_LIVE_BUCKETS);

        // The cap+1th DISTINCT triple must be refused a bucket.
        let overflow_tenant = tenant(0x700_0000);
        reg.record_admission_refusal(&overflow_tenant, None, RejectionReason::RateLimited, now);
        assert_eq!(
            reg.buckets.len(),
            MAX_LIVE_BUCKETS,
            "the table must not grow past the cap"
        );
        let after = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::RejectionBucketCapReached,
        );
        assert!(
            after > before,
            "the cap-hit must be counted on its degradation kind"
        );

        // And the overflow tenant's refusal never gets its own aggregate span —
        // its process-lifetime counter still moved (unchanged behaviour), but no
        // triple was bucketed for it.
        let spans = reg.roll_minute(at(6_000_001, 0));
        assert_eq!(spans.len(), MAX_LIVE_BUCKETS);
        assert_eq!(reg.snapshot(&overflow_tenant), (1, 0));
        assert!(
            !spans.iter().any(|s| s.tenant_id == overflow_tenant),
            "the overflow tenant must not have an aggregate span"
        );
    }

    /// An in-progress (current-minute) bucket must never be evicted early by the
    /// cap check racing with an ordinary insert — i.e. the cap only blocks NEW
    /// triples, never bumps to an existing one.
    #[test]
    fn an_existing_triple_keeps_incrementing_even_once_the_table_is_at_the_cap() {
        let reg = RejectionRegistry::new();
        let now = at(7_000_000, 0);
        let t = tenant(0x800_0000);
        reg.record_admission_refusal(&t, None, RejectionReason::RateLimited, now);

        // Fill the rest of the table to the cap with OTHER triples.
        for i in 1..MAX_LIVE_BUCKETS {
            let other = tenant(0x800_0000 + i as u128);
            reg.record_admission_refusal(&other, None, RejectionReason::RateLimited, now);
        }
        assert_eq!(reg.buckets.len(), MAX_LIVE_BUCKETS);

        // The FIRST triple (already bucketed) must still accept more refusals.
        reg.record_admission_refusal(&t, None, RejectionReason::RateLimited, now);
        reg.record_admission_refusal(&t, None, RejectionReason::RateLimited, now);

        let spans = reg.roll_minute(at(7_000_001, 0));
        let mine = spans
            .iter()
            .find(|s| s.tenant_id == t)
            .expect("the pre-existing triple must still roll into a span");
        assert_eq!(mine.attributes.tracelane_rejection_count, Some(3));
    }
}
