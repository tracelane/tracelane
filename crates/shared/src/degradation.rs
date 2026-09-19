//! One place that answers "what is degraded, and **for how long**".
//!
//! # Why this module exists
//!
//! A fail-open degradation is a deliberate choice to keep serving when a dependency
//! dies, and it is almost always right **for the duration it was designed for**. The
//! defect is that the duration is unbounded and *unmeasured*: nothing distinguishes
//! "degraded for 30 seconds" from "degraded for three weeks", so the second case looks
//! exactly like healthy operation. `docs/reference/TRAPS.md` §16.
//!
//! Earned by — ingest's tenant-config resolver faulted continuously for **three
//! weeks** after a migration, silently promoting every tenant to `Full` capture,
//! enforcing quota against a fallback cap, and leaving the `force_tail` kill-switch
//! inert. `fault_keep_all` is correct for a blip. Nothing said it had stopped being one.
//!
//!  inventoried five such paths in this system. **One had a counter; four had no
//! instrument at all**, and every one of them was found by a person looking directly at
//! it rather than by a signal.
//!
//! # Why not a metrics crate
//!
//! There is no metrics library in this workspace and no `/metrics` endpoint. Adding one
//! is not the cheap part — the cheap part is being *read*. This repo already contains
//! **five** hand-rolled counter registries and **four of them have no reader at all**
//! (`guardrail::render_prometheus` has zero non-test callers; `entitlement_cache` and
//! `circuit_breaker` snapshots are never called). A sixth orphan would be worse than
//! nothing, because its existence would imply coverage.
//!
//! So this module deliberately hangs off the path that already works end to end:
//!
//! **A stable log marker.** Every degradation logs `TRACELANE_DEGRADED` with a `kind`
//! field and an `open_for_secs`. The on-node watchdog (`scripts/ops/tlane-status.sh`)
//! already greps container logs for exactly this shape — it is how PromptGuard
//! fail-open surfaces today — so ONE grep covers all five kinds and alerting needs no
//! new infrastructure, no new endpoint, and no new dependency.
//!
//! # Why NOT `/v1/gateway/stats`
//!
//! That is the codebase's only live declare→increment→expose path, so it was the
//! obvious home — and it is the wrong one. It is **tenant-facing and per-tenant**
//! (`rejection_metrics` records against a `tenant_id`), while these counters are
//! process-global. Publishing them there would tell every customer when our billing
//! meter is failing, when detection is offline, and how long each has been broken.
//! An operational signal does not belong on a customer's response body.
//!
//! [`snapshot`] therefore exists for the operator surface and for tests, and has no
//! tenant-facing caller by design.
//!
//! # The duration question
//!
//! A count alone cannot distinguish a blip from an outage, so each kind carries
//! `first_seen` and `last_seen` unix-seconds. `open_for_secs()` is the number TRAPS §16
//! actually asks for: *how long has this been open?*
//!
//! # Cost
//!
//! A fixed enum indexed into a `static` array — no map, no string keys, no allocation.
//! `note()` is a `fetch_add` plus two relaxed stores on the hot path. Warnings are
//! rate-limited per kind so a 5K-RPS gateway cannot flood its own logs while still
//! surfacing total failure loudly.

use std::sync::atomic::{AtomicU64, Ordering};

/// Every fail-open path that is allowed to keep serving while a dependency is down.
///
/// Adding a variant is the point: `.claude/rules` requires a new fail-open path to ship
/// with a counter and a way to ask how long it has been open, or it is not fail-open —
/// it is undetectable failure with a comment explaining why that is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Degradation {
    /// `NATS_URL` unset or unreachable ⇒ span publish disabled, **every span dropped**,
    /// gateway still returns 200. On an observability product this is the worst-case
    /// silent failure. `crates/gateway/src/server.rs:348-369`.
    SpansDroppedNoNats = 0,
    /// A NATS publish returned an error on the span path. Distinct from the above: the
    /// client exists, the write failed. Was `warn!`-only at six call sites, counted
    /// nowhere.
    SpanPublishFailed = 1,
    /// Ingest's tenant-config resolve faulted ⇒ `fault_keep_all` (Full capture, fallback
    /// quota). The resolver returns `TenantConfig`, not `Result`, so the fault is
    /// structurally invisible to callers. **This is.**
    /// `crates/ingest/src/tenant_config.rs:261-279`.
    TenantConfigFault = 2,
    /// A Polar meter event failed to post. The flush still reports success upward, so
    /// billing usage can silently stop reaching Polar — which is exactly what happened:
    /// no meter event has ever reached production.
    /// `crates/gateway/src/billing/meter.rs:115-136`.
    MeterFlushFailed = 3,
    /// A predictive/detection predictor errored or was never initialised; the stack
    /// continues and the request is allowed. `crates/gateway/src/predictive/mod.rs`.
    PredictorError = 4,
    /// The ALERT EVALUATOR could not compute a rule's metric and skipped the rule
    /// (`alerts/checker.rs:129-131`, `continue`). **This is inside the alerting
    /// engine itself**: "I cannot see" is treated as "nothing to do", so a customer's
    /// alert silently stops evaluating while the UI still shows it as enabled. It had
    /// no instrument at all, which is the same defect the registry exists to close —
    /// the thing that is supposed to tell you something is broken, failing quietly.
    AlertEvalSkipped = 5,
    /// The post-anchor `ALTER TABLE audit_log UPDATE` that writes back the Ed25519
    /// `signature`/`signing_pubkey` (`audit.rs:1159`) or the `rekor_entry_id`
    /// (`audit.rs:1129`) FAILED. Both run in a detached `tokio::spawn` and their
    /// `Err` arm was a bare `warn!`, so the append path reports success, `/health`
    /// stays green, the hash chain stays intact — and the rows are left **unsigned
    /// and unanchored forever**. Nothing retries them.
    ///
    /// **This lands on the wedge.** "Tamper-evident, third-party verifiable offline"
    /// is the differentiated claim, and this is the one failure that removes it
    /// while every other signal says the ledger is fine. Found 2026-08-14 designing
    /// R11, where an under-grant on the gateway's ClickHouse user would have
    /// triggered it silently — but it is a standing defect independent of R11:
    /// NATS pressure, a ClickHouse hiccup or any transient error does the same.
    AuditBackfillFailed = 6,
    /// R21 — the anchor AGE SWEEP could not read a tenant's oldest un-anchored row and
    /// **skipped that tenant** (`audit.rs`, `flush_aged_batches`). Same shape as
    /// [`Self::AlertEvalSkipped`]: "I cannot see" silently becomes "nothing to do".
    ///
    /// **Earned before it ever shipped.** The sweep's first implementation bound the
    /// STRING `"-1"` as its no-lower-bound sentinel; ClickHouse answers
    /// `Code 53 TYPE_MISMATCH`, the `Err` arm was a bare `warn!` + `continue`, and so
    /// **every tenant that had never anchored was skipped — the entire population the
    /// sweep exists for.** The query is fixed; this counter is what makes the next
    /// instance loud instead of invisible, and the next instance is expected: R11
    /// re-grants the gateway's ClickHouse user, and an under-grant lands exactly here.
    AuditAgeSweepSkipped = 7,
    /// The GWY-24 semantic cache could not consult itself — the embedding
    /// provider was unreachable, or the ClickHouse scan failed. The request is
    /// served normally by the provider, so nothing breaks and NOTHING SHOWS.
    ///
    /// That silence is exactly why it is counted. A cache is a fault-tolerance
    /// path and fails OPEN by design, which means a permanently broken embedder
    /// looks identical to a cache with no hits: the bill stays high, latency
    /// stays normal, and no error is ever raised. `open_for_secs` is the only
    /// thing that can answer "how long has this been degraded?"
    SemanticCacheUnavailable = 8,
    /// An online-eval judge call failed — provider error, unresolvable rubric,
    /// or a ClickHouse write that did not land. **The customer's request already
    /// succeeded**; what failed is the scoring of a sample of it. Fail-open by
    /// construction (`online_eval::spawn` awaits nothing), so without this
    /// counter a workspace could stop being scored entirely and nothing would
    /// say so — the `/sessions` shape, on a paid feature.
    OnlineEvalJudgeFailed = 9,
    /// An online-eval judge call was REFUSED because the policy's monthly judge
    /// budget is spent. Not an error — the cap working — but it must be visible:
    /// a workspace that thinks it is scoring 1% of traffic and is scoring none
    /// has a bill-shaped surprise in the other direction, and silence here would
    /// be indistinguishable from "no traffic".
    OnlineEvalBudgetExceeded = 10,
    /// Ingest dropped a span because its trace passed the per-trace ceiling
    /// (`TRACELANE_MAX_SPANS_PER_TRACE` / `_BYTES_`). SRE register #54: this was
    /// the ONE drop path that logged at `debug!` only — counted in
    /// `per_trace_ceiling` for a `/metrics` nobody scrapes, invisible everywhere
    /// else. Routing it here gives it the `TRACELANE_DEGRADED` marker the
    /// watchdog reads and an `open_for_secs` a reader can act on.
    PerTraceCeilingDrop = 11,
    /// OBS-48 — a best-effort write on the PUBLIC share read path failed (the
    /// `view_count` increment or the cosmetic workspace-name read). The page
    /// still renders; the count is what tells an operator the DB is unhappy
    /// under an unauthenticated route, which is worth knowing about.
    TraceShareBestEffortWrite = 12,
    /// B-378 — the audit head-writer could not COMMIT a batch (Postgres or
    /// ClickHouse refused), so the events stay unacked in JetStream for
    /// redelivery. Nothing is lost while the stream has room; what this counts
    /// is how long the ledger has been falling behind, which the per-batch
    /// `error!` line that preceded it could not express.
    AuditAppendFailed = 13,
    /// B-378 — the audit JetStream backlog (`num_pending + num_ack_pending`)
    /// crossed the unhealthy threshold, or its reading went stale. The 1 GiB
    /// stream bound turns a long enough backlog into `503 audit_unavailable` on
    /// EVERY request; this is the signal that fires before that does.
    AuditBacklog = 14,
    /// B-386 — the single-instance advisory lock is NOT held: the connection
    /// that carried it dropped and re-acquisition has not succeeded, or another
    /// gateway holds it. While open, every per-process cap (rate limit, quota,
    /// budgets) may be enforced by more than one process against the same
    /// control plane — cap × instances.
    SingletonLockLost = 15,
    /// BILL-01 / ADR-076 A3 — the velocity breaker tripped: a key's daily
    /// output-token total exceeded `mean + sigma*stddev` of its own trailing
    /// window, and the key's tenant had prompt promotion FROZEN
    /// (`tenants.promotion_frozen_at`). Not a fault — the breaker working —
    /// but a founder-visible event, not a silent state change: a customer
    /// mid-rollout whose promote/rollback suddenly 423s needs a reason that
    /// outlives the single log line the trip itself emits.
    VelocityBreakerTripped = 16,
    /// BILL-01 / ADR-076 §2.3 — a `blobs` or `blob_refs` INSERT (ingest's
    /// content-addressed dedup, riding the same batch as the span flush)
    /// failed. The span itself still lands (this never blocks capture); what
    /// is lost is the ability to rehydrate that one attribute value on read,
    /// and — because the buffer is NOT retried the way the meter sink's is
    /// (the blob bytes came off a span already about to be flushed once) —
    /// silence here would look identical to "nothing this large was ever
    /// sent". `crates/ingest/src/clickhouse_writer.rs`.
    BlobStoreFailed = 17,
    /// BILL-01 / ADR-076 — the daily metering job (meters 2-5) failed a
    /// `GROUP BY` read or the `meter_gauges` write for a run. The gauges for
    /// that day stay stale (the usage route already reports "—, last
    /// computed …" for a stale gauge, so customers see it) but nothing else
    /// signals that the JOB itself is broken, as opposed to merely running
    /// late. `crates/gateway/src/billing/metering_job.rs`.
    MeteringJobFailed = 18,
    /// BILL-01 / ADR-076 — a Polar `/events/ingest` POST for one
    /// (tenant, meter, day) failed. Retried next run (idempotent on
    /// `external_id`), so nothing is lost permanently — but until the retry
    /// lands, that meter-day is simply absent from the customer's Polar
    /// invoice with no other signal that it was ever computed.
    /// `crates/gateway/src/billing/metering_job.rs`.
    PolarMeterEmissionFailed = 19,
    /// BILL-01 / ADR-076 — a usage-warning email (75%/90% of an included
    /// allowance) could not be sent because `RESEND_API_KEY` is unset. One
    /// warning per PROCESS (not per tenant, not per tick — the cause is
    /// process-wide config, so per-tenant noise would say nothing new): a
    /// tenant crossing 90% of their plan today looks, from outside, exactly
    /// like a tenant who was never warned.
    /// `crates/gateway/src/billing/email.rs`.
    UsageWarningEmailUnconfigured = 20,
    /// The daily metering job found a day without its marker row inside the
    /// lookback and recomputed it as of that day (founder, 2026-09-14, D). One
    /// WARN per occurrence; the count says how often 04:10 UTC is being missed.
    MeteringGaugeGapBackfilled = 21,
    /// B-427 — `GET /v1/audit/export` could not read the chain rows or the anchor
    /// records it was about to ship. Until 2026-09-19 a failed anchor read shipped
    /// the evidence pack with ZERO anchor lines and no log (`unwrap_or_default()`),
    /// and a failed page read mid-stream ended the NDJSON CLEANLY — a document that
    /// looks complete and, against the operator, proves nothing (DH-11: the Rekor
    /// anchor is the only guarantee a customer holds against us). The export now
    /// fails CLOSED — 500 before the body starts, an ABORTED transfer once it has —
    /// and this counts how often the wedge's export could not be produced.
    /// `crates/gateway/src/audit_export.rs`.
    AuditExportIncomplete = 22,
}

impl Degradation {
    /// Stable machine-readable name. Used as the `kind` log field and the
    /// `/v1/gateway/stats` key, so it is a wire contract — **renaming one breaks the
    /// watchdog grep and the dashboard key together.**
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpansDroppedNoNats => "spans_dropped_no_nats",
            Self::SpanPublishFailed => "span_publish_failed",
            Self::TenantConfigFault => "tenant_config_fault",
            Self::MeterFlushFailed => "meter_flush_failed",
            Self::PredictorError => "predictor_error",
            Self::AlertEvalSkipped => "alert_eval_skipped",
            Self::AuditBackfillFailed => "audit_backfill_failed",
            Self::AuditAgeSweepSkipped => "audit_age_sweep_skipped",
            Self::SemanticCacheUnavailable => "semantic_cache_unavailable",
            Self::OnlineEvalJudgeFailed => "online_eval_judge_failed",
            Self::OnlineEvalBudgetExceeded => "online_eval_budget_exceeded",
            Self::PerTraceCeilingDrop => "per_trace_ceiling_drop",
            Self::TraceShareBestEffortWrite => "trace_share_best_effort_write",
            Self::AuditAppendFailed => "audit_append_failed",
            Self::AuditBacklog => "audit_backlog",
            Self::SingletonLockLost => "singleton_lock_lost",
            Self::VelocityBreakerTripped => "velocity_breaker_tripped",
            Self::BlobStoreFailed => "blob_store_failed",
            Self::MeteringJobFailed => "metering_job_failed",
            Self::PolarMeterEmissionFailed => "polar_meter_emission_failed",
            Self::UsageWarningEmailUnconfigured => "email_unconfigured",
            Self::MeteringGaugeGapBackfilled => "metering_gauge_gap_backfilled",
            Self::AuditExportIncomplete => "audit_export_incomplete",
        }
    }

    /// One line an operator can act on, logged with the first occurrence.
    #[must_use]
    pub const fn consequence(self) -> &'static str {
        match self {
            Self::SpansDroppedNoNats => {
                "ALL spans are being dropped; the gateway still returns 200. Set NATS_URL \
                 and confirm NATS is reachable."
            }
            Self::SpanPublishFailed => {
                "spans are being lost on publish; NATS is connected but writes are failing."
            }
            Self::TenantConfigFault => {
                "every tenant is being served fallback capture policy and quota, and \
                 force_tail is inert. Check the control-plane pool."
            }
            Self::MeterFlushFailed => {
                "billing usage is NOT reaching Polar; the flush still reports success. \
                 Customers are being under-billed for as long as this is open."
            }
            Self::PredictorError => {
                "a detection predictor is not running; requests are being allowed past it."
            }
            Self::AlertEvalSkipped => {
                "an alert rule could not be evaluated and was SKIPPED — the customer's \
                 alert is silently not firing while the dashboard still shows it enabled."
            }
            Self::AuditBackfillFailed => {
                "audit rows are being left UNSIGNED and UNANCHORED — the ledger keeps \
                 appending and self-verify still passes on the hash chain, but those rows \
                 carry no Ed25519 signature and no Rekor entry, so they are NOT \
                 third-party verifiable. Nothing retries them. Check the gateway's \
                 ClickHouse ALTER grant and reachability."
            }
            Self::AuditAgeSweepSkipped => {
                "the 24h anchor age-sweep SKIPPED a tenant it could not read, so that \
                 tenant's rows stay unsigned and unanchored and nothing else will \
                 anchor them — a low-volume tenant never reaches the count threshold. \
                 Check the gateway's ClickHouse SELECT grant on audit_log and \
                 audit_anchor_records, and reachability."
            }
            Self::SemanticCacheUnavailable => {
                "the semantic cache is failing open — every request is going to the \
                 provider and the bill is as if the cache were off. Nothing errors, so \
                 this is invisible without this counter. Check the embedding provider \
                 credential and ClickHouse."
            }
            Self::OnlineEvalJudgeFailed => {
                "online-eval scoring is failing; customer requests are UNAFFECTED but a \
                 workspace that believes it is sampling is scoring nothing. Check the \
                 judge model's provider key and the ClickHouse write path."
            }
            Self::OnlineEvalBudgetExceeded => {
                "an online-eval policy has spent its monthly judge budget and scoring is \
                 paused for that workspace. This is the cap WORKING — raise the budget or \
                 lower the sample rate if the coverage is wanted."
            }
            Self::PerTraceCeilingDrop => {
                "spans past the per-trace ceiling (TRACELANE_MAX_SPANS_PER_TRACE / \
                 _BYTES_) are being DROPPED by ingest and the trace is truncated. Either \
                 a runaway agent loop or a ceiling set too low for a real workload; \
                 read the count and open_for_secs before raising it."
            }
            Self::TraceShareBestEffortWrite => {
                "a best-effort write on the public share page (view_count or workspace \
                 name) is failing; the page still renders. Check the control-plane pool."
            }
            Self::AuditAppendFailed => {
                "the audit head-writer cannot commit ledger batches (Postgres or \
                 ClickHouse refused); events are piling up unacked in JetStream. Requests \
                 still succeed until the 1 GiB stream bound, then EVERY request 503s. \
                 Check the control-plane pool and the ClickHouse audit_log insert."
            }
            Self::AuditBacklog => {
                "the audit JetStream backlog is past the unhealthy threshold or its reading \
                 is stale; the ledger is falling behind the gateway. Read \
                 /health.audit_backlog and the head-writer's own log."
            }
            Self::SingletonLockLost => {
                "the gateway's single-instance advisory lock is not held — a second gateway \
                 may be enforcing the same per-process caps against this control plane \
                 (cap × instances). Check for a duplicate container and the Postgres \
                 connection that carries the lock."
            }
            Self::VelocityBreakerTripped => {
                "an API key's output-token generation rate tripped the BILL-01 velocity \
                 breaker; its tenant's prompt promotion is now FROZEN (423 on promote/\
                 rollback) until a human clears it via DELETE /v1/billing/promotion-freeze. \
                 tenants.promotion_frozen_reason names the key and the numbers."
            }
            Self::BlobStoreFailed => {
                "a content-addressed blob or reference row failed to write; the span \
                 itself still landed, but that attribute value cannot be rehydrated on \
                 read. Check the gateway/ingest ClickHouse INSERT grant on blobs/blob_refs."
            }
            Self::MeteringJobFailed => {
                "the daily metering job (meters 2-5: hot window, series, query, cold) \
                 failed a read or write this run — those gauges are STALE for at least a \
                 day. Check the gateway's control-plane pool and ClickHouse reachability."
            }
            Self::PolarMeterEmissionFailed => {
                "a Polar usage event for one (tenant, meter, day) failed to post; it is \
                 retried next run (idempotent), but until then that meter-day is simply \
                 absent from the invoice. Check POLAR_ACCESS_TOKEN and Polar reachability."
            }
            Self::UsageWarningEmailUnconfigured => {
                "a usage-warning email (75%/90% of an included allowance) could not be \
                 sent — RESEND_API_KEY is unset. Customers crossing a threshold are not \
                 being notified; the in-app usage page still shows it."
            }
            Self::MeteringGaugeGapBackfilled => {
                "the daily metering job found a day without its own marker row inside \
                 the 7-day lookback and recomputed that day as of itself (spans carry \
                 ingested_at) — nothing was lost, but 04:10 UTC was MISSED at least once. \
                 A repeating count means the job is not running when it should."
            }
            Self::AuditExportIncomplete => {
                "an audit evidence-pack export could not read its chain rows or anchor \
                 records and was REFUSED (500) or ABORTED mid-transfer rather than shipped \
                 short. The customer got an error, not a pack missing its anchors. Check \
                 ClickHouse reachability and the gateway user's grants on audit_log / \
                 audit_anchor_records."
            }
        }
    }

    #[must_use]
    pub const fn all() -> [Degradation; COUNT] {
        [
            Self::SpansDroppedNoNats,
            Self::SpanPublishFailed,
            Self::TenantConfigFault,
            Self::MeterFlushFailed,
            Self::PredictorError,
            Self::AlertEvalSkipped,
            Self::AuditBackfillFailed,
            Self::AuditAgeSweepSkipped,
            Degradation::SemanticCacheUnavailable,
            Self::OnlineEvalJudgeFailed,
            Self::OnlineEvalBudgetExceeded,
            Self::PerTraceCeilingDrop,
            Self::TraceShareBestEffortWrite,
            Self::AuditAppendFailed,
            Self::AuditBacklog,
            Self::SingletonLockLost,
            Self::VelocityBreakerTripped,
            Self::BlobStoreFailed,
            Self::MeteringJobFailed,
            Self::PolarMeterEmissionFailed,
            Self::UsageWarningEmailUnconfigured,
            Self::MeteringGaugeGapBackfilled,
            Self::AuditExportIncomplete,
        ]
    }
}

/// Number of variants. A compile error here means a variant was added without extending
/// [`Degradation::all`] — which would leave the new path uncounted, the exact defect.
pub const COUNT: usize = 23;

/// `u64::MAX`, not `0`, so the very first occurrence always warns regardless of the wall
/// clock. A clock pinned near the Unix epoch would make a `0` sentinel indistinguishable
/// from "warned at t=0" and could silence the first warning — and loudness is the point.
/// Same reasoning as `otlp_emit::SPAN_DROP_WARN_NEVER`.
const NEVER: u64 = u64::MAX;

/// Minimum seconds between warnings for one kind.
const WARN_INTERVAL_SECS: u64 = 30;

struct Slot {
    count: AtomicU64,
    first_seen: AtomicU64,
    last_seen: AtomicU64,
    last_warn: AtomicU64,
    /// When the CURRENT episode opened (the first note after a resolve). `NEVER` until
    /// the first note. B-437.
    opened_at: AtomicU64,
    /// When the condition was last declared over. `NEVER` until the first resolve.
    resolved_at: AtomicU64,
    /// Ordering of the last note vs the last resolve, from the process-wide [`SEQ`]
    /// — wall-clock seconds cannot order a note and a resolve inside the same second.
    note_seq: AtomicU64,
    resolve_seq: AtomicU64,
}

/// Monotonic ticket for note/resolve ordering (B-437). Never wraps in practice.
static SEQ: AtomicU64 = AtomicU64::new(1);

impl Slot {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            first_seen: AtomicU64::new(NEVER),
            last_seen: AtomicU64::new(0),
            last_warn: AtomicU64::new(NEVER),
            opened_at: AtomicU64::new(NEVER),
            resolved_at: AtomicU64::new(NEVER),
            note_seq: AtomicU64::new(0),
            resolve_seq: AtomicU64::new(0),
        }
    }

    /// Open = has fired, and the last occurrence came AFTER the last resolve.
    fn is_open(&self) -> bool {
        self.note_seq.load(Ordering::Relaxed) > self.resolve_seq.load(Ordering::Relaxed)
    }
}

static SLOTS: [Slot; COUNT] = [
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
    Slot::new(),
];

/// A point-in-time view of one degradation, for `/v1/gateway/stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub kind: &'static str,
    pub count: u64,
    /// Unix seconds of the first occurrence in this process, or `None` if never.
    pub first_seen: Option<u64>,
    /// Unix seconds of the most recent occurrence, or `None` if never.
    pub last_seen: Option<u64>,
    /// B-437: is the condition STILL open — noted at least once and not [`resolve`]d
    /// since its last occurrence. Until 2026-09-19 a kind that had fired once read as
    /// open until the process restarted (`singleton_lock_lost` sat "open" on the
    /// status page for 33 h while the lock was held), which teaches readers to ignore
    /// the page — the B-419 class.
    pub open: bool,
    /// Unix seconds of the last [`resolve`], or `None` if never resolved.
    pub resolved_at: Option<u64>,
    /// Seconds the condition has been open in its CURRENT episode (now − the note that
    /// opened it), or `None` when it is not open. The TRAPS §16 question.
    pub open_for_secs: Option<u64>,
}

/// Record one occurrence of a degradation, returning the cumulative count for this kind.
///
/// Emits a **rate-limited** `warn!` carrying the stable `TRACELANE_DEGRADED` marker, the
/// `kind`, the running count, and how long the condition has been open. The first
/// occurrence always warns; subsequent ones at most once per [`WARN_INTERVAL_SECS`].
///
/// # Errors
/// None — infallible by construction. This is a **fault-tolerance** path: instrumenting
/// a degradation must never itself be able to fail the request it is describing.
pub fn note(kind: Degradation) -> u64 {
    let slot = &SLOTS[kind as usize];
    let count = slot.count.fetch_add(1, Ordering::Relaxed) + 1;
    let now = unix_now_secs();

    // B-437: a note that arrives while the kind is NOT open (never fired, or resolved
    // since its last occurrence) opens a new episode — that is the instant
    // `open_for_secs` counts from, not the first occurrence in the process lifetime.
    // Read BEFORE first_seen/last_seen move, or the first note reads as already open.
    let was_open = slot.is_open();
    // Only the first occurrence sets first_seen; `NEVER` is the "unset" marker.
    let _ = slot
        .first_seen
        .compare_exchange(NEVER, now, Ordering::Relaxed, Ordering::Relaxed);
    if !was_open {
        slot.opened_at.store(now, Ordering::Relaxed);
    }
    slot.last_seen.store(now, Ordering::Relaxed);
    slot.note_seq
        .store(SEQ.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);

    let last = slot.last_warn.load(Ordering::Relaxed);
    let due = last == NEVER || now.saturating_sub(last) >= WARN_INTERVAL_SECS;
    // The CAS lets exactly one racing thread win the warn, so concurrent occurrences
    // never double-log.
    if due
        && slot
            .last_warn
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let opened = slot.opened_at.load(Ordering::Relaxed);
        let open_for = if opened == NEVER {
            0
        } else {
            now.saturating_sub(opened)
        };
        tracing::warn!(
            marker = "TRACELANE_DEGRADED",
            kind = kind.as_str(),
            count,
            open_for_secs = open_for,
            "DEGRADED (fail-open active): {}",
            kind.consequence()
        );
    }
    count
}

/// B-437 — declare a degradation OVER: the condition it counts has provably ended (the
/// singleton lock was re-acquired, the metering job completed a run with no failure,
/// the audit backlog drained, an export succeeded). Returns `true` when the kind WAS
/// open and is now closed — that transition emits ONE `warn!` carrying the stable
/// `TRACELANE_RECOVERED` marker and how long the episode lasted (`logging.md`: *leave
/// it → one WARN*). Idempotent: resolving a kind that is not open records nothing and
/// logs nothing, so a caller may resolve on every healthy tick.
///
/// The count is NEVER reset — `count` stays the process-lifetime tally — only the
/// open/closed state moves. A later [`note`] re-opens the kind with a fresh
/// `opened_at`.
///
/// # Errors
/// None — infallible by construction, for the same reason as [`note`].
pub fn resolve(kind: Degradation) -> bool {
    let slot = &SLOTS[kind as usize];
    if !slot.is_open() {
        return false;
    }
    let now = unix_now_secs();
    let opened = slot.opened_at.load(Ordering::Relaxed);
    slot.resolved_at.store(now, Ordering::Relaxed);
    slot.resolve_seq
        .store(SEQ.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
    let lasted = if opened == NEVER {
        0
    } else {
        now.saturating_sub(opened)
    };
    tracing::warn!(
        marker = "TRACELANE_RECOVERED",
        kind = kind.as_str(),
        count = slot.count.load(Ordering::Relaxed),
        lasted_secs = lasted,
        "RECOVERED: the condition behind this degradation ended"
    );
    true
}

/// Is `kind` currently open? (B-437; see [`resolve`].)
#[must_use]
pub fn is_open(kind: Degradation) -> bool {
    SLOTS[kind as usize].is_open()
}

/// Current count for one kind, without recording anything. For tests and diagnostics.
///
/// **Test contract — the counter is process-global and monotonic.** Every test in a
/// binary shares one slot per kind, and tests run in parallel, so a test may only
/// assert that ITS occurrence landed (`count(kind) > before`), never an exact delta
/// (`== before + 1`, `after - before == 2`): any other test that drives the same kind
/// through its own path lands between the two reads. Four red gates said so before
/// it became a guard — `health_publishes_prompt_guard_fail_opens` (2026-09-06),
/// `spawn_publish_with_no_runtime…` (CI 34686533037), then the ceiling and FT-05 tests
/// together (2026-09-16). "Exactly N" belongs on a test-owned observable (the value
/// `note` returns, an in-flight figure, a loop bound), and a site that must stay exact
/// writes its reason on an `exact-delta-ok:` line for
/// `scripts/ci/check-degradation-count-assertions.py`.
#[must_use]
pub fn count(kind: Degradation) -> u64 {
    SLOTS[kind as usize].count.load(Ordering::Relaxed)
}

/// Every degradation, including the ones that have never fired.
///
/// Zeros are returned deliberately: a kind absent from the output is indistinguishable
/// from a kind that is not instrumented, and that ambiguity is the whole defect class
/// this module exists to close.
#[must_use]
pub fn snapshot() -> Vec<Stat> {
    Degradation::all()
        .into_iter()
        .map(|kind| {
            let slot = &SLOTS[kind as usize];
            let first = slot.first_seen.load(Ordering::Relaxed);
            let last = slot.last_seen.load(Ordering::Relaxed);
            let resolved = slot.resolved_at.load(Ordering::Relaxed);
            let opened = slot.opened_at.load(Ordering::Relaxed);
            let open = slot.is_open();
            let (first_seen, last_seen) = if first == NEVER {
                (None, None)
            } else {
                (Some(first), Some(last))
            };
            let open_for_secs = if open && opened != NEVER {
                Some(unix_now_secs().saturating_sub(opened))
            } else {
                None
            };
            Stat {
                kind: kind.as_str(),
                count: slot.count.load(Ordering::Relaxed),
                first_seen,
                last_seen,
                open,
                resolved_at: if resolved == NEVER {
                    None
                } else {
                    Some(resolved)
                },
                open_for_secs,
            }
        })
        .collect()
}

/// Wall-clock seconds since the Unix epoch, saturating to 0 on a pre-epoch clock. Used
/// only for the rate-limiter gate and the duration report, never in an assertion.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The counters are process-global, so tests must not assert absolute values —
    // another test (or a parallel one) may have incremented the same kind. Every
    // assertion below is a DELTA, which is what the requirement actually needs:
    // "drive the degradation and assert the counter moved".

    #[test]
    fn note_advances_the_counter_for_that_kind_only() {
        let before = count(Degradation::MeterFlushFailed);
        let other_before = count(Degradation::PredictorError);

        let returned = note(Degradation::MeterFlushFailed);

        // exact-delta-ok: this is the unit test of `note` itself, and it is the ONLY
        // noter of MeterFlushFailed and PredictorError in the shared test binary
        // (`grep -n 'note(Degradation::' crates/shared/src`); exactness is the property.
        assert_eq!(
            count(Degradation::MeterFlushFailed),
            before + 1,
            "note() must advance the counter for its own kind"
        );
        // exact-delta-ok: same single-noter argument as the assertion above.
        assert_eq!(
            returned,
            before + 1,
            "note() must return the new cumulative count"
        );
        // exact-delta-ok: same single-noter argument as the assertion above.
        assert_eq!(
            count(Degradation::PredictorError),
            other_before,
            "note() must not touch a different kind's counter"
        );
    }

    #[test]
    fn snapshot_reports_every_kind_even_when_never_fired() {
        let snap = snapshot();
        assert_eq!(
            snap.len(),
            COUNT,
            "a kind missing from the snapshot is indistinguishable from one that is \
             not instrumented — the defect this module closes"
        );
        for kind in Degradation::all() {
            assert!(
                snap.iter().any(|s| s.kind == kind.as_str()),
                "{} missing from snapshot",
                kind.as_str()
            );
        }
    }

    #[test]
    fn duration_is_reported_once_a_kind_has_fired() {
        note(Degradation::SpanPublishFailed);
        let snap = snapshot();
        let stat = snap
            .iter()
            .find(|s| s.kind == "span_publish_failed")
            .expect("kind present");
        assert!(stat.count >= 1);
        assert!(
            stat.first_seen.is_some() && stat.last_seen.is_some(),
            "a fired degradation must carry first/last seen"
        );
        assert!(
            stat.open_for_secs.is_some(),
            "open_for_secs is the TRAPS §16 question — how long has this been open"
        );
    }

    /// B-437: a kind that fired and was RESOLVED is not open; a new note re-opens it
    /// with a fresh episode; resolving a closed kind is a silent no-op. Uses a kind no
    /// other test in this binary drives (`TraceShareBestEffortWrite`), and `>`
    /// comparisons on the process-global count (B-423).
    #[test]
    fn resolve_closes_an_open_kind_and_a_new_note_reopens_it() {
        let kind = Degradation::TraceShareBestEffortWrite;
        let before = count(kind);
        note(kind);
        assert!(is_open(kind), "a noted kind is open");
        let stat = snapshot()
            .into_iter()
            .find(|s| s.kind == kind.as_str())
            .unwrap();
        assert!(stat.open && stat.open_for_secs.is_some());

        assert!(
            resolve(kind),
            "resolving an open kind reports the transition"
        );
        assert!(!is_open(kind), "a resolved kind is not open");
        let stat = snapshot()
            .into_iter()
            .find(|s| s.kind == kind.as_str())
            .unwrap();
        assert!(!stat.open, "snapshot must say closed");
        assert!(
            stat.open_for_secs.is_none(),
            "nothing is open, so no duration"
        );
        assert!(stat.resolved_at.is_some());
        assert!(
            stat.count > before,
            "the count is history and is never reset"
        );

        assert!(!resolve(kind), "resolving a closed kind is a no-op");

        note(kind);
        assert!(is_open(kind), "a note after a resolve re-opens the kind");
        let stat = snapshot()
            .into_iter()
            .find(|s| s.kind == kind.as_str())
            .unwrap();
        assert!(stat.open, "the new episode is open");
    }

    #[test]
    fn a_kind_that_never_fired_is_not_open_and_cannot_be_resolved() {
        // `PerTraceCeilingDrop` is an ingest-side kind; nothing in this binary notes it.
        let kind = Degradation::PerTraceCeilingDrop;
        if count(kind) == 0 {
            assert!(!is_open(kind));
            assert!(!resolve(kind));
        }
    }

    #[test]
    fn names_are_stable_unique_and_wire_safe() {
        // These strings are a wire contract: the watchdog greps them and the dashboard
        // keys on them. A duplicate would silently merge two degradations into one.
        let names: Vec<&str> = Degradation::all().iter().map(|k| k.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "degradation names must be unique"
        );
        for n in &names {
            assert!(
                !n.is_empty()
                    && n.chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "{n} must be a stable snake_case identifier"
            );
        }
    }

    #[test]
    fn every_variant_is_in_all_and_indexes_its_own_slot() {
        // Guards the `repr(usize)` ↔ SLOTS indexing. If a variant were added without
        // extending SLOTS or all(), some path would silently share another's counter.
        assert_eq!(Degradation::all().len(), COUNT);
        assert_eq!(SLOTS.len(), COUNT);
        for (i, kind) in Degradation::all().into_iter().enumerate() {
            assert_eq!(kind as usize, i, "{} indexes the wrong slot", kind.as_str());
        }
    }
}
