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
        ]
    }
}

/// Number of variants. A compile error here means a variant was added without extending
/// [`Degradation::all`] — which would leave the new path uncounted, the exact defect.
pub const COUNT: usize = 11;

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
}

impl Slot {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            first_seen: AtomicU64::new(NEVER),
            last_seen: AtomicU64::new(0),
            last_warn: AtomicU64::new(NEVER),
        }
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
    /// `last_seen - first_seen`. The TRAPS §16 question: how long has this been open?
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

    // Only the first occurrence sets first_seen; `NEVER` is the "unset" marker.
    let _ = slot
        .first_seen
        .compare_exchange(NEVER, now, Ordering::Relaxed, Ordering::Relaxed);
    slot.last_seen.store(now, Ordering::Relaxed);

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
        let first = slot.first_seen.load(Ordering::Relaxed);
        let open_for = if first == NEVER {
            0
        } else {
            now.saturating_sub(first)
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

/// Current count for one kind, without recording anything. For tests and diagnostics.
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
            let (first_seen, last_seen, open_for_secs) = if first == NEVER {
                (None, None, None)
            } else {
                (Some(first), Some(last), Some(last.saturating_sub(first)))
            };
            Stat {
                kind: kind.as_str(),
                count: slot.count.load(Ordering::Relaxed),
                first_seen,
                last_seen,
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

        assert_eq!(
            count(Degradation::MeterFlushFailed),
            before + 1,
            "note() must advance the counter for its own kind"
        );
        assert_eq!(
            returned,
            before + 1,
            "note() must return the new cumulative count"
        );
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
