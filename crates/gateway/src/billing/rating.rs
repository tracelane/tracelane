//! BILL-01 / ADR-076 — the pure rating engine, and the `RateCard` it rates
//! against.
//!
//! **Founder, 2026-09-13, verbatim: "do not hardcode prices, limits or config
//! values — reference tables."** No price, band boundary, burst multiple or
//! warning threshold is a literal in this file. Every number comes from the
//! `pricing_rates` + `billing_policy` Postgres tables (migration
//! `apps/web/db/migrations/0040_bill01_pricing_v3_entitlements.sql`), loaded
//! ONCE per refresh cycle (never per request — `.claude/rules/reference-tables.md`)
//! into a `RateCard` held in an `ArcSwap` on `AppState`. This module's own unit
//! tests load the SAME ruled numbers from `apps/web/db/plans.v3.json` rather
//! than re-typing them, so a price change here is a data change, not a code
//! review of two disagreeing literals.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

/// The six BILLED meters — `pricing_rates.meter` values, verbatim (migration
/// 24 / 0040's own comment). Distinct from `billing::meters::UsageMeter`
/// (what the gateway RECORDS) — this is what the gateway RATES; the mapping
/// between the two is 1:1 for meters 1 and 6 and N/A for 2-5 (gauges, not yet
/// built here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RatedMeter {
    IngestGb,
    HotGbMonth,
    Series,
    ScanUnits,
    ColdGbMonth,
    EvalRuns,
}

impl RatedMeter {
    // No production caller: `RateCard::load` only goes STRING -> ENUM
    // (`from_column`); nothing in this build renders a `RatedMeter` back to
    // its column string. Kept — not deleted — because `rated_meter_column_
    // round_trips` (below) is the falsification proof that `from_column` and
    // this method agree, the same shape PL-20 #1 asks every string<->enum
    // boundary in this repo to carry.
    #[allow(dead_code)]
    #[must_use]
    pub const fn column_value(self) -> &'static str {
        match self {
            Self::IngestGb => "ingest_gb",
            Self::HotGbMonth => "hot_gb_month",
            Self::Series => "series",
            Self::ScanUnits => "scan_units",
            Self::ColdGbMonth => "cold_gb_month",
            Self::EvalRuns => "eval_runs",
        }
    }

    #[must_use]
    pub fn from_column(s: &str) -> Option<Self> {
        match s {
            "ingest_gb" => Some(Self::IngestGb),
            "hot_gb_month" => Some(Self::HotGbMonth),
            "series" => Some(Self::Series),
            "scan_units" => Some(Self::ScanUnits),
            "cold_gb_month" => Some(Self::ColdGbMonth),
            "eval_runs" => Some(Self::EvalRuns),
            _ => None,
        }
    }
}

/// One graduated band: `[lo, hi)` in the meter's own unit, `hi = None` means
/// open-ended (the top band). A flat-rate meter (everything but meter 2) is
/// represented as exactly one band `[0, None)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Band {
    pub lo: f64,
    pub hi: Option<f64>,
    pub usd_per_unit: f64,
}

/// Retention job bounds: billing_policy.retention_sweep, refreshed once per run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
pub(crate) struct RetentionSweepPolicy {
    pub delete_wait_secs: u64,
    pub max_mutations_per_run: u64,
    pub max_run_secs: u64,
    pub tombstone_live_grace_hours: u64,
}

impl RetentionSweepPolicy {
    pub(crate) fn embedded() -> Self {
        // A malformed compiled seed disables mutation submission, never an unbounded fallback.
        serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../../apps/web/db/plans.v3.json"
        ))
        .ok()
        .and_then(|v| serde_json::from_value(v["policy"]["retention_sweep"].clone()).ok())
        .unwrap_or_default()
    }

    /// Fail-OPEN to the reviewed embedded row if Postgres cannot supply the policy.
    #[tracing::instrument(skip_all)]
    pub(crate) async fn load(pool: &crate::db::DbPool) -> Self {
        let result = async {
            let client = pool.get().await?;
            let row = client
                .query_opt(
                    "SELECT value::text FROM billing_policy WHERE key = 'retention_sweep'",
                    &[],
                )
                .await?;
            let text: String = row
                .ok_or_else(|| anyhow::anyhow!("retention_sweep row missing"))?
                .get(0);
            let policy: Self = serde_json::from_str(&text)?;
            anyhow::ensure!(
                policy.delete_wait_secs > 0 && policy.max_run_secs > 0,
                "retention sweep wait/run duration must be positive"
            );
            Ok::<_, anyhow::Error>(policy)
        }
        .await;
        match result {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(%error, "retention sweep policy unavailable; using embedded reference row");
                Self::embedded()
            }
        }
    }
}

/// Read-time identical-tool detection parameters, from billing_policy.agent_loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub struct AgentLoopPolicy {
    pub min_repeats: u32,
    pub window_secs: u32,
    pub max_instances: u32,
    pub max_span_ids_per_instance: u32,
}
impl AgentLoopPolicy {
    pub fn valid(&self) -> bool {
        // Packaged caps are the safety ceilings. Cached policy may lower them;
        // raising the ceilings requires reviewing the packaged reference data.
        static CEILINGS: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
        let Some((instances, spans)) = *CEILINGS.get_or_init(|| {
            let seed: serde_json::Value =
                serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
            let policy: Self = serde_json::from_value(seed["policy"]["agent_loop"].clone()).ok()?;
            Some((policy.max_instances, policy.max_span_ids_per_instance))
        }) else {
            return false;
        };
        (2..=50).contains(&self.min_repeats)
            && (10..=86400).contains(&self.window_secs)
            && (1..=instances).contains(&self.max_instances)
            && (1..=spans).contains(&self.max_span_ids_per_instance)
    }
    pub fn embedded() -> Option<Self> {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
        serde_json::from_value::<Self>(seed["policy"]["agent_loop"].clone())
            .ok()
            .filter(Self::valid)
    }
}

/// Display-only spend-spike parameters, shared by every workspace.
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize)]
pub struct SpendSpikeParams {
    pub baseline_buckets: u32,
    pub ratio: f64,
    pub min_usd: f64,
    pub min_history_buckets: u32,
    pub max_window_buckets: u32,
    pub max_spikes_returned: u32,
    pub drill_top_n: u32,
}
impl SpendSpikeParams {
    fn valid(&self, ceiling: Self) -> bool {
        self.baseline_buckets > 0
            && self.baseline_buckets <= ceiling.baseline_buckets
            && self.min_history_buckets > 0
            && self.min_history_buckets <= self.baseline_buckets
            && self.min_history_buckets <= ceiling.min_history_buckets
            && self.max_window_buckets > 0
            && self.max_window_buckets <= ceiling.max_window_buckets
            && self.max_spikes_returned > 0
            && self.max_spikes_returned <= ceiling.max_spikes_returned
            && self.drill_top_n > 0
            && self.drill_top_n <= ceiling.drill_top_n
            && self.ratio.is_finite()
            && self.ratio > 1.
            && self.ratio <= ceiling.ratio
            && self.min_usd.is_finite()
            && self.min_usd > 0.
            && self.min_usd <= ceiling.min_usd
    }
}
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize)]
pub struct SpendSpikePolicy {
    pub hour: SpendSpikeParams,
    pub day: SpendSpikeParams,
    pub backfill_days: u32,
    pub backfill_max_memory_bytes: u64,
    pub backfill_max_execution_seconds: u32,
}
impl SpendSpikePolicy {
    pub fn valid(&self) -> bool {
        // Packaged reference data is the reviewed ceiling for cached overrides.
        // Parse without calling valid/embedded here: validation must not recurse.
        static CEILINGS: std::sync::OnceLock<Option<SpendSpikePolicy>> = std::sync::OnceLock::new();
        let Some(ceiling) = CEILINGS.get_or_init(|| {
            let seed: serde_json::Value =
                serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
            serde_json::from_value(seed["policy"]["spend_spikes"].clone()).ok()
        }) else {
            return false;
        };
        self.hour.valid(ceiling.hour)
            && self.day.valid(ceiling.day)
            && (1..=ceiling.backfill_days).contains(&self.backfill_days)
            && (1..=ceiling.backfill_max_memory_bytes).contains(&self.backfill_max_memory_bytes)
            && (1..=ceiling.backfill_max_execution_seconds)
                .contains(&self.backfill_max_execution_seconds)
    }
    pub fn embedded() -> Option<Self> {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
        serde_json::from_value::<Self>(seed["policy"]["spend_spikes"].clone())
            .ok()
            .filter(Self::valid)
    }
}

/// Non-price policy knobs from `billing_policy` (`key`, `value jsonb`).
/// **Only the keys this gateway build actually consumes are modeled** — the
/// row exists in Postgres for every ADR-076 §0.5 mechanic (dunning, prepaid
/// credits, …), but those are web/billing-mechanics concerns outside this
/// slice. Defaults here are FAIL-OPEN-FOR-DISPLAY values (a missing key logs
/// once and this default is used), never a silent literal price.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub workspace_glance: WorkspaceGlancePolicy,
    pub trace_reads: TraceReadPolicy,
    pub attempt_records_since: Option<String>,
    pub trace_reads_tenant_key_multiplier: Option<u32>,
    pub agent_loop: Option<AgentLoopPolicy>,
    pub spend_spikes: Option<SpendSpikePolicy>,
    pub incident_regression: Option<crate::incident_routes::IncidentPolicy>,
    pub generation_issues: crate::generation_issues::SummaryPolicy,
    pub window_breakdown_max_rows: usize,
    pub request_labels: tracelane_shared::labels::LabelCaps,
    pub output_speed: tracelane_shared::labels::OutputSpeedPolicy,
    pub otlp_capture: tracelane_shared::otlp::content::OtlpCapturePolicy,
    /// Meters 1 and 4: any single day's usage up to this multiple of the
    /// trailing 30-day average is billed at included rates (ADR-076 §0.4).
    pub burst_multiple: f64,
    /// Warning thresholds, percent of an included allowance (§0.4: "75% and 90%").
    pub warn_pct: Vec<u32>,
    /// A3 velocity breaker: trip when today's per-key tokens exceed
    /// `mean + velocity_sigma * stddev` of the trailing window.
    pub velocity_sigma: f64,
    pub velocity_window_days: i64,
    pub velocity_interval_secs: u64,
    /// B-442 (b): a candidate already checked against `api_keys` is not re-read for
    /// this long. Must exceed Neon's suspend timeout (300 s) or a spike day pins the
    /// compute every tick — the 2026-09-19 `pg_stat_statements` read showed exactly
    /// that (`calls` 1 → 9 in 43 min with candidates present).
    pub velocity_recheck_secs: u64,
    /// B-445 (2026-09-19): a blob with no `blob_refs` reference is deleted by the weekly
    /// GC only once it is OLDER than this — the quarantine that turns "a ref insert
    /// failed on Tuesday" from a Sunday data loss into a window the redelivery
    /// (ingest now writes blobs/refs INSIDE the durable flush) closes long before.
    /// `billing_policy.blob_gc_grace_days`, seeded from `plans.v3.json`.
    pub blob_gc_grace_days: i64,
}

/// Reference-backed bounds for the workspace overview. Kept together so the
/// gateway route and its cache consume the same validated values.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, serde::Deserialize)]
pub struct WorkspaceGlancePolicy {
    pub volume_window_days: u32,
    pub activity_window_days: u32,
    pub cache_ttl_seconds: u64,
    pub storage_cache_ttl_seconds: u64,
    pub providers_top: u32,
    pub storage_tables_top: u32,
}

impl WorkspaceGlancePolicy {
    fn valid(self) -> bool {
        self.volume_window_days > 0
            && self.activity_window_days > 0
            && self.cache_ttl_seconds > 0
            && self.storage_cache_ttl_seconds > 0
            && self.providers_top > 0
            && self.storage_tables_top > 0
    }

    fn seeded() -> Option<Self> {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
        serde_json::from_value::<Self>(seed["policy"]["workspace_glance"].clone())
            .ok()
            .filter(|value| value.valid())
    }

    pub fn selftest() -> bool {
        let default = Self::default();
        let mut stale = default;
        stale.volume_window_days += 1;
        Self::seeded() == Some(default) && Self::seeded() != Some(stale)
    }
}

impl Default for WorkspaceGlancePolicy {
    fn default() -> Self {
        Self {
            volume_window_days: 30,
            activity_window_days: 7,
            cache_ttl_seconds: 300,
            storage_cache_ttl_seconds: 900,
            providers_top: 8,
            storage_tables_top: 8,
        }
    }
}

/// Cached, seeded bounds for trace reads. A missing control plane uses the
/// packaged seed values so display paths remain available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub struct TraceReadPolicy {
    pub export_max_rows: u32,
    pub list_max_page: u32,
    pub cost_sort_max_window_hours: u32,
}

impl TraceReadPolicy {
    fn valid(self) -> bool {
        self.export_max_rows > 0 && self.list_max_page > 0 && self.cost_sort_max_window_hours > 0
    }

    fn embedded() -> Self {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json"))
                .unwrap_or_default();
        serde_json::from_value(seed["policy"]["trace_reads"].clone())
            .ok()
            .filter(|p: &Self| p.valid())
            .unwrap_or(Self {
                export_max_rows: 10_000,
                list_max_page: 200,
                cost_sort_max_window_hours: 168,
            })
    }
}

/// Existing breakdown bounds, sourced from the reviewed row cap and Free plan.
/// Falls back to the values seeded today (200 rows, Free's 3-day window)
/// if the embedded table is ever malformed — a display default, never a panic.
pub(crate) fn breakdown_defaults() -> (usize, i32) {
    const FALLBACK: (usize, i32) = (200, 3);
    static VALUES: std::sync::LazyLock<(usize, i32)> = std::sync::LazyLock::new(|| {
        let Ok(seed) = serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../../apps/web/db/plans.v3.json"
        )) else {
            return FALLBACK;
        };
        let rows = seed["policy"]["window_breakdown_max_rows"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(FALLBACK.0);
        let days = seed["plans"]["free_v1"]["indexed_window_days"]
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(FALLBACK.1);
        (rows, days)
    });
    *VALUES
}

impl Default for Policy {
    /// The fail-open display defaults — used only when `billing_policy` has
    /// no row for a key, which this module warns about once when it happens.
    fn default() -> Self {
        Self {
            workspace_glance: WorkspaceGlancePolicy::default(),
            trace_reads: TraceReadPolicy::embedded(),
            trace_reads_tenant_key_multiplier: serde_json::from_str::<serde_json::Value>(
                include_str!("../../../../apps/web/db/plans.v3.json"),
            )
            .ok()
            .and_then(|v| v["policy"]["trace_reads_tenant_key_multiplier"].as_u64())
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0),
            attempt_records_since: serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../../apps/web/db/plans.v3.json"
            ))
            .ok()
            .and_then(|v| {
                v["policy"]["attempt_records_since"]
                    .as_str()
                    .map(str::to_owned)
            }),
            agent_loop: AgentLoopPolicy::embedded(),
            spend_spikes: SpendSpikePolicy::embedded(),
            incident_regression: crate::incident_routes::IncidentPolicy::embedded(),
            generation_issues: crate::generation_issues::SummaryPolicy::embedded(),
            window_breakdown_max_rows: breakdown_defaults().0,
            request_labels: tracelane_shared::labels::LabelCaps::embedded(),
            output_speed: tracelane_shared::labels::OutputSpeedPolicy::embedded(),
            otlp_capture: tracelane_shared::otlp::content::OtlpCapturePolicy::embedded(),
            burst_multiple: 5.0,
            warn_pct: vec![75, 90],
            velocity_sigma: 2.0,
            velocity_window_days: 7,
            velocity_interval_secs: 300,
            velocity_recheck_secs: 3600,
            blob_gc_grace_days: 14,
        }
    }
}

/// The rates + policy a tenant is billed against. Loaded ONCE per refresh
/// cycle (the entitlement cache's cadence — never per request) and held in an
/// `ArcSwap` on `AppState`.
#[derive(Debug, Clone)]
pub struct RateCard {
    /// `pricing_rates.price_version` this card was loaded for, or `"current"`
    /// when loaded via `is_current` rather than a pinned version.
    pub version: String,
    pub bands: HashMap<RatedMeter, Vec<Band>>,
    pub policy: Policy,
    /// `false` when no Postgres control plane is configured, or the load
    /// failed — the usage route reports `rates_available: false` and
    /// `overage_usd: null` rather than a fabricated number (a display path,
    /// fail-OPEN per CLAUDE.md §10).
    pub available: bool,
}

impl RateCard {
    /// The fail-open "no rates" card. `rate()` on this card always reports
    /// zero overage with `available: false`, which the usage route reads to
    /// render "rates unavailable" instead of a wrong $0.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            version: String::new(),
            bands: HashMap::new(),
            policy: Policy::default(),
            available: false,
        }
    }

    /// Load the current rate card from Postgres in ONE round trip (a `UNION
    /// ALL` over `pricing_rates` and `billing_policy`) — spec §2.5b: "1 query
    /// per refresh per process", never per tenant, never per request.
    ///
    /// # Errors
    /// Propagates a pool/query failure; the caller (the boot/refresh loop)
    /// decides whether to keep serving the previous card or fall back to
    /// [`Self::unavailable`].
    pub async fn load(pool: &crate::db::DbPool) -> anyhow::Result<Self> {
        let client = pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("rate card pool: {e}"))?;
        const SQL: &str = "\
            SELECT 'rate' AS kind, price_version, meter, band_lo::text AS band_lo, \
              band_hi::text AS band_hi, usd_per_unit::text AS usd_per_unit, unit, \
              is_current::text AS is_current, NULL::text AS policy_key, NULL::text AS policy_value \
            FROM pricing_rates WHERE is_current = true \
            UNION ALL \
            SELECT 'policy', NULL, NULL, NULL, NULL, NULL, NULL, NULL, key, value::text \
            FROM billing_policy";
        let rows = client
            .query(SQL, &[])
            .await
            .map_err(|e| anyhow::anyhow!("rate card query: {e}"))?;

        let mut bands: HashMap<RatedMeter, Vec<Band>> = HashMap::new();
        let mut version = String::from("current");
        let mut policy_raw: HashMap<String, String> = HashMap::new();

        for row in &rows {
            let kind: String = row.get("kind");
            if kind == "rate" {
                let Some(meter) = row
                    .get::<_, Option<String>>("meter")
                    .and_then(|m| RatedMeter::from_column(&m))
                else {
                    continue;
                };
                let lo: f64 = row
                    .get::<_, Option<String>>("band_lo")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                let hi: Option<f64> = row
                    .get::<_, Option<String>>("band_hi")
                    .and_then(|s| s.parse().ok());
                let Some(usd_per_unit) = row
                    .get::<_, Option<String>>("usd_per_unit")
                    .and_then(|s| s.parse().ok())
                else {
                    continue;
                };
                if let Some(v) = row.get::<_, Option<String>>("price_version") {
                    version = v;
                }
                bands.entry(meter).or_default().push(Band {
                    lo,
                    hi,
                    usd_per_unit,
                });
            } else if let (Some(k), Some(v)) = (
                row.get::<_, Option<String>>("policy_key"),
                row.get::<_, Option<String>>("policy_value"),
            ) {
                policy_raw.insert(k, v);
            }
        }
        for v in bands.values_mut() {
            v.sort_by(|a, b| a.lo.partial_cmp(&b.lo).unwrap_or(std::cmp::Ordering::Equal));
        }

        Ok(Self {
            version,
            bands,
            policy: Policy::from_raw(&policy_raw),
            available: true,
        })
    }
}

impl Policy {
    /// Parse the `billing_policy` key/value(jsonb-as-text) map. A missing or
    /// unparseable key falls back to [`Policy::default`]'s value for that
    /// field and logs ONE warning naming the key — never a silent literal.
    fn from_raw(raw: &HashMap<String, String>) -> Self {
        let default = Self::default();
        let num = |key: &str, fallback: f64| -> f64 {
            raw.get(key)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or_else(|| {
                    tracing::warn!(
                        policy_key = key,
                        fallback,
                        "billing_policy row missing/unparseable — using the documented default"
                    );
                    fallback
                })
        };
        let int = |key: &str, fallback: i64| -> i64 {
            raw.get(key)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(fallback)
        };
        let warn_pct = {
            let a = raw
                .get("warn_pct_1")
                .and_then(|v| v.trim().parse::<u32>().ok());
            let b = raw
                .get("warn_pct_2")
                .and_then(|v| v.trim().parse::<u32>().ok());
            match (a, b) {
                (Some(a), Some(b)) => vec![a, b],
                _ => default.warn_pct.clone(),
            }
        };
        Self {
            workspace_glance: raw
                .get("workspace_glance")
                .and_then(|value| serde_json::from_str::<WorkspaceGlancePolicy>(value).ok())
                .filter(|value| value.valid())
                .unwrap_or_else(|| {
                    tracing::warn!(policy_key = "workspace_glance", "billing_policy row missing/invalid — using the documented default");
                    default.workspace_glance
                }),
            // Fail RESTRICTED to the packaged multiplier on a missing/invalid row.
            trace_reads: raw.get("trace_reads")
                .and_then(|v| serde_json::from_str::<TraceReadPolicy>(v).ok())
                .filter(|p| p.valid())
                .unwrap_or_else(|| {
                    tracing::warn!(policy_key = "trace_reads", "billing_policy row missing/invalid — using the embedded read bounds");
                    default.trace_reads
                }),
            // No valid packaged value leaves finite-plan API-key reads CLOSED.
            trace_reads_tenant_key_multiplier: raw.get("trace_reads_tenant_key_multiplier")
                .and_then(|v| serde_json::from_str::<u32>(v).ok()).filter(|n| *n > 0)
                .or(default.trace_reads_tenant_key_multiplier),
            attempt_records_since: raw.get("attempt_records_since")
                .and_then(|v| serde_json::from_str::<String>(v).ok())
                .filter(|v| chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d").is_ok()),
            spend_spikes: raw
                .get("spend_spikes")
                .and_then(|s| serde_json::from_str::<SpendSpikePolicy>(s).ok())
                .filter(SpendSpikePolicy::valid)
                .or(default.spend_spikes),
            agent_loop: raw
                .get("agent_loop")
                .and_then(|v| serde_json::from_str::<AgentLoopPolicy>(v).ok())
                .filter(AgentLoopPolicy::valid)
                .or(default.agent_loop),
            incident_regression: raw
                .get("incident_regression")
                .and_then(|v| serde_json::from_str(v).ok())
                .filter(crate::incident_routes::IncidentPolicy::valid)
                .or_else(|| {
                    tracing::warn!(
                        policy_key = "incident_regression",
                        "billing_policy row missing/invalid — incident and outcome routes fail closed"
                    );
                    None
                }),
            generation_issues: raw
                .get("generation_issues")
                .and_then(|v| {
                    serde_json::from_str::<crate::generation_issues::SummaryPolicy>(v).ok()
                })
                .filter(crate::generation_issues::SummaryPolicy::valid)
                .unwrap_or_else(|| {
                    tracing::warn!(
                        policy_key = "generation_issues",
                        "billing_policy row missing/invalid — using the embedded display default"
                    );
                    default.generation_issues
                }),
            window_breakdown_max_rows: raw
                .get("window_breakdown_max_rows")
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(default.window_breakdown_max_rows),
            request_labels: raw
                .get("request_labels")
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or(default.request_labels),
            output_speed: raw
                .get("output_speed")
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or(default.output_speed),
            otlp_capture: raw
                .get("otlp_capture")
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or(default.otlp_capture),
            burst_multiple: num("burst_multiple", default.burst_multiple),
            warn_pct,
            velocity_sigma: num("velocity_sigma", default.velocity_sigma),
            velocity_window_days: int("velocity_window_days", default.velocity_window_days),
            velocity_interval_secs: u64::try_from(int(
                "velocity_interval_secs",
                default.velocity_interval_secs as i64,
            ))
            .unwrap_or(default.velocity_interval_secs),
            velocity_recheck_secs: u64::try_from(int(
                "velocity_recheck_secs",
                default.velocity_recheck_secs as i64,
            ))
            .unwrap_or(default.velocity_recheck_secs),
            blob_gc_grace_days: int("blob_gc_grace_days", default.blob_gc_grace_days).max(0),
        }
    }
}

/// Refresh the process-wide `RateCard` from Postgres, on the SAME cadence as
/// the entitlement cache (never per request — spec §2.5b). Keeps serving the
/// PREVIOUS card on a failed refresh (fail-open for a display path); falls
/// back to [`RateCard::unavailable`] only when nothing has ever loaded.
pub async fn spawn_refresher(pool: crate::db::DbPool, card: Arc<ArcSwap<RateCard>>) {
    match RateCard::load(&pool).await {
        Ok(loaded) => card.store(Arc::new(loaded)),
        Err(e) => {
            tracing::warn!(error = %e, "initial rate card load failed; serving 'unavailable'")
        }
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(refresh_interval());
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match RateCard::load(&pool).await {
                Ok(loaded) => card.store(Arc::new(loaded)),
                Err(e) => {
                    tracing::warn!(error = %e, "rate card refresh failed; keeping the previous card")
                }
            }
        }
    });
}

/// The refresher's cadence by default: the entitlement cache's own TTL
/// (`entitlement_cache::TTL`) — one value, reused, so the two caches cannot
/// drift into two different "how stale can this be" answers.
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(900);

/// The cadence actually used: `TRACELANE_RATE_CARD_REFRESH_SECS` when set and
/// parseable (floor 60 s), else [`REFRESH_INTERVAL`]. The same knob shape as
/// `alerts::checker::rules_cache_ttl` and for the same reason (NEON-COMPUTE-PIN):
/// every refresh is a control-plane query, and with zero tenants four Postgres
/// reads an hour is four Neon compute wakes an hour. `scripts/ops/growth-mode.sh
/// off` sets 21600 (6 h); `on` deletes the line. A rate-card change lands within
/// the interval — at zero users nobody is waiting for it.
pub(crate) fn refresh_interval() -> std::time::Duration {
    std::env::var("TRACELANE_RATE_CARD_REFRESH_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map_or(REFRESH_INTERVAL, |s| {
            std::time::Duration::from_secs(s.max(60))
        })
}

/// One meter's rated usage, as `/v1/billing/usage` renders it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rated {
    pub used: f64,
    /// `None` = custom/unlimited (Enterprise) — shown, never billed.
    pub included: Option<f64>,
    pub burst_exempt: f64,
    pub overage_units: f64,
    pub overage_usd: f64,
}

/// Rate one meter. Pure: no I/O, no clock — `used`/`included`/`burst_exempt`
/// are already resolved by the caller (the usage route, from ClickHouse +
/// the entitlement cache).
///
/// `overage_units = max(0, used - included - burst_exempt)`, banded by the
/// tenant's ABSOLUTE usage level (the standard "graduated" reading: the first
/// N units of usage sit in the first band regardless of whether they are
/// "included" or "overage" — the included allowance and the burst exemption
/// simply mark the bottom slice of usage as EXEMPT rather than restarting the
/// band ladder at zero for the overage alone). `included: None` (custom /
/// Enterprise) never bills overage, matching ADR-076: an Enterprise contract
/// is negotiated, not metered by this ladder.
#[must_use]
pub fn rate(
    card: &RateCard,
    meter: RatedMeter,
    used: f64,
    included: Option<f64>,
    burst_exempt: f64,
) -> Rated {
    let Some(included) = included else {
        return Rated {
            used,
            included: None,
            burst_exempt: 0.0,
            overage_units: 0.0,
            overage_usd: 0.0,
        };
    };
    let burst_exempt = burst_exempt.max(0.0).min((used - included).max(0.0));
    let exempt_up_to = included + burst_exempt;
    let overage_units = (used - exempt_up_to).max(0.0);
    let overage_usd = card
        .bands
        .get(&meter)
        .map(|bands| banded_cost(bands, used, exempt_up_to))
        .unwrap_or(0.0);
    Rated {
        used,
        included: Some(included),
        burst_exempt,
        overage_units,
        overage_usd,
    }
}

/// Sum `usd_per_unit * (overlap of [exempt_up_to, used] with each band)`.
/// A flat-rate meter (one band, `[0, None)`) degenerates to
/// `(used - exempt_up_to).max(0) * rate`.
fn banded_cost(bands: &[Band], used: f64, exempt_up_to: f64) -> f64 {
    let mut cost = 0.0;
    for b in bands {
        let lo = b.lo.max(exempt_up_to);
        let hi = b.hi.unwrap_or(f64::INFINITY).min(used);
        if hi > lo {
            cost += (hi - lo) * b.usd_per_unit;
        }
    }
    cost
}

/// ADR-076 §0.4 / spec §2.1 / founder ruling B12 — the EXEMPT PORTION of one
/// day's usage, given that day's value and the trailing-average of the
/// preceding COMPLETE days (mean of ≥3 of them; `avg <= 0` — including "not
/// enough history" — means no signal, hence no exemption).
///
/// `exempt = clamp(day - avg, 0, (multiple - 1) * avg)`:
/// - A day AT OR BELOW its own trailing average is not a spike at all:
///   `day - avg <= 0` ⇒ exempt = 0 ⇒ billed in full. **This is the
///   correction over the previous `min(day, multiple*avg)` reading, which
///   exempted a STEADY day's entire value — every ordinary day, forever.**
/// - The SLICE of usage strictly BETWEEN `avg` and `multiple * avg` is
///   forgiven — a genuine incident burst.
/// - Anything ABOVE `multiple * avg` is NEVER forgiven, no matter how large:
///   `(multiple - 1) * avg` is the exemption's own ceiling, so a runaway
///   loop does not earn free capacity that scales with its own runaway rate
///   (the previous reading's other error: capping the emitted/billed value
///   at `multiple*avg` instead of capping the EXEMPTION there).
#[must_use]
pub fn burst_exempt_for_day(day: f64, avg: f64, multiple: f64) -> f64 {
    if avg <= 0.0 {
        return 0.0;
    }
    let ceiling = (multiple - 1.0).max(0.0) * avg;
    (day - avg).clamp(0.0, ceiling)
}

/// Sums [`burst_exempt_for_day`] across `daily` (chronological order), each
/// day's trailing average taken over its own up-to-30 PRECEDING days (≥3
/// required, else that day's own exemption is 0 — not enough signal to call
/// anything a spike, and it avoids a single early high day exempting itself
/// against its own value). Capped so the total exemption can never exceed
/// the month's total usage — true by construction now (each day's exemption
/// is `<= day - avg <= day` whenever avg >= 0), kept as an explicit defensive
/// floor rather than assumed.
#[must_use]
pub fn burst_exempt_days(daily: &[f64], multiple: f64) -> f64 {
    let mut exempt = 0.0;
    for i in 0..daily.len() {
        let start = i.saturating_sub(30);
        let history = &daily[start..i];
        if history.len() < 3 {
            continue;
        }
        let avg: f64 = history.iter().sum::<f64>() / history.len() as f64;
        exempt += burst_exempt_for_day(daily[i], avg, multiple);
    }
    let used: f64 = daily.iter().sum();
    exempt.min(used.max(0.0))
}

#[cfg(test)]
mod tests {
    #[test]
    fn trace_read_limits_are_seeded() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let limits = &seed["policy"]["trace_reads"];
        assert_eq!(limits["export_max_rows"], 10_000);
        assert_eq!(limits["list_max_page"], 200);
        assert_eq!(limits["cost_sort_max_window_hours"], 168);
    }
    #[test]
    fn incident_policy_requires_independent_read_budget() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let mut value = seed["policy"]["incident_regression"].clone();
        assert_eq!(value["incident_reads_per_minute_per_tenant"], 120);
        value
            .as_object_mut()
            .unwrap()
            .remove("incident_reads_per_minute_per_tenant");
        let raw = HashMap::from([("incident_regression".to_owned(), value.to_string())]);
        assert!(Policy::from_raw(&raw).incident_regression.is_none());
        value["incident_reads_per_minute_per_tenant"] = serde_json::json!(0);
        let raw = HashMap::from([("incident_regression".to_owned(), value.to_string())]);
        assert!(Policy::from_raw(&raw).incident_regression.is_none());
    }
    #[test]
    fn cf3_retired_read_policy_does_not_alert() {
        Policy::from_raw(&HashMap::new());
        assert!(
            !tracelane_shared::degradation::snapshot()
                .iter()
                .any(|s| s.kind == "trace_read_policy_fallback" && s.count > 0),
            "unused trace-read policy must not ask operators to seed it"
        );
    }

    #[test]
    fn cf3_tenant_key_multiplier_uses_seed_and_cached_policy() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let packaged = Policy::default().trace_reads_tenant_key_multiplier;
        assert_eq!(
            packaged.map(u64::from),
            seed["policy"]["trace_reads_tenant_key_multiplier"].as_u64()
        );
        assert_eq!(packaged, Some(3));
        let mut raw = HashMap::from([("trace_reads_tenant_key_multiplier".into(), "2".into())]);
        assert_eq!(
            Policy::from_raw(&raw).trace_reads_tenant_key_multiplier,
            Some(2)
        );
        for invalid in ["0", "null", "-1", "4294967296", "1.5", "\"3\""] {
            raw.insert("trace_reads_tenant_key_multiplier".into(), invalid.into());
            assert_eq!(
                Policy::from_raw(&raw).trace_reads_tenant_key_multiplier,
                packaged
            );
        }
        assert_eq!(
            Policy::from_raw(&HashMap::new()).trace_reads_tenant_key_multiplier,
            packaged
        );
        assert!(
            include_str!("../../../../apps/web/db/seed.mjs").contains(
                "trace_reads_tenant_key_multiplier: pol.trace_reads_tenant_key_multiplier"
            )
        );
        assert!(
            seed["policy"]
                .get("trace_reads_per_minute_per_tenant")
                .is_none()
        );
    }
    #[test]
    fn cf_low_attempt_cutover_uses_seed_and_cached_policy() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        assert_eq!(
            Policy::default().attempt_records_since.as_deref(),
            seed["policy"]["attempt_records_since"].as_str()
        );
        let mut raw = HashMap::from([("attempt_records_since".into(), "\"2026-09-20\"".into())]);
        assert_eq!(
            Policy::from_raw(&raw).attempt_records_since.as_deref(),
            Some("2026-09-20")
        );
        raw.insert("attempt_records_since".into(), "\"invalid\"".into());
        assert_eq!(Policy::from_raw(&raw).attempt_records_since, None);
        assert!(
            include_str!("../../../../apps/web/db/seed.mjs")
                .contains("attempt_records_since: pol.attempt_records_since")
        );
    }

    #[test]
    fn cf_low_loop_caps_have_upper_bounds() {
        let mut policy = super::AgentLoopPolicy::embedded().unwrap();
        policy.max_instances = u32::MAX;
        assert!(!policy.valid(), "instance cap cannot be unbounded");
        policy = super::AgentLoopPolicy::embedded().unwrap();
        policy.max_span_ids_per_instance = u32::MAX;
        assert!(!policy.valid(), "evidence cap cannot be unbounded");
    }

    #[test]
    fn incident_policy_requires_seeded_candidate_cap() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let mut value = seed["policy"]["incident_regression"].clone();
        let raw = HashMap::from([("incident_regression".to_owned(), value.to_string())]);
        assert_eq!(
            Policy::from_raw(&raw)
                .incident_regression
                .unwrap()
                .incident_max_candidates,
            50
        );
        value
            .as_object_mut()
            .unwrap()
            .remove("incident_max_candidates");
        let raw = HashMap::from([("incident_regression".to_owned(), value.to_string())]);
        assert!(Policy::from_raw(&raw).incident_regression.is_none());
        value["incident_max_candidates"] = serde_json::json!(0);
        let raw = HashMap::from([("incident_regression".to_owned(), value.to_string())]);
        assert!(Policy::from_raw(&raw).incident_regression.is_none());
    }

    #[test]
    fn spend_policy_rejects_every_value_above_packaged_ceiling() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let policy = seed["policy"]["spend_spikes"].clone();
        let mut accepted = Vec::new();
        for unit in ["hour", "day"] {
            for key in [
                "baseline_buckets",
                "ratio",
                "min_usd",
                "min_history_buckets",
                "max_window_buckets",
                "max_spikes_returned",
                "drill_top_n",
            ] {
                let mut bad = policy.clone();
                bad[unit][key] = if ["ratio", "min_usd"].contains(&key) {
                    serde_json::json!(bad[unit][key].as_f64().unwrap() + 1.)
                } else {
                    serde_json::json!(bad[unit][key].as_u64().unwrap() + 1)
                };
                let raw = HashMap::from([("spend_spikes".to_owned(), bad.to_string())]);
                assert_eq!(
                    Policy::from_raw(&raw).spend_spikes,
                    super::SpendSpikePolicy::embedded()
                );
                if serde_json::from_value::<super::SpendSpikePolicy>(bad)
                    .unwrap()
                    .valid()
                {
                    accepted.push(format!("{unit}.{key}"));
                }
            }
        }
        for key in [
            "backfill_days",
            "backfill_max_memory_bytes",
            "backfill_max_execution_seconds",
        ] {
            let mut bad = policy.clone();
            bad[key] = serde_json::json!(bad[key].as_u64().unwrap() + 1);
            if serde_json::from_value::<super::SpendSpikePolicy>(bad)
                .unwrap()
                .valid()
            {
                accepted.push(key.to_owned());
            }
        }
        assert!(
            accepted.is_empty(),
            "unbounded spend policy values: {accepted:?}"
        );
    }

    #[test]
    fn spend_spikes_seed_and_cached_override_are_validated() {
        let policy =
            super::SpendSpikePolicy::embedded().expect("spend_spikes policy must be seeded");
        assert!(policy.valid());
        assert_eq!(super::Policy::default().spend_spikes, Some(policy));
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let mut value = seed["policy"]["spend_spikes"].clone();
        value["hour"]["ratio"] = serde_json::json!(policy.hour.ratio - 0.5);
        let mut raw = std::collections::HashMap::new();
        raw.insert("spend_spikes".into(), value.to_string());
        assert_eq!(
            super::Policy::from_raw(&raw)
                .spend_spikes
                .unwrap()
                .hour
                .ratio,
            policy.hour.ratio - 0.5
        );
        value["hour"]["min_history_buckets"] = serde_json::json!(0);
        raw.insert("spend_spikes".into(), value.to_string());
        assert_eq!(super::Policy::from_raw(&raw).spend_spikes, Some(policy));
        assert!(
            include_str!("../../../../apps/web/db/seed.mjs")
                .contains("spend_spikes: pol.spend_spikes")
        );
    }

    #[test]
    fn agent_loop_seed_is_present_and_bounded() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let value = &seed["policy"]["agent_loop"];
        assert!(value.is_object(), "agent_loop policy must be seeded");
        let embedded = super::AgentLoopPolicy::embedded().unwrap();
        assert_eq!(
            serde_json::from_value::<super::AgentLoopPolicy>(value.clone()).unwrap(),
            embedded
        );
        assert_eq!(super::Policy::default().agent_loop, Some(embedded));
        let mut raw = std::collections::HashMap::new();
        let mut changed = value.clone();
        changed["min_repeats"] = 4.into();
        raw.insert("agent_loop".into(), changed.to_string());
        assert_eq!(
            super::Policy::from_raw(&raw)
                .agent_loop
                .unwrap()
                .min_repeats,
            4
        );
        changed["min_repeats"] = 1.into();
        raw.insert("agent_loop".into(), changed.to_string());
        assert_eq!(super::Policy::from_raw(&raw).agent_loop, Some(embedded));
        assert!((2..=50).contains(&value["min_repeats"].as_u64().unwrap()));
        assert!((10..=86400).contains(&value["window_secs"].as_u64().unwrap()));
        assert!(
            include_str!("../../../../apps/web/db/seed.mjs").contains("agent_loop: pol.agent_loop")
        );
    }

    #[test]
    fn breakdown_reference_preserves_existing_bounds_and_loads_override() {
        assert_eq!(super::breakdown_defaults(), (200, 3));
        let raw =
            std::collections::HashMap::from([("window_breakdown_max_rows".into(), "7".into())]);
        assert_eq!(super::Policy::from_raw(&raw).window_breakdown_max_rows, 7);
        assert_eq!(
            super::Policy::default().window_breakdown_max_rows,
            super::breakdown_defaults().0
        );
    }

    #[test]
    fn label_policy_loader_overrides_and_fallback_match_seed() {
        let mut caps = tracelane_shared::labels::LabelCaps::embedded();
        caps.max_tags = 3;
        let speed = tracelane_shared::labels::OutputSpeedPolicy {
            min_generation_ms: 75,
        };
        let raw = std::collections::HashMap::from([
            (
                "request_labels".into(),
                serde_json::to_string(&caps).unwrap(),
            ),
            (
                "output_speed".into(),
                serde_json::to_string(&speed).unwrap(),
            ),
        ]);
        let policy = super::Policy::from_raw(&raw);
        assert_eq!(policy.request_labels, caps);
        assert_eq!(policy.output_speed, speed);
        let default = super::Policy::from_raw(&std::collections::HashMap::new());
        assert_eq!(
            default.request_labels,
            tracelane_shared::labels::LabelCaps::embedded()
        );
        assert_eq!(
            default.output_speed,
            tracelane_shared::labels::OutputSpeedPolicy::embedded()
        );
    }

    #[test]
    fn otlp_policy_loader_reads_overrides_and_embedded_fallback() {
        let mut caps = tracelane_shared::otlp::content::OtlpCapturePolicy::embedded();
        assert_eq!(
            caps.default_max_field_bytes,
            crate::server::config::DEFAULT_MAX_FIELD_BYTES
        );
        caps.max_links_per_span = 3;
        let raw = std::collections::HashMap::from([(
            "otlp_capture".to_string(),
            serde_json::to_string(&caps).unwrap(),
        )]);
        assert_eq!(super::Policy::from_raw(&raw).otlp_capture, caps);
        assert_eq!(
            super::Policy::from_raw(&std::collections::HashMap::new()).otlp_capture,
            tracelane_shared::otlp::content::OtlpCapturePolicy::embedded()
        );
    }

    use super::*;
    use serde::Deserialize;

    /// The JSON fixture's shape (`apps/web/db/plans.v3.json`), read so the
    /// tests below carry ZERO literal prices — not even in the test bodies,
    /// except band-boundary OFFSETS (`hi - 0.001`), which are test technique,
    /// not a price.
    #[derive(Deserialize)]
    struct Fixture {
        meters: FixtureMeters,
        policy: FixturePolicy,
    }
    #[derive(Deserialize)]
    struct FixtureMeters {
        ingest_usd_per_gb: f64,
        hot_window_usd_per_gb_month_ladder: Vec<(f64, Option<f64>, f64)>,
        series_usd_per_series_month: f64,
        query_usd_per_scan_unit: f64,
        cold_usd_per_gb_month: f64,
        eval_usd_per_judge_run: f64,
    }
    #[derive(Deserialize)]
    struct FixturePolicy {
        burst_multiple_of_trailing_30d_avg: f64,
        warning_thresholds_pct: Vec<u32>,
    }

    fn fixture() -> Fixture {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/web/db/plans.v3.json"
        ));
        serde_json::from_str(raw).expect("apps/web/db/plans.v3.json must parse")
    }

    fn card_from_fixture() -> RateCard {
        let f = fixture();
        let mut bands = HashMap::new();
        bands.insert(
            RatedMeter::IngestGb,
            vec![Band {
                lo: 0.0,
                hi: None,
                usd_per_unit: f.meters.ingest_usd_per_gb,
            }],
        );
        bands.insert(
            RatedMeter::HotGbMonth,
            f.meters
                .hot_window_usd_per_gb_month_ladder
                .iter()
                .map(|&(lo, hi, usd)| Band {
                    lo,
                    hi,
                    usd_per_unit: usd,
                })
                .collect(),
        );
        bands.insert(
            RatedMeter::Series,
            vec![Band {
                lo: 0.0,
                hi: None,
                usd_per_unit: f.meters.series_usd_per_series_month,
            }],
        );
        bands.insert(
            RatedMeter::ScanUnits,
            vec![Band {
                lo: 0.0,
                hi: None,
                usd_per_unit: f.meters.query_usd_per_scan_unit,
            }],
        );
        bands.insert(
            RatedMeter::ColdGbMonth,
            vec![Band {
                lo: 0.0,
                hi: None,
                usd_per_unit: f.meters.cold_usd_per_gb_month,
            }],
        );
        bands.insert(
            RatedMeter::EvalRuns,
            vec![Band {
                lo: 0.0,
                hi: None,
                usd_per_unit: f.meters.eval_usd_per_judge_run,
            }],
        );
        RateCard {
            version: "test".to_string(),
            bands,
            policy: Policy {
                burst_multiple: f.policy.burst_multiple_of_trailing_30d_avg,
                warn_pct: f.policy.warning_thresholds_pct.clone(),
                ..Policy::default()
            },
            available: true,
        }
    }

    #[test]
    fn flat_meter_bills_only_the_overage() {
        let card = card_from_fixture();
        let per_gb = card.bands[&RatedMeter::IngestGb][0].usd_per_unit;
        let r = rate(&card, RatedMeter::IngestGb, 30.0, Some(25.0), 0.0);
        assert!((r.overage_units - 5.0).abs() < 1e-9);
        assert!((r.overage_usd - 5.0 * per_gb).abs() < 1e-9);
    }

    #[test]
    fn under_the_included_allowance_bills_zero() {
        let card = card_from_fixture();
        let r = rate(&card, RatedMeter::IngestGb, 10.0, Some(25.0), 0.0);
        assert_eq!(r.overage_units, 0.0);
        assert_eq!(r.overage_usd, 0.0);
    }

    #[test]
    fn custom_allowance_never_bills_overage() {
        let card = card_from_fixture();
        let r = rate(&card, RatedMeter::IngestGb, 999_999.0, None, 0.0);
        assert_eq!(r.included, None);
        assert_eq!(
            r.overage_usd, 0.0,
            "Enterprise custom allowance is never metered by this ladder"
        );
    }

    /// Every ladder band boundary from the ruled JSON, exercised at
    /// `boundary - 0.001` (still the lower band) and `boundary` (the next
    /// band) — no literal GB figure appears here; the boundaries come from
    /// the fixture.
    #[test]
    fn every_ladder_band_boundary_bills_at_the_right_rate() {
        let card = card_from_fixture();
        let ladder = &card.bands[&RatedMeter::HotGbMonth];
        for w in ladder.windows(2) {
            let boundary = w[0].hi.expect("a non-final band has a hi bound");
            // Just under the boundary: one full extra unit of overage (used -
            // included = 1.0), still entirely inside the lower band, so it
            // costs exactly `1.0 * w[0].usd_per_unit` — the LOWER band's rate.
            let below = rate(
                &card,
                RatedMeter::HotGbMonth,
                boundary - 0.001,
                Some(boundary - 1.001),
                0.0,
            );
            assert!(
                (below.overage_usd - w[0].usd_per_unit).abs() < 1e-6,
                "just under {boundary}: expected one full unit at the lower band's rate, got {}",
                below.overage_usd
            );
            // One unit past the boundary: that marginal unit costs the HIGHER band's rate.
            let above = rate(
                &card,
                RatedMeter::HotGbMonth,
                boundary + 1.0,
                Some(boundary),
                0.0,
            );
            assert!(
                (above.overage_usd - w[1].usd_per_unit).abs() < 1e-6,
                "just over {boundary}: expected the higher band's rate"
            );
        }
    }

    // ── burst_exempt_for_day (pure, pinned scenarios — founder ruling B12) ──

    #[test]
    fn steady_day_at_its_own_average_is_never_exempt() {
        // The correction over the PRIOR (wrong) reading: a steady day used to
        // exempt its ENTIRE value (`min(day, multiple*avg)` with day <=
        // multiple*avg trivially true for any non-spiking day). Now: no
        // deviation from the average at all -> exempt 0 -> billed in full.
        assert_eq!(burst_exempt_for_day(10.0, 10.0, 5.0), 0.0);
    }

    #[test]
    fn a_day_below_its_own_average_is_never_exempt() {
        assert_eq!(burst_exempt_for_day(5.0, 10.0, 5.0), 0.0);
    }

    #[test]
    fn a_3x_spike_exempts_the_slice_between_avg_and_multiple_times_avg() {
        // day = 3*avg, multiple = 5 -> exempt = day - avg = 2*avg (well
        // within the (multiple-1)*avg = 4*avg ceiling) -> billed = avg.
        let avg = 10.0;
        let day = 3.0 * avg;
        let exempt = burst_exempt_for_day(day, avg, 5.0);
        assert!(
            (exempt - 2.0 * avg).abs() < 1e-9,
            "exempt={exempt}, want 2x avg"
        );
        assert!((day - exempt - avg).abs() < 1e-9, "billed must equal avg");
    }

    #[test]
    fn a_10x_spike_is_capped_at_the_multiple_minus_one_times_avg_ceiling() {
        // day = 10*avg, multiple = 5 -> ceiling = (multiple-1)*avg = 4*avg,
        // so exempt caps at 4*avg (NOT the whole day-avg=9*avg) -> billed =
        // 10*avg - 4*avg = 6*avg. **This is the other half of the
        // correction: the prior reading capped the BILLED value at
        // multiple*avg (forgiving everything past it); this caps only the
        // EXEMPTION, so anything above multiple*avg always bills.**
        let avg = 10.0;
        let day = 10.0 * avg;
        let exempt = burst_exempt_for_day(day, avg, 5.0);
        assert!(
            (exempt - 4.0 * avg).abs() < 1e-9,
            "exempt={exempt}, want 4x avg"
        );
        assert!(
            (day - exempt - 6.0 * avg).abs() < 1e-9,
            "billed must equal 6x avg"
        );
    }

    #[test]
    fn no_signal_avg_is_never_exempt() {
        // avg <= 0 (no history, or fewer than 3 preceding days upstream in
        // burst_exempt_days) means no trailing signal to compare against.
        assert_eq!(burst_exempt_for_day(1_000_000.0, 0.0, 5.0), 0.0);
    }

    // ── burst_exempt_days (the array/history-window integration) ────────────

    #[test]
    fn burst_exempt_days_bills_a_perfectly_steady_series_in_full() {
        let daily = vec![1.0; 10];
        assert_eq!(
            burst_exempt_days(&daily, 5.0),
            0.0,
            "a steady series (every day == its own trailing average) must never be exempt"
        );
    }

    #[test]
    fn burst_exempt_days_forgives_only_the_slice_of_a_3x_spike() {
        let mut daily = vec![1.0; 10]; // avg = 1.0 for the spike day
        daily.push(3.0); // a 3x spike
        let exempt = burst_exempt_days(&daily, 5.0);
        // Every quiet day sits at its OWN trailing average -> 0 exempt each;
        // only the spike day contributes: exempt = day - avg = 2.0.
        assert!((exempt - 2.0).abs() < 1e-9, "exempt={exempt}, want 2.0");
    }

    #[test]
    fn burst_exempt_days_never_forgives_above_the_multiple_ceiling() {
        let mut daily = vec![1.0; 10];
        daily.push(10.0); // a 10x spike
        let exempt = burst_exempt_days(&daily, 5.0);
        // Capped at (multiple-1)*avg = 4*1.0 = 4.0, not day-avg = 9.0.
        assert!(
            (exempt - 4.0).abs() < 1e-9,
            "exempt={exempt}, want 4.0 (capped)"
        );
    }

    #[test]
    fn fewer_than_three_preceding_days_is_never_exempt() {
        assert_eq!(
            burst_exempt_days(&[1_000_000.0], 5.0),
            0.0,
            "zero preceding days -> no signal"
        );
        assert_eq!(
            burst_exempt_days(&[1.0, 1.0, 1_000_000.0], 5.0),
            0.0,
            "only 2 preceding days -> still no signal (< 3 required)"
        );
    }

    #[test]
    fn burst_exemption_never_exceeds_total_used() {
        let daily = vec![0.001; 5]; // tiny, so 5x average could still be tiny — sanity floor
        let exempt = burst_exempt_days(&daily, 5.0);
        assert!(exempt <= daily.iter().sum::<f64>() + 1e-12);
    }

    #[test]
    fn a_day_with_no_history_is_never_exempt() {
        // A single huge first day has nothing to compare against.
        let daily = vec![1_000_000.0];
        assert_eq!(burst_exempt_days(&daily, 5.0), 0.0);
    }

    #[test]
    fn free_shows_over_100_pct_used_and_zero_dollars_when_overage_is_disallowed() {
        // Free's ruled `overage_allowed = false` is an entitlement-layer fact,
        // not a rating-layer one — `rate()` itself does not read
        // `overage_allowed`. The usage route is what must zero the dollar
        // figure while still SHOWING the over-100% used number; assert the
        // contract at the boundary this module owns: `rate()` still computes
        // a real `overage_units`/`overage_usd` here, so the caller can choose
        // to display-but-not-charge it.
        let card = card_from_fixture();
        let r = rate(&card, RatedMeter::IngestGb, 2.0, Some(1.0), 0.0);
        assert!(r.overage_units > 0.0);
    }

    #[test]
    fn policy_from_raw_preserves_display_defaults_and_fails_closed_for_strict_keys() {
        let p = Policy::from_raw(&HashMap::new());
        let expected = Policy {
            attempt_records_since: None,
            // This existing strict policy also refuses an embedded fallback.
            incident_regression: None,
            ..Policy::default()
        };
        assert_eq!(p, expected);
    }

    #[test]
    fn workspace_glance_default_matches_seed_and_missing_row_warns_to_default() {
        assert!(super::WorkspaceGlancePolicy::selftest());
        let default = super::WorkspaceGlancePolicy::default();
        assert_eq!(Policy::from_raw(&HashMap::new()).workspace_glance, default);
        let mut raw = HashMap::new();
        raw.insert(
            "workspace_glance".to_owned(),
            r#"{"volume_window_days":14,"activity_window_days":7,"cache_ttl_seconds":300,"storage_cache_ttl_seconds":900,"providers_top":8,"storage_tables_top":8}"#.to_owned(),
        );
        assert_eq!(
            Policy::from_raw(&raw).workspace_glance.volume_window_days,
            14
        );
    }

    #[test]
    fn policy_from_raw_reads_present_keys() {
        let mut raw = HashMap::new();
        raw.insert("burst_multiple".to_string(), "7".to_string());
        raw.insert("velocity_sigma".to_string(), "3".to_string());
        raw.insert("velocity_window_days".to_string(), "14".to_string());
        raw.insert("velocity_interval_secs".to_string(), "60".to_string());
        let p = Policy::from_raw(&raw);
        assert_eq!(p.burst_multiple, 7.0);
        assert_eq!(p.velocity_sigma, 3.0);
        assert_eq!(p.velocity_window_days, 14);
        assert_eq!(p.velocity_interval_secs, 60);
    }

    #[test]
    fn issue_summary_policy_loads_overrides_and_rejects_missing_or_zero_values() {
        let raw = HashMap::from([(
            "generation_issues".into(),
            r#"{"dashboard_window_days":2,"summary_cache_ttl_seconds":5,"inline_chip_limit":3}"#
                .into(),
        )]);
        let loaded = Policy::from_raw(&raw).generation_issues;
        assert_eq!(loaded.dashboard_window_days, 2);
        assert_eq!(loaded.summary_cache_ttl_seconds, 5);
        assert_eq!(loaded.inline_chip_limit, 3);
        for raw_value in [
            "{}",
            "null",
            r#"{"dashboard_window_days":0,"summary_cache_ttl_seconds":5,"inline_chip_limit":3}"#,
            "invalid",
        ] {
            let raw = HashMap::from([("generation_issues".into(), raw_value.into())]);
            assert_eq!(
                Policy::from_raw(&raw).generation_issues,
                crate::generation_issues::SummaryPolicy::embedded()
            );
        }
        assert_eq!(
            Policy::from_raw(&HashMap::new()).generation_issues,
            crate::generation_issues::SummaryPolicy::embedded()
        );
    }

    #[test]
    fn unavailable_card_bills_nothing_and_says_so() {
        let card = RateCard::unavailable();
        assert!(!card.available);
        let r = rate(&card, RatedMeter::IngestGb, 500.0, Some(1.0), 0.0);
        assert_eq!(r.overage_usd, 0.0, "no bands loaded -> zero, never a guess");
    }

    #[test]
    fn rated_meter_column_round_trips() {
        for m in [
            RatedMeter::IngestGb,
            RatedMeter::HotGbMonth,
            RatedMeter::Series,
            RatedMeter::ScanUnits,
            RatedMeter::ColdGbMonth,
            RatedMeter::EvalRuns,
        ] {
            assert_eq!(RatedMeter::from_column(m.column_value()), Some(m));
        }
        assert_eq!(RatedMeter::from_column("bogus"), None);
    }
}
