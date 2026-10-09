//! Tenant-scoped, independently failing workspace overview reads.

use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use tracelane_shared::TenantId;

use crate::{
    billing::{period, rating::WorkspaceGlancePolicy},
    clickhouse_query::{PlanTier, TenantQuery},
    trace_reads::{CostDimension, CostFilters, CostScope, TraceListFilters, TraceReader},
};

#[derive(Clone)]
pub struct GlanceState {
    ch: Client,
    reader: Arc<dyn TraceReader>,
    rate_card: Arc<arc_swap::ArcSwap<crate::billing::RateCard>>,
    entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
    self_host: bool,
    cache: moka::future::Cache<GlanceKey, Arc<Glance>>,
    storage_cache: moka::future::Cache<StorageKey, Arc<Storage>>,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct GlanceKey {
    tenant: TenantId,
    policy: WorkspaceGlancePolicy,
    window_days: u32,
}

struct GlanceExpiry;
impl moka::Expiry<GlanceKey, Arc<Glance>> for GlanceExpiry {
    fn expire_after_create(
        &self,
        key: &GlanceKey,
        value: &Arc<Glance>,
        _: std::time::Instant,
    ) -> Option<Duration> {
        Some(if value.cacheable() {
            Duration::from_secs(key.policy.cache_ttl_seconds)
        } else {
            // Observability failures stay visible, but the next read may retry.
            Duration::ZERO
        })
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct StorageKey {
    tenant: TenantId,
    ttl_seconds: u64,
    tables_top: u32,
}

struct StorageExpiry;
impl moka::Expiry<StorageKey, Arc<Storage>> for StorageExpiry {
    fn expire_after_create(
        &self,
        key: &StorageKey,
        value: &Arc<Storage>,
        _: std::time::Instant,
    ) -> Option<Duration> {
        Some(if value.state == SectionState::Ok {
            Duration::from_secs(key.ttl_seconds)
        } else {
            Duration::ZERO
        })
    }
}

fn glance_cache() -> moka::future::Cache<GlanceKey, Arc<Glance>> {
    moka::future::Cache::builder()
        .max_capacity(10_000)
        .expire_after(GlanceExpiry)
        .build()
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SectionState {
    Ok,
    Unavailable,
    OverCap,
    Denied,
}

#[derive(Clone, Serialize)]
struct Glance {
    as_of: DateTime<Utc>,
    cache_ttl_seconds: u64,
    deployment: &'static str,
    volume: Volume,
    ingest: Ingest,
    stored: Stored,
    agents: Agents,
    spend: Spend,
    providers: Providers,
    storage: Option<Storage>,
}

impl Glance {
    fn cacheable(&self) -> bool {
        [
            self.volume.state,
            self.ingest.state,
            self.stored.state,
            self.agents.state,
            self.spend.state,
            self.providers.state,
        ]
        .into_iter()
        .all(|state| state == SectionState::Ok)
            && self
                .storage
                .as_ref()
                .is_none_or(|storage| storage.state == SectionState::Ok)
    }
}

#[derive(Clone, Serialize)]
struct Volume {
    state: SectionState,
    window_days: u32,
    traces: Option<u64>,
    spans: Option<u64>,
}

#[derive(Clone, Serialize)]
struct Ingest {
    state: SectionState,
    source: &'static str,
    total_bytes: Option<f64>,
    since: Option<String>,
    period_bytes: Option<f64>,
    period_start: Option<String>,
    period_kind: Option<&'static str>,
}

#[derive(Clone, Serialize)]
struct Stored {
    state: SectionState,
    kind: &'static str,
    bytes: Option<f64>,
    as_of: Option<String>,
}

#[derive(Clone, Serialize)]
struct Agents {
    state: SectionState,
    window_days: u32,
    active: Option<u64>,
    direct_calls: Option<u64>,
}

#[derive(Clone, Serialize)]
struct Spend {
    state: SectionState,
    period_start: Option<String>,
    period_kind: Option<&'static str>,
    usd: Option<f64>,
    unpriced_requests: Option<u64>,
}

#[derive(Clone, Serialize)]
struct Providers {
    state: SectionState,
    window_days: u32,
    count: Option<u64>,
    top: Vec<String>,
}

#[derive(Clone, Serialize)]
struct Storage {
    state: SectionState,
    compressed_bytes: Option<u64>,
    uncompressed_bytes: Option<u64>,
    index_bytes: Option<u64>,
    primary_index_bytes: Option<u64>,
    on_disk_bytes: Option<u64>,
    ratio: Option<f64>,
    tables: Vec<StorageTable>,
    disk: Option<Disk>,
}

#[derive(Clone, Serialize)]
struct StorageTable {
    name: String,
    on_disk_bytes: u64,
    rows: u64,
}

#[derive(Clone, Serialize)]
struct Disk {
    free: u64,
    total: u64,
}

#[derive(Row, Deserialize)]
struct CountRow {
    total: u64,
}

#[derive(Row, Deserialize)]
struct MeterRow {
    rows: u64,
    total: f64,
    first_day: String,
}

#[derive(Row, Deserialize)]
struct SumRow {
    total: f64,
}

#[derive(Row, Deserialize)]
struct GaugeRow {
    value: f64,
    day_iso: String,
}

#[derive(Row, Deserialize)]
struct AgentRow {
    active: u64,
    direct_calls: u64,
}

#[derive(Row, Deserialize)]
struct ProviderRow {
    provider: String,
    provider_count: u64,
}

#[derive(Row, Deserialize)]
struct StoragePartRow {
    name: String,
    compressed_bytes: u64,
    uncompressed_bytes: u64,
    index_bytes: u64,
    primary_index_bytes: u64,
    on_disk_bytes: u64,
    rows: u64,
}

#[derive(Row, Deserialize)]
struct DiskRow {
    free: u64,
    total: u64,
}

fn section_error(err: &clickhouse::error::Error) -> SectionState {
    let message = err.to_string();
    if message.contains("ACCESS_DENIED") || message.contains("Not enough privileges") {
        SectionState::Denied
    } else if message.contains("TOO_MANY_ROWS")
        || message.contains("MEMORY_LIMIT_EXCEEDED")
        || message.contains("TIMEOUT_EXCEEDED")
    {
        SectionState::OverCap
    } else {
        SectionState::Unavailable
    }
}

fn state_from_error(err: &anyhow::Error) -> SectionState {
    err.downcast_ref::<clickhouse::error::Error>()
        .map_or(SectionState::Unavailable, section_error)
}

fn capped_sql(tier: PlanTier, tenant: &TenantId, statement: impl Into<String>) -> String {
    TenantQuery::new(statement, tier)
        .with_log_comment(format!("tenant_id={tenant}"))
        .sql_with_settings()
}

fn spans_sql() -> &'static str {
    "SELECT toUInt64(sum(span_count)) AS total FROM tracelane.trace_summaries \
     WHERE tenant_id = ? AND start_time >= fromUnixTimestamp64Micro(?) \
     AND start_time <= fromUnixTimestamp64Micro(?)"
}

fn meter_sql() -> &'static str {
    "SELECT toUInt64(count()) AS rows, sum(value) AS total, toString(min(day)) AS first_day \
     FROM tracelane.meter_counters WHERE tenant_id = ? AND meter = 'ingest_bytes'"
}

fn period_meter_sql() -> &'static str {
    "SELECT sum(value) AS total FROM tracelane.meter_counters \
     WHERE tenant_id = ? AND meter = 'ingest_bytes' AND day >= toDate(?)"
}

fn agent_sql() -> String {
    let agent_key = crate::kya_routes::agent_key_sql();
    let call = crate::kya_routes::CALL_SQL;
    format!(
        "SELECT toUInt64(uniqExactIf(agent_key, is_call AND agent_key != '')) AS active, \
         toUInt64(countIf(is_call AND agent_key = '')) AS direct_calls FROM (\
         SELECT {agent_key} AS agent_key, {call} AS is_call FROM tracelane.spans FINAL \
         WHERE tenant_id = ? AND start_time >= fromUnixTimestamp64Micro(?) \
         AND start_time <= fromUnixTimestamp64Micro(?))"
    )
}

fn provider_sql() -> &'static str {
    "SELECT JSONExtractString(attributes, 'gen_ai_provider_name') AS provider, \
     toUInt64(count() OVER ()) AS provider_count FROM tracelane.spans FINAL \
     WHERE tenant_id = ? AND start_time >= fromUnixTimestamp64Micro(?) \
     AND start_time <= fromUnixTimestamp64Micro(?) \
     AND JSONExtractString(attributes, 'gen_ai_provider_name') != '' \
     GROUP BY provider ORDER BY count() DESC, provider ASC LIMIT ?"
}

fn storage_parts_sql() -> &'static str {
    "SELECT table AS name, toUInt64(sum(data_compressed_bytes)) AS compressed_bytes, \
     toUInt64(sum(data_uncompressed_bytes)) AS uncompressed_bytes, \
     toUInt64(sum(secondary_indices_compressed_bytes)) AS index_bytes, \
     toUInt64(sum(primary_key_bytes_in_memory + marks_bytes)) AS primary_index_bytes, \
     toUInt64(sum(bytes_on_disk)) AS on_disk_bytes, toUInt64(sum(rows)) AS rows \
     FROM system.parts WHERE active = 1 AND database = 'tracelane' \
     GROUP BY table ORDER BY on_disk_bytes DESC, name ASC"
}

fn storage_disks_sql() -> &'static str {
    "SELECT toUInt64(sum(free_space)) AS free, toUInt64(sum(total_space)) AS total \
     FROM system.disks"
}

impl GlanceState {
    pub fn new(
        ch: Client,
        reader: Arc<dyn TraceReader>,
        rate_card: Arc<arc_swap::ArcSwap<crate::billing::RateCard>>,
        entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
        self_host: bool,
    ) -> Self {
        Self {
            ch,
            reader,
            rate_card,
            entitlements,
            self_host,
            cache: glance_cache(),
            storage_cache: moka::future::Cache::builder()
                .max_capacity(10_000)
                .expire_after(StorageExpiry)
                .build(),
        }
    }

    async fn tier_and_period(
        &self,
        tenant: &TenantId,
        now: DateTime<Utc>,
    ) -> (PlanTier, u32, WorkspaceGlancePolicy, period::BillingPeriod) {
        let resolved = match &self.entitlements {
            Some(cache) => Some(cache.resolved(*tenant.as_uuid()).await),
            None => None,
        };
        let tier = resolved.as_ref().map_or(PlanTier::Free, |e| {
            PlanTier::from_plan_key(&e.plan_lookup_key)
        });
        let mut policy = self.rate_card.load().policy.workspace_glance;
        let window_days = resolved.as_ref().map_or_else(
            || {
                // no control plane -> free window
                policy
                    .volume_window_days
                    .min(u32::try_from(crate::billing::rating::breakdown_defaults().1).unwrap_or(0))
            },
            |e| {
                policy
                    .volume_window_days
                    .min(u32::try_from(e.effective_window_days()).unwrap_or(0))
            },
        );
        policy.activity_window_days = resolved.as_ref().map_or_else(
            || {
                // no control plane -> free window
                policy
                    .activity_window_days
                    .min(u32::try_from(crate::billing::rating::breakdown_defaults().1).unwrap_or(0))
            },
            |e| {
                policy
                    .activity_window_days
                    .min(u32::try_from(e.effective_window_days()).unwrap_or(0))
            },
        );
        let period = period::billing_period(resolved.as_ref().and_then(|e| e.billing_period), now);
        (tier, window_days, policy, period)
    }

    async fn volume(
        &self,
        tenant: &TenantId,
        tier: PlanTier,
        now: DateTime<Utc>,
        window_days: u32,
    ) -> Volume {
        let start = now - chrono::Duration::days(i64::from(window_days));
        let filters = TraceListFilters {
            since_us: Some(start.timestamp_micros()),
            until_us: Some(now.timestamp_micros()),
            ..TraceListFilters::default()
        };
        let traces = self.reader.count_traces(tenant, &filters).await;
        let spans = self
            .ch
            .query(&capped_sql(tier, tenant, spans_sql()))
            .bind(tenant.to_string())
            .bind(start.timestamp_micros())
            .bind(now.timestamp_micros())
            .fetch_one::<CountRow>()
            .await;
        match (traces, spans) {
            (Ok(traces), Ok(spans)) => Volume {
                state: SectionState::Ok,
                window_days,
                traces: Some(traces),
                spans: Some(spans.total),
            },
            (Err(err), _) => Volume {
                state: state_from_error(&err),
                window_days,
                traces: None,
                spans: None,
            },
            (_, Err(err)) => Volume {
                state: section_error(&err),
                window_days,
                traces: None,
                spans: None,
            },
        }
    }

    async fn ingest(
        &self,
        tenant: &TenantId,
        tier: PlanTier,
        period: period::BillingPeriod,
    ) -> Ingest {
        let kind = if period.cycle.is_some() {
            "billing_cycle"
        } else {
            "calendar_month"
        };
        let start = period.start.to_string();
        if self.self_host {
            let result = self
                .ch
                .query(&capped_sql(
                    tier,
                    tenant,
                    "SELECT toUInt64(sum(span_bytes)) AS total FROM tracelane.spans \
                     WHERE tenant_id = ?",
                ))
                .bind(tenant.to_string())
                .fetch_one::<CountRow>()
                .await;
            return match result {
                Ok(row) => Ingest {
                    state: SectionState::Ok,
                    source: "spans",
                    total_bytes: Some(row.total as f64),
                    since: None,
                    period_bytes: None,
                    period_start: None,
                    period_kind: None,
                },
                Err(err) => Ingest {
                    state: section_error(&err),
                    source: "spans",
                    total_bytes: None,
                    since: None,
                    period_bytes: None,
                    period_start: None,
                    period_kind: None,
                },
            };
        }
        let total = self
            .ch
            .query(&capped_sql(tier, tenant, meter_sql()))
            .bind(tenant.to_string())
            .fetch_one::<MeterRow>()
            .await;
        let period_value = self
            .ch
            .query(&capped_sql(tier, tenant, period_meter_sql()))
            .bind(tenant.to_string())
            .bind(start.clone())
            .fetch_one::<SumRow>()
            .await;
        match (total, period_value) {
            (Ok(row), Ok(period_value)) if row.rows > 0 => Ingest {
                state: SectionState::Ok,
                source: "meter",
                total_bytes: Some(row.total),
                since: Some(row.first_day),
                period_bytes: Some(period_value.total),
                period_start: Some(start),
                period_kind: Some(kind),
            },
            (Ok(_), Ok(_)) => Ingest {
                state: SectionState::Unavailable,
                source: "meter",
                total_bytes: None,
                since: None,
                period_bytes: None,
                period_start: Some(start),
                period_kind: Some(kind),
            },
            (Err(err), _) | (_, Err(err)) => Ingest {
                state: section_error(&err),
                source: "meter",
                total_bytes: None,
                since: None,
                period_bytes: None,
                period_start: Some(start),
                period_kind: Some(kind),
            },
        }
    }

    async fn stored(&self, tenant: &TenantId, tier: PlanTier) -> Stored {
        if self.self_host {
            let result = self
                .ch
                .query(&capped_sql(
                    tier,
                    tenant,
                    "SELECT toUInt64(sum(span_bytes)) AS total FROM tracelane.spans \
                     WHERE tenant_id = ?",
                ))
                .bind(tenant.to_string())
                .fetch_one::<CountRow>()
                .await;
            return match result {
                Ok(row) => Stored {
                    state: SectionState::Ok,
                    kind: "span_bytes_sum",
                    bytes: Some(row.total as f64),
                    as_of: None,
                },
                Err(err) => Stored {
                    state: section_error(&err),
                    kind: "span_bytes_sum",
                    bytes: None,
                    as_of: None,
                },
            };
        }
        let result = self
            .ch
            .query(&capped_sql(
                tier,
                tenant,
                "SELECT value, toString(day) AS day_iso FROM tracelane.meter_gauges \
                 WHERE tenant_id = ? AND meter = 'hot_resident_bytes' \
                 ORDER BY day DESC, computed_at DESC LIMIT 1",
            ))
            .bind(tenant.to_string())
            .fetch_optional::<GaugeRow>()
            .await;
        match result {
            Ok(Some(row)) => Stored {
                state: SectionState::Ok,
                kind: "hot_resident_gauge",
                bytes: Some(row.value),
                as_of: Some(row.day_iso),
            },
            Ok(None) => Stored {
                state: SectionState::Unavailable,
                kind: "hot_resident_gauge",
                bytes: None,
                as_of: None,
            },
            Err(err) => Stored {
                state: section_error(&err),
                kind: "hot_resident_gauge",
                bytes: None,
                as_of: None,
            },
        }
    }

    async fn agents(
        &self,
        tenant: &TenantId,
        tier: PlanTier,
        now: DateTime<Utc>,
        window_days: u32,
    ) -> Agents {
        let start = now - chrono::Duration::days(i64::from(window_days));
        let result = self
            .ch
            .query(&capped_sql(tier, tenant, agent_sql()))
            .bind(tenant.to_string())
            .bind(start.timestamp_micros())
            .bind(now.timestamp_micros())
            .fetch_one::<AgentRow>()
            .await;
        match result {
            Ok(row) => Agents {
                state: SectionState::Ok,
                window_days,
                active: Some(row.active),
                direct_calls: Some(row.direct_calls),
            },
            Err(err) => Agents {
                state: section_error(&err),
                window_days,
                active: None,
                direct_calls: None,
            },
        }
    }

    async fn spend(
        &self,
        tenant: &TenantId,
        now: DateTime<Utc>,
        period: period::BillingPeriod,
    ) -> Spend {
        let start = period.start.to_string();
        let kind = if period.cycle.is_some() {
            "billing_cycle"
        } else {
            "calendar_month"
        };
        let since = period
            .start
            .and_hms_opt(0, 0, 0)
            .map(|v| v.and_utc().timestamp());
        let result = self
            .reader
            .cost_breakdown(
                tenant,
                &CostFilters {
                    meta_key: None,
                    since_secs: since,
                    until_secs: Some(now.timestamp()),
                    hours: 0,
                    dimension: CostDimension::Provider,
                    limit: crate::trace_reads::GATEWAY_PROVIDER_CAP,
                    scope: CostScope::All,
                },
            )
            .await;
        match result {
            Ok(rows) => Spend {
                state: SectionState::Ok,
                period_start: Some(start),
                period_kind: Some(kind),
                usd: Some(rows.first().map_or(0.0, |r| r.all_cost_usd)),
                unpriced_requests: Some(
                    rows.first()
                        .map_or(0, |r| r.all_requests.saturating_sub(r.all_priced_requests)),
                ),
            },
            Err(err) => Spend {
                state: state_from_error(&err),
                period_start: Some(start),
                period_kind: Some(kind),
                usd: None,
                unpriced_requests: None,
            },
        }
    }

    async fn providers(
        &self,
        tenant: &TenantId,
        tier: PlanTier,
        now: DateTime<Utc>,
        policy: WorkspaceGlancePolicy,
    ) -> Providers {
        let start = now - chrono::Duration::days(i64::from(policy.activity_window_days));
        let result = self
            .ch
            .query(&capped_sql(tier, tenant, provider_sql()))
            .bind(tenant.to_string())
            .bind(start.timestamp_micros())
            .bind(now.timestamp_micros())
            .bind(policy.providers_top)
            .fetch_all::<ProviderRow>()
            .await;
        match result {
            Ok(rows) => Providers {
                state: SectionState::Ok,
                window_days: policy.activity_window_days,
                count: Some(rows.first().map_or(0, |r| r.provider_count)),
                top: rows.into_iter().map(|r| r.provider).collect(),
            },
            Err(err) => Providers {
                state: section_error(&err),
                window_days: policy.activity_window_days,
                count: None,
                top: Vec::new(),
            },
        }
    }

    async fn storage(&self, tenant: &TenantId, tier: PlanTier, top: u32) -> Storage {
        // The boot-only self-host flag is checked by the sole call site. These
        // system tables describe the entire ClickHouse instance, never a tenant.
        let parts = self
            .ch
            .query(&capped_sql(tier, tenant, storage_parts_sql()))
            .fetch_all::<StoragePartRow>()
            .await;
        let disks = self
            .ch
            .query(&capped_sql(tier, tenant, storage_disks_sql()))
            .fetch_one::<DiskRow>()
            .await;
        let (parts, disk) = match (parts, disks) {
            (Ok(parts), Ok(disk)) => (parts, disk),
            (Err(err), _) | (_, Err(err)) => {
                return Storage {
                    state: section_error(&err),
                    compressed_bytes: None,
                    uncompressed_bytes: None,
                    index_bytes: None,
                    primary_index_bytes: None,
                    on_disk_bytes: None,
                    ratio: None,
                    tables: Vec::new(),
                    disk: None,
                };
            }
        };
        let compressed_bytes: u64 = parts.iter().map(|p| p.compressed_bytes).sum();
        let uncompressed_bytes: u64 = parts.iter().map(|p| p.uncompressed_bytes).sum();
        let index_bytes: u64 = parts.iter().map(|p| p.index_bytes).sum();
        let primary_index_bytes: u64 = parts.iter().map(|p| p.primary_index_bytes).sum();
        let on_disk_bytes: u64 = parts.iter().map(|p| p.on_disk_bytes).sum();
        Storage {
            state: SectionState::Ok,
            compressed_bytes: Some(compressed_bytes),
            uncompressed_bytes: Some(uncompressed_bytes),
            index_bytes: Some(index_bytes),
            primary_index_bytes: Some(primary_index_bytes),
            on_disk_bytes: Some(on_disk_bytes),
            ratio: (compressed_bytes > 0)
                .then_some(uncompressed_bytes as f64 / compressed_bytes as f64),
            tables: parts
                .into_iter()
                .take(top as usize)
                .map(|p| StorageTable {
                    name: p.name,
                    on_disk_bytes: p.on_disk_bytes,
                    rows: p.rows,
                })
                .collect(),
            disk: Some(Disk {
                free: disk.free,
                total: disk.total,
            }),
        }
    }

    async fn compute(
        &self,
        tenant: &TenantId,
        tier: PlanTier,
        now: DateTime<Utc>,
        policy: WorkspaceGlancePolicy,
        window_days: u32,
        period: period::BillingPeriod,
    ) -> Glance {
        let (volume, ingest, stored, agents, spend, providers) = tokio::join!(
            self.volume(tenant, tier, now, window_days),
            self.ingest(tenant, tier, period),
            self.stored(tenant, tier),
            self.agents(tenant, tier, now, policy.activity_window_days),
            self.spend(tenant, now, period),
            self.providers(tenant, tier, now, policy),
        );
        let storage = if self.self_host {
            let key = StorageKey {
                tenant: tenant.clone(),
                ttl_seconds: policy.storage_cache_ttl_seconds,
                tables_top: policy.storage_tables_top,
            };
            self.storage_cache
                .try_get_with(key, async {
                    Ok::<Arc<Storage>, anyhow::Error>(Arc::new(
                        self.storage(tenant, tier, policy.storage_tables_top).await,
                    ))
                })
                .await
                .ok()
                .map(|value| value.as_ref().clone())
        } else {
            None
        };
        let mut glance = Glance {
            as_of: now,
            cache_ttl_seconds: policy.cache_ttl_seconds,
            deployment: if self.self_host {
                "self_host"
            } else {
                "hosted"
            },
            volume,
            ingest,
            stored,
            agents,
            spend,
            providers,
            storage,
        };
        if !glance.cacheable() {
            glance.cache_ttl_seconds = 0;
        }
        glance
    }
}

pub fn routes(state: GlanceState) -> Router {
    Router::new()
        .route("/v1/workspace/glance", get(glance_handler))
        .with_state(state)
}

/// Authenticate the caller and require the read scope.
///
/// # Errors
/// Fails CLOSED: missing or invalid credentials return 401, auth-store failures
/// return 503, and a caller without read scope receives 403.
async fn authenticate(headers: &HeaderMap) -> Result<crate::auth::Claims, Response> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }
    let claims = crate::auth::validate_authorization(auth)
        .await
        .map_err(|err| crate::auth::failure(&err).0.into_response())?;
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    Ok(claims)
}

/// Return the tenant's independently computed overview sections.
///
/// # Errors
/// Authentication and authorization fail CLOSED with the response from
/// `authenticate`. Section reads fail OPEN: denied, capped or unavailable reads
/// retain their own state in a 200 response without hiding successful sections.
/// A cache-loader failure returns 502. The shared read-router limiter refuses
/// exhausted allowances with 429 and Retry-After before this handler runs.
async fn glance_handler(State(state): State<GlanceState>, headers: HeaderMap) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let tenant = claims.tenant_id;
    let now = Utc::now();
    let (tier, window_days, policy, period) = state.tier_and_period(&tenant, now).await;
    let key = GlanceKey {
        tenant: tenant.clone(),
        policy,
        window_days,
    };
    match state
        .cache
        .try_get_with(key, async {
            Ok::<Arc<Glance>, anyhow::Error>(Arc::new(
                state
                    .compute(&tenant, tier, now, policy, window_days, period)
                    .await,
            ))
        })
        .await
    {
        Ok(glance) => Json(glance.as_ref()).into_response(),
        Err(_) => axum::http::StatusCode::BAD_GATEWAY.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> GlanceState {
        let ch = Client::default();
        GlanceState::new(
            ch.clone(),
            Arc::new(crate::trace_reads::ClickHouseTraceReader::new(ch)),
            Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::billing::RateCard::unavailable(),
            )),
            None,
            false,
        )
    }

    #[tokio::test]
    async fn no_entitlements_uses_free_window() {
        let state = test_state();
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let (tier, window, _, _) = state.tier_and_period(&tenant, Utc::now()).await;
        assert!(matches!(tier, PlanTier::Free));
        let free_window = u32::try_from(crate::billing::rating::breakdown_defaults().1).unwrap();
        assert_eq!(window, free_window);

        let mut card = crate::billing::RateCard::unavailable();
        card.policy.workspace_glance.volume_window_days = free_window - 1;
        state.rate_card.store(Arc::new(card));
        let (_, window, _, _) = state.tier_and_period(&tenant, Utc::now()).await;
        assert_eq!(
            window,
            free_window - 1,
            "smaller policy window still applies"
        );
    }

    #[tokio::test]
    async fn glance_shares_tenant_and_key_read_limits_with_traces() {
        use crate::auth::{AuthMethod, dev_stub_claims, test_claims};
        use tower::ServiceExt;
        let mut state = test_state();
        let mut card = crate::billing::RateCard::unavailable();
        card.policy.trace_reads_tenant_key_multiplier = Some(2);
        state.rate_card.store(Arc::new(card));
        state.reader = Arc::new(
            crate::trace_reads::ClickHouseTraceReader::new(Client::default())
                .with_entitlements(None, Some(2))
                .with_rate_card(state.rate_card.clone()),
        );
        let tenant = dev_stub_claims(AuthMethod::ApiKey).tenant_id;
        let other = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        for tenant in [&tenant, &other] {
            let (_, window_days, policy, _) = state.tier_and_period(tenant, Utc::now()).await;
            state
                .cache
                .insert(
                    GlanceKey {
                        tenant: tenant.clone(),
                        policy,
                        window_days,
                    },
                    sample_glance(),
                )
                .await;
        }
        let trace_state = crate::trace_reads::TraceReadState {
            reader: state.reader.clone(),
            rejections: Arc::new(crate::rejection_metrics::RejectionRegistry::new()),
        };
        let app = crate::trace_reads::routes(trace_state, routes(state));
        for (tenant, method, key, path, expected) in [
            (
                &tenant,
                AuthMethod::ApiKey,
                "a",
                "/v1/workspace/glance",
                StatusCode::OK,
            ),
            (
                &tenant,
                AuthMethod::ApiKey,
                "a",
                "/v1/workspace/glance",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                &tenant,
                AuthMethod::ApiKey,
                "a",
                "/v1/traces",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                &tenant,
                AuthMethod::ApiKey,
                "b",
                "/v1/workspace/glance",
                StatusCode::OK,
            ),
            (
                &tenant,
                AuthMethod::ApiKey,
                "c",
                "/v1/workspace/glance",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                &tenant,
                AuthMethod::ApiKey,
                "d",
                "/v1/workspace/glance",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                &tenant,
                AuthMethod::ApiKey,
                "e",
                "/v1/workspace/glance",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                &other,
                AuthMethod::ApiKey,
                "a",
                "/v1/workspace/glance",
                StatusCode::OK,
            ),
            (
                &tenant,
                AuthMethod::JwtBearer,
                "session",
                "/v1/workspace/glance",
                StatusCode::OK,
            ),
            (
                &tenant,
                AuthMethod::JwtBearer,
                "session",
                "/v1/workspace/glance",
                StatusCode::OK,
            ),
            (
                &tenant,
                AuthMethod::JwtBearer,
                "session",
                "/v1/workspace/glance",
                StatusCode::TOO_MANY_REQUESTS,
            ),
        ] {
            let mut claims = dev_stub_claims(method);
            claims.tenant_id = tenant.clone();
            claims.sub = format!("apikey:{key}");
            claims.rate_limit_rpm = Some(1);
            let _guard = test_claims::Guard::set(claims);
            let request = axum::http::Request::builder()
                .uri(path)
                .header("authorization", "Bearer test")
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected, "{method:?} {key} {path}");
            if expected == StatusCode::TOO_MANY_REQUESTS {
                assert!(
                    response.headers()[header::RETRY_AFTER]
                        .to_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                        > 0
                );
            }
        }
    }

    #[tokio::test]
    async fn activity_windows_and_sql_follow_effective_retention() {
        use crate::entitlement_cache::{EntitlementCache, ResolvedEntitlements};
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        for (effective, volume_cap) in [(None, 30), (Some(2), 30), (Some(20), 1)] {
            server.reset().await;
            Mock::given(any())
                .respond_with(ResponseTemplate::new(503))
                .mount(&server)
                .await;
            let mut state = test_state();
            state.ch = Client::default()
                .with_url(server.uri())
                .with_compression(clickhouse::Compression::None);
            state.reader = Arc::new(crate::trace_reads::ClickHouseTraceReader::new(
                state.ch.clone(),
            ));
            let mut card = crate::billing::RateCard::unavailable();
            card.policy.workspace_glance.volume_window_days = volume_cap;
            let policy = card.policy.workspace_glance;
            state.rate_card.store(Arc::new(card));
            state.entitlements = effective.map(|days| {
                Arc::new(EntitlementCache::new(Arc::new(move |_| {
                    Box::pin(async move {
                        let mut ent = ResolvedEntitlements::deny_all();
                        ent.indexed_window_days = 30;
                        ent.auto_age_window_days = Some(days);
                        Ok(ent)
                    })
                })))
            });
            let claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
            let tenant = claims.tenant_id.clone();
            let _guard = crate::auth::test_claims::Guard::set(claims);
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, "Bearer test".parse().unwrap());
            let response = glance_handler(State(state), headers).await;
            assert_eq!(response.status(), StatusCode::OK, "sections fail open");
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let effective =
                u32::try_from(effective.unwrap_or(crate::billing::rating::breakdown_defaults().1))
                    .unwrap();
            assert_eq!(
                body["cache_ttl_seconds"], 0,
                "errored response must advertise no cache TTL"
            );
            let expected = policy.activity_window_days.min(effective);
            assert_eq!(
                body["agents"]["window_days"], expected,
                "agents must respect retention"
            );
            assert_eq!(
                body["providers"]["window_days"], expected,
                "providers must respect retention"
            );
            assert_eq!(body["volume"]["window_days"], volume_cap.min(effective));
            let now = DateTime::parse_from_rfc3339(body["as_of"].as_str().unwrap()).unwrap();
            let start = (now - chrono::Duration::days(i64::from(expected))).timestamp_micros();
            let requests = server.received_requests().await.unwrap();
            for marker in ["uniqExactIf(agent_key", "GROUP BY provider"] {
                let sql = requests
                    .iter()
                    .map(|r| {
                        r.url
                            .query_pairs()
                            .find(|(k, _)| k == "query")
                            .map(|(_, v)| v.into_owned())
                            .unwrap_or_else(|| String::from_utf8(r.body.clone()).unwrap())
                    })
                    .find(|q| q.contains(marker))
                    .expect("activity query was executed");
                assert!(
                    sql.contains(&format!("WHERE tenant_id = '{}'", tenant)),
                    "{sql}"
                );
                assert!(
                    sql.contains(&format!("start_time >= fromUnixTimestamp64Micro({start})")),
                    "{sql}"
                );
            }
        }
    }

    fn sample_glance() -> Arc<Glance> {
        Arc::new(Glance {
            as_of: Utc::now(),
            cache_ttl_seconds: WorkspaceGlancePolicy::default().cache_ttl_seconds,
            deployment: "hosted",
            volume: Volume {
                state: SectionState::Ok,
                window_days: 0,
                traces: None,
                spans: None,
            },
            ingest: Ingest {
                state: SectionState::Ok,
                source: "meter",
                total_bytes: None,
                since: None,
                period_bytes: None,
                period_start: None,
                period_kind: None,
            },
            stored: Stored {
                state: SectionState::Ok,
                kind: "hot_resident_gauge",
                bytes: None,
                as_of: None,
            },
            agents: Agents {
                state: SectionState::Ok,
                window_days: 0,
                active: None,
                direct_calls: None,
            },
            spend: Spend {
                state: SectionState::Ok,
                period_start: None,
                period_kind: None,
                usd: None,
                unpriced_requests: None,
            },
            providers: Providers {
                state: SectionState::Ok,
                window_days: 0,
                count: None,
                top: Vec::new(),
            },
            storage: None,
        })
    }

    fn sample_storage(state: SectionState) -> Arc<Storage> {
        Arc::new(Storage {
            state,
            compressed_bytes: None,
            uncompressed_bytes: None,
            index_bytes: None,
            primary_index_bytes: None,
            on_disk_bytes: None,
            ratio: None,
            tables: Vec::new(),
            disk: None,
        })
    }

    #[tokio::test]
    async fn failed_glance_sections_are_not_cached_but_successes_are() {
        let cache = glance_cache();
        let key = GlanceKey {
            tenant: TenantId::from_self_host_config(uuid::Uuid::new_v4()),
            policy: WorkspaceGlancePolicy::default(),
            window_days: 3,
        };
        for error in [
            SectionState::Unavailable,
            SectionState::Denied,
            SectionState::OverCap,
        ] {
            for section in 0..7 {
                let mut failed = sample_glance().as_ref().clone();
                match section {
                    0 => failed.volume.state = error,
                    1 => failed.ingest.state = error,
                    2 => failed.stored.state = error,
                    3 => failed.agents.state = error,
                    4 => failed.spend.state = error,
                    5 => failed.providers.state = error,
                    _ => failed.storage = Some(sample_storage(error).as_ref().clone()),
                }
                cache
                    .try_get_with(key.clone(), async {
                        Ok::<_, anyhow::Error>(Arc::new(failed))
                    })
                    .await
                    .unwrap();
                assert!(
                    cache.get(&key).await.is_none(),
                    "section {section} {error:?} must be retried"
                );
            }
        }
        cache.insert(key.clone(), sample_glance()).await;
        assert!(
            cache.get(&key).await.is_some(),
            "healthy hosted snapshot keeps its TTL"
        );
        let mut healthy = sample_glance().as_ref().clone();
        healthy.storage = Some(sample_storage(SectionState::Ok).as_ref().clone());
        cache.insert(key.clone(), Arc::new(healthy)).await;
        assert!(
            cache.get(&key).await.is_some(),
            "healthy self-host snapshot keeps its TTL"
        );
    }

    #[tokio::test]
    async fn failed_storage_is_not_cached_but_success_is() {
        let state = test_state();
        let policy = WorkspaceGlancePolicy::default();
        let key = StorageKey {
            tenant: TenantId::from_self_host_config(uuid::Uuid::new_v4()),
            ttl_seconds: policy.storage_cache_ttl_seconds,
            tables_top: policy.storage_tables_top,
        };
        for error in [
            SectionState::Unavailable,
            SectionState::Denied,
            SectionState::OverCap,
        ] {
            let returned = state
                .storage_cache
                .try_get_with(key.clone(), async {
                    Ok::<_, anyhow::Error>(sample_storage(error))
                })
                .await
                .unwrap();
            assert_eq!(
                returned.state, error,
                "failed section remains visible to the caller"
            );
            assert!(
                state.storage_cache.get(&key).await.is_none(),
                "{error:?} must be retried"
            );
        }
        state
            .storage_cache
            .insert(key.clone(), sample_storage(SectionState::Ok))
            .await;
        assert!(state.storage_cache.get(&key).await.is_some());
    }

    #[test]
    fn glance_sql_is_tenant_first_and_bounded() {
        for statement in [
            spans_sql().to_owned(),
            meter_sql().to_owned(),
            period_meter_sql().to_owned(),
            agent_sql(),
            provider_sql().to_owned(),
        ] {
            assert!(statement.contains("WHERE tenant_id = ?"), "{statement}");
            assert!(!statement.contains("tenant_id = '"), "{statement}");
        }
    }

    #[test]
    fn direct_api_calls_are_not_agents() {
        let statement = agent_sql();
        assert!(statement.contains("agent_key != ''"));
        assert!(statement.contains("agent_key = ''"));
        assert!(statement.contains(crate::kya_routes::CALL_SQL));
    }

    #[test]
    fn self_host_storage_is_instance_wide_and_never_tenant_attributed() {
        assert!(
            storage_parts_sql()
                .contains("FROM system.parts WHERE active = 1 AND database = 'tracelane'")
        );
        assert!(!storage_parts_sql().contains("tenant_id"));
        assert!(storage_disks_sql().contains("FROM system.disks"));
    }

    #[tokio::test]
    async fn concurrent_glance_reads_single_flight_per_tenant() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = glance_cache();
        let calls = Arc::new(AtomicUsize::new(0));
        let a = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let b = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let key = |tenant| GlanceKey {
            tenant,
            policy: WorkspaceGlancePolicy::default(),
            window_days: WorkspaceGlancePolicy::default().volume_window_days,
        };
        let tasks = (0..10).map(|_| {
            let cache = cache.clone();
            let calls = calls.clone();
            let key = key(a.clone());
            async move {
                cache
                    .try_get_with(key, async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok::<Arc<Glance>, anyhow::Error>(sample_glance())
                    })
                    .await
                    .expect("glance cache load")
            }
        });
        let values = futures::future::join_all(tasks).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(values.iter().all(|value| Arc::ptr_eq(value, &values[0])));
        cache
            .try_get_with(key(b), async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<Arc<Glance>, anyhow::Error>(sample_glance())
            })
            .await
            .expect("other tenant cache load");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL with schema and meter_counters"]
    async fn meter_read_is_tenant_isolated_on_a_real_clickhouse() {
        let url = std::env::var("CLICKHOUSE_TEST_URL")
            .expect("CLICKHOUSE_TEST_URL is required, not an optional pass");
        let client = Client::default().with_url(url).with_database("tracelane");
        let a = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let b = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        for (tenant, bytes) in [(&a, 3.0), (&b, 7.0)] {
            client
                .query(
                    "INSERT INTO tracelane.meter_counters \
                    (tenant_id, day, meter, dim, value, source) \
                    VALUES (?, today(), 'ingest_bytes', '', ?, 'glance-proof')",
                )
                .bind(tenant.to_string())
                .bind(bytes)
                .execute()
                .await
                .expect("insert isolated meter row");
        }
        let reader: Arc<dyn TraceReader> = Arc::new(
            crate::trace_reads::ClickHouseTraceReader::new(client.clone()),
        );
        let state = GlanceState::new(
            client,
            reader,
            Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::billing::RateCard::unavailable(),
            )),
            None,
            false,
        );
        let period = period::billing_period(None, Utc::now());
        let a_result = state.ingest(&a, PlanTier::Free, period).await;
        let b_result = state.ingest(&b, PlanTier::Free, period).await;
        assert_eq!(a_result.total_bytes, Some(3.0));
        assert_eq!(a_result.period_bytes, Some(3.0));
        assert_eq!(b_result.total_bytes, Some(7.0));
        let storage = state.storage(&a, PlanTier::Free, 8).await;
        assert_eq!(storage.state, SectionState::Ok);
        assert!(storage.disk.is_some());
        let now = Utc::now();
        assert_eq!(
            state.volume(&a, PlanTier::Free, now, 30).await.state,
            SectionState::Ok
        );
        assert_eq!(
            state.agents(&a, PlanTier::Free, now, 7).await.state,
            SectionState::Ok
        );
        let provider_start = now - chrono::Duration::days(7);
        let _: Vec<ProviderRow> = state
            .ch
            .query(&capped_sql(PlanTier::Free, &a, provider_sql()))
            .bind(a.to_string())
            .bind(provider_start.timestamp_micros())
            .bind(now.timestamp_micros())
            .bind(WorkspaceGlancePolicy::default().providers_top)
            .fetch_all()
            .await
            .expect("provider SQL must be accepted by ClickHouse");
        assert_eq!(
            state
                .providers(&a, PlanTier::Free, now, WorkspaceGlancePolicy::default())
                .await
                .state,
            SectionState::Ok
        );
        assert_eq!(state.spend(&a, now, period).await.state, SectionState::Ok);
    }
}
