//! Background cursor delivery from existing durable sources.
use super::*;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Instant;
/// Worker bounds. Read from the `siem_export` block of `translation_policy.v1.json`
/// (CLAUDE.md §23); `Default` parses it once, with the documented values as the fallback.
#[derive(Clone)]
pub struct Config {
    pub batch: usize,
    pub poll: Duration,
    pub visibility_lag: Duration,
    pub source_timeout: Duration,
    /// Wall-clock spent on one destination per tick; progress made inside it is kept.
    pub destination_budget: Duration,
    /// Destinations served at once, so one slow destination cannot stall the rest.
    pub concurrency: usize,
    pub delivery: DeliveryConfig,
}
fn fallback() -> Config {
    Config {
        batch: 100,
        poll: Duration::from_secs(301),
        visibility_lag: Duration::from_secs(30),
        source_timeout: Duration::from_secs(10),
        destination_budget: Duration::from_secs(30),
        concurrency: 8,
        delivery: DeliveryConfig {
            timeout: Duration::from_secs(5),
            max_bytes: 1024 * 1024,
            retry_delays: [0, 600, 1800].map(Duration::from_secs).to_vec(),
        },
    }
}
pub(crate) fn parse_table(raw: &str) -> Option<Config> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let v = v.get("siem_export")?;
    // Bounded both ways: a huge value would overflow `Instant + Duration` (panicking the worker)
    // or remove the fairness bound. 1 day / 64-way / 10k records / 16 MiB are far above use.
    let n = |k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .filter(|n| (1..=16 * 1024 * 1024).contains(n))
    };
    let secs = |k: &str| n(k).filter(|s| *s <= 86_400).map(Duration::from_secs);
    let u = |k: &str| n(k).and_then(|n| usize::try_from(n).ok());
    let retry_delays = v
        .get("retry_delays_secs")?
        .as_array()?
        .iter()
        .map(|d| d.as_u64().filter(|s| *s <= 86_400).map(Duration::from_secs))
        .collect::<Option<Vec<_>>>()?;
    Some(Config {
        batch: u("batch").filter(|b| *b <= 10_000)?,
        poll: secs("poll_secs")?,
        visibility_lag: secs("visibility_lag_secs")?,
        source_timeout: secs("source_timeout_secs")?,
        destination_budget: secs("destination_budget_secs")?,
        concurrency: u("concurrency").filter(|c| *c <= 64)?,
        delivery: DeliveryConfig {
            timeout: secs("timeout_secs")?,
            max_bytes: u("max_bytes")?,
            retry_delays,
        },
    })
}
impl Default for Config {
    fn default() -> Self {
        static C: std::sync::OnceLock<Config> = std::sync::OnceLock::new();
        C.get_or_init(|| {
            parse_table(include_str!("../../translation_policy.v1.json")).unwrap_or_else(|| {
                tracing::warn!(
                    "translation_policy.v1.json siem_export block did not parse — using the documented defaults"
                );
                fallback()
            })
        })
        .clone()
    }
}
/// Fail OPEN for gateway requests: called only by the independent background task.
/// Destinations run concurrently (bounded), each within its own wall-clock budget.
pub async fn tick(
    pool: &crate::db::DbPool,
    ch: Option<&clickhouse::Client>,
    ent: Option<&Arc<crate::entitlement_cache::EntitlementCache>>,
    config: &Config,
) -> Result<bool> {
    ensure!(
        config.batch > 0 && config.concurrency > 0 && config.poll.as_secs() > 300,
        "invalid SIEM worker bounds"
    );
    let Some(ent) = ent else {
        return Ok(false);
    };
    let mut due = Vec::new();
    for row in crate::db::otel_exports::directory(pool).await? {
        if row.format != "otlp" && ent.resolved(row.tenant_id).await.f_otel_export {
            due.push(row);
        }
    }
    let outcomes: Vec<Result<Drained>> = futures::stream::iter(due)
        .map(|row| drain(pool, ch, Some(ent), config, row))
        .buffer_unordered(config.concurrency)
        .collect()
        .await;
    let mut scan_failed = false;
    let mut backlog = false;
    for outcome in outcomes {
        backlog |= outcome.as_ref().is_ok_and(|d| d.backlog);
        // Err = a failed claim; skipped = records dropped as undeliverable.
        if !outcome.as_ref().is_ok_and(|d| !d.skipped) {
            scan_failed = true;
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::SiemExportFailed,
            );
        }
    }
    // Include paused failed destinations: one healthy destination cannot clear another.
    // `status` is CHECK-limited to never_delivered/ok/degraded (0076); paused = degraded + !enabled.
    let unresolved: bool = pool
        .get()
        .await?
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM otel_exports WHERE format<>'otlp' AND status='degraded')",
            &[],
        )
        .await?
        .get(0);
    if !scan_failed && !unresolved {
        tracelane_shared::degradation::resolve(
            tracelane_shared::degradation::Degradation::SiemExportFailed,
        );
    }
    Ok(backlog)
}
struct Drained {
    skipped: bool,
    /// The budget ran out with records still pending: the caller should come back soon.
    backlog: bool,
}
/// Claims batches for one destination until it is caught up, fails, or its budget is spent.
async fn drain(
    pool: &crate::db::DbPool,
    ch: Option<&clickhouse::Client>,
    ent: Option<&Arc<crate::entitlement_cache::EntitlementCache>>,
    c: &Config,
    row: crate::db::otel_exports::Sealed,
) -> Result<Drained> {
    let deadline = Instant::now() + c.destination_budget;
    let mut skipped = false;
    loop {
        let step = one(pool, ch, ent, c, &row, deadline).await?;
        skipped |= step.skipped;
        if !step.more || Instant::now() >= deadline {
            return Ok(Drained {
                skipped,
                backlog: step.more,
            });
        }
    }
}
/// The full cursor state after a source item has been handled.
#[derive(Clone)]
struct Cursor {
    action: i64,
    span_ms: i64,
    span_trace: String,
    span_id: String,
}
struct Step {
    more: bool,
    skipped: bool,
}
async fn one(
    pool: &crate::db::DbPool,
    ch: Option<&clickhouse::Client>,
    ent: Option<&Arc<crate::entitlement_cache::EntitlementCache>>,
    c: &Config,
    row: &crate::db::otel_exports::Sealed,
    deadline: Instant,
) -> Result<Step> {
    let idle = Step {
        more: false,
        skipped: false,
    };
    let token = Uuid::new_v4();
    let budget = i32::try_from(
        c.delivery
            .retry_delays
            .len()
            .checked_add(1)
            .context("retry overflow")?,
    )?;
    // An expired final reservation consumed the budget even if its process crashed.
    let paused = pool.get().await?.execute(
        "UPDATE otel_exports SET enabled=false,status='degraded',last_error_class='siem_attempt_interrupted',lease_token=NULL,lease_until='epoch' WHERE tenant_id=$1 AND id=$2 AND enabled AND updated_at=$3 AND lease_until<=now() AND delivery_attempts>=$4",
        &[&row.tenant_id,&row.id,&row.updated_at,&budget]).await?;
    if paused != 0 {
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::SiemExportFailed,
        );
        return Ok(idle);
    }
    // The destination budget plus one send timeout of slack. Fencing is authoritative.
    let lease = (c.destination_budget + c.source_timeout + c.delivery.timeout).as_secs_f64();
    let Some(claim) = pool.get().await?.query_opt(
        "UPDATE otel_exports SET delivery_attempts=delivery_attempts+1,lease_token=$3,lease_until=now()+($4::double precision * interval '1 second') WHERE tenant_id=$1 AND id=$2 AND enabled AND updated_at=$5 AND retry_at<=now() AND lease_until<=now() AND delivery_attempts<$6 RETURNING action_cursor,span_cursor_ms,span_cursor_trace,span_cursor_id,delivery_attempts",
        &[&row.tenant_id,&row.id,&token,&lease,&row.updated_at,&budget]).await? else { return Ok(idle); };
    let start = Cursor {
        action: claim.get(0),
        span_ms: claim.get(1),
        span_trace: claim.get(2),
        span_id: claim.get(3),
    };
    let attempts: i32 = claim.get(4);
    let mut done = start.clone();
    let (mut delivered, mut skipped, mut more) = (0_i64, 0_i64, false);
    // False until the first send: a failure before it is OURS (source read, key, config), never
    // the destination's, so it must not spend the destination's retry budget or pause it.
    let mut sending = false;
    let result: Result<()> = async {
        let mut items = Vec::new();
        let mut at = start.clone();
        let rows = pool.get().await?.query(
            "SELECT seq,event_type,payload FROM audit_log_rows WHERE tenant_id=$1 AND seq>$2 ORDER BY seq LIMIT $3",
            &[&row.tenant_id,&start.action,&i64::try_from(c.batch)?]).await?;
        more |= rows.len() >= c.batch;
        for r in rows {
            at.action = r.get(0);
            let record = if tracelane_audit_verifier::action::bundle::is_action(r.get::<_, &str>(1)) {
                // An undeliverable row is skipped and counted, never retried forever.
                match serde_json::from_str::<Envelope>(r.get::<_, &str>(2)).map_err(anyhow::Error::from).and_then(|e| action_record(row.tenant_id, &e)) {
                    Ok(record) => Some(Ok(record)),
                    Err(_) => Some(Err(())),
                }
            } else {
                None
            };
            items.push((record, at.clone()));
        }
        if let Some(ch) = ch {
            let tenant = tracelane_shared::TenantId::from_jwt_claim(row.tenant_id);
            let tier = crate::clickhouse_query::tier_for_tenant(ent, &tenant).await;
            let spans = tokio::time::timeout(
                c.source_timeout,
                span_batch(ch, row.tenant_id, start.span_ms, &start.span_trace, &start.span_id, tier, c),
            )
            .await
            .context("SIEM span source timed out")??;
            more |= spans.items.len() >= c.batch;
            for s in spans.items {
                at.span_ms = s.ms;
                at.span_trace = s.trace;
                at.span_id = s.id;
                items.push((Some(s.record.ok_or(())), at.clone()));
            }
        }
        let kind = connector(&row.format)?;
        let headers = crate::otel_export::open_headers(crate::byok::master_key(),row.tenant_id,row.id,row.headers_enc.as_deref()).map_err(anyhow::Error::msg)?;
        let destination = Destination { tenant: row.tenant_id, id: row.id, kind, url: row.url.clone(),
            credential: credential(kind, headers.iter().map(|(k,v)| (k.as_str(),v.expose_secret())))? };
        let single = DeliveryConfig { timeout: c.delivery.timeout, max_bytes: c.delivery.max_bytes, retry_delays: Vec::new() };
        sending = true;
        for (record, after) in items {
            if Instant::now() >= deadline {
                more = true;
                break;
            }
            match record {
                Some(Ok(record)) if fits(kind, &record, &single) => {
                    deliver(&destination, &record, &single).await?;
                    delivered += 1;
                }
                Some(_) => skipped += 1,
                None => {}
            }
            done = after;
        }
        Ok(())
    }.await;
    let progressed = done.action != start.action
        || done.span_ms != start.span_ms
        || done.span_trace != start.span_trace
        || done.span_id != start.span_id;
    // Progress made before a failure is kept (at-least-once), and resets the retry budget.
    let error_class = (skipped > 0).then_some("siem_record_skipped");
    match result {
        Ok(()) => {
            pool.get().await?.execute(
                "UPDATE otel_exports SET action_cursor=$4,span_cursor_ms=$5,span_cursor_trace=$6,span_cursor_id=$7,delivery_attempts=0,lease_token=NULL,lease_until='epoch',retry_at=now(),status='ok',last_error_class=$10,delivered=delivered+$8,failed=failed+$11,last_success_at=CASE WHEN $8>0 THEN now() ELSE last_success_at END WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND updated_at=$9",
                &[&row.tenant_id,&row.id,&token,&done.action,&done.span_ms,&done.span_trace,&done.span_id,&delivered,&row.updated_at,&error_class,&skipped]).await?;
            Ok(Step {
                more,
                skipped: skipped > 0,
            })
        }
        Err(e) if !sending => {
            // Our side failed before any send: release the lease, give back the claimed attempt,
            // keep the destination enabled, retry next tick. Counted, and labelled as ours.
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::SiemExportFailed,
            );
            pool.get().await?.execute(
                "UPDATE otel_exports SET delivery_attempts=GREATEST(delivery_attempts-1,0),lease_token=NULL,lease_until='epoch',retry_at=now(),status='degraded',last_error_class='siem_source_unavailable' WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND updated_at=$4",
                &[&row.tenant_id,&row.id,&token,&row.updated_at]).await?;
            Err(e)
        }
        Err(e) => {
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::SiemExportFailed,
            );
            let attempts = if progressed { 1 } else { attempts };
            let exhausted = attempts >= budget;
            let delay = c
                .delivery
                .retry_delays
                .get(usize::try_from(attempts - 1)?)
                .copied()
                .unwrap_or_default()
                .as_secs_f64();
            pool.get().await?.execute(
                "UPDATE otel_exports SET action_cursor=$7,span_cursor_ms=$8,span_cursor_trace=$9,span_cursor_id=$10,delivered=delivered+$11,failed=failed+$12+CASE WHEN $5 THEN 1 ELSE 0 END,delivery_attempts=$13,lease_token=NULL,lease_until='epoch',retry_at=now()+($4::double precision * interval '1 second'),enabled=NOT $5,status='degraded',last_error_class='siem_delivery_failed' WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND updated_at=$6",
                &[&row.tenant_id,&row.id,&token,&delay,&exhausted,&row.updated_at,&done.action,&done.span_ms,&done.span_trace,&done.span_id,&delivered,&skipped,&attempts]).await?;
            Err(e)
        }
    }
}
/// A record whose encoded form cannot be built or exceeds the size bound can never be
/// delivered; it is skipped and counted rather than retried until the destination pauses.
fn fits(kind: Connector, r: &Record, c: &DeliveryConfig) -> bool {
    payload(kind, r)
        .ok()
        .and_then(|p| serde_json::to_vec(&p).ok())
        .is_some_and(|b| b.len() <= c.max_bytes)
}
/// No request handler calls tick or waits for this task.
pub fn spawn(
    pool: crate::db::DbPool,
    ch: Option<clickhouse::Client>,
    ent: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
) {
    tokio::spawn(async move {
        let config = Config::default();
        loop {
            // A destination that ran out of budget with records pending is revisited after the
            // short visibility lag instead of a full poll, so a busy tenant does not fall behind
            // without bound; with no backlog the worker sleeps the full (>300 s) poll.
            let backlog = match tick(&pool, ch.as_ref(), ent.as_ref(), &config).await {
                Ok(backlog) => backlog,
                Err(_) => {
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::SiemExportFailed,
                    );
                    false
                }
            };
            tokio::time::sleep(if backlog {
                config.visibility_lag
            } else {
                config.poll
            })
            .await;
        }
    });
}
/// One span source row: the record, or `None` when the row cannot be converted (counted and
/// skipped by the worker), with the cursor position after it.
pub struct SpanItem {
    pub record: Option<Record>,
    pub ms: i64,
    pub trace: String,
    pub id: String,
}
pub struct SpanBatch {
    pub items: Vec<SpanItem>,
    pub cursor_ms: i64,
    pub cursor_id: String,
    pub cursor_trace: String,
}
#[cfg(test)]
impl SpanBatch {
    pub fn records(&self) -> Vec<&Record> {
        self.items
            .iter()
            .filter_map(|i| i.record.as_ref())
            .collect()
    }
}
#[derive(clickhouse::Row, Deserialize)]
struct SpanRow {
    tenant_id: String,
    span_id: String,
    trace_id: String,
    start_us: i64,
    attributes: String,
    ingested_ms: i64,
}
pub async fn span_batch(
    ch: &clickhouse::Client,
    tenant: Uuid,
    ms: i64,
    trace: &str,
    id: &str,
    tier: crate::clickhouse_query::PlanTier,
    config: &Config,
) -> Result<SpanBatch> {
    let sql = crate::clickhouse_query::TenantQuery::new(
        "SELECT tenant_id,span_id,trace_id,toUnixTimestamp64Micro(start_time) AS start_us,attributes,toUnixTimestamp64Milli(ingested_at) AS ingested_ms FROM spans FINAL WHERE tenant_id=? AND (toUnixTimestamp64Milli(ingested_at),trace_id,span_id)>(?,?,?) AND ingested_at<=now64(3)-toIntervalMillisecond(?) ORDER BY ingested_at,trace_id,span_id LIMIT ?", tier
    ).sql_with_settings();
    let rows = ch
        .query(&sql)
        .bind(tenant.to_string())
        .bind(ms)
        .bind(trace)
        .bind(id)
        .bind(u64::try_from(config.visibility_lag.as_millis())?)
        .bind(u64::try_from(config.batch)?)
        .fetch_all::<SpanRow>()
        .await?;
    let mut batch = SpanBatch {
        items: Vec::new(),
        cursor_ms: ms,
        cursor_trace: trace.into(),
        cursor_id: id.into(),
    };
    for row in rows {
        // Fail CLOSED: a tenant-filtered read returning another tenant's row stops the batch.
        ensure!(
            row.tenant_id == tenant.to_string(),
            "SIEM source tenant mismatch"
        );
        let record = span_from_row(tenant, &row).ok();
        batch.cursor_ms = row.ingested_ms;
        batch.cursor_trace.clone_from(&row.trace_id);
        batch.cursor_id.clone_from(&row.span_id);
        batch.items.push(SpanItem {
            record,
            ms: row.ingested_ms,
            trace: row.trace_id,
            id: row.span_id,
        });
    }
    Ok(batch)
}
fn span_from_row(tenant: Uuid, row: &SpanRow) -> Result<Record> {
    let span = TracelaneSpan {
        tenant_id: tracelane_shared::TenantId::from_jwt_claim(tenant),
        span_id: Uuid::parse_str(&row.span_id)?,
        trace_id: Uuid::parse_str(&row.trace_id)?,
        parent_span_id: None,
        name: String::new(),
        start_time: DateTime::from_timestamp_micros(row.start_us).context("invalid span time")?,
        end_time: None,
        attributes: serde_json::from_str(&row.attributes)?,
        status: tracelane_shared::SpanStatus {
            code: tracelane_shared::SpanStatusCode::Unset,
            message: None,
        },
    };
    span_record(&span)
}
