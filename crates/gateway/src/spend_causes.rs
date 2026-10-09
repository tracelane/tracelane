//! Attribution within one spend bucket, with raw-span totals kept separate from MV totals.
use crate::billing::rating::SpendSpikeParams;
use crate::spend_spikes::{Granularity, iso, median};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Dimension {
    #[default]
    Model,
    Key,
    Provider,
    Environment,
    Service,
    User,
    Tag,
}
impl Dimension {
    pub fn name(self) -> String {
        match self {
            Self::Model => "model",
            Self::Key => "key",
            Self::Provider => "provider",
            Self::Environment => "environment",
            Self::Service => "service",
            Self::User => "user",
            Self::Tag => "tag",
        }
        .into()
    }
    pub fn column(self) -> String {
        match self {
            Self::Model => "coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.request.model'), ''), JSONExtractString(attributes, 'llm.model_name'))",
            Self::Key => "api_key_id",
            Self::Provider => crate::trace_reads::MV_PROVIDER_EXPR,
            Self::Environment => "environment",
            Self::Service => "service",
            Self::User => "JSONExtractString(attributes, 'user_id')",
            Self::Tag => "arrayJoin(if(empty(tags), [''], arrayDistinct(tags)))",
        }
        .into()
    }
    pub fn aggregate_column(self) -> Option<String> {
        match self {
            Self::Model => Some("model".into()),
            Self::Key => Some("api_key_id".into()),
            Self::Environment => Some("environment".into()),
            Self::Service => Some("service".into()),
            _ => None,
        }
    }
}
#[derive(Debug, Default, Deserialize, clickhouse::Row)]
pub(crate) struct Summary {
    pub cost_usd: f64,
    pub requests: u64,
    pub unpriced_requests: u64,
    pub unlabelled_cost_usd: f64,
    pub has_model: u64,
    pub has_key: u64,
    pub has_provider: u64,
    pub has_environment: u64,
    pub has_service: u64,
    pub has_user: u64,
    pub has_tag: u64,
    pub overlapping_tags: u64,
}
#[derive(Debug, Clone, Default, Deserialize, clickhouse::Row)]
pub(crate) struct CauseRow {
    pub dimension: String,
    pub cost_usd: f64,
    pub requests: u64,
    pub unpriced_requests: u64,
    pub all_cost: f64,
    pub all_requests: u64,
    pub all_unpriced: u64,
}
#[derive(Debug, Deserialize, clickhouse::Row)]
pub(crate) struct BaselineRow {
    pub bucket_secs: i64,
    pub dimension: String,
    pub cost_usd: f64,
    pub requests: u64,
}
#[derive(Debug, Serialize)]
pub(crate) struct Cause {
    pub dimension: String,
    pub cost_usd: f64,
    pub share_pct: Option<f64>,
    pub requests: u64,
    pub unpriced_requests: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excess_usd: Option<f64>,
    pub traces_href: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct BucketTotals {
    pub start: String,
    pub end: String,
    pub cost_usd_series: f64,
    pub cost_usd_spans: f64,
}
#[derive(Debug, Serialize)]
pub(crate) struct Unattributed {
    pub unpriced_requests: u64,
    pub unlabelled_cost_usd: f64,
}
#[derive(Debug, Serialize)]
pub(crate) struct Causes {
    pub by: Dimension,
    pub bucket: BucketTotals,
    pub available_dimensions: Vec<String>,
    pub rows: Vec<Cause>,
    pub unattributed: Unattributed,
    pub overlapping_dimensions: bool,
}
pub(crate) fn summary_sql(by: Dimension) -> String {
    let missing = if by == Dimension::Tag {
        "empty(tags)".to_owned()
    } else {
        format!("empty({})", by.column())
    };
    let model = Dimension::Model.column();
    let provider = Dimension::Provider.column();
    format!(
        "SELECT sumIf(source.cost_usd, source.cost_usd_present = 1 AND isFinite(source.cost_usd)) AS cost_usd, \
count() AS requests, countIf(NOT (source.cost_usd_present = 1 AND isFinite(source.cost_usd))) AS unpriced_requests, \
sumIf(source.cost_usd, source.cost_usd_present = 1 AND isFinite(source.cost_usd) AND {missing}) AS unlabelled_cost_usd, \
countIf({model} != '') AS has_model, countIf(api_key_id != '') AS has_key, \
countIf({provider} != '') AS has_provider, countIf(environment != '') AS has_environment, \
countIf(service != '') AS has_service, countIf(JSONExtractString(attributes, 'user_id') != '') AS has_user, countIf(notEmpty(tags)) AS has_tag, \
countIf(length(arrayDistinct(tags)) > 1) AS overlapping_tags \
FROM tracelane.spans AS source FINAL WHERE tenant_id = ? AND start_time >= fromUnixTimestamp(?) AND start_time < fromUnixTimestamp(?) AND {provider} <> ''"
    )
}
pub(crate) fn rows_sql(by: Dimension, limit: u32) -> String {
    let provider = Dimension::Provider.column();
    format!(
        "SELECT {} AS dimension, sumIf(source.cost_usd, source.cost_usd_present = 1 AND isFinite(source.cost_usd)) AS cost_usd, \
count() AS requests, countIf(NOT (source.cost_usd_present = 1 AND isFinite(source.cost_usd))) AS unpriced_requests, \
sum(sumIf(source.cost_usd, source.cost_usd_present = 1 AND isFinite(source.cost_usd))) OVER () AS all_cost, \
sum(count()) OVER () AS all_requests, sum(countIf(NOT (source.cost_usd_present = 1 AND isFinite(source.cost_usd)))) OVER () AS all_unpriced \
FROM tracelane.spans AS source FINAL WHERE tenant_id = ? AND start_time >= fromUnixTimestamp(?) AND start_time < fromUnixTimestamp(?) AND {provider} <> '' \
GROUP BY dimension ORDER BY cost_usd DESC, dimension LIMIT {limit}",
        by.column()
    )
}
pub(crate) fn baseline_sql(by: Dimension, granularity: Granularity) -> Option<String> {
    let column = by.aggregate_column()?;
    Some(format!(
        "SELECT toInt64(toUnixTimestamp({}(bucket_hour))) AS bucket_secs, {column} AS dimension, sum(cost_usd) AS cost_usd, toUInt64(sum(requests)) AS requests \
FROM tracelane.spend_hourly WHERE tenant_id = ? AND bucket_hour >= fromUnixTimestamp(?) AND bucket_hour < fromUnixTimestamp(?) AND {column} IN ? GROUP BY bucket_secs, dimension",
        granularity.bucket_sql()
    ))
}
/// Builds contributor evidence without inventing missing prices.
/// # Errors
/// Fails CLOSED on non-finite costs or inconsistent counts; the endpoint returns unavailable.
pub(crate) fn build(
    by: Dimension,
    bucket: (i64, Granularity),
    params: SpendSpikeParams,
    series: f64,
    summary: Summary,
    rows: Vec<CauseRow>,
    baseline: Vec<BaselineRow>,
) -> anyhow::Result<Causes> {
    let (start, granularity) = bucket;
    anyhow::ensure!(
        series.is_finite()
            && summary.cost_usd.is_finite()
            && summary.unlabelled_cost_usd.is_finite()
            && rows
                .iter()
                .all(|r| r.cost_usd.is_finite() && r.all_cost.is_finite())
            && baseline.iter().all(|r| r.cost_usd.is_finite()),
        "non-finite spend attribution"
    );
    anyhow::ensure!(
        summary.unpriced_requests <= summary.requests,
        "inconsistent request counts"
    );
    let mut result = Vec::new();
    let mut top_cost = 0.;
    let mut top_requests = 0u64;
    let mut top_unpriced = 0u64;
    let (all_cost, all_requests, all_unpriced) = rows
        .first()
        .map(|r| (r.all_cost, r.all_requests, r.all_unpriced))
        .unwrap_or_default();
    for r in rows {
        top_cost += r.cost_usd;
        top_requests = top_requests.saturating_add(r.requests);
        top_unpriced = top_unpriced.saturating_add(r.unpriced_requests);
        let historic: std::collections::BTreeMap<_, _> = baseline
            .iter()
            .filter(|b| b.dimension == r.dimension)
            .map(|b| (b.bucket_secs, b))
            .collect();
        let own_baseline = if by.aggregate_column().is_some()
            && historic.values().filter(|b| b.requests > 0).count()
                >= params.min_history_buckets as usize
        {
            let step = granularity.seconds();
            let from = start - i64::from(params.baseline_buckets) * step;
            let mut costs: Vec<_> = (from..start)
                .step_by(step as usize)
                .map(|t| historic.get(&t).map_or(0., |b| b.cost_usd))
                .collect();
            median(&mut costs)
        } else {
            None
        };
        result.push(Cause {
            dimension: if r.dimension.is_empty() {
                "(not set)".into()
            } else {
                r.dimension
            },
            cost_usd: r.cost_usd,
            share_pct: (summary.cost_usd != 0.)
                .then(|| 100. * (r.cost_usd / summary.cost_usd))
                .filter(|v| v.is_finite()),
            requests: r.requests,
            unpriced_requests: r.unpriced_requests,
            baseline_usd: own_baseline,
            excess_usd: own_baseline.map(|b| r.cost_usd - b),
            traces_href: None,
        });
    }
    if all_requests > top_requests {
        let cost = (all_cost - top_cost).max(0.);
        result.push(Cause {
            dimension: "(other)".into(),
            cost_usd: cost,
            share_pct: (summary.cost_usd != 0.)
                .then(|| 100. * (cost / summary.cost_usd))
                .filter(|v| v.is_finite()),
            requests: all_requests - top_requests,
            unpriced_requests: all_unpriced.saturating_sub(top_unpriced),
            baseline_usd: None,
            excess_usd: None,
            traces_href: None,
        });
    }
    let available_dimensions = [
        (Dimension::Model, summary.has_model),
        (Dimension::Key, summary.has_key),
        (Dimension::Provider, summary.has_provider),
        (Dimension::Environment, summary.has_environment),
        (Dimension::Service, summary.has_service),
        (Dimension::User, summary.has_user),
        (Dimension::Tag, summary.has_tag),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .map(|(d, _)| d.name())
    .collect();
    Ok(Causes {
        by,
        bucket: BucketTotals {
            start: iso(start),
            end: iso(start + granularity.seconds()),
            cost_usd_series: series,
            cost_usd_spans: summary.cost_usd,
        },
        available_dimensions,
        rows: result,
        unattributed: Unattributed {
            unpriced_requests: summary.unpriced_requests,
            unlabelled_cost_usd: summary.unlabelled_cost_usd,
        },
        overlapping_dimensions: by == Dimension::Tag && summary.overlapping_tags > 0,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spend_counts_only_llm_spans_and_normalizes_dimensions() {
        let model = Dimension::Model.column();
        for key in [
            "gen_ai_request_model",
            "gen_ai.request.model",
            "llm.model_name",
        ] {
            assert!(model.contains(key), "missing model alias {key}");
        }
        assert!(Dimension::Provider.column().contains("gen_ai_system"));
        for by in [
            Dimension::Model,
            Dimension::Key,
            Dimension::Provider,
            Dimension::Environment,
            Dimension::Service,
            Dimension::User,
            Dimension::Tag,
        ] {
            for sql in [summary_sql(by), rows_sql(by, 10)] {
                assert!(
                    sql.contains(&format!("AND {} <> ''", Dimension::Provider.column())),
                    "LLM-only predicate missing: {sql}"
                );
            }
        }
        assert!(
            summary_sql(Dimension::Model).contains(&format!("countIf({model} != '') AS has_model"))
        );
    }
    #[test]
    fn shares_include_missing_labels_and_other_and_never_invent_user_excess() {
        let p = crate::billing::rating::SpendSpikePolicy::embedded()
            .unwrap()
            .hour;
        let response = build(
            Dimension::User,
            (0, Granularity::Hour),
            p,
            11.,
            Summary {
                cost_usd: 10.,
                requests: 4,
                unpriced_requests: 1,
                unlabelled_cost_usd: 3.,
                has_user: 2,
                ..Default::default()
            },
            vec![
                CauseRow {
                    dimension: "u".into(),
                    cost_usd: 5.,
                    requests: 1,
                    all_cost: 10.,
                    all_requests: 4,
                    all_unpriced: 1,
                    ..Default::default()
                },
                CauseRow {
                    cost_usd: 3.,
                    requests: 2,
                    unpriced_requests: 1,
                    all_cost: 10.,
                    all_requests: 4,
                    all_unpriced: 1,
                    ..Default::default()
                },
            ],
            vec![],
        )
        .unwrap();
        assert_eq!(response.rows.len(), 3);
        assert_eq!(
            response
                .rows
                .iter()
                .map(|r| r.share_pct.unwrap())
                .sum::<f64>(),
            100.
        );
        assert_eq!(response.unattributed.unpriced_requests, 1);
        assert!(response.rows.iter().all(|r| r.baseline_usd.is_none()
            && r.excess_usd.is_none()
            && r.traces_href.is_none()));
        let value = serde_json::to_value(response).unwrap();
        assert!(value["rows"][0].get("excess_usd").is_none());
    }
    #[test]
    fn all_cause_reads_are_tenant_first_and_bounded() {
        for d in [
            Dimension::Model,
            Dimension::Key,
            Dimension::Provider,
            Dimension::Environment,
            Dimension::Service,
            Dimension::User,
            Dimension::Tag,
        ] {
            for sql in [summary_sql(d), rows_sql(d, 10)] {
                assert!(sql.contains("WHERE tenant_id = ? AND start_time >= fromUnixTimestamp(?) AND start_time < fromUnixTimestamp(?)"));
                assert!(sql.contains(" FINAL "));
            }
            if let Some(sql) = baseline_sql(d, Granularity::Day) {
                assert!(sql.contains("WHERE tenant_id = ? AND bucket_hour >="));
                assert!(sql.contains("IN ?"));
            }
        }
        assert!(baseline_sql(Dimension::Provider, Granularity::Hour).is_none());
    }
}
