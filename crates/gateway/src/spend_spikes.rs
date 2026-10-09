//! Spend series and read-time spike evidence. Costs never substitute for missing prices.
use crate::billing::rating::SpendSpikeParams;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Granularity {
    #[default]
    Hour,
    Day,
}
impl Granularity {
    pub fn seconds(self) -> i64 {
        match self {
            Self::Hour => 3600,
            Self::Day => 86400,
        }
    }
    pub fn params(self, policy: crate::billing::rating::SpendSpikePolicy) -> SpendSpikeParams {
        match self {
            Self::Hour => policy.hour,
            Self::Day => policy.day,
        }
    }
    pub fn bucket_sql(self) -> String {
        match self {
            Self::Hour => "toStartOfHour",
            Self::Day => "toStartOfDay",
        }
        .to_owned()
    }
}
#[derive(Debug, Clone, Default, Deserialize, clickhouse::Row)]
pub(crate) struct BucketRow {
    pub bucket_secs: i64,
    pub cost_usd: f64,
    pub priced_requests: u64,
    pub unpriced_requests: u64,
    pub requests: u64,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Bucket {
    pub bucket_start: String,
    pub cost_usd: f64,
    pub priced_requests: u64,
    pub unpriced_requests: u64,
    pub requests: u64,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Spike {
    pub bucket_start: String,
    pub cost_usd: f64,
    pub baseline_usd: f64,
    pub ratio: Option<f64>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Series {
    pub granularity: Granularity,
    pub min_history_buckets: u32,
    pub baseline_buckets: u32,
    pub buckets: Vec<Bucket>,
    pub spikes: Vec<Spike>,
    pub history: String,
    pub window: Window,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Window {
    pub since: String,
    pub until: String,
    pub clamped: bool,
}
pub(crate) fn iso(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}
pub(crate) fn series_sql(granularity: Granularity) -> String {
    format!(
        "SELECT toInt64(toUnixTimestamp({}(bucket_hour))) AS bucket_secs, \
sum(cost_usd) AS cost_usd, toUInt64(sum(priced_requests)) AS priced_requests, \
toUInt64(sum(unpriced_requests)) AS unpriced_requests, toUInt64(sum(requests)) AS requests \
FROM tracelane.spend_hourly WHERE tenant_id = ? AND bucket_hour >= fromUnixTimestamp(?) AND bucket_hour < fromUnixTimestamp(?) \
GROUP BY bucket_secs ORDER BY bucket_secs",
        granularity.bucket_sql()
    )
}
pub(crate) fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    Some(if values.len().is_multiple_of(2) {
        values[mid - 1] / 2. + values[mid] / 2.
    } else {
        values[mid]
    })
}
pub(crate) fn detect_spikes(
    buckets: &[BucketRow],
    params: SpendSpikeParams,
    since: i64,
) -> (Vec<Spike>, bool) {
    let mut spikes = Vec::new();
    let mut enough = false;
    for (i, bucket) in buckets
        .iter()
        .enumerate()
        .filter(|(_, b)| b.bucket_secs >= since)
    {
        let history = &buckets[i.saturating_sub(params.baseline_buckets as usize)..i];
        if history.iter().filter(|b| b.requests > 0).count() < params.min_history_buckets as usize {
            continue;
        }
        enough = true;
        let mut values: Vec<_> = history.iter().map(|b| b.cost_usd).collect();
        let Some(baseline) = median(&mut values) else {
            continue;
        };
        if bucket.cost_usd >= params.min_usd && bucket.cost_usd >= params.ratio * baseline {
            spikes.push(Spike {
                bucket_start: iso(bucket.bucket_secs),
                cost_usd: bucket.cost_usd,
                baseline_usd: baseline,
                ratio: (baseline > 0.)
                    .then(|| bucket.cost_usd / baseline)
                    .filter(|r| r.is_finite()),
            });
        }
    }
    spikes.sort_by(|a, b| {
        b.cost_usd
            .total_cmp(&a.cost_usd)
            .then(a.bucket_start.cmp(&b.bucket_start))
    });
    spikes.truncate(params.max_spikes_returned as usize);
    (spikes, enough)
}
/// The aggregate can answer whole buckets only. Echo those actual bounds, including
/// a containing bucket for a sub-hour selection; never label a whole hour as a minute.
pub(crate) fn aligned_window(
    since: Option<i64>,
    until: i64,
    granularity: Granularity,
    params: SpendSpikeParams,
) -> (i64, i64, bool) {
    let step = granularity.seconds();
    let end = ((until + step - 1).div_euclid(step)) * step;
    let cap = i64::from(params.max_window_buckets) * step;
    let requested = since.unwrap_or(end - cap);
    let start = (requested.div_euclid(step) * step).max(end - cap);
    (start, end, start != requested || end != until)
}
/// Builds display evidence from finite aggregate costs.
/// # Errors
/// Fails CLOSED on non-finite costs: the endpoint returns unavailable, never a zero chart.
pub(crate) fn build_series(
    rows: Vec<BucketRow>,
    granularity: Granularity,
    params: SpendSpikeParams,
    since: i64,
    until: i64,
    clamped: bool,
) -> anyhow::Result<Series> {
    anyhow::ensure!(
        rows.iter().all(|r| r.cost_usd.is_finite()),
        "non-finite aggregate cost"
    );
    let map: std::collections::BTreeMap<_, _> =
        rows.into_iter().map(|r| (r.bucket_secs, r)).collect();
    let step = granularity.seconds();
    let history_start = since - i64::from(params.baseline_buckets) * step;
    let buckets: Vec<_> = (history_start..until)
        .step_by(step as usize)
        .map(|t| {
            map.get(&t).cloned().unwrap_or(BucketRow {
                bucket_secs: t,
                ..Default::default()
            })
        })
        .collect();
    let (spikes, enough) = detect_spikes(&buckets, params, since);
    Ok(Series {
        granularity,
        min_history_buckets: params.min_history_buckets,
        baseline_buckets: params.baseline_buckets,
        spikes,
        history: if enough { "ok" } else { "insufficient" }.into(),
        window: Window {
            since: iso(since),
            until: iso(until),
            clamped,
        },
        buckets: buckets
            .into_iter()
            .filter(|b| b.bucket_secs >= since)
            .map(|b| Bucket {
                bucket_start: iso(b.bucket_secs),
                cost_usd: b.cost_usd,
                priced_requests: b.priced_requests,
                unpriced_requests: b.unpriced_requests,
                requests: b.requests,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spend_daily_window_uses_policy_instead_of_trace_window_cap() {
        let p = crate::billing::rating::SpendSpikePolicy::embedded()
            .unwrap()
            .day;
        let end = 200 * 86400;
        let (start, served_end, _) = aligned_window(None, end, Granularity::Day, p);
        assert_eq!(served_end - start, i64::from(p.max_window_buckets) * 86400);
        let (start, served_end, clamped) = aligned_window(Some(0), end, Granularity::Day, p);
        assert_eq!(served_end - start, i64::from(p.max_window_buckets) * 86400);
        assert!(clamped);
        let shorter = SpendSpikeParams {
            max_window_buckets: p.max_window_buckets / 2,
            ..p
        };
        let (start, served_end, _) = aligned_window(None, end, Granularity::Day, shorter);
        assert_eq!(
            served_end - start,
            i64::from(shorter.max_window_buckets) * 86400
        );
    }
    #[test]
    fn series_echoes_aligned_buckets_and_counts_unpriced_without_spend() {
        let p = crate::billing::rating::SpendSpikePolicy::embedded()
            .unwrap()
            .hour;
        let (start, end, clamped) = aligned_window(Some(30), 3700, Granularity::Hour, p);
        assert_eq!((start, end, clamped), (0, 7200, true));
        let series = build_series(
            vec![BucketRow {
                bucket_secs: 0,
                requests: 1,
                unpriced_requests: 1,
                ..Default::default()
            }],
            Granularity::Hour,
            p,
            start,
            end,
            clamped,
        )
        .unwrap();
        assert_eq!(series.buckets.len(), 2);
        assert_eq!(series.buckets[0].unpriced_requests, 1);
        assert_eq!(series.history, "insufficient");
        assert!(series.spikes.is_empty());
    }
    #[test]
    fn spike_requires_history_floor_and_median_ratio() {
        let p = crate::billing::rating::SpendSpikePolicy::embedded()
            .unwrap()
            .hour;
        let mut rows: Vec<_> = (0..p.baseline_buckets)
            .map(|i| BucketRow {
                bucket_secs: i64::from(i) * 3600,
                cost_usd: p.min_usd,
                requests: 1,
                priced_requests: 1,
                ..Default::default()
            })
            .collect();
        let since = i64::from(p.baseline_buckets) * 3600;
        rows.push(BucketRow {
            bucket_secs: since,
            cost_usd: p.min_usd * 10.,
            requests: 1,
            priced_requests: 1,
            ..Default::default()
        });
        assert_eq!(
            detect_spikes(&rows, p, since).0.len(),
            1,
            "tenfold bucket must be detected"
        );
        rows.last_mut().unwrap().cost_usd = p.min_usd;
        assert!(detect_spikes(&rows, p, since).0.is_empty());
        for r in &mut rows {
            r.cost_usd = p.min_usd / 100.;
        }
        rows.last_mut().unwrap().cost_usd = p.min_usd / 10.;
        assert!(detect_spikes(&rows, p, since).0.is_empty());
        assert!(!detect_spikes(&rows[..5], p, 0).1);
    }
    #[test]
    fn series_is_tenant_first_and_never_scans_spans() {
        let sql = series_sql(Granularity::Hour);
        assert!(sql.contains("FROM tracelane.spend_hourly WHERE tenant_id = ? AND bucket_hour >="));
        assert!(!sql.contains("FROM tracelane.spans"));
    }
}
