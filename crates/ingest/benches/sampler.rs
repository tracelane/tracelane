//!
//! `TailSampler::evaluate` runs once per span the ClickHouse writer drains, so
//! its cost multiplies by ingest throughput. Budget: it must stay far under the
//! per-span ingest budget (≥50K spans/sec single-node = 20µs/span). It is a
//! DashMap read + a `u128` modulo with no allocation, so it should clear well
//! under ~200ns/call — the same order as the cardinality tracker.
//!
//! Run with `cargo bench -p ingest --bench sampler`.

use chrono::Utc;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ingest::tail_sampler::{SamplingPolicy, TailSampler};
use tracelane_shared::{SpanAttributes, SpanStatus, SpanStatusCode, TenantId, TracelaneSpan};
use uuid::Uuid;

fn span(trace_id: Uuid, code: SpanStatusCode) -> TracelaneSpan {
    TracelaneSpan {
        span_id: Uuid::new_v4(),
        trace_id,
        parent_span_id: None,
        tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(1)),
        name: "op".into(),
        start_time: Utc::now(),
        end_time: None,
        attributes: SpanAttributes::default(),
        status: SpanStatus {
            code,
            message: None,
        },
    }
}

/// The common case: clean OK spans, each a distinct trace, so `contains_key`
/// misses and the deterministic rate sample decides. This is the per-span cost
/// paid on the drain path for the ~90% of spans that are not error/intervention.
fn bench_evaluate_clean_rate_sample(c: &mut Criterion) {
    let s = TailSampler::with_rate(10);
    let spans: Vec<TracelaneSpan> = (0..10_000u128)
        .map(|i| span(Uuid::from_u128(i), SpanStatusCode::Ok))
        .collect();

    c.bench_function("sampler_evaluate_clean_rate_sample", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let sp = &spans[i % spans.len()];
            i = i.wrapping_add(1);
            black_box(s.evaluate(black_box(sp), SamplingPolicy::Tail))
        })
    });
}

/// A span of a trace already force-kept → `contains_key` hit returning Keep
/// without a rate computation (the sticky read path).
fn bench_evaluate_sticky_hit(c: &mut Criterion) {
    let s = TailSampler::with_rate(0);
    let t = Uuid::from_u128(0xABCD);
    s.evaluate(&span(t, SpanStatusCode::Error), SamplingPolicy::Tail); // prime the sticky entry
    let sp = span(t, SpanStatusCode::Ok);

    c.bench_function("sampler_evaluate_sticky_hit", |b| {
        b.iter(|| black_box(s.evaluate(black_box(&sp), SamplingPolicy::Tail)))
    });
}

criterion_group!(
    benches,
    bench_evaluate_clean_rate_sample,
    bench_evaluate_sticky_hit
);
criterion_main!(benches);
