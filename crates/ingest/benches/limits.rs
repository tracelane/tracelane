//! Hot-path microbench for ADR-029 ingest payload size enforcement.
//!
//! Budget: `check_payload_pre_decode` must reject a 10 MiB body in
//! <1 µs p50. The pre-decode guard runs on every OTLP request — its
//! latency is multiplied by every RPS we sell. The post-decode walk
//! per span is also benched as a sanity check on hot-path cost when a
//! normal batch is accepted.
//!
//! Run with `cargo bench -p ingest --bench limits`. The bench reports
//! mean / median / p99 in ns; CI compares the median against the 1 µs
//! ceiling asserted in `evals/pain-points/PP-OVERSIZE-SPAN.eval.ts`.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use ingest::limits::{IngestLimits, check_payload_pre_decode, check_span_post_decode};
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, KeyValue, any_value::Value as AnyValueValue,
};
use opentelemetry_proto::tonic::trace::v1::Span as OtlpSpan;

fn make_attr(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(AnyValueValue::StringValue(value.into())),
        }),
    }
}

fn small_span() -> OtlpSpan {
    OtlpSpan {
        trace_id: vec![1; 16],
        span_id: vec![2; 8],
        name: "chat".into(),
        attributes: vec![
            make_attr("gen_ai.system", "anthropic"),
            make_attr("gen_ai.request.model", "claude-sonnet-4-6"),
            make_attr("gen_ai.usage.input_tokens", "1024"),
            make_attr("gen_ai.usage.output_tokens", "512"),
        ],
        ..Default::default()
    }
}

fn bench_pre_decode_reject_10mb(c: &mut Criterion) {
    let limits = IngestLimits::default();
    // 10 MiB body — well over the 8 MiB default `max_batch_bytes`.
    let body_len = 10 * 1024 * 1024;

    let mut group = c.benchmark_group("ingest_limits_pre_decode");
    group.throughput(Throughput::Bytes(body_len as u64));
    group.bench_function("reject_10mb_payload", |b| {
        b.iter(|| {
            // Just the size check — no allocation. Budget: <1 µs p50.
            let r = check_payload_pre_decode(black_box(body_len), black_box(&limits));
            debug_assert!(r.is_err());
            r
        })
    });
    group.finish();
}

fn bench_pre_decode_accept_normal(c: &mut Criterion) {
    let limits = IngestLimits::default();
    // 16 KiB body — typical OTLP batch.
    let body_len = 16 * 1024;

    c.bench_function("ingest_limits_pre_decode_accept_normal", |b| {
        b.iter(|| {
            let r = check_payload_pre_decode(black_box(body_len), black_box(&limits));
            debug_assert!(r.is_ok());
            r
        })
    });
}

fn bench_post_decode_accept_small_span(c: &mut Criterion) {
    let limits = IngestLimits::default();
    let span = small_span();

    c.bench_function("ingest_limits_post_decode_small_span", |b| {
        b.iter(|| {
            let r = check_span_post_decode(black_box(&span), black_box(&limits));
            debug_assert!(r.is_ok());
            r
        })
    });
}

criterion_group!(
    benches,
    bench_pre_decode_reject_10mb,
    bench_pre_decode_accept_normal,
    bench_post_decode_accept_small_span,
);
criterion_main!(benches);
