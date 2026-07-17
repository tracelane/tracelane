//! Hot-path microbench for ADR-030 cardinality tracking.
//!
//! Budget: `CardinalityTracker::observe_and_classify` must clear
//! 1M calls in under 200 ms (= <200 ns p99 per call). The HLL++
//! sketch + DashMap lookup runs once per attribute on every accepted
//! span; latency multiplies by every (span × attr) on the wire.
//!
//! Run with `cargo bench -p ingest --bench cardinality`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ingest::cardinality::CardinalityTracker;
use uuid::Uuid;

fn bench_observe_single_workspace_unique_keys(c: &mut Criterion) {
    let t = CardinalityTracker::new();
    let ws = Uuid::new_v4();
    let cap = 1_000_000;
    // Pre-generate the key strings so the bench measures only the
    // tracker hot path, not formatting.
    let keys: Vec<String> = (0..10_000).map(|i| format!("attr_{i}")).collect();

    c.bench_function("cardinality_observe_unique_keys", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let key = &keys[i % keys.len()];
            i = i.wrapping_add(1);
            black_box(t.observe_and_classify(ws, key, cap))
        })
    });
}

fn bench_observe_single_workspace_repeated_keys(c: &mut Criterion) {
    // Realistic OTel-GenAI workload: ~5 distinct attribute keys per
    // span (gen_ai.system, gen_ai.request.model, gen_ai.usage.*).
    // Most observations land on a key already in the sketch.
    let t = CardinalityTracker::new();
    let ws = Uuid::new_v4();
    let cap = 1_000_000;
    let keys = [
        "gen_ai.system",
        "gen_ai.request.model",
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.output_tokens",
        "gen_ai.operation.name",
    ];

    c.bench_function("cardinality_observe_repeated_keys", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let key = keys[i % keys.len()];
            i = i.wrapping_add(1);
            black_box(t.observe_and_classify(ws, key, cap))
        })
    });
}

fn bench_observe_many_workspaces(c: &mut Criterion) {
    // Worst case under realistic load: 1 000 workspaces each emitting
    // one key. Exercises DashMap shard distribution + entry insertion.
    let t = CardinalityTracker::new();
    let workspaces: Vec<Uuid> = (0..1_000).map(|_| Uuid::new_v4()).collect();
    let cap = 1_000_000;

    c.bench_function("cardinality_observe_many_workspaces", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let ws = workspaces[i % workspaces.len()];
            i = i.wrapping_add(1);
            black_box(t.observe_and_classify(ws, "gen_ai.system", cap))
        })
    });
}

criterion_group!(
    benches,
    bench_observe_single_workspace_unique_keys,
    bench_observe_single_workspace_repeated_keys,
    bench_observe_many_workspaces,
);
criterion_main!(benches);
