//! Criterion benchmark harness for Channel A: Llama Prompt Guard 2 22M ONNX-INT8.
//!
//! Run: `cargo bench --bench bench_channel_a`
//! Outputs p50/p95/p99 per input length {128, 256, 512, 1024} tokens.
//! Measures cold-cache and warm-cache separately (see README.md).
//!
//! Required: model file at `ml/prompt_guard_export/llama_prompt_guard_2_22m.onnx`
//! (INT8 quantized). See `ml/prompt_guard_export/` for export instructions.
//!
//! Per ADR-014: publish results to `bench/predictive/RESULTS.md` before V1 ship.

// TODO(V1-week1): implement using `ort` crate + criterion.
// Placeholder — scaffolded by APPLY_RESEARCH_LEARNINGS_2026-05-10.md BUILD 3.
//
// Template structure:
//
// use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
// use ort::{Environment, Session, SessionBuilder};
//
// fn bench_channel_a(c: &mut Criterion) {
//     let env = Environment::builder().with_name("bench").build().unwrap();
//     let session = SessionBuilder::new(&env)
//         .unwrap()
//         .with_model_from_file("ml/prompt_guard_export/llama_prompt_guard_2_22m.onnx")
//         .unwrap();
//
//     let mut group = c.benchmark_group("channel_a_latency");
//     for token_len in [128_usize, 256, 512, 1024] {
//         let input = vec![1i64; token_len]; // dummy token ids
//         group.bench_with_input(
//             BenchmarkId::new("llama_prompt_guard_2_22m", token_len),
//             &input,
//             |b, inp| {
//                 b.iter(|| {
//                     // run inference; return decision
//                     let _ = session.run(ort::inputs!["input_ids" => inp.as_slice()].unwrap());
//                 })
//             },
//         );
//     }
//     group.finish();
// }
//
// criterion_group!(benches, bench_channel_a);
// criterion_main!(benches);
