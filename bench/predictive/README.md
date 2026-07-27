# bench/predictive — Predictive layer latency benchmarks

Per ADR-014, run this suite on Hetzner CCX13 production-equivalent hardware before V1 ship.
Publish results to `RESULTS.md`. Block V1 latency claim finalization on this measurement.

## What to measure

For each input length {128, 256, 512, 1024} tokens:
- p50, p95, p99 latency for Llama Prompt Guard 2 22M ONNX-INT8 (Channel A)
- p50, p95, p99 latency for DeBERTa-v3-xsmall (Channel B, once trained)
- p50, p95, p99 for heuristic Channel C (should be ≤ 1 ms)
- Channel A + B + C ensemble combined latency (sequential + async paths)

Both cold-cache and warm-cache runs. Minimum 10K iterations per measurement.

Reference baseline: DistilBERT-66M ONNX-INT8, p50=9 ms / p99<50 ms
(getstream.io/blog/optimize-transformer-inference).

## Pass/fail threshold

If Channel A p99 > 80 ms on CPU → evaluate INT4 quantization or an NVIDIA L4
inference adapter for Enterprise tier. Document the decision before V1 ship.

No inline-latency figure is published as fact until it is measured on
production-equivalent hardware and clears the budget; until then public copy
stays qualitative. These numbers are pending measurement.

## Files

- `bench_channel_a.rs` — Criterion harness for Llama Prompt Guard 2 22M ONNX-INT8
- `RESULTS.md` — populated by benchmark run; empty until V1 dev week 1
