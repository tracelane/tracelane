# bench/gateway — RESULTS

> **UNPOPULATED.** No production-hardware run has been recorded yet. Until this
> file holds a real measurement that clears the budget, the gateway perf claims
> (throughput and p99 overhead) stay OFF the public surface and out of copy.
> Populate from a CCX23 run per `README.md`, then a measured number may be
> restored to copy alongside this row.

## PP-G7 — gateway overhead (`overhead-measurement.js`)

| Date | Node SKU | k6 ver | Gateway SHA | p50 | p95 | p99 | error rate | Pass (<25ms p99)? |
|---|---|---|---|---|---|---|---|---|
| _pending_ | CCX23 | — | — | — | — | — | — | — |

## PP-G3 — sustained throughput (`sustained-5k-rps.js`)

| Date | Node SKU | k6 ver | Gateway SHA | target RPS | sustained RPS | p99 | error rate | Pass (5K @ <0.1%)? |
|---|---|---|---|---|---|---|---|---|
| _pending_ | CCX23 | — | — | 5000 | — | — | — | — |

## §2.6 — request-side guardrail dispatcher overhead (`dispatcher_overhead_p99`)

The the guardrail spec §2.6 budget is the **guardrail dispatcher** overhead
(`SideOutcome.total_latency_micros` — pure rail evaluation, excludes auth /
recording / network), not the end-to-end gateway wall-clock. Measured by the
gated bench `guardrail::engine::tests::dispatcher_overhead_p99` (full 9-rail
default engine, tool-using request, 20 000 iters, intra-request rail concurrency
on a 4-worker runtime). Budget: **aggregate p99 ≤ 5 000 µs (5 ms)**.

| Date | Host | Gateway branch | iters | agg p50 | agg p95 | **agg p99** | max | Pass (≤5ms p99)? |
|---|---|---|---|---|---|---|---|---|
| 2026-06-20 | WSL (Ryzen) | `feat/guardrails-v1` @ 25e74ea | 20 000 | 70µs | 209µs | **375µs** | 8 837µs | ✅ (13× margin) |

Per-rail p99 (request-side): R1_cost 32µs · R2_secrets_pii 109µs · R3_schema 46µs ·
R3_pinning 4µs · R4_trifecta 96µs · R7_topic_competitor 7µs · R8_injection 25µs.
(R5/R6 are response-side, not in the request-side aggregate.) Re-run:
`cargo test -p gateway --bin gateway -- --ignored --nocapture dispatcher_overhead_p99`.

## Status (k6 end-to-end gateway overhead — PP-G7/PP-G3 above)

The k6 `http_req_duration` rows stay **`_pending_`**. The deeper blocker is that
the gateway's auth path runs an Argon2id verify per request with no auth-result
cache, so with auth in the path `http_req_duration` measures auth cost, not
gateway processing — defeating the "mock-instant upstream ⇒ http_req_duration ≈
gateway overhead" premise. A clean PP-G7 number needs an auth-result cache or a
bench auth-bypass env. The guardrail-dispatcher overhead requirement is met
independently by the §2.6 dispatcher bench above.

## Notes

- Load generator must be a **separate** host from the gateway.
- Overhead run requires a `mock-instant` upstream so `http_req_duration` ≈
  gateway processing time.
- Report the **worst** p99 across ≥10 runs, not the best.
