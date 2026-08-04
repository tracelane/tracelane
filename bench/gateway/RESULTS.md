# bench/gateway — RESULTS

> **POPULATED 2026-08-04** for the **self-host / bench-auth** configuration only.
> Read the Scope block before quoting any number. These are raw measurements;
> framing, comparisons and any public copy are founder-gated and deliberately
> absent from this file.

## Scope — what these numbers are and are not

- **Auth path is self-host, not hosted.** The bench gateway ran
  `TRACELANE_SELF_HOST=1`, where the bearer token is a constant-time compare
  against `TRACELANE_MASTER_KEY` (`crates/gateway/src/auth/mod.rs:194`,
  `constant_time_eq`). The **hosted** path instead does a peppered-HMAC lookup
  plus an **Argon2id verify per request** with no auth-result cache
  (`crates/gateway/src/auth/api_key.rs:4`). That cost is **NOT** in any number
  below, so none of these may be quoted as hosted gateway overhead. The
  auth-cache blocker recorded previously still stands for the hosted path.
- **Network is in the numbers.** The load generator was a separate host, per
  `README.md`. Measured floor between the two boxes: **RTT min 0.448 ms /
  avg 0.628 ms / max 2.091 ms** (20 ICMP samples). Every `http_req_duration`
  below includes one round trip.
- **Upstream is mocked.** `TRACELANE_BENCH_MOCK_UPSTREAM=1` +
  `__bench_mock_instant`, so provider time ≈ 0 by construction.
- **Worst-of-N, not best.** Per the standing rule in Notes, PP-G7 reports the
  **worst** p99 across 10 runs. The best single run was 9.349 ms; reporting that
  one would have shown the <10 ms target met when worst-case it is not.

## Environment

| | |
|---|---|
| Date | 2026-08-04 |
| Gateway host | Hetzner **CCX23** (4 **dedicated** vCPU, 16 GB), Ubuntu 24.04, nbg1-dc3 |
| Load generator | Hetzner **CPX42** (8 shared vCPU, 16 GB), nbg1-dc3 — separate host |
| k6 | v2.0.0 |
| Gateway SHA | `fe1d2699` |
| Config | self-host single-tenant, NATS JetStream up, no Postgres control plane |

## PP-G7 — gateway overhead (`overhead-measurement.js`)

10 runs × 30 s, VUS=50 (closed loop, so the gateway ran at **saturation**
≈ 8.8–9.0 k rps — this is not a low-load latency figure).

| Date | Node SKU | k6 ver | Gateway SHA | p50 | p95 | p99 | error rate | Pass (<25 ms p99)? |
|---|---|---|---|---|---|---|---|---|
| 2026-08-04 | CCX23 | v2.0.0 | `fe1d2699` | 5.475 ms | 7.407 ms | **11.897 ms** | 0.000000 | ✅ |

Worst-of-10 in every column. Per-run p99 spread: 9.349 · 9.643 · 10.531 · 10.598
· 10.665 · 10.667 · 11.250 · 11.405 · 11.435 · 11.897 ms. Throughput 8 825–8 985
rps. 2 673 069 requests total, **0** non-2xx across all 10 runs.

**PP-G7's tighter <10 ms target is NOT met worst-case** (11.897 ms); it is met
only in the two best runs. The CLAUDE.md p99 <25 ms budget is met in all 10.

## PP-G3 — sustained throughput (`sustained-5k-rps.js`)

1 run × 60 s, constant arrival rate.

| Date | Node SKU | k6 ver | Gateway SHA | target RPS | sustained RPS | p99 | error rate | Pass (5K @ <0.1%)? |
|---|---|---|---|---|---|---|---|---|
| 2026-08-04 | CCX23 | v2.0.0 | `fe1d2699` | 5000 | **4 997.8** | 14.091 ms | 0.000000 | ✅ |

299 874 requests, p50 1.064 ms, p95 1.449 ms, max 209.281 ms.
**`dropped_iterations` = 126** (0.042%) — the generator could not dispatch on
126 occasions, which is why the achieved rate is 4 997.8 and not 5 000.

**Gateway CPU at 5 k rps: median 230.4 %, max 236.0 % of the 400 % available**
(4 dedicated vCPU), sampled at 2 s intervals over a separate instrumented 30 s
run at the same rate. ≈ 42 % CPU headroom remained at 5 k rps.

### Supersedes the 2026-08-03 p99 result

An earlier sustained run exited 99 on `http_req_duration` thresholds crossed and
was logged as MODELED-AND-QUESTIONED. That run put k6 and the gateway on the
**same** 4-vCPU box. Re-run here with a separate generator, the same threshold
passes (14.091 ms < 25 ms). The earlier miss is attributable to load-generator
CPU contention, not to the gateway.

## §2.6 — request-side guardrail dispatcher overhead (`dispatcher_overhead_p99`)

The guardrail spec §2.6 budget is the **guardrail dispatcher** overhead
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

## Validity gate

Every run above was accepted by `summary-gate.mjs`, which refuses to write a
summary export when >0.1 % of requests are non-2xx. All 13 k6 runs reported
0.000000 error rate. The gate is falsified on every CI run by
`summary-gate.selftest.mjs` (both halves: it must PASS valid runs and BLOCK
invalid ones) — its predecessor could not pass any run at all, which is why no
number was recorded before today.

## Notes

- Load generator must be a **separate** host from the gateway. Observed cost of
  ignoring this: a false p99 threshold failure (see the supersession note above).
- Overhead run requires a `mock-instant` upstream so `http_req_duration` ≈
  gateway processing time.
- Report the **worst** p99 across ≥10 runs, not the best.
- A hosted-path number requires the Argon2id auth-result cache first; until then
  a hosted PP-G7 figure would measure auth cost, not gateway processing.
