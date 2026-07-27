# bench/gateway — Gateway load-test harness

Real [k6](https://grafana.com/docs/k6/latest/) load tests that measure the
gateway's end-to-end behaviour under load. These produce the numbers behind two
pain-point claims — and **gate** whether those claims may appear in public copy.

| Script | Pain point | Measures | Budget |
|---|---|---|---|
| `overhead-measurement.js` | PP-G7 | gateway request-processing overhead (p50/p95/p99) | gateway-overhead budget (pending measurement) |
| `sustained-5k-rps.js` | PP-G3 | sustained throughput + error rate + p99 under a constant arrival rate | single-node sustained-throughput budget (pending measurement) |

Both are driven from the eval harness via `runK6` (`evals/src/harness.ts`), which
shells out to `k6 run`, parses `--summary-export` JSON, and returns the measured
percentiles. It **never** fabricates: no k6 binary or no summary → it throws.

## Why this exists (the honesty gate)

`bench/predictive/` covers the *predictive layer* latency; this covers the
*gateway*. **Neither the gateway nor the predictive numbers are yet measured on
production-equivalent hardware**, so no specific throughput or latency figure is
published as fact. A measured number is quoted only once a real run on
production-equivalent hardware is committed to `RESULTS.md` AND clears the budget.

## Running on production-equivalent hardware (CCX23)

Run against a deployed gateway on a production-equivalent CCX23 host, **not**
a laptop — laptop numbers are not publishable.

1. **Enable the gated bench upstream (PP-G7 overhead isolation).** Start the
   gateway with `TRACELANE_BENCH_MOCK_UPSTREAM=1` (a loud startup warning
   confirms it). Requests for the reserved `__bench_mock*` models then return an
   instant in-gateway canned response **instead of dispatching upstream** — so
   `http_req_duration` ≈ the gateway's own processing (auth, parse, breaker,
   span emit) with ~0 provider time. The k6 scripts already default `MODEL` to
   `__bench_mock_instant` / `__bench_mock_fast`. **Double-gated:** the flag is
   off by default AND the model must carry the `__bench_` prefix, so a normal
   tenant request can never reach the mock. **NEVER set this flag on a
   tenant-serving node** (loud warning + the security guidance in CLAUDE.md).
2. **Install k6** on the load-generating host (a *separate* box from the gateway,
   so the generator doesn't steal the gateway's CPU).
3. Run (no `MODEL` needed — the reserved default routes to the mock):

   ```bash
   # overhead (PP-G7)
   TARGET=https://gateway.tracelane.dev AUTH_TOKEN=tlane_… \
   k6 run bench/gateway/overhead-measurement.js
   # or: pnpm bench:gateway:overhead   (reads the same env)

   # sustained throughput floor (PP-G3)
   TARGET=https://gateway.tracelane.dev AUTH_TOKEN=tlane_… RATE=5000 DURATION=60s \
   k6 run bench/gateway/sustained-5k-rps.js
   ```

   Or, through the eval gate (asserts the budgets and reports pass/skip, never a
   fabricated pass):

   ```bash
   TRACELANE_EVAL_LIVE_GATEWAY_URL=https://gateway.tracelane.dev \
   TRACELANE_EVAL_GATEWAY_TOKEN=tlane_… \
   pnpm eval:run --suite=perf      # PP-G3 + PP-G7 run live instead of skipping
   ```

4. Record p50/p95/p99, sustained RPS, and error rate in `RESULTS.md` with the
   date, node SKU, k6 version, and the gateway commit SHA.

## STOP GATE

- If gateway-overhead **p99 > 25ms**, or sustained RPS falls short of **5K** at
  **<0.1% error**, the corresponding marketing claim does **not** return to the
  public surface — fix the hot path or restate the claim qualitatively.
- Minimum 10 runs; report the worst p99, not the best.
