import { describe, it } from "vitest";
import {
  expect,
  spawnGateway,
  runK6,
  isLiveGatewayConfigured,
} from "../src/harness.js";

/**
 * PP-G3 — Gateway sustains 5K RPS single-node without GIL stall
 *
 * Competitor behavior: LiteLLM degrades to <500 RPS due to Python GIL
 * contention under concurrent load (documented production incidents at
 * 300–500 RPS).
 *
 * Pain: Production AI agents hit cliff failures during traffic spikes.
 * Agents retry, compounding load. Teams scramble to horizontal-scale a
 * Python process that doesn't parallelize.
 *
 * Tracelane fix: Rust gateway on Axum + tokio. No GIL. Async I/O.
 * Each request is a lightweight future, not a thread. Target: 5K+ RPS
 * single-node with full tracing on, p99 <25ms.
 *
 * Eval design — HONEST GATING:
 * - This is a LIVE PERFORMANCE assertion. It measures nothing unless a real
 *   gateway is reachable. CI does NOT configure one, so these `it`s report as
 *   **skipped** in the vitest summary — never as a fabricated pass.
 * - To run for real: `pnpm bench:gateway` with TRACELANE_EVAL_LIVE_GATEWAY_URL
 *   set (or TRACELANE_EVAL_SPAWN_GATEWAY=1). The benchmark-runner subagent
 *   enforces this against the hard p99 budget.
 *
 */
const LIVE = isLiveGatewayConfigured();

describe("PP-G3: Gateway RPS throughput", () => {
  it.skipIf(!LIVE)(
    "sustains 5K RPS at p99 <25ms with <0.1% error rate [LIVE perf — requires real gateway]",
    async () => {
      const gateway = await spawnGateway({ providers: ["mock-fast"] });

      try {
        const k6 = await runK6({
          script: "./bench/gateway/sustained-5k-rps.js",
          duration: "60s",
          target: gateway.url,
          vus: 100,
        });

        expect(k6.p99_latency_ms).toBeLessThan(25);

        // Error rate: <0.1% (1 in 1000)
        expect(k6.error_rate).toBeLessThan(0.001);

        // Sustained throughput: must complete 5K RPS × 60s = 300K requests
        // Allow 2% margin: 294K+
        expect(k6.requests_completed).toBeGreaterThan(294_000);

        // Explicit RPS check
        expect(k6.rps_sustained).toBeGreaterThan(5_000);
      } finally {
        gateway.stop();
      }
    },
  );

  it.skipIf(!LIVE)(
    "p50 latency is under 5ms (hot path budget) [LIVE perf — requires real gateway]",
    async () => {
      const gateway = await spawnGateway({ providers: ["mock-fast"] });

      try {
        const k6 = await runK6({
          script: "./bench/gateway/sustained-5k-rps.js",
          duration: "60s",
          target: gateway.url,
          vus: 100,
        });

        expect(k6.p50_latency_ms).toBeLessThan(5);
      } finally {
        gateway.stop();
      }
    },
  );
});
