import { describe, it } from "vitest";
import {
  expect,
  spawnGateway,
  runK6,
  isLiveGatewayConfigured,
} from "../src/harness.js";

/**
 * PP-G7 — Gateway overhead <10ms p99
 *
 * Competitor behavior: LiteLLM Python overhead adds 50–200ms to every
 * request. Under load, Python GIL and event loop queuing push p99 overhead
 * to 500ms+. This is before any provider latency.
 *
 * Pain: AI agent loops run hundreds of LLM calls. 50ms gateway overhead
 * per call = 5 extra seconds per 100-step agent. Debugging sessions feel
 * sluggish. Real-time A2UI interactions break usability thresholds.
 *
 * Tracelane fix: Rust Axum gateway with async I/O. Zero-allocation hot
 * path. No serialization middleware on the critical path.
 * Target: p99 overhead <10ms (measured with mock provider that returns
 * instantly, isolating gateway processing time).
 *
 * Eval design — HONEST GATING:
 * - These are LIVE PERFORMANCE assertions. They measure real p99/p95/p50
 *   gateway overhead and therefore require a running gateway. CI does NOT
 *   configure one, so they report as **skipped** in the vitest summary —
 *   never as a fabricated pass on hardcoded latency constants.
 * - To run for real: `pnpm bench:gateway` with TRACELANE_EVAL_LIVE_GATEWAY_URL
 *   set (or TRACELANE_EVAL_SPAWN_GATEWAY=1).
 *
 */
const LIVE = isLiveGatewayConfigured();

describe("PP-G7: Gateway overhead <10ms p99", () => {
  it.skipIf(!LIVE)(
    "p99 gateway overhead is under 10ms with mock provider [LIVE perf — requires real gateway]",
    async () => {
      const gateway = await spawnGateway({ providers: ["mock-instant"] });

      try {
        const k6 = await runK6({
          script: "./bench/gateway/overhead-measurement.js",
          duration: "30s",
          target: gateway.url,
          vus: 50,
        });

        // Hard budget from CLAUDE.md §Performance budgets
        expect(k6.p99_latency_ms).toBeLessThan(10);
      } finally {
        gateway.stop();
      }
    },
  );

  it.skipIf(!LIVE)(
    "p95 gateway overhead is under 7ms [LIVE perf — requires real gateway]",
    async () => {
      const gateway = await spawnGateway({ providers: ["mock-instant"] });

      try {
        const k6 = await runK6({
          script: "./bench/gateway/overhead-measurement.js",
          duration: "30s",
          target: gateway.url,
          vus: 50,
        });

        expect(k6.p95_latency_ms).toBeLessThan(7);
      } finally {
        gateway.stop();
      }
    },
  );

  it.skipIf(!LIVE)(
    "p50 gateway overhead is under 3ms [LIVE perf — requires real gateway]",
    async () => {
      const gateway = await spawnGateway({ providers: ["mock-instant"] });

      try {
        const k6 = await runK6({
          script: "./bench/gateway/overhead-measurement.js",
          duration: "30s",
          target: gateway.url,
          vus: 50,
        });

        // p50 target: <5ms per CLAUDE.md; using 3ms as the p50 overhead ceiling
        expect(k6.p50_latency_ms).toBeLessThan(3);
      } finally {
        gateway.stop();
      }
    },
  );
});
