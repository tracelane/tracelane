import { describe, it, beforeAll, afterAll } from "vitest";
import { expect, isLiveGatewayConfigured } from "../src/harness.js";
import {
	spawnLiveGateway,
	type LiveGatewayContext,
	readPredictiveDecisions,
	expectPredictiveFired,
} from "../src/live-harness.js";

/**
 * PP-PR8 (live) — argument-distribution drift detection on a running gateway.
 *
 * Companion to PP-PR8.eval.ts (structural). Exercises the live PR8-lite
 * Mahalanobis drift predictor over HTTP. Reported as **skipped** (via
 * `it.skipIf` / `ctx.skip()`) when no live gateway is available — never as a
 * hidden pass. Same activation rules as PP-PR1-LIVE.
 *
 * Eval design:
 *   1. Warm baseline: 30 calls to a tool with arguments from a tight
 *      distribution (length 8±2, ascii-only).
 *   2. Drift call: one call with arguments from a wildly different
 *      distribution (length 200, mostly non-ASCII).
 *   3. Assert AFT-MCP-ARGDRIFT-001 fires with severity=warn on the drift
 *      call. PR8-lite uses Mahalanobis distance > 4σ.
 *
 * The fixture endpoint `/v1/predictive/test/argdrift` only exists when
 * `TRACELANE_PREDICTIVE_TEST_HOOKS=1` is set. If unreachable, the test
 * skips cleanly with a descriptive message.
 *
 */

const BASELINE_SAMPLES = 30;

function asciiArgsTight(): Record<string, unknown> {
	const len = 6 + Math.floor(Math.random() * 4); // 6..9
	const s = Array.from({ length: len }, () =>
		String.fromCharCode(97 + Math.floor(Math.random() * 26)),
	).join("");
	return { query: s, top_k: 5 };
}

function asciiArgsDrift(): Record<string, unknown> {
	const s = Array.from({ length: 200 }, () =>
		String.fromCharCode(0x4e00 + Math.floor(Math.random() * 0x100)),
	).join("");
	return { query: s, top_k: 5000 };
}

let live: LiveGatewayContext;

beforeAll(async () => {
	live = await spawnLiveGateway();
});

afterAll(async () => {
	if (live) await live.stop();
});

describe("PP-PR8 (live): argument-drift detection on a running gateway", () => {
	it.skipIf(!isLiveGatewayConfigured())(
		"AFT-MCP-ARGDRIFT-001 fires when arg distribution drifts > 4σ",
		async (ctx) => {
		// Env said a gateway should exist, but it never became healthy.
		if (live.skip) {
			// live gateway unavailable (live.skipReason) — mark skipped, not passed
			ctx.skip();
			return;
		}

		const tenant = "pp-pr8-live-tenant";
		const tool = "search";

		const probe = (args: Record<string, unknown>) =>
			fetch(`${live.url}/v1/predictive/test/argdrift`, {
				method: "POST",
				headers: {
					"content-type": "application/json",
					"x-tracelane-test-tenant": tenant,
				},
				body: JSON.stringify({ tool, args }),
			});

		// Probe once to confirm endpoint exists; bail out cleanly if not.
		const initial = await probe(asciiArgsTight());
		if (initial.status === 404) {
			// gateway has no /v1/predictive/test/argdrift (set TRACELANE_PREDICTIVE_TEST_HOOKS=1)
			ctx.skip();
			return;
		}
		expect(initial.ok).toBe(true);

		// Step 1 — warm baseline.
		for (let i = 0; i < BASELINE_SAMPLES; i++) {
			const r = await probe(asciiArgsTight());
			expect(r.ok).toBe(true);
		}

		// Step 2 — drift call.
		const drift = await probe(asciiArgsDrift());
		expect(drift.ok).toBe(true);

		// Step 3 — assert rule fired on the drift call.
		const decisions = await readPredictiveDecisions(drift);
		const hit = expectPredictiveFired(decisions, "AFT-MCP-ARGDRIFT-001");
		expect(["warn", "block"]).toContain(hit.severity);
		},
		60_000,
	);
});
