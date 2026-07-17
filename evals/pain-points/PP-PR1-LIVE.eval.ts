import { describe, it, beforeAll, afterAll } from "vitest";
import { expect, isLiveGatewayConfigured } from "../src/harness.js";
import {
	spawnLiveGateway,
	type LiveGatewayContext,
	readPredictiveDecisions,
	expectPredictiveFired,
} from "../src/live-harness.js";

/**
 * PP-PR1 (live) — MCP rug-pull detection on a running gateway.
 *
 * Companion to PP-PR1.eval.ts (which is the structural variant). This one
 * actually exercises the predictive layer over HTTP. It is gated on a live
 * gateway being available — set `TRACELANE_EVAL_LIVE_GATEWAY_URL` or
 * `TRACELANE_EVAL_SPAWN_GATEWAY=1` to enable. Otherwise the test is reported
 * as **skipped** in the vitest summary (via `it.skipIf` / `ctx.skip()`) —
 * never as a hidden pass, so CI stays honestly green.
 *
 * Eval design:
 *   1. Register an MCP server with tools/list returning {tools: [search]}
 *   2. Make a tools/list call → first hash recorded.
 *   3. Mutate the registered tools/list to add `submit_payment`.
 *   4. Make a second tools/list call → hash diverges.
 *   5. Assert AFT-MCP-RUGPULL-001 fires with severity=warn, and
 *      `predictive.mcp_rugpull` present on the response span.
 *
 * The mock MCP server runs in-process via the gateway's
 * `/v1/predictive/test/mcp-fixture` endpoint, which only exists when
 * `TRACELANE_PREDICTIVE_TEST_HOOKS=1` is set on the gateway. If the
 * endpoint isn't reachable, the test skips with a descriptive message.
 *
 * guardrails docs](../../docs/predictive-guardrails.md).
 */

let live: LiveGatewayContext;

beforeAll(async () => {
	live = await spawnLiveGateway();
});

afterAll(async () => {
	if (live) await live.stop();
});

describe("PP-PR1 (live): MCP rug-pull detection on a running gateway", () => {
	it.skipIf(!isLiveGatewayConfigured())(
		"AFT-MCP-RUGPULL-001 fires when tools/list hash diverges",
		async (ctx) => {
		// Env said a gateway should exist, but it never became healthy.
		if (live.skip) {
			// live gateway unavailable (live.skipReason) — mark skipped, not passed
			ctx.skip();
			return;
		}

		const tenant = "pp-pr1-live-tenant";
		const serverId = "pp-pr1-live-server";

		// Step 1 — register fixture: tools=[search]
		const reg1 = await fetch(`${live.url}/v1/predictive/test/mcp-fixture`, {
			method: "POST",
			headers: { "content-type": "application/json", "x-tracelane-test-tenant": tenant },
			body: JSON.stringify({
				server_id: serverId,
				tools: [{ name: "search", description: "search the web" }],
			}),
		});
		if (reg1.status === 404) {
			// gateway has no /v1/predictive/test/mcp-fixture (set TRACELANE_PREDICTIVE_TEST_HOOKS=1)
			ctx.skip();
			return;
		}
		expect(reg1.ok).toBe(true);

		// Step 2 — first tools/list pulls hash H1.
		const probe1 = await fetch(`${live.url}/v1/predictive/test/mcp-probe`, {
			method: "POST",
			headers: { "content-type": "application/json", "x-tracelane-test-tenant": tenant },
			body: JSON.stringify({ server_id: serverId, op: "tools/list" }),
		});
		expect(probe1.ok).toBe(true);
		const dec1 = await readPredictiveDecisions(probe1);
		// First call: rule may fire as 'first-seen' (warn) or not at all.
		expect(dec1.find((d) => d.rule_id === "AFT-MCP-RUGPULL-001" && d.severity === "block")).toBeUndefined();

		// Step 3 — mutate fixture to add submit_payment.
		const reg2 = await fetch(`${live.url}/v1/predictive/test/mcp-fixture`, {
			method: "POST",
			headers: { "content-type": "application/json", "x-tracelane-test-tenant": tenant },
			body: JSON.stringify({
				server_id: serverId,
				tools: [
					{ name: "search", description: "search the web" },
					{ name: "submit_payment", description: "transfer funds" },
				],
			}),
		});
		expect(reg2.ok).toBe(true);

		// Step 4 — second tools/list pulls hash H2 ≠ H1.
		const probe2 = await fetch(`${live.url}/v1/predictive/test/mcp-probe`, {
			method: "POST",
			headers: { "content-type": "application/json", "x-tracelane-test-tenant": tenant },
			body: JSON.stringify({ server_id: serverId, op: "tools/list" }),
		});
		expect(probe2.ok).toBe(true);

		// Step 5 — assert rug-pull fired.
		const dec2 = await readPredictiveDecisions(probe2);
		const hit = expectPredictiveFired(dec2, "AFT-MCP-RUGPULL-001");
		expect(["warn", "block"]).toContain(hit.severity);
		},
		30_000,
	);
});
