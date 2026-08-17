import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-G1 — BYOK gateway: 0% markup vs OpenRouter 5.5%
 *
 * Competitor behavior: OpenRouter charges a 5.5% markup on all provider
 * API calls. LiteLLM Cloud adds margin. Portkey adds per-request fees.
 * Customers paying ~$10K/mo in API costs pay an additional $550 to OpenRouter.
 *
 * Pain: AI builders are price-sensitive. Every dollar on infrastructure
 * is a dollar not spent on model calls. 5.5% compounds at scale.
 *
 * Tracelane fix: BYOK (Bring Your Own Key). The customer's provider API key
 * is used directly. Tracelane charges only for the observability platform,
 * never for API call margin. Cost to customer: $0 markup.
 *
 * Eval design:
 * - Inspect the gateway routing code to verify no markup coefficient exists
 * - Verify cost_per_token in span attributes == provider-reported cost
 * - Verify the pricing tiers match what the code enforces
 *
 * Linked: PP-G1
 */
/** Read a repo file relative to the repo root — the product, not a model of it. */
function repoRead(rel: string): string {
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const fs = require("node:fs");
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const path = require("node:path");
	return fs.readFileSync(path.resolve(__dirname, "../../", rel), "utf8");
}

describe("PP-G1: BYOK gateway — 0% markup", () => {
	it("gateway code contains no markup coefficient", () => {
		// REWRITTEN 2026-08-12. This declared `const markupCoefficient = 0.0` and
		// asserted it equalled 0.0 — a local literal compared to itself, which no
		// product change could ever turn red. 0% markup is a claim about the CODE,
		// so it is asserted against the code: a markup/margin/uplift multiplier
		// does not exist on the billing path. If one is ever added, this fails.
		const billing = [
			"crates/gateway/src/billing/usage.rs",
			"crates/gateway/src/pricing.rs",
		]
			.map((f) => repoRead(f))
			.join("\n");
		expect(
			/\bmarkup\b|\bmargin_pct\b|\buplift\b|platform_fee_pct/i.test(billing),
			"no markup/margin/uplift multiplier may exist on the billing path",
		).toBe(false);
	});

	it("tracelane billing never touches provider API call cost", () => {
		// REWRITTEN 2026-08-12 (was `const platformFeeIsFlat = true` asserted true).
		// The real, checkable statement: the meter the gateway reports to Polar is
		// a TOKEN COUNT, never a provider cost. If billing ever started metering
		// dollars, this fails — which is the only way a "we don't touch provider
		// cost" claim can be guarded from code.
		const usage = repoRead("crates/gateway/src/billing/usage.rs");
		expect(usage).toContain("tokens_processed");
		expect(
			/provider_cost|cost_usd\s*\*|charge_provider/i.test(usage),
			"the meter must not derive from provider cost",
		).toBe(false);
	});

	// Behavioral half: a real integration test (make a request through the
	// gateway, capture the outgoing Authorization header with a proxy, verify
	// it equals the customer key byte-for-byte) is not yet wired. Skip it
	// honestly rather than passing a `expect(true).toBe(true)` no-op.
	it.skip("provider key is passed verbatim in Authorization header — requires live gateway + proxy capture (TRACELANE_EVAL_LIVE_GATEWAY_URL)", async () => {
		// TODO: live integration — proxy-capture outgoing Authorization header.
		expect(true).toBe(true);
	});
});
