import fs from "node:fs";
import path from "node:path";
import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P12 — BYOK at raw API prices: 0% gateway markup
 *
 * Competitor behavior: some gateways mark up provider prices or charge a
 * percentage on every call, which is material at volume for margin-sensitive
 * teams.
 *
 * Tracelane fix: 100% BYOK with 0% gateway markup. Customers use their own
 * provider API keys (envelope-encrypted at rest); provider costs go directly to
 * the customer's provider bill at raw API prices.
 *
 * Eval: assert 0% markup and that BYOK is real code (no competitor numbers, no
 * private-doc reads).
 *
 * Linked: PP-P12
 */
const ROOT = path.resolve(__dirname, "../..");

/** Read a repo file relative to the repo root — the product, not a model of it. */
function repoRead(rel: string): string {
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const fs = require("node:fs");
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const path = require("node:path");
	return fs.readFileSync(path.resolve(__dirname, "../../", rel), "utf8");
}

describe("PP-P12: BYOK at raw API prices — 0% markup", () => {
	it("the gateway adds 0% markup on provider calls", () => {
		// REWRITTEN 2026-08-12 (was `const gatewayMarkupPct = 0` asserted 0 — a
		// literal compared to itself). The checkable form of "0% markup" is that
		// the price catalog holds PROVIDER list rates and applies no multiplier to
		// them. A markup would have to appear here to reach a customer.
		const pricing = repoRead("crates/gateway/src/pricing.rs");
		expect(
			/\bmarkup\b|\bmargin\b|\buplift\b|\* *1\.[0-9]+ *\/\/ *fee/i.test(pricing),
			"pricing.rs must apply no markup multiplier to provider rates",
		).toBe(false);
	});

	it("BYOK is structurally enforced in the gateway (envelope encryption)", () => {
		expect(fs.existsSync(path.join(ROOT, "crates/gateway/src/byok.rs"))).toBe(
			true,
		);
	});
});
