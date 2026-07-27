import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-CANARY — canary + kill-switch progressive delivery (ADR-038, §23.5/§23.6).
 *
 * Contract: a regressive canary is contained to its ≤5% traffic slice and never
 * promoted; the LB origin flip completes < 2s. Operationally, a misbehaving
 * predictor or upstream can be disabled fleet-wide via a kill-switch without a
 * redeploy.
 *
 * Structural: assert the kill-switch flag families with fail-safe defaults and
 * the blue-green deploy script + LB flip. The deterministic ≤5% COHORT router
 * is V1.1: the 2026-07-23 dead-code audit deleted `canary.rs` (zero call
 * sites — this eval had been green-lighting scaffold by grepping the dead
 * file), so the cohort test now pins the deletion + the live flag plumbing
 * (`kill_switch.rs`) and flips back to asserting the router when it ships.
 */
function read(rel: string): string {
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const fs = require("node:fs");
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const path = require("node:path");
	return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

describe("PP-CANARY: canary + kill-switch (ADR-038)", () => {
	it("canary cohort is V1.1 — no dead cohort module ships; flag plumbing exists", () => {
		// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
		const fs = require("node:fs");
		// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
		const path = require("node:path");
		// The dead module must STAY deleted — scaffold can't silently return
		// without this eval consciously flipping back to assert the router.
		expect(
			fs.existsSync(
				path.resolve(__dirname, "../../crates/gateway/src/canary.rs"),
			),
		).toBe(false);
		const ks = read("../../crates/gateway/src/kill_switch.rs");
		expect(ks).toContain("canary_enabled");
		expect(ks).toContain("flag.canary.");
	});

	it("kill-switch has the three flag families with fail-safe defaults", () => {
		const src = read("../../crates/gateway/src/kill_switch.rs");
		expect(src).toContain("kill.predictive.");
		expect(src).toContain("kill.upstream.");
		expect(src).toContain("flag.canary.");
		// fail-safe: unconfigured PostHog → safe defaults
		expect(src).toContain("safe defaults");
	});

	it("kill.predictive.* is wired into the predictive layer", () => {
		const src = read("../../crates/gateway/src/predictive/mod.rs");
		expect(src).toContain("is_killed");
		expect(src).toContain("predictive_killed");
	});

	it("kill.upstream.* force-opens in the dispatch path", () => {
		const src = read("../../crates/gateway/src/server.rs");
		expect(src).toContain("upstream_killed");
	});

	it("blue-green deploy script flips the Cloudflare LB origin", () => {
		const src = read("../../infra/prod/blue-green-deploy.sh");
		expect(src).toContain("load_balancers");
		expect(src).toContain("default_pools");
		// fails closed before the flip on a bad smoke/eval
		expect(src).toContain("aborting before LB flip");
	});

	it.skip("integration: regressive canary contained to slice, LB flip < 2s (Week 8)", () => {
		// Full: route ≤5% to a regressive candidate, assert it never promotes and
		// the blue→green (or rollback) LB origin flip completes under 2s.
	});
});
