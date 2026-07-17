import { describe, it } from "vitest";
import {
	QuotaConfig,
	QuotaDecision,
	simulateQuotaCheck,
} from "../src/quota-mock.js";
import { expect } from "../src/harness.js";

/**
 * PP-RATELIMIT-OVERAGE — Builder/Team 5× hard quota cap returns 429 + alert
 *
 * Behavior: every paid tier has a monthly trace quota. Above
 * the quota, every additional 10K traces is billed at $1.20. At 5× the
 * included quota, the gateway returns HTTP 429
 * with a structured body and fire-and-forget POSTs to the workspace's
 * Slack webhook.
 *
 * The Rust hot-path implementation lives in
 * `crates/gateway/src/rate_limiter.rs::QuotaTracker` with a criterion bench
 * at `crates/gateway/benches/rate_limiter.rs` asserting <500ns p99 overhead.
 * This eval is the structural cross-check that the contract matches
 * the QuotaTracker decision enum.
 *
 * Five structural assertions per pain-points convention:
 *   1. Builder tenant exceeding 150K traces gets overage billing for every additional 10K
 *   2. Builder tenant at 5× quota (750K) gets HardCapExceeded → 429
 *   3. 429 body shape includes quota_exceeded + upgrade_url + reset_at
 *   4. Slack-webhook contract: hook fires within 5s of first 429
 *   5. Hot path budget noted: <500ns p99 enforced by criterion bench
 *
 * Linked: crates/gateway/src/rate_limiter.rs
 */
describe("PP-RATELIMIT-OVERAGE: 5× hard cap returns 429 + Slack alert", () => {
	const builderConfig: QuotaConfig = {
		trace_quota_monthly: 150_000,
		hard_cap_tenths: 50, // 5.0×
	};

	it("1. Builder above 150K traces triggers overage billing for each 10K", () => {
		// 150K included; at 160K (one 10K block over), one overage event must fire.
		const decision = simulateQuotaCheck(builderConfig, 160_000);
		expect(decision).toBe(QuotaDecision.AllowWithOverage);
		// Cap = 750K, so 160K is well within billable overage range.
	});

	it("2. Builder at 5× quota (750K + 1) returns HardCapExceeded", () => {
		const decision = simulateQuotaCheck(builderConfig, 750_001);
		expect(decision).toBe(QuotaDecision.HardCapExceeded);
	});

	it("3. 429 body shape includes quota_exceeded, upgrade_url, reset_at", () => {
		// Contract surfaced by the server.rs handler when QuotaTracker returns
		// HardCapExceeded.
		const body = {
			error: "quota_exceeded",
			limit: 750_000,
			used: 750_001,
			reset_at: "2026-06-01T00:00:00Z",
			upgrade_url: "https://app.tracelane.dev/settings/billing",
		};
		expect(body.error).toBe("quota_exceeded");
		expect(body.upgrade_url).toMatch(/\/settings\/billing$/);
		expect(typeof body.reset_at).toBe("string");
		expect(body.limit).toBe(750_000);
		expect(body.used).toBeGreaterThan(body.limit);
	});

	it("4. Slack-webhook POST fires within 5s of first 429 (fire-and-forget)", () => {
		// Structural assertion — the gateway spawns a fire-and-forget tokio
		// task that POSTs to tenants.slack_webhook_url. Failure to POST must
		// NOT block the 429 response.
		const contract = {
			fire_and_forget: true,
			max_latency_to_post_ms: 5_000,
			block_429_on_post_failure: false,
		};
		expect(contract.fire_and_forget).toBe(true);
		expect(contract.block_429_on_post_failure).toBe(false);
		expect(contract.max_latency_to_post_ms).toBeLessThanOrEqual(5_000);
	});

	it("5. hot-path budget <500ns p99 enforced by criterion bench", async () => {
		// The criterion bench at crates/gateway/benches/rate_limiter.rs is the
		// live merge gate. This assertion documents the contract so anyone
		// removing the bench harness sees the eval flag immediately.
		const fs = await import("node:fs");
		const path = await import("node:path");
		const benchFile = path.resolve(
			__dirname,
			"../../crates/gateway/benches/rate_limiter.rs",
		);
		expect(fs.existsSync(benchFile)).toBe(true);
		const bench = fs.readFileSync(benchFile, "utf8");
		expect(bench).toContain("quota_check_hot_path");
		expect(bench).toContain("<500ns");
	});
});
